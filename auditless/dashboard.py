"""Local web dashboard + API for Auditless.

FastAPI app serving a single-page UI, a documented JSON API, and
interactive Swagger UI at /docs (ReDoc at /redoc, schema at
/openapi.json). Scan execution reuses the shared CLI pipeline, so results
cannot drift from the command line.

Security model:
    - Binds to loopback (127.0.0.1) by default; do not expose to untrusted
      networks without a reverse proxy providing authentication + TLS.
    - The SSH password is write-only: accepted on POST /api/scans, kept in
      server memory for the duration of the run, then scrubbed. It is never
      written to disk, never stored in job history, and never serialized
      into any response (Pydantic SecretStr + explicit response models).
    - Completed JSON reports are saved to ./reports/ (best effort) without
      credentials.

Usage:
    python -m auditless HOST USER PASS --serve
    python -m auditless --serve --serve-port 8080
"""

from __future__ import annotations

from collections.abc import Callable

import contextlib
import dataclasses
import io
import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, SecretStr

from .discovery import parse_network, probe_hosts
from .heatmap import build_heatmap
from .store import Store

MAX_JOBS = 50
MAX_REPORT_PAGE = 200
MAX_HOST_PAGE = 500
SCAN_STATUSES = {"queued", "running", "done", "error"}
REPORT_STATUSES = {"done", "error"}

_auth_scheme = HTTPBearer(auto_error=False)


def _parse_time_param(value: str | None, name: str) -> float | None:
    """Parse an epoch-seconds or ISO-8601 query timestamp (UTC if naive)."""
    if value is None or value == "":
        return None
    import math
    from datetime import datetime, timezone

    try:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError(value)
        return parsed
    except ValueError:
        pass
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"{name} must be epoch seconds or ISO-8601",
        ) from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _time_range(
    since: str | None, until: str | None
) -> tuple[float | None, float | None]:
    """Parse a since/until pair and reject inverted ranges."""
    start = _parse_time_param(since, "since")
    end = _parse_time_param(until, "until")
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=400, detail="since must not be after until")
    return start, end


def _status_filter(status: str | None, allowed: set[str]) -> str | None:
    """Validate a status filter (empty means no filter)."""
    if status is None or status == "":
        return None
    if status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {', '.join(sorted(allowed))}",
        )
    return status


def require_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_auth_scheme),
) -> str:
    """Enforce bearer auth on API routes; returns the actor name.

    Accepts the AUDITLESS_TOKEN fallback (actor "env-token") or a named
    API token from the store (actor "token:<name>"). Unset env token and
    no stored tokens preserves the historical behavior (loopback-only,
    no auth, actor "anonymous").
    """
    import hmac

    provided = credentials.credentials if credentials else ""
    if not provided:
        provided = request.query_params.get("token", "")
    if not provided:
        if os.environ.get("AUDITLESS_TOKEN", ""):
            raise HTTPException(
                status_code=401,
                detail="missing or invalid API token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return "anonymous"
    expected = os.environ.get("AUDITLESS_TOKEN", "")
    if expected and hmac.compare_digest(provided, expected):
        return "env-token"
    row = get_store().verify_token(provided)
    if row is not None:
        return f"token:{row['name']}"
    raise HTTPException(
        status_code=401,
        detail="missing or invalid API token",
        headers={"WWW-Authenticate": "Bearer"},
    )


_guarded = [Depends(require_token)]

_jobs: dict[str, "ScanJob"] = {}
_jobs_order: list[str] = []
_jobs_lock = threading.Lock()

_proposals: dict[str, dict] = {}
_proposals_lock = threading.Lock()

_STORE: Store | None = None


def get_store() -> Store:
    """Process-wide persistence handle (override via reset in tests)."""
    global _STORE
    if _STORE is None:
        _STORE = Store()
    return _STORE


def reset_store() -> None:
    """Drop the cached store (tests point at isolated dirs)."""
    global _STORE
    _STORE = None


MAX_JOB_LOG_CHARS = 65536


@dataclass
class ScanJob:
    """In-memory record of a single scan run (never holds credentials)."""

    id: str
    hostname: str
    username: str
    status: str = "queued"  # queued | running | done | error
    progress: str = "queued"
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    report: dict | None = None
    error: str | None = None
    log: str = ""

    def summary(self) -> dict:
        """Public summary safe for API responses."""
        hardening = (self.report or {}).get("summary", {}).get("hardening_index")
        return {
            "id": self.id,
            "hostname": self.hostname,
            "username": self.username,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "hardening_index": hardening,
            "error": self.error,
            "log": self.log,
        }


def _append_job_log(job: ScanJob, text: str) -> None:
    """Append timestamped text to a job log, capped to a fixed tail size."""
    if not text:
        return
    stamp = time.strftime("%H:%M:%S")
    chunk = "".join(
        f"[{stamp}] {line}\n" if line.strip() else "\n" for line in text.splitlines()
    )
    if not chunk:
        return
    with _jobs_lock:
        job.log = (job.log + chunk)[-MAX_JOB_LOG_CHARS:]


class ScanRequest(BaseModel):
    """Parameters for starting a scan. Password is write-only."""

    hostname: str = Field(default="", examples=["192.168.1.100"])
    username: str = Field(default="", examples=["admin"])
    password: SecretStr | None = Field(
        default=None,
        description="SSH password. Memory-only for the run; never stored or returned.",
    )
    jump_password: SecretStr | None = Field(
        default=None,
        description="Bastion password for jump hosts (memory-only).",
    )
    host_id: str | None = Field(
        default=None,
        description="Saved host to scan (alternative to hostname/username).",
    )
    port: int = 22
    timeout: float = 5.0
    command_timeout: float = 60.0
    scan_ports: str = Field(
        default="",
        description="Comma-separated ports; default uses common ports.",
    )
    profile: str = Field(
        default="", description="Profile name or path (see GET /api/profiles)."
    )
    enable_rootkit_scan: bool = False
    check_package_hygiene: bool = False
    strict_host_key_checking: bool = Field(
        default=False, description="Reject unknown host keys (MITM protection)."
    )


class RangeScanRequest(BaseModel):
    """Probe a network range for SSH and scan each reachable host.

    Credentials follow the same write-only rule as ``ScanRequest``: the
    password lives in server memory for the duration of the batch only.
    """

    network: str = Field(
        examples=["192.168.1.0/24", "192.168.1.10-20"],
        description="CIDR, hyphen range or single IP (bounded to max_hosts).",
    )
    username: str = Field(default="", examples=["admin"])
    password: SecretStr | None = Field(
        default=None, description="SSH password. Memory-only; never stored or returned."
    )
    port: int = 22
    max_hosts: int = Field(
        default=256, ge=1, le=1024, description="Cap on addresses in the range."
    )
    probe_timeout: float = Field(
        default=1.0, ge=0.1, le=10.0, description="Seconds per SSH port probe."
    )
    probe_concurrency: int = Field(
        default=32, ge=1, le=64, description="Parallel TCP probes."
    )
    max_concurrent: int = Field(
        default=4, ge=1, le=8, description="Cap simultaneous scan jobs."
    )
    timeout: float = 5.0
    command_timeout: float = 60.0
    scan_ports: str = ""
    profile: str = ""
    enable_rootkit_scan: bool = False
    check_package_hygiene: bool = False
    strict_host_key_checking: bool = Field(
        default=False, description="Reject unknown host keys."
    )


class RangeJob(BaseModel):
    """One launched job, paired with the host it targets."""

    host: str
    job_id: str


class RangeScanResponse(BaseModel):
    """Discovery summary plus the launched jobs (never credentials)."""

    network: str
    candidates: int
    discovered: int
    jobs: list[RangeJob]


class HostCreate(BaseModel):
    """Register a host for saved key auth and report history."""

    name: str = Field(examples=["prod-web-01"])
    hostname: str = Field(examples=["192.168.1.100"])
    username: str = Field(examples=["admin"])
    port: int = 22
    auth: str = Field(
        default="password",
        description="'password' (prompted per scan) or 'key' (stored server-side).",
    )
    jump_hostname: str = Field(
        default="", description="Bastion host (empty = direct connection)."
    )
    jump_port: int = 22
    jump_username: str = ""
    jump_auth: str = Field(default="password", description="'password' or 'key'.")


class HostUpdate(BaseModel):
    """Partial host update (all fields optional)."""

    name: str | None = None
    hostname: str | None = None
    username: str | None = None
    port: int | None = None
    auth: str | None = None
    jump_hostname: str | None = None
    jump_port: int | None = None
    jump_username: str | None = None
    jump_auth: str | None = None


class HostPublic(BaseModel):
    """Host metadata (key bytes are never exposed)."""

    id: str
    name: str
    hostname: str
    port: int
    username: str
    auth: str
    has_key: int
    jump_hostname: str = ""
    jump_port: int = 22
    jump_username: str = ""
    jump_auth: str = "password"
    has_jump_key: int = 0
    created_at: float
    updated_at: float


class KeyUpload(BaseModel):
    """Private key material (write-only; stored 0600, never readable back)."""

    key: str = Field(description="PEM/OpenSSH private key text.")


class ScheduleCreate(BaseModel):
    """Create an unattended scan schedule."""

    host_id: str
    name: str = Field(examples=["nightly prod-web"])
    cron: str = Field(
        examples=["0 3 * * *"],
        description="5-field cron (minute hour day month weekday).",
    )
    profile: str = ""
    webhook_url: str = Field(
        default="",
        description="Notification endpoint (write-only; never returned).",
    )
    notify_on: str = Field(
        default="regression",
        description="One of regression, threshold, always, never.",
    )
    min_index: int | None = Field(
        default=None, description="Breach threshold for threshold policy."
    )
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    """Partial schedule update (all fields optional)."""

    name: str | None = None
    cron: str | None = None
    profile: str | None = None
    webhook_url: str | None = None
    notify_on: str | None = None
    min_index: int | None = None
    enabled: bool | None = None


class SchedulePublic(BaseModel):
    """Schedule metadata (webhook URL never exposed)."""

    id: str
    host_id: str
    name: str
    cron: str
    profile: str
    has_webhook: bool
    notify_on: str
    min_index: int | None = None
    enabled: int
    last_run: float | None = None
    next_run: float | None = None
    created_at: float
    updated_at: float


class ScanJobPublic(BaseModel):
    """Job record safe for responses (no credentials, no report by default)."""

    id: str
    hostname: str
    username: str
    status: str
    progress: str
    created_at: float
    finished_at: float | None = None
    hardening_index: int | None = None
    error: str | None = None
    report: dict | None = None
    log: str = ""


class HeatmapTile(BaseModel):
    """A single treemap tile (labels + counts only, no raw check details)."""

    id: str
    label: str
    sublabel: str = ""
    value: int
    color: str
    hosts: list[dict] = Field(default_factory=list)
    meta: dict = Field(default_factory=dict)


class HeatmapGroup(BaseModel):
    """A labelled group of tiles (TradingView-sector equivalent)."""

    name: str
    value: int
    tiles: list[HeatmapTile]


class HeatmapResponse(BaseModel):
    """Grouped treemap data plus small summary counters."""

    mode: str
    groups: list[HeatmapGroup]
    total_hosts: int
    total_tiles: int
    generated_at: float


def _register_job(job: ScanJob) -> None:
    with _jobs_lock:
        _jobs[job.id] = job
        _jobs_order.append(job.id)
        while len(_jobs_order) > MAX_JOBS:
            _jobs.pop(_jobs_order.pop(0), None)


def _save_report_copy(hostname: str, payload: dict) -> None:
    """Persist a copy of a finished report (best effort, no credentials)."""
    try:
        reports = Path("reports")
        reports.mkdir(exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        safe_host = "".join(c if c.isalnum() or c in "-_." else "_" for c in hostname)
        (reports / f"auditless-{safe_host}-{ts}.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
    except OSError:
        pass  # Report persistence must never fail a scan


class _TeeWriter(io.TextIOBase):
    """File-like wrapper that buffers CLI output and forwards it to a callback."""

    def __init__(self, callback: Callable[[str], None] | None) -> None:
        self._buffer = io.StringIO()
        self._callback = callback

    def write(self, text: str) -> int:
        self._buffer.write(text)
        if self._callback and text:
            try:
                self._callback(text)
            except Exception:
                pass
        return len(text)

    def flush(self) -> None:
        return None

    def getvalue(self) -> str:
        return self._buffer.getvalue()


def run_scan(params: dict, log_cb: Callable[[str], None] | None = None) -> dict:
    """Execute one scan via the shared CLI pipeline and return the report.

    Args:
        params: Scan parameters (hostname, username, password, port,
            timeout, command_timeout, scan_ports, profile, key_path,
            enable_rootkit_scan, check_package_hygiene,
            strict_host_key_checking).
        log_cb: Optional callable receiving text chunks of CLI stdout/stderr.

    Returns:
        Parsed JSON report dict.

    Raises:
        RuntimeError: If the scan fails (SSH/auth/network). The message
            never contains the password.
    """
    from .cli import main as cli_main

    password = params.get("password") or ""
    key_path = params.get("key_path") or ""
    argv = [
        params.get("hostname") or "",
        params.get("username") or "",
        password,
        "--port",
        str(params.get("port", 22)),
        "--timeout",
        str(params.get("timeout", 5.0)),
        "--command-timeout",
        str(params.get("command_timeout", 60.0)),
        "--format",
        "json",
    ]
    if key_path:
        argv += ["--key-file", str(key_path)]
    if params.get("scan_ports"):
        argv += ["--scan-ports", str(params["scan_ports"])]
    if params.get("profile"):
        argv += ["--profile", str(params["profile"])]
    if params.get("enable_rootkit_scan"):
        argv.append("--enable-rootkit-scan")
    if params.get("check_package_hygiene"):
        argv.append("--check-package-hygiene")
    if params.get("strict_host_key_checking", True):
        argv.append("--strict-host-key-checking")
    else:
        argv.append("--no-strict-host-key-checking")
    if params.get("jobs") is not None:
        argv += ["--jobs", str(params["jobs"])]
    if params.get("check_timeout") is not None:
        argv += ["--check-timeout", str(params["check_timeout"])]
    if params.get("deadline") is not None:
        argv += ["--deadline", str(params["deadline"])]
    if params.get("retries") is not None:
        argv += ["--retries", str(params["retries"])]
    if params.get("no_cache"):
        argv.append("--no-cache")
    if params.get("max_output_bytes") is not None:
        argv += ["--max-output-bytes", str(params["max_output_bytes"])]
    if params.get("only_tests") is not None:
        argv += ["--only-tests", str(params["only_tests"])]
    if params.get("skip_tests") is not None:
        argv += ["--skip-tests", str(params["skip_tests"])]
    if params.get("reuse_session", True):
        argv.append("--reuse-session")
    gateway = params.get("gateway") or {}
    if gateway.get("hostname"):
        argv += [
            "--jump-host",
            str(gateway["hostname"]),
            "--jump-port",
            str(gateway.get("port") or 22),
            "--jump-user",
            str(gateway.get("username") or ""),
        ]
        if gateway.get("password"):
            argv += ["--jump-password", str(gateway["password"])]
        if gateway.get("key_path"):
            argv += ["--jump-key-file", str(gateway["key_path"])]

    out_path = Path(tempfile.mkdtemp(prefix="auditless-")) / "report.json"
    argv += ["--output", str(out_path)]
    buf = _TeeWriter(log_cb)
    try:
        if not password and not key_path:
            raise RuntimeError("password is required to start a scan")
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli_main(argv)
        if code != 0 or not out_path.exists():
            raise RuntimeError(f"scan failed (exit {code}): {buf.getvalue()[-500:]}")
        payload: dict = json.loads(out_path.read_text(encoding="utf-8"))
        return payload
    except SystemExit as exc:
        raise RuntimeError(
            f"scan failed (exit {exc.code}): {buf.getvalue()[-500:]}"
        ) from exc
    finally:
        params["password"] = None
        with contextlib.suppress(OSError):
            out_path.unlink()


def _persist_job(job: ScanJob, host_id: str | None, status: str | None = None) -> None:
    """Best-effort persistence (must never break status reporting)."""
    try:
        get_store().save_report(
            job.id,
            job.hostname,
            job.username,
            status or job.status,
            job.report,
            job.error,
            host_id,
            job.created_at,
            job.finished_at,
        )
    except Exception:
        pass


def _run_job(
    job: ScanJob, params: dict, host_id: str | None = None, actor: str = "unknown"
) -> None:
    # NOTE: the stored row is written with its terminal status BEFORE the
    # in-memory flag flips, so pollers that observe done/error are
    # guaranteed a matching stored row (no save race).
    job.status = "running"
    target = job.hostname
    if params.get("port") not in (None, "", 22, "22"):
        target = f"{job.hostname}:{params['port']}"
    job.progress = f"connecting to {target} over SSH"
    _append_job_log(job, f"starting scan of {target} as {job.username}")
    if params.get("profile"):
        _append_job_log(job, f"profile: {params['profile']}")
    if params.get("scan_ports"):
        _append_job_log(job, f"port scan targets: {params['scan_ports']}")
    if params.get("enable_rootkit_scan"):
        _append_job_log(job, "rootkit scan enabled (rkhunter)")
    if params.get("check_package_hygiene"):
        _append_job_log(job, "package hygiene checks enabled")
    if params.get("strict_host_key_checking", True):
        _append_job_log(job, "strict host-key checking: on")
    else:
        _append_job_log(job, "strict host-key checking: off (lab mode)")
    _append_job_log(job, "connecting over SSH and gathering system/check data")

    def _on_output(text: str) -> None:
        clean = text.rstrip()
        if clean:
            _append_job_log(job, clean)

    try:
        try:
            job.report = run_scan(params, log_cb=_on_output)
        except TypeError:
            job.report = run_scan(params)
        summary = (job.report or {}).get("summary", {})
        hardening_index = summary.get("hardening_index")
        passed = summary.get("passed")
        warned = summary.get("warned")
        failed = summary.get("failed")
        total = summary.get("total_checks")
        job.progress = "complete"
        _append_job_log(
            job,
            "scan complete"
            + (
                f" — hardening index {hardening_index}/100"
                if hardening_index is not None
                else ""
            )
            + (
                f" ({total} checks: {passed} passed, {warned} warned, {failed} failed)"
                if total is not None
                else ""
            ),
        )
        _save_report_copy(job.hostname, job.report)
        job.finished_at = time.time()
        _scrub_temp_key(params)
        _persist_job(job, host_id, status="done")
        job.status = "done"
        _audit(
            actor,
            "scan.completed",
            "scan",
            job.id,
            f"index={hardening_index}",
        )
    except Exception as exc:  # keep the job record, report the failure
        job.progress = "failed"
        job.error = str(exc)[:1000]
        _append_job_log(job, f"scan failed: {job.error}")
        job.finished_at = time.time()
        _persist_job(job, host_id, status="error")
        job.status = "error"
        _audit(actor, "scan.failed", "scan", job.id, job.error[:200])
    finally:
        _scrub_temp_key(params)


def _scrub_temp_key(params: dict) -> None:
    """Unlink materialized key bytes (idempotent backstop)."""
    for temp_key in params.get("_temp_keys") or []:
        with contextlib.suppress(OSError):
            Path(temp_key).unlink()


def start_scan(params: dict) -> ScanJob:
    """Validate params, register a job, and return it (caller runs it)."""
    hostname = (params.get("hostname") or "").strip()
    username = (params.get("username") or "").strip()
    password = params.get("password") or ""
    key_path = params.get("key_path") or ""
    if not hostname or not username or (not password and not key_path):
        raise ValueError("hostname, username and password (or key) are required")
    job = ScanJob(id=uuid.uuid4().hex[:12], hostname=hostname, username=username)
    _register_job(job)
    return job


def resolve_host_scan(host_id: str, overrides: dict) -> tuple[dict, dict]:
    """Build (job_params, run_params) for a saved host.

    Passwords are never stored: password hosts require a per-scan password,
    key hosts use the stored key file (optional password = sudo only).

    Raises:
        KeyError: Unknown host. ValueError: Missing credential.
    """
    host = get_store().get_host(host_id)
    if host is None:
        raise KeyError(f"unknown host {host_id}")
    password = overrides.get("password") or ""
    key_path = ""
    temp_keys: list[str] = []

    def _materialize(kind: str) -> str:
        # Decrypted key bytes go to a 0600 temp file; _temp_keys lets
        # _run_job unlink every copy afterwards.
        fd, path = tempfile.mkstemp(prefix="auditless-key-")
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(get_store().read_host_key(host_id, kind=kind))
        temp_keys.append(path)
        return path

    if host["auth"] == "key":
        if not get_store().has_host_key(host_id):
            raise ValueError("host uses key auth but no key is stored")
        key_path = _materialize("host")
    elif not password:
        raise ValueError("password is required for this host")
    gateway: dict = {}
    if host.get("jump_hostname"):
        if host.get("jump_auth", "password") == "key":
            if not get_store().has_host_key(host_id, kind="jump"):
                raise ValueError("jump host uses key auth but no key is stored")
            gateway = {
                "hostname": host["jump_hostname"],
                "port": host.get("jump_port") or 22,
                "username": host.get("jump_username") or "",
                "password": "",
                "key_path": _materialize("jump"),
            }
        else:
            jump_password = overrides.get("jump_password") or ""
            if not jump_password:
                raise ValueError("jump password is required for this host")
            gateway = {
                "hostname": host["jump_hostname"],
                "port": host.get("jump_port") or 22,
                "username": host.get("jump_username") or "",
                "password": jump_password,
                "key_path": "",
            }
    base = {
        "hostname": host["hostname"],
        "username": host["username"],
        "port": host["port"],
        "key_path": key_path,
        "timeout": overrides.get("timeout", 5.0),
        "command_timeout": overrides.get("command_timeout", 60.0),
        "scan_ports": overrides.get("scan_ports", ""),
        "profile": overrides.get("profile", ""),
        "enable_rootkit_scan": bool(overrides.get("enable_rootkit_scan")),
        "check_package_hygiene": bool(overrides.get("check_package_hygiene")),
        "strict_host_key_checking": bool(overrides.get("strict_host_key_checking")),
        "gateway": gateway,
        "_temp_keys": temp_keys,
    }
    return base, {**base, "password": password}


def diff_reports(before: dict, after: dict) -> dict:
    """Compare two stored reports check-by-check.

    Checks are keyed by (test_id, item). Returns fixed / regressed /
    new / gone lists plus the hardening-index delta.
    """

    def key(check: dict) -> str:
        return f"{check.get('test_id', '')}::{check.get('item', '')}"

    def rank(status: str) -> int:
        return {"pass": 2, "warn": 1, "fail": 0, "unknown": 1}.get(status, -1)

    old = {key(c): c for c in before.get("checks", [])}
    new = {key(c): c for c in after.get("checks", [])}
    fixed, regressed, changed = [], [], []
    for ident, new_check in new.items():
        if ident not in old:
            continue
        old_status, new_status = old[ident].get("status"), new_check.get("status")
        entry = {
            "test_id": new_check.get("test_id", ""),
            "item": new_check.get("item", ""),
            "category": new_check.get("category", ""),
            "from": old_status,
            "to": new_status,
            "recommendation": new_check.get("recommendation", ""),
        }
        if rank(new_status) > rank(old_status):
            fixed.append(entry)
        elif rank(new_status) < rank(old_status):
            regressed.append(entry)
        elif old[ident].get("details") != new_check.get("details"):
            changed.append(entry)
    return {
        "hardening_before": (before.get("summary") or {}).get("hardening_index"),
        "hardening_after": (after.get("summary") or {}).get("hardening_index"),
        "hardening_delta": (
            ((after.get("summary") or {}).get("hardening_index") or 0)
            - ((before.get("summary") or {}).get("hardening_index") or 0)
        ),
        "fixed": fixed,
        "regressed": regressed,
        "changed": changed,
        "new": [
            {
                "test_id": c.get("test_id", ""),
                "item": c.get("item", ""),
                "category": c.get("category", ""),
                "to": c.get("status", ""),
            }
            for ident, c in new.items()
            if ident not in old
        ],
        "gone": [
            {
                "test_id": c.get("test_id", ""),
                "item": c.get("item", ""),
                "category": c.get("category", ""),
                "from": c.get("status", ""),
            }
            for ident, c in old.items()
            if ident not in new
        ],
    }


def get_job(job_id: str) -> ScanJob | None:
    """Fetch a job by id (None when unknown)."""
    with _jobs_lock:
        return _jobs.get(job_id)


def list_jobs() -> list[dict]:
    """Newest-first summaries of recent jobs."""
    with _jobs_lock:
        jobs = [_jobs[jid] for jid in reversed(_jobs_order) if jid in _jobs]
    return [job.summary() for job in jobs]


def delete_job(job_id: str) -> bool:
    """Forget a job record. Returns True when a record was removed."""
    with _jobs_lock:
        if job_id not in _jobs:
            return False
        del _jobs[job_id]
        if job_id in _jobs_order:
            _jobs_order.remove(job_id)
        return True


def get_version_info() -> dict:
    """Scanner + API version metadata."""
    import platform

    from . import __version__

    return {
        "scanner": "Auditless",
        "version": __version__,
        "api_version": "1.0",
        "python": platform.python_version(),
        "features": [
            "ssh-scan",
            "port-scan",
            "profiles",
            "hardening-index",
            "formats-json-md-text",
            "rootkit-scan",
            "package-hygiene",
            "strict-host-key-checking",
        ],
    }


def list_profiles() -> list[dict]:
    """Discover scan profiles from conventional locations (names only)."""
    found: list[dict] = []
    seen: set[str] = set()

    def add(name: str, path: Path, source: str) -> None:
        key = str(path)
        if key not in seen:
            seen.add(key)
            found.append({"name": name, "path": key, "source": source})

    try:
        from .config import get_config_dirs, get_default_profile_paths
    except ImportError:
        return found

    for profiles_dir in [Path.cwd() / "profiles"] + [
        config_dir / "profiles" for config_dir in get_config_dirs()
    ]:
        if profiles_dir.is_dir():
            for candidate in sorted(profiles_dir.glob("*.yaml")) + sorted(
                profiles_dir.glob("*.yml")
            ):
                add(candidate.stem, candidate, "profiles-dir")
    for candidate in get_default_profile_paths():
        if candidate.exists():
            add(candidate.stem, candidate, "auto")
    return found


def render_report_dict(report: dict, fmt: str) -> tuple[str, str]:
    """Re-render a stored report dict in json/md/text (no job needed)."""
    if fmt not in ("json", "md", "text"):
        raise ValueError(f"unknown format {fmt!r}: use json, md or text")
    if fmt == "json":
        return json.dumps(report, indent=2), "application/json"

    from .checks import CheckResult, DetailedSecurityInfo, SystemInfo
    from .report import render_report, render_report_text
    from .scanner import PortStatus

    system = report.get("system", {})
    info = SystemInfo(
        hostname=system.get("hostname", ""),
        os=system.get("os", ""),
        kernel=system.get("kernel", ""),
        uptime=system.get("uptime", ""),
        users=system.get("logged_in_users", ""),
    )
    checks = [
        CheckResult(
            category=c.get("category", ""),
            item=c.get("item", ""),
            status=c.get("status", ""),
            details=c.get("details", ""),
            recommendation=c.get("recommendation", ""),
            test_id=c.get("test_id", ""),
        )
        for c in report.get("checks", [])
    ]
    ports = [
        PortStatus(
            port=p.get("port", 0),
            open=True,
            reason=p.get("reason", ""),
            banner=p.get("banner"),
            service=p.get("service"),
            version=p.get("version"),
        )
        for p in report.get("ports", {}).get("open_ports", [])
    ]
    findings = report.get("detailed_findings") or {}
    detailed = DetailedSecurityInfo(
        **{
            f.name: findings.get(f.name, "")
            for f in dataclasses.fields(DetailedSecurityInfo)
            if f.name not in ("rootkit_scan", "unused_packages")
        },
        rootkit_scan=findings.get("rootkit_scan"),
        unused_packages=findings.get("unused_packages"),
    )
    if fmt == "md":
        return (
            render_report(info, checks, ports, detailed),
            "text/markdown; charset=utf-8",
        )
    return (
        render_report_text(info, checks, ports, detailed),
        "text/plain; charset=utf-8",
    )


def render_saved_report(job: ScanJob, fmt: str) -> tuple[str, str]:
    """Re-render a finished in-memory job in json/md/text.

    Raises:
        ValueError: If the format is unknown.
        RuntimeError: If the scan is not finished successfully.
    """
    if job.status != "done" or not job.report:
        raise RuntimeError("scan is not complete")
    return render_report_dict(job.report, fmt)


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditless &mdash; Linux Security Scanner</title>
<link rel="icon" href="data:,">
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#e6edf3;--dim:#8b949e;
--grn:#3fb950;--yel:#d29922;--red:#f85149;--acc:#58a6ff}
*{box-sizing:border-box}body{background:var(--bg);color:var(--txt);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;padding:24px}
.wrap{max-width:1080px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--dim);font-size:13px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:16px;margin-bottom:16px}
label{font-size:12px;color:var(--dim);display:block;margin:8px 0 4px}
input,select{background:#0d1117;border:1px solid var(--line);color:var(--txt);
border-radius:6px;padding:8px;width:100%}
.row{display:grid;grid-template-columns:1fr 1fr 1fr 120px;gap:12px}
.opts{display:flex;gap:16px;margin-top:10px;font-size:13px;color:var(--dim)}
.opts label{display:inline;margin:0}.opts input{width:auto}
button{background:#1f6feb;border:0;color:#fff;border-radius:6px;padding:10px 18px;
font-size:14px;cursor:pointer;margin-top:12px}
button:disabled{opacity:.5;cursor:default}
.score{font-size:44px;font-weight:700}.chips{display:flex;gap:10px;flex-wrap:wrap}
.chip{border:1px solid var(--line);border-radius:6px;padding:6px 12px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600}.pass{color:var(--grn)}.warn{color:var(--yel)}
.fail{color:var(--red)}.toolbar{display:flex;gap:10px;margin:10px 0}
.toolbar input,.toolbar select{width:auto;flex:1}
.hist{font-size:13px;color:var(--dim)}.hist a{color:var(--acc);cursor:pointer}
.err{color:var(--red)}.note{font-size:12px;color:var(--dim);margin-top:8px}
.logbox{margin-top:8px}
.logbox summary{cursor:pointer;color:var(--dim);font-size:12px}
.logbox pre{margin:6px 0 0;background:#0d1117;border:1px solid var(--line);border-radius:6px;padding:8px;max-height:280px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12px;color:var(--txt)}
.heatmap{position:relative;height:420px;background:#0d1117;border:1px solid var(--line);
border-radius:6px;overflow:hidden}
.hmgroup{position:absolute;border:1px solid var(--line);border-radius:4px;
background:#11161d;overflow:hidden}
.hmname{position:absolute;top:0;left:0;right:0;height:18px;font-size:11px;
color:var(--dim);padding:2px 6px;background:#161b22;white-space:nowrap;
overflow:hidden;text-overflow:ellipsis}
.hmtile{position:absolute;border:1px solid #0d1117;border-radius:3px;cursor:pointer;
overflow:hidden;padding:3px;color:#fff;font-size:11px;line-height:1.15}
.hmtile:hover{filter:brightness(1.3);z-index:2}
.hmlabel{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hmsub{color:rgba(255,255,255,.78);font-size:10px;white-space:nowrap;
overflow:hidden;text-overflow:ellipsis}
.hmempty{position:absolute;inset:0;display:flex;align-items:center;
justify-content:center;color:var(--dim)}
</style>
</head>
<body>
<div class="wrap">
<h1>Auditless</h1>
<div class="sub">Agentless Linux security scanner &mdash; hardening index, checks &amp; remediation &mdash; <a style="color:var(--acc)" href="/docs">API reference (Swagger)</a></div>
<div class="card" id="tokbar" style="display:none;border-color:var(--yel)">
<h3 style="margin-top:0">API token required</h3>
<div class="toolbar"><input id="tokinput" type="password" placeholder="paste bearer token"></div>
<div class="toolbar"><button style="margin:0" onclick="saveTok()">Save for this tab</button>
<button style="margin:0" onclick="clearTok()">Clear</button></div>
<div class="note">Set <code>AUDITLESS_TOKEN</code> on the server. The token lives in
session storage only &mdash; never persisted.</div>
</div>
<div class="card">
<h3 style="margin-top:0">New scan</h3>
<div style="margin-bottom:8px"><label>Saved host (optional &mdash; overrides manual fields)</label><select id="hostsel" onchange="hostPick()"><option value="">manual entry</option></select></div>
<div class="row">
<div><label>Hostname / IP</label><input id="host" placeholder="192.168.1.100"></div>
<div><label>SSH username</label><input id="user" placeholder="admin"></div>
<div><label>SSH password</label><input id="pass" type="password" placeholder="required"></div>
<div><label>SSH port</label><input id="port" value="22"></div>
</div>
<div style="margin-bottom:8px"><label>Network range (optional &mdash; scans every host with the port above open)</label>
<input id="net" placeholder="192.168.1.0/24 or 192.168.1.10-20" style="max-width:420px"></div>
<div class="opts">
<label><input type="checkbox" id="strict"> strict host-key checking</label>
<label><input type="checkbox" id="rootkit"> rkhunter scan</label>
<label><input type="checkbox" id="hygiene"> package hygiene</label>
</div>
<button id="go" onclick="startScan()">Run scan</button>
<div class="note">A range probes each address for open SSH first, then scans only responsive hosts
(up to 256 addresses; CIDR, hyphen range or single IP). Password stays in server memory for the
run only &mdash; never stored or logged. Binds to localhost; do not expose without auth + TLS.</div>
<div id="status" style="margin-top:10px"></div>
</div>
<div class="card"><h3 style="margin-top:0">Recent scans (this session)</h3><div id="hist" class="hist">loading&hellip;</div></div>
<div class="card"><h3 style="margin-top:0">API tokens</h3>
<div class="toolbar"><input id="tokname" placeholder="token name (e.g. ci-pipe)"></div>
<button style="margin:0" onclick="addToken()">Create token</button>
<div id="tokout" class="hist" style="margin-top:8px"></div>
<div id="toks" class="hist" style="margin-top:8px">loading&hellip;</div></div>
<div class="card"><h3 style="margin-top:0">Audit trail</h3>
<div class="toolbar"><button style="margin:0" onclick="loadAudit()">Refresh</button>
<button style="margin:0" onclick="verifyAudit()">Verify chain</button></div>
<div id="audstat" class="hist"></div><div id="audit" class="hist">loading&hellip;</div></div>
<div class="card"><h3 style="margin-top:0">Fleet overview</h3>
<div class="toolbar"><button style="margin:0" onclick="loadFleet()">Refresh</button>
<button style="margin:0" onclick="scanFleet()">Scan all (parallel)</button></div>
<div id="fleet" class="hist">loading&hellip;</div>
<div id="trend"></div>
<div class="toolbar"><select id="compfw"><option value="auto">framework: auto</option><option value="cis-ubuntu22">CIS Ubuntu 22.04</option><option value="cis-debian12">CIS Debian 12</option><option value="cis-rhel9">CIS RHEL 9</option><option value="pci-dss4">PCI-DSS 4.0</option></select></div>
</div>
<div class="card"><h3 style="margin-top:0">Heatmap <span style="color:var(--dim);font-size:12px;font-weight:400">&mdash; hosts / issues at a glance</span></h3>
<div class="toolbar">
<select id="hmmode" onchange="loadHeatmap()" style="max-width:180px"><option value="host">by host</option><option value="issue">by issue</option></select>
<button style="margin:0" onclick="loadHeatmap()">Refresh</button>
</div>
<div id="hmlegend" class="note"></div>
<div id="heatmap" class="heatmap"><div class="hmempty">loading&hellip;</div></div>
<div id="heatdetail" class="hist" style="margin-top:8px"></div>
</div>
<div class="card"><h3 style="margin-top:0">Scan schedules</h3>
<div class="row" style="grid-template-columns:1fr 1fr 140px 120px">
<div><label>Host</label><select id="schedhost"></select></div>
<div><label>Name</label><input id="schedname" placeholder="nightly"></div>
<div><label>Cron</label><input id="schedcron" value="0 3 * * *"></div>
<div><label>Notify</label><select id="schednotify"><option value="regression">regression</option><option value="threshold">threshold</option><option value="always">always</option><option value="never">never</option></select></div>
</div>
<div class="row" style="grid-template-columns:1fr 120px">
<div><label>Webhook URL (optional, stored server-side, never shown)</label><input id="schedhook" placeholder="https://hooks.example.com/..."></div>
<div><label>Min index</label><input id="schedmin" placeholder="70"></div>
</div>
<button onclick="addSched()">Add schedule</button>
<div id="scheds" class="hist" style="margin-top:10px">loading&hellip;</div>
</div>
<div class="card"><h3 style="margin-top:0">Compare reports <span style="color:var(--dim);font-size:12px;font-weight:400">&mdash; pick any two runs for a host</span></h3>
<div class="row" style="grid-template-columns:1fr 1fr 1fr 130px">
<div><label>Host</label><select id="cmpHost" onchange="loadCompareReports()"><option value="">all saved reports</option></select></div>
<div><label>Baseline (A)</label><select id="cmpA"></select></div>
<div><label>Current (B)</label><select id="cmpB"></select></div>
<div><label>&nbsp;</label><button id="cmpGo" style="margin:0" onclick="runDiff()" disabled>Compare</button></div>
</div>
<div class="note">Checks are matched by test ID; the newest 200 reports for the selected host are listed. The A/B shortcuts in Saved reports prefill these selectors.</div>
<div class="toolbar"><button style="margin:0" onclick="loadCompareHosts()">Refresh list</button></div>
<div id="cmpstat" class="hist"></div><div id="cmpout"></div></div>
<div class="card"><h3 style="margin-top:0">Saved reports (persisted)</h3>
<div class="toolbar"><button style="margin:0" onclick="loadReports()">Refresh</button></div>
<div id="reps" class="hist">loading&hellip;</div><div id="diff"></div></div>
<div class="card"><h3 style="margin-top:0">Saved hosts</h3>
<div class="row" style="grid-template-columns:1fr 1fr 1fr 100px 110px">
<div><label>Name</label><input id="hname" placeholder="prod-web-01"></div>
<div><label>Hostname / IP</label><input id="hhost" placeholder="192.168.1.100"></div>
<div><label>SSH username</label><input id="huser" placeholder="admin"></div>
<div><label>Port</label><input id="hport" value="22"></div>
<div><label>Auth</label><select id="hauth"><option value="password">password</option><option value="key">key</option></select></div>
</div>
<button onclick="addHost()">Add host</button>
<div id="hosts" class="hist" style="margin-top:10px">loading&hellip;</div>
<div style="margin-top:10px"><label>Private key for selected host (write-only, stored 0600, never readable back)</label>
<div class="toolbar"><select id="keyhost"></select></div>
<textarea id="keytext" rows="4" style="width:100%;background:#0d1117;border:1px solid var(--line);color:var(--txt);border-radius:6px" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
<div class="toolbar"><button style="margin:0" onclick="putKey()">Save key</button>
<button style="margin:0" onclick="delKey()">Delete key</button></div></div>
</div>
<div id="result"></div>
</div>
<script>
let cur=null,timer=null,rangeTimer=null,rangeJobs=[],rangeReports={},rangeSummary="";
let TOK=sessionStorage.getItem("auditless_tok")||"";
async function api(p,o){o=o||{};o.headers=Object.assign({},o.headers||{});
 if(TOK)o.headers["Authorization"]="Bearer "+TOK;
 const r=await fetch(p,o);let j=null;
 try{j=await r.json()}catch(e){j={detail:r.status}}
 if(r.status===401){tokbar(true);throw new Error("API token required")}
 if(!r.ok)throw new Error((j&&(j.detail||j.error))||r.status);return j}
function tokbar(show){document.getElementById("tokbar").style.display=show?"block":"none"}
function saveTok(){TOK=tokinput.value;sessionStorage.setItem("auditless_tok",TOK);
 tokbar(false);loadHosts();loadReports();loadHist()}
function clearTok(){TOK="";sessionStorage.removeItem("auditless_tok");tokinput.value=""}
async function startScan(){
 clearInterval(rangeTimer);
 const net=document.getElementById("net").value.trim();
 if(net){await startRangeScan(net);return}
 const hs=hostsel.value;
 const b=hs?{host_id:hs}:{hostname:host.value,username:user.value,
  port:parseInt(port.value||"22",10)};
 if(pass.value)b.password=pass.value;
 if(!hs)b.port=parseInt(port.value||"22",10);
 Object.assign(b,{strict_host_key_checking:strict.checked,
  enable_rootkit_scan:rootkit.checked,check_package_hygiene:hygiene.checked});
 pass.value="";status("starting&hellip;");
 try{const j=await api("/api/scans",{method:"POST",
  headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});
  cur=j.id;go.disabled=true;status(esc(j.progress||"queued")+"&hellip;", j.log||"", true);poll();}
 catch(e){status('<span class="err">'+esc(e.message)+"</span>")}}
async function startRangeScan(net){
 clearInterval(timer);
 const b={network:net,username:user.value,
  port:parseInt(port.value||"22",10),
  strict_host_key_checking:strict.checked,
  enable_rootkit_scan:rootkit.checked,check_package_hygiene:hygiene.checked};
 if(pass.value)b.password=pass.value;
 pass.value="";go.disabled=true;
 status("probing "+esc(net)+"&hellip;");
 try{
  const j=await api("/api/scans/range",{method:"POST",
   headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});
  rangeJobs=j.jobs||[];rangeReports={};
  if(!rangeJobs.length){
   status("no hosts with SSH open in "+esc(net));
   go.disabled=false;loadHist();return}
  rangeSummary="probed "+j.candidates+" addresses &mdash; "+j.discovered+
   " with SSH open, "+rangeJobs.length+" scans launched";
  status(rangeSummary);
  renderRangeTable();pollRange();
 }catch(e){go.disabled=false;status('<span class="err">'+esc(e.message)+"</span>")}}
function renderRangeTable(){
 document.getElementById("status").innerHTML=
  "<div style='margin-bottom:8px'>"+rangeSummary+"</div>"+
  "<table><tr><th>Host</th><th>Status</th><th>Index</th><th></th></tr>"+
  rangeJobs.map((x,i)=>`<tr id="rj${i}"><td>${esc(x.host)}</td>`+
   `<td>queued</td><td>&ndash;</td><td><a onclick="showRangeLog(${i})">log</a></td></tr>`).join("")+"</table>"+
  "<div id='rangelog'></div>"}
async function pollRange(){
 clearInterval(rangeTimer);
 rangeTimer=setInterval(async()=>{
  const pending=rangeJobs.map((x,i)=>({x,i})).filter(({x})=>!x._done);
  if(!pending.length){
   clearInterval(rangeTimer);go.disabled=false;loadHist();return}
  await Promise.all(pending.map(async({x,i})=>{
   try{
    const j=await api("/api/scans/"+x.job_id);
    const row=document.getElementById("rj"+i);if(!row)return;
    const cells=row.children;
    cells[1].textContent=j.progress||j.status;
    x._last=j;
    if(j.status==="done"){
     x._done=true;rangeReports[x.job_id]=j.report;
     cells[1].textContent="done";
     const s=(j.report&&j.report.summary)||{};
     cells[2].textContent=s.hardening_index??"\u2013";
     cells[3].innerHTML='<a onclick="showRangeReport(\\''+esc(x.job_id)+'\\')">view</a> <a onclick="showRangeLog('+i+')">log</a>';
    }else if(j.status==="error"){
     x._done=true;cells[1].innerHTML='<span class="err">'+esc(j.error||"failed")+"</span>";
     cells[3].innerHTML='<a onclick="showRangeLog('+i+')">log</a>';
    }else{
     cells[3].innerHTML='<a onclick="showRangeLog('+i+')">log</a>';
    }
   }catch(e){/* transient poll error: retry next tick */}
  }));
 },1500)}
function showRangeReport(id){const r=rangeReports[id];if(r)render(r)}
async function showRangeLog(i){
 const x=rangeJobs[i];if(!x)return;
 try{
  const j=x._last||await api("/api/scans/"+x.job_id);
  x._last=j;
  const box=document.getElementById("rangelog");
  box.innerHTML="<h4 style='margin:8px 0 4px'>"+esc(x.host)+" session output</h4>"+renderLog(j.log||"(no output yet)", true);
 }catch(e){document.getElementById("rangelog").innerHTML='<span class="err">'+esc(e.message)+"</span>"}
}
function hostPick(){const d=!!hostsel.value;
 [host,user,port].forEach(i=>i.disabled=d)}
async function poll(){
 clearInterval(timer);
 timer=setInterval(async()=>{
  try{const j=await api("/api/scans/"+cur);
   if(j.status==="running"||j.status==="queued"){status(esc(j.progress||j.status)+"&hellip;", j.log||"", true);return}
   clearInterval(timer);go.disabled=false;
   if(j.status==="done"){status("done", j.log||"", false);render(j.report)}else{status('<span class="err">'+esc(j.error||"failed")+"</span>", j.log||"", true)}
   loadHist();
  }catch(e){clearInterval(timer);go.disabled=false;status('<span class="err">'+esc(e.message)+"</span>")}
 },1200)}
function renderLog(log, open){
 if(!log)return"";
 const attr=open?" open":"";
 return `<details class="logbox"${attr}><summary>Session output</summary><pre>${esc(log)}</pre></details>`;
}
function status(h, log, open){
 document.getElementById("status").innerHTML=h+(log?renderLog(log, open):"");
}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}
function lvl(i){return i>=90?"pass":i>=75?"pass":i>=60?"warn":"fail"}
async function loadHist(){
 try{const h=await api("/api/scans");
  document.getElementById("hist").innerHTML=h.length?h.map(j=>
   `<div><a onclick="show('${j.id}')">${esc(j.hostname)}</a> &mdash; ${j.status}`+
   (j.hardening_index!=null?` &mdash; <b>${j.hardening_index}/100</b>`:"")+
   (j.error?` &mdash; <span class="err">${esc(j.error.slice(0,80))}</span>`:"")+"</div>").join("")
  :"no scans yet";}
 catch(e){document.getElementById("hist").textContent="unavailable"}}
async function show(id){cur=id;const j=await api("/api/scans/"+id);
 if(j.status==="done"){status("done", j.log||"", false);render(j.report);}
 else if(j.status==="error"){status('<span class="err">'+esc(j.error||"failed")+"</span>", j.log||"", true)}
 else status(esc(j.progress||j.status)+"&hellip;", j.log||"", true)}
let cmpData=[];
function cmpLabel(x){const when=x.finished_at||x.created_at;
 const ts=when?new Date(when*1000).toLocaleString():"unknown time";
 return (x.hostname||"?")+" \u2014 "+ts+" \u2014 "+(x.hardening_index??"?")+"/100"}
async function loadCompareHosts(){
 try{const h=await api("/api/hosts");
  const sel=document.getElementById("cmpHost");
  const cur=sel.value;
  sel.innerHTML='<option value="">all saved reports</option>'+
   h.map(x=>`<option value="${esc(x.id)}">${esc(x.name)} (${esc(x.hostname)})</option>`).join("");
  if([...sel.options].some(o=>o.value===cur))sel.value=cur;
 }catch(e){document.getElementById("cmpstat").textContent="hosts unavailable"}
 await loadCompareReports()}
async function loadCompareReports(){
 const host=document.getElementById("cmpHost").value;
 const a=document.getElementById("cmpA"),b=document.getElementById("cmpB");
 const prevA=a.value,prevB=b.value;
 try{
  const q=host?"&host_id="+encodeURIComponent(host):"";
  cmpData=await api("/api/reports?limit=200"+q);
 }catch(e){cmpData=[]}
 const opts=cmpData.map(x=>`<option value="${esc(x.id)}">${esc(cmpLabel(x))}</option>`).join("");
 a.innerHTML=opts;b.innerHTML=opts;
 const ids=cmpData.map(x=>x.id);
 a.value=ids.includes(prevA)?prevA:(ids.length>1?ids[1]:(ids[0]||""));
 b.value=ids.includes(prevB)?prevB:(ids[0]||"");
 document.getElementById("cmpGo").disabled=cmpData.length<2;
 const stat=document.getElementById("cmpstat");
 if(!cmpData.length){stat.textContent="no saved reports for this selection";
  document.getElementById("cmpout").innerHTML=""}
 else if(cmpData.length===1){stat.textContent="one report \u2014 scan again to compare";
  document.getElementById("cmpout").innerHTML=""}
 else stat.textContent=cmpData.length+" reports available"}
async function addCmpOption(sel,id){
 if([...sel.options].some(o=>o.value===id))return true;
 try{
  const r=await api("/api/reports/"+encodeURIComponent(id));
  const o=document.createElement("option");
  o.value=id;o.textContent=cmpLabel(r);sel.appendChild(o);return true;
 }catch(e){return false}}
async function loadHosts(){
 try{const h=await api("/api/hosts");
  hostsel.innerHTML='<option value="">manual entry</option>'+h.map(x=>
   `<option value="${x.id}">${esc(x.name)} (${esc(x.hostname)})${x.auth==="key"?" [key]":""}</option>`).join("");
  keyhost.innerHTML=h.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join("");
  document.getElementById("hosts").innerHTML=h.length?h.map(x=>
   `<div>${esc(x.name)} &mdash; ${esc(x.username)}@${esc(x.hostname)}:${x.port}`+
   ` [${x.auth}${x.has_key?", key stored":""}] `+
   `<a onclick="scanHost('${x.id}')">scan</a> `+
   `<a onclick="delHost('${x.id}')">delete</a></div>`).join(""):"no saved hosts yet";}
 catch(e){document.getElementById("hosts").textContent="unavailable"}}
async function addHost(){
 const b={name:hname.value,hostname:hhost.value,username:huser.value,
  port:parseInt(hport.value||"22",10),auth:hauth.value};
 try{await api("/api/hosts",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify(b)});
  hname.value=hhost.value=huser.value="";loadHosts();}
 catch(e){status('<span class="err">'+esc(e.message)+"</span>")}}
async function delHost(id){await api("/api/hosts/"+id,{method:"DELETE"});loadHosts()}
async function scanHost(id){hostsel.value=id;hostPick();window.scrollTo(0,0)}
async function putKey(){
 try{await api("/api/hosts/"+keyhost.value+"/key",{method:"PUT",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({key:keytext.value})});
  keytext.value="";loadHosts();status("key stored (0600, never readable back)");}
 catch(e){status('<span class="err">'+esc(e.message)+"</span>")}}
async function delKey(){await api("/api/hosts/"+keyhost.value+"/key",{method:"DELETE"});loadHosts()}
async function scanFleet(){
 const pw=prompt("SSH/sudo password for password-auth hosts (empty if all key auth):","")||"";
 const r=await api("/api/fleet/scan",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({password:pw})});
 status("launched "+r.jobs.length+" scans (bounded pool)");loadHist();}
async function loadTokens(){
 try{const t=await api("/api/tokens");
  document.getElementById("toks").innerHTML=t.length?t.map(x=>
   `<div>${esc(x.name)} &mdash; last used: ${x.last_used?new Date(x.last_used*1000).toLocaleString():"never"} `+
   `<a onclick="delToken('${x.id}')">revoke</a></div>`).join(""):"no named tokens";}
 catch(e){document.getElementById("toks").textContent="unavailable"}}
async function addToken(){
 const t=await api("/api/tokens",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({name:tokname.value})});
 document.getElementById("tokout").innerHTML=
  `<b>Copy now — shown exactly once:</b> <code>${esc(t.token)}</code>`;
 tokname.value="";loadTokens()}
async function delToken(id){await api("/api/tokens/"+id,{method:"DELETE"});loadTokens()}
async function loadAudit(){
 try{const a=await api("/api/audit?limit=50");
  document.getElementById("audit").innerHTML=a.length?a.map(x=>
   `<div>${new Date(x.ts*1000).toLocaleString()} &mdash; <b>${esc(x.actor)}</b> `+
   `${esc(x.action)} ${esc(x.target_type)}:${esc(x.target_id)} `+
   `<span style="color:var(--dim)">${esc((x.detail||"").slice(0,80))}</span></div>`).join(""):"no audit records";}
 catch(e){document.getElementById("audit").textContent="unavailable"}}
async function verifyAudit(){
 const v=await api("/api/audit/verify");
 document.getElementById("audstat").innerHTML=v.ok?
  `<span class="pass">chain valid (${v.checked} records)</span>`:
  `<span class="err">BROKEN at record ${v.broken_at} (${v.checked} verified)</span>`}
async function loadFleet(){
 try{const f=await api("/api/fleet");
  document.getElementById("fleet").innerHTML=f.length?("<table><tr><th>Host</th>"+
   "<th>Latest</th><th>Reports</th><th></th></tr>"+f.map(x=>
   `<tr><td>${esc(x.name)}<br><span style="color:var(--dim)">${esc(x.hostname)}</span></td>`+
   `<td class="${lvl(x.latest_index||0)}"><b>${x.latest_index??"&ndash;"}</b></td>`+
   `<td>${x.total_reports}</td>`+
   `<td><a onclick="showTrend('${x.host_id}','${esc(x.name)}')">trend</a></td></tr>`).join("")+
   "</table>"):"no saved hosts yet";}
 catch(e){document.getElementById("fleet").textContent="unavailable"}}
async function showTrend(id,name){
 const t=await api("/api/hosts/"+id+"/trend?limit=100");
 const el=document.getElementById("trend");
 if(!t.length){el.innerHTML="<p class='hist'>no reports yet for "+esc(name)+"</p>";return}
 const W=520,H=160,P=28,vals=t.map(x=>x.hardening_index??0);
 const pts=vals.map((v,i)=>[P+i*(W-2*P)/Math.max(1,vals.length-1),H-P-v/100*(H-2*P)]);
 el.innerHTML=`<h4>${esc(name)} hardening trend</h4>`+
  `<svg width="${W}" height="${H}" style="background:#0d1117;border:1px solid var(--line);border-radius:6px">`+
  `<line x1="${P}" y1="${H-P}" x2="${W-P}" y2="${H-P}" stroke="#30363d"/>`+
  `<polyline fill="none" stroke="#58a6ff" stroke-width="2" points="${pts.map(p=>p.join(",")).join(" ")}"/>`+
  pts.map((p,i)=>`<circle cx="${p[0]}" cy="${p[1]}" r="3" fill="${vals[i]>=75?"#3fb950":vals[i]>=60?"#d29922":"#f85149"}"><title>${vals[i]} @ ${esc(t[i].report_id||"")}</title></circle>`).join("")+
  `</svg>`}
let hmData=null,hmMode="host";
function hmTreemap(items,x,y,w,h,out){
 items=(items||[]).filter(i=>i&&i.value>0).slice().sort((a,b)=>b.value-a.value);
 const total=items.reduce((s,i)=>s+i.value,0);
 if(!total||w<=0||h<=0)return out;
 if(items.length===1){out.push({item:items[0],x:x,y:y,w:w,h:h});return out}
 let acc=0,i=0;
 while(i<items.length-1&&acc+items[i].value<total/2){acc+=items[i].value;i++}
 if(i===0){i=1;acc=items[0].value}
 const a=items.slice(0,i),b=items.slice(i);
 if(w>=h){const wa=w*acc/total;hmTreemap(a,x,y,wa,h,out);hmTreemap(b,x+wa,y,w-wa,h,out)}
 else{const ha=h*acc/total;hmTreemap(a,x,y,w,ha,out);hmTreemap(b,x,y+ha,w,h-ha,out)}
 return out}
async function loadHeatmap(){
 const el=document.getElementById("heatmap");
 const mode=document.getElementById("hmmode").value;
 try{
  const data=await api("/api/fleet/heatmap?mode="+encodeURIComponent(mode));
  hmData=data;hmMode=mode;hmRender(el);
 }catch(e){el.innerHTML='<div class="hmempty">unavailable</div>'}}
function hmRender(el){
 el=el||document.getElementById("heatmap");
 el.innerHTML="";
 if(!hmData)return;
 const groups=(hmData.groups||[]).filter(g=>g.tiles&&g.tiles.length);
 if(!groups.length){
  el.innerHTML='<div class="hmempty">no reports yet &mdash; scan a host to populate the heatmap</div>';
  document.getElementById("hmlegend").textContent="";return}
 document.getElementById("hmlegend").textContent=hmMode==="host"
  ?"size = findings + 1 · colour = hardening index · click a tile for trend"
  :"size = weighted findings · colour = worst status · click a tile for impact";
 const W=Math.max(320,el.clientWidth||900),H=Math.max(200,el.clientHeight||420);
 const nodes=groups.map(g=>({g:g,value:g.tiles.reduce((s,t)=>s+Math.max(1,t.value||0),0)}));
 const laid=hmTreemap(nodes,0,0,W,H,[]);
 for(const n of laid){
  const g=n.item.g;
  const gd=document.createElement("div");gd.className="hmgroup";
  gd.style.left=n.x+"px";gd.style.top=n.y+"px";
  gd.style.width=n.w+"px";gd.style.height=n.h+"px";gd.title=g.name;
  const name=document.createElement("div");name.className="hmname";
  name.textContent=g.name;gd.appendChild(name);
  const inner=document.createElement("div");
  inner.style.cssText="position:absolute;left:0;right:0;top:18px;bottom:0";
  gd.appendChild(inner);
  const tiles=hmTreemap(g.tiles,0,0,n.w,Math.max(1,n.h-18),[]);
  for(const tn of tiles){
   const t=tn.item;
   const d=document.createElement("div");d.className="hmtile";
   d.style.left=tn.x+"px";d.style.top=tn.y+"px";
   d.style.width=tn.w+"px";d.style.height=tn.h+"px";
   d.style.background=t.color||"#30363d";
   d.title=(t.label||"")+" — "+(t.sublabel||"")+"\\n"+
    (t.hosts||[]).map(x=>x.name+" ("+x.status+")").join("\\n");
   d.onclick=(function(tile){return function(){hmSelect(tile)}})(t);
   const lab=document.createElement("div");lab.className="hmlabel";
   lab.textContent=t.label||"";d.appendChild(lab);
   const sub=document.createElement("div");sub.className="hmsub";
   sub.textContent=t.sublabel||"";d.appendChild(sub);
   inner.appendChild(d)}
  el.appendChild(gd)}}
function hmSelect(t){
 const m=t.meta||{},detail=document.getElementById("heatdetail");
 if(hmMode==="host"){
  detail.textContent="";
  if(m.host_id){
   showTrend(m.host_id,t.label||m.hostname||"host");
   document.getElementById("trend").scrollIntoView({behavior:"smooth",block:"nearest"})}
  return}
 const hosts=(t.hosts||[]).map(x=>esc(x.name)+" ("+esc(x.status)+")").join(", ");
 detail.innerHTML="<b>"+esc(t.label||"")+"</b> &mdash; "+esc(t.sublabel||"")+
  (m.test_id?" <code>"+esc(m.test_id)+"</code>":"")+
  (m.category?" ["+esc(m.category)+"]":"")+"<br>"+hosts+
  (m.recommendation?"<br>"+esc(m.recommendation):"")}
window.addEventListener("resize",()=>{if(hmData)hmRender()});
async function loadScheds(){
 try{const s=await api("/api/schedules");
  const hosts=await api("/api/hosts");
  schedhost.innerHTML=hosts.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join("");
  document.getElementById("scheds").innerHTML=s.length?s.map(x=>
   `<div>${esc(x.name)} &mdash; <code>${esc(x.cron)}</code> &mdash; `+
   `${x.enabled?"enabled":"disabled"} &mdash; notify:${x.notify_on}`+
   `${x.has_webhook?" (webhook)":""} &mdash; next:${x.next_run?new Date(x.next_run*1000).toLocaleString():"?"}`+
   ` <a onclick="runSched('${x.id}')">run now</a> `+
   `<a onclick="toggleSched('${x.id}',${x.enabled?0:1})">${x.enabled?"disable":"enable"}</a> `+
   `<a onclick="delSched('${x.id}')">delete</a></div>`).join(""):"no schedules yet";}
 catch(e){document.getElementById("scheds").textContent="unavailable"}}
async function addSched(){
 const b={host_id:schedhost.value,name:schedname.value,cron:schedcron.value,
  notify_on:schednotify.value,webhook_url:schedhook.value};
 if(schedmin.value)b.min_index=parseInt(schedmin.value,10);
 try{await api("/api/schedules",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify(b)});
  schedname.value=schedhook.value=schedmin.value="";loadScheds();}
 catch(e){status('<span class="err">'+esc(e.message)+"</span>")}}
async function delSched(id){await api("/api/schedules/"+id,{method:"DELETE"});loadScheds()}
async function toggleSched(id,en){await api("/api/schedules/"+id,{method:"PATCH",
 headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled:!!en})});loadScheds()}
async function runSched(id){const j=await api("/api/schedules/"+id+"/run",{method:"POST"});
 status("manual run started: "+j.id);cur=j.id;poll();loadHist()}
async function loadReports(){
 try{const r=await api("/api/reports?limit=30");
  document.getElementById("reps").innerHTML=r.length?r.map(x=>
   `<div><a onclick="viewReport('${x.id}')">${esc(x.hostname)}</a> &mdash; ${x.status}`+
   (x.hardening_index!=null?` &mdash; <b>${x.hardening_index}/100</b>`:"")+
   ` <a onclick="setDiff('A','${x.id}')">A</a> <a onclick="setDiff('B','${x.id}')">B</a> `+
   (x.host_id?`<a onclick="showComp('${x.host_id}')">compliance</a> `:"")+
   `<a onclick="proposeFixes('${x.id}')">fix</a> `+
   `<a onclick="delReport('${x.id}')">delete</a></div>`).join(""):"no saved reports yet";}
 catch(e){document.getElementById("reps").textContent="unavailable"}}
async function viewReport(id){const r=await api("/api/reports/"+id);
 window._repHost=r.host_id||null;
 if(r.report)render(r.report);else status("report has no payload")}
async function proposeFixes(id){
 const ps=await api("/api/reports/"+id+"/remediations",{method:"POST"});
 if(!ps.length){status("no safe fixes proposed for this report");return}
 document.getElementById("diff").innerHTML="<h3>Proposed fixes (dry-run — nothing executed)</h3>"+
  ps.map(p=>`<div class="card"><b>${esc(p.title)}</b> `+
   `<span class="chip">${p.risk}</span> <span class="chip">${esc(p.test_id)} ${esc(p.item)}</span>`+
   `<p class="hist">${esc(p.description)}<br>Preconditions: ${esc(p.preconditions)}</p>`+
   `<pre>${esc(p.script.join("\\n"))}</pre>`+
   `<button onclick="approveFix('${p.proposal_id}')">Approve &amp; apply</button></div>`).join("");}
async function approveFix(pid){
 const pw=prompt("SSH/sudo password (empty for key-auth hosts):","")||"";
 const hid=window._repHost||(hostsel.value||prompt("Host id to fix:","")||"");
 if(!hid){status('<span class="err">no host selected</span>');return}
 const r=await api("/api/remediations/"+pid+"/apply",{method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({host_id:hid,password:pw})});
 const rows=r.results.map(x=>`<tr><td><code>${esc(x.command.slice(0,60))}</code></td>`+
  `<td class="${x.exit_code===0?"pass":"fail"}"><b>${x.exit_code}</b></td>`+
  `<td>${esc((x.stdout||x.stderr||"").slice(0,200))}</td></tr>`).join("");
 document.getElementById("diff").innerHTML+=
  `<h3>Apply results</h3><table><tr><th>Command</th><th>Exit</th><th>Output</th></tr>${rows}</table>`+
  `<p class="hist">Verification scan: <a onclick="show('${r.verification_job_id}')">${r.verification_job_id}</a> (polls automatically)</p>`;
 cur=r.verification_job_id;poll();loadHist();}
async function delReport(id){await api("/api/reports/"+id,{method:"DELETE"});loadReports()}
async function setDiff(which,id){
 const sel=document.getElementById(which==="A"?"cmpA":"cmpB");
 if(!(await addCmpOption(sel,id))){
  status('<span class="err">could not load report for compare</span>');return}
 sel.value=id;
 const picked=sel.options[sel.selectedIndex];
 document.getElementById("cmpstat").textContent=
  (which==="A"?"baseline A":"current B")+": "+(picked?picked.text:"");
 document.getElementById("cmpout").scrollIntoView({behavior:"smooth",block:"nearest"})}
async function showComp(hostId){
 const fw=(document.getElementById("compfw")||{}).value||"auto";
 const c=await api("/api/hosts/"+hostId+"/compliance?framework="+fw);
 const rows=c.controls.map(x=>`<tr><td>${esc(x.control)}<br><span style="color:var(--dim)">${esc(x.title)}</span></td>`+
  `<td>${x.level}</td><td class="${x.status}"><b>${esc(String(x.status).toUpperCase())}</b></td>`+
  `<td>${x.score??"n/a"}</td><td>${x.tests.map(t=>esc(t.test_id)).join(", ")}</td></tr>`).join("");
 const secs=Object.entries(c.sections).map(([k,v])=>
  `<tr><td>${esc(v.section)}</td><td class="${v.score==null?"unknown":v.score>=75?"pass":v.score>=60?"warn":"fail"}"><b>${v.score??"n/a"}</b></td><td>${v.controls}</td></tr>`).join("");
 document.getElementById("diff").innerHTML=
  `<h3>CIS compliance: <span class="score ${c.overall_score==null?"unknown":lvl(c.overall_score)}">${c.overall_score??"n/a"}/100</span></h3>`+
  `<p class="hist">${esc(c.benchmark)} &mdash; coverage ${c.coverage.mapped_checks}/${c.coverage.total_checks} checks (${c.coverage.percent}%) &mdash; ${c.extended.length} extended (non-CIS) checks</p>`+
  `<h4>By section</h4><table><tr><th>Section</th><th>Score</th><th>Controls</th></tr>${secs}</table>`+
  `<h4>Controls</h4><table><tr><th>Control</th><th>Level</th><th>Status</th><th>Score</th><th>Tests</th></tr>${rows}</table>`}
async function runDiff(){
 const a=document.getElementById("cmpA").value;
 const b=document.getElementById("cmpB").value;
 const out=document.getElementById("cmpout");
 if(!a||!b){out.innerHTML='<p class="err">pick two reports first</p>';return}
 if(a===b){out.innerHTML='<p class="err">pick two different reports</p>';return}
 try{
  const d=await api("/api/diff?from_id="+encodeURIComponent(a)+"&to_id="+encodeURIComponent(b));
  const row=x=>`<tr><td>${esc(x.test_id||"")}</td><td>${esc(x.item||"")}</td>`+
   `<td>${esc(x.category||"")}</td><td>${esc(x.from||"")}&rarr;<b>${esc(x.to||"")}</b></td></tr>`;
  const table=items=>items.length?`<table><tr><th>Test</th><th>Item</th><th>Category</th><th>Status</th></tr>`+
   items.map(row).join("")+"</table>":'<p class="hist">none</p>';
  const from=d.from||{},to=d.to||{};
  out.innerHTML=
   `<h4>${esc(from.hostname||"")} <span style="color:var(--dim)">${esc(a)}</span> &rarr; `+
   `${esc(to.hostname||"")} <span style="color:var(--dim)">${esc(b)}</span></h4>`+
   `<h4>Hardening ${d.hardening_before??"?"} &rarr; <b>${d.hardening_after??"?"}</b>`+
   ` (delta ${d.hardening_delta>=0?"+":""}${d.hardening_delta})</h4>`+
   `<h4 class="pass">Fixed (${d.fixed.length})</h4>${table(d.fixed)}`+
   `<h4 class="fail">Regressed (${d.regressed.length})</h4>${table(d.regressed)}`+
   `<h4>Changed (${(d.changed||[]).length})</h4>${table(d.changed||[])}`+
   (d.new.length?`<h4>New (${d.new.length})</h4>${table(d.new)}`:"")+
   (d.gone.length?`<h4>Gone (${d.gone.length})</h4>${table(d.gone)}`:"");
 }catch(e){out.innerHTML='<p class="err">'+esc(e.message)+"</p>"}}
function render(r){
 const s=r.summary||{};const cats=r.hardening_by_category||{};
 const el=document.getElementById("result");
 el.innerHTML=`<div class="card"><h3 style="margin-top:0">Hardening index:
  <span class="score ${lvl(s.hardening_index||0)}">${s.hardening_index??"&ndash;"}/100</span>
  <span class="${lvl(s.hardening_index||0)}">${esc(s.hardening_level||"")}</span></h3>
  <div class="chips"><span class="chip">${s.total_checks} checks</span>
  <span class="chip pass">&#9989; ${s.passed} pass</span>
  <span class="chip warn">&#9888;&#65039; ${s.warned} warn</span>
  <span class="chip fail">&#10060; ${s.failed} fail</span>
  <span class="chip">${(r.ports||{}).open||0} open ports</span></div>
  <p style="color:var(--dim);font-size:13px">${esc((r.system||{}).hostname||"")} &mdash;
  ${esc((r.system||{}).os||"")} &mdash; ${esc((r.system||{}).kernel||"")}</p></div>
  <div class="card"><h3 style="margin-top:0">By category</h3><table>
  <tr><th>Category</th><th>Index</th><th>Pass</th><th>Warn</th><th>Fail</th></tr>
  ${Object.entries(cats).map(([k,v])=>
   `<tr><td>${esc(k)}</td><td class="${lvl(v.index)}"><b>${v.index}</b></td>
   <td>${v.passed}</td><td>${v.warned}</td><td>${v.failed}</td></tr>`).join("")}</table></div>
  <div class="card"><h3 style="margin-top:0">Checks
  <button style="margin:0 0 0 12px;padding:4px 10px;font-size:12px"
   onclick="dl()">Download JSON</button></h3>
  <div class="toolbar"><select id="f" onchange="flt()"><option value="">all</option>
  <option value="fail">fail</option><option value="warn">warn</option>
  <option value="pass">pass</option><option value="unknown">unknown</option></select>
  <input id="q" placeholder="filter text or test id&hellip;" oninput="flt()"></div>
  <table id="ct"><tr><th>Status</th><th>Test</th><th>Item</th><th>Details</th><th>Fix</th></tr>
  ${(r.checks||[]).map(c=>`<tr data-s="${c.status}"
   data-t="${esc((c.item+" "+c.details+" "+(c.test_id||"")).toLowerCase())}">
   <td class="${c.status}"><b>${c.status.toUpperCase()}</b></td>
   <td>${esc(c.test_id||"")}<br><span style="color:var(--dim)">${esc(c.category||"")}</span></td>
   <td>${esc(c.item||"")}</td><td>${esc(c.details||"")}</td>
   <td>${esc(c.recommendation||"")}</td></tr>`).join("")}</table></div>`;
 window._rep=r;flt()}
function flt(){const f=(document.getElementById("f")||{}).value||"";
 const q=((document.getElementById("q")||{}).value||"").toLowerCase();
 document.querySelectorAll("#ct tr[data-s]").forEach(tr=>{
  tr.style.display=(!f||tr.dataset.s===f)&&(!q||tr.dataset.t.includes(q))?"":"none"})}
function dl(){const b=new Blob([JSON.stringify(window._rep,null,2)],
 {type:"application/json"});const a=document.createElement("a");
 a.href=URL.createObjectURL(b);a.download="auditless-report.json";a.click()}
loadHist();
loadHosts();
loadCompareHosts();
loadReports();
loadFleet();
loadHeatmap();
loadScheds();
loadTokens();
loadAudit();
</script>
</body>
</html>
"""


def _audit(
    actor: str,
    action: str,
    target_type: str = "",
    target_id: str = "",
    detail: str = "",
) -> None:
    """Best-effort operator audit record (never breaks the request)."""
    try:
        get_store().audit(actor, action, target_type, target_id, detail)
    except Exception:
        pass


def _public_job(job: ScanJob, include_report: bool = False) -> ScanJobPublic:
    data = job.summary()
    if include_report and job.status == "done":
        data["report"] = job.report
    return ScanJobPublic(**data)


app = FastAPI(
    title="Auditless API",
    description=(
        "Local web API for the Auditless Linux security scanner. "
        "The SSH password is write-only: accepted on POST /api/scans, "
        "kept in server memory for the run, and never stored or returned."
    ),
    version="1.0",
)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> str:
    """Single-page dashboard UI."""
    return INDEX_HTML


@app.get("/healthz", summary="Liveness probe")
def healthz() -> dict:
    """Confirm the server is up."""
    return {"status": "ok"}


@app.get(
    "/api/version", summary="Scanner and API version metadata", dependencies=_guarded
)
def api_version() -> dict:
    """Scanner version, API version, and supported feature flags."""
    return get_version_info()


@app.get(
    "/api/scans",
    dependencies=_guarded,
    response_model=list[ScanJobPublic],
    summary="List recent scan jobs (newest first, no credentials)",
)
def api_list_scans(
    host: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int | None = Query(default=None, ge=1, le=MAX_JOBS),
    offset: int = Query(default=0, ge=0),
) -> list[ScanJobPublic]:
    """Summaries of recent jobs; full reports only via per-job GET.

    Supports host substring, status, and created-at range filters plus
    limit/offset paging. Omitting every parameter preserves the historical
    newest-first, all-jobs response.
    """
    status = _status_filter(status, SCAN_STATUSES)
    start, end = _time_range(since, until)
    with _jobs_lock:
        jobs = [_jobs[jid] for jid in reversed(_jobs_order) if jid in _jobs]
    if host:
        needle = host.lower()
        jobs = [job for job in jobs if needle in job.hostname.lower()]
    if status is not None:
        jobs = [job for job in jobs if job.status == status]
    if start is not None:
        jobs = [job for job in jobs if job.created_at >= start]
    if end is not None:
        jobs = [job for job in jobs if job.created_at <= end]
    jobs = jobs[offset:]
    if limit is not None:
        jobs = jobs[:limit]
    return [_public_job(job) for job in jobs]


@app.post(
    "/api/scans",
    dependencies=_guarded,
    response_model=ScanJobPublic,
    status_code=201,
    summary="Start a scan (password is write-only)",
)
def api_start_scan(
    data: ScanRequest, actor: str = Depends(require_token)
) -> ScanJobPublic:
    """Register a job and run the shared CLI scan pipeline in the background.

    Poll GET /api/scans/{id} until status is done or error. Pass host_id
    to scan a saved host (password still per-request unless key auth).
    """
    host_id = data.host_id
    overrides = {
        "port": data.port,
        "timeout": data.timeout,
        "command_timeout": data.command_timeout,
        "scan_ports": data.scan_ports,
        "profile": data.profile,
        "enable_rootkit_scan": data.enable_rootkit_scan,
        "check_package_hygiene": data.check_package_hygiene,
        "strict_host_key_checking": data.strict_host_key_checking,
    }
    secret = data.password.get_secret_value() if data.password else ""
    jump_secret = data.jump_password.get_secret_value() if data.jump_password else ""
    try:
        if host_id:
            try:
                base, run_params = resolve_host_scan(
                    host_id,
                    {**overrides, "password": secret, "jump_password": jump_secret},
                )
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            params = run_params
            job = start_scan({**base, "password": secret})
        else:
            params = {
                "hostname": data.hostname,
                "username": data.username,
                "password": secret,
                "key_path": "",
                **overrides,
            }
            job = start_scan(params)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Own thread (not BackgroundTasks): deterministic under both uvicorn
    # and TestClient, whose background-task timing varies by version.
    worker = threading.Thread(
        target=_run_job, args=(job, params, host_id, actor), daemon=True
    )
    worker.start()
    return _public_job(job)


@app.post(
    "/api/scans/range",
    dependencies=_guarded,
    response_model=RangeScanResponse,
    status_code=201,
    summary="Probe a network range and scan every host with SSH open",
)
def api_range_scan(
    data: RangeScanRequest, actor: str = Depends(require_token)
) -> RangeScanResponse:
    """Discover reachable SSH hosts in a range, then scan each in parallel.

    The port probe only checks TCP reachability — no credentials are used
    until a host is confirmed open. Each launched job is independent and is
    polled through ``GET /api/scans/{id}`` like any other scan. Discovered
    hosts are not registered as saved hosts.
    """
    secret = data.password.get_secret_value() if data.password else ""
    if not data.username.strip() or not secret:
        raise HTTPException(
            status_code=400, detail="username and password are required"
        )
    try:
        candidates = parse_network(data.network, data.max_hosts)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    reachable = probe_hosts(
        candidates,
        port=data.port,
        timeout=data.probe_timeout,
        max_concurrent=data.probe_concurrency,
    )
    slots = threading.Semaphore(min(max(1, data.max_concurrent), 8))
    overrides = {
        "port": data.port,
        "timeout": data.timeout,
        "command_timeout": data.command_timeout,
        "scan_ports": data.scan_ports,
        "profile": data.profile,
        "enable_rootkit_scan": data.enable_rootkit_scan,
        "check_package_hygiene": data.check_package_hygiene,
        "strict_host_key_checking": data.strict_host_key_checking,
    }

    def _range_worker(job: ScanJob, params: dict) -> None:
        with slots:
            _run_job(job, params, None, actor)

    jobs: list[RangeJob] = []
    for host in reachable:
        params = {
            "hostname": host,
            "username": data.username,
            "password": secret,
            "key_path": "",
            **overrides,
        }
        try:
            job = start_scan(params)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        threading.Thread(target=_range_worker, args=(job, params), daemon=True).start()
        jobs.append(RangeJob(host=host, job_id=job.id))

    _audit(
        actor,
        "scan.range",
        "range",
        data.network,
        f"candidates={len(candidates)} hosts={len(jobs)}",
    )
    return RangeScanResponse(
        network=data.network,
        candidates=len(candidates),
        discovered=len(reachable),
        jobs=jobs,
    )


@app.get(
    "/api/scans/{job_id}",
    dependencies=_guarded,
    response_model=ScanJobPublic,
    summary="Job status; includes the full report once done",
)
def api_get_scan(job_id: str) -> ScanJobPublic:
    """Fetch one job; report field is present only when done."""
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown scan id")
    return _public_job(job, include_report=True)


@app.delete(
    "/api/scans/{job_id}",
    dependencies=_guarded,
    summary="Forget a job record",
)
def api_delete_scan(job_id: str, actor: str = Depends(require_token)) -> dict:
    """Remove a job from history."""
    if not delete_job(job_id):
        raise HTTPException(status_code=404, detail="unknown scan id")
    _audit(actor, "scan.delete", "scan", job_id)
    return {"deleted": job_id}


@app.get(
    "/api/scans/{job_id}/report",
    dependencies=_guarded,
    summary="Finished report in json, md or text",
)
def api_get_report(  # pylint: disable=redefined-builtin
    job_id: str, format: str = "json"
) -> Response:
    """Re-render a completed scan's stored report in the requested format."""
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown scan id")
    try:
        content, content_type = render_saved_report(job, format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(content=content, media_type=content_type)


@app.get(
    "/api/profiles",
    summary="Scan profiles discovered on this host",
    dependencies=_guarded,
)
def api_list_profiles() -> list[dict]:
    """Profile names/paths usable as the scan `profile` parameter."""
    return list_profiles()


def scan_host_now(
    host_id: str, overrides: dict, actor: str = "scheduler"
) -> tuple[ScanJob, dict | None]:
    """Run a saved-host scan synchronously with persistence (scheduler path)."""
    base, run_params = resolve_host_scan(host_id, overrides)
    job = start_scan({**base, "password": run_params.get("password", "")})
    _run_job(job, run_params, host_id, actor)
    return job, (job.report if job.status == "done" else None)


def _schedule_public(row: dict) -> SchedulePublic:
    return SchedulePublic(
        id=str(row["id"]),
        host_id=str(row["host_id"]),
        name=str(row["name"]),
        cron=str(row["cron"]),
        profile=str(row.get("profile") or ""),
        has_webhook=bool(row.get("webhook_url")),
        notify_on=str(row["notify_on"]),
        min_index=row.get("min_index"),
        enabled=int(row["enabled"]),
        last_run=row.get("last_run"),
        next_run=row.get("next_run"),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


@app.get(
    "/api/compliance/controls",
    summary="Compliance control catalogs",
    dependencies=_guarded,
)
def api_compliance_controls(framework: str = "cis-ubuntu22") -> dict:
    """Test-ID mappings per framework (best effort, unmapped listed)."""
    from .compliance import FRAMEWORKS

    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail="unknown framework")
    active = FRAMEWORKS[framework]
    return {
        "benchmark": f"{active.title} {active.version}",
        "framework": active.id,
        "frameworks": sorted(FRAMEWORKS),
        "controls": active.titles,
        "mapping": {
            tid: [{"control": c, "level": lvl} for c, lvl in mappings]
            for tid, mappings in active.mapping.items()
        },
        "unmapped": active.unmapped,
    }


@app.get(
    "/api/hosts/{host_id}/compliance",
    summary="Compliance score for a host's latest report",
    dependencies=_guarded,
)
def api_host_compliance(host_id: str, framework: str = "auto") -> dict:
    """Score the host's latest completed report (auto-detects distro)."""
    import json as _json

    from .compliance import FRAMEWORKS, compliance_summary

    if framework != "auto" and framework not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail="unknown framework")
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    latest = None
    for row in get_store().list_reports(host_id, limit=20):
        if row["status"] == "done":
            full = get_store().get_report(row["id"])
            if full and full.get("report_json"):
                latest = _json.loads(full["report_json"])
                break
    if latest is None:
        raise HTTPException(status_code=409, detail="no completed report")
    try:
        result = compliance_summary(latest, framework)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["host_id"] = host_id
    return result


def _host_public(row: dict) -> HostPublic:
    return HostPublic(
        id=str(row["id"]),
        name=str(row["name"]),
        hostname=str(row["hostname"]),
        port=int(row["port"]),
        username=str(row["username"]),
        auth=str(row["auth"]),
        has_key=int(row["has_key"]),
        jump_hostname=str(row.get("jump_hostname") or ""),
        jump_port=int(row.get("jump_port") or 22),
        jump_username=str(row.get("jump_username") or ""),
        jump_auth=str(row.get("jump_auth") or "password"),
        has_jump_key=int(row.get("has_jump_key") or 0),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


@app.get(
    "/api/hosts",
    response_model=list[HostPublic],
    summary="List saved hosts",
    dependencies=_guarded,
)
def api_list_hosts(
    host: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int | None = Query(default=None, ge=1, le=MAX_HOST_PAGE),
    offset: int = Query(default=0, ge=0),
) -> list[HostPublic]:
    """Saved hosts (metadata only; key bytes never exposed).

    Filters match host name/hostname substrings and created-at range; the
    default response still includes every saved host.
    """
    start, end = _time_range(since, until)
    rows = get_store().list_hosts(
        host=host, since=start, until=end, limit=limit, offset=offset
    )
    return [_host_public(row) for row in rows]


@app.post(
    "/api/hosts",
    dependencies=_guarded,
    response_model=HostPublic,
    status_code=201,
    summary="Register a host",
)
def api_create_host(
    data: HostCreate, actor: str = Depends(require_token)
) -> HostPublic:
    """Save a host for key auth and report history."""
    if data.auth not in ("password", "key"):
        raise HTTPException(status_code=400, detail="auth must be 'password' or 'key'")
    if data.jump_auth not in ("password", "key"):
        raise HTTPException(
            status_code=400, detail="jump_auth must be 'password' or 'key'"
        )
    try:
        row = get_store().upsert_host(
            data.name,
            data.hostname,
            data.username,
            data.port,
            data.auth,
            jump_hostname=data.jump_hostname,
            jump_port=data.jump_port,
            jump_username=data.jump_username,
            jump_auth=data.jump_auth,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit(actor, "host.create", "host", row["id"], row["hostname"])
    return _host_public(row)


@app.get(
    "/api/hosts/{host_id}",
    response_model=HostPublic,
    summary="Fetch one host",
    dependencies=_guarded,
)
def api_get_host(host_id: str) -> HostPublic:
    """Fetch host metadata (never key bytes)."""
    row = get_store().get_host(host_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown host")
    return _host_public(row)


@app.patch(
    "/api/hosts/{host_id}",
    response_model=HostPublic,
    summary="Update a host",
    dependencies=_guarded,
)
def api_update_host(
    host_id: str, data: HostUpdate, actor: str = Depends(require_token)
) -> HostPublic:
    """Partial host update; changing auth to password drops nothing else."""
    row = get_store().get_host(host_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown host")
    if data.auth is not None and data.auth not in ("password", "key"):
        raise HTTPException(status_code=400, detail="auth must be 'password' or 'key'")
    if data.jump_auth is not None and data.jump_auth not in ("password", "key"):
        raise HTTPException(
            status_code=400, detail="jump_auth must be 'password' or 'key'"
        )
    updated = get_store().upsert_host(
        data.name or row["name"],
        data.hostname or row["hostname"],
        data.username or row["username"],
        data.port if data.port is not None else row["port"],
        data.auth or row["auth"],
        host_id=host_id,
        jump_hostname=(
            data.jump_hostname
            if data.jump_hostname is not None
            else row["jump_hostname"]
        ),
        jump_port=data.jump_port if data.jump_port is not None else row["jump_port"],
        jump_username=(
            data.jump_username
            if data.jump_username is not None
            else row["jump_username"]
        ),
        jump_auth=data.jump_auth or row["jump_auth"],
    )
    _audit(actor, "host.update", "host", host_id)
    return _host_public(updated)


@app.delete(
    "/api/hosts/{host_id}", summary="Delete a host and its key", dependencies=_guarded
)
def api_delete_host(host_id: str, actor: str = Depends(require_token)) -> dict:
    """Remove a host record and any stored key material."""
    if not get_store().delete_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    _audit(actor, "host.delete", "host", host_id)
    return {"deleted": host_id}


@app.put(
    "/api/hosts/{host_id}/key",
    summary="Store a host private key",
    dependencies=_guarded,
)
def api_put_host_key(
    host_id: str,
    data: KeyUpload,
    actor: str = Depends(require_token),
    kind: str = "host",
) -> dict:
    """Save key bytes with owner-only permissions (write-only endpoint)."""
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    if not data.key.strip():
        raise HTTPException(status_code=400, detail="empty key")
    try:
        get_store().set_host_key(host_id, data.key, kind=kind)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="unknown host") from exc
    _audit(actor, f"key.store.{kind}", "host", host_id)
    return {"host_id": host_id, "has_key": True}


@app.get(
    "/api/hosts/{host_id}/key",
    summary="Key presence (never the key)",
    dependencies=_guarded,
)
def api_get_host_key(host_id: str, kind: str = "host") -> dict:
    """Whether key bytes are stored. The key itself is never returned."""
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    try:
        present = get_store().has_host_key(host_id, kind=kind)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="unknown host") from exc
    return {"host_id": host_id, "has_key": present}


@app.delete(
    "/api/hosts/{host_id}/key", summary="Remove a stored key", dependencies=_guarded
)
def api_delete_host_key(
    host_id: str, actor: str = Depends(require_token), kind: str = "host"
) -> dict:
    """Delete stored key bytes (host record kept, flag cleared)."""
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    try:
        get_store().clear_host_key(host_id, kind=kind)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="unknown host") from exc
    _audit(actor, f"key.delete.{kind}", "host", host_id)
    return {"host_id": host_id, "has_key": False}


@app.get(
    "/api/reports",
    summary="Persisted scan reports, newest first",
    dependencies=_guarded,
)
def api_list_reports(
    host_id: str | None = None,
    host: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_REPORT_PAGE),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """Stored report summaries, optionally filtered by host, status or time.

    ``host_id`` matches a saved host exactly; ``host`` matches a hostname
    substring. Defaults keep the historical newest-first 50-row response.
    """
    status = _status_filter(status, REPORT_STATUSES)
    start, end = _time_range(since, until)
    return get_store().list_reports(
        host_id,
        limit=limit,
        offset=offset,
        status=status,
        host=host,
        since=start,
        until=end,
    )


@app.get(
    "/api/reports/{report_id}",
    summary="Fetch one persisted report",
    dependencies=_guarded,
)
def api_get_stored_report(report_id: str) -> dict:
    """Full stored report including the JSON payload."""
    import json as _json

    row = get_store().get_report(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown report")
    payload = dict(row)
    if payload.get("report_json"):
        payload["report"] = _json.loads(payload["report_json"])
    del payload["report_json"]
    return payload


@app.delete(
    "/api/reports/{report_id}",
    summary="Forget a persisted report",
    dependencies=_guarded,
)
def api_delete_stored_report(
    report_id: str, actor: str = Depends(require_token)
) -> dict:
    """Remove a stored report."""
    if not get_store().delete_report(report_id):
        raise HTTPException(status_code=404, detail="unknown report")
    _audit(actor, "report.delete", "report", report_id)
    return {"deleted": report_id}


@app.get(
    "/api/reports/{report_id}/report",
    summary="Persisted report re-rendered",
    dependencies=_guarded,
)
def api_get_stored_report_rendered(
    report_id: str, format: str = "json"  # pylint: disable=redefined-builtin
) -> Response:
    """Stored report rendered as json, md or text."""
    import json as _json

    row = get_store().get_report(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown report")
    if not row.get("report_json"):
        raise HTTPException(status_code=409, detail="scan did not complete")
    try:
        content, content_type = render_report_dict(
            _json.loads(row["report_json"]), format
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(content=content, media_type=content_type)


@app.get(
    "/api/diff", summary="Diff two reports (fixed vs regressed)", dependencies=_guarded
)
def api_diff_reports(from_id: str, to_id: str) -> dict:
    """Check-by-check progress between two stored reports."""
    import json as _json

    rows = [get_store().get_report(rid) for rid in (from_id, to_id)]
    if rows[0] is None or rows[1] is None:
        raise HTTPException(status_code=404, detail="unknown report id")
    if not rows[0].get("report_json") or not rows[1].get("report_json"):
        raise HTTPException(status_code=409, detail="report incomplete")
    result = diff_reports(
        _json.loads(rows[0]["report_json"]), _json.loads(rows[1]["report_json"])
    )
    result["from"] = {"id": from_id, "hostname": rows[0]["hostname"]}
    result["to"] = {"id": to_id, "hostname": rows[1]["hostname"]}
    return result


@app.get(
    "/api/schedules",
    response_model=list[SchedulePublic],
    summary="List scan schedules",
    dependencies=_guarded,
)
def api_list_schedules() -> list[SchedulePublic]:
    """Unattended scan schedules (webhook URLs never exposed)."""
    return [_schedule_public(row) for row in get_store().list_schedules()]


@app.post(
    "/api/schedules",
    response_model=SchedulePublic,
    status_code=201,
    summary="Create a scan schedule",
    dependencies=_guarded,
)
def api_create_schedule(
    data: ScheduleCreate, actor: str = Depends(require_token)
) -> SchedulePublic:
    """Schedule recurring scans for a saved host (cron validated)."""
    try:
        row = get_store().create_schedule(
            data.host_id,
            data.name,
            data.cron,
            data.profile,
            data.webhook_url,
            data.notify_on,
            data.min_index,
            data.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _audit(actor, "schedule.create", "schedule", row["id"], row["name"])
    return _schedule_public(row)


@app.get(
    "/api/schedules/{schedule_id}",
    response_model=SchedulePublic,
    summary="Fetch one schedule",
    dependencies=_guarded,
)
def api_get_schedule(schedule_id: str) -> SchedulePublic:
    """Fetch schedule metadata (never the webhook URL)."""
    row = get_store().get_schedule(schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown schedule")
    return _schedule_public(row)


@app.patch(
    "/api/schedules/{schedule_id}",
    response_model=SchedulePublic,
    summary="Update a schedule",
    dependencies=_guarded,
)
def api_update_schedule(
    schedule_id: str, data: ScheduleUpdate, actor: str = Depends(require_token)
) -> SchedulePublic:
    """Partial update; changing cron recomputes the next run."""
    try:
        row = get_store().update_schedule(
            schedule_id,
            **{k: v for k, v in data.model_dump().items() if v is not None},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="unknown schedule")
    _audit(actor, "schedule.update", "schedule", schedule_id)
    return _schedule_public(row)


@app.delete(
    "/api/schedules/{schedule_id}", summary="Delete a schedule", dependencies=_guarded
)
def api_delete_schedule(schedule_id: str, actor: str = Depends(require_token)) -> dict:
    """Remove an unattended schedule."""
    if not get_store().delete_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="unknown schedule")
    _audit(actor, "schedule.delete", "schedule", schedule_id)
    return {"deleted": schedule_id}


@app.post(
    "/api/schedules/{schedule_id}/run",
    response_model=ScanJobPublic,
    status_code=201,
    summary="Trigger a scheduled scan now",
    dependencies=_guarded,
)
def api_run_schedule_now(
    schedule_id: str, actor: str = Depends(require_token)
) -> ScanJobPublic:
    """Run a schedule's host immediately (same pipeline, persisted)."""
    row = get_store().get_schedule(schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown schedule")
    try:
        job, _ = scan_host_now(
            row["host_id"], {"profile": row.get("profile") or ""}, actor
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _public_job(job, include_report=True)


@app.get(
    "/api/hosts/{host_id}/trend",
    summary="Hardening-index history for a host",
    dependencies=_guarded,
)
def api_host_trend(host_id: str, limit: int = 100) -> list[dict]:
    """Chronological hardening scores for charting progress."""
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    rows = get_store().list_reports(host_id, max(1, min(limit, 500)))
    return [
        {
            "report_id": r["id"],
            "created_at": r["created_at"],
            "hardening_index": r["hardening_index"],
            "status": r["status"],
        }
        for r in reversed(rows)
    ]


@app.post(
    "/api/maintenance/backup",
    summary="Snapshot the database",
    dependencies=_guarded,
)
def api_backup(actor: str = Depends(require_token)) -> dict:
    """Best-effort SQLite snapshot (pruned server-side)."""
    dest = get_store().backup()
    _audit(actor, "maintenance.backup", "backup", dest.name)
    return {"path": dest.name, "bytes": dest.stat().st_size}


@app.get(
    "/api/remediations",
    summary="Remediation catalog (dry-run scripts)",
    dependencies=_guarded,
)
def api_remediation_catalog() -> list[dict]:
    """All available fixes with their exact scripts (nothing executes)."""
    from .remediations import REMEDIATIONS

    return [
        {
            "id": r.id,
            "title": r.title,
            "risk": r.risk,
            "description": r.description,
            "preconditions": r.preconditions,
            "test_ids": r.test_ids,
            "script": list(r.script),
        }
        for r in REMEDIATIONS
    ]


class RemediationApply(BaseModel):
    """Approval to execute a proposal on a host (password write-only)."""

    host_id: str
    password: SecretStr | None = Field(
        default=None,
        description="SSH/sudo password (memory-only; key hosts may omit).",
    )


@app.post(
    "/api/reports/{report_id}/remediations",
    summary="Propose fixes for a report (dry-run)",
    dependencies=_guarded,
)
def api_propose_remediations(report_id: str) -> list[dict]:
    """Match failed checks to catalog entries; returns scripts, runs nothing."""
    import json as _json
    import uuid as _uuid

    from .remediations import propose_for_report

    row = get_store().get_report(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown report")
    if not row.get("report_json"):
        raise HTTPException(status_code=409, detail="report incomplete")
    proposals = []
    for proposal in propose_for_report(_json.loads(row["report_json"])):
        proposal = dict(proposal)
        proposal["proposal_id"] = _uuid.uuid4().hex[:12]
        proposal["report_id"] = report_id
        with _proposals_lock:
            _proposals[proposal["proposal_id"]] = proposal
        proposals.append(proposal)
    return proposals


@app.post(
    "/api/remediations/{proposal_id}/apply",
    summary="Approve and execute a fix, then verify",
    dependencies=_guarded,
)
def api_apply_remediation(
    proposal_id: str, data: RemediationApply, actor: str = Depends(require_token)
) -> dict:
    """Execute the proposal script over SSH, then start a verify rescan.

    Returns per-command results plus the verification job id; poll the
    job and diff to prove the finding flipped.
    """
    from .checks import _run, reset_command_cache
    from .ssh_client import SSHSession, invalidate_sessions

    with _proposals_lock:
        proposal = _proposals.get(proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="unknown proposal")
    try:
        base, run_params = resolve_host_scan(
            data.host_id,
            {"password": data.password.get_secret_value() if data.password else ""},
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    password = run_params.get("password", "")
    results = []
    try:
        with SSHSession(
            hostname=base["hostname"],
            username=base["username"],
            password=password,
            port=base["port"],
            timeout=10.0,
            key_path=base.get("key_path") or None,
        ) as ssh:
            reset_command_cache()
            for line in proposal["script"]:
                code, out, err = _run(ssh, line, password, use_cache=False)
                results.append(
                    {
                        "command": line,
                        "exit_code": code,
                        "stdout": out[-500:],
                        "stderr": err[-500:],
                    }
                )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"apply failed: {exc}") from exc

    # The fix may restart services (sshd); drop pooled sessions so the
    # verification rescan redials instead of racing a dying connection.
    invalidate_sessions(base["hostname"], base["port"], base["username"])

    job = start_scan({**base, "password": password})
    worker = threading.Thread(
        target=_run_job, args=(job, {**run_params}, data.host_id, actor)
    )
    worker.daemon = True
    worker.start()
    _audit(
        actor,
        "remediation.apply",
        "remediation",
        proposal_id,
        proposal["remediation_id"],
    )
    return {"results": results, "verification_job_id": job.id}


class FleetScanRequest(BaseModel):
    """Launch scans across many hosts with bounded concurrency."""

    host_ids: list[str] | None = Field(
        default=None, description="Hosts to scan; default all saved hosts."
    )
    password: SecretStr | None = Field(
        default=None,
        description="SSH/sudo password applied to every target (memory-only).",
    )
    max_concurrent: int = Field(
        default=4, ge=1, le=8, description="Cap simultaneous scans."
    )


@app.post(
    "/api/fleet/scan",
    summary="Scan many hosts in parallel",
    dependencies=_guarded,
)
def api_fleet_scan(data: FleetScanRequest, actor: str = Depends(require_token)) -> dict:
    """Start one persisted scan per host (bounded pool); returns job ids."""
    store = get_store()
    targets = (
        [store.get_host(hid) for hid in (data.host_ids or [])]
        if data.host_ids is not None
        else store.list_hosts()
    )
    if data.host_ids is not None and any(h is None for h in targets):
        raise HTTPException(status_code=404, detail="unknown host id")
    hosts = [h for h in targets if h is not None]
    secret = data.password.get_secret_value() if data.password else ""
    slots = threading.Semaphore(min(max(1, data.max_concurrent), 8))

    def _fleet_worker(job: ScanJob, params: dict, host_id: str, job_actor: str) -> None:
        with slots:
            _run_job(job, params, host_id, job_actor)

    launched = []
    for host in hosts:
        try:
            base, run_params = resolve_host_scan(host["id"], {"password": secret})
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        job = start_scan({**base, "password": secret})
        worker = threading.Thread(
            target=_fleet_worker,
            args=(job, run_params, host["id"], actor),
            daemon=True,
        )
        worker.start()
        launched.append({"host_id": host["id"], "job_id": job.id})
    _audit(actor, "fleet.scan", "fleet", "", f"hosts={len(launched)}")
    return {"jobs": launched}


@app.get(
    "/api/fleet", summary="Fleet overview: latest score per host", dependencies=_guarded
)
def api_fleet() -> list[dict]:
    """One row per saved host with its latest hardening index."""
    fleet = []
    for host in get_store().list_hosts():
        rows = get_store().list_reports(host["id"], limit=1)
        latest = rows[0] if rows else None
        fleet.append(
            {
                "host_id": host["id"],
                "name": host["name"],
                "hostname": host["hostname"],
                "latest_index": latest["hardening_index"] if latest else None,
                "latest_report_id": latest["id"] if latest else None,
                "latest_at": latest["created_at"] if latest else None,
                "total_reports": len(get_store().list_reports(host["id"], limit=1000)),
            }
        )
    return fleet


@app.get(
    "/api/fleet/heatmap",
    dependencies=_guarded,
    response_model=HeatmapResponse,
    summary="Treemap data for saved hosts or fleet-wide issues",
)
def api_fleet_heatmap(mode: str = "host") -> HeatmapResponse:
    """Aggregate the latest report per host into grouped heatmap tiles.

    ``mode=host`` sizes tiles by finding weight and colours by hardening
    index; ``mode=issue`` aggregates checks across hosts by category. Raw
    check details never leave this endpoint (only labels and counts).
    """
    if mode not in ("host", "issue"):
        raise HTTPException(status_code=400, detail="mode must be 'host' or 'issue'")
    store = get_store()
    hosts = store.list_hosts()
    latest: dict[str, dict] = {}
    for host in hosts:
        rows = store.list_reports(host["id"], limit=1)
        if not rows:
            continue
        row = store.get_report(rows[0]["id"])
        raw = (row or {}).get("report_json")
        if not raw:
            continue
        with contextlib.suppress(TypeError, ValueError):
            payload = json.loads(raw)
            if isinstance(payload, dict):
                latest[host["id"]] = payload
    return HeatmapResponse(**build_heatmap(hosts, latest, mode))


class TokenCreate(BaseModel):
    """Name for a new API token (plaintext returned exactly once)."""

    name: str = Field(examples=["ci-pipeline"])


class RotateRequest(BaseModel):
    """Rotate data encryption to a new master key (both write-only)."""

    current_key: SecretStr = Field(description="Key the data is under now.")
    new_key: SecretStr = Field(description="Key to re-encrypt everything to.")


@app.post(
    "/api/tokens",
    summary="Create a named API token",
    dependencies=_guarded,
)
def api_create_token(data: TokenCreate, actor: str = Depends(require_token)) -> dict:
    """Mint a token; the plaintext shows exactly once — store it now."""
    if not data.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    created = get_store().create_token(data.name.strip())
    _audit(actor, "token.create", "token", created["id"], created["name"])
    return created


@app.get(
    "/api/tokens",
    summary="List API tokens (metadata only)",
    dependencies=_guarded,
)
def api_list_tokens() -> list[dict]:
    """Token metadata; hashes and plaintext never exposed."""
    return get_store().list_tokens()


@app.delete(
    "/api/tokens/{token_id}", summary="Revoke an API token", dependencies=_guarded
)
def api_delete_token(token_id: str, actor: str = Depends(require_token)) -> dict:
    """Revoke a token immediately."""
    if not get_store().delete_token(token_id):
        raise HTTPException(status_code=404, detail="unknown token")
    _audit(actor, "token.delete", "token", token_id)
    return {"deleted": token_id}


@app.get(
    "/api/audit",
    summary="Operator audit trail",
    dependencies=_guarded,
)
def api_list_audit(limit: int = 100) -> list[dict]:
    """Recent audit records, newest first."""
    return get_store().list_audit(limit)


@app.get(
    "/api/audit/verify",
    summary="Verify the audit hash chain",
    dependencies=_guarded,
)
def api_verify_audit() -> dict:
    """Recompute the chain; reports the first break, if any."""
    return get_store().verify_audit()


@app.get(
    "/api/scheduler/status",
    summary="Scheduler queue health",
    dependencies=_guarded,
)
def api_scheduler_status() -> dict:
    """Next runs, lag, recent failures, and worker state (read-only)."""
    from .scheduler import scheduler_status

    return scheduler_status(get_store())


@app.post(
    "/api/maintenance/migrate-secrets",
    summary="Encrypt plaintext secrets in place",
    dependencies=_guarded,
)
def api_migrate_secrets(actor: str = Depends(require_token)) -> dict:
    """Idempotent migration to encrypted storage (needs master key set)."""
    result = get_store().migrate_secrets()
    _audit(actor, "maintenance.migrate", "maintenance", "secrets", str(result))
    return result


@app.post(
    "/api/maintenance/rotate-key",
    summary="Re-encrypt all secrets under a new key",
    dependencies=_guarded,
)
def api_rotate_key(data: RotateRequest, actor: str = Depends(require_token)) -> dict:
    """Rotate data encryption. Restart with the new AUDITLESS_MASTER_KEY after."""
    from .secrets import SecretBox

    try:
        old_box, new_box = SecretBox(data.current_key.get_secret_value()), SecretBox(
            data.new_key.get_secret_value()
        )
        # Validate the new key parses before touching any data.
        assert new_box.decrypt(new_box.encrypt("rotate-check")) == "rotate-check"
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid key: {exc}") from exc
    result = get_store().rotate_secrets(old_box, new_box)
    _audit(actor, "maintenance.rotate", "maintenance", "secrets", str(result))
    return result


def serve_forever(
    host: str = "127.0.0.1", port: int = 8080, scheduler: bool = True
) -> None:
    """Run the dashboard with uvicorn until interrupted."""
    import sys

    import uvicorn

    from .secrets import require_master_key

    require_master_key()  # refuse to boot on a misconfigured master key

    from .secrets import require_master_key

    require_master_key()  # refuse to boot on a misconfigured master key

    stop_event: threading.Event | None = None
    if scheduler:
        import threading as _threading

        from .scheduler import scheduler_loop

        stop_event = _threading.Event()
        worker = _threading.Thread(
            target=scheduler_loop,
            args=(get_store(), stop_event),
            kwargs={"interval": 30.0},
            daemon=True,
            name="auditless-scheduler",
        )
        worker.start()
        print("Scheduler enabled (30s tick): unattended scans will run")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"Warning: binding {host} exposes the unauthenticated dashboard"
            " to the network; put authentication + TLS in front.",
            file=sys.stderr,
        )
    print(f"Auditless UI on http://{host}:{port} (Ctrl-C to stop)")
    print(f"Swagger docs at http://{host}:{port}/docs")
    try:
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except KeyboardInterrupt:
        pass
    finally:
        if stop_event is not None:
            stop_event.set()
