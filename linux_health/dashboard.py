"""Local web dashboard + API for Linux Health Security Scanner.

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
    python -m linux_health HOST USER PASS --serve
    python -m linux_health --serve --serve-port 8080
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field, SecretStr

from .store import Store

MAX_JOBS = 50

_jobs: dict[str, "ScanJob"] = {}
_jobs_order: list[str] = []
_jobs_lock = threading.Lock()

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
        }


class ScanRequest(BaseModel):
    """Parameters for starting a scan. Password is write-only."""

    hostname: str = Field(default="", examples=["192.168.1.100"])
    username: str = Field(default="", examples=["admin"])
    password: SecretStr | None = Field(
        default=None,
        description="SSH password. Memory-only for the run; never stored or returned.",
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


class HostUpdate(BaseModel):
    """Partial host update (all fields optional)."""

    name: str | None = None
    hostname: str | None = None
    username: str | None = None
    port: int | None = None
    auth: str | None = None


class HostPublic(BaseModel):
    """Host metadata (key bytes are never exposed)."""

    id: str
    name: str
    hostname: str
    port: int
    username: str
    auth: str
    has_key: int
    created_at: float
    updated_at: float


class KeyUpload(BaseModel):
    """Private key material (write-only; stored 0600, never readable back)."""

    key: str = Field(description="PEM/OpenSSH private key text.")


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


def run_scan(params: dict) -> dict:
    """Execute one scan via the shared CLI pipeline and return the report.

    Args:
        params: Scan parameters (hostname, username, password, port,
            timeout, command_timeout, scan_ports, profile, key_path,
            enable_rootkit_scan, check_package_hygiene,
            strict_host_key_checking).

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
    if params.get("strict_host_key_checking"):
        argv.append("--strict-host-key-checking")

    out_path = Path(tempfile.mkdtemp(prefix="auditless-")) / "report.json"
    argv += ["--output", str(out_path)]
    try:
        if not password and not key_path:
            raise RuntimeError("password is required to start a scan")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli_main(argv)
        if code != 0 or not out_path.exists():
            raise RuntimeError(f"scan failed (exit {code}): {buf.getvalue()[-500:]}")
        payload: dict = json.loads(out_path.read_text(encoding="utf-8"))
        return payload
    except SystemExit as exc:
        raise RuntimeError(
            f"scan failed: invalid arguments or SSH error ({exc})"
        ) from exc
    finally:
        params["password"] = None
        with contextlib.suppress(OSError):
            out_path.unlink()


def _persist_job(job: ScanJob, host_id: str | None) -> None:
    """Best-effort persistence (must never break status reporting)."""
    try:
        get_store().save_report(
            job.id,
            job.hostname,
            job.username,
            job.status,
            job.report,
            job.error,
            host_id,
            job.created_at,
            job.finished_at,
        )
    except Exception:
        pass


def _run_job(job: ScanJob, params: dict, host_id: str | None = None) -> None:
    # NOTE: terminal status flips only AFTER persisting, so pollers that
    # observe done/error are guaranteed a stored row (no save race).
    job.status = "running"
    job.progress = "connecting over SSH and gathering checks"
    try:
        job.report = run_scan(params)
        job.progress = "complete"
        _save_report_copy(job.hostname, job.report)
        job.finished_at = time.time()
        job.status = "done"
        _persist_job(job, host_id)
    except Exception as exc:  # keep the job record, report the failure
        job.error = str(exc)[:1000]
        job.progress = "failed"
        job.finished_at = time.time()
        job.status = "error"
        _persist_job(job, host_id)


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
    if host["auth"] == "key":
        if not get_store().has_host_key(host_id):
            raise ValueError("host uses key auth but no key is stored")
        key_path = str(get_store().key_path(host_id))
    elif not password:
        raise ValueError("password is required for this host")
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
        return {"pass": 2, "warn": 1, "fail": 0}.get(status, -1)

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
        "scanner": "Linux Health Security Scanner",
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

    for profiles_dir in (
        Path.cwd() / "profiles",
        Path.home() / ".config" / "linux_health" / "profiles",
        Path("/etc/linux_health/profiles"),
    ):
        if profiles_dir.is_dir():
            for candidate in sorted(profiles_dir.glob("*.yaml")) + sorted(
                profiles_dir.glob("*.yml")
            ):
                add(candidate.stem, candidate, "profiles-dir")
    try:
        from .config import get_default_profile_paths

        for candidate in get_default_profile_paths():
            if candidate.exists():
                add(candidate.stem, candidate, "auto")
    except ImportError:
        pass
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
        PortStatus(port=p.get("port", 0), open=True, reason=p.get("reason", ""))
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
</style>
</head>
<body>
<div class="wrap">
<h1>Auditless</h1>
<div class="sub">Agentless Linux security scanner &mdash; hardening index, checks &amp; remediation &mdash; <a style="color:var(--acc)" href="/docs">API reference (Swagger)</a></div>
<div class="card">
<h3 style="margin-top:0">New scan</h3>
<div style="margin-bottom:8px"><label>Saved host (optional &mdash; overrides manual fields)</label><select id="hostsel" onchange="hostPick()"><option value="">manual entry</option></select></div>
<div class="row">
<div><label>Hostname / IP</label><input id="host" placeholder="192.168.1.100"></div>
<div><label>SSH username</label><input id="user" placeholder="admin"></div>
<div><label>SSH password</label><input id="pass" type="password" placeholder="required"></div>
<div><label>SSH port</label><input id="port" value="22"></div>
</div>
<div class="opts">
<label><input type="checkbox" id="strict"> strict host-key checking</label>
<label><input type="checkbox" id="rootkit"> rkhunter scan</label>
<label><input type="checkbox" id="hygiene"> package hygiene</label>
</div>
<button id="go" onclick="startScan()">Run scan</button>
<div class="note">Password stays in server memory for the run only &mdash; never stored or logged.
Binds to localhost; do not expose without auth + TLS.</div>
<div id="status" style="margin-top:10px"></div>
</div>
<div class="card"><h3 style="margin-top:0">Recent scans (this session)</h3><div id="hist" class="hist">loading&hellip;</div></div>
<div class="card"><h3 style="margin-top:0">Saved reports (persisted)</h3>
<div class="toolbar"><button style="margin:0" onclick="loadReports()">Refresh</button>
<button style="margin:0" onclick="runDiff()">Compare A &rarr; B</button></div>
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
let cur=null,timer=null;
async function api(p,o){const r=await fetch(p,o);const j=await r.json();
if(!r.ok)throw new Error(j.detail||j.error||r.status);return j}
async function startScan(){
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
  cur=j.id;go.disabled=true;poll();}
 catch(e){status('<span class="err">'+esc(e.message)+"</span>")}}
function hostPick(){const d=!!hostsel.value;
 [host,user,port].forEach(i=>i.disabled=d)}
async function poll(){
 clearInterval(timer);
 timer=setInterval(async()=>{
  try{const j=await api("/api/scans/"+cur);
   if(j.status==="running"||j.status==="queued"){status(esc(j.progress||j.status)+"&hellip;");return}
   clearInterval(timer);go.disabled=false;
   if(j.status==="done"){status("done");render(j.report)}else{status('<span class="err">'+esc(j.error||"failed")+"</span>")}
   loadHist();
  }catch(e){clearInterval(timer);go.disabled=false;status('<span class="err">'+esc(e.message)+"</span>")}
 },1200)}
function status(h){document.getElementById("status").innerHTML=h}
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
 if(j.status==="done")render(j.report);else status(esc(j.status))}
let diffA=null,diffB=null;
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
async function loadReports(){
 try{const r=await api("/api/reports?limit=30");
  document.getElementById("reps").innerHTML=r.length?r.map(x=>
   `<div><a onclick="viewReport('${x.id}')">${esc(x.hostname)}</a> &mdash; ${x.status}`+
   (x.hardening_index!=null?` &mdash; <b>${x.hardening_index}/100</b>`:"")+
   ` <a onclick="setDiff('A','${x.id}')">A</a> <a onclick="setDiff('B','${x.id}')">B</a> `+
   `<a onclick="delReport('${x.id}')">delete</a></div>`).join(""):"no saved reports yet";}
 catch(e){document.getElementById("reps").textContent="unavailable"}}
async function viewReport(id){const r=await api("/api/reports/"+id);
 if(r.report)render(r.report);else status("report has no payload")}
async function delReport(id){await api("/api/reports/"+id,{method:"DELETE"});loadReports()}
function setDiff(which,id){if(which==="A")diffA=id;else diffB=id;
 status("diff: A="+(diffA||"?")+" B="+(diffB||"?"))}
async function runDiff(){
 if(!diffA||!diffB){status('<span class="err">pick A and B reports first</span>');return}
 const d=await api("/api/diff?from_id="+diffA+"&to_id="+diffB);
 const row=x=>`<tr><td>${esc(x.test_id||"")}</td><td>${esc(x.item||"")}</td>`+
  `<td>${esc(x.from||"")}&rarr;<b>${esc(x.to||"")}</b></td></tr>`;
 document.getElementById("diff").innerHTML=
  `<h4>Hardening ${d.hardening_before} &rarr; <b>${d.hardening_after}</b>`+
  ` (delta ${d.hardening_delta>=0?"+":""}${d.hardening_delta})</h4>`+
  `<h4 class="pass">Fixed (${d.fixed.length})</h4><table>${d.fixed.map(row).join("")}</table>`+
  `<h4 class="fail">Regressed (${d.regressed.length})</h4><table>${d.regressed.map(row).join("")}</table>`+
  (d.new.length?`<h4>New (${d.new.length})</h4><table>${d.new.map(row).join("")}</table>`:"");}
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
  <option value="pass">pass</option></select>
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
loadReports();
</script>
</body>
</html>
"""


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


@app.get("/api/version", summary="Scanner and API version metadata")
def api_version() -> dict:
    """Scanner version, API version, and supported feature flags."""
    return get_version_info()


@app.get(
    "/api/scans",
    response_model=list[ScanJobPublic],
    summary="List recent scan jobs (newest first, no credentials)",
)
def api_list_scans() -> list[ScanJobPublic]:
    """Summaries of recent jobs; full reports only via per-job GET."""
    with _jobs_lock:
        jobs = [_jobs[jid] for jid in reversed(_jobs_order) if jid in _jobs]
    return [_public_job(job) for job in jobs]


@app.post(
    "/api/scans",
    response_model=ScanJobPublic,
    status_code=201,
    summary="Start a scan (password is write-only)",
)
def api_start_scan(data: ScanRequest) -> ScanJobPublic:
    """Register a job and run the shared CLI scan pipeline in the background.

    Poll GET /api/scans/{id} until status is done or error. Pass host_id
    to scan a saved host (password still per-request unless key auth).
    """
    host_id = data.host_id
    overrides = {
        "timeout": data.timeout,
        "command_timeout": data.command_timeout,
        "scan_ports": data.scan_ports,
        "profile": data.profile,
        "enable_rootkit_scan": data.enable_rootkit_scan,
        "check_package_hygiene": data.check_package_hygiene,
        "strict_host_key_checking": data.strict_host_key_checking,
    }
    secret = data.password.get_secret_value() if data.password else ""
    try:
        if host_id:
            try:
                base, run_params = resolve_host_scan(
                    host_id, {**overrides, "password": secret}
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
    worker = threading.Thread(target=_run_job, args=(job, params, host_id), daemon=True)
    worker.start()
    return _public_job(job)


@app.get(
    "/api/scans/{job_id}",
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
    summary="Forget a job record",
)
def api_delete_scan(job_id: str) -> dict:
    """Remove a job from history."""
    if not delete_job(job_id):
        raise HTTPException(status_code=404, detail="unknown scan id")
    return {"deleted": job_id}


@app.get(
    "/api/scans/{job_id}/report",
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


@app.get("/api/profiles", summary="Scan profiles discovered on this host")
def api_list_profiles() -> list[dict]:
    """Profile names/paths usable as the scan `profile` parameter."""
    return list_profiles()


def _host_public(row: dict) -> HostPublic:
    return HostPublic(
        id=str(row["id"]),
        name=str(row["name"]),
        hostname=str(row["hostname"]),
        port=int(row["port"]),
        username=str(row["username"]),
        auth=str(row["auth"]),
        has_key=int(row["has_key"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


@app.get("/api/hosts", response_model=list[HostPublic], summary="List saved hosts")
def api_list_hosts() -> list[HostPublic]:
    """Saved hosts (metadata only; key bytes never exposed)."""
    return [_host_public(row) for row in get_store().list_hosts()]


@app.post(
    "/api/hosts",
    response_model=HostPublic,
    status_code=201,
    summary="Register a host",
)
def api_create_host(data: HostCreate) -> HostPublic:
    """Save a host for key auth and report history."""
    if data.auth not in ("password", "key"):
        raise HTTPException(status_code=400, detail="auth must be 'password' or 'key'")
    try:
        row = get_store().upsert_host(
            data.name, data.hostname, data.username, data.port, data.auth
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _host_public(row)


@app.get("/api/hosts/{host_id}", response_model=HostPublic, summary="Fetch one host")
def api_get_host(host_id: str) -> HostPublic:
    """Fetch host metadata (never key bytes)."""
    row = get_store().get_host(host_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown host")
    return _host_public(row)


@app.patch("/api/hosts/{host_id}", response_model=HostPublic, summary="Update a host")
def api_update_host(host_id: str, data: HostUpdate) -> HostPublic:
    """Partial host update; changing auth to password drops nothing else."""
    row = get_store().get_host(host_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown host")
    if data.auth is not None and data.auth not in ("password", "key"):
        raise HTTPException(status_code=400, detail="auth must be 'password' or 'key'")
    updated = get_store().upsert_host(
        data.name or row["name"],
        data.hostname or row["hostname"],
        data.username or row["username"],
        data.port if data.port is not None else row["port"],
        data.auth or row["auth"],
        host_id=host_id,
    )
    return _host_public(updated)


@app.delete("/api/hosts/{host_id}", summary="Delete a host and its key")
def api_delete_host(host_id: str) -> dict:
    """Remove a host record and any stored key material."""
    if not get_store().delete_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    return {"deleted": host_id}


@app.put("/api/hosts/{host_id}/key", summary="Store a host private key")
def api_put_host_key(host_id: str, data: KeyUpload) -> dict:
    """Save key bytes with owner-only permissions (write-only endpoint)."""
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    if not data.key.strip():
        raise HTTPException(status_code=400, detail="empty key")
    try:
        get_store().set_host_key(host_id, data.key)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="unknown host") from exc
    return {"host_id": host_id, "has_key": True}


@app.get("/api/hosts/{host_id}/key", summary="Key presence (never the key)")
def api_get_host_key(host_id: str) -> dict:
    """Whether key bytes are stored. The key itself is never returned."""
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    try:
        present = get_store().has_host_key(host_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="unknown host") from exc
    return {"host_id": host_id, "has_key": present}


@app.delete("/api/hosts/{host_id}/key", summary="Remove a stored key")
def api_delete_host_key(host_id: str) -> dict:
    """Delete stored key bytes (host record kept, flag cleared)."""
    if not get_store().get_host(host_id):
        raise HTTPException(status_code=404, detail="unknown host")
    try:
        get_store().clear_host_key(host_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="unknown host") from exc
    return {"host_id": host_id, "has_key": False}


@app.get("/api/reports", summary="Persisted scan reports, newest first")
def api_list_reports(host_id: str | None = None, limit: int = 50) -> list[dict]:
    """Stored report summaries, optionally filtered by host."""
    return get_store().list_reports(host_id, max(1, min(limit, 200)))


@app.get("/api/reports/{report_id}", summary="Fetch one persisted report")
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


@app.delete("/api/reports/{report_id}", summary="Forget a persisted report")
def api_delete_stored_report(report_id: str) -> dict:
    """Remove a stored report."""
    if not get_store().delete_report(report_id):
        raise HTTPException(status_code=404, detail="unknown report")
    return {"deleted": report_id}


@app.get("/api/reports/{report_id}/report", summary="Persisted report re-rendered")
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


@app.get("/api/diff", summary="Diff two reports (fixed vs regressed)")
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


def serve_forever(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the dashboard with uvicorn until interrupted."""
    import sys

    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"Warning: binding {host} exposes the unauthenticated dashboard"
            " to the network; put authentication + TLS in front.",
            file=sys.stderr,
        )
    print(f"Auditless UI on http://{host}:{port} (Ctrl-C to stop)")
    print(f"Swagger docs at http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="warning")
