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

MAX_JOBS = 50

_jobs: dict[str, "ScanJob"] = {}
_jobs_order: list[str] = []
_jobs_lock = threading.Lock()


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

    hostname: str = Field(examples=["192.168.1.100"])
    username: str = Field(examples=["admin"])
    password: SecretStr = Field(
        description="SSH password. Memory-only for the run; never stored or returned."
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
            timeout, command_timeout, scan_ports, profile,
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
    argv = [
        params.get("hostname") or "",
        params.get("username") or "",
        password if password else "-",
        "--port",
        str(params.get("port", 22)),
        "--timeout",
        str(params.get("timeout", 5.0)),
        "--command-timeout",
        str(params.get("command_timeout", 60.0)),
        "--format",
        "json",
    ]
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
    if not password:
        argv.append("--ask-password")

    out_path = Path(tempfile.mkdtemp(prefix="auditless-")) / "report.json"
    argv += ["--output", str(out_path)]
    try:
        if not password:
            raise RuntimeError("password is required to start a scan")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = cli_main(argv)
        if code != 0 or not out_path.exists():
            raise RuntimeError(f"scan failed (exit {code}): {buf.getvalue()[-500:]}")
        return json.loads(out_path.read_text(encoding="utf-8"))
    except SystemExit as exc:
        raise RuntimeError(f"scan failed: invalid arguments or SSH error ({exc})")
    finally:
        params["password"] = None
        with contextlib.suppress(OSError):
            out_path.unlink()


def _run_job(job: ScanJob, params: dict) -> None:
    job.status = "running"
    job.progress = "connecting over SSH and gathering checks"
    try:
        job.report = run_scan(params)
        job.status = "done"
        job.progress = "complete"
        _save_report_copy(job.hostname, job.report)
    except Exception as exc:  # keep the job record, report the failure
        job.status = "error"
        job.progress = "failed"
        job.error = str(exc)[:1000]
    finally:
        job.finished_at = time.time()


def start_scan(params: dict) -> ScanJob:
    """Validate params, register a job, and return it (caller runs it)."""
    hostname = (params.get("hostname") or "").strip()
    username = (params.get("username") or "").strip()
    password = params.get("password") or ""
    if not hostname or not username or not password:
        raise ValueError("hostname, username and password are required")
    job = ScanJob(id=uuid.uuid4().hex[:12], hostname=hostname, username=username)
    _register_job(job)
    return job


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


def render_saved_report(job: ScanJob, fmt: str) -> tuple[str, str]:
    """Re-render a finished scan's stored report in json/md/text.

    Raises:
        ValueError: If the format is unknown.
        RuntimeError: If the scan is not finished successfully.
    """
    if fmt not in ("json", "md", "text"):
        raise ValueError(f"unknown format {fmt!r}: use json, md or text")
    if job.status != "done" or not job.report:
        raise RuntimeError("scan is not complete")
    report = job.report
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
            k: findings.get(k, "")
            for k in DetailedSecurityInfo.__dataclass_fields__
            if k not in ("rootkit_scan", "unused_packages")
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
<div class="card"><h3 style="margin-top:0">Recent scans</h3><div id="hist" class="hist">loading&hellip;</div></div>
<div id="result"></div>
</div>
<script>
let cur=null,timer=null;
async function api(p,o){const r=await fetch(p,o);const j=await r.json();
if(!r.ok)throw new Error(j.detail||j.error||r.status);return j}
async function startScan(){
 const b={hostname:host.value,username:user.value,password:pass.value,
  port:parseInt(port.value||"22",10),
  strict_host_key_checking:strict.checked,enable_rootkit_scan:rootkit.checked,
  check_package_hygiene:hygiene.checked};
 pass.value="";status("starting&hellip;");
 try{const j=await api("/api/scans",{method:"POST",
  headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});
  cur=j.id;go.disabled=true;poll();}
 catch(e){status('<span class="err">'+esc(e.message)+"</span>")}}
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

    Poll GET /api/scans/{id} until status is done or error.
    """
    try:
        job = start_scan(
            {
                "hostname": data.hostname,
                "username": data.username,
                "password": data.password.get_secret_value(),
                "port": data.port,
                "timeout": data.timeout,
                "command_timeout": data.command_timeout,
                "scan_ports": data.scan_ports,
                "profile": data.profile,
                "enable_rootkit_scan": data.enable_rootkit_scan,
                "check_package_hygiene": data.check_package_hygiene,
                "strict_host_key_checking": data.strict_host_key_checking,
            }
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    params = {
        "hostname": job.hostname,
        "username": job.username,
        "password": data.password.get_secret_value(),
        "port": data.port,
        "timeout": data.timeout,
        "command_timeout": data.command_timeout,
        "scan_ports": data.scan_ports,
        "profile": data.profile,
        "enable_rootkit_scan": data.enable_rootkit_scan,
        "check_package_hygiene": data.check_package_hygiene,
        "strict_host_key_checking": data.strict_host_key_checking,
    }
    # Own thread (not BackgroundTasks): deterministic under both uvicorn
    # and TestClient, whose background-task timing varies by version.
    worker = threading.Thread(target=_run_job, args=(job, params), daemon=True)
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
def api_get_report(job_id: str, format: str = "json") -> Response:
    """Re-render a completed scan's stored report in the requested format."""
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown scan id")
    try:
        content, content_type = render_saved_report(job, format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return Response(content=content, media_type=content_type)


@app.get("/api/profiles", summary="Scan profiles discovered on this host")
def api_list_profiles() -> list[dict]:
    """Profile names/paths usable as the scan `profile` parameter."""
    return list_profiles()


def serve_forever(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the dashboard with uvicorn until interrupted."""
    import uvicorn

    print(f"Auditless UI on http://{host}:{port} (Ctrl-C to stop)")
    print(f"Swagger docs at http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="warning")
