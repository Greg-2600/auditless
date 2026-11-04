"""Local web dashboard for Linux Health Security Scanner.

Serves a single-page UI (stdlib only, no extra dependencies) that runs
security scans from the browser and renders the hardening index,
per-category breakdown, and filterable check results.

Security model:
    - Binds to loopback (127.0.0.1) by default; do not expose to untrusted
      networks without a reverse proxy providing authentication + TLS.
    - The SSH password lives in memory only for the duration of a scan run
      and is scrubbed afterwards. It is never written to disk, never stored
      in job history, and never included in any API response.
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY_BYTES = 64 * 1024
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
    """Validate params, register a job, and run it in a background thread."""
    hostname = (params.get("hostname") or "").strip()
    username = (params.get("username") or "").strip()
    password = params.get("password") or ""
    if not hostname or not username or not password:
        raise ValueError("hostname, username and password are required")
    job = ScanJob(id=uuid.uuid4().hex[:12], hostname=hostname, username=username)
    _register_job(job)
    worker = threading.Thread(target=_run_job, args=(job, dict(params)), daemon=True)
    worker.start()
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
<div class="sub">Agentless Linux security scanner &mdash; hardening index, checks &amp; remediation</div>
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
if(!r.ok)throw new Error(j.error||r.status);return j}
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


class _Handler(BaseHTTPRequestHandler):
    """JSON API + embedded SPA. Never logs or returns credentials."""

    server_version = "AuditlessUI/1.0"

    def log_message(self, *args):  # keep test output and logs quiet
        pass

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def do_GET(self) -> None:
        if self.path == "/":
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path == "/api/scans":
            self._json(200, list_jobs())
        elif self.path.startswith("/api/scans/"):
            job = get_job(self.path[len("/api/scans/") :].split("?")[0].split("/")[0])
            if job is None:
                self._json(404, {"error": "unknown scan id"})
                return
            payload = job.summary()
            if job.status == "done":
                payload["report"] = job.report
            self._json(200, payload)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/api/scans":
            self._json(404, {"error": "not found"})
            return
        data = self._read_json()
        if not isinstance(data, dict):
            self._json(400, {"error": "expected a JSON object"})
            return
        try:
            job = start_scan(
                {
                    "hostname": data.get("hostname", ""),
                    "username": data.get("username", ""),
                    "password": data.get("password", ""),
                    "port": int(data.get("port") or 22),
                    "timeout": float(data.get("timeout") or 5.0),
                    "command_timeout": float(data.get("command_timeout") or 60.0),
                    "scan_ports": data.get("scan_ports") or "",
                    "profile": data.get("profile") or "",
                    "enable_rootkit_scan": bool(data.get("enable_rootkit_scan")),
                    "check_package_hygiene": bool(data.get("check_package_hygiene")),
                    "strict_host_key_checking": bool(
                        data.get("strict_host_key_checking")
                    ),
                }
            )
        except (ValueError, TypeError) as exc:
            self._json(400, {"error": str(exc)[:300]})
            return
        self._json(201, job.summary())


def run_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Create (but not start) the dashboard server.

    Binds loopback by default. Call ``serve_forever()`` on the result,
    or use :func:`serve_forever` below.
    """
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    return server


def serve_forever(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the dashboard until interrupted."""
    server = run_server(host, port)
    print(f"Auditless UI on http://{host}:{server.server_address[1]} (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
