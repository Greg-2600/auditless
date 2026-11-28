"""Tests for the Auditless FastAPI dashboard + documented API.

The suite talks to the app exclusively through the first-party
ApiClient (real HTTP against uvicorn), so every assertion exercises the
public API surface exactly as users see it.
"""

import json
import socket
import time
from pathlib import Path

import pytest

from auditless import dashboard
from auditless.client import ApiError
from auditless.dashboard import get_job, list_jobs

SENTINEL_PASSWORD = "s3cr3t-pw-SENTINEL-9z9z"


def canned_report():
    """Minimal report shaped like render_report_json output."""
    return {
        "scan_info": {"scanner": "test"},
        "system": {
            "hostname": "web-01",
            "os": "TestOS",
            "kernel": "1.0",
            "uptime": "1d",
        },
        "summary": {
            "total_checks": 2,
            "passed": 1,
            "warned": 0,
            "failed": 1,
            "hardening_index": 50,
            "hardening_level": "POOR",
        },
        "hardening_by_category": {
            "Network": {
                "index": 50,
                "level": "POOR",
                "passed": 1,
                "warned": 0,
                "failed": 1,
                "total": 2,
            }
        },
        "checks": [
            {
                "test_id": "FIRE-4512",
                "category": "Network",
                "item": "Firewall",
                "status": "fail",
                "details": "off",
                "recommendation": "enable it",
            },
            {
                "test_id": "STOR-6310",
                "category": "Storage",
                "item": "Disk",
                "status": "pass",
                "details": "fine",
                "recommendation": "none",
            },
        ],
        "ports": {"scanned": 1, "open": 1, "open_ports": [{"port": 22}]},
    }


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_healthz(client):
    assert client.health() == {"status": "ok"}


def test_scheduler_status_endpoint(client):
    host = client.create_host("h", "h.example", "u")
    sched = client.create_schedule(host["id"], "nightly", "0 3 * * *")
    status = client.scheduler_status()
    assert status["enabled_schedules"] == 1
    assert [row["schedule_id"] for row in status["next_runs"]] == [sched["id"]]
    assert status["next_runs"][0]["next_run"] is not None
    assert status["lag_seconds"] == 0
    assert status["failures"] == 0
    assert status["active_runs"] == []
    assert status["worker_saturation"] == 0.0


def test_index_serves_spa(client):
    import urllib.request

    with urllib.request.urlopen(client.base_url + "/", timeout=10) as resp:
        html = resp.read().decode()
    assert "Auditless" in html
    assert "/docs" in html


def test_index_compare_reports_controls(client):
    """Any two stored reports are selectable and diffed through /api/diff."""
    import urllib.request

    with urllib.request.urlopen(client.base_url + "/", timeout=10) as resp:
        html = resp.read().decode()
    for control in ("cmpHost", "cmpA", "cmpB", "cmpGo", "cmpout"):
        assert f'id="{control}"' in html
    assert 'api("/api/diff?from_id="' in html
    assert "esc(from.hostname" in html
    assert "esc(to.hostname" in html
    assert "esc(x.test_id" in html


def test_swagger_ui_available(client):
    import urllib.request

    with urllib.request.urlopen(client.base_url + "/docs", timeout=10) as resp:
        assert "swagger" in resp.read().decode().lower()


def test_post_requires_credentials(client):
    with pytest.raises(ApiError) as exc_info:
        client._request("POST", "/api/scans", {"hostname": "h", "username": "u"})
    assert exc_info.value.status == 400  # no password and no saved key


def test_post_rejects_non_object(client):
    import urllib.request

    import urllib.error

    req = urllib.request.Request(
        client.base_url + "/api/scans",
        data=b"[1, 2]",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as exc:
        assert exc.code == 422
        exc.close()
        return
    raise AssertionError("expected HTTP error")


def test_unknown_scan_id_404(client):
    with pytest.raises(ApiError) as exc_info:
        client.get_scan("nope123")
    assert exc_info.value.status == 404


def test_full_scan_flow_hides_password(client, monkeypatch):
    """Mocked run: report returned, sentinel password appears nowhere."""
    from auditless.dashboard import _run_job

    def fake_run_scan(params):
        params["password"] = None  # mirror run_scan scrubbing
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    monkeypatch.setattr(dashboard, "_run_job", _run_job)  # keep real runner
    job = client.start_scan(
        hostname="web-01", username="root", password=SENTINEL_PASSWORD
    )
    # Instant mocks may already be done; the wait below is authoritative.
    assert job["status"] in ("queued", "running", "done")
    assert SENTINEL_PASSWORD not in json.dumps(job)

    done = client.wait_for(job["id"])
    assert done["status"] == "done"
    assert done["report"]["summary"]["hardening_index"] == 50
    assert "connecting over SSH" in done.get("log", "")
    assert "scan complete" in done.get("log", "")

    listing = json.dumps(client.list_scans())
    detail = json.dumps(client.get_scan(job["id"]))
    assert SENTINEL_PASSWORD not in listing
    assert SENTINEL_PASSWORD not in detail

    stored = get_job(job["id"])
    assert stored is not None
    assert "password" not in stored.summary()
    assert any(j["id"] == job["id"] for j in list_jobs())


def test_scan_error_path(client, monkeypatch):
    """Failing run surfaces an error status without credentials."""

    def boom(params):
        params["password"] = None
        raise RuntimeError("ssh unreachable (test)")

    monkeypatch.setattr(dashboard, "run_scan", boom)
    job = client.start_scan(hostname="gone", username="u", password=SENTINEL_PASSWORD)
    done = client.wait_for(job["id"])
    assert done["status"] == "error"
    assert "unreachable" in (done["error"] or "")
    assert "scan failed" in done.get("log", "")
    assert SENTINEL_PASSWORD not in json.dumps(done)


def test_run_scan_builds_cli_argv(monkeypatch):
    """run_scan delegates to the shared CLI pipeline (no logic fork)."""
    seen = {}

    def fake_main(argv):
        seen["argv"] = argv
        out = argv[argv.index("--output") + 1]
        import pathlib

        pathlib.Path(out).write_text(json.dumps(canned_report()))
        return 0

    monkeypatch.setattr("auditless.cli.main", fake_main)
    report = dashboard.run_scan(
        {
            "hostname": "h",
            "username": "u",
            "password": "pw",
            "strict_host_key_checking": True,
            "enable_rootkit_scan": True,
        }
    )
    assert report["summary"]["hardening_index"] == 50
    assert "--strict-host-key-checking" in seen["argv"]
    assert "--enable-rootkit-scan" in seen["argv"]
    assert "--format" in seen["argv"] and "json" in seen["argv"]


def test_run_scan_preserves_custom_port(monkeypatch):
    """Regression: API port must reach the CLI (dropped once by refactor)."""
    seen = {}

    def fake_main(argv):
        seen["argv"] = argv
        out = argv[argv.index("--output") + 1]
        import pathlib

        pathlib.Path(out).write_text(json.dumps(canned_report()))
        return 0

    monkeypatch.setattr("auditless.cli.main", fake_main)
    dashboard.run_scan(
        {"hostname": "h", "username": "u", "password": "pw", "port": 2222}
    )
    assert seen["argv"][seen["argv"].index("--port") + 1] == "2222"


def test_run_scan_requires_password():
    with pytest.raises(RuntimeError, match="password is required"):
        dashboard.run_scan({"hostname": "h", "username": "u", "password": ""})


def test_version_endpoint(client):
    info = client.version()
    from auditless import __version__

    assert info["version"] == __version__
    assert info["scanner"] == "Auditless"
    assert info["api_version"] == "1.0"
    assert "ssh-scan" in info["features"]


def test_openapi_spec_is_complete(client):
    spec = client.openapi_spec()
    assert spec["openapi"].startswith("3.")
    for path in (
        "/healthz",
        "/api/version",
        "/api/scans",
        "/api/scans/range",
        "/api/scans/{job_id}",
        "/api/scans/{job_id}/report",
        "/api/profiles",
        "/api/hosts",
        "/api/hosts/{host_id}",
        "/api/hosts/{host_id}/key",
        "/api/reports",
        "/api/reports/{report_id}",
        "/api/diff",
        "/api/schedules",
        "/api/schedules/{schedule_id}",
        "/api/schedules/{schedule_id}/run",
        "/api/hosts/{host_id}/trend",
        "/api/fleet",
        "/api/fleet/heatmap",
        "/api/compliance/controls",
        "/api/hosts/{host_id}/compliance",
        "/api/remediations",
        "/api/reports/{report_id}/remediations",
        "/api/remediations/{proposal_id}/apply",
        "/api/tokens",
        "/api/tokens/{token_id}",
        "/api/audit",
        "/api/audit/verify",
        "/api/scheduler/status",
        "/api/maintenance/backup",
        "/api/maintenance/migrate-secrets",
        "/api/maintenance/rotate-key",
    ):
        assert path in spec["paths"], path
    props = spec["components"]["schemas"]["ScanRequest"]["properties"]
    pw_schema = props["password"]
    branches = pw_schema.get("anyOf", [pw_schema])
    assert any(b.get("writeOnly") is True for b in branches)
    for field in (
        "hostname",
        "username",
        "password",
        "port",
        "profile",
        "strict_host_key_checking",
        "enable_rootkit_scan",
    ):
        assert field in props, field


def test_profiles_endpoint_returns_list(client):
    assert isinstance(client.list_profiles(), list)


def _done_job_id(client, monkeypatch):
    def fake_run_scan(params):
        params["password"] = None
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    job = client.start_scan(
        hostname="web-01", username="root", password=SENTINEL_PASSWORD
    )
    done = client.wait_for(job["id"])
    assert done["status"] == "done"
    return job["id"]


def test_report_formats(client, monkeypatch):
    job_id = _done_job_id(client, monkeypatch)
    md = client.get_report(job_id, format="md")
    assert isinstance(md, str) and "Firewall" in md
    text = client.get_report(job_id, format="text")
    assert isinstance(text, str) and "Firewall" in text
    with pytest.raises(ApiError) as exc_info:
        client.get_report(job_id, format="xml")
    assert exc_info.value.status == 400


def test_report_pending_returns_409(client, monkeypatch):
    import threading as _threading

    release = _threading.Event()

    def slow(params):
        params["password"] = None
        release.wait(15)
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", slow)
    job = client.start_scan(hostname="h", username="u", password=SENTINEL_PASSWORD)
    try:
        with pytest.raises(ApiError) as exc_info:
            client.get_report(job["id"])
        assert exc_info.value.status == 409
    finally:
        release.set()
    assert client.wait_for(job["id"])["status"] == "done"


def test_delete_job(client, monkeypatch):
    job_id = _done_job_id(client, monkeypatch)
    assert client.delete_scan(job_id) == {"deleted": job_id}
    with pytest.raises(ApiError) as exc_info:
        client.get_scan(job_id)
    assert exc_info.value.status == 404
    assert job_id not in json.dumps(client.list_scans())
    with pytest.raises(ApiError) as exc_info:
        client.delete_scan("nope")
    assert exc_info.value.status == 404


def test_backup_endpoint(client):
    result = client.backup()
    assert result["path"].endswith(".db")
    assert result["bytes"] > 0


def test_wait_for_times_out(client, monkeypatch):
    import threading as _threading

    release = _threading.Event()

    def slow(params):
        params["password"] = None
        release.wait(15)
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", slow)
    job = client.start_scan(hostname="h", username="u", password=SENTINEL_PASSWORD)
    try:
        with pytest.raises(TimeoutError):
            client.wait_for(job["id"], deadline=0.3, interval=0.05)
    finally:
        release.set()


def test_client_refuses_non_http_scheme():
    from auditless.client import ApiClient, ApiError

    with pytest.raises(ApiError, match="non-HTTP"):
        ApiClient("ftp://example.com").health()


def test_hostile_ids_never_touch_disk(client):
    """Traversal ids 404 without creating files (path-injection guard)."""
    for hostile in ("..%2Fescape", "..", "a/b"):
        with pytest.raises(ApiError) as exc_info:
            client.put_host_key(hostile, "x")
        assert exc_info.value.status == 404
        with pytest.raises(ApiError) as exc_info:
            client.get_host_key(hostile)
        assert exc_info.value.status == 404


def test_jump_key_lifecycle(client):
    """Jump keys store apart, never readable, delete cleanly."""
    host = client.create_host(
        "via",
        "inner",
        "u",
        jump_hostname="bastion",
        jump_username="b",
        jump_auth="key",
    )
    assert host["has_jump_key"] == 0
    assert client.put_host_key(host["id"], "JUMP-PEM", kind="jump")["has_key"] is True
    assert client.get_host_key(host["id"], kind="jump")["has_key"] is True
    assert "JUMP-PEM" not in json.dumps(client.get_host(host["id"]))
    assert client.delete_host_key(host["id"], kind="jump")["has_key"] is False
    # Host key surface untouched by jump operations.
    assert client.get_host_key(host["id"])["has_key"] is False


def test_resolve_assembles_gateway(client):
    """Saved jump config becomes session gateway params with temp keys."""
    from auditless import dashboard

    host = client.create_host(
        "via2",
        "inner",
        "u",
        auth="password",
        jump_hostname="bastion",
        jump_port=2222,
        jump_username="b",
        jump_auth="key",
    )
    client.put_host_key(host["id"], "JUMP-PEM-2", kind="jump")
    base, run_params = dashboard.resolve_host_scan(host["id"], {"password": "pw"})
    gw = base["gateway"]
    assert gw["hostname"] == "bastion"
    assert gw["port"] == 2222
    assert gw["username"] == "b"
    assert gw["key_path"].endswith(".jump") or "auditless-key-" in gw["key_path"]
    assert Path(gw["key_path"]).exists()
    dashboard._scrub_temp_key(run_params)
    assert not Path(gw["key_path"]).exists()


def test_resolve_jump_password_required(client):
    """Password jump hosts demand a jump password per scan."""
    from auditless import dashboard

    host = client.create_host(
        "via3",
        "inner",
        "u",
        auth="password",
        jump_hostname="bastion",
        jump_username="b",
        jump_auth="password",
    )
    with pytest.raises(ValueError, match="jump password"):
        dashboard.resolve_host_scan(host["id"], {"password": "pw"})
    base, _ = dashboard.resolve_host_scan(
        host["id"], {"password": "pw", "jump_password": "jp"}
    )
    assert base["gateway"]["password"] == "jp"


def test_fleet_scan_runs_bounded_and_parallel(client, monkeypatch):
    """Fleet endpoint launches per-host scans with capped concurrency."""
    import threading as _threading

    from auditless import dashboard

    hosts = [
        client.create_host(f"f{i}", f"10.9.9.{i}", "u", auth="password")
        for i in range(3)
    ]
    gate = _threading.Barrier(3, timeout=15)
    peak, lock, current = [0], _threading.Lock(), [0]

    def fake_run_job(job, params, host_id=None, actor="unknown"):
        with lock:
            current[0] += 1
            peak[0] = max(peak[0], current[0])
        try:
            gate.wait(timeout=15)  # all three must overlap to proceed
        finally:
            with lock:
                current[0] -= 1
        job.status = "done"

    monkeypatch.setattr(dashboard, "_run_job", fake_run_job)
    result = client.fleet_scan(
        host_ids=[h["id"] for h in hosts], password="pw", max_concurrent=3
    )
    assert sorted(j["host_id"] for j in result["jobs"]) == sorted(
        h["id"] for h in hosts
    )
    assert peak[0] == 3  # genuinely parallel, not sequential

    with pytest.raises(ApiError) as exc_info:
        client.fleet_scan(host_ids=["missing"], password="pw")
    assert exc_info.value.status == 404
    with pytest.raises(ApiError) as exc_info:
        client.fleet_scan(host_ids=[hosts[0]["id"]])
    assert exc_info.value.status == 400


def test_cli_jump_flags():
    from auditless.cli import build_parser

    args = build_parser().parse_args(
        [
            "h",
            "u",
            "pw",
            "--jump-host",
            "b",
            "--jump-user",
            "bu",
            "--jump-port",
            "2222",
            "--jump-key-file",
            "/k",
        ]
    )
    assert args.jump_host == "b"
    assert args.jump_port == 2222
    assert args.jump_key_file == "/k"


def test_schedules_crud_and_validation(client):
    host = client.create_host("sched", "10.9.9.9", "u")
    with pytest.raises(ApiError) as exc_info:
        client.create_schedule(host["id"], "bad", "not a cron")
    assert exc_info.value.status == 400
    with pytest.raises(ApiError) as exc_info:
        client.create_schedule("missing", "x", "* * * * *")
    assert exc_info.value.status == 404
    sched = client.create_schedule(
        host["id"],
        "nightly",
        "0 3 * * *",
        webhook_url="https://hooks/x/SECRET",
        notify_on="always",
    )
    assert sched["next_run"] is not None
    # Webhook URL stored server-side, never listed.
    assert "SECRET" not in json.dumps(client.list_schedules())
    assert "SECRET" not in json.dumps(client.get_schedule(sched["id"]))
    updated = client.update_schedule(sched["id"], cron="0 4 * * *")
    assert updated["cron"] == "0 4 * * *"
    assert client.delete_schedule(sched["id"])["deleted"] == sched["id"]
    with pytest.raises(ApiError) as exc_info:
        client.get_schedule(sched["id"])
    assert exc_info.value.status == 404


def test_run_schedule_now_triggers_scan(client, monkeypatch):
    from auditless import dashboard

    seen = {}

    def fake_scan_host(host_id, overrides, actor="scheduler"):
        seen.update(host_id=host_id, overrides=overrides)
        job = dashboard.ScanJob(id="manual1", hostname="h", username="u", status="done")
        job.report = canned_report()
        return job, job.report

    monkeypatch.setattr(dashboard, "scan_host_now", fake_scan_host)
    host = client.create_host("trig", "10.8.8.8", "u", auth="password")
    sched = client.create_schedule(host["id"], "n", "0 3 * * *")
    job = client.run_schedule_now(sched["id"])
    assert seen["host_id"] == host["id"]
    assert job["report"]["summary"]["hardening_index"] == 50
    with pytest.raises(ApiError) as exc_info:
        client.run_schedule_now("missing")
    assert exc_info.value.status == 404


def test_trend_and_fleet(client, monkeypatch):
    from auditless import dashboard

    def fake_run_scan(params):
        params["password"] = None
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    host = client.create_host("trend", "10.7.7.7", "u", auth="password")
    assert client.host_trend(host["id"]) == []
    for _ in range(2):
        done = client.wait_for(
            client.start_scan(host_id=host["id"], password="x")["id"]
        )
        assert done["status"] == "done"
    trend = client.host_trend(host["id"])
    assert len(trend) == 2
    assert [t["hardening_index"] for t in trend] == [50, 50]
    assert trend[0]["created_at"] <= trend[1]["created_at"]
    fleet = client.fleet()
    entry = next(f for f in fleet if f["host_id"] == host["id"])
    assert entry["latest_index"] == 50
    assert entry["total_reports"] == 2
    assert entry["latest_report_id"] == trend[1]["report_id"]
    with pytest.raises(ApiError) as exc_info:
        client.host_trend("missing")
    assert exc_info.value.status == 404


def test_range_scan_discovers_and_launches(client, monkeypatch):
    from auditless import dashboard

    def fake_run_scan(params):
        params["password"] = None
        return canned_report()

    seen: dict = {}

    def fake_probe(hosts, **kwargs):
        seen["hosts"] = hosts
        seen["kwargs"] = kwargs
        return hosts[:2]

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    monkeypatch.setattr(dashboard, "probe_hosts", fake_probe)

    result = client.range_scan(
        "192.168.1.0/29", "admin", "PW-SENTINEL-9z9z", port=2222, probe_timeout=0.5
    )
    assert result["network"] == "192.168.1.0/29"
    assert result["candidates"] == 6
    assert result["discovered"] == 2
    assert [job["host"] for job in result["jobs"]] == [
        "192.168.1.1",
        "192.168.1.2",
    ]
    assert seen["hosts"][0] == "192.168.1.1"
    assert seen["kwargs"]["port"] == 2222
    assert seen["kwargs"]["timeout"] == 0.5

    done = client.wait_for(result["jobs"][0]["job_id"])
    assert done["status"] == "done"
    assert done["report"]["summary"]["hardening_index"] == 50
    assert "PW-SENTINEL-9z9z" not in str(result)
    assert "PW-SENTINEL-9z9z" not in str(done)


def test_range_scan_rejects_invalid_input(client, monkeypatch):
    from auditless import dashboard

    monkeypatch.setattr(dashboard, "probe_hosts", lambda hosts, **kw: hosts)
    cases = [
        ("not-a-range", "u", "p"),
        ("10.0.0.0/8", "u", "p"),
        ("192.168.1.0/30", "", "p"),
        ("192.168.1.0/30", "u", ""),
    ]
    for network, username, password in cases:
        with pytest.raises(ApiError) as exc_info:
            client.range_scan(network, username, password)
        assert exc_info.value.status == 400


def test_range_scan_with_no_reachable_hosts(client, monkeypatch):
    from auditless import dashboard

    monkeypatch.setattr(dashboard, "probe_hosts", lambda hosts, **kw: [])
    result = client.range_scan("192.168.1.0/30", "u", "p")
    assert result["candidates"] == 2
    assert result["discovered"] == 0
    assert result["jobs"] == []


def test_fleet_heatmap_host_and_issue_modes(client, monkeypatch):
    def fake_run_scan(params):
        params["password"] = None
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    host = client.create_host("hm", "192.168.5.9", "u", auth="password")
    empty = client.heatmap("host")
    assert empty["total_hosts"] == 1
    assert empty["groups"][0]["tiles"][0]["sublabel"] == "not scanned"

    done = client.wait_for(client.start_scan(host_id=host["id"], password="x")["id"])
    assert done["status"] == "done"

    host_map = client.heatmap("host")
    assert host_map["mode"] == "host"
    assert host_map["total_hosts"] == 1
    group = host_map["groups"][0]
    assert group["name"] == "192.168.5.0/24"
    tile = group["tiles"][0]
    assert tile["label"] == "hm"
    assert tile["sublabel"] == "50/100"
    assert tile["meta"]["host_id"] == host["id"]

    issue_map = client.heatmap("issue")
    assert issue_map["mode"] == "issue"
    assert issue_map["total_tiles"] == 1
    issue = issue_map["groups"][0]["tiles"][0]
    assert issue["id"] == "FIRE-4512"
    assert issue["meta"]["worst"] == "fail"
    assert "off" not in str(issue)  # raw check details never leave the endpoint


def test_fleet_heatmap_rejects_unknown_mode(client):
    with pytest.raises(ApiError) as exc_info:
        client.heatmap("bogus")
    assert exc_info.value.status == 400


def test_json_report_carries_package_version():
    from auditless import __version__
    from auditless.checks import SystemInfo
    from auditless.report import render_report_json

    payload = json.loads(
        render_report_json(SystemInfo("h", "os", "k", "u", "u"), [], [])
    )
    assert payload["scan_info"]["version"] == __version__


def test_token_auth_flow(client, monkeypatch):
    """With AUDITLESS_TOKEN set: 401s, header/query acceptance, open pages."""
    import urllib.request

    from auditless.client import ApiClient, ApiError

    monkeypatch.setenv("AUDITLESS_TOKEN", "TEST-TOKEN-9z9z")
    base = client.base_url

    with pytest.raises(ApiError) as exc_info:
        client.list_scans()
    assert exc_info.value.status == 401

    authed = ApiClient(base, token="TEST-TOKEN-9z9z")
    assert authed.list_scans() == []
    host = authed.create_host("tok", "h", "u")
    assert host["name"] == "tok"

    with pytest.raises(ApiError) as exc_info:
        ApiClient(base, token="wrong").list_scans()
    assert exc_info.value.status == 401

    with urllib.request.urlopen(
        base + "/api/scans?token=TEST-TOKEN-9z9z", timeout=10
    ) as resp:
        assert resp.status == 200

    # Liveness, UI shell, and docs stay public.
    assert client.health() == {"status": "ok"}
    with urllib.request.urlopen(base + "/", timeout=10) as resp:
        html = resp.read().decode()
        assert "tokbar" in html and "sessionStorage" in html
    with urllib.request.urlopen(base + "/docs", timeout=10) as resp:
        assert resp.status == 200


def test_cli_serve_flags():
    from auditless.cli import build_parser

    args = build_parser().parse_args(["--serve"])
    assert args.serve is True
    assert args.serve_host == "127.0.0.1"
    assert args.serve_port == 8080


def test_cli_serve_bind_env_config(monkeypatch):
    """Bind address/port come from env, CLI flags win."""
    from auditless.cli import build_parser

    monkeypatch.setenv("AUDITLESS_HOST", "0.0.0.0")
    monkeypatch.setenv("AUDITLESS_PORT", "9000")
    args = build_parser().parse_args(["--serve"])
    assert args.serve_host == "0.0.0.0"
    assert args.serve_port == 9000
    args = build_parser().parse_args(
        ["--serve", "--serve-host", "127.0.0.1", "--serve-port", "9001"]
    )
    assert (args.serve_host, args.serve_port) == ("127.0.0.1", 9001)


def test_serve_warns_on_non_loopback(monkeypatch, capsys):
    """Binding off loopback prints a loud warning (then serves)."""
    from auditless import dashboard

    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    dashboard.serve_forever("0.0.0.0", 8080)
    assert "exposes the unauthenticated dashboard" in capsys.readouterr().err
    dashboard.serve_forever("127.0.0.1", 8080)
    assert "exposes" not in capsys.readouterr().err


def test_cli_serve_dispatch(monkeypatch):
    from auditless import cli

    called = {}
    monkeypatch.setattr(
        "auditless.dashboard.serve_forever",
        lambda host, port, scheduler=True: called.update(
            host=host, port=port, scheduler=scheduler
        ),
    )
    assert cli.main(["--serve", "--serve-port", "9001"]) == 0
    assert called == {"host": "127.0.0.1", "port": 9001, "scheduler": True}
    assert cli.main(["--serve", "--no-scheduler"]) == 0
    assert called["scheduler"] is False


def test_cli_missing_positionals_errors(capsys):
    from auditless.cli import main

    with pytest.raises(SystemExit):
        main([])
    assert "hostname" in capsys.readouterr().err


def test_hosts_crud(client):
    with pytest.raises(ApiError) as exc_info:
        client.get_host("missing")
    assert exc_info.value.status == 404
    host = client.create_host("web", "10.0.0.9", "admin", port=2222, auth="key")
    assert host["has_key"] == 0
    assert "BEGIN" not in json.dumps(host)
    assert client.get_host(host["id"])["hostname"] == "10.0.0.9"
    assert any(h["id"] == host["id"] for h in client.list_hosts())
    updated = client.update_host(host["id"], port=22)
    assert updated["port"] == 22
    assert client.delete_host(host["id"])["deleted"] == host["id"]
    assert client.list_hosts() == []


def test_host_key_lifecycle_never_readable(client, tmp_path):
    host = client.create_host("k", "h", "u", auth="key")
    assert client.get_host_key(host["id"]) == {"host_id": host["id"], "has_key": False}
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nSENTINEL-KEY-9z9z\n"
    assert client.put_host_key(host["id"], secret)["has_key"] is True
    assert client.get_host_key(host["id"])["has_key"] is True
    # Key bytes must not surface anywhere in the API.
    dump = json.dumps(client.get_host(host["id"])) + json.dumps(client.list_hosts())
    assert "SENTINEL-KEY-9z9z" not in dump
    assert client.delete_host_key(host["id"])["has_key"] is False
    assert client.get_host_key(host["id"])["has_key"] is False
    with pytest.raises(ApiError) as exc_info:
        client.put_host_key(host["id"], "   ")
    assert exc_info.value.status == 400


def test_key_file_permissions(client):
    import os
    import stat

    from auditless.dashboard import get_store

    host = client.create_host("k", "h", "u", auth="key")
    client.put_host_key(host["id"], "SENTINEL-PERM-KEY")
    if os.name != "nt":  # Windows has no POSIX permission bits
        mode = stat.S_IMODE(os.stat(get_store().key_path(host["id"])).st_mode)
        assert mode == 0o600, oct(mode)
    else:
        assert get_store().has_host_key(host["id"]) is True


def test_scan_saved_password_host(client, monkeypatch):
    seen = {}

    def fake_run_scan(params):
        seen.update(params)
        params["password"] = None
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    host = client.create_host("pw", "10.1.1.1", "root", auth="password")
    job = client.start_scan(host_id=host["id"], password=SENTINEL_PASSWORD)
    done = client.wait_for(job["id"])
    assert done["status"] == "done"
    assert seen["hostname"] == "10.1.1.1"
    assert "key_path" not in seen or not seen["key_path"]
    assert SENTINEL_PASSWORD not in json.dumps(done)


def test_scan_saved_key_host_uses_stored_key(client, monkeypatch):
    seen = {}

    def fake_run_scan(params):
        seen.update(params)
        params["password"] = None
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    host = client.create_host("kk", "10.2.2.2", "root", auth="key")
    client.put_host_key(host["id"], "SENTINEL-STORED-KEY")
    job = client.start_scan(host_id=host["id"])  # no password needed
    done = client.wait_for(job["id"])
    assert done["status"] == "done"
    # Key materializes to a 0600 temp file for the run, then is unlinked.
    assert "auditless-key-" in seen["key_path"]
    assert not Path(seen["key_path"]).exists()
    assert SENTINEL_PASSWORD not in json.dumps(done)


def test_scan_host_errors(client):
    with pytest.raises(ApiError) as exc_info:
        client.start_scan(host_id="missing", password="x")
    assert exc_info.value.status == 404
    host = client.create_host("nokey", "h", "u", auth="key")
    with pytest.raises(ApiError) as exc_info:
        client.start_scan(host_id=host["id"])
    assert exc_info.value.status == 400
    pw = client.create_host("nopw", "h", "u", auth="password")
    with pytest.raises(ApiError) as exc_info:
        client.start_scan(host_id=pw["id"])
    assert exc_info.value.status == 400


def test_reports_persisted_and_diffed(client, monkeypatch):
    def fake_run_scan(params):
        params["password"] = None
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    host = client.create_host("hist", "10.3.3.3", "u", auth="password")
    first = client.wait_for(client.start_scan(host_id=host["id"], password="x")["id"])
    assert first["status"] == "done"
    stored = client.list_reports(host_id=host["id"])
    assert len(stored) == 1 and stored[0]["hardening_index"] == 50
    full = client.get_stored_report(stored[0]["id"])
    assert full["report"]["summary"]["hardening_index"] == 50

    # Second report with one fix and one regression.
    improved = canned_report()
    improved["checks"][0]["status"] = "pass"  # Firewall fixed
    improved["checks"][1]["status"] = "fail"  # Disk regressed
    improved["summary"]["hardening_index"] = 55

    def fake_run_scan2(params):
        params["password"] = None
        return improved

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan2)
    second = client.wait_for(client.start_scan(host_id=host["id"], password="x")["id"])
    assert second["status"] == "done"
    ids = [r["id"] for r in client.list_reports(host_id=host["id"])]
    assert len(ids) == 2
    diff = client.diff_reports(ids[1], ids[0])
    assert diff["hardening_delta"] == 5
    assert [f["test_id"] for f in diff["fixed"]] == ["FIRE-4512"]
    assert [r["test_id"] for r in diff["regressed"]] == ["STOR-6310"]
    assert client.delete_stored_report(ids[0])["deleted"] == ids[0]
    with pytest.raises(ApiError) as exc_info:
        client.diff_reports(ids[1], ids[0])
    assert exc_info.value.status == 404


def test_list_reports_filters_and_pagination(client):
    """Reports support status/host/time filters and bounded paging."""
    store = dashboard.get_store()
    store.save_report("r1", "alpha", "u", "done", None, None, "h1", 100.0, 101.0)
    store.save_report("r2", "beta", "u", "error", None, "boom", "h2", 200.0, 201.0)
    store.save_report("r3", "alpha", "u", "done", None, None, "h1", 300.0, 301.0)

    assert [r["id"] for r in client.list_reports()] == ["r3", "r2", "r1"]
    assert [r["id"] for r in client.list_reports(limit=2)] == ["r3", "r2"]
    assert [r["id"] for r in client.list_reports(limit=1, offset=1)] == ["r2"]
    assert [r["id"] for r in client.list_reports(status="error")] == ["r2"]
    assert [r["id"] for r in client.list_reports(host_id="h1")] == ["r3", "r1"]
    assert [r["id"] for r in client.list_reports(host="alpha")] == ["r3", "r1"]
    assert [r["id"] for r in client.list_reports(since=150, until=250)] == ["r2"]
    assert [
        r["id"]
        for r in client.list_reports(
            since="1970-01-01T00:02:30Z", until="1970-01-01T00:04:10Z"
        )
    ] == ["r2"]

    for bad in (
        {"status": "bogus"},
        {"since": "not-a-date"},
        {"until": "not-a-date"},
        {"since": 300, "until": 100},
    ):
        with pytest.raises(ApiError) as exc_info:
            client.list_reports(**bad)
        assert exc_info.value.status == 400
    for bad in ({"limit": 0}, {"limit": 9999}, {"offset": -1}):
        with pytest.raises(ApiError) as exc_info:
            client.list_reports(**bad)
        assert exc_info.value.status == 422


def test_list_hosts_filters_and_pagination(client):
    """Hosts keep the all-hosts default while offering filters and paging."""
    first = client.create_host("web-a", "10.0.0.1", "u")
    second = client.create_host("db-b", "10.0.0.2", "u")

    all_hosts = client.list_hosts()
    assert {h["id"] for h in all_hosts} == {first["id"], second["id"]}
    assert [h["id"] for h in client.list_hosts(limit=1)] == [all_hosts[0]["id"]]
    assert [h["id"] for h in client.list_hosts(limit=1, offset=1)] == [
        all_hosts[1]["id"]
    ]
    assert [h["id"] for h in client.list_hosts(host="web")] == [first["id"]]
    assert [h["id"] for h in client.list_hosts(host="10.0.0.2")] == [second["id"]]
    now = time.time()
    assert {h["id"] for h in client.list_hosts(since=now - 60, until=now + 60)} == {
        first["id"],
        second["id"],
    }
    assert client.list_hosts(since=now + 60) == []

    for bad in ({"since": "not-a-date"}, {"until": "not-a-date"}):
        with pytest.raises(ApiError) as exc_info:
            client.list_hosts(**bad)
        assert exc_info.value.status == 400
    with pytest.raises(ApiError) as exc_info:
        client.list_hosts(since=now, until=now - 60)
    assert exc_info.value.status == 400
    for bad in ({"limit": 0}, {"limit": 9999}, {"offset": -1}):
        with pytest.raises(ApiError) as exc_info:
            client.list_hosts(**bad)
        assert exc_info.value.status == 422


def test_list_scans_filters_and_pagination(client):
    """Scan history supports host/status/time filters and bounded paging."""
    for job_id, hostname, status, created in (
        ("s1", "web-01", "done", 100.0),
        ("s2", "db-01", "error", 200.0),
        ("s3", "web-02", "done", 300.0),
    ):
        dashboard._register_job(
            dashboard.ScanJob(
                id=job_id,
                hostname=hostname,
                username="u",
                status=status,
                created_at=created,
            )
        )

    assert [j["id"] for j in client.list_scans()] == ["s3", "s2", "s1"]
    assert [j["id"] for j in client.list_scans(limit=2)] == ["s3", "s2"]
    assert [j["id"] for j in client.list_scans(limit=1, offset=1)] == ["s2"]
    assert [j["id"] for j in client.list_scans(status="done")] == ["s3", "s1"]
    assert [j["id"] for j in client.list_scans(host="web")] == ["s3", "s1"]
    assert [j["id"] for j in client.list_scans(since=150, until=250)] == ["s2"]

    for bad in (
        {"status": "bogus"},
        {"since": "not-a-date"},
        {"until": "not-a-date"},
        {"since": 300, "until": 100},
    ):
        with pytest.raises(ApiError) as exc_info:
            client.list_scans(**bad)
        assert exc_info.value.status == 400
    for bad in ({"limit": 0}, {"limit": 9999}, {"offset": -1}):
        with pytest.raises(ApiError) as exc_info:
            client.list_scans(**bad)
        assert exc_info.value.status == 422


def test_ssh_key_auth_wiring(monkeypatch):
    """SSHSession passes key_filename through to paramiko."""
    from unittest.mock import MagicMock, patch

    from auditless.ssh_client import SSHSession

    with patch("auditless.ssh_client.paramiko.SSHClient") as cls:
        mock_client = MagicMock()
        cls.return_value = mock_client
        session = SSHSession("h", "u", "", key_path="/keys/abc")
        session.connect()
        _, kwargs = mock_client.connect.call_args
        assert kwargs["key_filename"] == "/keys/abc"
        assert kwargs["password"] is None


def test_cli_key_file_flag():
    from auditless.cli import build_parser

    args = build_parser().parse_args(["h", "u", "--key-file", "/keys/abc"])
    assert args.key_file == "/keys/abc"
