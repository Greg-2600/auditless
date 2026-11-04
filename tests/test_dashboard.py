"""Tests for the Auditless FastAPI dashboard + documented API.

The suite talks to the app exclusively through the first-party
ApiClient (real HTTP against uvicorn), so every assertion exercises the
public API surface exactly as users see it.
"""

import json
import socket
import threading
import time

import pytest
import uvicorn

from linux_health import dashboard
from linux_health.client import ApiClient, ApiError
from linux_health.dashboard import app, get_job, list_jobs

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


@pytest.fixture()
def client():
    """Live uvicorn server + ApiClient, job store reset around each test."""
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    api = ApiClient(f"http://127.0.0.1:{port}", timeout=10.0)
    end = time.time() + 15
    while time.time() < end:
        try:
            api.health()
            break
        except Exception:  # server still booting
            time.sleep(0.1)
    else:
        raise AssertionError("test server did not start")
    yield api
    server.should_exit = True
    thread.join(timeout=10)
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()


def test_healthz(client):
    assert client.health() == {"status": "ok"}


def test_index_serves_spa(client):
    import urllib.request

    with urllib.request.urlopen(client.base_url + "/", timeout=10) as resp:
        html = resp.read().decode()
    assert "Auditless" in html
    assert "/docs" in html


def test_swagger_ui_available(client):
    import urllib.request

    with urllib.request.urlopen(client.base_url + "/docs", timeout=10) as resp:
        assert "swagger" in resp.read().decode().lower()


def test_post_requires_credentials(client):
    with pytest.raises(ApiError) as exc_info:
        client._request("POST", "/api/scans", {"hostname": "h", "username": "u"})
    assert exc_info.value.status == 422  # Pydantic: missing password


def test_post_rejects_non_object(client):
    import urllib.request

    req = urllib.request.Request(
        client.base_url + "/api/scans",
        data=b"[1, 2]",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("expected HTTP error")
    except OSError as exc:  # HTTPError
        assert getattr(exc, "code", None) == 422


def test_unknown_scan_id_404(client):
    with pytest.raises(ApiError) as exc_info:
        client.get_scan("nope123")
    assert exc_info.value.status == 404


def test_full_scan_flow_hides_password(client, monkeypatch):
    """Mocked run: report returned, sentinel password appears nowhere."""
    from linux_health.dashboard import _run_job

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

    monkeypatch.setattr("linux_health.cli.main", fake_main)
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


def test_run_scan_requires_password():
    with pytest.raises(RuntimeError, match="password is required"):
        dashboard.run_scan({"hostname": "h", "username": "u", "password": ""})


def test_version_endpoint(client):
    info = client.version()
    from linux_health import __version__

    assert info["version"] == __version__ == "2.0.0"
    assert info["api_version"] == "1.0"
    assert "ssh-scan" in info["features"]


def test_openapi_spec_is_complete(client):
    spec = client.openapi_spec()
    assert spec["openapi"].startswith("3.")
    for path in (
        "/healthz",
        "/api/version",
        "/api/scans",
        "/api/scans/{job_id}",
        "/api/scans/{job_id}/report",
        "/api/profiles",
    ):
        assert path in spec["paths"], path
    props = spec["components"]["schemas"]["ScanRequest"]["properties"]
    assert props["password"].get("writeOnly") is True
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
    from linux_health.client import ApiClient, ApiError

    with pytest.raises(ApiError, match="non-HTTP"):
        ApiClient("ftp://example.com").health()


def test_json_report_carries_package_version():
    from linux_health import __version__
    from linux_health.checks import SystemInfo
    from linux_health.report import render_report_json

    payload = json.loads(
        render_report_json(SystemInfo("h", "os", "k", "u", "u"), [], [])
    )
    assert payload["scan_info"]["version"] == __version__


def test_cli_serve_flags():
    from linux_health.cli import build_parser

    args = build_parser().parse_args(["--serve"])
    assert args.serve is True
    assert args.serve_host == "127.0.0.1"
    assert args.serve_port == 8080


def test_cli_serve_dispatch(monkeypatch):
    from linux_health import cli

    called = {}
    monkeypatch.setattr(
        "linux_health.dashboard.serve_forever",
        lambda host, port: called.update(host=host, port=port),
    )
    assert cli.main(["--serve", "--serve-port", "9001"]) == 0
    assert called == {"host": "127.0.0.1", "port": 9001}


def test_cli_missing_positionals_errors(capsys):
    from linux_health.cli import main

    with pytest.raises(SystemExit):
        main([])
    assert "hostname" in capsys.readouterr().err
