"""Tests for the Auditless FastAPI dashboard + documented API."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from linux_health import dashboard
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


@pytest.fixture()
def client():
    """TestClient with a clean job store (background tasks enabled)."""
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()
    with TestClient(app) as test_client:
        yield test_client
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()


def _wait_done(client, job_id, deadline=20.0):
    end = time.time() + deadline
    while time.time() < end:
        resp = client.get(f"/api/scans/{job_id}")
        assert resp.status_code == 200
        job = resp.json()
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.2)
    raise AssertionError(f"job {job_id} did not finish in time")


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_index_serves_spa(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Auditless" in resp.text
    assert "/docs" in resp.text


def test_swagger_ui_available(client):
    resp = client.get("/docs")
    assert resp.status_code == 200
    assert "swagger" in resp.text.lower()


def test_post_requires_credentials(client):
    resp = client.post("/api/scans", json={"hostname": "h", "username": "u"})
    assert resp.status_code == 422  # Pydantic: missing required password


def test_post_rejects_non_object(client):
    resp = client.post("/api/scans", json=[1, 2])
    assert resp.status_code == 422


def test_unknown_scan_id_404(client):
    resp = client.get("/api/scans/nope123")
    assert resp.status_code == 404


def test_full_scan_flow_hides_password(client, monkeypatch):
    """Mocked run: report returned, sentinel password appears nowhere."""
    from linux_health.dashboard import _run_job

    def fake_run_scan(params):
        params["password"] = None  # mirror run_scan scrubbing
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    monkeypatch.setattr(dashboard, "_run_job", _run_job)  # keep real runner
    resp = client.post(
        "/api/scans",
        json={
            "hostname": "web-01",
            "username": "root",
            "password": SENTINEL_PASSWORD,
        },
    )
    assert resp.status_code == 201
    assert SENTINEL_PASSWORD not in resp.text
    job_id = resp.json()["id"]

    job = _wait_done(client, job_id)
    assert job["status"] == "done"
    assert job["report"]["summary"]["hardening_index"] == 50

    listing = client.get("/api/scans").text
    detail = client.get(f"/api/scans/{job_id}").text
    assert SENTINEL_PASSWORD not in listing
    assert SENTINEL_PASSWORD not in detail

    stored = get_job(job_id)
    assert stored is not None
    assert "password" not in stored.summary()
    assert any(j["id"] == job_id for j in list_jobs())


def test_scan_error_path(client, monkeypatch):
    """Failing run surfaces an error status without credentials."""

    def boom(params):
        params["password"] = None
        raise RuntimeError("ssh unreachable (test)")

    monkeypatch.setattr(dashboard, "run_scan", boom)
    resp = client.post(
        "/api/scans",
        json={"hostname": "gone", "username": "u", "password": SENTINEL_PASSWORD},
    )
    assert resp.status_code == 201
    job = _wait_done(client, resp.json()["id"])
    assert job["status"] == "error"
    assert "unreachable" in (job["error"] or "")
    assert SENTINEL_PASSWORD not in json.dumps(job)


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
    info = client.get("/api/version").json()
    from linux_health import __version__

    assert info["version"] == __version__ == "2.0.0"
    assert info["api_version"] == "1.0"
    assert "ssh-scan" in info["features"]


def test_openapi_spec_is_complete(client):
    spec = client.get("/openapi.json").json()
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
    resp = client.get("/api/profiles")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def _done_job_id(client, monkeypatch):
    def fake_run_scan(params):
        params["password"] = None
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    resp = client.post(
        "/api/scans",
        json={
            "hostname": "web-01",
            "username": "root",
            "password": SENTINEL_PASSWORD,
        },
    )
    assert resp.status_code == 201
    job = _wait_done(client, resp.json()["id"])
    assert job["status"] == "done"
    return job["id"]


def test_report_formats(client, monkeypatch):
    job_id = _done_job_id(client, monkeypatch)
    md = client.get(f"/api/scans/{job_id}/report", params={"format": "md"})
    assert md.status_code == 200
    assert "markdown" in md.headers["content-type"]
    assert "Firewall" in md.text
    text = client.get(f"/api/scans/{job_id}/report", params={"format": "text"})
    assert text.status_code == 200
    assert "Firewall" in text.text
    assert (
        client.get(f"/api/scans/{job_id}/report", params={"format": "xml"}).status_code
        == 400
    )


def test_report_pending_returns_409(client, monkeypatch):
    import threading as _threading

    release = _threading.Event()

    def slow(params):
        params["password"] = None
        release.wait(15)
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", slow)
    resp = client.post(
        "/api/scans",
        json={"hostname": "h", "username": "u", "password": SENTINEL_PASSWORD},
    )
    job_id = resp.json()["id"]
    try:
        pending = client.get(f"/api/scans/{job_id}/report")
        assert pending.status_code == 409
    finally:
        release.set()
    _wait_done(client, job_id)


def test_delete_job(client, monkeypatch):
    job_id = _done_job_id(client, monkeypatch)
    resp = client.delete(f"/api/scans/{job_id}")
    assert resp.status_code == 200
    assert resp.json() == {"deleted": job_id}
    assert client.get(f"/api/scans/{job_id}").status_code == 404
    assert job_id not in client.get("/api/scans").text
    assert client.delete("/api/scans/nope").status_code == 404


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
