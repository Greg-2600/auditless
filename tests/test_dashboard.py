"""Tests for the Auditless local web dashboard (stdlib HTTP, no extra deps)."""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from linux_health import dashboard
from linux_health.dashboard import get_job, list_jobs, run_server

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
def server():
    """Running dashboard server on an ephemeral loopback port."""
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()
    srv = run_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()


def _request(base, path, method="GET", payload=None, expect=200):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            assert resp.status == expect, body
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        assert exc.code == expect, body
        return exc.code, body


def _wait_done(base, job_id, deadline=15.0):
    end = time.time() + deadline
    while time.time() < end:
        _, body = _request(base, f"/api/scans/{job_id}")
        job = json.loads(body)
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.2)
    raise AssertionError(f"job {job_id} did not finish in time")


def test_healthz(server):
    code, body = _request(server, "/healthz")
    assert code == 200
    assert json.loads(body)["status"] == "ok"


def test_index_serves_spa(server):
    code, body = _request(server, "/")
    assert code == 200
    assert "Auditless" in body
    assert "/api/scans" in body


def test_post_requires_credentials(server):
    code, body = _request(
        server,
        "/api/scans",
        method="POST",
        payload={"hostname": "h", "username": "u"},
        expect=400,
    )
    assert code == 400
    assert "required" in body


def test_post_rejects_non_object(server):
    code, _ = _request(server, "/api/scans", method="POST", payload=[1, 2], expect=400)
    assert code == 400


def test_unknown_scan_id_404(server):
    code, _ = _request(server, "/api/scans/nope123", expect=404)
    assert code == 404


def test_full_scan_flow_hides_password(server, monkeypatch):
    """Mocked run: report returned, sentinel password appears nowhere."""

    def fake_run_scan(params):
        params["password"] = None  # mirror run_scan scrubbing
        return canned_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    code, body = _request(
        server,
        "/api/scans",
        method="POST",
        payload={
            "hostname": "web-01",
            "username": "root",
            "password": SENTINEL_PASSWORD,
        },
        expect=201,
    )
    assert code == 201
    assert SENTINEL_PASSWORD not in body
    job_id = json.loads(body)["id"]

    job = _wait_done(server, job_id)
    assert job["status"] == "done"
    assert job["report"]["summary"]["hardening_index"] == 50

    # History + detail responses must not leak the password either.
    _, listing = _request(server, "/api/scans")
    _, detail = _request(server, f"/api/scans/{job_id}")
    assert SENTINEL_PASSWORD not in listing
    assert SENTINEL_PASSWORD not in detail

    stored = get_job(job_id)
    assert stored is not None
    assert "password" not in stored.summary()
    assert any(j["id"] == job_id for j in list_jobs())


def test_scan_error_path(server, monkeypatch):
    """Failing run surfaces an error status without credentials."""

    def boom(params):
        params["password"] = None
        raise RuntimeError("ssh unreachable (test)")

    monkeypatch.setattr(dashboard, "run_scan", boom)
    _, body = _request(
        server,
        "/api/scans",
        method="POST",
        payload={"hostname": "gone", "username": "u", "password": SENTINEL_PASSWORD},
        expect=201,
    )
    job = _wait_done(server, json.loads(body)["id"])
    assert job["status"] == "error"
    assert "unreachable" in (job["error"] or "")
    assert SENTINEL_PASSWORD not in json.dumps(job)


def test_run_scan_builds_cli_argv(monkeypatch, tmp_path):
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


def test_cli_serve_flags():
    from linux_health.cli import build_parser

    args = build_parser().parse_args(["--serve"])
    assert args.serve is True
    assert args.serve_host == "127.0.0.1"
    assert args.serve_port == 8080
    args = build_parser().parse_args(
        ["--serve", "--serve-host", "0.0.0.0", "--serve-port", "9000"]
    )
    assert args.serve_host == "0.0.0.0"
    assert args.serve_port == 9000


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
