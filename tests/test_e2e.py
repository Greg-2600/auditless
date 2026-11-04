"""End-to-end suite: real containers, real SSH, every feature exercised.

Spins up a throwaway OpenSSH server and the auditless app (both Docker),
then drives CLI scans, key auth, the full HTTP API, persistence across
restarts, and report diffing — all through the first-party ApiClient.

Run locally:  AUDITLESS_E2E=1 .venv/bin/python -m pytest tests/test_e2e.py -v
CI runs the same via the `e2e` workflow job. Without AUDITLESS_E2E=1 (or
without a working docker daemon) the whole module skips cleanly.
"""

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from linux_health.client import ApiClient, ApiError

E2E_PASSWORD = "e2e-pw-SENTINEL-7k7k"
E2E_KEY_COMMENT = "e2e-key-SENTINEL-9q9q"
SSH_IMAGE = "lscr.io/linuxserver/openssh-server:latest"
NETWORK = "auditless-e2e-net"
SSH_NAME = "auditless-e2e-ssh"
APP_NAME = "auditless-e2e-app"
VOLUME = "auditless-e2e-data"

pytestmark = pytest.mark.skipif(
    os.environ.get("AUDITLESS_E2E") != "1",
    reason="set AUDITLESS_E2E=1 to run containerized end-to-end tests",
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run the docker CLI (colima-backed on macOS, native on CI)."""
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=300
    )


def docker_available() -> bool:
    """Daemon reachable (None-safe for skip decisions)."""
    if shutil.which("docker") is None:
        return False
    proc = docker("info", check=False)
    return proc.returncode == 0


def free_port() -> int:
    """Ephemeral loopback port for publishing container services."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_ssh(
    host: str, port: int, username: str, password: str, deadline: float = 120
) -> None:
    """Poll paramiko until the throwaway SSH server accepts logins."""
    import paramiko

    end = time.time() + deadline
    last: Exception | None = None
    while time.time() < end:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=5,
                allow_agent=False,
                look_for_keys=False,
            )
            client.close()
            return
        except Exception as exc:  # still booting
            last = exc
            time.sleep(2)
        finally:
            client.close()
    raise AssertionError(f"SSH target never came up: {last}")


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    """Build images, boot SSH + app containers on one network, yield handles."""
    if not docker_available():
        pytest.skip("docker daemon not reachable")
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen required for key-auth tests")

    workdir = tmp_path_factory.mktemp("e2e")
    key_path = workdir / "e2e_ed25519"
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            E2E_KEY_COMMENT,
            "-f",
            str(key_path),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    private_key = key_path.read_text()
    public_key = (workdir / "e2e_ed25519.pub").read_text().strip()

    ssh_port = free_port()
    app_port = free_port()

    docker("network", "create", NETWORK, check=False)
    try:
        docker("pull", SSH_IMAGE)
        docker(
            "run",
            "-d",
            "--name",
            SSH_NAME,
            "--network",
            NETWORK,
            "-p",
            f"127.0.0.1:{ssh_port}:2222",
            "-e",
            "USER_NAME=tester",
            "-e",
            f"USER_PASSWORD={E2E_PASSWORD}",
            "-e",
            "PASSWORD_ACCESS=true",
            "-e",
            "SUDO_ACCESS=true",
            "-e",
            f"PUBLIC_KEY={public_key}",
            SSH_IMAGE,
        )
        wait_for_ssh("127.0.0.1", ssh_port, "tester", E2E_PASSWORD)

        docker("build", "-t", "auditless:e2e", str(REPO_ROOT))
        docker("volume", "create", VOLUME, check=False)
        docker(
            "run",
            "-d",
            "--name",
            APP_NAME,
            "--network",
            NETWORK,
            "-p",
            f"127.0.0.1:{app_port}:8080",
            "-e",
            "PYTHONUNBUFFERED=1",
            "-e",
            "AUDITLESS_DATA_DIR=/app/data",
            "-v",
            f"{VOLUME}:/app/data",
            "auditless:e2e",
            "--serve",
            "--serve-host",
            "0.0.0.0",
            "--serve-port",
            "8080",
        )
        api = ApiClient(f"http://127.0.0.1:{app_port}", timeout=30.0)
        end = time.time() + 120
        while time.time() < end:
            try:
                api.health()
                break
            except Exception:
                time.sleep(1)
        else:
            raise AssertionError("app container never became healthy")

        yield {
            "api": api,
            "ssh_host": "127.0.0.1",  # from the test runner
            "ssh_port": ssh_port,
            "ssh_name": SSH_NAME,  # from inside the app container
            "username": "tester",
            "password": E2E_PASSWORD,
            "private_key": private_key,
            "key_path": key_path,
        }
    finally:
        docker("rm", "-f", APP_NAME, check=False)
        docker("rm", "-f", SSH_NAME, check=False)
        docker("network", "rm", NETWORK, check=False)
        docker("volume", "rm", VOLUME, check=False)


def run_cli(*argv: str, timeout: int = 420) -> subprocess.CompletedProcess:
    """One-shot CLI scan from the checkout's venv."""
    import sys

    venv_python = str(Path(sys.executable))
    return subprocess.run(
        [venv_python, "-m", "linux_health", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(REPO_ROOT),
    )


def test_cli_text_scan(stack):
    """Full password scan over SSH prints a hardening index."""
    proc = run_cli(
        stack["ssh_host"],
        stack["username"],
        stack["password"],
        "--port",
        str(stack["ssh_port"]),
        "--timeout",
        "10",
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "HARDENING INDEX" in proc.stdout
    assert E2E_PASSWORD not in proc.stdout


def test_cli_json_scan_to_file(stack, tmp_path):
    """JSON report to disk carries version + checks + no secrets."""
    out = tmp_path / "scan.json"
    proc = run_cli(
        stack["ssh_host"],
        stack["username"],
        stack["password"],
        "--port",
        str(stack["ssh_port"]),
        "--timeout",
        "10",
        "--format",
        "json",
        "--output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    report = json.loads(out.read_text())
    assert report["summary"]["hardening_index"] is not None
    assert len(report["checks"]) > 50
    assert E2E_PASSWORD not in out.read_text()


def test_cli_markdown_scan(stack, tmp_path):
    """Markdown report renders."""
    out = tmp_path / "scan.md"
    proc = run_cli(
        stack["ssh_host"],
        stack["username"],
        stack["password"],
        "--port",
        str(stack["ssh_port"]),
        "--timeout",
        "10",
        "--format",
        "md",
        "--output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "Hardening" in out.read_text() or "hardening" in out.read_text().lower()


def test_cli_key_auth_scan(stack, tmp_path):
    """Key auth (no password) completes a real scan."""
    out = tmp_path / "keyscan.json"
    proc = run_cli(
        stack["ssh_host"],
        stack["username"],
        "",
        "--port",
        str(stack["ssh_port"]),
        "--timeout",
        "10",
        "--key-file",
        str(stack["key_path"]),
        "--format",
        "json",
        "--output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    report = json.loads(out.read_text())
    assert len(report["checks"]) > 50


def test_cli_strict_host_key_rejects_unknown(stack):
    """--strict-host-key-checking fails closed on unknown keys (MITM-safe)."""
    proc = run_cli(
        stack["ssh_host"],
        stack["username"],
        stack["password"],
        "--port",
        str(stack["ssh_port"]),
        "--timeout",
        "10",
        "--strict-host-key-checking",
    )
    assert proc.returncode != 0
    assert E2E_PASSWORD not in proc.stdout


def test_api_version_and_profiles(stack):
    """Version + profile discovery through the public client."""
    info = stack["api"].version()
    from linux_health import __version__

    assert info["version"] == __version__
    assert "ssh-scan" in info["features"]
    assert isinstance(stack["api"].list_profiles(), list)
    spec = stack["api"].openapi_spec()
    for path in ("/api/hosts", "/api/reports", "/api/diff"):
        assert path in spec["paths"]


def test_api_ui_and_docs(stack):
    """UI index and Swagger load from the container."""
    import urllib.request

    base = stack["api"].base_url
    with urllib.request.urlopen(base + "/", timeout=30) as resp:
        assert "Auditless" in resp.read().decode()
    with urllib.request.urlopen(base + "/docs", timeout=30) as resp:
        assert "swagger" in resp.read().decode().lower()


def test_api_host_crud_and_key(stack):
    """Saved hosts + write-only key, no bytes ever readable."""
    api = stack["api"]
    host = api.create_host("e2e-box", SSH_NAME, "tester", auth="key")
    assert host["has_key"] == 0
    assert api.put_host_key(host["id"], stack["private_key"])["has_key"] is True
    assert api.get_host_key(host["id"])["has_key"] is True
    dump = json.dumps(api.get_host(host["id"])) + json.dumps(api.list_hosts())
    assert E2E_KEY_COMMENT not in dump
    assert api.update_host(host["id"], port=22)["port"] == 22
    assert api.delete_host_key(host["id"])["has_key"] is False
    assert api.delete_host(host["id"])["deleted"] == host["id"]


def test_api_password_scan_persisted(stack):
    """API scan by raw creds finishes, persists, and hides secrets."""
    api = stack["api"]
    job = api.start_scan(
        hostname=SSH_NAME,
        username="tester",
        password=E2E_PASSWORD,
        port=2222,
        timeout=10.0,
    )
    assert job["status"] in ("queued", "running", "done")
    done = api.wait_for(job["id"], deadline=420, interval=2.0)
    assert done["status"] == "done", done.get("error")
    assert done["report"]["summary"]["hardening_index"] is not None
    assert E2E_PASSWORD not in json.dumps(done)
    stored = api.list_reports()
    assert any(r["id"] == job["id"] for r in stored)
    full = api.get_stored_report(job["id"])
    assert full["report"]["summary"]["total_checks"] > 50


def test_api_key_host_scan(stack):
    """Key-auth host scan with no password anywhere in the request."""
    api = stack["api"]
    host = api.create_host("e2e-keybox", SSH_NAME, "tester", port=2222, auth="key")
    api.put_host_key(host["id"], stack["private_key"])
    done = api.wait_for(
        api.start_scan(host_id=host["id"])["id"], deadline=420, interval=2.0
    )
    assert done["status"] == "done", done.get("error")
    assert done["report"]["summary"]["total_checks"] > 50


def test_api_diff_and_report_formats(stack):
    """Two scans of one host diff cleanly; md/text re-render."""
    api = stack["api"]
    first = api.wait_for(
        api.start_scan(
            hostname=SSH_NAME,
            username="tester",
            password=E2E_PASSWORD,
            port=2222,
            timeout=10.0,
        )["id"],
        deadline=420,
        interval=2.0,
    )
    second = api.wait_for(
        api.start_scan(
            hostname=SSH_NAME,
            username="tester",
            password=E2E_PASSWORD,
            port=2222,
            timeout=10.0,
        )["id"],
        deadline=420,
        interval=2.0,
    )
    assert first["status"] == "done" and second["status"] == "done"
    diff = api.diff_reports(first["id"], second["id"])
    assert diff["hardening_delta"] == 0
    assert diff["fixed"] == [] and diff["regressed"] == []
    md = api.get_report(second["id"], format="md")
    assert isinstance(md, str) and len(md) > 1000
    with pytest.raises(ApiError) as exc_info:
        api.get_report(second["id"], format="xml")
    assert exc_info.value.status == 400


def test_api_persistence_across_restart(stack):
    """Hosts + reports survive an app container restart (named volume)."""
    api = stack["api"]
    host = api.create_host("e2e-persist", SSH_NAME, "tester", auth="password")
    before = {r["id"] for r in api.list_reports()}
    docker("restart", APP_NAME)
    end = time.time() + 120
    while time.time() < end:
        try:
            api.health()
            break
        except Exception:
            time.sleep(1)
    assert any(h["id"] == host["id"] for h in api.list_hosts())
    after = {r["id"] for r in api.list_reports()}
    assert before <= after
