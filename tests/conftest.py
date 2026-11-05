"""Shared fixtures for dashboard API tests (live uvicorn + ApiClient)."""

import socket
import threading
import time

import pytest
import uvicorn

from linux_health import dashboard
from linux_health.client import ApiClient
from linux_health.dashboard import app


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Live uvicorn + ApiClient; jobs and persistence isolated per test."""
    monkeypatch.setenv("AUDITLESS_DATA_DIR", str(tmp_path / "data"))
    dashboard.reset_store()
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Generous timeout: Windows CI runners are slow to serve first bytes.
    api = ApiClient(f"http://127.0.0.1:{port}", timeout=30.0)
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
    dashboard.reset_store()
    dashboard._jobs.clear()
    dashboard._jobs_order.clear()
