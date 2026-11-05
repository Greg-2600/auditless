"""Tests for service banner grabbing + version inference (ROADMAP item 27)."""

import json
import socket
import threading
from typing import Any

from linux_health.report import render_report_json, render_report_text
from linux_health.scanner import (
    PortStatus,
    _grab_banner,
    _identify_service,
    scan_ports,
)


def _serve_once(payload: bytes, holder: dict[str, Any]) -> int:
    """Background TCP server answering one connection with payload."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    holder["port"] = int(listener.getsockname()[1])

    def _run() -> None:
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5.0)
                conn.sendall(payload)
        finally:
            listener.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return int(holder["port"])


def test_identify_service_table_and_versions() -> None:
    """Port table + banner regexes identify common services."""
    assert _identify_service(22, "SSH-2.0-OpenSSH_9.6p1 Debian-1") == (
        "ssh",
        "9.6p1",
    )
    assert _identify_service(80, "Server: Apache/2.4.57 (Unix)") == ("http", "2.4.57")
    assert _identify_service(80, "server: nginx/1.25.3") == ("http", "1.25.3")
    assert _identify_service(25, "220 mail ESMTP Exim 4.96") == ("smtp", "4.96")
    assert _identify_service(22, "") == ("ssh", None)
    assert _identify_service(9999, "") == (None, None)


def test_grab_banner_spontaneous() -> None:
    """Daemons greeting on connect are captured verbatim-ish."""
    holder: dict[str, Any] = {}
    port = _serve_once(b"SSH-2.0-OpenSSH_9.6p1\r\n", holder)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        assert _grab_banner(sock, 22, 2.0) == "SSH-2.0-OpenSSH_9.6p1"


def test_grab_banner_truncated() -> None:
    """Oversized banners are capped, never fail the scan."""
    holder: dict[str, Any] = {}
    port = _serve_once(b"X" * 500, holder)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        assert len(_grab_banner(sock, port, 2.0)) <= 256


def test_grab_banner_http_probe() -> None:
    """Silent HTTP ports answer the HEAD probe with Server headers."""
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _run() -> None:
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5.0)
                request = conn.recv(1024)
                assert b"HEAD" in request
                conn.sendall(b"HTTP/1.0 200 OK\r\nServer: TestSvc/1.2\r\n\r\n")
        finally:
            listener.close()

    threading.Thread(target=_run, daemon=True).start()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        assert _grab_banner(sock, 80, 2.0) == "HTTP/1.0 200 OK Server: TestSvc/1.2"


def test_scan_single_reports_banner_service_version() -> None:
    """Live loopback probe yields the full identification triple."""
    holder: dict[str, Any] = {}
    port = _serve_once(b"SSH-2.0-OpenSSH_9.6p1\r\n", holder)
    results = scan_ports("127.0.0.1", [port], timeout=3.0)
    assert len(results) == 1
    found = results[0]
    assert found.open is True
    assert found.banner == "SSH-2.0-OpenSSH_9.6p1"
    assert found.version == "9.6p1"


def test_scan_ports_opt_out_skips_banners() -> None:
    """grab_banners=False keeps service guess, drops the banner read."""
    results = scan_ports("127.0.0.1", [22], timeout=3.0, grab_banners=False)
    assert results[0].banner is None
    assert results[0].service == "ssh"


def _base_system() -> Any:
    from linux_health.checks import SystemInfo

    return SystemInfo("h", "TestOS 1.0", "1.0", "1 day", "u")


def test_json_report_carries_service_fields() -> None:
    """open_ports entries expose service/version/banner (additive keys)."""
    ports = [
        PortStatus(
            port=22,
            open=True,
            reason="Connected",
            banner="SSH-2.0-OpenSSH_9.6p1",
            service="ssh",
            version="9.6p1",
        )
    ]
    report = json.loads(render_report_json(_base_system(), [], ports, None))
    entry = report["ports"]["open_ports"][0]
    assert entry["service"] == "ssh"
    assert entry["version"] == "9.6p1"
    assert entry["banner"] == "SSH-2.0-OpenSSH_9.6p1"


def test_text_report_shows_service_suffix() -> None:
    """Human reports append the identification only when known."""
    known = [
        PortStatus(
            port=22, open=True, reason="Connected", service="ssh", version="9.6p1"
        )
    ]
    unknown = [PortStatus(port=22, open=True, reason="Connected")]
    assert "(ssh 9.6p1)" in render_report_text(_base_system(), [], known, None)
    assert "(ssh" not in render_report_text(_base_system(), [], unknown, None)
