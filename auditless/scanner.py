"""Concurrent port scanner for non-invasive service detection.

Provides TCP connect-based port scanning using concurrent threads to efficiently
probe common service ports on target systems. Results are deterministic and
orderable by port number.

Classes:
    PortStatus: Dataclass representing a single port scan result

Functions:
    scan_ports: Scan multiple ports concurrently with configurable timeout
    _scan_single: Internal function for single port scanning

Example:
    >>> results = scan_ports('192.168.1.100', [22, 80, 443])
    >>> open_ports = [r.port for r in results if r.open]
    >>> print(f'Open ports: {open_ports}')
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List

COMMON_PORTS = [
    22,
    80,
    443,
    8080,
    8443,
    3306,
    5432,
    6379,
    3389,
    25,
    110,
    143,
    993,
    995,
    53,
    111,
    139,
    445,
    2049,
    21,
    23,
    5900,
    9200,
    27017,
]


@dataclass
class PortStatus:
    port: int
    open: bool
    reason: str | None = None
    banner: str | None = None
    service: str | None = None
    version: str | None = None


#: Well-known service per port (top-20 coverage; refined by banners).
KNOWN_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

#: Ports that stay silent until probed with an HTTP request line.
_HTTP_PROBE_PORTS = frozenset({80, 8000, 8080, 8888})

#: (compiled pattern, version-group index) tried in order.
_VERSION_PATTERNS: list[tuple[re.Pattern[str], int]] = [
    (re.compile(r"OpenSSH[_-](\d[\d.]*\w*)"), 1),
    (re.compile(r"Apache/(\d[\d.]*)"), 1),
    (re.compile(r"nginx/(\d[\d.]*)"), 1),
    (re.compile(r"Exim (\d[\d.]*\w*)"), 1),
    (re.compile(r"vsFTPd (\d[\d.]*)"), 1),
    (re.compile(r"ProFTPD (\d[\d.]*)"), 1),
    (re.compile(r"Dovecot(?: ready)?[, ] v?(\d[\d.]*)", re.IGNORECASE), 1),
    (re.compile(r"OpenSMTPD (\d[\d.]*)"), 1),
    (re.compile(r"(\d+\.\d+\.\d+)-MariaDB"), 1),
    (re.compile(r"(\d+\.\d+\.\d+)-MySQL"), 1),
    (re.compile(r"lighttpd/(\d[\d.]*)"), 1),
    (re.compile(r"Squid/(\d[\d.]*)"), 1),
    (re.compile(r"Postfix"), 0),
    (re.compile(r"SSH-2\.0-(\S+)"), 1),
    (re.compile(r"220[ -](\S+)"), 1),
]

#: Banner bytes kept per open port (first line-ish, bounded).
_MAX_BANNER = 256


def normalize_host(host: str) -> str:
    """Strip one pair of brackets from RFC 3986 IPv6 literals.

    ``[::1]`` → ``::1`` for socket/SSH APIs; bare hosts, hostnames, and
    already-bare addresses pass through unchanged.
    """
    candidate = host.strip()
    if len(candidate) >= 2 and candidate.startswith("[") and candidate.endswith("]"):
        return candidate[1:-1]
    return candidate


#: Seconds waited for a spontaneous greeting before probing/returning.
_GREETING_WINDOW = 0.5


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """Read a service banner from a connected socket (never raises).

    Most daemons greet spontaneously within a short window; quiet HTTP
    ports get one HEAD probe. Returns decoded text (possibly empty).
    """
    sock.settimeout(_GREETING_WINDOW)
    try:
        data = sock.recv(1024)
    except (socket.timeout, OSError):
        data = b""
    if not data and port in _HTTP_PROBE_PORTS:
        try:
            sock.settimeout(min(timeout, 2.0))
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: auditless\r\n\r\n")
            data = sock.recv(1024)
        except (socket.timeout, OSError):
            return ""
    text = data.decode("utf-8", errors="replace")
    single_line = " ".join(text.split())
    return single_line[:_MAX_BANNER]


def _identify_service(port: int, banner: str) -> tuple[str | None, str | None]:
    """Guess (service, version) from the port table plus banner regexes."""
    service = KNOWN_SERVICES.get(port)
    version: str | None = None
    for pattern, group in _VERSION_PATTERNS:
        match = pattern.search(banner)
        if match:
            version = match.group(group) if group else None
            break
    return service, version


def _scan_single(
    host: str, port: int, timeout: float, grab_banner: bool = True
) -> PortStatus:
    """Probe single port on target host using TCP connect.

    Args:
        host: Target hostname or IP address (v4/v6, brackets optional)
        port: Port number (1-65535)
        timeout: Connection timeout in seconds

    Returns:
        PortStatus with open flag and diagnostic reason

    Note:
        Dual-stack: every address returned for the host is tried in
        order (first success wins). Uses socket.SOCK_STREAM (TCP) for
        connect-based scanning. Handles all exceptions gracefully for
        robust concurrent execution.
    """
    target = normalize_host(host)
    try:
        addrinfos = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return PortStatus(port=port, open=False, reason=str(exc))
    last_error = "no addresses resolved"
    for family, socktype, proto, _canonname, sockaddr in addrinfos:
        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect(sockaddr)
            except socket.timeout:
                last_error = "timeout"
                continue
            except OSError as exc:
                last_error = str(exc)
                continue
            banner = _grab_banner(sock, port, timeout) if grab_banner else ""
            service, version = _identify_service(port, banner)
            return PortStatus(
                port=port,
                open=True,
                reason="Connected",
                banner=banner or None,
                service=service,
                version=version,
            )
    return PortStatus(port=port, open=False, reason=last_error)


def scan_ports(
    host: str,
    ports: Iterable[int],
    timeout: float = 0.7,
    max_workers: int = 50,
    grab_banners: bool = True,
) -> List[PortStatus]:
    """Scan multiple ports concurrently on target host.

    Efficiently probes target system using concurrent TCP connect attempts.
    Results are sorted by port number and include diagnostic failure reasons.

    Args:
        host: Target hostname or IP address (v4/v6, brackets optional)
        ports: Iterable of port numbers to scan (duplicates removed)
        timeout: Per-port connection timeout in seconds (default: 0.7)
        max_workers: Maximum concurrent threads (default: 50)
        grab_banners: Capture service banners on open ports (default: True)

    Returns:
        List of PortStatus objects sorted by port number

    Performance:
        - 25 ports with 50 workers: ~1-3 seconds (typical)
        - Linear with timeout, sublinear with port count
        - Network limited, not CPU limited

    Example:
        >>> results = scan_ports('target.example.com', [22, 80, 443, 3306])
        >>> for r in results:
        ...     status = 'OPEN' if r.open else 'CLOSED'
        ...     print(f':{r.port} {status}')
    """
    target = normalize_host(host)
    unique_ports = sorted({int(p) for p in ports if int(p) > 0})
    results: list[PortStatus] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_scan_single, target, port, timeout, grab_banners): port
            for port in unique_ports
        }
        for future in as_completed(future_to_port):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)
