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


def normalize_host(host: str) -> str:
    """Strip one pair of brackets from RFC 3986 IPv6 literals.

    ``[::1]`` → ``::1`` for socket/SSH APIs; bare hosts, hostnames, and
    already-bare addresses pass through unchanged.
    """
    candidate = host.strip()
    if len(candidate) >= 2 and candidate.startswith("[") and candidate.endswith("]"):
        return candidate[1:-1]
    return candidate


def _scan_single(host: str, port: int, timeout: float) -> PortStatus:
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
                return PortStatus(port=port, open=True, reason="Connected")
            except socket.timeout:
                last_error = "timeout"
            except OSError as exc:
                last_error = str(exc)
    return PortStatus(port=port, open=False, reason=last_error)


def scan_ports(
    host: str, ports: Iterable[int], timeout: float = 0.7, max_workers: int = 50
) -> List[PortStatus]:
    """Scan multiple ports concurrently on target host.

    Efficiently probes target system using concurrent TCP connect attempts.
    Results are sorted by port number and include diagnostic failure reasons.

    Args:
        host: Target hostname or IP address (v4/v6, brackets optional)
        ports: Iterable of port numbers to scan (duplicates removed)
        timeout: Per-port connection timeout in seconds (default: 0.7)
        max_workers: Maximum concurrent threads (default: 50)

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
            executor.submit(_scan_single, target, port, timeout): port
            for port in unique_ports
        }
        for future in as_completed(future_to_port):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)
