"""Network range parsing and SSH reachability probing for range scans.

Pure helpers with no dashboard or scan dependencies. ``parse_network`` turns
a CIDR, a hyphen range or a single IP into a bounded list of addresses;
``probe_hosts`` checks which of them accept a TCP connection on the SSH
port using a small thread pool.

Both functions are deliberately bounded: a caller cannot ask for an entire
/8 to be enumerated or probed from the dashboard.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

DEFAULT_MAX_HOSTS = 256
MAX_HOSTS_CEILING = 1024
DEFAULT_PROBE_TIMEOUT = 1.0
MAX_PROBE_TIMEOUT = 10.0
DEFAULT_PROBE_CONCURRENCY = 32
MAX_PROBE_CONCURRENCY = 64


def _too_many(text: str, count: int, limit: int) -> ValueError:
    return ValueError(
        f"network range {text!r} spans {count} addresses; "
        f"limit is {limit} (narrow the range or raise max_hosts)"
    )


def _hyphen_range(text: str, limit: int) -> tuple[list[str], int]:
    """Parse ``start-end`` (end may be a bare IPv4 octet, e.g. .10-20)."""
    start_text, end_text = (part.strip() for part in text.split("-", 1))
    start = ipaddress.ip_address(start_text)
    if "." in end_text or ":" in end_text:
        end = ipaddress.ip_address(end_text)
    else:
        parts = start_text.split(".")
        if start.version != 4 or len(parts) != 4:
            raise ValueError("a shorthand end requires an IPv4 start address")
        end = ipaddress.ip_address(".".join((*parts[:3], end_text)))
    if start.version != end.version:
        raise ValueError("start and end must be the same IP version")
    first, last = int(start), int(end)
    count = last - first + 1
    if count <= 0:
        raise ValueError("range start is after range end")
    if count > limit:
        return [], count
    return [str(ipaddress.ip_address(n)) for n in range(first, last + 1)], count


def parse_network(value: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> list[str]:
    """Return a bounded list of IP addresses for a CIDR, range or single IP.

    Inputs such as ``192.168.1.0/24``, ``192.168.1.10-20`` and
    ``192.0.2.5`` are accepted. IPv6 works too. Raises ``ValueError`` for
    malformed input, empty ranges or anything larger than ``max_hosts``
    (capped at ``MAX_HOSTS_CEILING``). Network/broadcast addresses are
    excluded from IPv4 CIDRs by ``ipaddress``.
    """
    text = (value or "").strip()
    if not text:
        raise ValueError("network range is required")
    try:
        limit = max(1, min(int(max_hosts), MAX_HOSTS_CEILING))
    except (TypeError, ValueError) as exc:
        raise ValueError("max_hosts must be a number") from exc

    try:
        if "-" in text:
            hosts, count = _hyphen_range(text, limit)
        elif "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            count = network.num_addresses
            if count > limit + 2:
                raise _too_many(text, count, limit)
            hosts = [str(address) for address in network.hosts()]
        else:
            hosts, count = [str(ipaddress.ip_address(text))], 1
    except ValueError as exc:
        if "limit is" in str(exc):
            raise
        raise ValueError(f"invalid network range {text!r}: {exc}") from exc

    if count > limit:
        raise _too_many(text, count, limit)
    if not hosts:
        raise ValueError(f"network range {text!r} contains no usable addresses")
    return hosts


def probe_hosts(
    hosts: list[str],
    port: int = 22,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    max_concurrent: int = DEFAULT_PROBE_CONCURRENCY,
) -> list[str]:
    """Return the hosts accepting a TCP connection on ``port``.

    Addresses are probed concurrently with a bounded pool. The result keeps
    the input order, so callers get deterministic job/host pairing. Only
    an open port is reported — no credentials are used here.
    """
    if not hosts:
        return []
    target_port = max(1, min(int(port), 65535))
    wait = max(0.1, min(float(timeout), MAX_PROBE_TIMEOUT))
    workers = max(1, min(int(max_concurrent), MAX_PROBE_CONCURRENCY))

    def _is_open(host: str) -> str | None:
        try:
            with socket.create_connection((host, target_port), timeout=wait):
                return host
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
        return [host for host in pool.map(_is_open, hosts) if host is not None]
