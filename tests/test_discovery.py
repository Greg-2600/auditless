"""Tests for bounded network range parsing and SSH reachability probing."""

from __future__ import annotations

import pytest

from linux_health.discovery import MAX_PROBE_TIMEOUT, parse_network, probe_hosts


class _FakeConnection:
    """Minimal context manager standing in for a connected socket."""

    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


def test_parse_cidr_excludes_network_and_broadcast() -> None:
    assert parse_network("192.168.1.0/29") == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "192.168.1.5",
        "192.168.1.6",
    ]
    assert parse_network("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_parse_hyphen_range_and_shorthand() -> None:
    assert parse_network("192.168.1.10-12") == [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
    ]
    assert parse_network("10.0.0.8-10.0.0.9") == ["10.0.0.8", "10.0.0.9"]


def test_parse_single_ip_and_ipv6() -> None:
    assert parse_network(" 192.0.2.5 ") == ["192.0.2.5"]
    assert parse_network("2001:db8::/126") == [
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::3",
    ]


def test_parse_rejects_empty_malformed_and_reversed() -> None:
    with pytest.raises(ValueError, match="required"):
        parse_network("")
    with pytest.raises(ValueError, match="invalid network range"):
        parse_network("not-a-range")
    with pytest.raises(ValueError, match="start is after"):
        parse_network("192.168.1.20-10")
    with pytest.raises(ValueError, match="same IP version"):
        parse_network("192.168.1.1-2001:db8::1")


def test_parse_rejects_oversized_ranges_before_materialising() -> None:
    with pytest.raises(ValueError, match="limit is 256"):
        parse_network("10.0.0.0/8")
    with pytest.raises(ValueError, match="limit is 32"):
        parse_network("10.0.0.1-10.0.0.100", max_hosts=32)
    with pytest.raises(ValueError, match="limit is 1024"):
        parse_network("10.0.0.0/20", max_hosts=999999)


def test_probe_hosts_keeps_only_reachable_in_input_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, int, float]] = []

    def _connect(address: tuple[str, int], timeout: float) -> _FakeConnection:
        host, port = address
        seen.append((host, port, timeout))
        if host in {"192.0.2.2", "192.0.2.4"}:
            return _FakeConnection()
        raise OSError("connection refused")

    monkeypatch.setattr("linux_health.discovery.socket.create_connection", _connect)
    hosts = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]
    assert probe_hosts(hosts, port=2222, timeout=0.25) == ["192.0.2.2", "192.0.2.4"]
    assert {port for _, port, _ in seen} == {2222}
    assert all(wait == 0.25 for _, _, wait in seen)
    assert len(seen) == 4


def test_probe_hosts_clamps_port_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, int, float]] = []

    def _connect(address: tuple[str, int], timeout: float) -> _FakeConnection:
        seen.append((address[0], address[1], timeout))
        return _FakeConnection()

    monkeypatch.setattr("linux_health.discovery.socket.create_connection", _connect)
    assert probe_hosts(["192.0.2.1"], port=0, timeout=999, max_concurrent=999) == [
        "192.0.2.1"
    ]
    assert seen == [("192.0.2.1", 1, MAX_PROBE_TIMEOUT)]


def test_probe_hosts_empty_input() -> None:
    assert probe_hosts([]) == []


def test_parse_clamps_small_limits() -> None:
    # max_hosts is floored at one, so a single address remains valid.
    assert parse_network("192.0.2.9", max_hosts=0) == ["192.0.2.9"]
