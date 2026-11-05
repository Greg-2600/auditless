"""Tests for the (host, command) output cache with TTL (ROADMAP item 28)."""

from collections.abc import Iterator

import pytest

from linux_health import checks as checks_mod
from linux_health.checks import (
    _run,
    disable_command_cache,
    enable_command_cache,
    get_command_cache_ttl,
    get_max_output_bytes,
    is_command_cache_enabled,
    reset_command_cache,
    set_command_cache_ttl,
    set_max_output_bytes,
    truncate_output,
)
from linux_health.ssh_client import SSHSession


class CountingSSH(SSHSession):
    """Session double counting real executions (cache bypass visible)."""

    def __init__(self, hostname: str) -> None:
        super().__init__(hostname, "user", "")
        self.calls = 0

    def run(self, command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        self.calls += 1
        return 0, f"out-{self.hostname}", ""


@pytest.fixture()
def cache_env() -> Iterator[None]:
    """Isolate global cache state (enabled + 300s TTL baseline)."""
    was_enabled = is_command_cache_enabled()
    was_ttl = get_command_cache_ttl()
    enable_command_cache()
    set_command_cache_ttl(300.0)
    reset_command_cache()
    try:
        yield
    finally:
        reset_command_cache()
        set_command_cache_ttl(was_ttl)
        if was_enabled:
            enable_command_cache()
        else:
            disable_command_cache()


def test_cache_hits_same_host_command(cache_env: None) -> None:
    """Repeat commands on one host execute once."""
    ssh = CountingSSH("web-01")
    assert _run(ssh, "hostname") == (0, "out-web-01", "")
    assert _run(ssh, "hostname") == (0, "out-web-01", "")
    assert ssh.calls == 1


def test_cache_isolates_hosts(cache_env: None) -> None:
    """Same command on different hosts never shares entries (fleet-safe)."""
    first, second = CountingSSH("web-01"), CountingSSH("web-02")
    assert _run(first, "hostname") == (0, "out-web-01", "")
    assert _run(second, "hostname") == (0, "out-web-02", "")
    assert (first.calls, second.calls) == (1, 1)
    assert _run(first, "hostname") == (0, "out-web-01", "")
    assert first.calls == 1


def test_ttl_zero_disables_hits(cache_env: None) -> None:
    """TTL 0 expires entries immediately (always re-executes)."""
    set_command_cache_ttl(0.0)
    ssh = CountingSSH("web-01")
    _run(ssh, "hostname")
    _run(ssh, "hostname")
    assert ssh.calls == 2


def test_reset_clears_entries(cache_env: None) -> None:
    """reset_command_cache drops stored results."""
    ssh = CountingSSH("web-01")
    _run(ssh, "hostname")
    reset_command_cache()
    _run(ssh, "hostname")
    assert ssh.calls == 2


def test_use_cache_false_bypasses(cache_env: None) -> None:
    """Per-call use_cache=False skips read and write."""
    ssh = CountingSSH("web-01")
    _run(ssh, "hostname", use_cache=False)
    _run(ssh, "hostname", use_cache=False)
    assert ssh.calls == 2
    _run(ssh, "hostname")
    assert ssh.calls == 3  # bypassing writes nothing, so this misses too


def test_enable_disable_getter_roundtrip(cache_env: None) -> None:
    """Enabled flag and TTL accessors round-trip."""
    assert is_command_cache_enabled() is True
    disable_command_cache()
    assert is_command_cache_enabled() is False
    ssh = CountingSSH("web-01")
    _run(ssh, "hostname")
    _run(ssh, "hostname")
    assert ssh.calls == 2
    enable_command_cache()
    assert is_command_cache_enabled() is True
    set_command_cache_ttl(60.0)
    assert get_command_cache_ttl() == 60.0
    assert checks_mod._CACHE_TTL_S == 60.0


def test_no_cache_flag_parser_default() -> None:
    """--no-cache exists and defaults off."""
    from linux_health.cli import build_parser

    assert build_parser().parse_args(["h", "u", "p"]).no_cache is False
    assert build_parser().parse_args(["h", "u", "p", "--no-cache"]).no_cache is True


def test_truncate_output_bounds() -> None:
    """Short text passes through; long text caps with a marker."""
    assert truncate_output("abc", 1024) == "abc"
    capped = truncate_output("x" * 200, 100)
    assert len(capped.encode("utf-8")) <= 100 + 64
    assert "truncated" in capped
    assert truncate_output("x" * 200, 0) == "x" * 200
    assert truncate_output("héllo-wörld", 5).startswith("h")


def test_max_output_bytes_accessors() -> None:
    """Cap getter/setter round-trip (restored afterwards)."""
    previous = get_max_output_bytes()
    try:
        set_max_output_bytes(1234)
        assert get_max_output_bytes() == 1234
    finally:
        set_max_output_bytes(previous)


def test_run_caps_huge_output(cache_env: None) -> None:
    """A 2MB command output is stored truncated, never whole."""
    previous = get_max_output_bytes()
    set_max_output_bytes(1024)
    try:
        ssh = CountingSSH("big-host")

        def huge(command: str, timeout: float = 10.0) -> tuple[int, str, str]:
            ssh.calls += 1
            return 0, "y" * (2 * 1024 * 1024), ""

        ssh.run = huge  # type: ignore[method-assign]
        code, out, _ = _run(ssh, "generate-massive-output")
        assert code == 0
        assert len(out.encode("utf-8")) < 2048
        assert "truncated" in out
    finally:
        set_max_output_bytes(previous)


def test_run_uncapped_when_disabled(cache_env: None) -> None:
    """Non-positive caps preserve full output for special callers."""
    previous = get_max_output_bytes()
    set_max_output_bytes(0)
    try:
        ssh = CountingSSH("full-host")

        def huge(command: str, timeout: float = 10.0) -> tuple[int, str, str]:
            ssh.calls += 1
            return 0, "y" * 5000, ""

        ssh.run = huge  # type: ignore[method-assign]
        _, out, _ = _run(ssh, "generate-massive-output")
        assert out == "y" * 5000
    finally:
        set_max_output_bytes(previous)


def test_max_output_bytes_flag() -> None:
    """--max-output-bytes defaults to 1MB and parses explicit values."""
    from linux_health.cli import build_parser

    assert build_parser().parse_args(["h", "u", "p"]).max_output_bytes == 1048576
    args = build_parser().parse_args(["h", "u", "p", "--max-output-bytes", "0"])
    assert args.max_output_bytes == 0
