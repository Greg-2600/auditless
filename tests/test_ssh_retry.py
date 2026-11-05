"""Tests for SSH connect retry with backoff (ROADMAP item 24)."""

import socket
from typing import Any

import paramiko
import pytest

from linux_health import ssh_client
from linux_health.ssh_client import SSHSession


class FakeSSHClient:
    """paramiko.SSHClient double with a scripted connect outcome queue."""

    outcomes: list[Any] = []
    attempts: int = 0

    def set_missing_host_key_policy(self, policy: Any) -> None:
        pass

    def load_system_host_keys(self, filename: Any = None) -> None:
        pass

    def connect(self, **kwargs: Any) -> None:
        type(self).attempts += 1
        if type(self).outcomes:
            outcome = type(self).outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome

    def close(self) -> None:
        pass

    def get_transport(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _fake_client(
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    FakeSSHClient.outcomes = []
    FakeSSHClient.attempts = 0
    monkeypatch.setattr(ssh_client.paramiko, "SSHClient", FakeSSHClient)
    yield


def _session(**kwargs: Any) -> SSHSession:
    return SSHSession("host-1", "ops", "pw", **kwargs)


def test_auth_failure_fails_fast() -> None:
    """Bad credentials never retry (lockout protection)."""
    FakeSSHClient.outcomes = [paramiko.AuthenticationException("bad")]
    session = _session(retries=3)
    with pytest.raises(paramiko.AuthenticationException):
        session.connect()
    assert FakeSSHClient.attempts == 1
    assert session._client is None


def test_transient_failures_retry_then_succeed() -> None:
    """Timeouts/resets retry until one attempt connects."""
    FakeSSHClient.outcomes = [
        socket.timeout("timed out"),
        ConnectionResetError("reset"),
        None,
    ]
    session = _session(retries=3, retry_backoff=0.0)
    session.connect()
    assert FakeSSHClient.attempts == 3
    assert session._client is not None


def test_backoff_schedule_is_exponential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sleeps double per attempt (base, 2x base, 4x base, ...)."""
    sleeps: list[float] = []
    monkeypatch.setattr(ssh_client.time, "sleep", sleeps.append)
    FakeSSHClient.outcomes = [socket.timeout("t"), socket.timeout("t"), None]
    _session(retries=3, retry_backoff=2.0).connect()
    assert sleeps == [2.0, 4.0]


def test_exhausted_retries_raise_last_error() -> None:
    """Attempts stop at retries+1 and the final error surfaces."""
    FakeSSHClient.outcomes = [socket.timeout("t")] * 3
    session = _session(retries=2, retry_backoff=0.0)
    with pytest.raises(socket.timeout):
        session.connect()
    assert FakeSSHClient.attempts == 3
    assert session._client is None


def test_zero_retries_single_attempt() -> None:
    """Default behavior is unchanged: one attempt, immediate raise."""
    FakeSSHClient.outcomes = [socket.timeout("t"), None]
    with pytest.raises(socket.timeout):
        _session().connect()
    assert FakeSSHClient.attempts == 1


def test_unknown_host_fails_closed_with_guidance() -> None:
    """RejectPolicy misses fail once, with key-management instructions."""
    from paramiko.ssh_exception import SSHException

    FakeSSHClient.outcomes = [SSHException("Server 'h' not found in known_hosts")]
    with pytest.raises(RuntimeError, match="ssh-keyscan"):
        _session().connect()
    assert FakeSSHClient.attempts == 1


def test_dns_failure_retried() -> None:
    """Name resolution flakes are network failures, not auth."""
    FakeSSHClient.outcomes = [socket.gaierror("dns"), None]
    session = _session(retries=1, retry_backoff=0.0)
    session.connect()
    assert FakeSSHClient.attempts == 2


def test_non_transient_errors_not_retried() -> None:
    """Config errors fail immediately without consuming the retry budget."""
    FakeSSHClient.outcomes = [ValueError("bad config"), None]
    with pytest.raises(ValueError, match="bad config"):
        _session(retries=3).connect()
    assert FakeSSHClient.attempts == 1


def test_unreadable_gateway_key_raises_value_error() -> None:
    """Bastion key problems surface as ValueError (never retried)."""
    session = SSHSession(
        "h", "u", "pw", gateway={"hostname": "bastion", "key_path": "/nonexistent"}
    )
    with pytest.raises(ValueError, match="unreadable gateway key"):
        session._load_gateway_key()
    assert not issubclass(ValueError, ssh_client._TRANSIENT_ERRORS)


def test_retries_flag_defaults_and_parses() -> None:
    """--retries defaults to 0 and accepts explicit values."""
    from linux_health.cli import build_parser

    assert build_parser().parse_args(["h", "u", "p"]).retries == 0
    assert build_parser().parse_args(["h", "u", "p", "--retries", "3"]).retries == 3


def test_open_session_passes_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scan session inherits the CLI retry budget."""
    import linux_health.cli as cli_mod

    seen: dict[str, Any] = {}

    class RecorderSession(SSHSession):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            seen.update(kwargs)
            super().__init__("h", "u", "pw")

    monkeypatch.setattr(cli_mod, "SSHSession", RecorderSession)
    args = cli_mod.build_parser().parse_args(["h", "u", "pw", "--retries", "3"])
    cli_mod._open_session(args, "pw", None)
    assert seen["retries"] == 3
