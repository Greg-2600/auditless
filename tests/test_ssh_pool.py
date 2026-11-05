"""Tests for SSH session pooling (ROADMAP item 22)."""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

import pytest

from linux_health import ssh_client
from linux_health.ssh_client import (
    PoolKey,
    SessionPool,
    SSHSession,
    drain_session_pool,
    pooled_session,
)


class FakeTransport:
    """Transport double with controllable liveness."""

    def __init__(self, alive: bool = True) -> None:
        self.alive = alive

    def is_active(self) -> bool:
        return self.alive


class FakeClient:
    """SSHClient double exposing a controllable transport."""

    def __init__(self, alive: bool = True) -> None:
        self.transport = FakeTransport(alive)

    def get_transport(self) -> FakeTransport:
        return self.transport


class FakeSession(SSHSession):
    """Session double: no network, deterministic health."""

    connects: int = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__("pool-test", "user", "")
        self.dead = False
        self.closed = False

    def connect(self) -> None:
        type(self).connects += 1
        self._client = FakeClient()  # type: ignore[assignment]

    def run(self, command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        if self.closed or self.dead or self._client is None:
            raise RuntimeError("session gone (test)")
        return 0, "ok", ""

    def close(self) -> None:
        self.closed = True
        self._client = None


@pytest.fixture()
def pool() -> SessionPool:
    """Fresh pool per test (never the module-global default)."""
    return SessionPool()


@pytest.fixture(autouse=True)
def _reset_connects() -> Iterator[None]:
    FakeSession.connects = 0
    yield
    FakeSession.connects = 0
    drain_session_pool()


def _key(pool: SessionPool) -> PoolKey:
    return SessionPool.key_for("host-1", 22, "ops")


def _connect(pool: SessionPool) -> FakeSession:
    session = FakeSession()
    session.connect()
    return session


def _acquire(pool: SessionPool, key: PoolKey) -> FakeSession:
    """Acquire typed as the fake (pool API returns the base class)."""
    return cast("FakeSession", pool.acquire(key, lambda: _connect(pool)))


def test_reuses_healthy_session(pool: SessionPool) -> None:
    """Release + re-acquire returns the same object without redialing."""
    key = _key(pool)
    first = _acquire(pool, key)
    pool.release(key, first)
    assert pool.idle_count() == 1
    second = _acquire(pool, key)
    assert second is first
    assert FakeSession.connects == 1


def test_discards_unhealthy_session(pool: SessionPool) -> None:
    """A session that fails health check is closed, never reissued."""
    key = _key(pool)
    first = _acquire(pool, key)
    first.dead = True
    pool.release(key, first)
    assert first.closed
    assert pool.idle_count() == 0
    second = _acquire(pool, key)
    assert second is not first
    assert FakeSession.connects == 2


def test_expired_session_reconnects() -> None:
    """Idle TTL expiry forces a fresh connection on next acquire."""
    pool = SessionPool(idle_ttl=-1.0)
    key = _key(pool)
    first = _acquire(pool, key)
    pool.release(key, first)
    assert pool.idle_count() == 1  # expiry is observed lazily at take time
    second = _acquire(pool, key)
    assert first.closed
    assert FakeSession.connects == 2
    assert second is not first


def test_exception_closes_without_parking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed block closes the session instead of returning it."""
    monkeypatch.setattr(ssh_client, "SSHSession", FakeSession)
    pool = SessionPool()
    held: list[FakeSession] = []
    with pytest.raises(RuntimeError, match="boom"):
        with pooled_session("h", "u", "pw", pool=pool) as session:
            assert isinstance(session, FakeSession)
            held.append(session)
            raise RuntimeError("boom")
    assert held and held[0].closed
    assert pool.idle_count() == 0


def test_acquire_failure_propagates(pool: SessionPool) -> None:
    """Connect errors surface exactly as without pooling (clean fallback)."""

    def fail() -> FakeSession:
        raise RuntimeError("dial failed (test)")

    with pytest.raises(RuntimeError, match="dial failed"):
        pool.acquire(_key(pool), fail)
    assert pool.idle_count() == 0


def test_idle_caps_enforced() -> None:
    """Per-host and total caps close overflow instead of parking it."""
    pool = SessionPool(max_idle_per_host=1, max_idle_total=1)
    first = pool.acquire(_key(pool), lambda: _connect(pool))
    pool.release(_key(pool), first)
    other_key = SessionPool.key_for("host-2", 22, "ops")
    overflow = _acquire(pool, other_key)
    pool.release(other_key, overflow)
    assert overflow.closed
    assert pool.idle_count() == 1


def test_threaded_acquire_release() -> None:
    """Concurrent borrowers never deadlock and drain empties the pool."""
    pool = SessionPool()
    errors: list[BaseException] = []

    def borrow() -> None:
        try:
            for _ in range(5):
                key = _key(pool)
                session = _acquire(pool, key)
                pool.release(key, session)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=borrow) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors
    pool.drain()
    assert pool.idle_count() == 0


def test_key_ignores_secrets() -> None:
    """Pool identity covers endpoints, never credential material."""
    same_a = SessionPool.key_for("h", 22, "u", password="one")
    same_b = SessionPool.key_for("h", 22, "u", password="two")
    assert same_a == same_b
    assert "one" not in repr(same_a) and "two" not in repr(same_b)
    assert same_a != SessionPool.key_for("other", 22, "u", password="one")


def test_invalidate_drops_host_sessions() -> None:
    """Post-change invalidation closes parked sessions for one host only."""
    pool = SessionPool()
    target = _acquire(pool, _key(pool))
    pool.release(_key(pool), target)
    other_key = SessionPool.key_for("host-2", 22, "ops")
    other = _acquire(pool, other_key)
    pool.release(other_key, other)
    assert pool.invalidate("host-1", 22, "ops") == 1
    assert target.closed
    assert not other.closed
    assert pool.idle_count() == 1
    assert pool.invalidate("host-2") == 1
    assert pool.idle_count() == 0


def test_open_session_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """--reuse-session selects pooled vs fresh session construction."""
    import argparse

    import linux_health.cli as cli_mod

    seen: dict[str, Any] = {}

    @contextmanager
    def fake_pooled(**kwargs: Any) -> Iterator[FakeSession]:
        seen["pooled"] = kwargs
        yield FakeSession()

    class FreshSession(FakeSession):
        pass

    monkeypatch.setattr(cli_mod, "pooled_session", fake_pooled)
    monkeypatch.setattr(cli_mod, "SSHSession", FreshSession)
    args = cli_mod.build_parser().parse_args(["h", "u", "pw", "--reuse-session"])
    assert isinstance(args, argparse.Namespace)
    with cli_mod._open_session(args, "pw", None) as session:
        assert isinstance(session, FakeSession)
    assert seen["pooled"]["hostname"] == "h"
    plain = cli_mod.build_parser().parse_args(["h", "u", "pw"])
    with cli_mod._open_session(plain, "pw", None) as session:
        assert type(session) is FreshSession
    assert args.reuse_session is True
    assert plain.reuse_session is False


def test_run_scan_reuse_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dashboard sends --reuse-session by default, omits on opt-out."""
    import json as jsonlib
    from pathlib import Path

    import linux_health.cli as cli_mod
    from linux_health import dashboard

    seen: dict[str, Any] = {}

    def fake_main(argv: list[str]) -> int:
        seen["argv"] = list(argv)
        out = argv[argv.index("--output") + 1]
        Path(out).write_text(jsonlib.dumps({"ok": True}), encoding="utf-8")
        return 0

    monkeypatch.setattr(cli_mod, "main", fake_main)
    dashboard.run_scan({"hostname": "h", "username": "u", "password": "pw"})
    assert "--reuse-session" in seen["argv"]
    dashboard.run_scan(
        {"hostname": "h", "username": "u", "password": "pw", "reuse_session": False}
    )
    assert "--reuse-session" not in seen["argv"]
