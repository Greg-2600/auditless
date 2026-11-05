"""Tests for the privilege model (ROADMAP item 30)."""

import itertools
from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest

from linux_health import checks as checks_mod
from linux_health.checks import (
    NEEDS_ELEVATION,
    CheckResult,
    _check_thunks,
    _privilege_placeholder,
    _session_elevated,
    get_privilege,
    run_all_checks,
    run_all_checks_parallel,
)
from linux_health.test_ids import CHECK_TEST_IDS


@pytest.fixture(autouse=True)
def _fresh_cache() -> Iterator[None]:
    """Reset entries so hostname-keyed tests never see another test's data."""
    from linux_health.checks import reset_command_cache

    reset_command_cache()
    yield
    reset_command_cache()


_host_seq = itertools.count()


def _mock_ssh(
    uid_out: str = "1000",
    sudo_ret: int = 1,
    hostname: str | None = None,
) -> MagicMock:
    """Session double routing id/sudo probes plus canned check output."""
    if hostname is None:
        hostname = f"priv-test-{next(_host_seq)}"

    def fake_run(command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        if command == "id -u":
            return 0, uid_out, ""
        if command.startswith("sudo -n true"):
            return sudo_ret, "", ""
        return 0, "test output", ""

    ssh = MagicMock()
    ssh.hostname = hostname
    ssh._client = None
    ssh.run = fake_run
    return ssh


def test_table_covers_only_real_checks() -> None:
    """Every gated name exists in the thunk table with a registry ID."""
    names = {name for name, _ in _check_thunks(_mock_ssh())}
    assert NEEDS_ELEVATION
    assert NEEDS_ELEVATION <= names
    for name in NEEDS_ELEVATION:
        assert CHECK_TEST_IDS.get(name), name


def test_get_privilege_parses() -> None:
    """Root, sudo-nopasswd, and plain users are distinguished."""
    assert get_privilege(_mock_ssh(uid_out="0", sudo_ret=1)).is_root is True
    assert get_privilege(_mock_ssh(sudo_ret=0)).sudo_no_password is True
    plain = get_privilege(_mock_ssh())
    assert (plain.is_root, plain.sudo_no_password, plain.uid) == (
        False,
        False,
        "1000",
    )


def test_get_privilege_never_raises() -> None:
    """Failing transports yield unknown privilege, not exceptions."""

    def boom(command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        raise RuntimeError("gone")

    ssh = MagicMock()
    ssh.hostname = "gone"
    ssh._client = None
    ssh.run = boom
    info = get_privilege(ssh)
    assert (info.is_root, info.sudo_no_password, info.uid) == (False, False, "")
    assert _session_elevated(info, "") is True  # fail-open on ambiguity


def test_unprivileged_gates_table_members() -> None:
    """Proven non-root sessions get unknown-marked WARNs, others run."""
    results = run_all_checks(_mock_ssh(), password="")
    by_item = {r.item: r for r in results}
    for name in NEEDS_ELEVATION:
        slot = by_item[f"{name} skipped (unprivileged)"]
        assert slot.status == "unknown"
        assert slot.category == "Privilege"
        assert "unknown" in slot.details
        assert slot.test_id == CHECK_TEST_IDS.get(name, "")
    assert len(results) == len(run_all_checks(_mock_ssh(), password="x"))


def test_parallel_runner_gates_too() -> None:
    """The pool path degrades identically to the sequential path."""
    seq = {(r.test_id, r.item, r.status) for r in run_all_checks(_mock_ssh())}
    par = {
        (r.test_id, r.item, r.status)
        for r in run_all_checks_parallel(_mock_ssh(), max_workers=8)
    }
    assert seq == par
    assert any(item.endswith("skipped (unprivileged)") for _, item, _ in par)


def test_elevated_sessions_run_everything() -> None:
    """Root, sudo-nopasswd, or password sessions skip the gate."""
    variants = [
        _mock_ssh(uid_out="0"),
        _mock_ssh(sudo_ret=0),
    ]
    for ssh in variants:
        assert not any(
            r.category == "Privilege" for r in run_all_checks(ssh, password="")
        )
    assert not any(
        r.category == "Privilege"
        for r in run_all_checks(_mock_ssh(), password="s3cret")
    )


def test_ambiguous_privilege_runs_everything() -> None:
    """Bare mocks (non-string uid) fail open to today's behavior."""
    ssh = MagicMock()
    ssh._client = None
    ssh.hostname = "bare-mock"
    ssh.run = MagicMock(return_value=(0, "test output", ""))
    assert not any(r.category == "Privilege" for r in run_all_checks(ssh, ""))


def test_placeholder_shape() -> None:
    """Direct placeholder construction stays well-formed."""
    slot: CheckResult = _privilege_placeholder("check_x")
    assert (slot.status, slot.category) == ("unknown", "Privilege")
    assert "elevated privileges" in slot.details
    assert isinstance(checks_mod.NEEDS_ELEVATION, frozenset)
