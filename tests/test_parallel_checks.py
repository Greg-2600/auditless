"""Tests for parallel check execution (ROADMAP item 21)."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from linux_health.checks import (
    CheckResult,
    enable_command_cache,
    reset_command_cache,
    run_all_checks,
    run_all_checks_parallel,
)


def _mock_ssh() -> Mock:
    """Mock session shaped like the suite-wide convention."""
    ssh = Mock()
    ssh._client = None  # force the ssh.run() path in _run
    ssh.run = MagicMock(return_value=(0, "test output", ""))
    return ssh


def _signature(results: list[CheckResult]) -> list[tuple[str, str, str, str]]:
    return [(r.test_id, r.item, r.status, r.details) for r in results]


def test_parallel_matches_sequential() -> None:
    """Same session, same results in the same order."""
    expected = _signature(run_all_checks(_mock_ssh(), password=""))
    actual = _signature(run_all_checks_parallel(_mock_ssh(), password=""))
    assert actual == expected
    assert len(actual) > 0


def test_jobs_one_delegates_to_sequential() -> None:
    """max_workers<=1 takes the identical sequential path."""
    expected = _signature(run_all_checks(_mock_ssh(), password=""))
    for jobs in (1, 0, -4):
        actual = _signature(
            run_all_checks_parallel(_mock_ssh(), password="", max_workers=jobs)
        )
        assert actual == expected


def test_large_worker_count_clamped() -> None:
    """Absurd worker counts are capped, results still match."""
    expected = _signature(run_all_checks(_mock_ssh(), password=""))
    actual = _signature(
        run_all_checks_parallel(_mock_ssh(), password="", max_workers=10_000)
    )
    assert actual == expected


def test_check_exception_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing check raises from the parallel runner, as sequential does."""
    import linux_health.checks as checks_mod

    def boom(ssh: Any, password: str = "") -> CheckResult:
        raise RuntimeError("check exploded (test)")

    monkeypatch.setattr(checks_mod, "check_memory", boom)
    with pytest.raises(RuntimeError, match="exploded"):
        run_all_checks_parallel(_mock_ssh(), password="")
    with pytest.raises(RuntimeError, match="exploded"):
        run_all_checks(_mock_ssh(), password="")


def test_parallel_safe_with_cache_enabled() -> None:
    """Locked output cache stays consistent under thread load."""
    enable_command_cache()
    try:
        reset_command_cache()
        first = _signature(
            run_all_checks_parallel(_mock_ssh(), password="", max_workers=8)
        )
        second = _signature(
            run_all_checks_parallel(_mock_ssh(), password="", max_workers=8)
        )
        assert first == second
    finally:
        reset_command_cache()


def test_jobs_flag_defaults_and_parses() -> None:
    """--jobs defaults to 4 and accepts explicit values."""
    from linux_health.cli import build_parser

    assert build_parser().parse_args(["h", "u", "p"]).jobs == 4
    assert build_parser().parse_args(["h", "u", "p", "--jobs", "1"]).jobs == 1
    assert build_parser().parse_args(["h", "u", "p", "--jobs", "16"]).jobs == 16


def test_run_scan_forwards_jobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dashboard passes params['jobs'] through to the CLI pipeline."""
    import linux_health.cli as cli_mod
    from linux_health import dashboard

    seen: dict[str, Any] = {}

    def fake_main(argv: list[str]) -> int:
        seen["argv"] = list(argv)
        out = argv[argv.index("--output") + 1]
        Path(out).write_text(json.dumps({"ok": True}), encoding="utf-8")
        return 0

    monkeypatch.setattr(cli_mod, "main", fake_main)
    payload = dashboard.run_scan(
        {"hostname": "h", "username": "u", "password": "pw", "jobs": 6}
    )
    assert payload == {"ok": True}
    argv = seen["argv"]
    assert argv[argv.index("--jobs") + 1] == "6"
