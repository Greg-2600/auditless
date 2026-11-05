"""Tests for the auditless import alias shim (ROADMAP item 9)."""

import subprocess
import sys
from pathlib import Path

import auditless
import linux_health

ROOT = Path(__file__).resolve().parent.parent


def test_version_matches_package() -> None:
    """Shim re-exports the canonical version string."""
    assert auditless.__version__ == linux_health.__version__
    assert isinstance(auditless.__version__, str)


def test_submodule_alias_shares_object() -> None:
    """auditless.cli IS linux_health.cli (no state duplication)."""
    from auditless import cli

    import linux_health.cli

    assert cli is linux_health.cli


def test_sys_modules_fallback_caches_alias() -> None:
    """First attribute access registers auditless.<sub> in sys.modules."""
    from auditless import dashboard

    assert sys.modules["auditless.dashboard"] is dashboard


def test_unknown_submodule_raises_attribute_error() -> None:
    """Unknown names behave like normal missing attributes."""
    try:
        auditless.nonexistent_module_xyz  # noqa: B018
    except AttributeError:
        return
    raise AssertionError("expected AttributeError")


def test_linux_health_still_importable() -> None:
    """Legacy import path keeps working with the same version."""
    import linux_health.cli  # noqa: F401

    assert linux_health.__version__ == auditless.__version__


def test_module_main_runs_cli_help() -> None:
    """python -m auditless behaves like python -m linux_health."""
    for module in ("auditless", "linux_health"):
        proc = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=60,
        )
        assert proc.returncode == 0
        assert "usage: auditless" in proc.stdout
