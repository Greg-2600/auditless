"""Package-rename locks (ROADMAP item 159).

Auditless 4.0 completed the rename: ``auditless`` is the only import
package, module path, distribution and console script. The legacy
package name is built from parts so it never appears as a live token.
"""

import importlib
import subprocess
import sys
from pathlib import Path

import pytest

import auditless

ROOT = Path(__file__).resolve().parent.parent
LEGACY_PACKAGE = "linux" + "_health"


def test_version_is_string() -> None:
    """The canonical package exposes a version string."""
    assert isinstance(auditless.__version__, str)
    assert auditless.__version__


def test_legacy_package_is_not_importable() -> None:
    """The pre-4.0 import path is gone, not merely aliased."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(LEGACY_PACKAGE)


def test_no_alias_shim_module() -> None:
    """No stray top-level shim shadows the package."""
    assert not (ROOT / f"{LEGACY_PACKAGE}.py").exists()


def test_submodules_import() -> None:
    """Submodules resolve under the canonical package."""
    from auditless import cli

    assert callable(cli.main)


def test_module_main_runs_cli_help() -> None:
    """python -m auditless is the supported module entry point."""
    proc = subprocess.run(
        [sys.executable, "-m", "auditless", "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "usage: auditless" in proc.stdout
