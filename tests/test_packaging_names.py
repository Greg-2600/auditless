"""Console-script and distribution-name locks (ROADMAP item 15).

Complements test_packaging_meta.py (setup/pyproject field parity) and
test_import_alias.py (alias mechanics): this file pins the installable
entry-point surface — both console scripts declared in both files and
resolving to a callable — plus the distribution name and alias smoke.
"""

import importlib
import tomllib
from pathlib import Path
from typing import Any, cast

import auditless
import linux_health

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_SCRIPTS = {
    "auditless": "linux_health.cli:main",
    "linux-health": "linux_health.cli:main",
}


def _pyproject_scripts() -> dict[str, str]:
    with open(ROOT / "pyproject.toml", "rb") as handle:
        project = cast("dict[str, Any]", tomllib.load(handle)["project"])
    return dict(project["scripts"])


def _resolve(target: str) -> Any:
    """Resolve a 'module:attr' entry-point target to the object."""
    module_name, _, attr = target.partition(":")
    assert attr, f"malformed entry point target: {target!r}"
    return getattr(importlib.import_module(module_name), attr)


def test_dist_name_is_auditless() -> None:
    """Distribution name is auditless (not linux-health)."""
    with open(ROOT / "pyproject.toml", "rb") as handle:
        project = cast("dict[str, Any]", tomllib.load(handle)["project"])
    assert project["name"] == "auditless"


def test_pyproject_console_scripts() -> None:
    """Both console scripts are declared with the right targets."""
    assert _pyproject_scripts() == EXPECTED_SCRIPTS


def test_setup_console_scripts_match() -> None:
    """setup.py entry_points mirror the pyproject scripts table."""
    text = (ROOT / "setup.py").read_text(encoding="utf-8")
    for script, target in EXPECTED_SCRIPTS.items():
        assert f'"{script}={target}"' in text, script


def test_console_script_targets_resolve() -> None:
    """Every declared script target imports to a callable main."""
    for script, target in _pyproject_scripts().items():
        resolved = _resolve(target)
        assert callable(resolved), script


def test_import_alias_smoke() -> None:
    """The auditless alias exposes the package version and CLI module."""
    assert auditless.__version__ == linux_health.__version__
    from auditless import cli

    assert callable(cli.main)


def test_no_yourusername_in_entry_points() -> None:
    """No stale placeholder leaks through packaging files."""
    for filename in ("setup.py", "pyproject.toml"):
        assert "yourusername" not in (ROOT / filename).read_text(encoding="utf-8")
