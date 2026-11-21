"""Console-script and distribution-name locks (ROADMAP item 15).

Complements test_packaging_meta.py (setup/pyproject field parity) and
test_import_alias.py (single-package surface): this file pins the
installable entry-point surface — one console script declared in both
files and resolving to a callable — plus the distribution name.
"""

import importlib
import tomllib
from pathlib import Path
from typing import Any, cast

import auditless

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_SCRIPTS = {
    "auditless": "auditless.cli:main",
}

LEGACY_SCRIPT = "linux" + "-health"
LEGACY_PACKAGE = "linux" + "_health"


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
    """Distribution name is auditless."""
    with open(ROOT / "pyproject.toml", "rb") as handle:
        project = cast("dict[str, Any]", tomllib.load(handle)["project"])
    assert project["name"] == "auditless"


def test_pyproject_console_scripts() -> None:
    """The single console script is declared with the right target."""
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


def test_canonical_package_smoke() -> None:
    """The package exposes a version and a CLI module."""
    assert isinstance(auditless.__version__, str)
    from auditless import cli

    assert callable(cli.main)


def test_no_legacy_names_in_packaging() -> None:
    """Neither the old package nor the old script survives in packaging."""
    for filename in ("setup.py", "pyproject.toml"):
        text = (ROOT / filename).read_text(encoding="utf-8")
        assert LEGACY_PACKAGE not in text, filename
        assert LEGACY_SCRIPT not in text, filename


def test_no_yourusername_in_entry_points() -> None:
    """No stale placeholder leaks through packaging files."""
    for filename in ("setup.py", "pyproject.toml"):
        assert "yourusername" not in (ROOT / filename).read_text(encoding="utf-8")
