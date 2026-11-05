"""Drift locks between setup.py shim and pyproject.toml (ROADMAP item 14).

pyproject.toml is authoritative; setup.py must mirror it. Parsed via AST
(never executed) plus stdlib tomllib.
"""

import ast
import re
import tomllib
from pathlib import Path
from typing import Any, cast

import linux_health

ROOT = Path(__file__).resolve().parent.parent


def _setup_kwargs() -> dict[str, Any]:
    """Literal setup() kwargs from setup.py without executing it.

    Non-literal values (version variable, find_packages call, file-derived
    strings) are skipped; version is pinned separately by
    test_version_single_sourced.
    """
    tree = ast.parse((ROOT / "setup.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "setup":
            kwargs: dict[str, Any] = {}
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                try:
                    kwargs[kw.arg] = ast.literal_eval(kw.value)
                except ValueError:
                    continue
            return kwargs
    raise AssertionError("setup() call not found in setup.py")


def _pyproject() -> dict[str, Any]:
    with open(ROOT / "pyproject.toml", "rb") as handle:
        return cast("dict[str, Any]", tomllib.load(handle)["project"])


def _req_names(path: Path) -> set[str]:
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "-")):
            names.add(re.split(r"[<>=!~\s\[]", line, maxsplit=1)[0].lower())
    return names


def test_setup_mirrors_pyproject() -> None:
    """Name, author, description, URLs, keywords, classifiers stay in sync."""
    setup = _setup_kwargs()
    project = _pyproject()
    assert setup["name"] == project["name"] == "auditless"
    assert setup["author"] == project["authors"][0]["name"]
    assert setup["description"] == project["description"]
    assert setup["url"] == project["urls"]["Repository"]
    for label, href in setup["project_urls"].items():
        assert href in project["urls"].values(), label
    assert setup["keywords"] == project["keywords"]
    assert setup["classifiers"] == project["classifiers"]
    assert setup["py_modules"] == ["auditless"]
    assert setup["python_requires"] == project["requires-python"]


def test_no_stale_placeholders_in_packaging() -> None:
    """yourusername template URLs must not survive anywhere packaged."""
    for filename in ("setup.py", "pyproject.toml"):
        text = (ROOT / filename).read_text(encoding="utf-8")
        assert "yourusername" not in text, filename


def test_version_single_sourced() -> None:
    """__init__ version and pyproject version move together."""
    assert linux_health.__version__ == _pyproject()["version"]


def test_requirements_match_pyproject_deps() -> None:
    """requirements.txt and [project] dependencies cover the same packages."""
    wanted = {
        re.split(r"[<>=!~\s\[]", dep, maxsplit=1)[0].lower()
        for dep in _pyproject()["dependencies"]
    }
    assert _req_names(ROOT / "requirements.txt") == wanted
