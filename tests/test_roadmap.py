"""Tests for scripts/roadmap.py (loaded by path; scripts/ is not a package)."""

import importlib.util
import pathlib
import types

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "roadmap.py"
ROADMAP = pathlib.Path(__file__).resolve().parent.parent / "ROADMAP.md"


def _mod() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("roadmap_helper", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_parse_and_next() -> None:
    mod = _mod()
    items = mod.parse_items("- [ ] 2 — [P0] Second\n- [x] 1 — [P0] First\n")
    assert len(items) == 2
    assert mod.next_item(items)["n"] == 2


def test_next_none_when_complete() -> None:
    mod = _mod()
    items = mod.parse_items("- [x] 1 — [P0] Only\n")
    assert mod.next_item(items) is None


def test_render_marked() -> None:
    mod = _mod()
    out = mod.render_marked("- [ ] 7 — [P1] Thing\n", 7)
    assert "- [x] 7 — [P1] Thing" in out


def test_render_marked_missing_raises() -> None:
    mod = _mod()
    try:
        mod.render_marked("- [ ] 7 — [P1] Thing\n", 9)
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_roadmap_has_sequential_numbered_items() -> None:
    """Guard: ROADMAP.md stays exactly items 1..N, unique, sequential."""
    mod = _mod()
    items = mod.parse_items(ROADMAP.read_text(encoding="utf-8"))
    nums = sorted(i["n"] for i in items)
    assert nums == list(range(1, len(nums) + 1))


def test_milestone_report_not_hit() -> None:
    mod = _mod()
    assert mod.milestone_report(44, 200) == "44/200 done; next review at 50"
    assert mod.milestone_report(0, 200) == "0/200 done; next review at 10"


def test_milestone_report_hit() -> None:
    mod = _mod()
    out = mod.milestone_report(50, 200)
    assert "milestone hit: 50/200" in out
    assert "ROADMAP-REVIEW-050.md" in out
