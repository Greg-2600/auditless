"""Tests for the markdownlint baseline helper."""

import importlib.util
import pathlib

MODULE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "scripts"
    / "check_markdown_baseline.py"
)
SPEC = importlib.util.spec_from_file_location("check_markdown_baseline", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
baseline_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline_tool)

SAMPLE = """markdownlint-cli2 v0.24.2
README.md:7:81 error MD013/line-length Line length [Expected: 80]
docs/guide.md:12 error MD022/blanks-around-headings Headings need blank lines
Summary: 2 issues in 2 files
"""


def test_parse_findings_ignores_progress_lines() -> None:
    assert baseline_tool.parse_findings(SAMPLE) == {
        ("README.md", "MD013", 7),
        ("docs/guide.md", "MD022", 12),
    }


def test_baseline_round_trip(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "baseline.json"
    findings = {("b.md", "MD013", 4), ("a.md", "MD022", 2), ("a.md", "MD013", 9)}
    baseline_tool.write_baseline(findings, target)
    assert baseline_tool.load_baseline(target) == findings
