"""Docs naming locks (ROADMAP item 18).

Live docs say Auditless; point-in-time historical analyses keep the name
they were written under (see docs/NAMING.md for the alias table).
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LIVE_DOCS = [
    "docs/README.md",
    "docs/TEST_ID_REFERENCE.md",
    "scripts/README.md",
]


def test_naming_guide_exists() -> None:
    """docs/NAMING.md alias table is present."""
    text = (ROOT / "docs" / "NAMING.md").read_text(encoding="utf-8")
    assert "Auditless" in text
    assert "linux_health" in text
    assert "Greg-2600/auditless" in text


def test_v3_roadmap_points_to_roadmap() -> None:
    """Historical v3.0 plan carries a superseded-by pointer, body intact."""
    text = (ROOT / "docs" / "IMPLEMENTATION_ROADMAP_V3.md").read_text(encoding="utf-8")
    assert "superseded" in text.lower()
    assert "ROADMAP.md" in text
    assert "# Linux Health v3.0 Roadmap" in text  # era title preserved


def test_live_docs_use_auditless() -> None:
    """Live docs brand Auditless; the old product string is gone there."""
    for rel in LIVE_DOCS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "Auditless" in text, rel
        assert "Linux Health Security Scanner" not in text, rel
