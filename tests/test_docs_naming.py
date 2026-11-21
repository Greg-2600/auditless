"""Docs naming locks (ROADMAP items 18 and 159).

Live docs say Auditless; point-in-time historical analyses keep the name
they were written under (see docs/NAMING.md). Legacy identifiers are
assembled from parts so this guard never revives them as live tokens.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY_PACKAGE = "linux" + "_health"
LEGACY_BRAND = "Linux" + " Health Security Scanner"

LIVE_DOCS = [
    "docs/README.md",
    "docs/TEST_ID_REFERENCE.md",
    "scripts/README.md",
]


def test_naming_guide_describes_single_name() -> None:
    """docs/NAMING.md documents the canonical surface only."""
    text = (ROOT / "docs" / "NAMING.md").read_text(encoding="utf-8")
    assert "Auditless" in text
    assert "auditless" in text
    assert "Greg-2600/auditless" in text
    assert LEGACY_PACKAGE not in text


def test_v3_roadmap_points_to_roadmap() -> None:
    """Historical v3.0 plan carries a superseded-by pointer, body intact."""
    text = (ROOT / "docs" / "IMPLEMENTATION_ROADMAP_V3.md").read_text(encoding="utf-8")
    assert "superseded" in text.lower()
    assert "ROADMAP.md" in text
    assert "v3.0 Roadmap" in text  # era title preserved


def test_live_docs_use_auditless() -> None:
    """Live docs brand Auditless; the old product string is gone there."""
    for rel in LIVE_DOCS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "Auditless" in text, rel
        assert LEGACY_BRAND not in text, rel


def test_migration_guide_names_the_old_package() -> None:
    """Upgrade docs tell 3.x users exactly what to change."""
    text = (ROOT / "docs" / "MIGRATION_v4.md").read_text(encoding="utf-8")
    assert LEGACY_PACKAGE in text
    assert "auditless" in text
    assert "python -m auditless" in text


def test_security_verify_example_parameterized() -> None:
    """Release verify snippet takes VERSION (no hardcoded stale release)."""
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "VERSION=${VERSION" in text
    assert "auditless:${VERSION}" in text
    assert '"v${VERSION}"' in text
    assert "auditless:2.5.2" not in text
