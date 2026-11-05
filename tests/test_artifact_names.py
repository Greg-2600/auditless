"""Artifact filename prefix locks (ROADMAP item 17).

Every generated artifact (report copies, DB backups/snapshots, tempfiles,
downloads) uses the auditless-* prefix. Audit 2026-11-05 found zero
legacy-prefixed builders; these tests keep it that way.
"""

from pathlib import Path

import pytest

from linux_health.dashboard import _save_report_copy
from linux_health.store import Store


def test_backup_uses_auditless_prefix(tmp_path: Path) -> None:
    """DB snapshots are auditless-*.db and pruning keeps the newest."""
    store = Store(tmp_path / "data")
    store.upsert_host("web", "10.0.0.1", "admin")
    first = store.backup(keep=2)
    second = store.backup(keep=2)
    assert first.name.startswith("auditless-")
    assert second.name.endswith(".db")
    third = store.backup(keep=2)
    remaining = sorted((tmp_path / "data" / "backups").glob("*.db"))
    assert len(remaining) == 2
    assert third in remaining
    assert all(p.name.startswith("auditless-") for p in remaining)


def test_report_copy_uses_auditless_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Report copies sanitize the hostname under the auditless- prefix."""
    monkeypatch.chdir(tmp_path)
    _save_report_copy("web 01/x", {"summary": {"hardening_index": 50}})
    copies = list((tmp_path / "reports").glob("*.json"))
    assert len(copies) == 1
    assert copies[0].name.startswith("auditless-web_01_x-")


def test_no_legacy_artifact_prefixes_in_source() -> None:
    """Tripwire: no linux_health-/linux-health- filename builders in code."""
    roots = [Path("linux_health"), Path("scripts")]
    roots.append(Path("auditless.py"))
    offenders: list[str] = []
    for root in roots:
        files = [root] if root.is_file() else sorted(root.glob("*.py"))
        for path in files:
            text = path.read_text(encoding="utf-8")
            if "linux_health-" in text or "linux-health-" in text:
                offenders.append(str(path))
    assert offenders == []
