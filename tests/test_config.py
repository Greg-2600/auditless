"""Tests for dual config-path discovery (ROADMAP item 10)."""

import warnings
from pathlib import Path

import pytest

from linux_health.config import (
    get_config_dirs,
    get_default_profile_paths,
    is_legacy_profile_path,
    load_profile_auto,
)


def _write(path: Path, name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"name: {name}\ndescription: test\n", encoding="utf-8")


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point cwd and home at an empty dir so real user files can't leak in."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    # Windows resolves Path.home() from USERPROFILE, not HOME.
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def test_canonical_paths_precede_legacy() -> None:
    """Every auditless location sorts before its linux_health twin."""
    paths = get_default_profile_paths()
    home = Path.home()
    cwd = Path.cwd()
    pairs = [
        (cwd / "auditless.yaml", cwd / "linux_health.yaml"),
        (cwd / ".auditless.yaml", cwd / ".linux_health.yaml"),
        (
            home / ".config" / "auditless" / "profile.yaml",
            home / ".config" / "linux_health" / "profile.yaml",
        ),
        (
            home / ".auditless" / "profile.yaml",
            home / ".linux_health" / "profile.yaml",
        ),
        (
            Path("/etc/auditless/profile.yaml"),
            Path("/etc/linux_health/profile.yaml"),
        ),
    ]
    for canonical, legacy in pairs:
        assert paths.index(canonical) < paths.index(
            legacy
        ), f"{canonical} should precede {legacy}"


def test_is_legacy_profile_path() -> None:
    """Legacy detector flags old locations only."""
    assert is_legacy_profile_path("linux_health.yaml")
    assert is_legacy_profile_path(".linux_health.yaml")
    assert is_legacy_profile_path("/etc/linux_health/profile.yaml")
    assert is_legacy_profile_path(Path.home() / ".config/linux_health/profile.yaml")
    assert not is_legacy_profile_path("auditless.yaml")
    assert not is_legacy_profile_path("/etc/auditless/profile.yaml")


def test_legacy_path_loads_with_deprecation_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Old paths keep working but warn exactly once per call site."""
    _isolate(tmp_path, monkeypatch)
    _write(tmp_path / "linux_health.yaml", "legacy-profile")
    with pytest.warns(DeprecationWarning, match="legacy path"):
        profile = load_profile_auto()
    assert profile is not None
    assert profile.name == "legacy-profile"


def test_canonical_path_wins_without_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When both spellings exist, the auditless one wins silently."""
    _isolate(tmp_path, monkeypatch)
    _write(tmp_path / "linux_health.yaml", "legacy-profile")
    _write(tmp_path / "auditless.yaml", "canonical-profile")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        profile = load_profile_auto()
    assert profile is not None
    assert profile.name == "canonical-profile"


def test_no_profile_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty search locations yield no profile (and no warning)."""
    _isolate(tmp_path, monkeypatch)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert load_profile_auto() is None


def test_get_config_dirs_canonical_first() -> None:
    """Shared base dirs: every auditless dir precedes its legacy twin."""
    dirs = get_config_dirs()
    home = Path.home()
    pairs = [
        (
            home / ".config" / "auditless",
            home / ".config" / "linux_health",
        ),
        (home / ".auditless", home / ".linux_health"),
        (Path("/etc/auditless"), Path("/etc/linux_health")),
    ]
    for canonical, legacy in pairs:
        assert dirs.index(canonical) < dirs.index(legacy)


def test_default_paths_built_from_config_dirs() -> None:
    """Non-cwd profile paths are exactly config_dirs + profile.yaml."""
    dirs = get_config_dirs()
    tails = [p.parent for p in get_default_profile_paths() if p.name == "profile.yaml"]
    assert tails == dirs


def test_list_profiles_uses_shared_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dashboard discovers profiles in canonical and legacy profile dirs."""
    from linux_health.dashboard import list_profiles

    _isolate(tmp_path, monkeypatch)
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "quick.yaml").write_text("name: quick\n", encoding="utf-8")
    legacy_dir = tmp_path / ".config" / "linux_health" / "profiles"
    legacy_dir.mkdir(parents=True)
    (legacy_dir / "old.yaml").write_text("name: old\n", encoding="utf-8")
    found = {entry["name"]: entry for entry in list_profiles()}
    assert found["quick"]["source"] == "profiles-dir"
    assert found["old"]["source"] == "profiles-dir"
