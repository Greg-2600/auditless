"""Tests for dual config-path discovery (ROADMAP item 10)."""

import warnings
from pathlib import Path

import pytest

from linux_health.config import (
    ScanProfile,
    get_config_dirs,
    get_default_profile_paths,
    is_legacy_profile_path,
    load_profile_auto,
    merge_cli_test_filters,
    parse_test_id_list,
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


def test_parse_test_id_list() -> None:
    """Comma-separated IDs parse with whitespace tolerance."""
    assert parse_test_id_list(None) == set()
    assert parse_test_id_list("") == set()
    assert parse_test_id_list("STOR-6310") == {"STOR-6310"}
    assert parse_test_id_list("STOR-6310, AUTH-9328 ,,") == {"STOR-6310", "AUTH-9328"}


def test_merge_no_flags_returns_profile_untouched() -> None:
    """Without CLI flags the YAML profile passes through by identity."""
    profile = ScanProfile(name="prod")
    assert merge_cli_test_filters(profile) is profile
    assert merge_cli_test_filters(None) is None


def test_merge_cli_only_builds_profile() -> None:
    """CLI flags alone produce an effective profile from defaults."""
    merged = merge_cli_test_filters(None, {"A-1"}, {"B-2"})
    assert merged is not None
    assert merged.only_tests == {"A-1"}
    assert merged.skip_tests == {"B-2"}


def test_merge_intersects_only_unions_skip() -> None:
    """only_tests narrows, skip_tests accumulates across YAML + CLI."""
    profile = ScanProfile(name="prod", only_tests={"A-1", "A-2"}, skip_tests={"B-1"})
    merged = merge_cli_test_filters(profile, {"A-2", "A-3"}, {"B-2"})
    assert merged is not None
    assert merged.only_tests == {"A-2"}
    assert merged.skip_tests == {"B-1", "B-2"}
    assert merged.name == "prod"


def test_lint_valid_profile(tmp_path: Path) -> None:
    """A well-formed profile lints clean."""
    from linux_health.config import lint_profile_file

    profile = tmp_path / "good.yaml"
    profile.write_text(
        "name: test\nskip_tests: [STOR-6310]\ntimeout: 10\nverbose: false\n",
        encoding="utf-8",
    )
    assert lint_profile_file(profile) == ([], [])


def test_lint_catches_schema_problems() -> None:
    """Unknown keys and wrong types are errors naming the culprit."""
    from linux_health.config import lint_profile

    errors, warnings = lint_profile(
        {"name": "t", "skip_test": ["STOR-6310"], "timeout": "soon"}
    )
    assert any("skip_test" in e for e in errors)
    assert any("timeout" in e for e in errors)
    assert warnings == []


def test_lint_unknown_ids_suggest(tmp_path: Path) -> None:
    """Unknown test IDs error, with did-you-mean for close matches."""
    from linux_health.config import lint_profile

    errors, _ = lint_profile(
        {
            "skip_tests": ["STOR-6310"],
            "only_tests": ["STOR-6310", "STOR-631", "stor-6310", "NOPE-0"],
        }
    )
    assert not any("STOR-6310'" in e and "unknown" in e for e in errors)
    suggest = next(e for e in errors if "'STOR-631'" in e)
    assert "STOR-6310" in suggest and "did you mean" in suggest
    lowered = next(e for e in errors if "'stor-6310'" in e)
    assert "STOR-6310" in lowered
    assert any("skip wins" in w for w in _warnings_for_overlap())
    assert any("'NOPE-0'" in e and "did you mean" not in e for e in errors)


def _warnings_for_overlap() -> list:
    """Overlap warning helper sharing the overlap fixture profile."""
    from linux_health.config import lint_profile

    _, warnings = lint_profile(
        {"skip_tests": ["STOR-6310"], "only_tests": ["STOR-6310"]}
    )
    return warnings


def test_lint_file_problems(tmp_path: Path) -> None:
    """Missing files and broken YAML are errors, never tracebacks."""
    from linux_health.config import lint_profile_file

    errors, _ = lint_profile_file(tmp_path / "missing.yaml")
    assert any("not found" in e for e in errors)
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: [unclosed\n", encoding="utf-8")
    errors, _ = lint_profile_file(broken)
    assert any("invalid YAML" in e for e in errors)


def test_profile_lint_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """auditless profile lint exits 0/1/2 for clean/bad/misuse."""
    from linux_health import cli

    good = tmp_path / "good.yaml"
    good.write_text("name: t\nskip_tests: [STOR-6310]\n", encoding="utf-8")
    assert cli.main(["profile", "lint", str(good)]) == 0
    assert "profile OK" in capsys.readouterr().out

    bad = tmp_path / "bad.yaml"
    bad.write_text("name: t\nskip_test: [STOR-6310]\n", encoding="utf-8")
    assert cli.main(["profile", "lint", str(bad)]) == 1
    assert "skip_test" in capsys.readouterr().err

    assert cli.main(["profile", "lint"]) == 2
    assert cli.main(["profile", "--help"]) == 0
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["profile", "bogus"])
    assert exc_info.value.code == 2
