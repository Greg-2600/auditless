"""Tests for dual config-path discovery (ROADMAP item 10)."""

import warnings
from pathlib import Path

import pytest

from auditless.config import (
    DEFAULT_FIM_MAX_AGE_DAYS,
    MAX_FIM_MAX_AGE_DAYS,
    ScanProfile,
    get_config_dirs,
    get_default_profile_paths,
    load_profile_auto,
    merge_cli_test_filters,
    normalize_fim_max_age_days,
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


def test_default_profile_paths_shape() -> None:
    """Profile search covers cwd spellings, then every config dir."""
    paths = get_default_profile_paths()
    cwd = Path.cwd()
    assert paths[:2] == [cwd / "auditless.yaml", cwd / ".auditless.yaml"]
    assert [p.parent for p in paths if p.name == "profile.yaml"] == get_config_dirs()


def test_cwd_profile_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A profile in the working directory is discovered silently."""
    _isolate(tmp_path, monkeypatch)
    _write(tmp_path / "auditless.yaml", "cwd-profile")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        profile = load_profile_auto()
    assert profile is not None
    assert profile.name == "cwd-profile"


def test_no_profile_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty search locations yield no profile (and no warning)."""
    _isolate(tmp_path, monkeypatch)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert load_profile_auto() is None


def test_get_config_dirs_exact() -> None:
    """Config dirs are the three canonical auditless locations."""
    home = Path.home()
    assert get_config_dirs() == [
        home / ".config" / "auditless",
        home / ".auditless",
        Path("/etc/auditless"),
    ]


def test_default_paths_built_from_config_dirs() -> None:
    """Non-cwd profile paths are exactly config_dirs + profile.yaml."""
    dirs = get_config_dirs()
    tails = [p.parent for p in get_default_profile_paths() if p.name == "profile.yaml"]
    assert tails == dirs


def test_list_profiles_uses_shared_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dashboard discovers profiles in the cwd and user profile dirs."""
    from auditless.dashboard import list_profiles

    _isolate(tmp_path, monkeypatch)
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "quick.yaml").write_text("name: quick\n", encoding="utf-8")
    user_dir = tmp_path / ".config" / "auditless" / "profiles"
    user_dir.mkdir(parents=True)
    (user_dir / "old.yaml").write_text("name: old\n", encoding="utf-8")
    found = {entry["name"]: entry for entry in list_profiles()}
    assert found["quick"]["source"] == "profiles-dir"
    assert found["old"]["source"] == "profiles-dir"


def test_default_fim_max_age_days() -> None:
    """Profiles keep the historical 90-day FIM threshold by default."""
    assert ScanProfile().fim_max_age_days == DEFAULT_FIM_MAX_AGE_DAYS == 90


def test_load_profile_custom_fim_max_age_days(tmp_path: Path) -> None:
    """A profile can tune the FIM database-age threshold."""
    from auditless.config import load_profile

    profile = tmp_path / "fim.yaml"
    profile.write_text("name: fim\nfim_max_age_days: 30\n", encoding="utf-8")
    assert load_profile(profile).fim_max_age_days == 30


def test_load_profile_bad_fim_max_age_days_falls_back(tmp_path: Path) -> None:
    """Invalid YAML values never crash profile loading."""
    from auditless.config import load_profile

    profile = tmp_path / "fim.yaml"
    profile.write_text("name: fim\nfim_max_age_days: soon\n", encoding="utf-8")
    assert load_profile(profile).fim_max_age_days == 90


@pytest.mark.parametrize(
    "bad", [0, -1, MAX_FIM_MAX_AGE_DAYS + 1, 30.0, "30", True, None]
)
def test_normalize_fim_max_age_days_rejects_bad_input(bad: object) -> None:
    """Only positive ints within the sane bound are accepted."""
    assert normalize_fim_max_age_days(bad) == 90
    assert normalize_fim_max_age_days(MAX_FIM_MAX_AGE_DAYS) == MAX_FIM_MAX_AGE_DAYS


def test_lint_fim_max_age_days_range() -> None:
    """Profile linting flags out-of-range thresholds, not valid ones."""
    from auditless.config import lint_profile

    assert lint_profile({"fim_max_age_days": 30}) == ([], [])
    for bad in (0, -1, MAX_FIM_MAX_AGE_DAYS + 1, "soon"):
        errors, _ = lint_profile({"fim_max_age_days": bad})
        assert any("fim_max_age_days" in error for error in errors)


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
    from auditless.config import lint_profile_file

    profile = tmp_path / "good.yaml"
    profile.write_text(
        "name: test\nskip_tests: [STOR-6310]\ntimeout: 10\nverbose: false\n",
        encoding="utf-8",
    )
    assert lint_profile_file(profile) == ([], [])


def test_lint_catches_schema_problems() -> None:
    """Unknown keys and wrong types are errors naming the culprit."""
    from auditless.config import lint_profile

    errors, warnings = lint_profile(
        {"name": "t", "skip_test": ["STOR-6310"], "timeout": "soon"}
    )
    assert any("skip_test" in e for e in errors)
    assert any("timeout" in e for e in errors)
    assert warnings == []


def test_lint_unknown_ids_suggest(tmp_path: Path) -> None:
    """Unknown test IDs error, with did-you-mean for close matches."""
    from auditless.config import lint_profile

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


def test_lint_accepts_time_sync_extended_id() -> None:
    """The extended time sync check is usable in profiles."""
    from auditless.config import lint_profile

    errors, warnings = lint_profile(
        {"skip_tests": ["TIME-3105"], "only_tests": ["TIME-3105"]}
    )
    assert not any("TIME-3105" in e and "unknown" in e for e in errors)
    assert any("skip wins" in w for w in warnings)


def _warnings_for_overlap() -> list:
    """Overlap warning helper sharing the overlap fixture profile."""
    from auditless.config import lint_profile

    _, warnings = lint_profile(
        {"skip_tests": ["STOR-6310"], "only_tests": ["STOR-6310"]}
    )
    return warnings


def test_lint_file_problems(tmp_path: Path) -> None:
    """Missing files and broken YAML are errors, never tracebacks."""
    from auditless.config import lint_profile_file

    errors, _ = lint_profile_file(tmp_path / "missing.yaml")
    assert any("not found" in e for e in errors)
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: [unclosed\n", encoding="utf-8")
    errors, _ = lint_profile_file(broken)
    assert any("invalid YAML" in e for e in errors)


def test_profile_lint_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """auditless profile lint exits 0/1/2 for clean/bad/misuse."""
    from auditless import cli

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
