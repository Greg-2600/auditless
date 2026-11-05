"""Configuration and profile management for Auditless."""

from __future__ import annotations

import difflib
import warnings
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Set

try:
    import yaml  # type: ignore[import-untyped]

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class ScanProfile:
    """Scan profile configuration."""

    name: str = "default"
    description: str = "Default security scan profile"

    # Test control
    skip_tests: Set[str] = field(default_factory=set)
    only_tests: Set[str] = field(default_factory=set)
    skip_categories: Set[str] = field(default_factory=set)

    # Scan options
    enable_rootkit_scan: bool = False
    enable_package_hygiene: bool = False
    timeout: int = 10
    command_timeout: int = 60

    # Reporting
    show_warnings_only: bool = False
    verbose: bool = False

    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)


def load_profile(profile_path: str | Path) -> ScanProfile:
    """Load a scan profile from YAML file."""
    if not YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required for profile support. "
            "Install it with: pip install pyyaml"
        )

    path = Path(profile_path)
    if not path.exists():
        raise FileNotFoundError(f"Profile not found: {profile_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data:
        return ScanProfile()

    # Convert lists to sets for skip/only tests
    skip_tests = set(data.get("skip_tests", []))
    only_tests = set(data.get("only_tests", []))
    skip_categories = set(data.get("skip_categories", []))

    return ScanProfile(
        name=data.get("name", "custom"),
        description=data.get("description", ""),
        skip_tests=skip_tests,
        only_tests=only_tests,
        skip_categories=skip_categories,
        enable_rootkit_scan=data.get("enable_rootkit_scan", False),
        enable_package_hygiene=data.get("enable_package_hygiene", False),
        timeout=data.get("timeout", 10),
        command_timeout=data.get("command_timeout", 60),
        show_warnings_only=data.get("show_warnings_only", False),
        verbose=data.get("verbose", False),
        custom_settings=data.get("custom_settings", {}),
    )


def create_default_profile(output_path: str | Path) -> None:
    """Create a default profile template."""
    if not YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required for profile support. "
            "Install it with: pip install pyyaml"
        )

    profile_content = """# Auditless Scan Profile
# Customize this file to control scan behavior

name: custom
description: Custom security scan profile

# Skip specific tests by test ID (e.g., STOR-6310, AUTH-9328)
skip_tests:
  # - BOOT-5122  # Skip bootloader password check
  # - KERN-5820  # Skip kernel hardening check

# Run only specific tests (if specified, all others are skipped)
only_tests: []
  # - BOOT-5122
  # - AUTH-9328

# Skip entire categories
skip_categories: []
  # - "Boot/Kernel"
  # - "Web Server"

# Enable optional deep scans
enable_rootkit_scan: false
enable_package_hygiene: false

# Timeout settings (seconds)
timeout: 10
command_timeout: 60

# Reporting options
show_warnings_only: false
verbose: false

# Custom settings (key-value pairs for extensions)
custom_settings: {}
"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(profile_content)


def is_legacy_profile_path(path: str | Path) -> bool:
    """Whether a profile path uses a legacy ``linux_health`` location."""
    name = Path(path).name
    parts = Path(path).parts
    return (
        "linux_health" in name
        or "linux_health" in parts
        or name in (".linux_health.yaml",)
    )


def get_config_dirs() -> list[Path]:
    """Base config directories, canonical ``auditless`` first, legacy last.

    Shared by :func:`get_default_profile_paths` (appends ``profile.yaml``)
    and the dashboard profile-directory scan (appends ``profiles``).
    """
    home = Path.home()
    return [
        home / ".config" / "auditless",
        home / ".auditless",
        Path("/etc/auditless"),
        home / ".config" / "linux_health",
        home / ".linux_health",
        Path("/etc/linux_health"),
    ]


def get_default_profile_paths() -> list[Path]:
    """Get default profile search paths (canonical first, legacy last)."""
    paths = []
    stems = [
        "auditless.yaml",
        ".auditless.yaml",
        "linux_health.yaml",
        ".linux_health.yaml",
    ]

    # Current directory (canonical before legacy)
    for stem in stems:
        paths.append(Path.cwd() / stem)

    paths.extend(config_dir / "profile.yaml" for config_dir in get_config_dirs())

    return paths


def load_profile_auto() -> ScanProfile | None:
    """Auto-load profile from default locations."""
    if not YAML_AVAILABLE:
        return None

    for path in get_default_profile_paths():
        if path.exists():
            if is_legacy_profile_path(path):
                warnings.warn(
                    f"Profile at legacy path {path} is deprecated; "
                    "move it to the auditless equivalent "
                    "(~/.config/auditless/profile.yaml).",
                    DeprecationWarning,
                    stacklevel=2,
                )
            try:
                return load_profile(path)
            except (FileNotFoundError, yaml.YAMLError, ValueError):
                continue

    return None


def parse_test_id_list(raw: str | None) -> set[str]:
    """Parse comma-separated test IDs (whitespace-tolerated, empties dropped)."""
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def merge_cli_test_filters(
    profile: ScanProfile | None,
    only_tests: set[str] | None = None,
    skip_tests: set[str] | None = None,
) -> ScanProfile | None:
    """Combine a YAML profile with CLI --only-tests/--skip-tests.

    only_tests narrows (intersection when both constrain), skip_tests
    accumulates (union). Returns the profile untouched when no CLI
    flags are given, or None when nothing filters at all.
    """
    cli_only = only_tests or set()
    cli_skip = skip_tests or set()
    if not cli_only and not cli_skip:
        return profile
    base = profile if profile is not None else ScanProfile()
    if cli_only and base.only_tests:
        only = base.only_tests & cli_only
    else:
        only = cli_only or base.only_tests
    return replace(base, only_tests=only, skip_tests=base.skip_tests | cli_skip)


def should_skip_test(test_id: str, category: str, profile: ScanProfile | None) -> bool:
    """Determine if a test should be skipped based on profile."""
    if not profile:
        return False

    # If only_tests is specified, skip everything not in the list
    if profile.only_tests and test_id not in profile.only_tests:
        return True

    # Skip if test ID is in skip list
    if test_id in profile.skip_tests:
        return True

    # Skip if category is in skip list
    if category in profile.skip_categories:
        return True

    return False


#: Profile top-level keys with their expected value types. Categories are
#: intentionally absent: they are free-form strings with no central
#: registry, so only their element type is checked.
_PROFILE_FIELD_TYPES: dict[str, tuple[type, ...]] = {
    "name": (str,),
    "description": (str,),
    "skip_tests": (list,),
    "only_tests": (list,),
    "skip_categories": (list,),
    "enable_rootkit_scan": (bool,),
    "enable_package_hygiene": (bool,),
    "timeout": (int,),
    "command_timeout": (int,),
    "show_warnings_only": (bool,),
    "verbose": (bool,),
    "custom_settings": (dict,),
}


def _suggest_test_id(bad_id: str) -> str:
    """Closest registry IDs for an unknown test ID (may be empty)."""
    from .test_ids import CHECK_TEST_IDS

    candidates = sorted(set(CHECK_TEST_IDS.values()))
    matches = difflib.get_close_matches(bad_id.upper(), candidates, n=3, cutoff=0.6)
    if not matches:
        return ""
    return " (did you mean: " + ", ".join(matches) + "?)"


def lint_profile(data: object) -> tuple[list[str], list[str]]:
    """Validate parsed profile data, returning (errors, warnings).

    Checks unknown keys (likely typos), value types, and unknown test
    IDs (with suggestions). Pure function: parsing/file errors belong
    to lint_profile_file.
    """
    from .test_ids import CHECK_TEST_IDS

    errors: list[str] = []
    warns: list[str] = []
    if not isinstance(data, dict):
        return ["profile must be a mapping of settings"], []
    known_ids = set(CHECK_TEST_IDS.values())
    for key in data:
        if key not in _PROFILE_FIELD_TYPES:
            errors.append(f"unknown setting {key!r} (possible typo)")
    for key, types in _PROFILE_FIELD_TYPES.items():
        if key not in data:
            continue
        value = data[key]
        # bool is an int subclass: reject booleans for int fields explicitly.
        if not isinstance(value, types) or (
            isinstance(value, bool) and bool not in types
        ):
            expected = "/".join(t.__name__ for t in types)
            errors.append(f"{key!r} must be {expected}")
            continue
        if key in ("skip_tests", "only_tests") and isinstance(value, list):
            bad_items = [v for v in value if not isinstance(v, str)]
            if bad_items:
                errors.append(f"{key!r} entries must be strings")
            for entry in [v for v in value if isinstance(v, str)]:
                if entry not in known_ids:
                    errors.append(
                        f"unknown test ID {entry!r} in {key!r}"
                        + _suggest_test_id(entry)
                    )
        if key == "skip_categories" and isinstance(value, list):
            bad_items = [v for v in value if not isinstance(v, str)]
            if bad_items:
                errors.append(f"{key!r} entries must be strings")
    skip = data.get("skip_tests") or []
    only = data.get("only_tests") or []
    if isinstance(skip, list) and isinstance(only, list):
        overlap = {v for v in skip if isinstance(v, str)} & {
            v for v in only if isinstance(v, str)
        }
        if overlap:
            warns.append(
                "tests in both only_tests and skip_tests "
                f"(skip wins): {sorted(overlap)}"
            )
    return errors, warns


def lint_profile_file(path: str | Path) -> tuple[list[str], list[str]]:
    """Lint a profile file, returning (errors, warnings)."""
    profile_path = Path(path)
    if not profile_path.exists():
        return [f"profile not found: {path}"], []
    if not YAML_AVAILABLE:
        return ["PyYAML is required for profile support"], []
    try:
        with open(profile_path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        return [f"invalid YAML in {path}: {exc}"], []
    if data is None:
        return [], []
    return lint_profile(data)
