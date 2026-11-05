"""Tests for shared distro detection (ROADMAP item 29)."""

from typing import Any
from unittest.mock import MagicMock

import pytest

from linux_health.distro import (
    DistroInfo,
    family_for,
    get_distro,
    parse_os_release,
)

UBUNTU_2204 = """PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
"""

DEBIAN_12 = """PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
"""

RHEL_9 = """NAME="Red Hat Enterprise Linux"
VERSION="9.3 (Plow)"
ID="rhel"
VERSION_ID="9.3"
PLATFORM_ID="platform:el9"
ID_LIKE="fedora"
"""

ALPINE_319 = """NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.0
PRETTY_NAME="Alpine Linux v3.19"
HOME_URL="https://alpinelinux.org/"
"""

ROCKY_9 = """NAME="Rocky Linux"
VERSION="9.3 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"
"""


def test_parse_ubuntu() -> None:
    """Ubuntu 22.04 resolves to the debian family with version."""
    info = parse_os_release(UBUNTU_2204)
    assert info == DistroInfo(
        id="ubuntu",
        name="Ubuntu",
        version_id="22.04",
        like=("debian",),
        family="debian",
    )


def test_parse_debian() -> None:
    """Debian 12 resolves without any ID_LIKE hint."""
    info = parse_os_release(DEBIAN_12)
    assert (info.id, info.version_id, info.family) == ("debian", "12", "debian")


def test_parse_rhel() -> None:
    """RHEL 9 resolves via explicit ID (LIKE is a fallback only)."""
    info = parse_os_release(RHEL_9)
    assert (info.id, info.version_id, info.family) == ("rhel", "9.3", "rhel")


def test_parse_alpine() -> None:
    """Alpine resolves with no LIKE line at all."""
    info = parse_os_release(ALPINE_319)
    assert (info.id, info.family) == ("alpine", "alpine")


def test_parse_derivative_via_like() -> None:
    """Rocky resolves to rhel through its ID_LIKE chain."""
    assert parse_os_release(ROCKY_9).family == "rhel"
    assert family_for("linuxmint", ("ubuntu",)) == "debian"
    assert family_for("neon", ("ubuntu",)) == "debian"
    assert family_for("something-new", ()) == "unknown"


def test_parse_tolerates_noise() -> None:
    """Comments, blanks, single quotes, and missing keys never raise."""
    info = parse_os_release("# comment\n\nID='arch'\nMALFORMED\nNAME=NoQuotes\n")
    assert (info.id, info.name, info.family) == ("arch", "NoQuotes", "arch")
    assert parse_os_release("").family == "unknown"


def _mock_ssh(hostname: str, *os_release_hits: tuple[int, str]) -> MagicMock:
    """SSH double serving canned os-release reads in order."""
    ssh = MagicMock()
    ssh.hostname = hostname
    ssh._client = None
    outputs = list(os_release_hits)

    def fake_run(command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        if command.startswith("cat ") and outputs:
            ret, out = outputs.pop(0)
            return ret, out, ""
        return 1, "", ""

    ssh.run = fake_run
    return ssh


@pytest.fixture(autouse=True)
def _fresh_cache() -> Any:
    """Reset entries so host-keyed tests never see another test's data."""
    from linux_health.checks import reset_command_cache

    reset_command_cache()
    yield
    reset_command_cache()


def test_get_distro_reads_os_release() -> None:
    """Primary path parses /etc/os-release."""
    assert get_distro(_mock_ssh("ubu", (0, UBUNTU_2204))).family == "debian"


def test_get_distro_falls_back_to_usr_lib() -> None:
    """Empty primary falls through to /usr/lib/os-release."""
    info = get_distro(_mock_ssh("rhel-fb", (0, ""), (0, RHEL_9)))
    assert (info.id, info.family) == ("rhel", "rhel")


def test_get_distro_unknown_never_raises() -> None:
    """Unreadable files and failing commands yield unknown, not errors."""
    assert get_distro(_mock_ssh("gone", (1, ""), (1, ""))).family == "unknown"


def test_get_distro_rhel_and_alpine() -> None:
    """Family coverage across the remaining fixtures."""
    assert get_distro(_mock_ssh("rhel", (0, RHEL_9))).family == "rhel"
    assert get_distro(_mock_ssh("alpine", (0, ALPINE_319))).family == "alpine"
