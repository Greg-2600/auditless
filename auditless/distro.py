"""Distribution detection shared by all checks (one helper, one parser).

Reads ``/etc/os-release`` (falling back to ``/usr/lib/os-release``) and
normalizes the result to a small family vocabulary (debian/rhel/alpine/
suse/arch/unknown) so checks stop reimplementing ``which``-based
guessing. Detection never raises: anything unreadable is ``unknown``
and callers keep their legacy fallback paths.
"""

from __future__ import annotations

from dataclasses import dataclass

from .checks import _run
from .ssh_client import SSHSession

_DEBIAN_IDS = frozenset(
    {
        "debian",
        "ubuntu",
        "linuxmint",
        "pop",
        "pop_os",
        "raspbian",
        "kali",
        "elementary",
        "zorin",
    }
)
_RHEL_IDS = frozenset(
    {
        "rhel",
        "centos",
        "fedora",
        "rocky",
        "almalinux",
        "ol",
        "scientific",
        "amzn",
    }
)
_ALPINE_IDS = frozenset({"alpine"})
_SUSE_IDS = frozenset({"sles", "opensuse-leap", "opensuse-tumbleweed", "opensuse"})
_ARCH_IDS = frozenset({"arch", "manjaro", "endeavouros", "artix"})


@dataclass(frozen=True)
class DistroInfo:
    """Normalized distribution identity (unknown fields stay empty)."""

    id: str = ""
    name: str = ""
    version_id: str = ""
    like: tuple[str, ...] = ()
    family: str = "unknown"


def family_for(distro_id: str, like: tuple[str, ...] = ()) -> str:
    """Map an os-release ID (+ ID_LIKE) to a family name.

    Checks the ID first, then ID_LIKE tokens directly, then transitively
    (``ID=neon ID_LIKE=ubuntu`` resolves through ubuntu to debian), so
    derivatives resolve even with unfamiliar IDs.
    """
    ident = distro_id.strip().lower()
    likes = {token.strip().lower() for token in like}
    if ident in _DEBIAN_IDS or "debian" in likes:
        return "debian"
    if ident in _RHEL_IDS or likes & {"rhel", "centos", "fedora"}:
        return "rhel"
    if ident in _ALPINE_IDS or "alpine" in likes:
        return "alpine"
    if ident in _SUSE_IDS or likes & {"suse", "opensuse"}:
        return "suse"
    if ident in _ARCH_IDS or "arch" in likes:
        return "arch"
    for token in likes:
        if token != ident:
            nested = family_for(token)
            if nested != "unknown":
                return nested
    return "unknown"


def parse_os_release(text: str) -> DistroInfo:
    """Parse os-release content (comments, quotes, missing keys tolerated)."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    distro_id = values.get("ID", "").lower()
    like = tuple(values.get("ID_LIKE", "").split())
    return DistroInfo(
        id=distro_id,
        name=values.get("NAME", ""),
        version_id=values.get("VERSION_ID", ""),
        like=tuple(token.lower() for token in like),
        family=family_for(distro_id, tuple(like)),
    )


def get_distro(ssh: SSHSession) -> DistroInfo:
    """Detect the remote distribution (never raises; unknown on failure)."""
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            ret, out, _ = _run(ssh, f"cat {path} 2>/dev/null")
        except Exception:
            continue
        if ret == 0 and out.strip():
            return parse_os_release(out)
    return DistroInfo()
