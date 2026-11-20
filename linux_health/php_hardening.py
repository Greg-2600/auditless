"""Read-only PHP-FPM/opcache hardening probe helpers for PHP-2320.

The dashboard/CLI executes :data:`PHP_HARDENING_PROBE` once per host; the
pure parsers here turn its marker-delimited output into concrete gaps. No
command in this module changes system state and no credentials are used.
"""

from __future__ import annotations

import re

#: One remote shell: effective PHP ini values via ``php -i``, whether FPM is
#: present/active, and the directives in each FPM pool config.
PHP_HARDENING_PROBE = (
    "bash -lc '"
    "echo ===INI; "
    'php -i 2>/dev/null | grep -E "^(disable_functions|expose_php|'
    "allow_url_fopen|allow_url_include|opcache.enable|opcache.restrict_api|"
    'opcache.enable_file_override|session.cookie_httponly|session.cookie_secure) =>"; '
    "echo ===FPM; "
    "(command -v php-fpm || command -v php-fpm8.2 || command -v php-fpm8.3 "
    "|| true) 2>/dev/null | head -1; "
    "systemctl is-active php-fpm.service php-fpm php8.2-fpm.service "
    "php8.2-fpm 2>/dev/null | head -1; "
    "echo ===POOLS; "
    "for f in /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf; do "
    '[ -f "$f" ] || continue; echo "FILE:$f"; '
    'grep -hE "^[[:space:]]*(user|group|listen|listen.mode|listen.owner|'
    'listen.group)[[:space:]]*=" "$f" 2>/dev/null; '
    "done; "
    "true'"
)

REQUIRED_DISABLED_FUNCTIONS = (
    "exec",
    "passthru",
    "shell_exec",
    "system",
    "proc_open",
    "popen",
    "curl_exec",
    "curl_multi_exec",
    "parse_ini_file",
    "show_source",
)

_TRUTHY = {"1", "on", "true", "yes", "enabled"}


def probe_sections(output: str) -> dict[str, list[str]]:
    """Split a marker-delimited probe into named sections."""
    sections: dict[str, list[str]] = {}
    current = ""
    for line in output.splitlines():
        if line.startswith("==="):
            current = line[3:].strip()
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def _is_on(value: str) -> bool:
    return value.strip().lower() in _TRUTHY


def ini_values(sections: dict[str, list[str]]) -> dict[str, str]:
    """Parse ``php -i`` ``key => local => master`` lines (local value wins)."""
    values: dict[str, str] = {}
    for line in sections.get("INI", []):
        parts = [part.strip() for part in line.split("=>")]
        if len(parts) >= 2 and parts[0]:
            values[parts[0].lower()] = parts[1]
    return values


def _ini_unset(value: str) -> bool:
    """True when php -i reports an absent value (``no value``/empty/none)."""
    return value.strip().lower() in {"", "no value", "none", "<no value>"}


def missing_functions(disable_functions: str) -> list[str]:
    """Return dangerous functions absent from an exact comma-separated list."""
    disabled = {
        name.strip().strip("\"'").lower() for name in disable_functions.split(",")
    }
    return [name for name in REQUIRED_DISABLED_FUNCTIONS if name not in disabled]


def fpm_pools(sections: dict[str, list[str]]) -> dict[str, dict[str, str]]:
    """Parse FPM pool configs into ``{path: {directive: value}}``."""
    pools: dict[str, dict[str, str]] = {}
    current = ""
    for line in sections.get("POOLS", []):
        text = line.strip()
        if text.startswith("FILE:"):
            current = text[5:]
            pools[current] = {}
        elif current and "=" in text:
            key, _, value = text.partition("=")
            pools[current][key.strip().lower()] = value.strip()
    return pools


def _fpm_gaps(sections: dict[str, list[str]]) -> list[str]:
    state = " ".join(sections.get("FPM", [])).strip().lower()
    binary = any(
        line.strip().startswith(("/usr", "php-fpm")) for line in sections.get("FPM", [])
    )
    if not binary and not state.startswith("active"):
        return []
    pools = fpm_pools(sections)
    if not pools:
        return ["PHP-FPM is present but no pool config was found"]
    gaps: list[str] = []
    for path, settings in pools.items():
        label = path.rsplit("/", 1)[-1]
        if settings.get("user", "").lower() in {"root", "0"}:
            gaps.append(f"FPM pool {label} runs as root")
        if settings.get("group", "").lower() in {"root", "0"}:
            gaps.append(f"FPM pool {label} uses the root group")
        mode = settings.get("listen.mode", "")
        match = re.search(r"0?([0-7]{3,4})", mode)
        if match and int(match.group(1), 8) & 0o002:
            gaps.append(f"FPM pool {label} has a world-writable listen mode ({mode})")
        listen = settings.get("listen", "").lower()
        if listen.startswith(("0.0.0.0:", "[::]:", "*:", "9000")) or listen.isdigit():
            gaps.append(f"FPM pool {label} listens on all interfaces ({listen})")
    return gaps


def hardening_gaps(sections: dict[str, list[str]]) -> list[str]:
    """Derive stage-2 PHP/FPM/opcache gaps from probe sections."""
    values = ini_values(sections)
    gaps: list[str] = []

    missing = missing_functions(values.get("disable_functions", ""))
    if missing:
        gaps.append("dangerous functions not disabled: " + ", ".join(missing[:4]))

    if _is_on(values.get("expose_php", "")):
        gaps.append("expose_php enabled (version disclosure)")
    if _is_on(values.get("allow_url_fopen", "")):
        gaps.append("allow_url_fopen enabled (remote file inclusion risk)")
    if _is_on(values.get("allow_url_include", "")):
        gaps.append("allow_url_include enabled (remote code execution risk)")
    if not _is_on(values.get("session.cookie_httponly", "")):
        gaps.append("session.cookie_httponly not enabled")
    if not _is_on(values.get("session.cookie_secure", "")):
        gaps.append("session.cookie_secure not enabled")

    if any(key.startswith("opcache.") for key in values):
        if _ini_unset(values.get("opcache.restrict_api", "")):
            gaps.append("opcache.restrict_api not set (web users may call opcache API)")
        if _is_on(values.get("opcache.enable_file_override", "")):
            gaps.append("opcache.enable_file_override bypasses file existence checks")

    gaps.extend(_fpm_gaps(sections))
    return gaps
