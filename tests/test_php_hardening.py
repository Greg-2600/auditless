"""Tests for the PHP-2320 stage-2 FPM/opcache/ini hardening audit."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from auditless.checks import (
    check_php_security,
    disable_command_cache,
    enable_command_cache,
    is_command_cache_enabled,
    reset_command_cache,
)
from auditless.php_hardening import (
    PHP_HARDENING_PROBE,
    fpm_pools,
    hardening_gaps,
    ini_values,
    missing_functions,
    probe_sections,
)


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    was_enabled = is_command_cache_enabled()
    disable_command_cache()
    reset_command_cache()
    yield
    reset_command_cache()
    if was_enabled:
        enable_command_cache()


_HARDENED_INI = (
    "disable_functions => exec,passthru,shell_exec,system,proc_open,popen,"
    "curl_exec,curl_multi_exec,parse_ini_file,show_source => same\n"
    "expose_php => Off => Off\n"
    "allow_url_fopen => Off => Off\n"
    "allow_url_include => Off => Off\n"
    "session.cookie_httponly => 1 => 1\n"
    "session.cookie_secure => 1 => 1\n"
    "opcache.enable => On => On\n"
    "opcache.restrict_api => /usr/local/bin => /usr/local/bin\n"
    "opcache.enable_file_override => Off => Off\n"
)

_WEAK_INI = (
    "disable_functions => no value => no value\n"
    "expose_php => On => On\n"
    "allow_url_fopen => On => On\n"
    "allow_url_include => On => On\n"
    "session.cookie_httponly => 0 => 0\n"
    "session.cookie_secure => 0 => 0\n"
    "opcache.enable => On => On\n"
    "opcache.restrict_api => no value => no value\n"
    "opcache.enable_file_override => On => On\n"
)


def _probe(ini: str = _HARDENED_INI, fpm: str = "", pools: str = "") -> str:
    return f"===INI\n{ini}===FPM\n{fpm}\n===POOLS\n{pools}\n"


def _ssh(*responses: tuple[int, str, str]) -> MagicMock:
    ssh = MagicMock()
    ssh._client = None  # use ssh.run() for deterministic test responses
    ssh.run.side_effect = responses
    return ssh


def test_probe_is_read_only_and_marker_delimited() -> None:
    assert "bash -lc" in PHP_HARDENING_PROBE
    for marker in ("===INI", "===FPM", "===POOLS"):
        assert marker in PHP_HARDENING_PROBE
    for write_op in (">>", "tee", "sed -i", " > "):
        assert write_op not in PHP_HARDENING_PROBE


def test_probe_sections_and_ini_values() -> None:
    sections = probe_sections(_probe())
    assert list(sections) == ["INI", "FPM", "POOLS"]
    values = ini_values(sections)
    assert values["disable_functions"].startswith("exec,passthru")
    assert values["opcache.restrict_api"] == "/usr/local/bin"


def test_missing_functions_uses_exact_names() -> None:
    # Substring matching would wrongly accept "exec" from "shell_exec".
    assert missing_functions("shell_exec,system") == [
        "exec",
        "passthru",
        "proc_open",
        "popen",
        "curl_exec",
        "curl_multi_exec",
        "parse_ini_file",
        "show_source",
    ]
    assert missing_functions(_HARDENED_INI.split("=>")[1].strip()) == []


def test_hardened_php_has_no_gaps() -> None:
    assert hardening_gaps(probe_sections(_probe())) == []


def test_weak_ini_reports_all_policy_gaps() -> None:
    gaps = hardening_gaps(probe_sections(_probe(ini=_WEAK_INI)))
    assert any("dangerous functions" in gap for gap in gaps)
    assert "expose_php enabled (version disclosure)" in gaps
    assert any("allow_url_fopen" in gap for gap in gaps)
    assert any("allow_url_include" in gap for gap in gaps)
    assert "session.cookie_httponly not enabled" in gaps
    assert "session.cookie_secure not enabled" in gaps
    assert any("opcache.restrict_api" in gap for gap in gaps)
    assert any("enable_file_override" in gap for gap in gaps)


def test_fpm_pool_parser_and_root_socket_gaps() -> None:
    pools = _probe(
        fpm="/usr/sbin/php-fpm\nactive\n",
        pools=(
            "FILE:/etc/php/8.2/fpm/pool.d/www.conf\n"
            "user = root\n"
            "group = root\n"
            "listen = 0.0.0.0:9000\n"
            "listen.mode = 0666\n"
        ),
    )
    parsed = fpm_pools(probe_sections(pools))
    assert parsed["/etc/php/8.2/fpm/pool.d/www.conf"]["listen.mode"] == "0666"
    gaps = hardening_gaps(probe_sections(pools))
    assert any("runs as root" in gap for gap in gaps)
    assert any("root group" in gap for gap in gaps)
    assert any("world-writable listen mode" in gap for gap in gaps)
    assert any("all interfaces" in gap for gap in gaps)


def test_fpm_absent_adds_no_gaps() -> None:
    assert hardening_gaps(probe_sections(_probe(fpm="inactive\n"))) == []


def test_check_php_not_detected() -> None:
    result = check_php_security(_ssh((1, "", "")))
    assert result.status == "pass"
    assert "PHP not detected" in result.details
    assert result.test_id == "PHP-2320"


def test_check_php_hardened_passes() -> None:
    result = check_php_security(
        _ssh(
            (0, "PHP 8.2.0 (cli) (built: Jan 1 2026)", ""),
            (0, _probe(), ""),
        )
    )
    assert result.status == "pass"
    assert "8.2.0" in result.details
    assert "opcache" in result.details


def test_check_php_with_gaps_warns() -> None:
    result = check_php_security(
        _ssh(
            (0, "PHP 8.2.0 (cli)", ""),
            (0, _probe(ini=_WEAK_INI), ""),
        )
    )
    assert result.status == "warn"
    assert "expose_php" in result.details
    assert "opcache.restrict_api not set" in result.details


def test_check_php_probe_failure_is_unknown() -> None:
    result = check_php_security(
        _ssh(
            (0, "PHP 8.2.0 (cli)", ""),
            (0, "", ""),
        )
    )
    assert result.status == "unknown"
    assert "stage-2 probe" in result.details
