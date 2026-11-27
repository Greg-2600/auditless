"""Local service TLS certificate expiry checks.

Finds certificate files referenced by common service configurations
(Postfix, Dovecot, PostgreSQL, MySQL/MariaDB, Nginx, Apache) and reads
their ``notAfter`` value with ``openssl x509`` on the target. No network
connections are made.

Test ID: TLS-4500
Category: TLS Certificates
"""

from __future__ import annotations

import posixpath
import re
import shlex
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any

from .checks import CheckResult, _fail, _pass, _run, _unknown, _warn
from .config import (
    DEFAULT_TLS_CERT_WARN_DAYS,
    normalize_tls_cert_warn_days,
)

if TYPE_CHECKING:
    from .ssh_client import SSHSession


#: Search only local configuration trees; never connects to remote hosts.
_TLS_CERT_CONFIG_PROBE = (
    "bash -lc 'for d in /etc/postfix /etc/dovecot /etc/postgresql "
    "/etc/mysql /etc/my.cnf /etc/nginx /etc/apache2 /etc/httpd; do "
    '[ -e "$d" ] || continue; '
    "grep -rIHnE "
    '"^[[:space:]]*(smtpd_tls_cert_file|smtpd_tls_chain_files|'
    "ssl_certificate|ssl_cert_file|ssl-cert|ssl_cert|"
    'SSLCertificateFile|SSLCertificateChainFile)[[:space:]]*[= ]" '
    '"$d" 2>/dev/null; done; true\''
)

_CERT_KEYS = frozenset(
    {
        "smtpd_tls_cert_file",
        "smtpd_tls_chain_files",
        "ssl_certificate",
        "ssl_cert_file",
        "ssl-cert",
        "ssl_cert",
        "SSLCertificateFile",
        "SSLCertificateChainFile",
    }
)

_CERT_KEY_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z][A-Za-z0-9_-]*)\s*(?:=\s*|\s+)(?P<value>.+?)\s*$"
)

#: TLS expiry warning threshold (days) applied from the active scan profile.
TLS_CERT_WARN_DAYS: int = DEFAULT_TLS_CERT_WARN_DAYS


def set_tls_cert_warn_days(days: Any) -> None:
    """Set the TLS expiry warning threshold; bad values fall back to 30."""
    global TLS_CERT_WARN_DAYS
    TLS_CERT_WARN_DAYS = normalize_tls_cert_warn_days(days)


def get_tls_cert_warn_days() -> int:
    """Current TLS certificate expiry warning threshold in days."""
    return TLS_CERT_WARN_DAYS


def _service_for(key: str, config_path: str) -> str:
    """Human-readable service label for a certificate reference."""
    if key.startswith("smtpd_tls_"):
        return "postfix"
    if key.startswith("SSLCertificate"):
        return "apache"
    if key == "ssl_certificate":
        return "nginx"
    if key == "ssl_cert_file":
        return "postgresql"
    if key == "ssl-cert":
        return "mysql/mariadb"
    if config_path.startswith("/etc/dovecot"):
        return "dovecot"
    if config_path.startswith("/etc/mysql") or config_path.startswith("/etc/my.cnf"):
        return "mysql/mariadb"
    if config_path.startswith("/etc/postgresql"):
        return "postgresql"
    if config_path.startswith("/etc/nginx"):
        return "nginx"
    if config_path.startswith(("/etc/apache2", "/etc/httpd")):
        return "apache"
    return "local service"


def _strip_config_value(raw: str) -> str:
    """Remove comments, quoting, separators and Dovecot's ``<`` marker."""
    value = raw.strip()
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    value = value.rstrip(";").strip()
    if value.startswith("<"):
        value = value[1:].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1].strip()
    return value


def _expand_cert_path(value: str, config_path: str) -> str:
    """Expand Postfix's config_directory and resolve relative paths."""
    value = value.replace("${config_directory}", "/etc/postfix")
    value = value.replace("$config_directory", "/etc/postfix")
    if not value or "$" in value:
        return ""
    if not value.startswith("/"):
        value = posixpath.join(posixpath.dirname(config_path), value)
    return value


def _extract_tls_cert_paths(output: str) -> list[tuple[str, str]]:
    """Parse grep ``path:line:content`` output into (service, cert path)."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        parts = raw_line.split(":", 2)
        if len(parts) != 3 or not parts[1].isdigit():
            continue
        config_path, _, content = parts
        content = content.strip()
        if not content or content.startswith("#"):
            continue
        match = _CERT_KEY_RE.match(content)
        if match is None:
            continue
        key = match.group("key")
        if key not in _CERT_KEYS:
            continue
        service = _service_for(key, config_path)
        clean = _strip_config_value(match.group("value"))
        candidates = (
            re.split(r"[,\s]+", clean) if key == "smtpd_tls_chain_files" else [clean]
        )
        for candidate in candidates:
            path = _expand_cert_path(candidate, config_path)
            if not path or path in seen:
                continue
            seen.add(path)
            found.append((service, path))
    return found


def _parse_not_after(text: str) -> datetime | None:
    """Parse an ``openssl x509 -enddate`` notAfter line into UTC."""
    match = re.search(r"^notAfter=(.+)$", text, re.MULTILINE)
    if match is None:
        return None
    try:
        expiry = parsedate_to_datetime(match.group(1).strip())
    except (TypeError, ValueError):
        return None
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry.astimezone(timezone.utc)


def _certificate_label(service: str, path: str, expiry: datetime, now: datetime) -> str:
    """One-line certificate summary with expiry date and days remaining."""
    days = (expiry - now).total_seconds() / 86400
    return (
        f"{service} {path} (expires {expiry:%Y-%m-%d %H:%M UTC}, " f"{days:.1f} days)"
    )


def check_tls_certificate_expiry(
    ssh: "SSHSession",
    password: str = "",
    warn_days: int | None = None,
    timeout: int = 60,
) -> CheckResult:
    """Check expiry of certificates referenced by local service configs.

    Test ID: TLS-4500
    Category: TLS Certificates

    Covers mail (Postfix/Dovecot), database (PostgreSQL/MySQL/MariaDB)
    and web (Nginx/Apache) certificate directives. Expired certificates
    fail; certificates expiring within ``warn_days`` (default 30) warn.
    Hosts with no referenced certificates pass as not applicable.
    """
    category = "TLS Certificates"
    test_id = "TLS-4500"
    limit = (
        get_tls_cert_warn_days()
        if warn_days is None
        else normalize_tls_cert_warn_days(warn_days)
    )

    try:
        _, probe_out, _ = _run(ssh, _TLS_CERT_CONFIG_PROBE, command_timeout=timeout)
        references = _extract_tls_cert_paths(probe_out)
        if not references:
            return _pass(
                "Local Service Certificate Expiry",
                "No TLS certificates referenced by local service "
                "configurations found",
                "No action required if local TLS services are not used",
                category,
                test_id,
            )

        now = datetime.now(timezone.utc)
        expired: list[str] = []
        expiring: list[str] = []
        valid: list[str] = []
        unreadable: list[str] = []

        for service, path in references:
            command = (
                "openssl x509 -enddate -noout -in " + shlex.quote(path) + " 2>/dev/null"
            )
            _, cert_out, _ = _run(ssh, command, command_timeout=timeout)
            expiry = _parse_not_after(cert_out)
            if expiry is None:
                unreadable.append(f"{service} {path}")
                continue
            label = _certificate_label(service, path, expiry, now)
            if expiry <= now:
                expired.append(label)
            elif (expiry - now).total_seconds() <= limit * 86400:
                expiring.append(label)
            else:
                valid.append(label)

        unreadable_note = "; unreadable: " + ", ".join(unreadable) if unreadable else ""

        if expired:
            return _fail(
                "Local Service Certificate Expiry",
                "Expired certificate(s): " + "; ".join(expired) + unreadable_note,
                "Renew expired service certificates and reload the affected "
                "services",
                category,
                test_id,
            )

        if expiring:
            return _warn(
                "Local Service Certificate Expiry",
                f"Certificate(s) expiring within {limit} days: "
                + "; ".join(expiring)
                + unreadable_note,
                "Renew certificates before they expire and automate renewal",
                category,
                test_id,
            )

        if unreadable and not valid:
            return _unknown(
                "Local Service Certificate Expiry",
                f"Found {len(unreadable)} referenced certificate(s) but could "
                "not read their expiry: " + ", ".join(unreadable),
                "Verify openssl is installed and the certificate files are "
                "readable, or re-run privileged",
                category,
                test_id,
            )

        details = (
            f"{len(valid)} local service certificate(s) valid for more than "
            f"{limit} days"
        )
        if valid:
            details += ": " + "; ".join(valid)
        if unreadable_note:
            details += unreadable_note
        return _pass(
            "Local Service Certificate Expiry",
            details,
            "Continue monitoring certificate expiry and automate renewal",
            category,
            test_id,
        )

    except Exception as exc:  # pylint: disable=broad-except
        return _fail(
            "Local Service Certificate Expiry",
            f"Error checking local service certificate expiry: {exc}",
            "Verify SSH connectivity and openssl availability",
            category,
            test_id,
        )


def run_all_tls_checks(ssh: "SSHSession", password: str = "") -> list[CheckResult]:
    """Run all local TLS certificate checks."""
    return [check_tls_certificate_expiry(ssh, password)]
