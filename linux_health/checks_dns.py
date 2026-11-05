"""DNS Security Module for BIND and other DNS servers.

This module implements DNS security checks following Lynis test patterns
(DNS-4000 to DNS-4004 range).

Test IDs: DNS-4000 to DNS-4004
Category: DNS Security
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .checks import CheckResult, _fail, _pass, _run, _warn

if TYPE_CHECKING:
    from .ssh_client import SSHSession


def check_dns_server_installed(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if DNS server software is installed.

    Test ID: DNS-4000 (Lynis equivalent)
    Category: DNS

    Detects BIND (named), dnsmasq, and other DNS server installations.
    """
    category = "DNS"
    test_id = "DNS-4000"

    # Check for BIND (named)
    ret, out, err = _run(ssh, "which named 2>/dev/null")
    bind_installed = ret == 0 and out.strip()

    # Check for dnsmasq
    ret, out, err = _run(ssh, "which dnsmasq 2>/dev/null")
    dnsmasq_installed = ret == 0 and out.strip()

    # Check for unbound
    ret, out, err = _run(ssh, "which unbound 2>/dev/null")
    unbound_installed = ret == 0 and out.strip()

    if not bind_installed and not dnsmasq_installed and not unbound_installed:
        return _pass(
            "DNS Server Installation",
            "No DNS server software detected",
            "DNS server not required for non-DNS systems",
            category,
            test_id,
        )

    installed = []
    if bind_installed:
        ret, ver, _ = _run(ssh, "named -v 2>&1 | head -1")
        if ret == 0:
            installed.append(f"BIND ({ver.strip()})")
        else:
            installed.append("BIND")

    if dnsmasq_installed:
        ret, ver, _ = _run(ssh, "dnsmasq --version 2>&1 | head -1")
        if ret == 0:
            installed.append(f"dnsmasq ({ver.strip()})")
        else:
            installed.append("dnsmasq")

    if unbound_installed:
        ret, ver, _ = _run(ssh, "unbound -V 2>&1 | head -1")
        if ret == 0:
            installed.append(f"Unbound ({ver.strip()})")
        else:
            installed.append("Unbound")

    return _warn(
        "DNS Server Installation",
        f"DNS server installed: {', '.join(installed)}",
        "Harden DNS configuration and restrict zone transfers",
        category,
        test_id,
    )


def check_dnssec_configured(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if DNSSEC is configured and enabled.

    Test ID: DNS-4001
    Category: DNS

    Verifies DNSSEC validation and zone signing configuration.
    """
    category = "DNS"
    test_id = "DNS-4001"

    dnssec_found = []

    # Check BIND DNSSEC configuration
    ret, out, err = _run(
        ssh,
        "grep -r 'dnssec-enable\\|dnssec-validation' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        dnssec_found.append("BIND DNSSEC validation")

    # Check for DNSSEC keys
    ret, out, err = _run(
        ssh,
        "find /etc/bind /etc/named -name '*.key' -o -name '*.private' 2>/dev/null | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        dnssec_found.append("DNSSEC signing keys")

    # Check unbound DNSSEC
    ret, out, err = _run(
        ssh,
        "grep -r 'auto-trust-anchor-file\\|trust-anchor-file' /etc/unbound 2>/dev/null | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        dnssec_found.append("Unbound DNSSEC validation")

    if not dnssec_found:
        return _warn(
            "DNSSEC Configuration",
            "DNSSEC not configured",
            "Enable DNSSEC validation: set dnssec-validation to auto in named.conf",
            category,
            test_id,
        )

    return _pass(
        "DNSSEC Configuration",
        f"DNSSEC configured: {', '.join(dnssec_found)}",
        "Regularly update DNSSEC trust anchors and monitor key rollovers",
        category,
        test_id,
    )


def check_zone_transfer_restrictions(
    ssh: SSHSession, password: str = ""
) -> CheckResult:
    """Check if zone transfers are properly restricted.

    Test ID: DNS-4002
    Category: DNS

    Verifies allow-transfer and also-notify ACLs to prevent unauthorized AXFR.
    """
    category = "DNS"
    test_id = "DNS-4002"

    restrictions = []
    issues = []

    # Check BIND allow-transfer restrictions
    ret, out, err = _run(
        ssh,
        "grep -r 'allow-transfer' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        restrictions.append("BIND allow-transfer ACL")
    else:
        issues.append("BIND missing allow-transfer restrictions")

    # Check for wildcard allow-transfer (security issue)
    ret, out, err = _run(
        ssh,
        "grep -r 'allow-transfer.*{.*any.*}' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        issues.append("BIND allows transfers to 'any'")

    # Check dnsmasq (doesn't support AXFR by default)
    ret, out, err = _run(ssh, "pgrep dnsmasq")
    if ret == 0:
        restrictions.append("dnsmasq (no AXFR support)")

    if issues:
        return _fail(
            "Zone Transfer Restrictions",
            f"Security issues: {'; '.join(issues)}",
            "Restrict zone transfers: allow-transfer { trusted-servers; };",
            category,
            test_id,
        )

    if not restrictions:
        return _pass(
            "Zone Transfer Restrictions",
            "No DNS server running or zone transfers N/A",
            "Zone transfer restrictions not applicable",
            category,
            test_id,
        )

    return _pass(
        "Zone Transfer Restrictions",
        f"Zone transfers restricted: {', '.join(restrictions)}",
        "Audit trusted servers list and use TSIG for zone transfers",
        category,
        test_id,
    )


def check_tsig_authentication(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for TSIG (Transaction Signature) authentication.

    Test ID: DNS-4003
    Category: DNS

    Verifies TSIG keys are configured for secure zone transfers and updates.
    """
    category = "DNS"
    test_id = "DNS-4003"

    tsig_found = []

    # Check for TSIG key definitions
    ret, out, err = _run(
        ssh,
        "grep -r '^[[:space:]]*key[[:space:]]' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        tsig_found.append(f"{out.strip()} TSIG keys defined")

    # Check for TSIG key files
    ret, out, err = _run(
        ssh, "find /etc/bind /etc/named -name '*.key' 2>/dev/null | wc -l"
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        key_count = out.strip()
        tsig_found.append(f"{key_count} key files")

    # Check server declarations with keys
    ret, out, err = _run(
        ssh,
        "grep -r 'server.*{' /etc/bind /etc/named 2>/dev/null | grep 'keys' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        tsig_found.append("TSIG authentication enabled")

    if not tsig_found:
        return _warn(
            "TSIG Authentication",
            "No TSIG authentication configured",
            "Configure TSIG keys for secure zone transfers and dynamic updates",
            category,
            test_id,
        )

    return _pass(
        "TSIG Authentication",
        f"TSIG configured: {', '.join(tsig_found)}",
        "Rotate TSIG keys periodically and use strong algorithms (HMAC-SHA256)",
        category,
        test_id,
    )


def check_dns_service_configuration(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check DNS service configuration and security settings.

    Test ID: DNS-4004
    Category: DNS

    Verifies version hiding, recursion controls, rate limiting, and other hardening.
    """
    category = "DNS"
    test_id = "DNS-4004"

    security_features = []
    recommendations = []

    # Check version hiding
    ret, out, err = _run(
        ssh,
        "grep -r 'version[[:space:]]*\"' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        security_features.append("Version disclosure hidden")
    else:
        recommendations.append("Hide version in named.conf options")

    # Check recursion restrictions
    ret, out, err = _run(
        ssh,
        "grep -r 'allow-recursion' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        security_features.append("Recursion restricted")
    else:
        recommendations.append("Restrict recursion to trusted clients")

    # Check rate limiting
    ret, out, err = _run(
        ssh,
        "grep -r 'rate-limit' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        security_features.append("Rate limiting enabled")

    # Check query logging
    ret, out, err = _run(
        ssh,
        "grep -r 'querylog\\|query-log' /etc/bind /etc/named 2>/dev/null | grep -v '^#' | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        security_features.append("Query logging enabled")

    # Check if running as non-root
    ret, out, err = _run(
        ssh,
        "ps aux | grep -E 'named|dnsmasq|unbound' | grep -v root | grep -v grep | wc -l",
    )
    if ret == 0 and int(out.strip() or "0") > 0:
        security_features.append("Running as non-root user")
    else:
        recommendations.append("Run DNS server as non-root user")

    if not security_features and not recommendations:
        return _pass(
            "DNS Service Configuration",
            "No DNS server configuration found",
            "DNS service not running on this system",
            category,
            test_id,
        )

    if len(security_features) >= 3:
        return _pass(
            "DNS Service Configuration",
            f"Security features: {', '.join(security_features)}",
            "Continue monitoring and updating DNS configuration",
            category,
            test_id,
        )

    return _warn(
        "DNS Service Configuration",
        f"Found {len(security_features)} features: {', '.join(security_features) if security_features else 'none'}",
        f"Recommendations: {'; '.join(recommendations) if recommendations else 'Enable version hiding, recursion controls, and rate limiting'}",
        category,
        test_id,
    )


def run_all_dns_checks(ssh: SSHSession, password: str = "") -> list[CheckResult]:
    """Run all DNS security checks.

    Args:
        ssh: SSH session to target system
        password: SSH password if needed

    Returns:
        List of CheckResult objects
    """
    return [
        check_dns_server_installed(ssh, password),
        check_dnssec_configured(ssh, password),
        check_zone_transfer_restrictions(ssh, password),
        check_tsig_authentication(ssh, password),
        check_dns_service_configuration(ssh, password),
    ]
