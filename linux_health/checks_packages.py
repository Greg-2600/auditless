"""Extended Package Management Module for Linux Health Security Scanner.

This module implements advanced package management security checks for APT, YUM,
repository security, package signing, and vulnerability detection following
Lynis-compatible test patterns.

Test IDs: PKGS-7300 to PKGS-7305
Category: Package Management
"""

from __future__ import annotations

from typing import List

from .checks import CheckResult, _fail, _pass, _run, _warn
from .distro import get_distro
from .ssh_client import SSHSession
from .test_ids import CHECK_TEST_IDS


def check_yum_security_plugin(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if YUM security plugin is installed and enabled.

    Test ID: PKGS-7300 (Lynis equivalent: PKGS-7381)
    Category: Package Management

    Verifies that YUM/DNF has security update capabilities enabled for
    Red Hat based systems.
    """
    category = "Package Management"
    test_id = "PKGS-7300"

    # Non-RPM families skip the YUM/DNF probe (one os-release read,
    # shared with every other check via the _run cache).
    if get_distro(ssh).family not in ("rhel", "unknown"):
        return _pass(
            "YUM Security Plugin",
            "Not a YUM/DNF-based system",
            "No action required on non-RPM systems",
            category,
            test_id,
        )

    # Check if this is a YUM-based system
    ret, out, err = _run(ssh, "which yum dnf 2>/dev/null")

    if ret != 0 or not out:
        return _pass(
            "YUM Security Plugin",
            "Not a YUM/DNF-based system",
            "No action required for Debian-based systems",
            category,
            test_id,
        )

    pkg_manager = "dnf" if "dnf" in out else "yum"

    # Check for security plugin/capability
    ret, out, err = _run(
        ssh,
        f"{pkg_manager} list installed | grep -i 'yum-plugin-security\\|dnf-plugin-security' 2>/dev/null",
    )

    # DNF has built-in security features, check for updateinfo
    if "dnf" in pkg_manager:
        ret, out, err = _run(ssh, "dnf updateinfo list security 2>&1 | head -5")

        if ret == 0 and (
            "sec" in out.lower()
            or "security" in out.lower()
            or "updates" in out.lower()
        ):
            return _pass(
                "YUM Security Plugin",
                "DNF security features are functional",
                "Run 'dnf updateinfo list security' to view available security updates",
                category,
                test_id,
            )
        else:
            return _warn(
                "YUM Security Plugin",
                "DNF installed but security features unclear",
                "Verify: dnf updateinfo list security",
                category,
                test_id,
            )

    # For YUM, check plugin
    if "yum-plugin-security" in out or "yum-security" in out:
        return _pass(
            "YUM Security Plugin",
            "YUM security plugin is installed",
            "Use 'yum list-security' to view security updates",
            category,
            test_id,
        )
    else:
        return _fail(
            "YUM Security Plugin",
            "YUM security plugin not installed",
            "Install: yum install yum-plugin-security",
            category,
            test_id,
        )


def check_apt_security_updates(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if APT has security update sources configured.

    Test ID: PKGS-7301 (Lynis equivalent: PKGS-7388)
    Category: Package Management

    Verifies that Debian/Ubuntu systems have security update repositories
    properly configured in sources.list.
    """
    category = "Package Management"
    test_id = "PKGS-7301"

    # Non-DEB families skip the APT probe (one os-release read, shared
    # with every other check via the _run cache).
    if get_distro(ssh).family not in ("debian", "unknown"):
        return _pass(
            "APT Security Updates",
            "Not an APT-based system",
            "No action required on non-DEB systems",
            category,
            test_id,
        )

    # Check if this is an APT-based system
    ret, out, err = _run(ssh, "which apt-get apt 2>/dev/null")

    if ret != 0 or not out:
        return _pass(
            "APT Security Updates",
            "Not an APT-based system",
            "No action required for RPM-based systems",
            category,
            test_id,
        )

    # Check for security repository in sources.list
    ret, out, err = _run(
        ssh,
        "grep -r 'security' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -v '^#' | head -5",
    )

    if not out:
        return _fail(
            "APT Security Updates",
            "No security update sources configured",
            "Add security repository to /etc/apt/sources.list: deb http://security.debian.org/ stable/updates main",
            category,
            test_id,
        )

    # Count security sources
    security_sources = len([line for line in out.split("\n") if line.strip()])

    # Check if sources are enabled (not commented)
    if security_sources >= 1:
        return _pass(
            "APT Security Updates",
            f"Security update sources configured ({security_sources} entries)",
            "Run 'apt-get update && apt-get upgrade' regularly",
            category,
            test_id,
        )
    else:
        return _warn(
            "APT Security Updates",
            "Security sources may be commented out",
            "Enable security repositories in /etc/apt/sources.list",
            category,
            test_id,
        )


def check_repository_gpg_keys(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if package repository GPG keys are configured.

    Test ID: PKGS-7302 (Lynis equivalent: PKGS-7345)
    Category: Package Management

    Verifies that package manager uses GPG key verification to ensure
    package authenticity and prevent tampering.
    """
    category = "Package Management"
    test_id = "PKGS-7302"

    # Check which package manager is in use
    ret, out, err = _run(ssh, "which apt-get yum dnf 2>/dev/null")

    if not out:
        return _warn(
            "Repository GPG Keys",
            "No supported package manager detected",
            "Manually verify package signature configuration",
            category,
            test_id,
        )

    keys_found = 0

    # Check APT keys
    if "apt-get" in out:
        ret, out, err = _run(ssh, "apt-key list 2>/dev/null | grep -c 'pub' || echo 0")
        try:
            keys_found += int(out.strip())
        except ValueError:
            pass

        # Also check modern method
        ret, out, err = _run(ssh, "ls -1 /etc/apt/trusted.gpg.d/ 2>/dev/null | wc -l")
        try:
            keys_found += int(out.strip())
        except ValueError:
            pass

    # Check RPM keys
    if "yum" in out or "dnf" in out:
        ret, out, err = _run(ssh, "rpm -q gpg-pubkey 2>/dev/null | wc -l")
        try:
            keys_found += int(out.strip())
        except ValueError:
            pass

    if keys_found >= 1:
        return _pass(
            "Repository GPG Keys",
            f"Repository GPG keys configured ({keys_found} keys)",
            "Regularly update repository keys",
            category,
            test_id,
        )
    else:
        return _fail(
            "Repository GPG Keys",
            "No repository GPG keys found",
            "Import distribution GPG keys: apt-key add OR rpm --import",
            category,
            test_id,
        )


def check_package_signing_enabled(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if package signature verification is enabled.

    Test ID: PKGS-7303 (Lynis equivalent: PKGS-7346)
    Category: Package Management

    Ensures that package managers are configured to verify package signatures
    before installation to prevent malicious package injection.
    """
    category = "Package Management"
    test_id = "PKGS-7303"

    # Check which package manager
    ret, out, err = _run(ssh, "which apt-get yum dnf 2>/dev/null")

    if not out:
        return _warn(
            "Package Signing",
            "No supported package manager detected",
            "Manually verify signature checking is enabled",
            category,
            test_id,
        )

    issues = []

    # Check APT configuration
    if "apt-get" in out:
        ret, out, err = _run(
            ssh,
            "apt-config dump | grep -i 'APT::Get::AllowUnauthenticated' 2>/dev/null",
        )

        if "true" in out.lower():
            issues.append("APT allows unauthenticated packages")

    # Check YUM/DNF configuration
    if "yum" in out or "dnf" in out:
        ret, out, err = _run(
            ssh,
            "grep -i 'gpgcheck' /etc/yum.conf /etc/dnf/dnf.conf 2>/dev/null | grep -v '^#'",
        )

        if "gpgcheck=0" in out:
            issues.append("YUM/DNF GPG checking is disabled")
        elif "gpgcheck=1" in out:
            pass  # Good!
        else:
            issues.append("YUM/DNF GPG check configuration not found")

    if issues:
        return _fail(
            "Package Signing",
            f"Package signature verification issues: {', '.join(issues)}",
            "Enable gpgcheck=1 in /etc/yum.conf or disable AllowUnauthenticated in APT",
            category,
            test_id,
        )
    else:
        return _pass(
            "Package Signing",
            "Package signature verification is enabled",
            "Maintain strict signature checking policy",
            category,
            test_id,
        )


def check_vulnerable_packages(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for known vulnerable package versions.

    Test ID: PKGS-7304 (Lynis equivalent: PKGS-7392)
    Category: Package Management

    Identifies installed packages with known security vulnerabilities using
    distribution-specific security advisories.
    """
    category = "Package Management"
    test_id = "PKGS-7304"

    # Determine package manager
    ret, out, err = _run(ssh, "which apt dnf yum 2>/dev/null | head -1")

    if not out:
        return _warn(
            "Vulnerable Packages",
            "Cannot determine package manager",
            "Manually check for security updates",
            category,
            test_id,
        )

    pkg_manager = out.strip().split("/")[-1]

    # Check for security updates
    if pkg_manager in ["apt", "apt-get"]:
        # Refresh cache first (quick)
        ret, out, err = _run(
            ssh,
            "sudo -S apt-get update -qq 2>&1 | grep -c 'error\\|fail' || echo 0",
            password=password,
            command_timeout=10.0,
        )

        # Check for upgradeable packages
        ret, out, err = _run(
            ssh,
            "apt list --upgradable 2>/dev/null | grep -i 'security' | wc -l || echo 0",
        )

        try:
            vuln_count = int(out.strip())
        except ValueError:
            vuln_count = 0

    elif pkg_manager in ["dnf", "yum"]:
        # Check for security updates
        ret, out, err = _run(
            ssh,
            f"sudo -S {pkg_manager} updateinfo list security 2>/dev/null | grep -c 'security' || echo 0",
            password=password,
            command_timeout=10.0,
        )

        try:
            vuln_count = int(out.strip())
        except ValueError:
            vuln_count = 0
    else:
        return _warn(
            "Vulnerable Packages",
            f"Unsupported package manager: {pkg_manager}",
            "Manually check for security updates",
            category,
            test_id,
        )

    if vuln_count == 0:
        return _pass(
            "Vulnerable Packages",
            "No security updates available",
            "Continue regular update checks",
            category,
            test_id,
        )
    elif vuln_count <= 5:
        return _warn(
            "Vulnerable Packages",
            f"{vuln_count} security updates available",
            f"Apply updates: sudo {pkg_manager} upgrade",
            category,
            test_id,
        )
    else:
        return _fail(
            "Vulnerable Packages",
            f"{vuln_count} security updates pending",
            f"Urgent: Apply security updates immediately with sudo {pkg_manager} upgrade",
            category,
            test_id,
        )


def check_package_audit_log(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if package management operations are logged.

    Test ID: PKGS-7305 (Lynis equivalent: PKGS-7398)
    Category: Package Management

    Verifies that package installation, removal, and update operations are
    logged for audit trail and forensics.
    """
    category = "Package Management"
    test_id = "PKGS-7305"

    # Check for package manager logs
    logs_found = []

    # APT logs
    ret, out, err = _run(ssh, "test -f /var/log/apt/history.log && echo apt_history")
    if "apt_history" in out:
        logs_found.append("APT history")

    ret, out, err = _run(ssh, "test -f /var/log/dpkg.log && echo dpkg_log")
    if "dpkg_log" in out:
        logs_found.append("dpkg log")

    # YUM/DNF logs
    ret, out, err = _run(ssh, "test -f /var/log/yum.log && echo yum_log")
    if "yum_log" in out:
        logs_found.append("YUM log")

    ret, out, err = _run(ssh, "test -f /var/log/dnf.log && echo dnf_log")
    if "dnf_log" in out:
        logs_found.append("DNF log")

    if not logs_found:
        return _warn(
            "Package Audit Log",
            "No package manager log files found",
            "Verify package manager logging is enabled",
            category,
            test_id,
        )

    # Check if logs have recent entries (within last 30 days)
    ret, out, err = _run(
        ssh,
        "find /var/log -name 'apt/history.log' -o -name 'dpkg.log' -o -name 'yum.log' -o -name 'dnf.log' -mtime -30 2>/dev/null | wc -l",
    )

    try:
        recent_logs = int(out.strip())
    except ValueError:
        recent_logs = 0

    if recent_logs >= 1:
        return _pass(
            "Package Audit Log",
            f"Package management logging active: {', '.join(logs_found)}",
            "Regularly review package change logs",
            category,
            test_id,
        )
    else:
        return _warn(
            "Package Audit Log",
            f"Package logs found but may be stale: {', '.join(logs_found)}",
            "Verify package manager is actively logging changes",
            category,
            test_id,
        )


def run_all_package_management_checks(
    ssh: SSHSession, password: str = ""
) -> List[CheckResult]:
    """Run all extended package management security checks.

    Returns:
        List of CheckResult objects for all package management checks.
    """
    checks = [
        check_yum_security_plugin,
        check_apt_security_updates,
        check_repository_gpg_keys,
        check_package_signing_enabled,
        check_vulnerable_packages,
        check_package_audit_log,
    ]

    results = []
    for check in checks:
        try:
            result = check(ssh, password)
            results.append(result)
        except Exception as e:
            # Create a failure result if check crashes
            results.append(
                CheckResult(
                    category="Package Management",
                    item=check.__name__.replace("check_", "").replace("_", " ").title(),
                    status="unknown",
                    details=f"Check failed with error (not assessed): {str(e)}",
                    recommendation="Review check implementation and SSH connection",
                    test_id=CHECK_TEST_IDS.get(check.__name__, "PKGS-XXXX"),
                )
            )

    return results
