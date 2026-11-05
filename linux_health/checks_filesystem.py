"""Filesystem & NFS Security Module for Linux Health Security Scanner.

This module implements filesystem security checks for NFS exports, mount options,
partition security, and filesystem integrity monitoring following Lynis-compatible
test patterns.

Test IDs: NFS-3000 to NFS-3005, FS-3010 to FS-3015
Category: Filesystem, Storage
"""

from __future__ import annotations

from typing import List

from .checks import CheckResult, _fail, _pass, _run, _warn
from .ssh_client import SSHSession
from .test_ids import CHECK_TEST_IDS


def check_nfs_exports_security(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check NFS exports for security issues.

    Test ID: NFS-3000 (Lynis equivalent: NFS-3000)
    Category: Filesystem

    Examines /etc/exports for insecure NFS export configurations including
    world-readable shares and missing security options.
    """
    category = "Filesystem"
    test_id = "NFS-3000"

    # Check if NFS server is installed
    ret, out, err = _run(ssh, "which nfsd exportfs rpc.nfsd 2>/dev/null")

    if ret != 0 or not out:
        return _pass(
            "NFS Exports Security",
            "NFS server not installed",
            "No action required if NFS not needed",
            category,
            test_id,
        )

    # Check for /etc/exports file
    ret, out, err = _run(ssh, "test -f /etc/exports && echo exists || echo missing")

    if "missing" in out:
        return _pass(
            "NFS Exports Security",
            "NFS installed but no exports configured",
            "Configure exports securely if NFS sharing needed",
            category,
            test_id,
        )

    # Check exports for security issues
    ret, out, err = _run(
        ssh,
        "sudo -S grep -v '^#' /etc/exports 2>/dev/null | grep -v '^$'",
        password=password,
    )

    if not out:
        return _pass(
            "NFS Exports Security",
            "No active NFS exports found",
            "Review /etc/exports if shares expected",
            category,
            test_id,
        )

    issues = []

    # Check for world-readable exports (*)
    if "*" in out or "0.0.0.0" in out:
        issues.append("World-readable exports detected")

    # Check for rw without root_squash protection
    if "rw" in out and "no_root_squash" in out:
        issues.append("Read-write exports with no_root_squash (dangerous)")

    # Check for missing sync option
    if "async" in out:
        issues.append("Async exports (data integrity risk)")

    # Check for insecure options
    if "no_subtree_check" not in out and "subtree_check" not in out:
        issues.append("Missing subtree_check option")

    if issues:
        return _warn(
            "NFS Exports Security",
            f"Found {len(issues)} NFS security issues: {', '.join(issues[:2])}",
            "Review /etc/exports: use host restrictions, root_squash, sync, sec=krb5",
            category,
            test_id,
        )
    else:
        return _pass(
            "NFS Exports Security",
            "NFS exports configured with security options",
            "Continue monitoring NFS access patterns",
            category,
            test_id,
        )


def check_mount_options_security(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check filesystem mount options for security hardening.

    Test ID: FS-3010 (Lynis equivalent: FILE-6310)
    Category: Storage

    Validates that filesystems are mounted with appropriate security options
    like nodev, nosuid, noexec where applicable.
    """
    category = "Storage"
    test_id = "FS-3010"

    # Get current mount points
    ret, out, err = _run(ssh, "mount | grep -E '(ext|xfs|btrfs)' 2>/dev/null")

    if not out:
        return _warn(
            "Mount Options Security",
            "No standard filesystems detected",
            "Verify system mount configuration",
            category,
            test_id,
        )

    issues = []
    mounts = out.strip().split("\n")

    # Check /tmp for noexec, nodev, nosuid
    tmp_mounts = [m for m in mounts if " /tmp " in m or " on /tmp " in m]
    if tmp_mounts:
        tmp_mount = tmp_mounts[0]
        if "noexec" not in tmp_mount:
            issues.append("/tmp mounted without noexec")
        if "nodev" not in tmp_mount:
            issues.append("/tmp mounted without nodev")
        if "nosuid" not in tmp_mount:
            issues.append("/tmp mounted without nosuid")

    # Check /var/tmp for similar options
    vartmp_mounts = [m for m in mounts if " /var/tmp " in m or " on /var/tmp " in m]
    if vartmp_mounts:
        vartmp_mount = vartmp_mounts[0]
        if "noexec" not in vartmp_mount:
            issues.append("/var/tmp mounted without noexec")

    # Check /home for nosuid
    home_mounts = [m for m in mounts if " /home " in m or " on /home " in m]
    if home_mounts:
        home_mount = home_mounts[0]
        if "nosuid" not in home_mount:
            issues.append("/home mounted without nosuid")

    if len(issues) >= 3:
        return _fail(
            "Mount Options Security",
            f"Multiple mount security issues: {', '.join(issues[:3])}",
            "Remount with secure options: mount -o remount,noexec,nodev,nosuid /tmp",
            category,
            test_id,
        )
    elif issues:
        return _warn(
            "Mount Options Security",
            f"Found {len(issues)} mount option issues: {', '.join(issues[:2])}",
            "Add security options to /etc/fstab and remount",
            category,
            test_id,
        )
    else:
        return _pass(
            "Mount Options Security",
            "Filesystems mounted with appropriate security options",
            "Continue monitoring mount configurations",
            category,
            test_id,
        )


def check_tmp_noexec(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if /tmp is mounted with noexec option.

    Test ID: FS-3011 (Lynis equivalent: FILE-6311)
    Category: Storage

    Verifies that /tmp prevents execution of binaries, mitigating common
    attack vectors that rely on /tmp for malicious code execution.
    """
    category = "Storage"
    test_id = "FS-3011"

    # Check /tmp mount options
    ret, out, err = _run(ssh, "mount | grep ' /tmp ' 2>/dev/null")

    if not out:
        # /tmp might not be a separate mount
        ret, out, err = _run(ssh, "mount | grep ' / ' 2>/dev/null")
        return _warn(
            "/tmp Noexec Protection",
            "/tmp is not a separate partition",
            "Consider mounting /tmp as separate partition with noexec,nodev,nosuid",
            category,
            test_id,
        )

    if "noexec" in out:
        return _pass(
            "/tmp Noexec Protection",
            "/tmp mounted with noexec option",
            "Verify applications still function correctly",
            category,
            test_id,
        )
    else:
        return _warn(
            "/tmp Noexec Protection",
            "/tmp allows code execution (missing noexec)",
            "Add noexec to /tmp in /etc/fstab: /tmp /tmp tmpfs defaults,noexec,nodev,nosuid 0 0",
            category,
            test_id,
        )


def check_home_nosuid(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if /home is mounted with nosuid option.

    Test ID: FS-3012 (Lynis equivalent: FILE-6312)
    Category: Storage

    Verifies that /home prevents SUID bit execution, reducing privilege
    escalation risks from user-controlled files.
    """
    category = "Storage"
    test_id = "FS-3012"

    # Check /home mount options
    ret, out, err = _run(ssh, "mount | grep ' /home ' 2>/dev/null")

    if not out:
        # /home might not be a separate mount
        return _warn(
            "/home Nosuid Protection",
            "/home is not a separate partition",
            "Consider mounting /home as separate partition with nosuid,nodev",
            category,
            test_id,
        )

    if "nosuid" in out:
        return _pass(
            "/home Nosuid Protection",
            "/home mounted with nosuid option",
            "SUID executables in user directories are disabled",
            category,
            test_id,
        )

    return _warn(
        "/home Nosuid Protection",
        "/home allows SUID executables (missing nosuid)",
        "Add nosuid to /home in /etc/fstab for improved security",
        category,
        test_id,
    )


def check_var_permissions(ssh: SSHSession, _password: str = "") -> CheckResult:
    """Check /var directory permissions and ownership.

    Test ID: FS-3013 (Lynis equivalent: FILE-6362)
    Category: Storage

    Validates that /var and critical subdirectories have secure permissions
    to prevent unauthorized access to logs, temporary files, and cache.
    """
    category = "Storage"
    test_id = "FS-3013"

    # Check /var permissions
    _, out, _ = _run(
        ssh, "ls -ld /var /var/log /var/tmp /var/cache 2>/dev/null | head -5"
    )

    if not out:
        return _warn(
            "/var Permissions",
            "Could not verify /var permissions",
            "Manually check: ls -ld /var",
            category,
            test_id,
        )

    issues = []
    lines = out.strip().split("\n")

    for line in lines:
        parts = line.split()
        if len(parts) >= 9:
            perms = parts[0]
            path = parts[-1]

            # Check for world-writable without sticky bit
            if perms[8] == "w" and perms[9] != "t":
                issues.append(f"{path} is world-writable without sticky bit")

            # Check for group-writable /var
            if path == "/var" and perms[5] == "w":
                issues.append("/var is group-writable")

            # Check for world-writable on /var/log
            if "/log" in path and perms[8] == "w":
                issues.append(f"{path} is world-writable")

    if issues:
        return _warn(
            "/var Permissions",
            f"Found {len(issues)} /var permission issues: {', '.join(issues[:2])}",
            "Fix permissions: chmod 755 /var; chmod 755 /var/log; chmod 1777 /var/tmp",
            category,
            test_id,
        )
    else:
        return _pass(
            "/var Permissions",
            "/var directory permissions are secure",
            "Continue monitoring filesystem permissions",
            category,
            test_id,
        )


def check_filesystem_integrity_tools(
    ssh: SSHSession, _password: str = ""
) -> CheckResult:
    """Check if filesystem integrity monitoring tools are installed.

    Test ID: FS-3014 (Lynis equivalent: FINT-4350)
    Category: Storage

    Verifies installation of tools like AIDE, Tripwire, or OSSEC for
    filesystem integrity monitoring and intrusion detection.
    """
    category = "Storage"
    test_id = "FS-3014"

    # Check for common integrity tools
    _, out, _ = _run(
        ssh,
        "which aide tripwire ossec-control samhain 2>/dev/null",
    )

    tools_found = []
    if out:
        tools_found = [tool.split("/")[-1] for tool in out.strip().split("\n")]

    if not tools_found:
        return _fail(
            "Filesystem Integrity Tools",
            "No filesystem integrity monitoring tools detected",
            "Install AIDE: apt-get install aide OR yum install aide",
            category,
            test_id,
        )

    # Check if AIDE database exists (most common tool)
    if "aide" in tools_found:
        _, out, _ = _run(
            ssh, "test -f /var/lib/aide/aide.db && echo exists || echo missing"
        )

        if "exists" in out:
            return _pass(
                "Filesystem Integrity Tools",
                "AIDE installed with initialized database",
                "Schedule regular AIDE checks via cron",
                category,
                test_id,
            )
        else:
            return _warn(
                "Filesystem Integrity Tools",
                "AIDE installed but database not initialized",
                "Initialize AIDE: aideinit OR aide --init",
                category,
                test_id,
            )

    # Other tools found
    return _pass(
        "Filesystem Integrity Tools",
        f"Integrity tools installed: {', '.join(tools_found)}",
        "Ensure tools are configured and scheduled",
        category,
        test_id,
    )


def run_all_filesystem_checks(ssh: SSHSession, password: str = "") -> List[CheckResult]:
    """Run all filesystem and NFS security checks.

    Returns:
        List of CheckResult objects for all filesystem security checks.
    """
    checks = [
        check_nfs_exports_security,
        check_mount_options_security,
        check_tmp_noexec,
        check_home_nosuid,
        check_var_permissions,
        check_filesystem_integrity_tools,
    ]

    results = []
    for check in checks:
        try:
            result = check(ssh, password)
            results.append(result)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # Create a failure result if check crashes
            results.append(
                CheckResult(
                    category="Filesystem" if "nfs" in check.__name__ else "Storage",
                    item=check.__name__.replace("check_", "").replace("_", " ").title(),
                    status="unknown",
                    details=f"Check failed with error (not assessed): {str(e)}",
                    recommendation="Review check implementation and SSH connection",
                    test_id=CHECK_TEST_IDS.get(check.__name__, "FS-XXXX"),
                )
            )

    return results
