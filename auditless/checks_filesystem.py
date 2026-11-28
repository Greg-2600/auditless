"""Filesystem & NFS Security Module for Auditless Security Scanner.

This module implements filesystem security checks for NFS exports, mount options,
partition security, and filesystem integrity monitoring following Lynis-compatible
test patterns.

Test IDs: NFS-3000 to NFS-3005, FS-3010 to FS-3015, FILE-7525
Category: Filesystem, Storage
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .checks import CheckResult, _fail, _pass, _run, _unknown, _warn
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


_PRIVILEGED_FILE_PROBE = r"""command -v dpkg-query >/dev/null 2>&1 && tool=dpkg || tool=none
command -v rpm >/dev/null 2>&1 && [ "$tool" = none ] && tool=rpm
printf 'tool:%s\n' "$tool"
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /etc -xdev \
  -type f \( -perm -002 -o -perm -4000 -o -perm -2000 \) \
  -printf '%p\t%m\t%u\t%g\n' 2>/dev/null | head -n 200 | \
while IFS="$(printf '\t')" read -r path mode owner group; do
  pkg='-'
  if [ "$tool" = dpkg ]; then
    pkg=$(dpkg-query -S "$path" 2>/dev/null | head -n 1 | cut -d: -f1)
  elif [ "$tool" = rpm ]; then
    pkg=$(rpm -qf --qf '%{NAME}\n' "$path" 2>/dev/null | head -n 1)
  fi
  [ -n "$pkg" ] || pkg='-'
  printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$mode" "$owner" "$group" "$pkg"
done
"""


@dataclass(frozen=True)
class _PrivilegedFile:
    """One candidate emitted by the read-only permission probe."""

    path: str
    mode: int
    owner: str
    group: str
    package: str

    @property
    def world_writable(self) -> bool:
        """Whether anyone can write the file."""
        return bool(self.mode & 0o002)

    @property
    def privileged(self) -> bool:
        """Whether the SUID or SGID bit is set."""
        return bool(self.mode & (0o4000 | 0o2000))

    @property
    def sticky(self) -> bool:
        """Whether the sticky bit is set on the file."""
        return bool(self.mode & 0o1000)

    @property
    def package_owned(self) -> bool:
        """Whether a package claims this path."""
        return self.package not in {"", "-"}


def _parse_privileged_probe(output: str) -> tuple[str, list[_PrivilegedFile]]:
    """Parse the package-tool marker and tab-separated candidate rows."""
    tool = ""
    files: list[_PrivilegedFile] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("tool:"):
            tool = line.split(":", 1)[1].strip()
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        path, mode_text, owner, group, package = parts
        if not path.startswith("/"):
            continue
        try:
            mode = int(mode_text, 8)
        except ValueError:
            continue
        files.append(
            _PrivilegedFile(path, mode, owner.strip(), group.strip(), package.strip())
        )
    return tool, files


def _triage_privileged_files(
    files: list[_PrivilegedFile],
) -> tuple[list[str], list[str], list[str]]:
    """Split candidates into unpackaged, packaged-writable, and allowlisted."""
    unpackaged: list[str] = []
    packaged_writable: list[str] = []
    allowlisted: list[str] = []
    for item in files:
        if item.world_writable and not item.sticky:
            kind = "world-writable"
        elif item.privileged:
            kind = "SUID/SGID"
        else:
            continue
        label = f"{item.path} ({kind} {item.mode:04o} {item.owner}:{item.group})"
        if not item.package_owned:
            unpackaged.append(label)
        elif kind == "world-writable":
            packaged_writable.append(f"{label} package {item.package}")
        else:
            allowlisted.append(f"{label} package {item.package}")
    return unpackaged, packaged_writable, allowlisted


def check_privileged_writable_triage(
    ssh: SSHSession, _password: str = ""
) -> CheckResult:
    """Triage world-writable and SUID/SGID files against package ownership.

    Test ID: FILE-7525
    Category: File Permissions

    One bounded read-only probe collects world-writable and SUID/SGID files
    in system paths together with the owning package (dpkg-query or rpm -qf).
    Package-owned SUID/SGID binaries are expected and allowlisted; an
    unpackaged privileged or world-writable file is a finding because no
    package justifies its presence. Packaged files that became world-writable
    warn as permission drift. Without a package database the allowlist cannot
    be applied, so the result is unknown rather than a false pass.
    """
    category = "File Permissions"
    test_id = "FILE-7525"
    try:
        code, out, err = _run(ssh, _PRIVILEGED_FILE_PROBE)
        if code != 0 and not out.strip():
            return _unknown(
                "Privileged/Writable File Triage",
                f"Unable to probe file permissions: {err.strip() or out.strip()}",
                "Verify SSH connectivity and permission to inspect system files",
                category,
                test_id,
            )

        package_tool, files = _parse_privileged_probe(out)
        if package_tool not in {"dpkg", "rpm"}:
            return _unknown(
                "Privileged/Writable File Triage",
                "No dpkg-query or rpm available; package-owned allowlist cannot be applied",
                "Install a package manager or review privileged files manually",
                category,
                test_id,
            )

        unpackaged, packaged_writable, allowlisted = _triage_privileged_files(files)
        item_name = "Privileged/Writable File Triage"
        if unpackaged:
            details = "Unpackaged privileged/writable file(s): " + "; ".join(
                unpackaged[:5]
            )
            if len(unpackaged) > 5:
                details += f" (+{len(unpackaged) - 5} more)"
            if allowlisted:
                details += (
                    f"; {len(allowlisted)} package-owned SUID/SGID binaries allowlisted"
                )
            return _fail(
                item_name,
                details,
                "Investigate unpackaged privileged/writable files: confirm provenance, "
                "remove setuid/setgid (chmod u-s,g-s) or world write (chmod o-w), "
                "and reinstall from a trusted package",
                category,
                test_id,
            )

        if packaged_writable:
            details = "Package-owned world-writable file(s): " + "; ".join(
                packaged_writable[:5]
            )
            return _warn(
                item_name,
                details,
                "Restore packaged permissions (dpkg --verify or rpm -V) and remove "
                "world write with chmod o-w",
                category,
                test_id,
            )

        if allowlisted:
            details = (
                f"{len(allowlisted)} package-owned SUID/SGID binary(ies) allowlisted: "
                + "; ".join(allowlisted[:3])
            )
            if len(allowlisted) > 3:
                details += f" (+{len(allowlisted) - 3} more)"
            details += "; no unpackaged privileged or world-writable files"
            return _pass(
                item_name,
                details,
                "Keep package-owned SUID/SGID binaries tracked by the package manager",
                category,
                test_id,
            )

        return _pass(
            item_name,
            "No world-writable or SUID/SGID files in system paths",
            "Continue periodic permission reviews",
            category,
            test_id,
        )
    except Exception as e:
        return _unknown(
            "Privileged/Writable File Triage",
            f"Error triaging privileged/writable files: {str(e)}",
            "Verify SSH connectivity and permissions",
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
        check_privileged_writable_triage,
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
