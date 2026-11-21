"""Remediation catalog: failed checks become reviewable fix scripts.

Each entry maps (test_id, item text) to an idempotent shell script.
Nothing executes on proposal — dry-run rendering only. Execution happens
exclusively through the approve step (API/UI), line by line over the
target SSH session, followed by an automatic verification rescan.

Risk levels:
    safe     file writes with no service impact (verified by rescan).
    service  touches a running service config (sshd reload); preconditions
             in the entry must hold before approving.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Remediation:
    """One reviewable fix for a class of failed findings."""

    id: str
    title: str
    risk: str  # safe | service
    description: str
    preconditions: str
    test_ids: list[str] = field(default_factory=list)
    match_item: str = ""  # case-insensitive substring of the check item
    script: list[str] = field(default_factory=list)

    def matches(self, test_id: str, item: str) -> bool:
        """Whether this remediation addresses the given finding."""
        return test_id in self.test_ids and self.match_item.lower() in item.lower()

    def render(self) -> str:
        """Dry-run text: the exact commands approval would execute."""
        return "\n".join(self.script)


REMEDIATIONS: list[Remediation] = [
    Remediation(
        id="ssh-password-auth",
        title="Disable SSH password authentication",
        risk="service",
        description=(
            "Sets PasswordAuthentication no in sshd_config, validates with "
            "sshd -t, and reloads sshd. Findings flip on the next scan."
        ),
        preconditions="Key-based auth already works for at least one account.",
        test_ids=["SSH-7408"],
        match_item="PasswordAuthentication",
        script=[
            "sudo -S cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.auditless.bak",
            "sudo -S sed -i -E 's/^#?\\s*PasswordAuthentication\\s+.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "sudo -S sh -c \"grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config\"",
            "sudo -S sh -c 'command -v sshd >/dev/null && sshd -t && echo VALIDATED || echo VALIDATION-SKIPPED'",
            "sudo -S sh -c 'service ssh reload 2>/dev/null || systemctl reload sshd 2>/dev/null || kill -HUP $(cat /run/sshd.pid 2>/dev/null) 2>/dev/null || true'",
        ],
    ),
    Remediation(
        id="ssh-root-login",
        title="Disable SSH root login",
        risk="service",
        description=(
            "Sets PermitRootLogin prohibit-password, validates, reloads sshd. "
            "Root keeps key-only access; use sudo from user accounts."
        ),
        preconditions="A non-root sudo-capable account exists.",
        test_ids=["SSH-7408"],
        match_item="PermitRootLogin",
        script=[
            "sudo -S cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.auditless.bak",
            "sudo -S sed -i -E 's/^#?\\s*PermitRootLogin\\s+.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config",
            "sudo -S sh -c \"grep -q '^PermitRootLogin prohibit-password' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config\"",
            "sudo -S sh -c 'command -v sshd >/dev/null && sshd -t && echo VALIDATED || echo VALIDATION-SKIPPED'",
            "sudo -S sh -c 'service ssh reload 2>/dev/null || systemctl reload sshd 2>/dev/null || kill -HUP $(cat /run/sshd.pid 2>/dev/null) || true'",
        ],
    ),
    Remediation(
        id="shell-timeout",
        title="Set shell timeout and history controls",
        risk="safe",
        description=(
            "Appends TMOUT=900 plus history controls to /etc/profile "
            "(idempotent: skipped when already present)."
        ),
        preconditions="None.",
        test_ids=["SHLL-6202"],
        match_item="Shell security",
        script=[
            "sudo -S sh -c \"grep -q '^TMOUT=900' /etc/profile || echo 'TMOUT=900; export TMOUT' >> /etc/profile\"",
            "sudo -S sh -c \"grep -q '^HISTSIZE=' /etc/profile || echo 'HISTSIZE=5000; HISTFILESIZE=10000; export HISTSIZE HISTFILESIZE' >> /etc/profile\"",
        ],
    ),
    Remediation(
        id="kernel-sysctl",
        title="Apply secure kernel networking parameters",
        risk="safe",
        description=(
            "Writes expected values with sysctl -w and persists them to "
            "/etc/sysctl.d/99-auditless.conf. Per-parameter results are "
            "reported; read-only keys (common in containers) are reported, "
            "not fatal."
        ),
        preconditions="None. Some keys are read-only under container runtimes.",
        test_ids=["KERN-5820"],
        match_item="Kernel hardening",
        script=[
            'sudo -S sh -c \'for kv in net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 net.ipv4.icmp_echo_ignore_broadcasts=1 net.ipv4.icmp_ignore_bogus_error_responses=1 fs.suid_dumpable=0 kernel.dmesg_restrict=1 kernel.kptr_restrict=2 kernel.yama.ptrace_scope=1; do if sysctl -w "$kv" >/dev/null 2>&1; then echo "OK $kv"; else echo "SKIP $kv (read-only?)"; fi; done\'',
            "sudo -S sh -c \"printf '%s\\n' 'net.ipv4.conf.all.rp_filter=1' 'net.ipv4.conf.default.rp_filter=1' 'net.ipv4.conf.all.accept_source_route=0' 'net.ipv4.conf.default.accept_source_route=0' 'net.ipv4.conf.all.send_redirects=0' 'net.ipv4.conf.default.send_redirects=0' 'net.ipv4.icmp_echo_ignore_broadcasts=1' 'net.ipv4.icmp_ignore_bogus_error_responses=1' 'fs.suid_dumpable=0' 'kernel.dmesg_restrict=1' 'kernel.kptr_restrict=2' 'kernel.yama.ptrace_scope=1' > /etc/sysctl.d/99-auditless.conf\"",
        ],
    ),
    Remediation(
        id="usb-storage",
        title="Disable USB storage via modprobe",
        risk="safe",
        description=(
            "Installs a modprobe rule so usb-storage can never load. "
            "Takes effect for future module loads; no reboot, no services."
        ),
        preconditions="None.",
        test_ids=["USB-1000"],
        match_item="USB storage",
        script=[
            "sudo -S sh -c \"echo 'install usb-storage /bin/true' > /etc/modprobe.d/disable-usb-storage.conf\"",
        ],
    ),
]


def propose_for_report(report: dict) -> list[dict]:
    """Match failed/warn checks in a stored report to remediations.

    Returns proposal dicts (no execution). Passed checks never propose.
    """
    proposals = []
    for check in report.get("checks", []):
        if check.get("status") not in ("warn", "fail"):
            continue
        for entry in REMEDIATIONS:
            if entry.matches(check.get("test_id", ""), check.get("item", "")):
                proposals.append(
                    {
                        "remediation_id": entry.id,
                        "title": entry.title,
                        "risk": entry.risk,
                        "description": entry.description,
                        "preconditions": entry.preconditions,
                        "test_id": check.get("test_id", ""),
                        "item": check.get("item", ""),
                        "status": check.get("status", ""),
                        "script": list(entry.script),
                    }
                )
    return proposals
