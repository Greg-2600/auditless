"""CIS Benchmark mapping and compliance scoring (best effort).

Maps auditless test IDs to controls in the CIS Ubuntu Linux 22.04 LTS
Benchmark v2.0.0. Mappings carry a level (direct = the check validates
the control, partial = adjacent coverage); checks with no corresponding
control land in the "extended" bucket and neither help nor hurt the
compliance score. Coverage is always reported alongside the score so
the number cannot mislead.
"""

from __future__ import annotations

BENCHMARK = "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0"

# Registry IDs with no corresponding CIS control (documented, not silent).
UNMAPPED_REASONS: dict[str, str] = {
    "STOR-6310": "capacity management has no CIS control",
    "MEM-2914": "resource health has no CIS control",
    "CPU-1620": "resource health has no CIS control",
    "KERN-5830": "reboot hygiene has no CIS control",
    "PROC-3612": "resource health has no CIS control",
    "PKGS-7380": "pending-update review has no CIS control",
    "AUTH-9234": "UID-0 enumeration has no direct CIS control",
    "NETW-3032": "anomaly detection has no CIS control",
    "MALW-3280": "malware detection is beyond CIS OS scope",
    "MALW-3288": "malware detection is beyond CIS OS scope",
    "MALW-3292": "malware detection is beyond CIS OS scope",
    "AUTH-9340": "account monitoring has no CIS control",
    "FILE-6374": "hidden-file review has no CIS control",
    "AUTH-9283": "exploit-vector review has no direct CIS control",
    "PROC-3602": "deleted-handle review has no CIS control",
    "CONT-8104": "containers are outside the CIS OS benchmark",
    "NETW-3035": "resolver monitoring has no CIS control",
    "NETW-3200": "anomaly detection has no CIS control",
    "TOOL-5002": "compiler presence has no CIS control",
    "HRDN-7220": "compiler presence has no CIS control",
    "HTTP-6622": "web servers are outside the CIS OS benchmark",
    "DBS-1804": "databases are outside the CIS OS benchmark",
    "MAIL-8816": "mail servers are outside the CIS OS benchmark",
    "PHP-2320": "interpreters are outside the CIS OS benchmark",
    "NAME-4016": "resolver configuration has no CIS control",
}

SECTION_NAMES = {
    "1": "Initial Setup",
    "2": "Services",
    "3": "Network Configuration",
    "4": "Logging and Auditing",
    "5": "Access, Authentication and Authorization",
    "6": "System Maintenance",
}

CONTROL_TITLES = {
    "1.1": "Filesystem and mount hardening (/tmp, /dev/shm, removable media)",
    "1.1.23": "USB storage disabled",
    "1.2": "Package manager repositories and GPG verification",
    "1.3": "Filesystem integrity monitoring (AIDE)",
    "1.4.1": "Bootloader password set",
    "1.6": "Mandatory access control (SELinux / AppArmor)",
    "2.1": "Legacy services removed (telnet, rsh, talk)",
    "2.2": "Unnecessary services disabled; time synchronization in use",
    "2.4": "Cron hardening and access control",
    "3.2": "Secure kernel networking parameters (sysctl)",
    "3.4": "Host firewall enabled (firewalld / nftables / iptables)",
    "4.1": "System auditing (auditd) configured and enabled",
    "4.2": "Centralized logging (rsyslog / journald) configured",
    "5.1": "sudo configuration hardened (no NOPASSWD, logging)",
    "5.2": "SSH server hardened (protocol, root login, ciphers)",
    "5.3": "Account lockout and failed-login handling",
    "5.4": "Password policy, umask, and shell hardening",
    "5.4.1": "Password quality enforcement (pam_pwquality)",
    "6.1": "File permissions (SUID audit, world-writable files)",
}

# test_id -> [(control, level)]. Levels: direct | partial.
TEST_CIS: dict[str, list[tuple[str, str]]] = {
    "BOOT-5122": [("1.4.1", "direct")],
    "KERN-5820": [("3.2", "direct")],
    "KRNL-5788": [("1.1", "partial")],
    "SSH-7408": [("5.2", "direct")],
    "FIRE-4512": [("3.4", "direct")],
    "TIME-3104": [("2.2", "partial")],
    "AUTH-9252": [("5.3", "partial")],
    "AUTH-9408": [("5.3", "partial")],
    "AUTH-9262": [("5.2", "partial")],
    "AUTH-9328": [("5.1", "partial")],
    "AUTH-9230": [("5.4.1", "direct")],
    "NETW-3030": [("2.2", "partial")],
    "FINT-4350": [("1.3", "partial")],
    "FINT-4402": [("1.3", "partial")],
    "FINT-4316": [("1.3", "direct")],
    "FILE-6310": [("1.1", "partial"), ("6.1", "partial")],
    "FILE-7524": [("6.1", "partial")],
    "SCHD-7230": [("2.4", "direct")],
    "LOGG-2154": [("4.1", "partial"), ("4.2", "partial")],
    "LOGG-2138": [("4.1", "partial"), ("4.2", "partial")],
    "PKGS-7388": [("1.2", "partial")],
    "MACF-6234": [("1.6", "partial")],
    "SHLL-6202": [("5.4", "partial")],
    "INSE-8016": [("2.1", "direct")],
    "USB-1000": [("1.1.23", "direct")],
    "FS-3010": [("1.1", "partial")],
    "FS-3011": [("1.1", "direct")],
    "FS-3012": [("1.1", "direct")],
    "FS-3013": [("1.1", "partial")],
    "FS-3014": [("1.1", "partial")],
    "FS-3015": [("1.1", "partial")],
    "FILE-6311": [("1.1", "partial")],
    "FILE-6312": [("1.1", "partial")],
    "FILE-6362": [("1.1", "partial")],
    "NFS-3000": [("2.2", "partial")],
    "NFS-3005": [("2.2", "partial")],
    "PKGS-7300": [("1.2", "partial")],
    "PKGS-7301": [("1.2", "partial")],
    "PKGS-7302": [("1.2", "partial")],
    "PKGS-7303": [("1.2", "partial")],
    "PKGS-7304": [("1.2", "partial")],
    "PKGS-7305": [("1.2", "partial")],
    "PKGS-7345": [("1.2", "partial")],
    "PKGS-7346": [("1.2", "partial")],
    "PKGS-7381": [("1.2", "partial")],
    "PKGS-7392": [("1.2", "partial")],
    "PKGS-7398": [("1.2", "partial")],
    "ACCT-5000": [("4.1", "partial")],
    "ACCT-5001": [("4.1", "partial")],
    "ACCT-5002": [("4.1", "partial")],
    "ACCT-5003": [("4.2", "partial")],
    "ACCT-5004": [("4.2", "partial")],
    "ACCT-5005": [("4.2", "partial")],
    "ACCT-5006": [("4.2", "partial")],
    "LOGG-2150": [("4.1", "partial")],
}


def _score_of(status: str) -> float:
    return {"pass": 1.0, "warn": 0.5, "fail": 0.0}.get(status, 0.0)


def compliance_summary(report: dict) -> dict:
    """Score a stored report dict against the CIS mapping.

    Returns benchmark metadata, per-control verdicts (worst contributing
    check wins), per-section scores, an overall 0-100 score, coverage,
    and the unmapped "extended" checks.
    """
    checks = report.get("checks", [])
    by_control: dict[str, dict] = {}
    extended: list[dict] = []

    for check in checks:
        test_id = check.get("test_id", "")
        entry = {
            "test_id": test_id,
            "item": check.get("item", ""),
            "status": check.get("status", ""),
            "recommendation": check.get("recommendation", ""),
        }
        mappings = TEST_CIS.get(test_id)
        if not mappings:
            extended.append(entry)
            continue
        for control, level in mappings:
            bucket = by_control.setdefault(
                control,
                {"control": control, "level": level, "tests": []},
            )
            bucket["tests"].append(entry)
            # A control checked twice keeps the stricter (direct) level.
            if level == "direct":
                bucket["level"] = "direct"

    controls = []
    sections: dict[str, dict] = {}
    for control in sorted(by_control):
        bucket = by_control[control]
        statuses = [t["status"] for t in bucket["tests"]]
        worst = min(statuses, key=_score_of) if statuses else "fail"
        score = sum(_score_of(s) for s in statuses) / len(statuses) if statuses else 0.0
        section = control.split(".")[0]
        controls.append(
            {
                "control": control,
                "title": CONTROL_TITLES.get(control, ""),
                "section": SECTION_NAMES.get(section, section),
                "level": bucket["level"],
                "status": worst,
                "score": round(score * 100),
                "tests": bucket["tests"],
            }
        )
        sec = sections.setdefault(
            control.split(".")[0],
            {"section": SECTION_NAMES.get(section, section), "scores": []},
        )
        sec["scores"].append(score)

    section_summary = {
        sec: {
            "section": data["section"],
            "score": round(sum(data["scores"]) / len(data["scores"]) * 100),
            "controls": len(data["scores"]),
        }
        for sec, data in sorted(sections.items())
    }
    overall = (
        round(sum(c["score"] for c in controls) / len(controls)) if controls else 0
    )
    total = len(checks)
    mapped = total - len(extended)
    return {
        "benchmark": BENCHMARK,
        "overall_score": overall,
        "coverage": {
            "mapped_checks": mapped,
            "total_checks": total,
            "percent": round(mapped / total * 100) if total else 0,
        },
        "controls": controls,
        "sections": section_summary,
        "extended": extended,
    }
