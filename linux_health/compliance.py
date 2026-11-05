"""Compliance mapping and scoring across frameworks (best effort).

Ships CIS mappings for Ubuntu 22.04, Debian 12 and RHEL 9 plus a
PCI-DSS 4.0 overlay. Mappings carry a level (direct = the check validates
the control, partial = adjacent coverage); checks with no corresponding
control land in the "extended" bucket and neither help nor hurt the
score. Coverage is always reported alongside the score so the number
cannot mislead. Control numbers come from working knowledge of the
benchmarks — validate critical findings against CIS-CAT or an assessor.
"""

from __future__ import annotations

from dataclasses import dataclass

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
    "DBS-1000": "databases are outside the CIS OS benchmark",
    "DBS-1001": "databases are outside the CIS OS benchmark",
    "DBS-1002": "databases are outside the CIS OS benchmark",
    "DBS-1003": "databases are outside the CIS OS benchmark",
    "DBS-1004": "databases are outside the CIS OS benchmark",
    "DBS-1005": "databases are outside the CIS OS benchmark",
    "DBS-1006": "databases are outside the CIS OS benchmark",
    "DBS-1007": "databases are outside the CIS OS benchmark",
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


@dataclass(frozen=True)
class Framework:
    """One scorable benchmark: metadata plus its mapping tables."""

    id: str
    title: str
    version: str
    sections: dict
    titles: dict
    mapping: dict
    unmapped: dict


DEBIAN_SECTION_NAMES = dict(SECTION_NAMES)

DEBIAN_CONTROL_TITLES = dict(CONTROL_TITLES)
DEBIAN_CONTROL_TITLES.update(
    {
        "1.6": "Mandatory access control (AppArmor enforced)",
        "3.4": "Host firewall enabled (nftables / iptables)",
    }
)

RHEL_SECTION_NAMES = {
    "1": "Initial Setup",
    "2": "Services",
    "3": "Network Configuration",
    "4": "Logging and Auditing",
    "5": "Access, Authentication and Authorization",
    "6": "System Maintenance",
}

RHEL_CONTROL_TITLES = {
    "1": "Filesystem, bootloader, and package hardening",
    "2": "Unnecessary services removed",
    "3": "Firewall and kernel networking parameters",
    "4": "Auditing and centralized logging",
    "5": "SSH, sudo, and account hardening",
    "6": "File permissions and ownership",
}


# Section-level RHEL mapping (conservative granularity for v3 numbering).
def _to_sections(
    mapping: dict[str, list[tuple[str, str]]],
) -> dict[str, list[tuple[str, str]]]:
    sectioned: dict[str, list[tuple[str, str]]] = {}
    for tid, controls in mapping.items():
        seen: set[str] = set()
        for control, _ in controls:
            sec = control.split(".")[0]
            if sec not in seen:
                seen.add(sec)
                sectioned.setdefault(tid, []).append((sec, "partial"))
    return sectioned


RHEL_MAPPING = _to_sections(TEST_CIS)

PCI_SECTION_NAMES = {
    "1": "Install and Maintain Network Security Controls",
    "2": "Apply Secure Configurations",
    "5": "Protect Against Malicious Software",
    "6": "Develop and Maintain Secure Systems and Software",
    "7": "Restrict Access by Business Need to Know",
    "8": "Identify Users and Authenticate Access",
    "10": "Log and Monitor All Access",
    "11": "Test Security Regularly",
}

PCI_CONTROL_TITLES = {
    "1.5": "Network security controls (firewall) in place",
    "2.2": "System configuration standards (hardened services)",
    "5.2": "Anti-malware mechanisms deployed and maintained",
    "6.2": "System software patches kept current",
    "7.2": "Least-privilege access control",
    "8.3": "Strong authentication (passwords, lockout)",
    "10.2": "Audit trails for access and actions",
    "10.4": "Time synchronization for logs",
    "11.5": "Change detection and integrity monitoring",
}

PCI_MAPPING: dict[str, list[tuple[str, str]]] = {
    "FIRE-4512": [("1.5", "direct")],
    "SSH-7408": [("2.2", "partial")],
    "AUTH-9230": [("8.3", "partial")],
    "AUTH-9252": [("8.3", "partial")],
    "AUTH-9408": [("8.3", "partial")],
    "AUTH-9328": [("7.2", "partial")],
    "AUTH-9234": [("7.2", "partial")],
    "AUTH-9262": [("2.2", "partial")],
    "TIME-3104": [("10.4", "direct")],
    "PKGS-7380": [("6.2", "partial")],
    "MALW-3280": [("5.2", "partial")],
    "MALW-3288": [("5.2", "partial")],
    "MALW-3292": [("5.2", "partial")],
    "FINT-4350": [("11.5", "partial")],
    "FINT-4402": [("11.5", "partial")],
    "FINT-4316": [("11.5", "partial")],
    "LOGG-2138": [("10.2", "partial")],
    "LOGG-2154": [("10.2", "partial")],
    "ACCT-5000": [("10.2", "partial")],
    "ACCT-5001": [("10.2", "partial")],
    "ACCT-5002": [("10.2", "partial")],
    "ACCT-5003": [("10.2", "partial")],
    "ACCT-5004": [("10.2", "partial")],
    "ACCT-5005": [("10.2", "partial")],
    "ACCT-5006": [("10.2", "partial")],
    "LOGG-2150": [("10.2", "partial")],
}

PCI_UNMAPPED: dict[str, str] = dict(UNMAPPED_REASONS)
PCI_UNMAPPED.update(
    {
        tid: "no PCI-DSS 4.0 requirement maps to this check"
        for tid in TEST_CIS
        if tid not in PCI_MAPPING
    }
)

FRAMEWORKS: dict[str, Framework] = {
    "cis-ubuntu22": Framework(
        id="cis-ubuntu22",
        title="CIS Ubuntu Linux 22.04 LTS Benchmark",
        version="v2.0.0",
        sections=SECTION_NAMES,
        titles=CONTROL_TITLES,
        mapping=TEST_CIS,
        unmapped=UNMAPPED_REASONS,
    ),
    "cis-debian12": Framework(
        id="cis-debian12",
        title="CIS Debian Linux 12 Benchmark",
        version="v1.0.0",
        sections=DEBIAN_SECTION_NAMES,
        titles=DEBIAN_CONTROL_TITLES,
        mapping=TEST_CIS,
        unmapped=UNMAPPED_REASONS,
    ),
    "cis-rhel9": Framework(
        id="cis-rhel9",
        title="CIS Red Hat Enterprise Linux 9 Benchmark",
        version="v3.0.0",
        sections=RHEL_SECTION_NAMES,
        titles=RHEL_CONTROL_TITLES,
        mapping=RHEL_MAPPING,
        unmapped=UNMAPPED_REASONS,
    ),
    "pci-dss4": Framework(
        id="pci-dss4",
        title="PCI-DSS",
        version="v4.0",
        sections=PCI_SECTION_NAMES,
        titles=PCI_CONTROL_TITLES,
        mapping=PCI_MAPPING,
        unmapped=PCI_UNMAPPED,
    ),
}


def detect_framework(os_string: str) -> str:
    """Pick a framework from a report's OS string (auto mode).

    Returns a framework id; unknown distros fall back to cis-ubuntu22
    and the caller records what was detected.
    """
    text = (os_string or "").lower()
    if "debian" in text:
        return "cis-debian12"
    for marker in ("rhel", "red hat", "centos", "rocky", "alma", "oracle"):
        if marker in text:
            return "cis-rhel9"
    return "cis-ubuntu22"


def _score_of(status: str) -> float:
    return {"pass": 1.0, "warn": 0.5, "fail": 0.0}.get(status, 0.0)


def compliance_summary(report: dict, framework: str = "auto") -> dict:
    """Score a stored report dict against a compliance framework.

    Args:
        report: Stored report payload (checks + optional system info).
        framework: Framework id, or "auto" to detect from report.system.os.

    Returns benchmark metadata, per-control verdicts (worst contributing
    check wins), per-section scores, an overall 0-100 score, coverage,
    and the unmapped "extended" checks.
    """
    if framework == "auto":
        detected = detect_framework((report.get("system") or {}).get("os", ""))
    else:
        detected = framework
    if detected not in FRAMEWORKS:
        raise ValueError(f"unknown framework {detected!r}")
    active = FRAMEWORKS[detected]
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
        mappings = active.mapping.get(test_id)
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
        # Unknown evidence (not assessed) never decides a control.
        assessed = [
            t for t in bucket["tests"] if t["status"] in ("pass", "warn", "fail")
        ]
        if assessed:
            statuses = [t["status"] for t in assessed]
            worst = min(statuses, key=_score_of)
            score: float | None = sum(_score_of(s) for s in statuses) / len(statuses)
        else:
            worst = "unknown"
            score = None
        section = control.split(".")[0]
        controls.append(
            {
                "control": control,
                "title": active.titles.get(control, ""),
                "section": active.sections.get(section, section),
                "level": bucket["level"],
                "status": worst,
                "score": round(score * 100) if score is not None else None,
                "tests": bucket["tests"],
            }
        )
        sec = sections.setdefault(
            control.split(".")[0],
            {"section": active.sections.get(section, section), "scores": []},
        )
        if score is not None:
            sec["scores"].append(score)

    section_summary = {
        sec: {
            "section": data["section"],
            "score": (
                round(sum(data["scores"]) / len(data["scores"]) * 100)
                if data["scores"]
                else None
            ),
            "controls": len(data["scores"]),
        }
        for sec, data in sorted(sections.items())
    }
    scored = [c["score"] for c in controls if c["score"] is not None]
    if scored:
        overall = round(sum(scored) / len(scored))
    elif controls:
        overall = None  # controls exist but none were assessable
    else:
        overall = 0
    total = len(checks)
    mapped = total - len(extended)
    return {
        "benchmark": f"{active.title} {active.version}",
        "framework": active.id,
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
