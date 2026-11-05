"""Report determinism locks (ROADMAP item 38).

Same inputs must yield byte-identical reports regardless of hash seed
(diff-friendly output), and the human-meaningful top-level key order
must not drift. Construction order is deterministic by design
(canonical check order, sorted ports, ORDER BY in every store query);
these tests prove it instead of asserting implementation details.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_RENDER_SNIPPET = """
import json
from linux_health.checks import SystemInfo, CheckResult
from linux_health.report import render_report_json
from linux_health.scanner import PortStatus
system = SystemInfo("h", "TestOS 1.0", "1.0", "1 day", "u")
checks = [
    CheckResult("Network", "b trans", "fail", "d", "r", test_id="NETW-9"),
    CheckResult("Auth", "a login", "warn", "d", "r", test_id="AUTH-9"),
    CheckResult("Storage", "c disk", "pass", "d", "r", test_id="STOR-9"),
    CheckResult("Network", "d conn", "warn", "d", "r", test_id="NETW-8"),
]
ports = [PortStatus(443, True, "Connected"), PortStatus(22, True, "Connected")]
print(render_report_json(system, checks, ports, None))
"""


def _render_with_seed(seed: str) -> bytes:
    """Render the fixed report in a fresh interpreter under one hash seed.

    The generated_at timestamp is normalized away: wall-clock time is
    the only legitimate per-run difference.
    """
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = seed
    proc = subprocess.run(
        [sys.executable, "-c", _RENDER_SNIPPET],
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()[-500:]
    return re.sub(rb'"generated_at": "[^"]*"', b'"generated_at": "STAMP"', proc.stdout)


def test_json_bytes_stable_across_hash_seeds() -> None:
    """Identical inputs render byte-identical JSON under any hash seed."""
    first = _render_with_seed("0")
    for seed in ("1", "42"):
        assert _render_with_seed(seed) == first


def test_json_top_level_key_order_locked() -> None:
    """Human-meaningful key order must not drift (no sort_keys scramble)."""
    report = json.loads(_render_with_seed("0").decode())
    assert list(report.keys()) == [
        "scan_info",
        "system",
        "summary",
        "hardening_by_category",
        "checks",
        "ports",
    ]
    assert list(report["summary"].keys()) == [
        "total_checks",
        "passed",
        "warned",
        "failed",
        "hardening_index",
        "hardening_level",
    ]


def test_text_groups_fail_first_deterministically() -> None:
    """Text rendering groups fail/warn/pass with stable in-group order."""
    from linux_health.checks import CheckResult, SystemInfo
    from linux_health.report import render_report_text

    system = SystemInfo("h", "TestOS 1.0", "1.0", "1 day", "u")
    checks = [
        CheckResult("B", "b-pass", "pass", "d", "r"),
        CheckResult("A", "a-fail", "fail", "d", "r"),
        CheckResult("C", "c-warn", "warn", "d", "r"),
        CheckResult("A", "d-fail", "fail", "d", "r"),
    ]
    first = render_report_text(system, checks, [], None)
    assert render_report_text(system, checks, [], None) == first
    positions = [first.index(marker) for marker in ("a-fail", "d-fail", "c-warn")]
    assert positions == sorted(positions)


def test_diff_order_follows_check_order() -> None:
    """Diff fixed/regressed lists track report order, not hash order."""
    from linux_health.dashboard import diff_reports

    def payload(statuses: list[tuple[str, str, str]]) -> dict:
        return {
            "summary": {"hardening_index": 50},
            "checks": [
                {
                    "test_id": tid,
                    "item": item,
                    "category": "C",
                    "status": status,
                    "details": "",
                    "recommendation": "",
                }
                for tid, item, status in statuses
            ],
        }

    before = payload([("T-3", "c", "fail"), ("T-1", "a", "warn"), ("T-2", "b", "fail")])
    after = payload([("T-3", "c", "pass"), ("T-1", "a", "pass"), ("T-2", "b", "warn")])
    first = diff_reports(before, after)
    assert diff_reports(before, after) == first
    assert [e["test_id"] for e in first["fixed"]] == ["T-3", "T-1", "T-2"]
    assert first["regressed"] == []
