#!/usr/bin/env python3
"""Test JSON output format."""

sys.path.insert(0, "/home/greg/projects/auditless")
import json

from auditless.checks import CheckResult, DetailedSecurityInfo, SystemInfo
from auditless.report import render_report_json
from auditless.scanner import PortStatus

# Create test data
system = SystemInfo(
    hostname="testhost",
    os="Ubuntu 22.04 LTS",
    kernel="5.15.0-58-generic",
    uptime="up 5 days",
    users=["user1", "user2"],
)

checks = [
    CheckResult(
        category="Storage",
        item="Disk usage",
        status="pass",
        details="Disk is 45% full",
        recommendation="No action",
        test_id="STOR-6310",
    ),
    CheckResult(
        category="Memory",
        item="Memory availability",
        status="warn",
        details="78% memory used",
        recommendation="Investigate memory usage",
        test_id="MEM-2914",
    ),
    CheckResult(
        category="Authentication",
        item="SSH configuration",
        status="fail",
        details="PermitRootLogin enabled",
        recommendation="Disable root login",
        test_id="SSH-7408",
    ),
]

ports = [
    PortStatus(port=22, open=True, reason="ssh"),
    PortStatus(port=80, open=True, reason="http"),
    PortStatus(port=443, open=False, reason="filtered"),
]

detailed = DetailedSecurityInfo(
    suid_binaries="test",
    root_logins="0",
    successful_ssh_logins="0",
    failed_ssh_logins="0",
    top_processes="",
    disk_usage_dirs="",
    available_updates="",
    firewall_rules="",
    sshd_config_check="",
    failed_systemd_units="",
    sudoers_info="",
    critical_file_permissions="",
)

# Generate JSON report
json_output = render_report_json(system, checks, ports, detailed)

# Parse and pretty print
report = json.loads(json_output)
print("✅ JSON Output Test PASSED\n")
print(f"Scan Info: {json.dumps(report['scan_info'], indent=2)}")
print(f"\nSummary: {json.dumps(report['summary'], indent=2)}")
print(f"\nTotal checks: {len(report['checks'])}")
print(f"Open ports: {len(report['ports']['open_ports'])}")

# Verify structure
assert "scan_info" in report
assert "system" in report
assert "summary" in report
assert "hardening_by_category" in report
assert "checks" in report
assert "ports" in report
assert report["summary"]["hardening_index"] > 0
assert report["summary"]["hardening_index"] <= 100

print("\n✅ All JSON structure validations passed!")
print(f"Hardening Index: {report['summary']['hardening_index']}/100")
print(f"Hardening Level: {report['summary']['hardening_level']}")
