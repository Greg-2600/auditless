"""Tests for test-ID registry completeness and CIS compliance scoring."""

import pytest

from linux_health.client import ApiError
from linux_health.compliance import (
    BENCHMARK,
    TEST_CIS,
    UNMAPPED_REASONS,
    compliance_summary,
)
from linux_health.test_ids import CHECK_TEST_IDS


def test_every_registry_id_has_compliance_stance():
    """No check silently falls through: mapped or explicitly unmapped."""
    uncovered = [
        tid
        for tid in set(CHECK_TEST_IDS.values())
        if tid not in TEST_CIS and tid not in UNMAPPED_REASONS
    ]
    assert not uncovered, f"IDs without a compliance stance: {uncovered}"


def test_mapping_references_known_controls():
    """Every mapped control has a title (no dangling references)."""
    from linux_health.compliance import CONTROL_TITLES

    dangling = {
        control
        for mappings in TEST_CIS.values()
        for control, _ in mappings
        if control not in CONTROL_TITLES
    }
    assert not dangling, f"controls without titles: {dangling}"


def _report(*statuses):
    return {
        "summary": {"hardening_index": 80},
        "checks": [
            {
                "test_id": tid,
                "item": f"item-{tid}",
                "category": "C",
                "status": status,
                "details": "",
                "recommendation": "",
            }
            for tid, status in statuses
        ],
    }


def test_compliance_scoring_math():
    summary = compliance_summary(
        _report(("BOOT-5122", "pass"), ("USB-1000", "fail"), ("STOR-6310", "pass"))
    )
    assert summary["benchmark"] == BENCHMARK
    by_control = {c["control"]: c for c in summary["controls"]}
    assert by_control["1.4.1"]["status"] == "pass"
    assert by_control["1.4.1"]["score"] == 100
    assert by_control["1.1.23"]["status"] == "fail"
    assert by_control["1.1.23"]["score"] == 0
    # Worst contributing check wins; coverage counts the unmapped check.
    assert summary["coverage"] == {"mapped_checks": 2, "total_checks": 3, "percent": 67}
    assert [e["test_id"] for e in summary["extended"]] == ["STOR-6310"]
    assert summary["overall_score"] == 50


def test_compliance_warn_halves_control():
    summary = compliance_summary(_report(("SSH-7408", "warn")))
    assert summary["controls"][0]["score"] == 50
    assert summary["overall_score"] == 50


def test_compliance_empty_report():
    summary = compliance_summary({"summary": {}, "checks": []})
    assert summary["overall_score"] == 0
    assert summary["controls"] == []
    assert summary["coverage"]["percent"] == 0


def test_detect_framework():
    from linux_health.compliance import detect_framework

    assert detect_framework("Ubuntu 22.04.5 LTS") == "cis-ubuntu22"
    assert detect_framework("Debian GNU/Linux 12 (bookworm)") == "cis-debian12"
    assert detect_framework("Red Hat Enterprise Linux 9.4") == "cis-rhel9"
    assert detect_framework("Rocky Linux 9.3") == "cis-rhel9"
    assert detect_framework("") == "cis-ubuntu22"
    assert detect_framework("Something Else 1.0") == "cis-ubuntu22"


def test_frameworks_all_registered():
    from linux_health.compliance import FRAMEWORKS

    assert set(FRAMEWORKS) == {"cis-ubuntu22", "cis-debian12", "cis-rhel9", "pci-dss4"}
    for fw in FRAMEWORKS.values():
        assert fw.title and fw.version and fw.sections and fw.titles


def test_pci_scoring_and_auto_detection():
    report = {
        "system": {"os": "Debian GNU/Linux 12"},
        "summary": {"hardening_index": 70},
        "checks": [
            {
                "test_id": "FIRE-4512",
                "item": "Firewall",
                "category": "N",
                "status": "pass",
                "details": "",
                "recommendation": "",
            },
            {
                "test_id": "TIME-3104",
                "item": "Clock",
                "category": "N",
                "status": "fail",
                "details": "",
                "recommendation": "",
            },
        ],
    }
    auto = compliance_summary(report)
    assert auto["framework"] == "cis-debian12"
    pci = compliance_summary(report, "pci-dss4")
    assert pci["framework"] == "pci-dss4"
    by_control = {c["control"]: c for c in pci["controls"]}
    assert by_control["1.5"]["status"] == "pass"
    assert by_control["10.4"]["status"] == "fail"
    assert pci["coverage"]["total_checks"] == 2
    with pytest.raises(ValueError, match="unknown framework"):
        compliance_summary(report, "soc2")


def _canned_compliance_report():
    return {
        "summary": {"hardening_index": 75},
        "checks": [
            {
                "test_id": "BOOT-5122",
                "item": "Bootloader",
                "category": "Boot",
                "status": "pass",
                "details": "",
                "recommendation": "",
            },
            {
                "test_id": "SSH-7408",
                "item": "SSH",
                "category": "Auth",
                "status": "warn",
                "details": "",
                "recommendation": "",
            },
            {
                "test_id": "STOR-6310",
                "item": "Disk",
                "category": "Storage",
                "status": "pass",
                "details": "",
                "recommendation": "",
            },
        ],
    }


def test_host_compliance_endpoint(client, monkeypatch):
    from linux_health import dashboard

    def fake_run_scan(params):
        params["password"] = None
        return _canned_compliance_report()

    monkeypatch.setattr(dashboard, "run_scan", fake_run_scan)
    host = client.create_host("comp", "10.5.5.5", "u", auth="password")
    with pytest.raises(ApiError) as exc_info:
        client.host_compliance(host["id"])
    assert exc_info.value.status == 409  # no completed report yet
    done = client.wait_for(client.start_scan(host_id=host["id"], password="x")["id"])
    assert done["status"] == "done"
    comp = client.host_compliance(host["id"])
    assert comp["benchmark"].startswith("CIS Ubuntu Linux")
    by_control = {c["control"]: c for c in comp["controls"]}
    assert by_control["1.4.1"]["status"] == "pass"
    assert by_control["5.2"]["status"] == "warn"
    assert comp["coverage"]["total_checks"] == 3
    assert [e["test_id"] for e in comp["extended"]] == ["STOR-6310"]
    with pytest.raises(ApiError) as exc_info:
        client.host_compliance("missing")
    assert exc_info.value.status == 404


def test_compliance_controls_catalog(client):
    catalog = client.compliance_controls()
    assert catalog["benchmark"].startswith("CIS Ubuntu Linux")
    assert catalog["framework"] == "cis-ubuntu22"
    assert "1.4.1" in catalog["controls"]
    assert catalog["mapping"]["BOOT-5122"] == [{"control": "1.4.1", "level": "direct"}]
    assert "STOR-6310" in catalog["unmapped"]
    pci = client.compliance_controls(framework="pci-dss4")
    assert pci["framework"] == "pci-dss4"
    assert "10.4" in pci["controls"]
    with pytest.raises(ApiError) as exc_info:
        client.compliance_controls(framework="soc2")
    assert exc_info.value.status == 400
