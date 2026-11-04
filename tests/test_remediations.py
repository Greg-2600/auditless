"""Tests for the remediation catalog, propose/approve flow, and apply."""

import pytest

from linux_health.client import ApiError
from linux_health.remediations import REMEDIATIONS, Remediation, propose_for_report

SENTINEL = "apply-pw-SENTINEL"


def _report(*checks):
    return {
        "summary": {"hardening_index": 60},
        "checks": [
            {
                "test_id": tid,
                "item": item,
                "category": "C",
                "status": status,
                "details": "",
                "recommendation": "",
            }
            for tid, item, status in checks
        ],
    }


def test_catalog_has_five_safe_starting_fixes():
    assert len(REMEDIATIONS) == 5
    assert {r.risk for r in REMEDIATIONS} <= {"safe", "service"}
    assert all(r.script and r.preconditions for r in REMEDIATIONS)
    assert all(r.id and r.title for r in REMEDIATIONS)


def test_match_is_case_insensitive():
    entry = Remediation(
        id="x",
        title="t",
        risk="safe",
        description="d",
        preconditions="p",
        test_ids=["SSH-7408"],
        match_item="passwordauthentication",
        script=["true"],
    )
    assert entry.matches("SSH-7408", "PasswordAuthentication") is True
    assert entry.matches("SSH-7408", "PermitRootLogin") is False
    assert entry.matches("OTHER-1", "PasswordAuthentication") is False


def test_propose_skips_passing_checks():
    proposals = propose_for_report(
        _report(
            ("SSH-7408", "PasswordAuthentication", "warn"),
            ("SSH-7408", "PermitRootLogin", "pass"),
            ("STOR-6310", "Disk", "fail"),
        )
    )
    assert [(p["remediation_id"], p["item"]) for p in proposals] == [
        ("ssh-password-auth", "PasswordAuthentication")
    ]
    assert proposals[0]["script"][0].startswith("sudo -S cp -n")
    assert proposals[0]["risk"] == "service"


def test_propose_unknown_report_states(client):
    from linux_health.client import ApiError

    with pytest.raises(ApiError) as exc_info:
        client.propose_remediations("missing")
    assert exc_info.value.status == 404


def test_catalog_endpoint_lists_scripts(client):
    catalog = client.list_remediations()
    assert len(catalog) == 5
    by_id = {c["id"]: c for c in catalog}
    assert "sshd -t" in " ".join(by_id["ssh-password-auth"]["script"])


def test_propose_and_apply_flow(client, monkeypatch):
    """End-to-end approve flow with a stubbed SSH session."""
    import linux_health.dashboard as dash

    report = _report(
        ("USB-1000", "USB storage", "warn"),
        ("SSH-7408", "PasswordAuthentication", "warn"),
    )
    stored_id = "remediation-flow-r1"
    dash.get_store().save_report(
        stored_id, "h", "u", "done", report, None, None, 1.0, 2.0
    )
    proposals = client.propose_remediations(stored_id)
    assert {p["remediation_id"] for p in proposals} == {
        "usb-storage",
        "ssh-password-auth",
    }
    usb = next(p for p in proposals if p["remediation_id"] == "usb-storage")
    assert "sudo -S sh -c" in usb["script"][0]
    assert "install usb-storage /bin/true" in usb["script"][0]

    host = client.create_host("apply-target", "10.9.9.9", "root", auth="password")
    commands = []

    class FakeSession:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_run(ssh, command, password="", **kwargs):
        assert kwargs.get("use_cache") is False  # never poison the cache
        commands.append(command)
        return 0, "ok", ""

    def fake_scan(params):
        params["password"] = None
        return None

    monkeypatch.setattr("linux_health.ssh_client.SSHSession", FakeSession)
    # api_apply_remediation imports _run lazily from linux_health.checks.
    monkeypatch.setattr("linux_health.checks._run", fake_run)
    monkeypatch.setattr(dash, "run_scan", fake_scan)
    result = client.apply_remediation(usb["proposal_id"], host["id"], password=SENTINEL)
    assert commands == usb["script"]
    assert result["results"][0]["exit_code"] == 0
    assert result["verification_job_id"]

    with pytest.raises(ApiError) as exc_info:
        client.apply_remediation("missing", host["id"], password="x")
    assert exc_info.value.status == 404


def test_apply_needs_credential_for_password_host(client):
    host = client.create_host("needpw", "10.9.9.8", "u", auth="password")
    report = _report(("USB-1000", "USB storage", "warn"))
    dash_store_id = "remediation-cred-r1"
    from linux_health import dashboard as dash

    dash.get_store().save_report(
        dash_store_id, "h", "u", "done", report, None, None, 1.0, 2.0
    )
    proposal = client.propose_remediations(dash_store_id)[0]
    from linux_health.client import ApiError

    with pytest.raises(ApiError) as exc_info:
        client.apply_remediation(proposal["proposal_id"], host["id"])
    assert exc_info.value.status == 400
