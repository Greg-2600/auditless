"""Tests for the fleet heatmap aggregation (dashboard treemap data)."""

from __future__ import annotations

import pytest

from linux_health.heatmap import build_heatmap, build_host_tiles, build_issue_tiles


def _report(index: int, checks: list[dict], failed: int = 0, warned: int = 0) -> dict:
    return {
        "summary": {
            "hardening_index": index,
            "failed": failed,
            "warned": warned,
            "unknown": 0,
        },
        "checks": checks,
    }


def _check(
    test_id: str, category: str, status: str, item: str = "", recommendation: str = ""
) -> dict:
    return {
        "test_id": test_id,
        "category": category,
        "item": item or test_id,
        "status": status,
        "details": "SENSITIVE-RAW-DETAIL",
        "recommendation": recommendation,
    }


HOSTS = [
    {"id": "a1", "name": "web-01", "hostname": "192.168.1.10"},
    {"id": "a2", "name": "db-01", "hostname": "192.168.1.20"},
    {"id": "b1", "name": "edge", "hostname": "10.0.0.5"},
]


def test_host_tiles_group_by_subnet_and_color_by_score():
    latest = {
        "a1": _report(90, [], failed=1),
        "a2": _report(40, [], failed=2, warned=1),
        "b1": _report(70, []),
    }
    groups = build_host_tiles(HOSTS, latest)
    names = [group["name"] for group in groups]
    assert names == ["192.168.1.0/24", "10.0.0.0/24"]
    subnet = groups[0]
    tiles = {tile["id"]: tile for tile in subnet["tiles"]}
    # Higher finding weight gets the larger tile inside the group.
    assert [t["id"] for t in subnet["tiles"]] == ["a2", "a1"]
    assert tiles["a2"]["value"] == 1 + 2 * 3 + 1 * 2
    assert tiles["a1"]["sublabel"] == "90/100"
    assert tiles["a1"]["color"] == "#28a028"
    assert tiles["a2"]["color"] == "#c88828"
    assert groups[1]["tiles"][0]["color"] == "#78a028"


def test_host_tiles_include_unscanned_hosts_as_unaudited():
    groups = build_host_tiles(HOSTS, {"a1": _report(100, [])})
    tiles = {tile["id"]: tile for group in groups for tile in group["tiles"]}
    assert tiles["a2"]["sublabel"] == "not scanned"
    assert tiles["a2"]["color"] == "#6e7681"
    assert tiles["a2"]["value"] == 1
    assert len(tiles) == 3


def test_host_group_falls_back_to_hostname_prefix():
    hosts = [
        {"id": "x", "name": "x", "hostname": "prod-web-01"},
        {"id": "y", "name": "y", "hostname": "lab.example.com"},
        {"id": "z", "name": "z", "hostname": ""},
    ]
    groups = {group["name"] for group in build_host_tiles(hosts, {})}
    assert groups == {"prod", "example.com", "other"}


def test_issue_tiles_aggregate_across_hosts_and_drop_passes():
    latest = {
        "a1": _report(
            50,
            [
                _check("FIRE-4512", "Network", "fail", "Firewall", "enable it"),
                _check("STOR-6310", "Storage", "pass", "Disk"),
            ],
        ),
        "a2": _report(
            60,
            [
                _check("FIRE-4512", "Network", "warn", "Firewall", "fix it"),
                _check("AUTH-9234", "Accounts", "unknown", "Extra UID 0"),
            ],
        ),
        "b1": _report(80, [_check("FIRE-4512", "Network", "fail", "Firewall")]),
    }
    groups = build_issue_tiles(HOSTS, latest)
    by_name = {group["name"]: group for group in groups}
    assert set(by_name) == {"Network", "Accounts"}
    network = by_name["Network"]["tiles"][0]
    assert network["id"] == "FIRE-4512"
    assert network["value"] == 3 + 2 + 3  # fail, warn, fail
    assert network["sublabel"] == "3 hosts"
    assert network["meta"]["worst"] == "fail"
    assert network["color"] == "#c9372c"
    assert {host["status"] for host in network["hosts"]} == {"fail", "warn"}
    assert network["meta"]["recommendation"] == "enable it"
    assert by_name["Accounts"]["tiles"][0]["color"] == "#6e7681"
    assert "STOR-6310" not in {t["id"] for g in groups for t in g["tiles"]}


def test_issue_tiles_never_expose_raw_check_details():
    groups = build_issue_tiles(
        HOSTS, {"a1": _report(50, [_check("T-1", "Network", "fail")])}
    )
    payload = str(groups)
    assert "SENSITIVE-RAW-DETAIL" not in payload


def test_issue_tiles_handle_malformed_reports():
    latest = {"a1": {"checks": ["not-a-dict", None]}, "a2": {"checks": None}}
    assert build_issue_tiles(HOSTS, latest) == []


def test_build_heatmap_response_shape_and_mode_validation():
    latest = {"a1": _report(50, [_check("T-1", "Network", "fail")], failed=1)}
    payload = build_heatmap(HOSTS, latest, "issue")
    assert payload["mode"] == "issue"
    assert payload["total_hosts"] == 3
    assert payload["total_tiles"] == 1
    assert payload["generated_at"] > 0
    with pytest.raises(ValueError, match="mode must be"):
        build_heatmap(HOSTS, latest, "bogus")


def test_labels_are_bounded():
    host = {"id": "x", "name": "n" * 300, "hostname": "h" * 300}
    tile = build_host_tiles([host], {})[0]["tiles"][0]
    assert len(tile["label"]) == 80
    assert len(build_host_tiles([host], {})[0]["name"]) == 40
