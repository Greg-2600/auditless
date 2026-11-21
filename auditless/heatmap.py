"""Fleet heatmap aggregation for the dashboard treemap.

Pure, I/O-free helpers that turn the latest report per host into grouped
tiles. Only labels, counts and status metadata leave this layer — raw check
``details`` (which can contain hashes, paths or credentials on a target) are
deliberately never included in a tile.

Two modes:

* ``host`` — one tile per saved host, sized by finding weight, coloured by
  hardening index, grouped by subnet or hostname prefix.
* ``issue`` — one tile per failing/warning/unknown check, sized by the
  number/severity of affected hosts, coloured by worst status, grouped by
  check category.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

#: Severity weight used for tile size (TradingView uses market cap here).
_STATUS_WEIGHT: dict[str, int] = {"fail": 3, "warn": 2, "unknown": 1}
_STATUS_RANK: dict[str, int] = {"fail": 0, "warn": 1, "unknown": 2}

_UNAUDITED_COLOR = "#6e7681"
_STATUS_COLORS: dict[str, str] = {
    "fail": "#c9372c",
    "warn": "#b8860b",
    "unknown": "#6e7681",
}

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _text(value: Any, limit: int = 80) -> str:
    """Bound user/target-controlled labels before they reach the DOM."""
    text = " ".join(str(value or "").split())
    return text[:limit]


def _score_color(index: Any) -> str:
    """Red → amber → green ramp for a 0-100 hardening index."""
    if not isinstance(index, (int, float)) or isinstance(index, bool):
        return _UNAUDITED_COLOR
    value = max(0, min(100, int(index)))
    if value < 50:
        red, green, blue = 200, int(40 + value * 2.4), 40
    else:
        red, green, blue = int(200 - (value - 50) * 4), 160, 40
    return f"#{red:02x}{green:02x}{blue:02x}"


def _host_group(host: dict[str, Any]) -> str:
    """Derive a TradingView-style sector label for a host."""
    hostname = _text(host.get("hostname"), 120)
    if _IPV4.match(hostname):
        return ".".join(hostname.split(".")[:3]) + ".0/24"
    name = hostname.lower()
    if "." in name:
        return _text(name.split(".", 1)[1], 40) or "other"
    prefix = name.split("-", 1)[0]
    return _text(prefix if len(prefix) > 1 else "other", 40)


def _host_label(host: dict[str, Any]) -> str:
    return _text(host.get("name") or host.get("hostname") or host.get("id") or "host")


def _summary(report: dict[str, Any] | None) -> dict[str, Any]:
    return (report or {}).get("summary") or {}


def _count(summary: dict[str, Any], key: str) -> int:
    value = summary.get(key) or 0
    return (
        int(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
        else 0
    )


def build_host_tiles(
    hosts: list[dict[str, Any]], latest: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """One tile per host, grouped by subnet/prefix (never scanned included)."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for host in hosts:
        host_id = str(host.get("id") or "")
        report = latest.get(host_id)
        summary = _summary(report)
        index = summary.get("hardening_index")
        failed = _count(summary, "failed")
        warned = _count(summary, "warned")
        unknown = _count(summary, "unknown")
        label = _host_label(host)
        tile = {
            "id": host_id,
            "label": label,
            "sublabel": (
                f"{index}/100" if isinstance(index, (int, float)) else "not scanned"
            ),
            # +1 keeps clean (unscanned/perfect) hosts visible in the treemap.
            "value": 1 + failed * 3 + warned * 2 + unknown,
            "color": _score_color(index),
            "hosts": [
                {
                    "name": label,
                    "status": (
                        "scanned" if isinstance(index, (int, float)) else "not scanned"
                    ),
                }
            ],
            "meta": {
                "host_id": host_id,
                "hostname": _text(host.get("hostname")),
                "index": index if isinstance(index, (int, float)) else None,
                "failed": failed,
                "warned": warned,
                "unknown": unknown,
            },
        }
        grouped[_host_group(host)].append(tile)
    return _groups(grouped)


def build_issue_tiles(
    hosts: list[dict[str, Any]], latest: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """One tile per issue, aggregated over hosts, grouped by category."""
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for host in hosts:
        report = latest.get(str(host.get("id") or ""))
        if not report:
            continue
        host_label = _host_label(host)
        checks = report.get("checks")
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, dict):
                continue
            status = str(check.get("status") or "")
            if status not in _STATUS_WEIGHT:
                continue  # pass / unknown-shape checks are not heatmap issues
            category = _text(check.get("category") or "Other", 40)
            key = _text(check.get("test_id") or check.get("item") or "UNKNOWN-0", 40)
            entry = grouped[category].get(key)
            if entry is None:
                entry = {
                    "id": key,
                    "label": _text(check.get("item") or key, 60),
                    "sublabel": "",
                    "value": 0,
                    "color": _STATUS_COLORS[status],
                    "hosts": [],
                    "meta": {
                        "test_id": key,
                        "category": category,
                        "worst": status,
                        "recommendation": _text(check.get("recommendation"), 240),
                    },
                }
                grouped[category][key] = entry
            entry["value"] += _STATUS_WEIGHT[status]
            entry["hosts"].append({"name": host_label, "status": status})
            if _STATUS_RANK[status] < _STATUS_RANK[entry["meta"]["worst"]]:
                entry["meta"]["worst"] = status
                entry["color"] = _STATUS_COLORS[status]
                if check.get("recommendation"):
                    entry["meta"]["recommendation"] = _text(
                        check.get("recommendation"), 240
                    )

    for tiles in grouped.values():
        for tile in tiles.values():
            tile["sublabel"] = f"{len(tile['hosts'])} host" + (
                "s" if len(tile["hosts"]) != 1 else ""
            )
    return _groups(grouped)


def _groups(grouped: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Shape grouped tiles into sorted, response-ready group records."""
    result: list[dict[str, Any]] = []
    for name, raw in grouped.items():
        tiles = list(raw.values()) if isinstance(raw, dict) else list(raw)
        if not tiles:
            continue
        valid = [tile for tile in tiles if isinstance(tile.get("value"), int)]
        if not valid:
            continue
        result.append(
            {
                "name": _text(name, 40),
                "value": sum(tile["value"] for tile in valid),
                "tiles": sorted(
                    valid, key=lambda tile: (-tile["value"], tile["label"])
                ),
            }
        )
    return sorted(result, key=lambda group: (-group["value"], group["name"]))


def build_heatmap(
    hosts: list[dict[str, Any]],
    latest: dict[str, dict[str, Any]],
    mode: str,
) -> dict[str, Any]:
    """Build the full heatmap response payload for ``mode``."""
    if mode == "host":
        groups = build_host_tiles(hosts, latest)
    elif mode == "issue":
        groups = build_issue_tiles(hosts, latest)
    else:
        raise ValueError("mode must be 'host' or 'issue'")
    return {
        "mode": mode,
        "groups": groups,
        "total_hosts": len(hosts),
        "total_tiles": sum(len(group["tiles"]) for group in groups),
        "generated_at": time.time(),
    }
