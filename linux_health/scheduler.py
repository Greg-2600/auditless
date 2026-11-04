"""Unattended scheduled scans with drift alerts (stdlib only).

A background loop ticks over enabled schedules, runs due scans through
the shared scan pipeline, diffs each result against the host's previous
completed report, and POSTs a webhook payload on regression, threshold
breach, or every run depending on the schedule policy.

Webhook URLs may carry secrets: they live server-side in SQLite, are
never returned by the API, and never appear in logs.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Any


def _previous_report(store: Any, host_id: str, exclude_id: str) -> dict | None:
    """Most recent completed report for the host other than the new one."""
    for row in store.list_reports(host_id, limit=10):
        if row["id"] != exclude_id and row["status"] == "done":
            full = store.get_report(row["id"])
            if full and full.get("report_json"):
                parsed: dict = json.loads(full["report_json"])
                return parsed
    return None


def should_notify(schedule: dict, report: dict | None, diff: dict | None) -> bool:
    """Decide whether a finished scheduled run pages the webhook."""
    policy = schedule.get("notify_on", "regression")
    if policy == "never":
        return False
    if policy == "always":
        return True
    if report is None:
        return False  # failed runs stay quiet unless policy is always
    if policy == "threshold":
        threshold = schedule.get("min_index")
        index = (report.get("summary") or {}).get("hardening_index")
        return threshold is not None and index is not None and index < threshold
    # regression (default): any regressed check versus the previous report
    return bool(diff and diff.get("regressed"))


def post_webhook(url: str, payload: dict) -> None:
    """POST JSON to a webhook URL (secrets never logged)."""
    if not url:
        return
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    except Exception as exc:  # delivery failure must not fail the scan
        print(f"webhook delivery failed: {exc}")


def run_due_schedules(store: Any, scan_host: Any) -> list[dict]:
    """Run every enabled schedule whose next_run has passed.

    Args:
        store: Persistence handle.
        scan_host: Callable ``(host_id, overrides) -> (job, report_or_None)``
            performing a full persisted scan (dashboard.scan_host_now).

    Returns:
        Per-schedule outcome dicts (schedule id, report id, notified).
    """
    from .dashboard import diff_reports

    now = time.time()
    outcomes: list[dict] = []
    for schedule in store.list_schedules(enabled_only=True):
        if schedule.get("next_run") and schedule["next_run"] > now:
            continue
        outcome: dict[str, Any] = {"schedule_id": schedule["id"], "notified": False}
        try:
            previous = _previous_report(store, schedule["host_id"], "")
            job, report = scan_host(schedule["host_id"], {})
            if report is not None:
                outcome["report_id"] = job.id
                diff = diff_reports(previous, report) if previous else None
                if should_notify(schedule, report, diff):
                    post_webhook(
                        schedule.get("webhook_url") or "",
                        {
                            "event": "scan.completed",
                            "schedule_id": schedule["id"],
                            "schedule_name": schedule.get("name", ""),
                            "host_id": schedule["host_id"],
                            "report_id": job.id,
                            "hardening_before": (diff or {}).get("hardening_before"),
                            "hardening_after": (
                                (report.get("summary") or {}).get("hardening_index")
                            ),
                            "fixed": (diff or {}).get("fixed", []),
                            "regressed": (diff or {}).get("regressed", []),
                        },
                    )
                    outcome["notified"] = True
            else:
                outcome["error"] = (job.error or "scan failed")[:300]
        except Exception as exc:
            outcome["error"] = str(exc)[:300]
        finally:
            store.mark_schedule_run(schedule["id"])
        outcomes.append(outcome)
    return outcomes


def scheduler_loop(
    store: Any,
    stop: threading.Event,
    interval: float = 30.0,
    scan_host: Any | None = None,
) -> None:
    """Tick forever (daemon thread): run due schedules, then sleep."""
    from .dashboard import scan_host_now

    while not stop.wait(interval):
        try:
            run_due_schedules(store, scan_host or scan_host_now)
        except Exception as exc:  # the loop itself must never die
            print(f"scheduler tick failed: {exc}")
