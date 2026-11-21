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


def post_webhook(url: str, payload: dict, retries: int = 3) -> bool:
    """POST JSON to a webhook URL with backoff retries.

    Secrets never logged. Returns True on delivery, False after
    exhausting retries (delivery failure never fails the scan).
    """
    if not url:
        return False
    body = json.dumps(payload).encode("utf-8")
    for attempt in range(max(1, retries)):
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            return True
        except Exception:  # delivery failure must not fail the scan
            if attempt + 1 >= max(1, retries):
                print("webhook delivery failed after retries")
            else:
                time.sleep(2.0 * (attempt + 1))
    return False


_running: set[str] = set()
_running_lock = threading.Lock()


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
        with _running_lock:
            if schedule["id"] in _running:
                outcomes.append(
                    {"schedule_id": schedule["id"], "skipped": "already running"}
                )
                continue
            _running.add(schedule["id"])
        outcome: dict[str, Any] = {"schedule_id": schedule["id"], "notified": False}
        try:
            previous = _previous_report(store, schedule["host_id"], "")
            job, report = scan_host(schedule["host_id"], {})
            if report is not None:
                outcome["report_id"] = job.id
                diff = diff_reports(previous, report) if previous else None
                if should_notify(schedule, report, diff):
                    if post_webhook(
                        store.webhook_for(schedule),
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
                    ):
                        outcome["notified"] = True
            else:
                outcome["error"] = (job.error or "scan failed")[:300]
        except Exception as exc:
            outcome["error"] = str(exc)[:300]
        finally:
            with _running_lock:
                _running.discard(schedule["id"])
            store.mark_schedule_run(schedule["id"])
        outcomes.append(outcome)
    return outcomes


def scheduler_loop(
    store: Any,
    stop: threading.Event,
    interval: float = 30.0,
    scan_host: Any | None = None,
) -> None:
    """Tick forever (daemon thread): run due schedules, then sleep.

    Takes a best-effort database snapshot once per calendar day.
    """
    import datetime

    from .dashboard import scan_host_now

    last_backup = ""
    while not stop.wait(interval):
        today = datetime.date.today().isoformat()
        if today != last_backup:
            try:
                store.backup()
            except Exception:
                pass
            last_backup = today
        try:
            run_due_schedules(store, scan_host or scan_host_now)
        except Exception as exc:  # the loop itself must never die
            print(f"scheduler tick failed: {exc}")
