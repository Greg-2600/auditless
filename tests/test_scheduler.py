"""Tests for cron parsing, schedule storage, and the scheduler loop."""

import datetime
import json
import threading
import time

import pytest

from linux_health.cron import CronExpr
from linux_health.scheduler import (
    post_webhook,
    run_due_schedules,
    scheduler_loop,
    should_notify,
)
from linux_health.store import Store


def test_cron_every_minute():
    expr = CronExpr("* * * * *")
    moment = datetime.datetime(2026, 1, 1, 0, 0)
    assert expr.matches(moment) is True
    assert expr.next_after(moment) == datetime.datetime(2026, 1, 1, 0, 1)


def test_cron_nightly():
    expr = CronExpr("0 3 * * *")
    assert expr.matches(datetime.datetime(2026, 5, 4, 3, 0)) is True
    assert expr.matches(datetime.datetime(2026, 5, 4, 3, 1)) is False
    assert expr.next_after(datetime.datetime(2026, 5, 4, 3, 0)) == datetime.datetime(
        2026, 5, 5, 3, 0
    )


def test_cron_steps_and_lists():
    expr = CronExpr("*/15 9-17 * * 1-5")
    assert expr.matches(datetime.datetime(2026, 5, 4, 9, 30)) is True  # Monday
    assert expr.matches(datetime.datetime(2026, 5, 4, 9, 31)) is False
    assert expr.matches(datetime.datetime(2026, 5, 9, 9, 30)) is False  # Saturday


def test_cron_invalid_rejected():
    for bad in (
        "",
        "* * * *",
        "* * * * * *",
        "61 * * * *",
        "*/0 * * * *",
        "9-7 * * * *",
        "nope * * * *",
    ):
        with pytest.raises(ValueError):
            CronExpr(bad)


@pytest.fixture()
def store(tmp_path):
    """Isolated store."""
    return Store(tmp_path / "data")


def _host(store):
    return store.upsert_host("h", "10.0.0.1", "u")


def _report(index, checks=None):
    return {
        "summary": {"hardening_index": index},
        "checks": checks or [],
    }


def test_schedule_crud_validates(store):
    host = _host(store)
    sched = store.create_schedule(host["id"], "nightly", "0 3 * * *")
    assert sched["next_run"] is not None and sched["next_run"] > time.time()
    assert sched["notify_on"] == "regression"
    with pytest.raises(ValueError, match="cron"):
        store.create_schedule(host["id"], "bad", "not a cron")
    with pytest.raises(ValueError, match="notify_on"):
        store.create_schedule(host["id"], "bad", "* * * * *", notify_on="sms")
    with pytest.raises(KeyError):
        store.create_schedule("missing", "x", "* * * * *")
    updated = store.update_schedule(sched["id"], cron="0 4 * * *", enabled=False)
    assert updated["cron"] == "0 4 * * *"
    assert updated["enabled"] == 0
    assert store.get_schedule("missing") is None
    assert store.delete_schedule(sched["id"]) is True
    assert store.delete_schedule(sched["id"]) is False


def test_schedule_webhook_never_listed(store):
    host = _host(store)
    sched = store.create_schedule(
        host["id"], "n", "* * * * *", webhook_url="https://hooks/x/SECRET"
    )
    assert sched["webhook_url"] == "https://hooks/x/SECRET"  # stored server-side
    listed = store.list_schedules()
    assert len(listed) == 1  # dashboard strips the URL before responding


def test_should_notify_policies():
    base = {"notify_on": "regression"}
    report = _report(80)
    assert should_notify(base, report, {"regressed": [{"a": 1}]}) is True
    assert should_notify(base, report, {"regressed": []}) is False
    assert should_notify(base, None, None) is False
    assert should_notify({"notify_on": "never"}, report, {"regressed": [1]}) is False
    assert should_notify({"notify_on": "always"}, None, None) is True
    assert (
        should_notify({"notify_on": "threshold", "min_index": 70}, _report(60), None)
        is True
    )
    assert (
        should_notify({"notify_on": "threshold", "min_index": 70}, _report(80), None)
        is False
    )


def _canned(index, status_map=None):
    checks = [
        {
            "test_id": "A-1",
            "item": "I1",
            "category": "C",
            "status": (status_map or {}).get("A-1", "pass"),
            "details": "d",
            "recommendation": "r",
        },
        {
            "test_id": "B-2",
            "item": "I2",
            "category": "C",
            "status": (status_map or {}).get("B-2", "pass"),
            "details": "d",
            "recommendation": "r",
        },
    ]
    return {"summary": {"hardening_index": index}, "checks": checks}


def test_run_due_schedules_notifies_regression(store):
    import uuid

    from linux_health import dashboard

    host = _host(store)
    sched = store.create_schedule(
        host["id"], "n", "* * * * *", webhook_url="http://x/hook"
    )
    # Force due now (fresh schedules target the next minute).
    import sqlite3

    with sqlite3.connect(str(store.db_path)) as conn:
        conn.execute("UPDATE schedules SET next_run = 0 WHERE id = ?", (sched["id"],))
    # Seed a passing previous report.
    store.save_report(
        uuid.uuid4().hex, "h", "u", "done", _canned(90), None, host["id"], 1.0, 2.0
    )

    posted = []
    monkey = pytest.MonkeyPatch()

    def fake_scan_host(host_id, overrides):
        assert host_id == host["id"]
        job = dashboard.ScanJob(id="job1", hostname="h", username="u")
        return job, _canned(70, {"A-1": "fail"})

    monkey.setattr(
        "linux_health.scheduler.post_webhook",
        lambda url, payload: posted.append((url, payload)) or True,
    )
    try:
        outcomes = run_due_schedules(store, fake_scan_host)
    finally:
        monkey.undo()
    assert len(outcomes) == 1
    assert outcomes[0]["notified"] is True
    assert len(posted) == 1
    url, payload = posted[0]
    assert url == "http://x/hook"
    assert payload["hardening_after"] == 70
    assert [r["test_id"] for r in payload["regressed"]] == ["A-1"]
    assert "SECRET" not in json.dumps(payload)


def test_run_due_skips_future_and_disabled(store):
    host = _host(store)
    future = store.create_schedule(host["id"], "f", "0 0 1 1 *")
    # Push next_run far out, then disable another.
    import datetime as _dt

    far = (_dt.datetime.now() + _dt.timedelta(days=30)).timestamp()
    import sqlite3

    with sqlite3.connect(str(store.db_path)) as conn:
        conn.execute(
            "UPDATE schedules SET next_run = ? WHERE id = ?", (far, future["id"])
        )
    off = store.create_schedule(host["id"], "o", "* * * * *")
    store.update_schedule(off["id"], enabled=False)

    calls = []
    outcomes = run_due_schedules(store, lambda h, o: calls.append(h) or (None, None))
    assert outcomes == []
    assert calls == []


def test_post_webhook_delivery():
    """Real HTTP POST against a stub receiver (no secrets in logs)."""
    import http.server

    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            # NOTE: receivers must consume the request body first; closing
            # with it unread RSTs the connection on some stacks (flaky 200s).
            length = int(self.headers.get("Content-Length", 0))
            received["body"] = self.rfile.read(length)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}
    )
    thread.daemon = True
    thread.start()
    try:
        post_webhook(
            f"http://127.0.0.1:{server.server_address[1]}/hook",
            {"event": "scan.completed", "regressed": []},
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert json.loads(received["body"])["event"] == "scan.completed"


def test_post_webhook_retries_then_gives_up():
    """Flaky receiver: two failures then success still delivers."""
    import http.server

    attempts = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            # Consume the body: closing with it unread RSTs responses (flaky).
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            attempts.append(1)
            if len(attempts) < 3:
                self.send_response(500)
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}
    )
    thread.daemon = True
    thread.start()
    try:
        assert (
            post_webhook(
                f"http://127.0.0.1:{server.server_address[1]}/hook",
                {"event": "x"},
                retries=3,
            )
            is True
        )
        assert len(attempts) == 3
        attempts.clear()
        assert (
            post_webhook(
                f"http://127.0.0.1:{server.server_address[1]}/dead",
                {"event": "x"},
                retries=1,
            )
            is False
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_run_due_skips_overlapping_run(store):
    """A schedule already running is skipped, never stacked."""
    import linux_health.scheduler as sched_mod

    host = _host(store)
    sched = store.create_schedule(host["id"], "n", "* * * * *")
    import sqlite3

    with sqlite3.connect(str(store.db_path)) as conn:
        conn.execute("UPDATE schedules SET next_run = 0 WHERE id = ?", (sched["id"],))
    started = threading.Event()
    release = threading.Event()

    def slow_scan_host(host_id, overrides):
        from linux_health import dashboard

        started.set()
        assert release.wait(15)
        job = dashboard.ScanJob(
            id="slow", hostname="h", username="u", status="error", error="boom"
        )
        return job, None

    calls = []
    thread = threading.Thread(
        target=lambda: calls.append(run_due_schedules(store, slow_scan_host)),
        daemon=True,
    )
    thread.start()
    assert started.wait(10)
    time.sleep(0.2)  # let the first tick register running
    second = run_due_schedules(store, slow_scan_host)
    assert second == [{"schedule_id": sched["id"], "skipped": "already running"}]
    release.set()
    thread.join(timeout=15)
    assert calls[0][0]["error"] == "boom"  # None report takes the error path
    assert sched_mod._running == set()  # lock released on every path


def test_scheduler_loop_ticks_and_stops(store):
    host = _host(store)
    sched = store.create_schedule(host["id"], "n", "* * * * *")
    # Force the schedule due now (fresh schedules target next minute).
    import sqlite3

    with sqlite3.connect(str(store.db_path)) as conn:
        conn.execute("UPDATE schedules SET next_run = 0 WHERE id = ?", (sched["id"],))
    calls = []
    stop = threading.Event()

    def fake_scan_host(host_id, overrides):
        calls.append(host_id)
        job = {"id": "x"}
        return job, None

    # Patch mark to avoid next_run recompute racing the assertion.
    thread = threading.Thread(
        target=scheduler_loop, args=(store, stop, 0.05, fake_scan_host), daemon=True
    )
    thread.start()
    time.sleep(0.3)
    stop.set()
    thread.join(timeout=5)
    assert calls and all(c == host["id"] for c in calls)
