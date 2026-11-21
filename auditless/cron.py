"""Minimal 5-field cron parsing for scan schedules (stdlib only).

Supports ``*``, ``*/n``, ``a-b``, ``a-b/n``, comma lists, and plain
integers in minute hour day-of-month month day-of-week order. Anything
else raises ValueError at schedule creation time (never at 3am).
"""

from __future__ import annotations

import datetime


def _parse_field(raw: str, minimum: int, maximum: int) -> set[int]:
    """Expand one cron field into the set of matching values."""
    values: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"empty cron field part in {raw!r}")
        step = 1
        if "/" in part:
            part, step_raw = part.split("/", 1)
            step = int(step_raw)
            if step < 1:
                raise ValueError(f"bad cron step in {raw!r}")
        if part in ("*", ""):
            lo, hi = minimum, maximum
        elif "-" in part:
            lo_raw, hi_raw = part.split("-", 1)
            lo, hi = int(lo_raw), int(hi_raw)
        else:
            lo = hi = int(part)
        if lo < minimum or hi > maximum or lo > hi:
            raise ValueError(f"cron value out of range in {raw!r}")
        values.update(range(lo, hi + 1, step))
    return values


class CronExpr:
    """Parsed 5-field cron expression with next-run computation."""

    FIELDS = (
        ("minute", 0, 59),
        ("hour", 0, 23),
        ("day", 1, 31),
        ("month", 1, 12),
        ("weekday", 0, 7),  # cron: Sunday=0 (7 also accepted), Saturday=6
    )

    def __init__(self, expr: str) -> None:
        parts = expr.split()
        if len(parts) != 5:
            raise ValueError(f"cron expression needs 5 fields: {expr!r}")
        self.expr = expr
        self.allowed = {
            name: _parse_field(raw, lo, hi)
            for (name, lo, hi), raw in zip(self.FIELDS, parts)
        }
        # Normalize Sunday alias 7 -> 0.
        self.allowed["weekday"] = {0 if v == 7 else v for v in self.allowed["weekday"]}

    def matches(self, moment: datetime.datetime) -> bool:
        """Whether the expression fires at the given minute."""
        # datetime.weekday: Monday=0..Sunday=6; cron: Sunday=0..Saturday=6.
        cron_weekday = (moment.weekday() + 1) % 7
        return (
            moment.minute in self.allowed["minute"]
            and moment.hour in self.allowed["hour"]
            and moment.day in self.allowed["day"]
            and moment.month in self.allowed["month"]
            and cron_weekday in self.allowed["weekday"]
        )

    def next_after(self, moment: datetime.datetime) -> datetime.datetime:
        """Next firing minute strictly after the given moment."""
        candidate = moment.replace(second=0, microsecond=0) + datetime.timedelta(
            minutes=1
        )
        # A year of minutes is a safe upper bound for any valid expression.
        for _ in range(366 * 24 * 60):
            if self.matches(candidate):
                return candidate
            candidate += datetime.timedelta(minutes=1)
        raise ValueError(f"cron expression never fires: {self.expr!r}")
