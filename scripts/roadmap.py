"""ROADMAP.md backlog helper (stdlib only).

Usage:
    python scripts/roadmap.py status    # done/total + next item
    python scripts/roadmap.py next      # first unchecked item as "N — title"
    python scripts/roadmap.py get N     # full line for item N
    python scripts/roadmap.py mark N    # check the box for item N (in place)

Item lines look like:  - [ ] 12 — [P0] Description `area` (effort: S)
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROADMAP = ROOT / "ROADMAP.md"

ITEM_RE = re.compile(r"^- \[( |x)\] (\d+) — (.+)$")


def parse_items(text):
    """Parse ROADMAP text into [{'n', 'done', 'title', 'line'}]."""
    items = []
    for line in text.splitlines():
        match = ITEM_RE.match(line)
        if match:
            box, num, title = match.groups()
            items.append(
                {
                    "n": int(num),
                    "done": box == "x",
                    "title": title.strip(),
                    "line": line,
                }
            )
    return items


def next_item(items):
    """First unchecked item (by number), or None when complete."""
    pending = [i for i in items if not i["done"]]
    return min(pending, key=lambda i: i["n"]) if pending else None


def render_marked(text, n):
    """Return text with item N's box checked. Raises KeyError/ValueError."""
    lines = text.splitlines()
    changed = False
    for idx, line in enumerate(lines):
        match = ITEM_RE.match(line)
        if match and int(match.group(2)) == n:
            if match.group(1) == "x":
                raise ValueError(f"item {n} is already done")
            lines[idx] = line.replace("- [ ]", "- [x]", 1)
            changed = True
            break
    if not changed:
        raise KeyError(f"item {n} not found")
    return "\n".join(lines) + "\n"


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "status"
    text = ROADMAP.read_text(encoding="utf-8")
    items = parse_items(text)

    if cmd == "status":
        done = sum(1 for i in items if i["done"])
        nxt = next_item(items)
        print(f"{done}/{len(items)} done")
        if nxt:
            print(f"next: {nxt['n']} — {nxt['title']}")
        else:
            print("roadmap complete")
        return 0
    if cmd == "next":
        nxt = next_item(items)
        if not nxt:
            print("roadmap complete")
            return 1
        print(f"{nxt['n']} — {nxt['title']}")
        return 0
    if cmd == "get":
        want = int(argv[2])
        for item in items:
            if item["n"] == want:
                print(item["line"])
                return 0
        print(f"item {want} not found", file=sys.stderr)
        return 1
    if cmd == "mark":
        want = int(argv[2])
        ROADMAP.write_text(render_marked(text, want), encoding="utf-8")
        print(f"marked {want} done")
        return 0
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
