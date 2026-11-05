---
description: Milestone review every 10 roadmap items (quality, stability, security, wow) + next-horizon roadmap
---

One completed milestone = 10 more ROADMAP.md boxes checked. Do NOT start
the next feature item this turn. Instead, review the last 10 merged
items and write the milestone review file, then ship it through the
standard gates + PR flow.

Milestone under review (from the helper — do not compute by hand):

!`.venv/bin/python scripts/roadmap.py milestone`

## Workflow

1. **Sync and branch.** `git fetch origin`, update local `main`, then
   create `roadmap/review-<NNN>` from `main` (`<NNN>` = the done-count,
   e.g. `roadmap/review-050`). Worktree must be clean before branching
   (stash nothing — stop and report if dirty).
2. **Gather evidence** (read, don't guess):
   - `git log --oneline -12` (the merged items + any fix commits)
   - `ROADMAP.md` boxes just checked (titles + areas)
   - Full pytest count, gate status, coverage if touched
   - Any CI red/fix-rounds observed on those PRs (check `gh pr` history if needed)
3. **Write `ROADMAP-REVIEW-<NNN>.md`** (repo root, beside `ROADMAP.md`)
   with exactly these sections, scored against the four drivers:
   - `## Shipped` — the 10 items, one line each with merge commit
   - `## Quality` — suite size/pass trend, gates green?, new tests,
     flaky or order-dependent tests found, code-health notes
   - `## Stability` — CI reds + causes (infra flake vs real), e2e
     flakes, Windows/macOS specifics, retries/reruns used
   - `## Security` — security-relevant changes shipped, new attack
     surface or trust changes introduced, audit notes
   - `## Wow factor` — user-visible improvements, demo-worthy moments
   - `## Next horizon` — focus adjustments and concrete backlog
     candidates for the future (numbered `C-01`, `C-02`, … — do NOT
     renumber `ROADMAP.md`; the 1–200 list is locked by test)
   - `## Metrics` — items done/total, PRs merged, tests added, suite
     totals, wall-time observations if measured
   Be specific and evidence-backed. If a section has nothing to say,
   write "Nothing notable." — never invent.
4. **Quality gates** (same bar as feature work): ruff, black --check,
   pylint, mypy, bandit, full pytest. Docs-only diffs still run the
   full suite (regression gate).
5. **Commit, push, merge** exactly like `/roadmap` step 5 (PR, watch
   CI, squash-merge only on green, solo `--admin` bypass only when
   documented conditions hold, back to `main`).
6. **If stuck**, same rule as `/roadmap` step 6 (draft PR, report, stop).

## Rules

- One review per run. Never mix a review file with feature work.
- Review files are append-only history (`ROADMAP-REVIEW-050.md`,
  `-060.md`, …). Never rewrite past reviews.
- `ROADMAP.md` numbering stays exactly 1–200 (locked by
  `test_roadmap_has_200_numbered_items`). Future items live as
  `C-NN` candidates inside reviews until a v2 backlog is cut.
- Final report: review filename, per-driver highlights (2–3 bullets
  each max), PR number + merge commit.

$ARGUMENTS
