---
name: Roadmap Worker
description: Work through the auditless ROADMAP.md backlog one item at a time (implement, gate, test, PR, merge) or run milestone reviews
---

Project-specific worker for the `Greg-2600/auditless` roadmap loop.
Use when asked to continue the roadmap loop, work the next backlog
item, or run a milestone review. One invocation = exactly ONE
iteration (one item or one review), then end the turn.

Repo: `/Users/greg/Documents/Default Project/linux_health`
(source of truth for paths below; commands live in
`../commands/roadmap.md` and `../commands/roadmap-review.md`
relative to this skill's directory).

## Iteration

1. **Triage open PRs (unstick blockers first).** Run `gh pr list
   --state open`: finish or close your own leftover roadmap branch
   first (never leave two open); merge-conflicted branches get
   `origin/main` merged in (never rebase), pushed, and re-watched;
   red CI gets fixed per the 2-fix-round rule, or one
   `gh run rerun <run-id> --failed` for proven infra flakes; stuck
   pending checks get one rerun, then close + reopen. Never merge red,
   never force-push, never touch others' PRs unasked. Report every
   unstick action.
2. **Status.** Run `.venv/bin/python scripts/roadmap.py status`. If it
   reports roadmap complete, stop the loop with a final
   summary instead of working.
3. **Milestone check.** Run
   `.venv/bin/python scripts/roadmap.py milestone`. If it reports a
   milestone was just hit (done-count is a multiple of 10), run the
   `/roadmap-review` workflow this turn (see `../commands/roadmap-review.md`):
   write `ROADMAP-REVIEW-<NNN>.md` (Shipped, Quality, Stability,
   Security, Wow factor, Next horizon with `C-NN` candidates, Metrics),
   ship it through gates + PR, and end the turn.
4. **Otherwise work exactly ONE unchecked item** per
   `../commands/roadmap.md`: sync + branch
   (`roadmap/<NNN>-<slug>` from `main`), implement with proper tests,
   run all gates (ruff, black --check, pylint 10.00, mypy, bandit
   HIGH-only, full pytest, Selenium UI e2e), update docs, check the box
   via `scripts/roadmap.py mark <NNN>`, commit, push, open a PR, watch
   CI (`gh pr checks --watch --fail-fast`, up to 2 fix rounds),
   squash-merge ONLY on green (solo `--admin` bypass only under the
   documented conditions), back to `main`.
5. **If blocked** (red after 2 fix rounds, ambiguous requirement, or a
   gate that cannot pass unlowered): push the branch, convert the PR
   to draft, report clearly, do NOT merge, and stop the loop for
   human review.

## Rules

- One item (or one review) per run. Never batch, never merge red CI,
  never push `main` directly, never force-push.
- Never lower a gate or delete a failing test to make it pass.
- Keep diffs scoped (item + tests/docs + checkbox).
- `ROADMAP.md` numbering stays sequential 1–N (locked by test);
  future ideas live as `C-NN` candidates inside reviews.
- Typing everywhere (repo gate: mypy strict-ish on `linux_health/`;
  new test/script code fully annotated too).
- Final report: item number + title (or review filename), files
  changed, gate results, PR number + merge commit.

## Pacing

End every iteration by scheduling the next run **14400s (4 hours)**
later (user-ordered standing pacing). Only `stop_loop` (done or
blocked) ends the loop instead. In scheduler terms: call
`schedule_next_run` with `delay_seconds: 14400`, or `stop_loop`
with a short reason — never leave a turn without one of the two,
or the loop ends silently.
