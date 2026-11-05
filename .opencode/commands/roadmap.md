---
description: Implement the next ROADMAP.md item end-to-end (code, gates, tests, docs, PR, merge)
---

Work through exactly ONE unchecked ROADMAP.md item, end to end.

Next item (from the helper — do not skip ahead):

!`.venv/bin/python scripts/roadmap.py next`

## Workflow

1. **Sync and branch.** `git fetch origin`, update local `main`, then create `roadmap/<NNN>-<short-slug>` from `main`. Worktree must be clean before branching (stash nothing — stop and report if dirty).
2. **Implement item N** plus proper tests (unit tests for new behavior; extend fixtures, not just happy paths). Follow `docs/REMEDIATION_AUTHORING.md` / existing module conventions for the area.
3. **Quality gates — all must pass, no exceptions:**
   - `.venv/bin/ruff check linux_health/ tests/ auditless.py`
   - `.venv/bin/black --check linux_health/ tests/ auditless.py` (run `black` to fix, then re-check)
   - `.venv/bin/pylint linux_health/ auditless.py --fail-under=10.0`
   - `.venv/bin/mypy linux_health/ auditless.py`
   - `.venv/bin/bandit -r linux_health/ auditless.py -q -lll`
   - `.venv/bin/python -m pytest tests/ -q` (full suite = regression gate)
   - `.venv/bin/python -m pytest tests/test_ui_selenium.py -q` (Selenium UI e2e:
     headless Chrome against live uvicorn; skips cleanly with no browser;
     asserts zero SEVERE console errors, history → report render, fleet table)
   - Fix failures properly. Never lower a gate, never delete a failing test to make it pass.
4. **Docs.** Update the relevant docs for the change, then check the box: `.venv/bin/python scripts/roadmap.py mark <NNN>`. Verify `scripts/roadmap.py status` advances by one.
5. **Commit, push, merge.**
   - Commit (pre-commit hooks run automatically — they must pass).
   - `git push -u origin roadmap/<NNN>-<slug>`, then `gh pr create --fill --base main`.
   - Wait for CI: `gh pr checks --watch --fail-fast` (generous timeout). If checks fail, fix on the same branch, push, and watch again — up to 2 fix rounds.
   - Merge only on green: `gh pr merge --squash --delete-branch`. If the
     repo ruleset reports `REVIEW_REQUIRED` with no second reviewer available
     (documented solo-dev bypass in `SECURITY.md`) and all checks are green,
     use `gh pr merge --squash --admin --delete-branch` and say so in the report. Confirm `git status` clean on the branch, then switch back to `main` and pull.
6. **If stuck** (red after 2 fix rounds, ambiguous requirement, or a gate that cannot pass without lowering it): push the branch, convert the PR to draft, report the blocker clearly, and do NOT merge. Do not start another item.

## Rules

- One item per run. Never batch multiple roadmap items into one PR.
- Never merge red CI. Never push to `main` directly, never force-push.
- Keep the diff scoped to the item (plus its tests/docs and the ROADMAP checkbox).
- Final report: item number + title, files changed, gate results (pytest passed/skipped counts), PR number + merge commit.

$ARGUMENTS
