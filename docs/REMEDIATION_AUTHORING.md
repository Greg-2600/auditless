# Remediation Authoring Guide

Fixes live in `linux_health/remediations.py` as `Remediation` entries.
A fix runs **only** after a user approves the exact rendered script, and
every apply is followed by an automatic verification rescan.

## Rules for a good remediation

1. **Idempotent.** Re-applying must be a no-op (guard with `grep -q`
   before appending, `cp -n` before backing up).
2. **Every privileged line is self-sufficient.** The runner pipes the
   approval password only to `sudo -S` invocations, and sudo timestamps
   do not reliably cross SSH exec channels — so each line carries its
   own `sudo -S`. Redirections must attach *inside* `sh -c` (never
   `echo | sudo` or heredocs on the sudo command itself: both steal
   sudo's stdin, so it reads data instead of the password).
2. **Validate before reloading.** Any service config change ends with a
   config test (`sshd -t`) and the reload must tolerate environments
   without systemd (`service ... || systemctl ... || kill -HUP ... || true`).
3. **Narrow matching.** `test_ids` + `match_item` must select exactly the
   finding the script fixes — never a sibling finding under a shared ID.
4. **Honest risk.** `safe` = file writes with no service impact.
   `service` = touches a running service; spell out preconditions (e.g.
   "key auth already works") because a bad sshd reload locks people out.
5. **Verifiable.** The fix must flip its check on rescan in the
   containerized e2e range (`tests/test_e2e.py`). If it cannot flip
   there (needs reboot, bare metal, absent tooling), say so in the
   description instead of shipping it.

## Anatomy of an entry

```python
Remediation(
    id="ssh-password-auth",          # stable slug for API/UI/tests
    title="Disable SSH password authentication",
    risk="service",                  # safe | service
    description="What it changes and how verification looks.",
    preconditions="Key-based auth already works for one account.",
    test_ids=["SSH-7408"],           # findings it may address
    match_item="PasswordAuthentication",  # substring of the check item
    script=[                        # the exact commands, in order
        "sudo cp -n /etc/ssh/sshd_config /etc/ssh/sshd_config.auditless.bak",
        "...",
    ],
)
```

## Checklist before opening a PR

- [ ] Dry-run (`GET /api/remediations`, propose endpoint) shows the script.
- [ ] Unit test: propose matches the finding; apply executes lines in
      order with `use_cache=False` (see `tests/test_remediations.py`).
- [ ] Live-fire: apply against the throwaway SSH target, rescan, and
      show the finding flip warn/fail → pass.
- [ ] Preconditions documented; `service`-risk entries reviewed twice.
