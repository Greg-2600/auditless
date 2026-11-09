# Milestone Review — 050/200 (first review)

Date: 2026-11-09. Scope: boxes 41–48 (P1 checks) + 80 (UI e2e) + 177
(duplicate closure). Process/docs PRs in window noted, not scored.

## Shipped

- 41 — Sudoers.d auditing (`AUTH-9341`) — `02d8010` (#85)
- 42 — PAM faillock/pwquality (`AUTH-9350`) — `a931b34` (#86)
- 43 — sshd hardening directives, `SSH-7408` family — `c602986` (#87)
- 44 — Secure Boot + module signatures (`BOOT-5124`) — `2c2aa7a` (#99)
- 45 — Kernel livepatch, report-only (`KRNL-5790`) — `d642e5c` (#102)
- 46 — Extended sysctl pass (`KERN-5822`) — `04ab060` (#103)
- 47 — FIM database freshness (`FINT-4316`) — `230c804` (#104)
- 48 — USB device authorization (`USB-1000`) — `1473531` (#112)
- 80 — Selenium UI e2e harness — `56f24d6` (#45, earlier; box checked this window)
- 177 — `SECURITY.md` parameterization — closed as duplicate of item 20
  (box checked in #100, no separate diff)

No-box PRs in window: #96 (review process), #97 (worker skill),
#98 (PR triage step), #100/#101 (roadmap quality passes).

## Quality

- Suite: **737 passed / 16 deselected** (e2e deselected locally; was 704
  after item 45). New unit tests per item: 41/42/43 (classes
  `TestCheckSudoersDAuditing`, `TestCheckPamFaillock`,
  `TestCheckSSHConfigDirectives`), 44: 5, 45: 7, 46: 7, 47: 10, 48: 7.
- Gates green on every merge: ruff, black, mypy, pylint 10.00,
  bandit HIGH-only, full pytest + Selenium e2e in CI.
- Self-inflicted issues caught pre-merge by live runs and gates:
  duplicated `def` line (44), dropped PASS return (44), convoluted
  kpatch parsing (45), garbled thunk lambda (45), FIM schedule
  cross-talk between tools (47), USB soft-pass on `authorized_default=-1`
  with empty controls (48). All fixed before ship; black drift fixed
  twice. Pattern: live-container proof runs earn their keep.
- No flaky or order-dependent unit tests found. Unique mock hostnames
  per test (cache cross-talk rule) held up.

## Stability

- CI reds in window, all resolved without spec changes:
  - #101 e2e: `docker pull lscr.io/...` failed at setup (16/16 ERROR).
    Proven registry-flake class → one policy rerun → green.
  - #104 e2e: 15/16 green; `test_api_password_scan_persisted` failed on
    transient SSH "Unable to open channel" at connect time (no FIM code
    path on bare targets — no extra commands issued). One rerun → green.
  - #112 watch opened with "no checks reported" (queue delay); all
    green once queued.
- Matrix (Ubuntu/macOS/Windows × py3.11/3.12) green throughout.
- Dependabot action merges landed on `main` mid-window; worker branches
  rebased cleanly, no conflicts.

## Security

- Eight checks added/extended, all read-only over SSH (no new attack
  surface): sudoers `NOPASSWD` scope, PAM deny/lockout, sshd
  AllowUsers/MaxAuthTries/GraceTime/ClientAlive, Secure Boot +
  `module.sig_enforce`, livepatch (never FAILs, contract-tested),
  extended sysctl (unprivileged BPF, userns, forwarding, SYN cookies,
  perf paranoia ≥2), FIM DB freshness (presence alone no longer
  passes), USB authorization (kernel default-deny / USBGuard / UDISKS).
- Honest-unknown discipline held: absent livepatch tooling, zero
  readable sysctl keys, and unreadable FIM signals all report `unknown`
  (excluded from scoring) instead of false passes. `-1`
  `authorized_default` correctly treated as default-allow.
- IDs: `BOOT-5124`, `KRNL-5790`, `KERN-5822` registered; `USB-1000` and
  `FINT-4316` extended in place (CIS mappings unchanged or honestly
  partial: `KERN-5822` → CIS 3.2 partial).

## Wow factor

- Boot/Kernel matrix row grew 2 → 5 controls; Hardware row 1 → 2.
- Live runs caught real findings on stock containers
  (`userns_clone=1`, `authorized_default=-1` with visible devices) —
  the checks visibly work, not just pass.
- FIM freshness and USB authorization close two "installed ≠
  protected" gaps competitors hand-wave over.
- Nothing demo-packaged this window (demo env/video remain items
  193/194).

## Next horizon

- C-01 — Remediation entries for the new checks (udev rule for
  `authorized_default=0`, `aideinit`/`tripwire --init` + schedule
  guidance, USBGuard baseline policy). Feeds item 101.
- C-02 — Investigate e2e "Unable to open channel": does item-24 retry
  cover channel-open failures, or only connect/auth? One failed run is
  a hint, not evidence — do not change code without a repro.
- C-03 — `authorized_default=-1` fleet note: stock kernels report the
  unset marker, so most fleets will warn on USB until hardened. Call
  this out in docs when item 48's area is next touched.
- C-04 — Make the 90-day FIM DB-age threshold profile-configurable
  instead of hardcoded.
- C-05 — Correlate livepatch-active with reboot-required (`KERN-5830`):
  a livepatched host pending reboot is less urgent than one without.
- Focus: items 49–60 finish the P1 check wave; review at 60 should
  weigh cutting the v2.6.0 platform slice (61–79 subset).

## Metrics

- 50/200 done. Feature PRs merged this window: #85, #86, #87, #99,
  #102, #103, #104, #112 (8) + #45 (e2e, earlier commit).
- ~50 new unit tests across items 41–48; suite 704 → 737 measured.
- e2e green on all 8 PRs (2 needed one policy rerun each).
- Wall time per item PR (implement → merge): same-day; CI ~4–8 min
  per PR including matrix + e2e.
