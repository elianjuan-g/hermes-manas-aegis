# Contributing — Manas Aegis (CONTRIBUTING.md)

Thank you for helping. This plugin is still ALPHA, so the rules below
matter — they are what keep our claims honest.

## How to contribute

1. Read README.md first — especially the guard table and the
   "What it does NOT prevent" section.
2. Make small changes, focused on one thing.
3. Include tests when you change code behaviour.
4. Update README.md / CHANGELOG.md when your change alters any
   behaviour, limit, or claim.
5. Submit your change as a pull request explaining: what changed,
   why, and what evidence (tests / run results).

## Claim rules (mandatory)

- **Every claim must point at code + a test.** Do not write a
  security claim ("prevents X", "blocks Y", "N standards enforced")
  without naming the file + line of code that does it and the test
  that proves it.
- **Do not invent numbers or untested versions.** Do not write a
  standards count, active-rule count, supported Hermes version, or
  test result without repeatable run evidence.
- **State status honestly:** `implemented` (real enforcement in the
  hook path, proven by tests), `experimental` (code exists but is
  pattern-based/partial, with known bypasses), `planned` (only
  defined, without enforcement), `not supported` (does not exist at
  all). Do not raise a status without evidence.
- **Do not use exaggerated language:** avoid "absolute defense",
  "complete protection", "system patch", "live feed", or "CVE" for
  internal IDs (`HERMES-SEC-...` are not public CVEs).

## How to run the tests

Run the tests from the repo root:

```sh
python3 -m unittest discover -v
```

There are currently **99 unit tests** (83 from v2.6.2: 61 base + 22
new in v2.6.2 + 11 new in v2.6.3 + 5 new in v2.6.4) and all of them **pass (99/99)**,
verified 2026-11-10. Do not hide test failures: if your run is not
green, write the real result in the PR. When you add a guard or change
a pattern, add tests for: normal input, bypass/edge cases, and failure
conditions (e.g. failed DNS, corrupt state file).

## What we do not accept

- Changes that introduce a claim without evidence (see "Claim rules"
  above).
- Code that probes vulnerabilities in other people's systems.
- Paid dependencies or services that require a new account/key
  without prior discussion.
- Large changes without a prior issue/PR discussion.

## Reporting a security vulnerability

Not via pull request. See SECURITY.md — report via GitHub Issues
with the `security` label.
