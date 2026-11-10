# Security — How to Report a Vulnerability (SECURITY.md)

Manas Aegis is still **ALPHA / prototype** (v2.6.4-alpha). Vulnerability
reports help a lot — but please report them safely.

## How to report

Report via **GitHub Issues on this repo with the `security` label**.

Include:

1. What happened (steps to reproduce, as short as possible).
2. The plugin version and Hermes version you use.
3. What you expected to happen vs. what actually happened.
4. If relevant, a snippet of the argument/log — **after removing any
   secret, token, or personal data**.

## What you must NOT do

- **Do not test vulnerabilities on other people's systems or data.**
  Test only in your own environment.
- **Do not publish vulnerability details** (on social media, a blog,
  or a public issue without the security label) before a fix exists.
- **Do not include real secrets/tokens** in the report.
- **Do not use a vulnerability you found** to access, change, or
  damage anything.

## Policy

- **No bounty.** There is no monetary reward for vulnerability reports.
- Incoming reports are read by the maintainer; fixes are prioritised
  (the most dangerous vulnerabilities first).
- Known vulnerabilities already recorded in the CHANGELOG (the
  "Known, queued for R2" section) do not need to be reported again —
  unless you find a new variant or impact.

## Honest note on this plugin's security status

This plugin is a pattern-based guardrail, not standalone security.
Do not use it to protect secrets or production operations.

The issues that were listed as known in earlier versions are now
fixed: SSRF is fail-closed when DNS fails (since v2.6.0); chained git
commands are handled by a real shell parser (since v2.6.0); dangerous
`python -c` is detected through absolute paths and combined flags
(since v2.6.0, hardened in v2.6.2); paths are canonicalized and
symlinks are checked (since v2.6.0); and the HUD has CSRF protection,
rate limiting, and token authentication (since v2.6.0, always on
since v2.6.3 — a token is auto-generated when none is configured).

What remains true: the guard is pattern-based, so new bypass variants
may exist; telemetry stores redacted evidence fragments; and the HUD
is loopback-only with token auth off by default. Current limits are
listed in README.md (guard table) and CHANGELOG.md.
