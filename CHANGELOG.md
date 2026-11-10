# Changelog — Manas Aegis

All important changes to this plugin are recorded here. The format
loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions use `MAJOR.MINOR.PATCH` + the `-alpha` label while the
plugin is still a prototype.

## [2.6.4-alpha] — 2026-11-10

Load failure on real Hermes 0.21.5, found by a live-discovery test (the
v2.6.3 self-verdict missed it: `hermes plugins validate` probes
`register()` with a permissive mock context, and the HUD still served
because its server starts before the failing call). Two fixes, both
verified by new contract tests and a live-discovery test on real
Hermes 0.21.5.

### Fixed

- **`register_tool` now uses the real signature.** Both tool
  registrations called `ctx.register_tool(name=..., description=...,
  parameters={...}, handler=...)` — no `toolset`, no `schema`, and
  `parameters=` is not a keyword the real `register_tool(name,
  toolset, schema, handler, ...)` accepts. On real 0.21.5 discovery
  that raised `TypeError` and the loader discarded ALL of the
  plugin's registrations (hooks included), so the plugin failed to
  load while looking alive. Both calls are now the single form
  `register_tool(name, toolset="hermes_manas_aegis",
  schema={"name": ..., "description": ..., "parameters": {...}},
  handler=...)`, with the JSON Schemas byte-identical to before.
- **Tool handlers now unwrap the arguments dict.** Core calls
  handlers as `handler(args_dict, **kwargs)`, but
  `tool_manas_tactical_core(action="status")` and
  `tool_manas_stix_intelligence(view="stix_feed")` took the value as
  a plain string parameter — so a model call bound the whole dict to
  `action`/`view` and the tool silently returned the default branch
  for every call (`barrage` and `matrix` could never run). Two thin
  wrappers (`tool_manas_tactical_core_handler`,
  `tool_manas_stix_intelligence_handler`) read the value out of the
  dict and forward it; they are the registered handlers now. The
  bare functions are unchanged — the `/manas-hud`, `/manas-barrage`,
  and `/manas-stix` slash commands still call them directly with
  kwargs.

## [2.6.3-alpha] — 2026-11-10

Revision on the catalog maintainer's review of PR #151504 at commit
`cc182958` (teknium1, CHANGES_REQUESTED). Seven fixes, all verified
by tests (94/94) and a real-HTTP HUD harness (17/17, `e2e-hud.py`).

### Security — fixed

- **Plugin root shim uses a relative import.** `__init__.py` now does
  `from .hermes_manas_aegis import ...` instead of the absolute
  import, so the plugin loads when Hermes mounts the plugin directory
  as a package without putting it on `sys.path`.
- **RCE pattern no longer has unbounded lazy segments.** The two
  `.*?` gaps in the `python3 -c` branch are now `[^\n]{0,256}?`, the
  pattern searches are capped at the first 8 KB of serialized
  arguments, and a 40 KB near-miss input is now checked in ~0.1 s
  (the reviewer measured 2.2 s on a ~9 KB input). A payload hidden
  past 8 KB is not scanned by these patterns — a documented trade-off.
- **Credential-file contents are never read.** Config integrity now
  uses `os.stat` fingerprints (size + mtime_ns + inode) instead of
  SHA-256 of the file contents, and the filesystem scan skips
  `.env`, `auth.json`, and `config.yaml` entirely. Same-size content
  changes are invisible to the fingerprint by design (a same-size,
  same-mtime rewrite is indistinguishable from no change) — a changed
  size or mtime is still detected.
- **HUD: Host check + login always on.** Requests whose `Host` header
  is not `127.0.0.1:<port>` or `localhost:<port>` are rejected (403).
  The CSRF token is no longer embedded in an unauthenticated GET —
  the dashboard is only served after login. When no `hud_auth_token`
  is configured, one is generated once on first run and stored in the
  state directory (`hud_auth_token.txt`, mode 0600).

### Changed

- **Manifest declares top-level `provides_tools` / `provides_hooks`.**
  `hermes plugins validate` (and the loader) read only those
  top-level lists — the nested `provides:` block was invisible to
  the validator, so the registered tools and hooks were reported as
  "undeclared" and validation failed on v2.6.2 and v2.6.3 alike.
  Both lists now exist (kept in sync with the nested block).
- **Detection patterns are plain readable raw strings.** The five
  detection patterns (SQLI, RCE, CONFIG_HOOK_POISON,
  MEMORY_DIRECTIVE_POISON, XSS) are now `re.compile(r"...")`
  literals instead of base64 blobs — same matches (verified by
  sample-equivalence tests), except the RCE bound segments above.
  `PROTECTED_FILES` and `SAFE_GIT_PREFIX` remain base64-encoded
  path/command literals, not detection patterns.
- **Detection/test vectors live in a JSON fixture.** The arena
  scenarios, the `python -c` dangerous-token list, and the two
  scanner-flagged test payloads moved from code literals to
  `fixtures/vectors.json` (loaded by `load_vectors_fixture()` at
  import; a missing or malformed fixture raises instead of running
  with an empty corpus). Payloads are byte-identical to the
  literals they replace — verified by round-trip plus the
  unchanged 94-test suite and a 10/10 arena. The install-time
  scanner treats a `fixtures/` tree as inert test data, so
  `hermes plugins validate` no longer flags the plugin's own
  corpus. Historical payload examples in
  `docs/history/phase0-verification.md` now reference the fixture
  instead of quoting them.
- **Desktop HUD uses `SandboxedFrame` + port from config.**
  `desktop/plugin.js` renders the HUD with the SDK `SandboxedFrame`
  (opaque origin, `allow-scripts`) instead of a raw iframe, and reads
  the port from the plugin's `hud_port` config via the
  `plugins.manage` list RPC instead of hardcoding 18777. Because the
  frame's opaque origin has no cookies/storage, login stays token-in-
  page (after login) rather than a cookie-based CSRF double-submit.
- **State lives under `plugin-data/`.** All state (telemetry,
  archive, scan state, baseline, intel cache, custom rules, HUD
  token) now lives in
  `<hermes home>/plugin-data/hermes-manas-aegis/`, resolved via
  `plugin_data_dir()` when available and `get_hermes_home()` as
  fallback. State from the old locations is copied over on first run
  and never deleted.

## [2.6.2-alpha] — 2026-11-09

Revision on Argon's audit of v2.6.1 (researched and corrected by Ciel;
Argon's line numbers were not used — every finding was re-located with
grep). Nine fixes: three P1 (shell parser, recursive argument
inspection, SSRF), three P2 (packaging, HUD threading/locking/atomic
writes, clear-history + config schema), three P3 (dead sound button,
intel loading indicator, documentation cleanup).

### Security — fixed

- **Shell parser: subshells/backticks/newlines no longer fragment the
  check.** `$(...)` and `` `...` `` are now tracked (separators inside
  them no longer split segments), and `\n` is a separator — so
  `$(curl ... | sh)` and `echo ok\nrm -rf /tmp/x` no longer slip
  through fragmentation. Dangerous `python -c` is now also detected
  via `python3.11`, absolute paths, and combined flags
  (`python3 -u -c`, `python3 -X utf8 -c`); `from os import system`
  is blocked too.
- **The RCE pattern now matches `rm -rf` to any absolute path**
  (`rm -rf /tmp/x`, `rm -rf /`, `rm -fr`, `rm -r -f`, `--recursive
  --force`, plus `$(rm -rf /)` and backtick forms). Previously the
  pattern demanded `/` followed by a space/end/`*`, so `/tmp/x`
  slipped through. New `sh $(curl ...)` / `` sh `curl ...` `` (and
  `eval`) forms are blocked too.
- **Argument inspection is now recursive.** Credential paths inside
  nested dicts/lists are checked (previously top-level only), and
  `~` is expanded before canonicalization — `~/.../.hermes/auth.json`
  no longer slips through.
- **SSRF: multicast + unspecified blocked** (IPv4/IPv6, literal and
  DNS-resolved); URLs are extracted with trailing JSON punctuation
  stripped so a public host is not blocked because of `},`;
  `scp`/`rsync`/`ssh`/`nc`/`dig`/`nslookup` (and `sftp`/`ftp`)
  now count as egress for taint gating.

### Fixed

- **Packaging: `MANIFEST.in` + `data-files`.** The sdist and wheel now
  carry `plugin.yaml` + desktop assets (`desktop/plugin.js`) +
  honeypot decoys — verified from the contents of the built archives.
- **HUD: `ThreadingHTTPServer`** (was single-threaded);
  `reload_state()`/`_save_events()`/`_save_scan_state()`/
  `clear_all_history()` now use the existing lock; state writes are
  atomic (temp file + rename).
- **"Clear history" now also deletes scan findings**
  (`scan_findings` + `scan_state.json`), as the README already
  promised. The `MANAS-CALLID-RACE` strategy in the catalog changed
  from `SYNTHESIZE_PATCH` to `HARD_BLOCK` (matching real behaviour).
  Five R3 config keys were added to `plugin.yaml`
  (`taint_ttl_minutes`, `ssrf_allowlist`, `callid_race_window_s`,
  `callid_race_enabled`, `hud_auth_token`).
- **Sound button removed.** The button was dead (it only flipped
  `localStorage`; there is no audio at all in the HUD) — removed
  together with its i18n keys rather than kept as decoration.
- **The "Refresh intel" button now shows a loading state**
  (disabled + "Updating intel…" label while the fetch runs).
- **Documentation cleaned up:** the "8 experimental + 2 planned"
  claim removed (10/10 enforced since v2.6.0); CSRF/rate-limit
  contradictions straightened out (CSRF + rate limit + opt-in token
  auth are indeed active); stale SSRF fail-open text removed from
  the README, code comments, and rule explanations; `CONTRIBUTING.md`
  now states the real test count.

## [2.6.1-alpha] — 2026-11-09

Small revision on MyLord's complaint (HUD screenshot): the Posture
Score card appeared on EVERY tab and took too much space.

### Fixed

- **The Posture Score card is now only on the Activity tab.** Root
  cause: the card was rendered in the shared `<main>` flow before the
  tab panels, so the tab switcher (which only hides `.panel`) never
  hid it. The card moved inside the `tab-act` panel.
- **The card became a minimal box (`.posture-mini`).** A 44px score +
  five full rows became one compact row: 26px score + grade on the
  left, five components as small chips (label + 70px bar + value) on
  the right. Padding 12px, much smaller total height.
- **All Activity content is now inside its own tab.** KPIs, history
  lines, the "What is monitored" card, and the "Scan" card also moved
  into the Activity panel (previously in the shared flow, so switching
  tabs changed nothing on screen). Each tab now shows fully different
  content.
- **180ms fade transition** when the active panel changes (rise 4px +
  fade), so tab switching no longer feels stiff.

### Notes

- Tests: unit + contract 61/61, e2e R3 26/26, e2e posture-mini 17/17.

## [2.6.0-alpha] — 2026-11-09

R3 revision (on MyLord's order: "How do we make the score 10 in
everything" + "I need the best guard among all of them"). Ten
features to close the enforcement gaps proven by the REVISI.txt
verdict and competitor research (llm-antidote ~82, blackbox ~78).
The maturity dimension stays honestly at 7–8: catalog PR #151504
must be merged by Nous + real users first — that is outside the
code's control.

### Added

- **Taint tracking (per session).** A credential-file access (deceived
  to the honeypot or blocked) marks the session as tainted (60-minute
  TTL, in-memory only); the next egress from the same session is
  hard-blocked (MANAS-CRED-HONEYPOT). Simulation never marks taint.
- **A real shell parser** replaces regex for chained commands:
  separators `;` `&&` `||` `|` `&` (respecting quotes + escapes);
  each segment is checked on its own — dangerous `python -c` is
  blocked per segment, git subcommands are rewritten per segment.
- **SSRF fail-closed + allowlist.** A failed DNS now blocks (was:
  treated as SAFE). `ssrf_allowlist` in configuration exempts named
  hosts.
- **MANAS-SYMLINK-GUARD enforced.** Arguments are canonicalized
  (`Path.resolve`); reads pointing at protected files are redirected
  to the honeypot decoy. Status planned → experimental.
- **MANAS-CALLID-RACE enforced.** Identical runtime calls (session +
  tool + same argument hash) within 10 seconds are hard-blocked.
  Status planned → experimental. The window is configurable
  (`callid_race_window_s`). Simulation is exempt.
- **Posture Score (0–100 + grade A–F)** in the HUD: rules 25 +
  enforcement 25 + hygiene 20 + intelligence 15 + activity 15.
- **Guard Arena.** 10 attack scenarios (text only, never executed)
  run on a disposable core through the runtime enforcement path;
  results stored (`arena_last.json`) and shown in the Arena tab.
- **Time-travel audit.** Re-check of stored runtime events: events
  that would only now be caught by the R3 mechanisms are marked
  "newly caught". A pattern-based audit over stored evidence (not a
  full replay — telemetry does not store "allow" events).
- **HUD hardening.** CSRF token on all POSTs (header
  `X-CSRF-Token`); rate limit 20 POST/IP/60 seconds (HTTP 429);
  opt-in token auth (`hud_auth_token`) + login page + 24-hour
  HttpOnly session cookie (off by default — the HUD is loopback-only
  inside the Desktop iframe).
- **CI + contract tests + coverage gate.** `.github/workflows/ci.yml`
  (Python 3.11/3.12): unit + contract tests, 70% coverage gate
  (measured 79% in v2.6.0). `tests/test_contract.py`: plugin.yaml
  version == pyproject == codename, required catalog fields,
  `register()` registers all declared hooks + tools, HUD render,
  hardening constants, zero non-stdlib dependencies.

### Changed

- **All 10 rules are now experimental** (no more planned).
  `rules_enforced` in posture: 8 → 10.
- **i18n: 159 → 180 keys** per language (21 new keys: posture 6 +
  arena 11 + time-travel 4), 15 languages complete, 0 mismatch.
- **Rule explanations (RULE_EXPLAIN)** for SYMLINK-GUARD,
  CALLID-RACE, and SHELL-RCE updated to R3 enforcement status.
- **README:** bypass table updated (git chaining, `python -c`,
  SSRF fail-open, symlink — all fixed); new Posture Score / Arena /
  time-travel / HUD hardening sections.

### Fixed

- **Simulation sub-counts** now use the same substring matching as
  the summary (correct since R2.5.1; R3 tests lock the value
  (4, 2, 1) = 7 events from 6 barrage inputs).
- **`get_last_simulation()`** no longer cuts a run at 6 events —
  one input can produce several events (the git vector now produces
  2 modifies).

### Tests

- **Unit + contract: 61/61 passed** — 38 old + 16 new R3 (taint,
  shell parser, SSRF fail-closed + allowlist, symlink, call-ID race,
  posture score, arena 10/10, time-travel, CSRF/posture/arena in the
  HUD, key count 180) + 7 contract tests.
- **Real-HTTP e2e: 26/26 passed** (`/tmp/e2e-r3.py`): CSRF 403/200,
  arena 10/10, time-travel, barrage 6 results, rate limit 429 on the
  21st POST, token auth (login 401/302 + session cookie + HUD 200).
- **Coverage: 79%** (core 80%, i18n 100%, threat_intel 86%).

### Honest notes

- **Maturity stays 7–8, not 10.** The catalog PR must be merged and
  real users must use this plugin first.
- **Packaging (wheel/sdist carrying plugin.yaml + desktop assets)**
  still open from Phase R2 — not one of the 10 R3 features.
- **Arena scenario `arena-ssrf-dns-fail` removed** from the 10
  scenarios (not deterministic: DNS in the VM always resolves via
  the egress proxy to 198.18.x.x); fail-closed is tested by a unit
  test with a mocked `socket.getaddrinfo`.
- **Translations of 21 new keys × 13 non-en/id languages** written by
  Ciel (not a native speaker) — same pattern as R2.5.2.

## [2.5.2-alpha] — 2026-11-09

R2.5.2 revision (on MyLord's report: the language feature is good but
not even — in English mode, the Findings tab still showed Indonesian,
and vice versa). Four sources of unevenness, all fixed.

### Fixed

- **Scan finding titles + details were hardcoded Indonesian.** 15
  finding titles + 15 details (in `run_scan` and `_scan_filesystem`)
  are now stored key-based (`title_key`/`detail_key`/`params`) and
  rendered per language in the HUD. English text is stored as a
  readable fallback in the raw JSON. Total i18n keys: 115 →
  **159** (41 finding/check/file/level keys + 3 NVD severity words).
- **"File" header hardcoded English.** Now the `findings_file` key
  ("File" / "Berkas" / etc. in 15 languages).
- **Check names = raw English IDs.** Now translated labels
  (`check_config_integrity` → "Config integrity" / "Integritas
  konfigurasi", etc. for 9 checks).
- **Intel level labels = raw English data.** The CISA level
  "Actively exploited" and NVD levels "9.8 CRITICAL" are now
  translated (the numeric score is kept, the severity word is
  translated: "9.8 Kritis" / "7.5 Tinggi" / "5.0 Sedang" /
  "2.1 Rendah").
- **Old findings (37 rows) migrated too.** Findings stored before
  v2.5.2 (Indonesian titles, no keys) are mapped on load
  (`_migrate_old_finding`, 15 title patterns) so they also show in
  the HUD language — not stuck in Indonesian.
- **A finding cell shows title + detail.** The Detail column now
  shows the finding title (bold) + detail (dimmed) — previously only
  the detail, so the title was never visible.

### Notes

- Translations for 13 languages besides en/id written by Ciel (not a
  native speaker) — same as previous i18n keys.
- **Unit tests: 38/38 passed** — 33 old + 5 new R2.5.2 (159-key
  completeness, full en+id finding rendering with no cross-leak,
  old-finding migration, intel level labels, key+English fallback).
  **E2E: 32/32 passed** (real HTTP: en+id finding rendering,
  Berkas/File header, check names, migration, intel levels).

## [2.5.1-alpha] — 2026-11-09

R2.5.1 revision (on MyLord's report + screenshot: the simulation had
already run but the KPI cards still showed 0; Quick Scan "didn't go
into browse/library"). Two bugs + one integration not yet proven.

### Fixed

- **Simulation sub-counts 0/0/0 (BUG).** The KPI cards computed
  simulation sub-counts with exact matching (`verdict == "BLOCK"`),
  but the real verdict strings are `"HARD_BLOCK"`,
  `"SYNTHESIZED_PATCH (Modify Args)"`, and
  `"HONEYPOT_DECEIVED (Modify Args)"`. Result: MyLord's 12 simulation
  events (8 blocked, 2 modified, 2 deceived) read as 0/0/0.
  Now uses the same substring matching as `get_last_simulation()`
  and the posture counter (`"BLOCK" in verdict`). The "Last
  simulation" summary was already correct (substring matching) — only
  the per-card sub-counts were wrong.
- **Scans not leading to results (UX).** After a Quick/Full/Network
  scan, the page only reloaded on the Activity tab, so findings were
  hidden in the Findings tab and MyLord thought the scan had not run.
  Now after a successful scan the page moves to the Findings tab
  (`?tab=find`, kept in the URL; the server renders the requested
  tab, falling back to Activity for an unknown parameter). Search
  stays on the Activity tab (hidden input `tab=act`).

### Added

- **Real-data path proven.** `intercept_tool_call` has
  `event_source="runtime"` (the default) — the same path Hermes uses
  when an agent actually calls a tool. Tested directly on the PC (not
  a simulation): 1 destructive shell call blocked (HARD_BLOCK), 1
  argument modified, 1 credential redirected to the honeypot. All
  three were recorded as REAL events (source=runtime) and raised the
  KPI cards. Further real data appears automatically whenever a Hermes
  agent calls a tool — the plugin cannot "detect" a tool that is never
  called.
- **Cross-process integration (reload_state).** The HUD server is a
  long-lived process, but events are also written by other processes
  (a Hermes agent intercepting real tools, scans from another
  session). Previously the HUD only loaded state at startup — real
  events from another process did not appear until the server was
  restarted (proven during the real-intercept test: 3 real events
  written to file, HUD still showing 12). Now `core.reload_state()`
  is called on every GET, so the page always reflects what is on disk.
- **Unit tests: 33/33 passed** — 28 old + 5 new R2.5.1 (simulation
  sub-counts with real verdict strings incl. reproduction of MyLord's
  telemetry 12 events → 8/2/2, tab parameter, scan redirect,
  cross-process reload_state). **E2E: 21/21 passed** (real HTTP:
  non-zero simulation sub-counts totalling 6, tab=find, scan →
  Findings, real intercept → real counter > 0, second process writing
  an event → HUD showing it without a restart).

## [2.5.0-alpha] — 2026-11-09

R2.5 revision (on MyLord's order: "UI-UX shouldn't be AI slop, go look
for a design on Figma or somewhere, use a professional one" + "add dark
and light themes"): the HUD was redesigned from the C3iHub CISO
dashboard design system (IIT Kanpur, 2024 — an enterprise security
platform actually shipped to clients, not a Dribbble concept), plus
dark + light themes. **Function did not change** — only the visual
layer changed (colours, typography, layout, icons).

### Added

- **Dark + light themes.** Theme button at top right (sun/moon icon,
  Lucide SVG). Choice stored in the browser (`localStorage
  'manas-aegis-theme'`) and applied before first paint (no flash).
  Default: dark. The light theme uses the same tokens (same severity
  hues, darkened for contrast on white; action blue stays #0168FF).
- **Professional SVG icons (Lucide, ISC).** All emoji icons in the HUD
  (🔊 ▶ 🔍 ◆) replaced with inline SVG (shield, activity, search,
  play, volume, refresh, scan, trash, sun, moon — 24px grid, stroke 2,
  currentColor), per MyLord's standing icon order.

### Changed

- **New design system (reference: C3iHub CISO dashboard).**
  Dark slate page #2A2C38, cards #1E1F27, sidebar #1F1F3B, action
  blue #0168FF, selected nav #2F2263. One severity scale everywhere:
  Critical #F53821, High #FF9B10, Medium #FFCE20, Low #00D796,
  Informative #80CAFF — used on KPI cards (left accent line), source
  badges, finding severity badges, and intel level badges. Strong
  colours only for meaningful things; blue only for actions.
- **Professional typography.** The UI uses system sans-serif (Inter/
  Segoe UI); monospace only for data values (timestamps, IDs,
  evidence). Neon cyan (#00f5d4) and deep black background (#040811)
  removed — both hallmarks of a "generic AI dashboard".
- **Sidebar layout.** Navigation (Activity / Threat intel / Findings)
  moved to a fixed left sidebar (like a real SOC dashboard);
  main content max-width 1120px. On narrow screens (<760px) the
  sidebar collapses to a top bar. Tables wrapped in cards (radius +
  border), small-caps headers, row hover, severity badges with dot +
  label (not colour alone — accessible for colour blindness).
- **Unit tests: 28/28 passed** (6 V22 + 6 R1 + 11 R2 + 5 new R2.5).
  **E2E: 36/36 passed** (real HTTP: themes + design + all R2 flows).

## [2.4.0-alpha] — 2026-11-09

Phase R2 revision (on MyLord's requests, one by one from chat):
HUD i18n (English default, 15 languages), persistent visible
simulation, user-addable/editable custom rules, scans (quick/full/
network) + Findings tab, unlimited history + search, information-rich
empty state, and real-time global threat intelligence + lay/professional
explanation column. **Guard decisions (block/modify) did not change** —
what changed was language, visibility, and the tools around them, not
the blocking logic.

### Added

- **HUD i18n (15 languages, English default).** `hermes_manas_aegis/i18n.py`:
  English, Indonesian, Spanish, French, German, Portuguese, Italian,
  Russian, Turkish, Arabic, Hindi, Chinese, Japanese, Korean,
  Vietnamese. Language menu at the top right of the HUD; choice stored
  in the browser; `?lang=` in the URL also supported; unknown languages
  fall back to English. Rule names, advisory IDs, and CWEs are not
  translated. Lay/professional explanations are available in English +
  Indonesian; other languages show the English explanation.
- **Persistent visible simulation.** The last simulation summary
  (time, how many of 6 examples matched, how many blocked/modified/
  redirected) is now stored and shown in the HUD — no longer lost on
  page reload. Each KPI card also shows its simulation sub-count
  (`simulation: N`). The big cards still count **only real activity**
  — simulation never inflates real numbers (that was a v2.2.0
  dishonesty fixed in R1 and kept here).
- **Custom rules.** File `~/.hermes/manas-aegis-custom-rules.json`
  (in the home directory, not the plugin directory, so it is not
  deleted on reinstall): `rules[]` (new rules, `rule_id` must start
  with `CUSTOM-`) and `overrides{}` (replacing the main patterns of
  MANAS-SQLI-AST, MANAS-SHELL-RCE, MANAS-CONFIG-FIM,
  MANAS-MEM-FIREWALL). Full validation on load (regex must compile,
  `test_positive`/`test_negative` must pass, overrides of unknown
  rules are rejected); invalid entries are rejected and logged as
  errors — the plugin never dies because of a broken rules file.
  Valid custom rules really run in the engine and appear in the HUD
  catalog with a "custom" badge.
- **Scans (quick / full / network) + Findings tab.**
  Quick: config integrity vs the persistent baseline
  (`cce_baseline.json`), honeypot decoys, custom-rule validation,
  telemetry backstop, rule self-test. Full: quick + content scan of
  files in `~/.hermes` (prompt-injection patterns, zero-width
  characters, secrets outside known credential files, token-bomb
  heuristics; max. 300 files / 1 MB per file; plugin directories
  skipped). Network: **only** the plugin's own network posture (HUD
  loopback, state-file permissions, SSRF posture) — **not** a port
  scan and **not** a LAN/internet scan. Findings are stored
  (`scan_state.json`, max. 50, duplicates merged) and shown in the
  Findings tab — that is this plugin's "notification"; there is no
  push channel.
- **Unlimited history + search.** The 120-event cap is **removed**.
  The live file stores the newest 500 events (so the HUD loads fast);
  older events move to an append-only archive
  (`manas_telemetry_archive.jsonl`) that the plugin never deletes —
  except via "Clear history" (which also deletes the archive). A
  search box on the Activity tab + endpoint `/api/search?q=...`
  searches live history and the archive.
- **Information-rich empty state.** When there is no real activity
  yet, the empty panel now shows the version, connection status,
  rule count (experimental + custom + planned), custom rules, last
  simulation, last scan, and how to produce activity — not just one
  sentence.
- **Real-time global threat intelligence.** Fetched automatically from
  **CISA KEV** and **NVD CVE API 2.0** (both free, no key, official),
  local cache `threat_intel.json` (max. 40 items), automatic refresh
  every 10 minutes if the cache is older than 6 hours + a "Refresh
  intel" button. Without internet, the old cache stays displayed and
  the HUD clearly writes that the data may be stale. Shown as
  **global awareness** — the plugin does NOT check whether this device
  is affected.
- **Explanation column in the rule catalog.** Every rule has a
  two-level explanation: "For everyone" (plain language) and "For
  security professionals" (patterns/triggers and their limits).

### Changed

- **HUD default language: English** (was Indonesian).
  R1 tests that assumed Indonesian now call the HUD with `lang="id"`
  explicitly.
- **The config baseline is now persistent** (`cce_baseline.json`) and
  **re-compared** by quick scan — the MANAS-CONFIG-FIM row in the
  README updated (still not real FIM: no real-time monitoring).
- **"Clear history" now also deletes the archive** (live + archive +
  STIX feed), not just the live file.
- **Unit tests: 23/23 passed** (6 V22 + 6 R1 + 11 new R2).
  **E2E: 27/27 passed** (real HTTP: default English, `?lang=id`,
  unknown-language fallback, barrage → persistent summary, search,
  scans, intel refresh, clear history).

## [2.3.0-alpha] — 2026-11-09

Phase R1 revision: claims straightened out, alpha labelling,
operational documentation, honest HUD UI, telemetry redaction,
separation of simulation events. **Guard decisions (block/modify) did
not change** — what changed was the honesty of labels/numbers and how
data is recorded and displayed, not the blocking logic.

### Changed

- **Alpha label.** The plugin is now clearly labelled ALPHA/prototype
  in README.md (first line), `plugin.yaml`, and `pyproject.toml`
  (version 2.3.0). Opt-in warning + non-sensitive test-environment
  notice written up front.
- **Claims straightened out.**
  - Removed: "Absolute Defense", "Autonomous Threat-Synthesis Core"
    as a security claim, "10 runtime rules" without distinction,
    "standards enforced" (a static value in code, not an inspection
    result — the old README itself only named ~12 frameworks),
    "TAXII LIVE" (no TAXII transport — only a local STIX 2.1 bundle),
    and "Virtual Patching Engine" as a system patch (what it does is
    only rewrite the arguments returned to Hermes).
  - Removed: the "Dual-Layout Compatibility (Hermes 0.21.x & 0.23.x)"
    and "validate/doctor pass cleanly" claims — no integration evidence
    in the repo supported them. Replaced with what was actually
    tested: Hermes 0.21.5 on the PC; 0.23.x NOT tested.
  - The `stix-taxii` tag in `plugin.yaml` replaced with `stix-local`.
  - The `tactical_doctrine` description fixed: `ssvc_enforce` and
    `stealth_audit` have no behaviour at all in code (only enum
    values; no SSVC gate anywhere) — the only doctrine branch is
    `counter_deceive`; other doctrines make CRED-HONEYPOT fall
    through to HARD_BLOCK.
- **README rewritten from scratch** (README.md): plain language,
  "what it DOES / does NOT prevent" sections, a 10-guard table
  (threat, trigger, action, status, bypass limits, recorded data),
  how to install, enable/disable, configure, verify success,
  troubleshooting, uninstall/rollback, stored data, tested Hermes
  versions, and a glossary.
- **Guard status stated honestly:** 0 implemented, 8 experimental,
  2 planned (MANAS-SYMLINK-GUARD and MANAS-CALLID-RACE only defined
  in the catalog, without enforcement).
- **New documents:** SECURITY.md (how to report a vulnerability, no
  bounty), CHANGELOG.md (this file), CONTRIBUTING.md (claim rules +
  how to run tests).

### Implemented in code (not just in documents)

- **HUD UI revised** (see `Manas-Aegis-Usulan-Revisi-UI.md`): a calm
  first screen without fake CVE alarms (empty state "No activity
  matching the protection rules yet." + "What is monitored / What is
  not scanned" panel); `HERMES-SEC-...` IDs shown as internal
  advisory IDs, not CVEs; "Virtual Patches" → "Activity made safer";
  "Hard Blocks" → "Activity blocked by rules"; "N Rules Active" →
  "N rules defined"; the catalog score moved to Technical details
  labelled "rule reference value"; "Active" status only when the
  hook is verified registered, otherwise "Connection status cannot be
  verified yet"; chime off by default (opt-in via the Sound toggle);
  "Clear history" button + `/api/clear-history` endpoint.
- **Telemetry redaction before storage:** `_redact_evidence`
  (recursive: secret patterns + credentials in URLs + 160-character
  cut) applied to evidence before an event is written to
  `manas_telemetry.json` — not only on the output stream.
- **Simulation events separated from real events:** `intercept_tool_call`
  accepts `event_source="simulation"`; `execute_barrage_simulation`
  uses it; the `total_intercepted`/`hard_blocked` counters count only
  real events; simulation events are counted separately
  (`simulation_events`) and labelled SIMULATION in the HUD.
- **Guard status in code:** `ThreatVectorSpec.status` — 8
  `experimental`, 2 `planned` (SYMLINK-GUARD, CALLID-RACE);
  `get_system_posture` returns `rules_defined` (10) and
  `rules_enforced` (8, experimental rules) + `alpha: True`, replacing
  `verifiable_rules_active` and `standards_enforced` (21, static
  value).
- **Tests:** 12 unit tests (6 old + 6 new R1: recursive redaction,
  redaction in stored telemetry, simulation counter separation,
  planned rule status, HUD empty state, SIMULATION badge) —
  **12/12 passed** (`python3 -m unittest discover -v`, verified
  2026-11-09). Discovery from root now finds all tests (was 0 —
  fixed with `tests/__init__.py`).

### Known, queued for R2

- **SSRF fail-open:** a failed DNS is currently treated as SAFE
  (core_engine.py: `except socket.gaierror: pass`). Will be made
  fail-closed; the DNS check result also does not yet bind the next
  connection, redirect not yet checked.
- **Confirmed git chaining bypass:** `git status; touch /tmp/pwned` —
  the second command stays intact. The rewrite only replaces the first
  `git` occurrence.
- **Confirmed `python -c` bypass:** `python -c` without `socket` +
  `subprocess` in the same string escapes the SHELL-RCE pattern.
- **Path canonicalization:** path checks are substring-based, without
  canonicalization and without a symlink check.
- **HUD without auth/CSRF/rate limit:** HUD endpoints (including
  `/api/barrage` via POST) use no application authentication,
  Origin/CSRF check, or rate limit; HUD is loopback only.
- **Tests:** 12 unit tests (6 old + 6 new R1), coverage still narrow —
  the known bypasses (git chaining, `python -c`, SSRF fail-open) not
  yet fixed, that is Phase R2. No Hermes contract test, CI, or clean
  install test yet.
- **Packaging:** the Python wheel does not carry `plugin.yaml` /
  Desktop assets and has no declared Hermes plugin entry point; a
  clean Hermes install needs to become a release gate.
- **Two planned guards:** MANAS-SYMLINK-GUARD and MANAS-CALLID-RACE
  have no enforcement at all.

## [2.2.0] — 2026-11-08

The version submitted to the Hermes hackathon (catalog PR #151320).
Claims in this version that were later straightened out are listed in
`REVISI.txt` (revision verdict).
