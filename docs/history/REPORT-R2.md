# Phase R2 Revision Report — Manas Aegis v2.4.0-alpha

**Date:** 2026-11-09 (05:12–~06:30 WIB)
**Order:** MyLord, one item at a time from chat (6 items + 1 extra about the history limit). Working mode: "I'll revise 1 by 1 from my chat, you focus on finishing all of them from my chat."
**Verdict rule:** single project, single revision (MyLord, 9 Nov 04:04 WIB) — Ciel gives the verdict himself, no Alicia verdict requested. Alicia is still notified (coordination).
**Package:** `~/workspace/manas-aegis-rev1/` (19 files + `tests/`).

## Summary

All six of MyLord's revision items + one extra (the 120 history limit) were implemented, tested, and verified:

1. **i18n** — HUD in 15 languages, English default (previously Indonesian).
2. **Persistent simulation visibility** — the last simulation summary no longer disappears on reload; KPI cards show simulation sub-counts. The big cards still count **only real activity**.
3. **README "What is monitored" + custom rules** — users can add and edit rules; added rules are actually executed by the engine and validated.
4. **Scans: quick / full / network** — integrated, with the Findings tab as the "notification" channel (no push channel).
5. **Information-rich empty state** — version, status, rules, last simulation, last scan, how to produce activity.
6. **Real-time global threat intelligence** — CISA KEV + NVD, automatic refresh, table with plain-language + professional explanation columns.
7. **Unlimited history** (extra from MyLord, 05:32) — the 120 cap removed; append-only archive + history search.

## Answer to MyLord's question: "The simulation count doesn't increase — is that on purpose?"

**Yes, on purpose — and that was an R1 decision, not a bug.** The three big KPI cards count **only real activity**; simulation never inflates them (that inflation was the v2.2.0 dishonesty fixed in R1). Live evidence (checked 05:17 WIB): MyLord's telemetry `manas_telemetry.json` (written 05:14) contained **6 events, all simulation, 0 real** — MyLord's simulation **did run**. MyLord's screenshot showing "0 events recorded" was taken before the tab was reloaded. **What R2 fixed:** simulation results are now persistently visible (summary row + per-card sub-counts), so nobody has to wonder whether the simulation ran or not.

## What changed (per file)

| File | Change |
|---|---|
| `hermes_manas_aegis/i18n.py` (NEW, 1810 lines) | 15 languages, 111 keys, `RULE_EXPLAIN` (10 rules × en+id), `t()` + `explain()` with fallback to English. Written by a subagent, **verified by Ciel personally** (import + completeness of all languages + id spot-check). 3 extra keys (`kpi_rules_sub`, `scan_last`, `scan_never`) added by Ciel to all 15 languages. |
| `hermes_manas_aegis/core_engine.py` | Custom rules (`_load_custom_rules`, full validation, 4 rule overrides), persistent CCE baseline + re-compared by quick scan, `get_last_simulation()`, scan engine (`run_scan` quick/full/network), `get_history_stats()` + telemetry archive (live 500 + unlimited JSONL) + `search_events()` + `clear_all_history()`, `refresh_threat_intel()`, posture: `total_stored` = total incl. archive, `history_real`/`history_sim`, codename v2.4.0-alpha. |
| `hermes_manas_aegis/threat_intel.py` (NEW) | CISA KEV + NVD CVE API 2.0 (free, no key, official), parser, cache `threat_intel.json` (max 40 items), refresh that never throws; if both sources fail, the old cache is kept + marked stale. |
| `hermes_manas_aegis/__init__.py` | `build_analytical_hud_html(core, lang, query)` — all strings via `t()`; language picker; persistent simulation summary + per-card sub-counts; information-rich empty state; custom rules in catalog + scope panel; scan buttons + status row + Findings tab; global intel table + Explanation column; search box + `/api/search`; unlimited-history label; `POST /api/scan`, `POST /api/intel-refresh` endpoints; `clear-history` via `clear_all_history()`; intel refresh daemon (10 minutes, when cache > 6 hours). |
| `README.md` | v2.4.0-alpha banner; "What is monitored" section (+ custom rules, format + validation + reload); MANAS-CONFIG-FIM row updated (hash now re-compared); "Scans" section (checks per scope + what it does NOT do); "Global threat intelligence" section (sources + refresh + not a device scan); "Languages" section; "Stored data" table (archive, scan, intel, baseline, custom rules); test count 23/23. |
| `CHANGELOG.md` | v2.4.0-alpha entry (added/changed). |
| `plugin.yaml` / `pyproject.toml` | Version 2.3.0 → 2.4.0. |
| `tests/test_manas_aegis.py` | New `TestManasAegisR2` class (11 tests). Two R1 tests updated: the HUD is now called with explicit `lang="id"` (default changed to English). |
| `SECURITY.md`, `core_engine.py` docstring | Version 2.3.0 → 2.4.0 (historical "since v2.3.0" references kept). |

## Verification

- **Unit tests: 23/23 passed** (`python3 -m unittest discover`). 6 V22 + 6 R1 + 11 new R2. R2 covers: i18n completeness + English default + fallback; custom rules firing on a non-URL pattern + rejection of 6 invalid entries + SQLI override; last simulation summary; quick scan detecting a changed config.yaml (with the correct setup order: write config BEFORE the first core); full scan finding a prompt-injection file + token bomb, and a secret in `auth.json` NOT flagged; network scan `hud_ok=False` = critical; intel parser + refresh with a mock opener (both sources failing → old cache kept + stale); HUD containing the Explanation column + Findings tab + scan buttons + intel row; telemetry archive + search + clear history.
- **E2E: 27/27 passed** (`/tmp/e2e-r2.py`, real HTTP to the HUD server on port 18778): English default, `?lang=id`, unknown-language fallback, barrage → persistent summary + per-card sub-counts + still there after reload, search (`?q=` + `/api/search`), quick scan, intel refresh, intel row from cache, clear history.
- **Telemetry smoke test** (ephemeral, `/tmp/smoke-telemetry.py`): live 3 + archive 2 = total 5 after 5 events (with `TELEMETRY_LIVE_MAX=3`); reload keeps the total; search finds an archive event (n0) and a live event (n4); clear removes both. Two bugs found and fixed during the smoke test: (1) `self.events` not trimmed in memory → total counted twice; (2) archive indexing shifted after trim → events lost. Both fixed by archiving the overflow from the current window (not from absolute indexes).
- **R2 smoke test** (`/tmp/smoke-r2.py`): custom rules, scans, intel parser — all passed. Two artifacts noted (not bugs): (a) the "tamper" step reported "New config file" because the baseline was created before config.yaml existed — the unit test uses the correct setup order; (b) a custom rule blocked by the built-in SSRF in the VM (DNS via proxy returns 198.18.x.x) — the unit test uses a non-URL pattern so custom-rule verification is clean.

## Honest limits (still apply / new)

- **Guard decisions unchanged.** What changed is language, visibility, and the tooling around them — not blocking logic. The known bypasses (git chaining, `python -c`, SSRF fail-open) are still there — that is Phase R2 (queued after this revision).
- **Scans are not a device scanner.** Quick/full/network do not scan the whole computer, do no port scan, do no LAN/internet scan, and do not fix anything automatically.
- **Global intel is not a device scan.** CISA KEV + NVD advisories are awareness; the plugin does not check whether this device is affected.
- **Notifications = in the HUD.** No push channel (system/email/chat). Scan findings appear in the Findings tab; real-time blocks appear in the Activity table.
- **Explanations only en + id.** Other languages show the English explanation (fallback).
- **Archive search reads at most the last 20 MB** so the HUD does not slow down on a very large archive.
- **Visuals on MyLord's phone/Desktop** can only be verified from MyLord's devices (OPEN, as usual).

## Ciel's verdict (self-verdict, single-revision rule)

**PASS WITH NOTES.**

- All 6 revision items + 1 extra implemented and verified (unit 23/23, e2e 27/27).
- Notes: (1) phone/Desktop visuals for MyLord still OPEN (only verifiable from his devices); (2) explanations only en+id; (3) Phase R2 bypasses (SSRF fail-closed etc.) still queued and untouched by this revision; (4) translations of the 3 extra keys (`kpi_rules_sub`, `scan_last`, `scan_never`) were written by Ciel personally for the 13 non-en/id languages — short and simple, but not native-speaker translations.
