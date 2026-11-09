# R2.5.2 Revision Report — Manas Aegis v2.5.2-alpha

**Date:** 2026-11-09 ~07:10 WIB
**Trigger:** MyLord's report (06:33 WIB) — "try it, the language feature is good but it's not even across all menus and tabs, there are still languages that aren't finished, for example when using English, the findings tab still uses Indonesian, and vice versa, same thing".
**Scope:** one project, one revision round (single-revision rule, 9 Nov 04:04) — Ciel gives the verdict himself; Alicia is notified (coordination), no verdict requested.

## Diagnosis (verified from code, not guessed)

Four sources of unevenness, all real:

1. **Scan finding titles + details hardcoded Indonesian** in `core_engine.py` (`run_scan` ~10 titles + ~10 details, `_scan_filesystem` 4+4, e.g. "Berkas konfigurasi berubah: {fname}") and stored that way in `scan_state.json` — showing Indonesian in ALL language modes.
2. **"File" header hardcoded English** in the template (`__init__.py`, last column of the Findings table).
3. **Check names = raw English IDs** (`config_integrity`, `honeypot_decoys`, …) — shown as-is.
4. **Intel level labels = English data** (CISA "Actively exploited", NVD "9.8 CRITICAL") — shown as-is in all modes.

What was NOT part of the problem (already correct): `_plain_reason`, `RULE_EXPLAIN`, `_custom_explain` are only en+id with a documented en fallback; other UI strings are already keyed.

## Fixes

- **Key-based findings.** `run_scan`/`_scan_filesystem` now store `title_key`/`detail_key`/`params` + English text as fallback in the raw JSON. The HUD renders via `t(lang, …)` (`_finding_text`). The Detail column now shows title (bold) + detail (dimmed) — previously only the detail.
- **41 new keys × 15 languages** (15 finding titles/details + `findings_file` + 9 `check_*` names + `intel_level_exploited`) **+ 3 NVD severity-word keys** (`intel_sev_high/medium/low`; CRITICAL reuses the existing `sev_critical`). Total keys: 115 → **159** per language, 0 mismatch.
- **Intel level labels** (`_intel_level_label`): "Actively exploited" → translated label; "9.8 CRITICAL" → score kept + severity word translated ("9.8 Kritis" / "7.5 Tinggi" / "5.0 Sedang" / "2.1 Rendah").
- **Old-finding migration** (`_migrate_old_finding`, 15 Indonesian title patterns → keys + parameter extraction from title/detail): 37 findings stored before v2.5.2 now show in the HUD language — not stuck in Indonesian. Findings that match no pattern still show their stored text (fallback, not raw keys).

## Verification

- **Unit tests: 38/38 passed** (33 old + 5 new R2.5.2, including full en+id finding rendering with no cross-leak, old-finding migration, intel level labels).
- **E2E: 32/32 passed** (real HTTP: en+id finding rendering, Berkas/File header, check names, migration, intel levels — plus all R2.5.1 flows still green).
- **Live on PC:** verified after install (see the report sent to MyLord).

## Self-verdict: PASS WITH NOTES

- Language across all menus + the Findings tab is now even (en + id verified with full rendering; the other 13 languages have complete keys, translations by Ciel — not a native speaker).
- 37 old findings migrated (not stuck in Indonesian).
- Notes: (1) translations for the 13 non-en/id languages were written by Ciel, not a native speaker; (2) Phase R2 bypasses (SSRF fail-closed etc.) still queued.
