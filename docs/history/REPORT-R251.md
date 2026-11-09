# Phase R2.5.1 Revision Report — Manas Aegis v2.5.1-alpha

**Date:** 2026-11-09 (~06:36–07:00 WIB)
**Order:** MyLord, from chat + screenshot (KPI cards 0/0/0/10, "simulation: 0" on all cards): "the simulation data was already run but here it's still 0, I want not only the simulation data but the real data also detected and everything implemented and integrated with each other, also in Scans, is that feature really real, why when I click quick scan it doesn't go into browse/library".
**Verdict rule:** single project, single revision (MyLord, 9 Nov 04:04 WIB) — Ciel gives the verdict himself, no Alicia verdict requested. Alicia is still notified (coordination).
**Package:** `~/workspace/manas-aegis-rev1/`.

## Findings (checked against real data on the PC, not against reports)

### 1. Simulation sub-counts 0/0/0 — BUG, fixed

Telemetry on the PC when inspected: **12 events, all simulation**, with verdicts:

- `HARD_BLOCK`: 8
- `SYNTHESIZED_PATCH (Modify Args)`: 2
- `HONEYPOT_DECEIVED (Modify Args)`: 2

The KPI cards computed simulation sub-counts with **exact** matching (`verdict == "BLOCK"`). `"HARD_BLOCK" != "BLOCK"`, so the result was 0/0/0 — even though the data was there and the "Last simulation" summary had been correct all along (that function uses substring matching). **This was my bug**, not MyLord's data being lost. Fix: sub-counts now use the same substring matching as the posture counter and `get_last_simulation()`. Result after the fix (with MyLord's same telemetry): **8/2/2**.

Note: the BIG cards still show 0 — that is correct by R1 design (big cards count only REAL activity; simulation must not inflate them). Only the sub-counts were wrong.

### 2. Real data — the path exists, the proof is now visible

All 12 events in telemetry were simulation; **0 real events**. The honest reason: real events only appear when Hermes actually intercepts a tool call from a running agent. The plugin is installed and its hooks are registered, but no real tool call had passed through since installation — so there was nothing to "detect".

To prove the real path is implemented and fully integrated, I tested it directly on the PC through the same path Hermes uses (`intercept_tool_call`, `event_source="runtime"` — the default, not simulation): 1 destructive shell call blocked (HARD_BLOCK), 1 argument modified, 1 credential redirected to the honeypot. All three were recorded as REAL events and raised the KPI cards. **This is a direct integration test, not a simulation** — and I say plainly: further real data appears automatically whenever a Hermes agent calls a tool. The plugin cannot detect a tool that is never called.

### 3. Scans — the feature REALLY works

Evidence from data on the PC: **37 stored findings** (1 telemetry backstop + 36 filesystem content from a full scan — real detections on files in `~/.hermes`). The last scan MyLord ran (network) found 0 findings — that is a clean result, not a failure to run.

What was broken was the UX: after a scan, the page only reloaded on the Activity tab, so the findings were hidden in the Findings tab and looked like they "didn't go anywhere". Fix: after a successful scan, the page automatically moves to the Findings tab (`?tab=find` in the URL; the server renders the requested tab). Search stays on the Activity tab.

### 4. Cross-process integration — the HUD did not see other processes' events

While proving the real path, I found a real integration gap: the HUD server loaded events into memory at startup only. The real-intercept test wrote 3 real events to the telemetry file, but the running HUD still showed 12 events (not seeing the 3 new ones) until the server was restarted. Fix: `core.reload_state()` is called on every GET — the page always reflects what is on disk, so events from a running Hermes agent (another process) appear without a restart.

## Verification

- **Unit tests: 33/33 passed** (28 old + 5 new R2.5.1, including reproducing MyLord's telemetry: 12 events → sub-counts 8/2/2, and cross-process reload_state).
- **E2E: 21/21 passed** (real HTTP: non-zero simulation sub-counts totalling 6, `?tab=find` rendering active Findings, scan → Findings, real intercept → real counter > 0, second process writing an event → HUD showing it without a restart).
- **Live on PC:** verified after install (see the report sent to MyLord).

## Honest limits (still apply)

- **New real events** only appear when a Hermes agent actually calls a tool. The integration test above proves the path works; how often real data appears depends on MyLord's Hermes usage.
- **Uneven language** (MyLord's earlier report: scan findings still Indonesian in English mode, etc.) is **NOT** fixed in this release — that is the next turn (v2.5.2). Scan finding titles/details are still hardcoded Indonesian in `core_engine.py`; the "File" header is still hardcoded English.
- **Phase R2 bypasses** (SSRF fail-closed etc.) still queued.

## Ciel's verdict (self-verdict, single-revision rule)

**PASS WITH NOTES.**

- Simulation sub-count bug fixed and proven with MyLord's real telemetry (8/2/2).
- Real-data path proven with a direct integration test on the PC, plus the cross-process integration gap (HUD not seeing other processes' events) closed with reload_state on every GET.
- Scan UX fixed (automatic move to Findings).
- Notes: (1) further real data depends on Hermes usage; (2) language fixes (v2.5.2) still queued; (3) Phase R2 bypasses still queued.
