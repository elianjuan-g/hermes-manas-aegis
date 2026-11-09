# Phase R1 Revision Report — Manas Aegis v2.3.0-alpha

Written by Ciel, 2026-11-09 ~03:30 WIB.
Package: `~/workspace/manas-aegis-rev1/` (ready to become a new repo, not yet pushed).

## How this revision was done (honestly)

MyLord ordered me to do this revision myself. A coordinator I had started at the beginning was stopped on that order. An early draft (Phase 0 verification + documents + part of the code) already existed when I took over — I re-read **all** of its changes line by line, fixed the wrong/stale parts, added tests, and ran **all** verification myself. What I did myself: README/CHANGELOG/CONTRIBUTING fixes, tool/command wording fixes, 6 new tests + discovery fix, e2e 17/17, and this report.

## What changed (per item in REVISI.txt + the UI document)

### 1. Claims corrected
- "Absolute Defense" / security boundary: removed from README, HUD, plugin.yaml, pyproject, tool/command descriptions.
- "10 runtime rules" → "10 defined rules, 8 experimental, 2 planned" (guard table in README + HUD + `get_system_posture`).
- "21 standards enforced" → removed; that static value is now explained as a catalog reference value, not a measurement result.
- STIX vs TAXII: "TAXII LIVE" removed; only a local STIX 2.1 bundle exists; tag `stix-taxii` → `stix-local`.
- "Virtual patch" → "modifies arguments" (not a system patch).
- `cve_id` holding `HERMES-SEC-...` → displayed as "internal advisory ID", not a CVE; CVSS/EPSS/CWSS/SSVC scores labelled "rule reference values".
- `tactical_doctrine`: `ssvc_enforce`/`stealth_audit` stated to have no behaviour in code (enum values only); the only branch is `counter_deceive`.
- Barrage = labelled local simulation; "live exploit" removed from all tool/command/parameter descriptions.

### 2. Alpha label
README (first line), HUD ("ALPHA"), plugin.yaml + pyproject (v2.3.0, description `[ALPHA] ... Opt-in, test environments only`).

### 3. Operational README (full rewrite)
What it prevents / what it does NOT prevent; 10-guard table (threat, trigger, action, status, bypass limits, recorded data); install, enable/disable, configuration (each option explained as to what it actually does), verifying success, troubleshooting, uninstall/rollback, stored data, tested Hermes versions, glossary. Unverified claims are marked `[NOT YET VERIFIED]`.

### 4. HUD UI (per the UI Revision Proposal document)
- Calm first screen: empty state "No activity matched the protection rules." + "What is monitored / What is not scanned" panel.
- Full relabelling (see §1); scores moved to Technical details.
- Honest connection status: "Active" only when a hook is verified registered; otherwise: "Connection status could not be verified". `on_session_start_hook` now returns `hud_ok`.
- Simulation: secondary "Run local simulation" button + honest confirmation dialog + results labelled SIMULASI per row + real-activity counters unchanged + chime off by default (opt-in via the Sound toggle, stored in localStorage).
- Activity list: Time · Source (Real/Simulation) · Rule · Action (Blocked / Arguments modified / Content redacted) + plain-language reason detail + optional technical detail.
- "Clear history" + `/api/clear-history` endpoint (clears telemetry + local STIX feed); the 120-event limit labelled "stored history".
- "Threat intelligence" tab: rule catalog with experimental/planned status, labelled "global information — not found on this device".

### 5. Telemetry redaction (code)
`_redact_evidence` recursive (secret patterns + credentials in URLs + 160-character cut) applied to evidence **before** the event is written to `manas_telemetry.json`. The README privacy section was corrected to match this fact (it previously wrongly said redaction happened only on output).

### 6. Simulation event separation (code)
`intercept_tool_call(..., event_source="simulation")`; `execute_barrage_simulation` uses it; counters `total_intercepted`/`hard_blocked` count only real events; `simulation_events` + `total_stored` are separate.

### 7. New supporting documents
SECURITY.md (how to report a vulnerability, no bounty), CHANGELOG.md (v2.3.0-alpha + "Known, going into R2" list), CONTRIBUTING.md (mandatory claim rules: every claim points to code + tests).

## Verification evidence (run by Ciel personally)

- **Unit tests: 12/12 passed** (`python3 -m unittest discover -v`, 2026-11-09) — 6 old + 6 new R1 (recursive redaction, redaction in stored telemetry, simulation counter separation, planned rule status, HUD empty state, SIMULASI badge). Discovery from root now finds all tests (was 0 — fixed with `tests/__init__.py`).
- **E2E: 17/17 passed** (`/tmp/e2e-r1.py`, exact new-user flow): HUD server alive on the test port; new profile → calm empty state + coverage panel + unverified status; 1 real event + 1 simulation event → SIMULASI + Real badges shown, real counter stays 1, simulation counter 1; `POST /api/clear-history` → history empty again. All from HTML actually read, not from logic.
- **Claim sweep:** final grep for "Absolute Defense", "TAXII LIVE", "10 runtime rules", "21 standards", "live exploit", "Virtual Patching Engine" across the whole package → 0 remaining occurrences except honest explanatory quotes in CHANGELOG/CONTRIBUTING (about claims that were removed / are forbidden).
- **Complete, self-contained package:** 16 source files + new documents (README, CHANGELOG, SECURITY, CONTRIBUTING, phase0-verification) + `.gitignore` Secrets block. Ready to become a new repo without old history.

## What was NOT changed (goes into Phase R2)

SSRF fail-open (failed DNS → SAFE); git chaining bypass (`git status; touch /tmp/pwned`); `python -c` bypass; path/symlink canonicalization; HUD without auth/CSRF/rate limit; CI; wheel packaging (plugin.yaml + desktop in the package); Hermes contract test; clean install. All recorded honestly in the README guard table + CHANGELOG "Known, going into R2".

## What I did not re-verify in this revision (honestly)

The full simulation-button flow (click the button in the HUD → `POST /api/barrage` → 6 sample inputs) was **not re-run** in this revision, because the file holding those sample inputs did not pass the security check when I read it. What I verified instead: simulation event separation tested directly via `intercept_tool_call(event_source="simulation")` (unit + e2e tests above) — and the simulation code itself is **unchanged** from v2.2.0, which was verified live on the PC on 8 Nov (barrage runs, KPIs rise). If MyLord wants, the full button flow can be tested on the PC when the revision is installed.

## Next steps (need MyLord + Alicia)

1. MyLord reads this package (especially README + HUD).
2. Alicia gives a verdict on the R1 revision.
3. If PASS: upload as a NEW repo (same name is fine), then a NEW catalog PR; the old PR #151320 is closed.
4. Install on MyLord's PC only after a PASS verdict (verdict first for server/data changes — the gate stands).
