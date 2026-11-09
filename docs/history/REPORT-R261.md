# v2.6.1-alpha Revision Report — Minimal Posture Score Card, Activity Tab Only

**Trigger:** MyLord's complaint via a HUD screenshot (9 Nov 2026 ~15:07 WIB): "why does it show on every tab? it takes too much space, just make it a minimal box card" — the Posture Score card (65, grade C) appeared on all tabs.

## Root cause (confirmed from code)

The card was rendered in `build_analytical_hud_html` in the shared `<main>` flow, BEFORE the tab panels (`tab-act`, `tab-intel`, `tab-find`, `tab-arena`). The tab switcher (`showTab`) only adds/removes the `active` class on `.panel` elements — a card that is not a `.panel` is never hidden, so it showed on every tab. Not a CSS bug; purely placement outside the panels.

## Fixes

1. **Moved inside the Activity panel.** `{posture_html}` is now rendered right after `<div class="panel" id="tab-act">` opens, before the search form. The only placement (assert: exactly 1 occurrence).
2. **Minimal box (`.posture-mini`).** Replaces the big card (`.posture-big`, 44px number + 5 full rows):
   - One flex row: small title + 26px score + 14px grade on the left.
   - Five components as small chips on the right: label + 70px bar (was 140px) + bold value, wrapping neatly on narrow screens.
   - Padding 12px 16px (was 16px 18px + 14px margin).

## What did NOT change

- The "What is monitored" and "Scans" cards stay in the shared flow (as they have been since v2.4.0; not part of this complaint). If MyLord wants, both can also move into Activity in a later revision.
- Score/component values did not change — only placement + appearance. The live 65/C score on MyLord's PC stayed 65/C after install.

## Verification (Ciel personally)

- HUD render (EN + ID): exactly 1 `.posture-mini`, inside `tab-act` (position: after `id="tab-act"`, before `id="tab-intel"`), `posture-big` gone, 44px font gone, rendered values correct (fresh core 70/C, 25/25, 25/25, 20/20, 0/15, 0/15).
- Unit + contract: **61/61 PASS**.
- E2E R3 (regression, real HTTP): **26/26 PASS**.
- E2E posture-mini (real HTTP): **17/17 PASS** — including `GET /?tab=intel` still showing 1 mini-box, CSRF 403 without token / 200 with token, arena 10/10, Indonesian label "Skor postur".
- Two early "FAIL"s were wrong expectations in the check script, not code: fresh-core score 70 (not live 65) and the arena response nested under `arena.passed` — both fixed in the script, then green.

## Self-verdict: PASS WITH NOTES

- Notes: (1) the visual verdict still belongs to MyLord — the mini card + Activity-only placement needs his eyes on phone/Desktop; (2) "What is monitored" + "Scans" still show on all tabs (deliberate, outside the complaint); (3) the CI workflow file (`.github/workflows/ci.yml`) is still only in the working tree — not yet pushed (needs the `workflow` scope, open since R3).
- Repo: commit v2.6.1-alpha; catalog PR #151504 updated to v2.6.1.
- PC install: backup v260, gateway restart, HUD live v2.6.1-alpha.

## Extension (MyLord's second complaint, screenshot 15:12 WIB)

> "every time I switch tabs nothing changes, only the bottom changes, it's not interesting at all, too stiff"

This complaint has the SAME root but is BROADER than the Posture Score card: the KPIs, history lines, "What is monitored" card, and "Scans" card were also still in the shared `<main>` flow — so switching tabs only swapped the bottom panel, with 80% of the top of the screen staying identical. It felt dead/stiff.

### Additional fixes (still v2.6.1, before install)

- **All Activity content moved into `tab-act`**: KPIs (4 cards), posture-mini, 3 history lines, scope card, scan card. The shared flow above the panels is now ONLY the header (title + language/theme/sound/simulation controls) + status line. Each tab now shows fully different content.
- **180ms fade transition** when the active panel changes (`.panel.active{animation:panelFade .18s ease}` — rise 4px + fade), per the 150–250ms animation standard. Tab switching no longer "snaps" stiffly.

### Additional verification

- Render (EN + ID): KPIs, posture-mini, history, scope, scan — all exactly 1x and all between `id="tab-act"` and `id="tab-intel"`; the shared flow above tab-act is clean of Activity blocks; `panelFade` CSS present; fresh-core KPI values correct (0/0/0/10).
- Unit + contract 61/61, E2E R3 26/26, E2E posture-mini 17/17 — all green again after the extension.

## Live (PC, 9 Nov 2026 ~15:20 WIB)

- Install: backup v2.6.0 (1.2M) -> `/home/elian/.hermes/backups/manas-aegis/`; state kept (cce_baseline, scan_state 50 findings, threat_intel 25 items, dashboard, arena_last, tta_last); gateway restart, HUD v2.6.1-alpha.
- Live verification (real HTTP, 20/20 PASS): version v2.6.1-alpha; 1 posture-mini inside tab-act; KPIs/scope/scan inside tab-act; panelFade + animation present; live score 65/C (same as v2.6.0 — values unchanged, only appearance + placement); CSRF 403/200; arena 10/10 live; Indonesian render correct ("Skor postur").
- Repo: 53ef3c6 (posture-mini) + d7069f8 (per-tab + fade); PR #151504 -> v2.6.1 (YAML commit 735aa5c, explanatory comment posted).
- Self-verdict: PASS WITH NOTES (notes above still apply).
