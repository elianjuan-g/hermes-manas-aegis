# R3 Blueprint — Manas Aegis v2.6.0-alpha ("Best Guard")

**Date:** 2026-11-09
**Trigger:** MyLord's order — score 10 in every dimension, unique, valid, useful features + guard; "the best guard among all of them".
**Method:** Creation Synthesis — TRIZ + SCAMPER + Six Hats + first-principles + diverge→converge.
**Status:** PLAN — awaiting MyLord's GAS to build.

## 1. Core contradiction (TRIZ)

**"If guard strictness rises (% of dangerous calls blocked), then legitimate work breaks (% of legitimate calls passing through without interruption falls)."**
Solutions from the inventive principles:
- **Segmentation** — tiered enforcement per rule/per tool/per session (block / modify / ask / audit), not one global switch.
- **Asymmetry** — different treatment per segment: terminal = real shell parser; read_file = honeypot; model calls = taint tracking.
- **Blessing in disguise** — honesty about limits (per-rule bypass table) becomes a trust feature.
- **Preliminary action** — compute state BEFORE the call (taint, baseline) so the decision at call time is instant.
- **The other way round** — flip from blocklist to allowlist for the most dangerous tools: known-safe passes automatically, unknown gets checked.
- **Self-service** — user custom rules + auto-tune from user decisions.

## 2. First principles (what is CERTAINLY true)

- A guard can only enforce what it SEES (tool calls through the hook).
- A guard can only BLOCK what it DECIDES before execution.
- Pattern matching is shallow; state (taint) is deep.
- The user is the final authority; the guard's job is to make user decisions easy, not to replace them.
- A guard that false-alarms often will be turned off; a guard that stays silent is trusted until it fails.
- So build from zero: (a) stateful taint tracking, (b) tiered enforcement, (c) evidence (simulations) the user can run, (d) one posture number.

## 3. Diverge → converge (14 ideas, scored F/I/C/R 1–5, total /20)

| # | Idea | F | I | C | R | Total | Decision |
|---|---|---|---|---|---|---|---|
| 1 | Taint tracking (sensitive read → egress blocked, per session) | 4 | 5 | 3 | 2 | 14 | BUILD |
| 2 | Real shell parser (replace regex; split `;` `&&` `\|\|` `\|`) | 4 | 5 | 3 | 2 | 14 | BUILD |
| 3 | SSRF fail-closed + DNS allowlist | 5 | 4 | 4 | 3 | 16 | BUILD |
| 4 | Symlink guard (realpath canonicalization) — planned rule becomes real | 5 | 3 | 4 | 4 | 16 | BUILD |
| 5 | Call-ID race guard (duplicate/replay detection) — planned rule becomes real | 4 | 3 | 4 | 3 | 14 | BUILD |
| 6 | HUD auth + CSRF + rate-limit | 4 | 4 | 3 | 3 | 14 | BUILD |
| 7 | CI + contract tests + coverage gate | 5 | 3 | 5 | 4 | 17 | BUILD |
| 8 | Guard Arena (named red-team scenarios + pass/fail report) | 4 | 5 | 3 | 3 | 15 | BUILD |
| 9 | Posture Score (one 0–100 number in the HUD) | 5 | 4 | 5 | 4 | 18 | BUILD |
| 10 | Time-travel audit (replay old sessions through TODAY's rules) | 4 | 4 | 4 | 3 | 15 | BUILD |
| 11 | Auto-tune (learn from user allow/deny) | 2 | 4 | 2 | 2 | 10 | DEFER — can be gamed, needs separate trust design |
| 12 | Skill guard (verify skills before load) | 3 | 3 | 3 | 3 | 12 | DEFER — queued for R3.1 |
| 13 | Package guard (OSV.dev lookup) | 3 | 3 | 2 | 3 | 11 | DEFER — needs network, queued for R3.1 |
| 14 | Guard Duel (second model attacks the guard itself) | 2 | 4 | 2 | 2 | 10 | DEFER — needs a second model, ongoing cost |

**What was rejected and why (one sentence):** Auto-tune was rejected because user decisions can be gamed by an attacker via prompt injection; Skill/Package guard were deferred because they need separate trust design + network; Guard Duel was deferred because it needs a second model and ongoing cost.

## 4. Mapping to 10/10 scores

| Dimension (old score) | Features that close it | Target |
|---|---|---|
| Enforcement 5 | Taint tracking, shell parser, SSRF fail-closed, symlink guard, callid-race guard | 10 |
| Coverage 7 | 2 planned rules become real (10/10 enforced); taint tracking | 10 |
| Observability 9 | Posture Score, Guard Arena, Time-travel audit | 10 |
| Honesty 9 | Already 9; Guard Arena + Time-travel audit prove claims (not just write them) | 10 |
| Tests 7 | CI + contract tests + coverage gate | 10 |
| Docs/UX 8 | Posture Score + Arena (new UX); README updated | 10 |
| Maturity 4 | CI + PR merge (outside Ciel's control — honestly noted) + real users (outside control) | 7–8 (honest: 10 needs merge + users) |
| Plugin security 6 | HUD auth + CSRF + rate-limit | 10 |
| Extensibility 8 | Arena + Posture Score use the same rule engine | 10 |
| Uniqueness 7 | Guard Arena, Posture Score, Time-travel audit — no competitor has them | 10 |

**Honest note:** the Maturity dimension cannot be 10 from code alone — it needs PR #151504 merged by Nous and the first real users. That is outside Ciel's control; what Ciel can do is make the plugin merge-worthy (green CI, contract tests, complete docs).

## 5. What makes us UNIQUE vs llm-antidote & blackbox (after R3)

| Feature | Manas Aegis R3 | llm-antidote | blackbox |
|---|---|---|---|
| Taint tracking | ✅ (new) | ✅ | ❌ |
| Shell parser (not regex) | ✅ (new) | ✅ (capability class) | ❌ (patterns) |
| SSRF fail-closed | ✅ (new) | — | — |
| Real symlink + callid-race enforcement | ✅ (new) | — | — |
| HUD + 15 languages + themes | ✅ | ❌ | ✅ (dashboard, 1 language) |
| Global intel CISA/NVD | ✅ | ❌ | ✅ (DKG graph, heavy) |
| Guard Arena (named red-team) | ✅ (new) | ✅ (behavioral eval, no UI) | ❌ |
| Posture Score 0–100 | ✅ (new) | ❌ | ❌ |
| Time-travel audit | ✅ (new) | ❌ | ❌ |
| User custom rules + self-test | ✅ | ❌ (fleet policy, enterprise) | ❌ |
| Barrage simulation | ✅ | ❌ | ❌ |
| CI + contract tests | ✅ (new) | ✅ | ✅ |

## 6. Execution plan (after GAS)

1. Core enforcement: taint tracking + shell parser + SSRF fail-closed + symlink + callid-race.
2. HUD: auth/CSRF/rate-limit + Posture Score + Guard Arena + Time-travel audit.
3. Quality: CI (GitHub Actions) + contract tests + coverage gate + README/CHANGELOG.
4. Verification: unit + e2e (values, not labels) + live on PC.
5. Self-verdict → push repo → update PR #151504 → notify Alicia → install on PC → live verification → report to MyLord.
