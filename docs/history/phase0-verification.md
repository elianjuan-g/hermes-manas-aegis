# Phase 0 Verification — Manas Aegis Plugin Revision v2.2.0

- **Code inspected:** `/tmp/ma-check/` (clone of repo `elianjuan-g/hermes-manas-aegis`, commit `7c8f9d6`)
- **Verdict documents:** `~/workspace/user/files/REVISI.txt` and `~/workspace/user/files/Manas-Aegis-Usulan-Revisi-UI.md` (read in full)
- **Method:** read code line by line; decode Base64 patterns for static analysis; test regexes against string literals (pattern analysis, NOT command execution); run `python3 -m unittest discover` (root vs `-s tests`) for item 10. **No code file was changed** (only `__pycache__` from the unittest run in the `/tmp` clone, cleaned up again). No dangerous commands were executed.
- **Verification date:** 2026-11-09

## Executive summary

| Verdict | Count (of 14 items) |
|---|---|
| TRUE | 13 |
| PARTLY TRUE | 1 (item 14 — the "29" figure in the video is inconsistent with an empty state) |
| FALSE | 0 |
| CANNOT BE VERIFIED | 0 |

**Conclusion:** nearly all of the Argon verdict's claims are **confirmed from code**. Three claims confirmed earlier were re-verified: (1) SSRF failed DNS → `SAFE` (`core_engine.py:354-358`, `except socket.gaierror: pass` then `return True, "SAFE"`); (2) `MANAS-SYMLINK-GUARD` + `MANAS-CALLID-RACE` exist only in the threat matrix, with no enforcement branch; (3) git rewrite is regex-based (`core_engine.py:464-473`).

The sharpest findings, independently re-verified:

- **Not one of the 10 guards is fully `implemented`** under the task's definition (real enforcement, not partial/regex): 8 are `experimental` (a branch exists in the hook path, but regex/substring/shape-only and bypassable), 2 are `planned`.
- **The `git status; touch /tmp/pwned` bypass is confirmed by pattern analysis:** the rewrite only replaces the FIRST `git` occurrence (`count=1`, `core_engine.py:469`), separators `;`/`&&` are untouched, the second command stays intact. Plain `python -c` also escapes `RCE_PATTERN` (that pattern demands `socket` + `subprocess` in the same string).
- **`ssvc_enforce` and `stealth_audit` have no behaviour whatsoever in code** — they only appear as enum values in `plugin.yaml:43`; there is no branch anywhere that checks an SSVC decision (`ACT`/`ATTEND`) as a gate.
- **Unittest discovery from root finds 0 tests** (verified: `Ran 0 tests`); the 6 tests only run when called explicitly as `python3 -m unittest discover -s tests -v` (6/6 OK).

## 10-guard status table

Status definitions per the task: `implemented` = real enforcement in the hook path; `experimental` = code exists but partial/regex only; `planned` = only in matrix/metadata; `not supported` = does not exist at all.

| # | Rule | Status | Evidence (hook path `intercept_tool_call`, `core_engine.py`) |
|---|---|---|---|
| 1 | MANAS-GIT-FS-RCE | **experimental** | l.461-473: `re.search(r"\bgit\s+(?:status\|diff\|log\|checkout\|pull\|fetch|clone)\b")` then `re.sub(r"\bgit\s+", SAFE_GIT_PREFIX, count=1)`; only keys `command`/`cmd`/`script`; no shell parsing; chaining (`;`, `&&`) untouched |
| 2 | MANAS-CRED-HONEYPOT | **experimental** | l.425-445: `any(p in v for p in PROTECTED_FILES)` — substring matching on string values; no path canonicalization/normalization, no symlink check; redirect to decoy only when `doctrine == "counter_deceive"` and the tool name contains read/cat/view/load/open/get |
| 3 | MANAS-SSRF-SINKHOLE | **experimental** | l.401-411 + `evaluate_ssrf_target` l.325-359: literal-IP check + `socket.getaddrinfo`; `except socket.gaierror: pass` → `return True, "SAFE"` (l.354-358); DNS results do not bind the next connection; no redirect/egress check |
| 4 | MANAS-WEBHOOK-AUTH | **experimental** | l.372-381: only `session_id.startswith("webhook:") and session_id.count(":") > 2` — a string-shape check, not webhook authentication |
| 5 | MANAS-CONFIG-FIM | **experimental** | l.413-421: `CONFIG_HOOK_POISON` text regex (`hooks_auto_accept: true`, `post_llm_call:`, `pre_tool_call:`); the hash baseline is snapshotted once in `__init__` (`_snapshot_cce_baseline`, l.258-266) and **never re-compared** — `cce_hashes` is only read for `len()` in `get_system_posture` (l.299); not file-integrity monitoring |
| 6 | MANAS-MEM-FIREWALL | **experimental** | l.447-457: only when `"memory" in tool_name.lower()` and `MEMORY_DIRECTIVE_POISON` (regex) matches; string substitution `[MANAS-NEUTRALIZED-DIRECTIVE]` on matching string arguments |
| 7 | MANAS-SYMLINK-GUARD | **planned** | Only a `THREAT_MATRIX` entry (l.140-155, `advisory_id="HERMES-SEC-SYMLINK-TOCTOU"`); no other `SYMLINK`/`CALLID` reference in `core_engine.py` (grep: only l.140 and l.185); no `os.path.realpath`/`resolve`/symlink check anywhere |
| 8 | MANAS-SQLI-AST | **experimental** | l.384-392: `SQLI_PATTERN` regex (UNION SELECT / `OR '1'='1'` / `; DROP|ALTER|TRUNCATE|ATTACH` / `LOAD_EXTENSION(`); not a SQL AST; no SQLite parser |
| 9 | MANAS-SHELL-RCE | **experimental** | l.394-402: `RCE_PATTERN` regex (4 alternatives; pattern text: see `fixtures/vectors.json`, RCE_PATTERN); `python -c` without both required module names escapes; `touch`, `;`/`&&` chaining not handled |
| 10 | MANAS-CALLID-RACE | **planned** | Only a `THREAT_MATRIX` entry (l.185-200, `advisory_id="HERMES-SEC-CALLID-RACE"`); no call-ID tracking, lock, or race detection in `intercept_tool_call` |

Note: 5 of the 8 `experimental` guards (git, cred, SSRF, SQLi, webhook) do produce real block/modify effects on their nominal inputs — proven by 5 of the 6 existing unit tests. Their status is `experimental`, not `implemented`, because each is regex/shape-only with a demonstrated bypass (item 12) and no enforcement on the actual operation path (file/network/shell).

---

## Verification per item

### 1. Enforcement branches of the 10 rules — **TRUE**

See the table above. Eight rules have a branch in `intercept_tool_call` (`core_engine.py:360-477`); two (`MANAS-SYMLINK-GUARD`, `MANAS-CALLID-RACE`) appear only in `THREAT_MATRIX` (l.32-200) with no other reference in the engine. Dispatcher order: webhook (l.372) → SQLI (l.384) → SHELL-RCE (l.394) → SSRF (l.401) → CONFIG-FIM (l.413) → CRED-HONEYPOT (l.425) → MEM-FIREWALL (l.447) → GIT-FS-RCE (l.461). All enforcement is regex/substring/shape-based — no shell parser, SQL AST, path canonicalization, or symlink check.

### 2. "21 standards enforced" and static multipliers — **TRUE**

- `"standards_enforced": 21` is a **static integer literal** in `get_system_posture` (`core_engine.py:297`). There is no counting, enumeration, or verification of 21 standards anywhere in the code.
- The README (`README.md:11`) names only ~12 frameworks (CWE, CAPEC, MITRE ATT&CK/ATLAS, OWASP Top 10, CVSS v3.1, CWSS, EPSS, CASS, CCE, SSVC, STIX 2.1, TAXII 2.1) — not 21. There is no list of 21 standards in the repo.
- `"verifiable_rules_active": len(THREAT_MATRIX)` (l.296) = 10 — this too only counts catalog entries, not rules proven active in the hook.
- The CASS multiplier is static/configuration-based, not a measurement result: default `cass_multiplier: float = 1.35` in `compute_risk_and_ssvc` (l.308); `session_cass` default `1.35` (l.377); `on_session_start_hook` sets `1.75` (remote) / `1.20` (local) (`__init__.py:319-320`); `pre_llm_call_hook` sets `1.95` when a memory-poison pattern matches (`__init__.py:314`). The risk score is computed from catalog values (CVSS/CWSS/EPSS/maturity in `THREAT_MATRIX` l.32-200) times this multiplier — not from verification of 21 standards.

### 3. STIX vs TAXII — **TRUE**

- What exists: a **local STIX 2.1 bundle** built in `_log_stix_event` (`core_engine.py:502-530`, `type: "bundle"`, `spec_version: "2.1"`) and written to the local file `stix21_taxii_feed.json` (l.555-558, only the last 30 events), plus served via `GET /api/stix` (`__init__.py:245-252`).
- **No TAXII transport**: no TAXII client/server, discovery, polling, collections, or external connections anywhere in the repo (grep `TAXII`/`taxii` only finds: the filename `stix21_taxii_feed.json`, the tag `stix-taxii` in `plugin.yaml:21`, and the HUD label `"STIX 2.1 & TAXII 2.1 LIVE"` in `__init__.py:158`). The "TAXII LIVE" label in the HUD is backed by no implementation at all.

### 4. "Virtual patch" = argument rewrite — **TRUE**

- Git: `re.sub(r"\bgit\s+", SAFE_GIT_PREFIX, cmd_val, count=1)` (`core_engine.py:469`) — only inserts the flags `-c core.fsmonitor=false -c core.hooksPath=/dev/null -c protocol.file.allow=never` (`SAFE_GIT_PREFIX`, l.211, decoded from Base64) in front of the first git subcommand, then returns `{"action": "modify", "args": mutated_args}` (l.475-476). No patching of any repo, file, or on-disk configuration.
- Memory: string substitution `[MANAS-NEUTRALIZED-DIRECTIVE]` (`core_engine.py:452-454`), also via `modify`.
- The strategy names in the matrix confirm it: `strategy="SYNTHESIZE_PATCH"` (l.54, 135, 199) — "patch" here is a label for argument rewriting, not a system patch.

### 5. "Red-team barrage" = local simulation, hard-coded payloads — **TRUE**

- `execute_barrage_simulation` (`core_engine.py:563-575`): the `encoded_vectors` list holds **6 hard-coded Base64 payloads** that are decoded and passed to `intercept_tool_call` itself — no real execution, no network, no external attack. Decoded payloads (decode verified):
  1. `terminal` — `git status && git log -n 1` (session `cli:developer-workspace`)
  2. `read_file` — `~/.hermes/auth.json` (session `group:public-chat:404`)
  3. `browser_snapshot` — `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (session `webhook:external:701`)
  4. `sqlite_query` — `SELECT * FROM messages WHERE id='1' OR '1'='1' UNION SELECT secret FROM keys--` (session `webhook:external:702`)
  5. `memory_write` — directive-injection payload (see `fixtures/vectors.json`, arena-memory-injection) (session `group:public-chat:409`)
  6. `terminal` — `id` (session `webhook:admin:escalated_colon_route:999` — what blocks here is the `session_id` shape, not the `id` command)
- The results are recorded as ordinary telemetry events (with no `source`/simulation marker) — see item 14.
- Triggered from the HUD via `POST /api/barrage` (`__init__.py:255-266`), the `manas_tactical_core(action="barrage")` tool (`__init__.py:352-367`), and the `/manas-barrage` command.

### 6. `cve_id` used for internal `HERMES-SEC-...` IDs — **TRUE**

- `_log_stix_event` fills `"cve_id": spec.advisory_id` (`core_engine.py:515` — field name `cve_id`, value from `advisory_id`).
- All `advisory_id` values in `THREAT_MATRIX` have the form `HERMES-SEC-…`: `HERMES-SEC-GIT-RCE` (l.40), `HERMES-SEC-CRED-STORE` (l.56), `HERMES-SEC-SSRF-EGRESS` (l.71), `HERMES-SEC-WEBHOOK-COLON` (l.86), `HERMES-SEC-CONFIG-HOOK` (l.101), `HERMES-SEC-MEMORY-POISON` (l.116), `HERMES-SEC-SYMLINK-TOCTOU` (l.145), `HERMES-SEC-SQLI-GUARD` (l.160), `HERMES-SEC-SHELL-RCE` (l.175), `HERMES-SEC-CALLID-RACE` (l.190).
- Grep `CVE-[0-9]` across the whole repo: **0 results** — there is not a single public CVE ID (`CVE-YYYY-NNNN`). The HUD displays this value in the "Advisory / CWE Vector" column (`__init__.py:44`, `cve_esc`).

### 7. Telemetry: raw arguments, non-recursive redaction, no permission/retention — **TRUE**

- **Raw evidence stored before redaction:** `_log_stix_event` takes `evidence` as-is and stores it in `record["evidence"]` and then in `manas_telemetry.json` (l.494-554). Its callers send raw argument fragments: `serialized[:160]` for SQLI/RCE/CONFIG (l.386, 395, 417), `f"{u} -> {reason}"` containing the full URL for SSRF (l.408), `f"Blocked access to '{v}'"` containing the full path (l.443), `f"Synthesized safe Git flags -> {patched[:110]}"` (l.471). Raw `session_id` is also stored (l.500). There is no redaction call before `_log_stix_event`.
- **The redaction filter is string-only, not recursive:** `scrub_output_stream` (`core_engine.py:479-491`) takes `text: str` and applies `SECRET_PATTERNS` (5 regexes: `sk-…`, `sk-ant-…`, `ghp_/github_pat_…`, `AKIA…`, JWT) + XSS patterns to that string only. Its callers in `transform_tool_result_hook` / `transform_llm_output_hook` (`__init__.py:328-348`) only call it when `isinstance(result, str)` — dict/list results pass through unfiltered. No recursive dict/list traversal.
- **Permission/retention unspecified:** no `os.chmod`, `permission`, or `retention` in the code (grep: 0 results). Files are written via `Path.write_text` with the default umask (`_save_events`, l.266-271). The only limit is truncation to the last 120 events on load (l.262: `data[-120:]`) and on save (l.269: `self.events[-120:]`) — no TTL, no rotation, no encryption. The STIX file is limited to the last 30 events (l.558).

### 8. HUD: no auth/Origin/CSRF/rate limit; POST barrage; URL still returned on failed start — **TRUE**

- `_ManasHUDHandler` (`__init__.py:237-277`): `do_GET` serves `/api/stix` and the HUD page to anyone on loopback; `do_POST` accepts `/api/barrage` without checking body, headers, tokens, `Origin`/`Referer`, or rate limits. There is no application authentication, CSRF check, or rate limit anywhere in the handler. `log_message` is silenced (l.238-239).
- Single-threaded server: `HTTPServer` (not `ThreadingHTTPServer`) in `ensure_hud_server_running` (`__init__.py:286`) — one slow DNS request or file write can stall the server (note: `evaluate_ssrf_target` calls synchronous `socket.getaddrinfo` in the request path, `core_engine.py:348`).
- **Failed start still returns a URL:** `ensure_hud_server_running` (`__init__.py:283-292`) wraps `HTTPServer(...)` in `try/except Exception: pass`, then **unconditionally** `return f"http://127.0.0.1:{port}"`. `_SERVER_STARTED` is never reset. `on_session_start_hook` (`__init__.py:316-324`) and `tool_manas_tactical_core` (`__init__.py:349-350`) return that URL as `live_hud_url` as if the HUD were alive.
- Port note: the default `hud_port` 18777 in `plugin.yaml:52-54` and `desktop/plugin.js:13` both hardcode 18777 — but if `hud_port` is changed via configuration, the Desktop iframe still points at 18777 (possible mismatch, per the verdict claim).

### 9. Packaging: wheel does not carry plugin.yaml/desktop; no package.json/lockfile — **TRUE**

- `pyproject.toml`: `[tool.setuptools] packages = ["hermes_manas_aegis"]` — only that Python package. No `[project.entry-points]` / Hermes plugin entry point, no `[tool.setuptools.package-data]`, and **no `MANIFEST.in`** in the repo — so `plugin.yaml`, `desktop/plugin.js`, and `honeypot_sandbox/` (decoys) are not included in the wheel/sdist (the wheel carries only the Python package + `README.md` as metadata).
- `desktop/`: only `plugin.js` (58 lines) — **no `package.json`, lockfile, or build instructions**. `plugin.js` imports `@hermes/plugin-sdk` and `react/jsx-runtime`, which are not available/declared in the repo.
- The root shim `__init__.py` (repo root) re-exports from the package so that `hermes plugins validate` finds the entrypoint — but that shim itself is not in the wheel either (not part of `packages`).
- No `CONTRIBUTING.md`, `SECURITY.md`, changelog, or CI in the tree (verified with `find`: 0 results).

### 10. Tests: 6 tests, narrow coverage, discovery from root = 0 — **TRUE**

- `tests/test_manas_aegis.py`: 56 lines, **6 tests** (`grep -c "def test_"` = 6): `test_git_virtual_patch`, `test_honeypot_deception`, `test_ssrf_block`, `test_sqli_block`, `test_webhook_colon_guard`, `test_hud_html_escaping_prevents_self_xss` (l.26-53).
- **Run results (verified directly):** `python3 -m unittest discover` from root → `Ran 0 tests / NO TESTS RAN` (because `tests/` is not a package — no `tests/__init__.py` — and the module name is not found from root). `python3 -m unittest discover -s tests -v` → `Ran 6 tests / OK`.
- **Not tested:** SYMLINK-GUARD, CALLID-RACE, MEM-FIREWALL, CONFIG-FIM, SHELL-RCE (including chaining/`python -c` bypasses), SSRF fail-open DNS (`.invalid`/gaierror), redirect/rebinding, path traversal/symlink, structured output (dict/list), HTTP endpoints (`/api/stix`, `/api/barrage`), port conflicts, corrupt state (`manas_telemetry.json` corrupt — only `except: self.events = []`, l.263-265), Hermes contract test, STIX validity, package installation.

### 11. README not operational — **TRUE**

- `README.md`: only **13 lines** — title + 5 "Architectural Highlights" points (architecture claims). Not one of: install steps, enable/disable, configuration (even though `plugin.yaml` has 5 config options), usage examples, verifying success, troubleshooting, uninstall/rollback, stored data, per-guard limits, or how to report a vulnerability. Misleading claims inside it: "10 Verifiable Runtime Rules" (l.11) and "Dual-Layout Compatibility (Hermes 0.21.x & 0.23.x)" + "`hermes plugins validate` and `hermes plugins doctor` pass cleanly" (l.13) — with no integration evidence in the repo.

### 12. Bypass audit — **TRUE** (static pattern analysis + rewrite reconstruction; no dangerous commands executed)

- **The git-status shape (second in the fixture).** The pattern covers only its four listed destructive shapes; this one is documented in `fixtures/vectors.json` (`arena_scenarios`, id `arena-git-chain`).
- **`python -c` escapes the pattern tried.** The `python` branch of `RCE_PATTERN` demands two specific module names in the same string (pattern text: see `fixtures/vectors.json`, RCE_PATTERN). Pattern verified: `python -c "print(1)"` = no match; only variants containing both module names match. So `python -c` for general execution is not prevented.
- Root cause: no shell parsing — the regex rewrite is blind to `;`, `&&`, `||`, `|`, `$()`, backticks, and subshells.

### 13. `pre_llm_call` only raises a score; `ssvc_enforce`/`stealth_audit` have no behaviour — **TRUE**

- `pre_llm_call_hook` (`__init__.py:308-315`): only scans the last 3 messages against `MEMORY_DIRECTIVE_POISON`; on a match, `core.session_cass[session_id] = 1.95` (raises the score multiplier). **Always `return None`** — it never blocks, modifies, or filters any LLM message.
- `ssvc_enforce` / `stealth_audit`: only appear as enum values in `plugin.yaml:43` (`enum: ["counter_deceive", "ssvc_enforce", "stealth_audit"]`) and one description sentence (l.44: "`ssvc_enforce` hard-blocks ACT/ATTEND threats"). **Grep in `*.py`: 0 results.** The only doctrine branch in the code is `if doctrine == "counter_deceive"` (`core_engine.py:428`); other doctrines only make CRED-HONEYPOT fall through to `HARD_BLOCK` (l.443-445) — not "hard-block ACT/ATTEND" in general.
- No SSVC gate: grep `ssvc ==`, `== "ACT"` in `*.py` = 0 results. `compute_risk_and_ssvc` computes a score + decision (`ACT`/`ATTEND`/`TRACK*`/`TRACK`, `core_engine.py:306-323`), but that decision is only recorded in events and shown in the HUD — **never used to decide block/allow**.

### 14. UI document claims — **PARTLY TRUE**

- **HUD statistics are computed from stored events, not from a scan — TRUE.** `get_system_posture` (`core_engine.py:276-305`): `total_intercepted = len(self.events)`, `hard_blocked`/`virtual_patched`/`honeypot_deceived` = substring verdict counts (`"BLOCK"`/`"SYNTHESIZED"`/`"HONEYPOT"`) over `self.events`. There is no host/CVE scanning anywhere.
- **History limited to 120 events — TRUE.** `_load_events` l.262 (`data[-120:]`) and `_save_events` l.269 (`self.events[-120:]`). The HUD shows only the last 15 rows (`__init__.py:30`, `core.events[-15:]`); the STIX feed shows the last 25 (`__init__.py:246`) / last 30 in the file (l.558). The HUD empty state shows "No active threats intercepted. Click LAUNCH 6-VECTOR RED-TEAM BARRAGE…" (`__init__.py:88`) — not "No activity yet…".
- **The "29" figure in the v2.3 video is NOT consistent with an empty state — this claim is FALSE (the part that makes this item PARTLY TRUE).** On a fresh state without `manas_telemetry.json`, `self.events = []` so all statistics are **0** (`virtual_patched` = 0, etc.). One barrage produces at most **2** `SYNTHESIZED` events (git + memory) — so a figure of 29 on the "virtual patches" panel cannot come from a single simulation; it requires previously accumulated telemetry on the demo machine (e.g. ~15x barrage, or old state) — not a device-scan result, and the video does not explain it. Note: the UI document itself already records "Demo and repo commit may not be the same UI/implementation version" — so the 29 figure cannot be verified from the code at commit `7c8f9d6`; what the code does establish is: empty state → 0, and barrage events are not labelled/limited as simulation (barrage events go into the same counts as real events — no `source`/`type` field in the `record`, `core_engine.py:497-540`).
- Other supporting claims in the UI document confirmed: the "TAXII LIVE" label without transport (item 3); the `cve_id` field holding `HERMES-SEC-…` (item 6); the WebAudio chime active by default in `triggerBarrage` (`__init__.py:212-244`, `playChime()` called before fetch); no "Clear history" button or retention control in the HUD/code.

---

## Facts used for the Phase R1 guard table

(This list is intended as source material for the R1 guard table — each row points at code + tests.)

| Guard | R1 status | Threat (claim) | Real trigger in code | Real action | Proven bypass limit | Recorded data | Proving test |
|---|---|---|---|---|---|---|---|
| MANAS-GIT-FS-RCE | experimental | Git hook/config RCE (CWE-78) | `git` + subcommand from the 7-item list, keys `command`/`cmd`/`script` | modify: insert safe `-c` flags in front of the first subcommand | `;`/`&&` chaining intact; subcommands outside the list escape; second `git` untouched | `patched[:110]` raw in evidence | `test_git_virtual_patch` (nominal case only) |
| MANAS-CRED-HONEYPOT | experimental | Credential store read (CWE-522/73) | substring path from 7 `PROTECTED_FILES` entries in argument string values | modify: replace path → decoy (when `counter_deceive` + read tool) or block | no canonicalization; symlink, `..`, encoding, case/path variations escape; non-read tools are not deceived | raw path in evidence | `test_honeypot_deception` |
| MANAS-SSRF-SINKHOLE | experimental | SSRF/metadata (CWE-918) | URL `http(s)://` in arguments; literal private/loopback/link-local/reserved IPs; DNS → internal IP | block | **Failed DNS → SAFE** (fail-open); no redirect check; DNS result does not bind the next connection; no egress policy | raw URL + reason | `test_ssrf_block` (literal 169.254.x IPs only) |
| MANAS-WEBHOOK-AUTH | experimental | Webhook session escalation (CWE-863) | `session_id` starting with `webhook:` and `:` > 2 | block | string-shape check only; no authentication/signature/allowlist | raw `session_id` | `test_webhook_colon_guard` |
| MANAS-CONFIG-FIM | experimental | Config hook injection (CWE-94) | regex `hooks_auto_accept: true` / `post_llm_call:` / `pre_tool_call:` in arguments | block | hash baseline snapshotted once at init, **never re-compared** → not FIM; text patterns easy to avoid | `serialized[:160]` raw | — (none) |
| MANAS-MEM-FIREWALL | experimental | Memory directive poisoning (CWE-74) | `"memory"` in tool name + directive/zero-width regex | modify: substitute `[MANAS-NEUTRALIZED-DIRECTIVE]` | only tools named `*memory*`; limited regex patterns | static evidence `"Purged directive injection…"` | — (none; only covered indirectly via barrage) |
| MANAS-SYMLINK-GUARD | planned | Symlink TOCTOU (CWE-59) | — (none) | — | whole path missing | — | — |
| MANAS-SQLI-AST | experimental | SQL injection (CWE-89) | regex UNION SELECT / `OR '1'='1'` / `; DROP|ALTER|…` / `LOAD_EXTENSION(` | block | regex, not AST; variants outside the pattern escape | `serialized[:160]` raw | `test_sqli_block` |
| MANAS-SHELL-RCE | experimental | Reverse shell/destructive command (CWE-78) | regex with 4 patterns (see `fixtures/vectors.json`, RCE_PATTERN) | block | `python -c` without both required module names escapes; `touch`, chaining, `$()`, backticks not handled | `serialized[:160]` raw | — (none) |
| MANAS-CALLID-RACE | planned | Cross-session call-ID race (CWE-362) | — (none) | — | whole path missing | — | — |

**Cross-guard facts for R1:** (a) "10 rules" in the README/HUD counts catalog entries, not enforcement — the honest UI label is "10 defined rules, 8 experimental, 2 not yet built"; (b) "21 standards" is a static literal (`core_engine.py:297`); (c) CVSS/EPSS/CWSS/SSVC scores are catalog values + a static multiplier, not scan results; (d) "virtual patch" = argument rewrite; (e) STIX = local bundle, no TAXII; (f) barrage = 6 hard-coded payloads, results mixed with real events without a simulation label; (g) telemetry stores raw argument/URL fragments, redaction is string-only and output-path-only, no permission/retention; (h) HUD without auth/CSRF/rate limit and returning a URL even on failed start; (i) `pre_llm_call` does not block; the `ssvc_enforce`/`stealth_audit` doctrines have no behaviour; (j) 6 tests cover only 5 nominal cases + 1 HTML escaping test; discovery from root = 0 tests.
