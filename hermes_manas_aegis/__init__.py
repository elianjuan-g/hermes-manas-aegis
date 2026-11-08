"""
Hermes Manas-Aegis Plugin Package Entrypoint & Live Analytical Matrix UI Server.
"""

from __future__ import annotations

import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .core_engine import ManasAegisCore, THREAT_MATRIX
from .i18n import DEFAULT_LANG, LANGS, SUPPORTED_LANGS, explain, t


_CORE: Optional[ManasAegisCore] = None
_SERVER_STARTED = False
_SERVER_OK: Optional[bool] = None  # None = belum dicoba, True = bind berhasil, False = bind gagal


def get_core(config: Optional[Dict[str, Any]] = None) -> ManasAegisCore:
    global _CORE
    if _CORE is None:
        state_dir = Path.home() / ".hermes" / "plugins" / "hermes-manas-aegis"
        _CORE = ManasAegisCore(state_dir=state_dir, config=config or {})
    return _CORE


def _action_label(verdict: str, lang: str = "en") -> str:
    if "HARD_BLOCK" in verdict:
        return t(lang, "action_blocked")
    if "SYNTHESIZED" in verdict:
        return t(lang, "action_modified")
    if "HONEYPOT" in verdict:
        return t(lang, "action_deceived")
    return t(lang, "action_logged")


def _strategy_label(strategy: str, lang: str = "en") -> str:
    return {
        "HARD_BLOCK": t(lang, "action_blocked"),
        "SYNTHESIZE_PATCH": t(lang, "action_modified"),
        "HONEYPOT_DECEIVE": t(lang, "action_deceived"),
    }.get(strategy, strategy)


def _plain_reason(ev: Dict[str, Any], lang: str = "en") -> str:
    verdict = str(ev.get("verdict", ""))
    rule = str(ev.get("codename", "aturan ini"))
    if lang == "id":
        if "HARD_BLOCK" in verdict:
            return (
                f"Aktivitas ini diblokir karena cocok dengan pola {rule}. "
                "Pemblokiran didasarkan pada kecocokan pola, bukan bukti bahwa "
                "ada penyerang atau kompromi nyata."
            )
        if "SYNTHESIZED" in verdict:
            return (
                f"Argumen aktivitas ini diubah agar lebih aman sesuai {rule}. "
                "Ini mengubah argumen yang diteruskan, bukan memasang patch "
                "perangkat lunak."
            )
        if "HONEYPOT" in verdict:
            return (
                f"Aktivitas ini dialihkan ke data umpan (honeypot) sesuai {rule}, "
                "sehingga target aslinya tidak dibaca."
            )
        return f"Aktivitas ini dicatat oleh {rule}."
    if "HARD_BLOCK" in verdict:
        return (
            f"This activity was blocked because it matched the {rule} pattern. "
            "Blocking is based on a pattern match, not proof of a real "
            "attacker or compromise."
        )
    if "SYNTHESIZED" in verdict:
        return (
            f"The arguments of this activity were changed to be safer, "
            f"following {rule}. This changes the arguments passed on; it "
            "does not install a software patch."
        )
    if "HONEYPOT" in verdict:
        return (
            f"This activity was redirected to honeypot (decoy) data following "
            f"{rule}, so the real target was not read."
        )
    return f"This activity was recorded by {rule}."


def _custom_explain(entry: Dict[str, Any], lang: str = "en") -> Dict[str, str]:
    """Generated explanation for a user-defined rule (no curated text)."""
    spec = entry["spec"]
    pattern = entry["pattern"]
    tools = entry.get("tools") or []
    if lang == "id":
        lay = (
            f"Aturan khusus “{spec.codename}” — memblokir aktivitas "
            "yang cocok dengan polanya."
        )
        pro = (
            f"Pola: /{pattern.pattern}/ · Tool: "
            f"{', '.join(tools) or 'semua'} · {spec.cwe_id}"
        )
    else:
        lay = (
            f"Custom rule “{spec.codename}” — blocks activity "
            "matching its pattern."
        )
        pro = (
            f"Pattern: /{pattern.pattern}/ · Tools: "
            f"{', '.join(tools) or 'all'} · {spec.cwe_id}"
        )
    return {"lay": lay, "pro": pro}


_HUD_CSS = """
:root{--bg:#040811;--card:#0a1226;--line:#1b2a4a;--txt:#e8eefc;--mut:#8fa3c8;
--cyan:#00f5d4;--gold:#f59e0b;--crimson:#ff2a5f;--green:#34d399}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:'JetBrains Mono',ui-monospace,monospace;padding:18px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.badge{font-size:28px;color:var(--cyan)}
h1{margin:0;font-size:22px;letter-spacing:.08em}
.sub{color:var(--mut);font-size:12px;margin-top:4px}
.sub2{color:var(--mut);font-size:11px;margin-top:2px}
.btn{background:#12203d;border:1px solid var(--line);color:var(--txt);padding:8px 12px;border-radius:8px;cursor:pointer;font:inherit;font-size:12px}
.btn:hover{border-color:var(--cyan)}
select{background:#12203d;border:1px solid var(--line);color:var(--txt);padding:8px 10px;border-radius:8px;font:inherit;font-size:12px}
.status{margin:16px 0 8px;font-size:12px;color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.kpi .n{font-size:26px;font-weight:700}
.kpi .l{font-size:11px;color:var(--mut);margin-top:4px}
.kpi .f{font-size:10px;color:var(--mut);margin-top:6px}
.kpi .s{font-size:10px;color:var(--mut);margin-top:4px}
.hist{font-size:11px;color:var(--mut);margin:8px 0}
.scope{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;margin:12px 0;font-size:12px}
.scope h3{margin:0 0 6px;font-size:12px;color:var(--cyan)}
.scope p{margin:4px 0;color:var(--mut)}
.scanrow{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0;align-items:center}
.scanline{font-size:11px;color:var(--mut);margin:6px 0}
.search{display:flex;gap:8px;margin:10px 0;align-items:center}
.search input{flex:1;background:#12203d;border:1px solid var(--line);color:var(--txt);padding:8px 10px;border-radius:8px;font:inherit;font-size:12px}
.search a{color:var(--cyan);font-size:12px}
.tabs{display:flex;gap:8px;margin:14px 0 8px}
.tab{background:#12203d;border:1px solid var(--line);color:var(--txt);padding:7px 14px;border-radius:8px 8px 0 0;cursor:pointer;font:inherit;font-size:12px}
.tab.active{border-color:var(--cyan);color:var(--cyan)}
.panel{display:none}
.panel.active{display:block}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{border-bottom:1px solid var(--line);padding:8px 6px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700}
.pill-real{background:#12351f;color:#34d399}
.pill-sim{background:#3a2b00;color:#f59e0b}
.pill-custom{background:#2b1a4a;color:#c4b5fd}
.empty{background:var(--card);border:1px dashed var(--line);border-radius:10px;padding:22px;text-align:center;color:var(--mut);font-size:13px}
.empty b{color:var(--txt)}
.info{background:var(--card);border:1px dashed var(--line);border-radius:10px;padding:16px 20px;font-size:12px;text-align:left}
.info h3{margin:0 0 10px;font-size:13px;color:var(--txt);text-align:center}
.info .row{display:flex;gap:10px;margin:5px 0}
.info .k{color:var(--mut);min-width:150px;flex-shrink:0}
.note{font-size:11px;color:var(--mut);margin-top:10px}
.explain{font-size:11px;color:var(--mut)}
.explain b{color:var(--txt)}
details{font-size:11px;color:var(--mut)}
summary{cursor:pointer;color:var(--cyan)}
@media(max-width:700px){.kpis{grid-template-columns:repeat(2,1fr)}.info .k{min-width:110px}}
"""


def build_analytical_hud_html(core, lang="en", query=None) -> str:
    if lang not in {c for c, _ in SUPPORTED_LANGS}:
        lang = DEFAULT_LANG
    posture = core.get_system_posture()
    st = posture["stats"]
    total = st["total_stored"]
    hist = core.get_history_stats()
    sim = posture.get("last_simulation")
    scan = posture.get("last_scan")
    intel = getattr(core, "threat_intel", {}) or {}
    custom = getattr(core, "custom_rules", [])
    custom_errors = getattr(core, "custom_rule_errors", [])
    experimental = [r for r in THREAT_MATRIX.values() if r.status == "experimental"]
    planned = [r for r in THREAT_MATRIX.values() if r.status == "planned"]

    # Simulation subcounts per KPI card (live events only).
    sim_block = sum(
        1 for e in core.events if e.get("source") == "simulation" and e.get("verdict") == "BLOCK"
    )
    sim_modify = sum(
        1
        for e in core.events
        if e.get("source") == "simulation" and e.get("verdict") == "SYNTHESIZED"
    )
    sim_deceive = sum(
        1 for e in core.events if e.get("source") == "simulation" and e.get("verdict") == "HONEYPOT"
    )

    # Status line.
    if core.hooks_verified:
        status_line = t(lang, "status_connected")
    else:
        status_line = t(lang, "status_unverified")
    if _SERVER_OK is False:
        status_line += t(lang, "status_server_fail")

    # Stored-history range label (unlimited: live file + archive).
    if hist["total"] == 0:
        range_label = t(lang, "range_empty")
    else:
        range_label = t(
            lang,
            "range_label",
            first=hist["first_ts"],
            last=hist["last_ts"],
            total=str(hist["total"]),
        )

    # Persistent last-simulation line (survives reloads; the post-run
    # message alone used to vanish).
    if sim:
        sim_line = t(
            lang,
            "sim_last",
            time=sim["timestamp"],
            matched=str(sim["matched"]),
            total=str(sim["total"]),
            blocked=str(sim["blocked"]),
            modified=str(sim["modified"]),
            deceived=str(sim["deceived"]),
        )
    else:
        sim_line = t(lang, "sim_never")

    # Scan status line (last_scan stores counts, not the finding list).
    if scan:
        scan_line = t(
            lang,
            "scan_last",
            time=scan["started_at"],
            scope=scan["scope"],
            findings=str(scan.get("findings_count", 0)),
            critical=str(scan.get("critical_count", 0)),
        )
    else:
        scan_line = t(lang, "scan_never")

    # Language selector options.
    lang_options = "".join(
        f'<option value="{code}"{" selected" if code == lang else ""}>{html.escape(name)}</option>'
        for code, name in SUPPORTED_LANGS
    )

    # Activity rows: search results when a query is given, else latest 15.
    if query:
        rows_events = core.search_events(query)
        if rows_events:
            search_note = t(lang, "search_results", n=len(rows_events), q=query)
        else:
            search_note = t(lang, "search_none", q=query)
    else:
        rows_events = core.events[-15:]
        search_note = ""

    rows = ""
    for ev in reversed(rows_events):
        src = ev.get("source", "")
        if src == "simulation":
            pill = f'<span class="pill pill-sim">{t(lang, "source_sim")}</span>'
        else:
            pill = f'<span class="pill pill-real">{t(lang, "source_real")}</span>'
        detail = (
            f'<details><summary>{t(lang, "detail_show")}</summary>'
            f'<div>{t(lang, "detail_advisory")}: {html.escape(str(ev.get("cve_id", "")))}</div>'
            f'<div>{t(lang, "detail_evidence")}: {html.escape(str(ev.get("evidence", ""))[:300])}</div>'
            f'<div>{t(lang, "detail_ref")}: {html.escape(str(ev.get("rule_ref", "")))}</div>'
            f'<div>{html.escape(_plain_reason(ev, lang))}</div>'
            f"</details>"
        )
        rows += (
            f'<tr><td>{html.escape(str(ev.get("timestamp", "")))}</td>'
            f"<td>{pill}</td>"
            f'<td>{html.escape(str(ev.get("codename", "")))}<br><span style="color:var(--mut)">{html.escape(str(ev.get("cve_id", "")))}</span></td>'
            f"<td>{html.escape(_action_label(str(ev.get('verdict', '')), lang))}</td>"
            f"<td>{detail}</td></tr>"
        )

    # Rule catalog rows (built-in) + custom rules appended.
    cat_rows = ""
    for rule_id, spec in THREAT_MATRIX.items():
        ex = explain(rule_id, lang)
        if ex["lay"]:
            expl = (
                f'<div class="explain"><b>{t(lang, "intel_explain_lay")}:</b> '
                f"{html.escape(ex['lay'])}<br><b>{t(lang, 'intel_explain_pro')}:</b> "
                f"{html.escape(ex['pro'])}</div>"
            )
        else:
            expl = f'<div class="explain">{html.escape(t(lang, "intel_note"))}</div>'
        if spec.status == "planned":
            status_txt = t(lang, "status_planned")
            action_txt = t(lang, "action_none")
        else:
            status_txt = t(lang, "status_experimental")
            action_txt = _strategy_label(spec.strategy, lang)
        cat_rows += (
            f"<tr><td>{html.escape(spec.codename)}</td>"
            f"<td>{html.escape(spec.advisory_id)}</td>"
            f"<td>{html.escape(status_txt)}</td>"
            f"<td>{html.escape(action_txt)}</td>"
            f"<td>{expl}</td>"
            f"<td>{html.escape(t(lang, 'intel_note'))}</td></tr>"
        )
    for entry in custom:
        spec = entry["spec"]
        ex = _custom_explain(entry, lang)
        expl = (
            f'<div class="explain"><b>{t(lang, "intel_explain_lay")}:</b> '
            f"{html.escape(ex['lay'])}<br><b>{t(lang, 'intel_explain_pro')}:</b> "
            f"{html.escape(ex['pro'])}</div>"
        )
        cat_rows += (
            f'<tr><td>{html.escape(spec.codename)} '
            f'<span class="pill pill-custom">{t(lang, "custom_badge")}</span></td>'
            f"<td>{html.escape(spec.advisory_id)}</td>"
            f"<td>{html.escape(t(lang, 'status_experimental'))}</td>"
            f"<td>{html.escape(_strategy_label(spec.strategy, lang))}</td>"
            f"<td>{expl}</td>"
            f"<td>{html.escape(t(lang, 'custom_label'))}</td></tr>"
        )

    # Findings rows (latest first).
    findings = getattr(core, "scan_findings", []) or []
    find_rows = ""
    for f in reversed(findings):
        sev = str(f.get("severity", "info"))
        sev_label = t(lang, "sev_" + sev) if "sev_" + sev in LANGS.get(lang, {}) else sev
        fdetail = str(f.get("detail", ""))
        ffile = str(f.get("file", ""))
        fline = f.get("line")
        file_cell = html.escape(ffile)
        if fline is not None:
            file_cell += f":{fline}"
        find_rows += (
            f'<tr><td>{html.escape(str(f.get("timestamp", "")))}</td>'
            f"<td>{html.escape(str(f.get('check', '')))}</td>"
            f"<td>{html.escape(sev_label)}</td>"
            f"<td>{html.escape(fdetail)}</td>"
            f"<td>{file_cell}</td></tr>"
        )

    # Global intel rows.
    intel_items = intel.get("items") or []
    intel_rows = ""
    for item in intel_items:
        product = item.get("product") or item.get("name") or ""
        vendor = item.get("vendor") or ""
        if vendor and product and not product.startswith(vendor):
            product = f"{vendor} {product}"
        intel_rows += (
            f"<tr><td>{html.escape(str(item.get('id', '')))}</td>"
            f"<td>{html.escape(str(product))}</td>"
            f"<td>{html.escape(str(item.get('level', '')))}</td>"
            f"<td>{html.escape(str(item.get('date', '')))}</td>"
            f"<td>{html.escape(str(item.get('description', ''))[:200])}</td></tr>"
        )
    intel_status = ""
    if intel.get("fetched_at"):
        intel_status = t(lang, "intel_updated", time=str(intel["fetched_at"]))
        if intel.get("stale"):
            intel_status += " · " + t(lang, "intel_stale", time=str(intel["fetched_at"]))
    if intel.get("sources"):
        for src, st_src in intel["sources"].items():
            if not st_src.get("ok"):
                intel_status += " · " + t(lang, "intel_offline")
                break
    sources = ", ".join(sorted((intel.get("sources") or {}).keys())) or "CISA KEV, NVD"

    # Scope panel custom-rules line.
    if custom_errors:
        custom_line = t(lang, "custom_invalid", n=len(custom_errors))
    elif custom:
        custom_line = t(lang, "custom_note", n=len(custom))
    else:
        custom_line = ""

    # Enriched empty state (info panel, shown when no real activity yet).
    runtime_total = st["total_intercepted"]
    if runtime_total == 0 and not query:
        empty_html = (
            f'<div class="info"><h3>{t(lang, "empty_title")}</h3>'
            f'<div class="row"><span class="k">{t(lang, "empty_version")}</span><span>{html.escape(str(posture["codename"]))}</span></div>'
            f'<div class="row"><span class="k">{t(lang, "empty_status")}</span><span>{html.escape(status_line)}</span></div>'
            f'<div class="row"><span class="k">{t(lang, "empty_rules")}</span><span>{html.escape(t(lang, "kpi_rules_sub", exp=str(len(experimental)), custom=str(len(custom)), planned=str(len(planned))))}</span></div>'
            f'<div class="row"><span class="k">{t(lang, "empty_custom")}</span><span>{html.escape(custom_line or t(lang, "empty_never"))}</span></div>'
            f'<div class="row"><span class="k">{t(lang, "empty_last_sim")}</span><span>{html.escape(sim_line)}</span></div>'
            f'<div class="row"><span class="k">{t(lang, "empty_last_scan")}</span><span>{html.escape(scan_line)}</span></div>'
            f'<div class="row"><span class="k">{t(lang, "empty_how")}</span><span>{html.escape(t(lang, "empty_how_text"))}</span></div>'
            f'<div class="note">{t(lang, "empty_note")}</div></div>'
        )
    else:
        empty_html = ""

    # I18N strings for the JS (JSON-encoded, safe to embed).
    i18n_js = json.dumps(
        {
            "confirm_barrage": t(lang, "confirm_barrage"),
            "confirm_clear": t(lang, "confirm_clear"),
            "barrage_done": t(lang, "barrage_done"),
            "alert_barrage_fail": t(lang, "alert_barrage_fail"),
            "alert_clear_fail": t(lang, "alert_clear_fail"),
            "alert_scan_fail": t(lang, "alert_scan_fail"),
            "scan_done": t(lang, "scan_done"),
            "scan_done_clean": t(lang, "scan_done_clean"),
        }
    )

    q_esc = html.escape(query or "")
    clear_q = f"?lang={lang}" if lang != "en" else "/"

    html_out = f"""<!DOCTYPE html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MANAS AEGIS — {html.escape(t(lang, "title_sub"))}</title>
<style>{_HUD_CSS}</style></head>
<body>
<div class="top">
<div>
<div class="badge">◆ MANAS AEGIS</div>
<h1>MANAS AEGIS</h1>
<div class="sub">{t(lang, "title_sub")}</div>
<div class="sub2">{t(lang, "title_sub2")}</div>
</div>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
<label style="font-size:12px;color:var(--mut)">{t(lang, "lang_label")}</label>
<select id="langSel" onchange="setLang(this.value)">{lang_options}</select>
<button class="btn" onclick="toggleSound()">🔊 {t(lang, "sound")}</button>
<button class="btn" onclick="triggerBarrage()">▶ {t(lang, "run_sim")}</button>
</div>
</div>
<div class="status">{html.escape(status_line)}</div>
<div class="kpis">
<div class="kpi"><div class="n">{st["hard_blocked"]}</div><div class="l">{t(lang, "kpi_blocked")}</div><div class="f">{t(lang, "kpi_blocked_foot")}</div><div class="s">{t(lang, "kpi_sim", n=sim_block)}</div></div>
<div class="kpi"><div class="n">{st["virtual_patched"]}</div><div class="l">{t(lang, "kpi_modified")}</div><div class="f">{t(lang, "kpi_modified_foot")}</div><div class="s">{t(lang, "kpi_sim", n=sim_modify)}</div></div>
<div class="kpi"><div class="n">{st["honeypot_deceived"]}</div><div class="l">{t(lang, "kpi_honeypot")}</div><div class="f">{t(lang, "kpi_honeypot_foot")}</div><div class="s">{t(lang, "kpi_sim", n=sim_deceive)}</div></div>
<div class="kpi"><div class="n">{posture["rules_defined"]}</div><div class="l">{t(lang, "kpi_rules")}</div><div class="f">{t(lang, "kpi_events", n=total)}</div><div class="s">{t(lang, "kpi_rules_sub", exp=str(len(experimental)), custom=str(len(custom)), planned=str(len(planned)))}</div></div>
</div>
<div class="hist">{html.escape(range_label)}</div>
<div class="hist">{html.escape(t(lang, "history_line", real=str(hist["real"]), sim=str(hist["sim"])))}</div>
<div class="hist">{html.escape(sim_line)}</div>
<div class="scope">
<h3>{t(lang, "scope_monitored")}</h3>
<p>{t(lang, "scope_monitored_text", n=str(len(experimental)))}</p>
{"<p>" + html.escape(custom_line) + "</p>" if custom_line else ""}
<h3>{t(lang, "scope_not")}</h3>
<p>{t(lang, "scope_not_text")}</p>
</div>
<div class="scanrow">
<button class="btn" onclick="runScan('quick')">🔍 {t(lang, "scan_quick")}</button>
<button class="btn" onclick="runScan('full')">🔍 {t(lang, "scan_full")}</button>
<button class="btn" onclick="runScan('network')">🔍 {t(lang, "scan_network")}</button>
</div>
<div class="scanline">{html.escape(scan_line)}</div>
<div class="tabs">
<button class="tab active" onclick="showTab('act',this)">{t(lang, "tab_activity")}</button>
<button class="tab" onclick="showTab('intel',this)">{t(lang, "tab_intel")}</button>
<button class="tab" onclick="showTab('find',this)">{t(lang, "tab_findings")}</button>
</div>
<div class="panel active" id="tab-act">
<form class="search" method="get" action="">
<input type="hidden" name="lang" value="{lang}">
<input name="q" value="{q_esc}" placeholder="{html.escape(t(lang, 'search_placeholder'))}">
<button class="btn" type="submit">{t(lang, "search_button")}</button>
{f'<a href="{clear_q}">{t(lang, "search_clear")}</a>' if query else ""}
</form>
{f'<div class="hist">{html.escape(search_note)}</div>' if search_note else ""}
{empty_html if empty_html else ""}
{f'<table><tr><th>{t(lang, "col_time")}</th><th>{t(lang, "table_source")}</th><th>{t(lang, "col_rule")}</th><th>{t(lang, "col_action")}</th><th>{t(lang, "col_detail")}</th></tr>{rows}</table>' if rows else ("" if empty_html else f'<div class="empty">{t(lang, "no_activity")}</div>')}
<div style="margin-top:10px"><button class="btn" onclick="clearHistory()">{t(lang, "clear_history")}</button></div>
</div>
<div class="panel" id="tab-intel">
<h3 style="font-size:13px">{t(lang, "intel_global_title")}</h3>
<div class="note">{t(lang, "intel_global_note", sources=sources)}</div>
{f'<div class="note">{html.escape(intel_status)}</div>' if intel_status else ""}
<div style="margin:8px 0"><button class="btn" onclick="refreshIntel()">{t(lang, "intel_refresh")}</button></div>
{f'<table><tr><th>{t(lang, "intel_col_id")}</th><th>{t(lang, "intel_col_product")}</th><th>{t(lang, "intel_col_level")}</th><th>{t(lang, "intel_col_date")}</th><th>{t(lang, "intel_explain")}</th></tr>{intel_rows}</table>' if intel_rows else f'<div class="empty">{t(lang, "intel_none")}</div>'}
<h3 style="font-size:13px;margin-top:18px">{t(lang, "tab_intel")}</h3>
<table><tr><th>{t(lang, "col_rule")}</th><th>{t(lang, "intel_advisory")}</th><th>{t(lang, "intel_status")}</th><th>{t(lang, "col_action")}</th><th>{t(lang, "intel_explain")}</th><th>{t(lang, "intel_note_col")}</th></tr>{cat_rows}</table>
<div class="note">{t(lang, "intel_note")}</div>
</div>
<div class="panel" id="tab-find">
{f'<table><tr><th>{t(lang, "findings_time")}</th><th>{t(lang, "findings_check")}</th><th>{t(lang, "findings_severity")}</th><th>{t(lang, "findings_detail")}</th><th>File</th></tr>{find_rows}</table>' if find_rows else f'<div class="empty">{t(lang, "findings_empty")}</div>'}
</div>
<script>
const I18N = {i18n_js};
let soundOn = localStorage.getItem('manas-aegis-sound') === '1';
function setLang(v){{localStorage.setItem('manas-aegis-lang', v); const u = new URL(location.href); u.searchParams.set('lang', v); location.href = u.toString();}}
(function(){{const s = localStorage.getItem('manas-aegis-lang'); const u = new URL(location.href); if(!u.searchParams.get('lang') && s && s !== document.documentElement.lang){{u.searchParams.set('lang', s); location.replace(u.toString());}}}})();
function showTab(id, el){{document.querySelectorAll('.panel').forEach(p => p.classList.remove('active')); document.getElementById('tab-' + id).classList.add('active'); document.querySelectorAll('.tab').forEach(b => b.classList.remove('active')); el.classList.add('active');}}
function toggleSound(){{soundOn = !soundOn; localStorage.setItem('manas-aegis-sound', soundOn ? '1' : '0');}}
async function triggerBarrage(){{if(!confirm(I18N.confirm_barrage)) return; try{{const r = await fetch('/api/barrage', {{method: 'POST'}}); const d = await r.json(); if(d.status === 'ok'){{alert(I18N.barrage_done.replace('{{matched}}', d.results.filter(x => x.verdict === 'block' || x.verdict === 'modify').length)); location.reload();}} else {{alert(I18N.alert_barrage_fail);}}}} catch(e){{alert(I18N.alert_barrage_fail);}}}}
async function clearHistory(){{if(!confirm(I18N.confirm_clear)) return; try{{const r = await fetch('/api/clear-history', {{method: 'POST'}}); const d = await r.json(); if(d.status === 'ok'){{location.reload();}} else {{alert(I18N.alert_clear_fail);}}}} catch(e){{alert(I18N.alert_clear_fail);}}}}
async function runScan(scope){{try{{const r = await fetch('/api/scan', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{scope}})}}); const d = await r.json(); if(d.status === 'ok'){{const s = d.scan; alert(s.findings === 0 ? I18N.scan_done_clean.replace('{{scope}}', scope) : I18N.scan_done.replace('{{scope}}', scope).replace('{{findings}}', s.findings).replace('{{critical}}', s.critical)); location.reload();}} else {{alert(I18N.alert_scan_fail);}}}} catch(e){{alert(I18N.alert_scan_fail);}}}}
async function refreshIntel(){{try{{await fetch('/api/intel-refresh', {{method: 'POST'}}); setTimeout(() => location.reload(), 4000);}} catch(e){{}}}}
</script>
</body>
</html>"""
    return html_out


def write_hud_snapshot(core: ManasAegisCore, lang: Optional[str] = None) -> Path:
    html_str = build_analytical_hud_html(core, lang=lang or getattr(core, "last_lang", "en"))
    hud_file = core.state_dir / "dashboard.html"
    hud_file.write_text(html_str, encoding="utf-8")
    return hud_file


class _ManasHUDHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        core = get_core()
        parsed = urlparse(self.path)
        if parsed.path == "/api/search":
            qs = parse_qs(parsed.query)
            q = (qs.get("q", [""])[0] or "").strip()
            results = core.search_events(q)
            trimmed = [
                {
                    "timestamp": e.get("timestamp", ""),
                    "source": e.get("source", ""),
                    "rule_id": e.get("rule_id", ""),
                    "codename": e.get("codename", ""),
                    "cve_id": e.get("cve_id", ""),
                    "tool_name": e.get("tool_name", ""),
                    "verdict": e.get("verdict", ""),
                    "evidence": (e.get("evidence", "") or "")[:300],
                }
                for e in results
            ]
            payload = json.dumps(
                {"status": "ok", "query": q, "count": len(trimmed), "results": trimmed}
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed.path == "/api/stix":
            payload = json.dumps([e["stix_bundle"] for e in core.events[-25:]], indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return

        qs = parse_qs(parsed.query)
        lang = (qs.get("lang", ["en"])[0] or "en").strip()
        q = (qs.get("q", [""])[0] or "").strip()
        core.last_lang = lang
        html_bytes = build_analytical_hud_html(core, lang=lang, query=q or None).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_bytes)

    def do_POST(self) -> None:
        core = get_core()
        if self.path == "/api/barrage":
            results = core.execute_barrage_simulation()
            write_hud_snapshot(core)
            payload = json.dumps({"status": "ok", "results": results}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/clear-history":
            cleared = core.clear_all_history()
            write_hud_snapshot(core)
            payload = json.dumps({"status": "ok", "cleared": cleared}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length") or 0)
            scope = "quick"
            if length:
                try:
                    payload_in = json.loads(self.rfile.read(length).decode("utf-8"))
                    scope = str(payload_in.get("scope", "quick"))
                except Exception:
                    scope = "quick"
            summary = core.run_scan(scope, hud_ok=_SERVER_OK)
            write_hud_snapshot(core)
            payload = json.dumps({"status": "ok", "scan": summary}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/intel-refresh":
            threading.Thread(target=core.refresh_threat_intel, daemon=True).start()
            payload = json.dumps({"status": "ok", "refreshing": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()


def ensure_hud_server_running(port: int = 18777) -> str:
    global _SERVER_STARTED, _SERVER_OK
    if not _SERVER_STARTED:
        try:
            server = HTTPServer(("127.0.0.1", port), _ManasHUDHandler)
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            _SERVER_STARTED = True
            _SERVER_OK = True
            # Background threat-intel refresh: every 10 minutes, refresh
            # the global intel cache when it is missing or older than
            # 6 hours. Never raises; a failed refresh leaves the old
            # cache in place (and the HUD says so).
            def _intel_refresh_loop() -> None:
                while True:
                    try:
                        core = get_core()
                        intel = core.threat_intel or {}
                        fetched = str(intel.get("fetched_at", ""))
                        stale = True
                        if fetched:
                            try:
                                from datetime import datetime, timezone

                                age = (
                                    datetime.now(timezone.utc)
                                    - datetime.fromisoformat(fetched.replace("Z", "+00:00"))
                                ).total_seconds()
                                stale = age > 6 * 3600
                            except Exception:
                                stale = True
                        if stale or not intel.get("items"):
                            core.refresh_threat_intel()
                    except Exception:
                        pass
                    time.sleep(600)

            threading.Thread(target=_intel_refresh_loop, daemon=True).start()
        except Exception:
            _SERVER_OK = False
    return f"http://127.0.0.1:{port}"


def on_session_start_hook(session_id: str = "default", platform: str = "cli", **kwargs: Any) -> Dict[str, Any]:
    core = get_core()
    is_remote = any(k in session_id.lower() or k in platform.lower() for k in ("webhook", "group", "matrix", "telegram", "discord"))
    core.session_cass[session_id] = 1.75 if is_remote else 1.20
    hud_file = write_hud_snapshot(core)
    url = ensure_hud_server_running(int(core.config.get("hud_port", 18777)))
    return {"status": "MANAS_CORE_ENGAGED", "live_hud_url": url, "hud_file": str(hud_file), "hud_ok": bool(_SERVER_OK)}


def pre_llm_call_hook(messages: Any = None, session_id: str = "default", **kwargs: Any) -> Optional[Dict[str, Any]]:
    core = get_core()
    if isinstance(messages, list):
        for m in messages[-3:]:
            txt = m.get("content", "") if isinstance(m, dict) else str(m)
            if isinstance(txt, str) and core.MEMORY_DIRECTIVE_POISON.search(txt):
                core.session_cass[session_id] = 1.95
    return None


def pre_tool_call_hook(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    session_id: str = "default",
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    core = get_core()
    verdict = core.intercept_tool_call(tool_name=tool_name, args=args or {}, session_id=session_id)
    if verdict:
        write_hud_snapshot(core)
        return verdict
    return None


def transform_tool_result_hook(tool_name: str = "", result: Any = "", **kwargs: Any) -> Any:
    core = get_core()
    if isinstance(result, str):
        cleaned, count = core.scrub_output_stream(result)
        if count > 0:
            write_hud_snapshot(core)
        return cleaned
    return result


def transform_llm_output_hook(output: Any = "", **kwargs: Any) -> Any:
    core = get_core()
    if isinstance(output, str):
        cleaned, count = core.scrub_output_stream(output)
        if count > 0:
            write_hud_snapshot(core)
        return cleaned
    return output


def tool_manas_tactical_core(action: str = "status") -> str:
    core = get_core()
    url = ensure_hud_server_running(int(core.config.get("hud_port", 18777)))
    if action == "barrage":
        sim = core.execute_barrage_simulation()
        hud_file = write_hud_snapshot(core)
        return json.dumps(
            {
                "notice": "《 Notice: 6 local simulation examples checked against the rules (SIMULASI, not real attacks). 》",
                "live_hud_url": url,
                "dashboard_file": str(hud_file),
                "barrage_telemetry": sim,
            },
            indent=2,
        )
    hud_file = write_hud_snapshot(core)
    return json.dumps(
        {
            "notice": "《 Notice: Manas-Aegis guardrail (alpha) online. 》",
            "live_hud_url": url,
            "dashboard_file": str(hud_file),
            "posture": core.get_system_posture(),
        },
        indent=2,
    )


def tool_manas_stix_intelligence(view: str = "stix_feed") -> str:
    core = get_core()
    if view == "matrix":
        return json.dumps({k: vars(v) for k, v in THREAT_MATRIX.items()}, indent=2)
    return json.dumps(
        {
            "stix_version": "2.1",
            "total_bundles": len(core.events),
            "latest_bundles": [e["stix_bundle"] for e in core.events[-5:]],
        },
        indent=2,
    )


def register(ctx: Any) -> None:
    """Official Hermes Plugin Entrypoint (`hermes_manas_aegis:register`)."""
    cfg = getattr(ctx, "config", {}) if hasattr(ctx, "config") else {}
    core = get_core(cfg)
    write_hud_snapshot(core)
    if core.config.get("auto_launch_hud_server", True):
        ensure_hud_server_running(int(core.config.get("hud_port", 18777)))

    if hasattr(ctx, "register_hook"):
        ctx.register_hook("on_session_start", on_session_start_hook)
        ctx.register_hook("pre_llm_call", pre_llm_call_hook)
        ctx.register_hook("pre_tool_call", pre_tool_call_hook)
        ctx.register_hook("transform_tool_result", transform_tool_result_hook)
        ctx.register_hook("transform_llm_output", transform_llm_output_hook)
        core.hooks_verified = True

    if hasattr(ctx, "register_tool"):
        ctx.register_tool(
            name="manas_tactical_core",
            description="Control the Manas-Aegis guardrail (alpha): `status` shows local posture, `barrage` runs 6 local simulation examples against the rules.",
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["status", "barrage"],
                        "description": "Use 'barrage' to run 6 local simulation examples against the rules.",
                    }
                },
                "required": ["action"],
            },
            handler=tool_manas_tactical_core,
        )
        ctx.register_tool(
            name="manas_stix_intelligence",
            description="Export local STIX 2.1 bundles from stored events, or inspect the rule catalogue (internal advisory IDs, reference scores).",
            parameters={
                "type": "object",
                "properties": {
                    "view": {
                        "type": "string",
                        "enum": ["stix_feed", "matrix"],
                    }
                },
                "required": ["view"],
            },
            handler=tool_manas_stix_intelligence,
        )

    if hasattr(ctx, "register_command"):
        ctx.register_command(
            "/manas-hud",
            lambda *a, **kw: tool_manas_tactical_core(action="status"),
            description="Launch & display the Live Analytical Security HUD URL (http://127.0.0.1:18777).",
        )
        ctx.register_command(
            "/manas-barrage",
            lambda *a, **kw: tool_manas_tactical_core(action="barrage"),
            description="Run 6 local simulation examples against the rules (Git, credential, SSRF, SQLi, memory, webhook).",
        )
        ctx.register_command(
            "/manas-stix",
            lambda *a, **kw: tool_manas_stix_intelligence(view="stix_feed"),
            description="Export local STIX 2.1 bundles from stored events.",
        )
