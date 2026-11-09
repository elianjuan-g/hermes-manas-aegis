"""
Hermes Manas-Aegis Plugin Package Entrypoint & Live Analytical Matrix UI Server.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
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

# R3 (v2.6.0-alpha): HUD hardening. The server binds loopback only,
# but a malicious page in the user's browser could still POST to it
# (CSRF), and a runaway loop could hammer the endpoints. So every
# POST needs the per-process CSRF token (embedded in the page, sent
# as X-CSRF-Token) and is rate-limited per client IP. Token auth is
# opt-in: set config "hud_auth_token" and every request needs a
# session cookie obtained from /api/login; by default (no token
# configured) the HUD is open on loopback, as before.
_CSRF_TOKEN = secrets.token_hex(16)
_RATE_LIMIT: Dict[str, list] = {}
_RATE_MAX = 20  # POSTs per window per IP
_RATE_WINDOW = 60.0  # seconds
_SESSIONS: Dict[str, float] = {}  # session value -> expiry epoch


def _session_for(token: str) -> str:
    return hashlib.sha256(f"manas-aegis:{token}".encode("utf-8")).hexdigest()


def _rate_limited(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _RATE_LIMIT.get(ip, []) if now - t < _RATE_WINDOW]
    if len(hits) >= _RATE_MAX:
        _RATE_LIMIT[ip] = hits
        return True
    hits.append(now)
    _RATE_LIMIT[ip] = hits
    return False


def _csrf_ok(handler) -> bool:
    return hmac.compare_digest(handler.headers.get("X-CSRF-Token") or "", _CSRF_TOKEN)


def _authed(handler, core) -> bool:
    token = core.config.get("hud_auth_token")
    if not token:
        return True
    cookie = handler.headers.get("Cookie") or ""
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("manas_session="):
            sess = part.split("=", 1)[1].strip()
            exp = _SESSIONS.get(sess)
            if exp and exp > time.time() and hmac.compare_digest(sess, _session_for(str(token))):
                return True
    return False


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
/* Manas Aegis HUD — visual system adapted from the C3iHub CISO dashboard
   (real shipped enterprise security platform, IIT Kanpur, 2024):
   deep slate page, cards one step off the page, one severity scale used
   on every card/table/progress element, blue reserved for actions.
   No neon, no monospace UI, no emoji icons (Lucide SVG, stroke 2). */
:root{--page:#2A2C38;--card:#1E1F27;--card2:#23242F;--sidebar:#1F1F3B;
--line:#34364A;--line-soft:#2E3040;
--txt:#EDEEF2;--mut:#9A9DB0;--mut2:#6E7186;
--blue:#0168FF;--blue-hover:#2B7FFF;--nav-sel:#2F2263;--nav-sel-txt:#fff;
--crit:#F53821;--high:#FF9B10;--med:#FFCE20;--low:#00D796;--info:#80CAFF;
--danger:#E6292F;
--btn-bg:#2B2D3A;--input-bg:#2B2D3A;--th-bg:rgba(255,255,255,.02);--row-hover:rgba(255,255,255,.02)}
/* Light theme: same layout, same severity hues (darkened for contrast on
   white), same blue for actions. Toggle button in the topbar; choice is
   saved in the browser (localStorage 'manas-aegis-theme'). */
[data-theme="light"]{--page:#F2F3F5;--card:#FFFFFF;--card2:#F8F9FA;--sidebar:#FFFFFF;
--line:#DDE0E6;--line-soft:#E9EAEE;
--txt:#17181D;--mut:#5B5E6E;--mut2:#8A8D9C;
--blue:#0168FF;--blue-hover:#0A6CFF;--nav-sel:#E4EBFF;--nav-sel-txt:#0168FF;
--crit:#D92D20;--high:#DC6803;--med:#B54708;--low:#067647;--info:#175CD3;
--danger:#D92D20;
--btn-bg:#FFFFFF;--input-bg:#FFFFFF;--th-bg:rgba(0,0,0,.02);--row-hover:rgba(0,0,0,.03)}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--txt);font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.5}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
.app{display:flex;min-height:100vh}
.sidebar{width:224px;flex-shrink:0;background:var(--sidebar);border-right:1px solid var(--line-soft);padding:20px 14px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;padding:2px 10px 16px;border-bottom:1px solid var(--line-soft);margin-bottom:12px}
.brand-mark{width:34px;height:34px;flex-shrink:0;border-radius:9px;background:var(--blue);display:flex;align-items:center;justify-content:center;color:#fff}
.brand-mark svg{width:20px;height:20px}
.brand-name{font-size:15px;font-weight:700;letter-spacing:.03em;line-height:1.2}
.brand-sub{font-size:11px;color:var(--mut);line-height:1.35;margin-top:2px}
.nav-label{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut2);padding:10px 10px 6px}
.tab{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:transparent;border:0;color:var(--mut);padding:10px 12px;border-radius:8px;cursor:pointer;font:inherit;font-size:13px;font-weight:500}
.tab svg{width:16px;height:16px;flex-shrink:0}
.tab:hover{background:var(--row-hover);color:var(--txt)}
.tab.active{background:var(--nav-sel);color:var(--nav-sel-txt)}
.sidebar-foot{margin-top:auto;font-size:11px;color:var(--mut2);padding:10px;line-height:1.5}
.main{flex:1;min-width:0;padding:24px 28px 40px;max-width:1120px}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:18px}
h1{margin:0;font-size:20px;font-weight:700;letter-spacing:-.01em}
.sub{color:var(--mut);font-size:13px;margin-top:4px}
.sub2{color:var(--mut2);font-size:12px;margin-top:2px}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.actions label{font-size:12px;color:var(--mut)}
.btn{background:var(--btn-bg);border:1px solid var(--line);color:var(--txt);padding:8px 14px;border-radius:8px;cursor:pointer;font:inherit;font-size:13px;font-weight:500;display:inline-flex;align-items:center;gap:6px}
.btn svg{width:14px;height:14px;flex-shrink:0}
.btn:hover{border-color:var(--blue);color:#fff}
.btn-primary{background:var(--blue);border-color:var(--blue);color:#fff}
.btn-primary:hover{background:var(--blue-hover);border-color:var(--blue-hover);color:#fff}
select{background:var(--btn-bg);border:1px solid var(--line);color:var(--txt);padding:8px 10px;border-radius:8px;font:inherit;font-size:13px}
.status{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mut);margin-bottom:16px}
.status .dot{width:8px;height:8px;border-radius:50%;background:var(--low);flex-shrink:0}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:0 0 16px}
.kpi{background:var(--card);border:1px solid var(--line-soft);border-radius:12px;padding:16px 18px;position:relative;overflow:hidden}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--acc,var(--info))}
.kpi .n{font-size:30px;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.posture-mini{display:flex;gap:18px;align-items:center;flex-wrap:wrap;background:var(--card);border:1px solid var(--line-soft);border-radius:12px;padding:12px 16px;margin:0 0 14px}
.posture-mini .ps-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
.posture-mini .ps-score{font-size:26px;font-weight:800;line-height:1.1;font-variant-numeric:tabular-nums;white-space:nowrap}
.posture-mini .ps-score .grade{font-size:14px;color:var(--mut);font-weight:700}
.posture-mini .ps-comps{display:flex;gap:14px;flex-wrap:wrap;flex:1}
.posture-mini .ps-comp{font-size:12px;color:var(--mut);white-space:nowrap}
.posture-mini .ps-comp .bar{width:70px;height:6px}
.posture-mini .ps-comp b{color:var(--txt);font-weight:600;font-variant-numeric:tabular-nums}
.bar{display:inline-block;width:140px;height:8px;background:var(--line-soft);border-radius:4px;vertical-align:middle;overflow:hidden}
.bar span{display:block;height:100%;background:var(--info)}
.pill-pass{background:rgba(0,215,150,.14);color:var(--low)}
.pill-fail{background:rgba(245,56,33,.14);color:var(--crit)}
.kpi .l{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin-top:2px}
.kpi .f{font-size:12px;color:var(--mut2);margin-top:8px}
.kpi .s{font-size:12px;color:var(--mut);margin-top:2px}
.hist{font-size:12px;color:var(--mut);margin:6px 0}
.card{background:var(--card);border:1px solid var(--line-soft);border-radius:12px;padding:16px 18px;margin:14px 0}
.card h3{margin:0 0 8px;font-size:13px;font-weight:600;color:var(--txt)}
.card p{margin:4px 0;color:var(--mut);font-size:13px}
.scanrow{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.scanline{font-size:12px;color:var(--mut);margin:8px 0 0}
.search{display:flex;gap:8px;margin:12px 0;align-items:center}
.search input{flex:1;background:var(--input-bg);border:1px solid var(--line);color:var(--txt);padding:9px 12px;border-radius:8px;font:inherit;font-size:13px}
.search a{font-size:13px}
.panel{display:none}
.panel.active{display:block}
.section-title{font-size:15px;font-weight:700;margin:20px 0 10px}
.tablewrap{background:var(--card);border:1px solid var(--line-soft);border-radius:12px;overflow:hidden;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:11px 12px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.06em;background:var(--th-bg);border-bottom:1px solid var(--line-soft)}
td{border-bottom:1px solid var(--line-soft)}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--row-hover)}
.mono{font-family:ui-monospace,'JetBrains Mono',Menlo,monospace;font-size:12px}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.02em;white-space:nowrap}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}
.pill-real{background:rgba(0,215,150,.12);color:var(--low)}
.pill-sim{background:rgba(255,155,16,.12);color:var(--high)}
.pill-custom{background:rgba(128,202,255,.12);color:var(--info)}
.pill-crit{background:rgba(245,56,33,.12);color:var(--crit)}
.pill-high{background:rgba(255,155,16,.12);color:var(--high)}
.pill-med{background:rgba(255,206,32,.12);color:var(--med)}
.pill-low{background:rgba(0,215,150,.12);color:var(--low)}
.pill-info{background:rgba(128,202,255,.12);color:var(--info)}
.empty{background:var(--card);border:1px dashed var(--line);border-radius:12px;padding:28px;text-align:center;color:var(--mut);font-size:13px}
.info{background:var(--card);border:1px solid var(--line-soft);border-radius:12px;padding:20px 22px;font-size:13px;text-align:left}
.info h3{margin:0 0 12px;font-size:14px;color:var(--txt);text-align:left}
.info .row{display:flex;gap:12px;margin:0;padding:7px 0;border-bottom:1px solid var(--line-soft)}
.info .row:last-child{border-bottom:0}
.info .k{color:var(--mut);min-width:160px;flex-shrink:0;font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding-top:2px}
.note{font-size:12px;color:var(--mut2);margin-top:10px}
.explain{font-size:12px;color:var(--mut);line-height:1.55}
.explain b{color:var(--txt);font-weight:600}
details{font-size:12px;color:var(--mut)}
summary{cursor:pointer;color:var(--blue)}
@media(max-width:760px){.app{flex-direction:column}.sidebar{width:100%;height:auto;position:static;flex-direction:row;flex-wrap:wrap;align-items:center;padding:12px}.brand{border:0;padding:0 10px 0 0;margin:0}.nav-label{display:none}.tab{width:auto}.sidebar-foot{display:none}.main{padding:16px}.kpis{grid-template-columns:repeat(2,1fr)}.info .k{min-width:110px}}
"""


def _svg(inner: str, size: int = 16) -> str:
    """Inline Lucide icon (ISC, 24px grid, stroke 2, currentColor)."""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round">{inner}</svg>'
    )


_SVG_SHIELD = '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
_SVG_ACTIVITY = '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>'
_SVG_SEARCH = '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'
_SVG_PLAY = '<polygon points="6 3 20 12 6 21 6 3"/>'
_SVG_VOLUME = '<path d="M11 4.702a.705.705 0 0 0-1.203-.498L6.413 7.587A1.4 1.4 0 0 1 5.416 8H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2.416a1.4 1.4 0 0 1 .997.413l3.383 3.384A.705.705 0 0 0 11 19.298z"/><path d="M16 9a5 5 0 0 1 0 6"/><path d="M19.364 18.364a9 9 0 0 0 0-12.728"/>'
_SVG_REFRESH = '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>'
_SVG_SCAN = '<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M7 12h10"/>'
_SVG_TRASH = '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>'
_SVG_TARGET = '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>'
_SVG_SUN = '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>'
_SVG_MOON = '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>'


def _sev_pill_class(sev: str) -> str:
    """Findings severity -> pill class (CISO severity scale)."""
    return {"critical": "pill-crit", "warning": "pill-high", "info": "pill-info"}.get(sev, "pill-info")


def _intel_level_pill(level: str) -> str:
    """Intel level string -> pill class (CISO severity scale)."""
    lv = (level or "").upper()
    if "CRITICAL" in lv or "ACTIVELY EXPLOITED" in lv:
        return "pill-crit"
    if "HIGH" in lv:
        return "pill-high"
    if "MEDIUM" in lv or "MODERATE" in lv:
        return "pill-med"
    if "LOW" in lv:
        return "pill-low"
    return "pill-info"


def _intel_level_label(level: str, lang: str = "en") -> str:
    """Translate the intel level for display.

    The level is data from CISA/NVD (English). The CISA level
    "Actively exploited" gets a translated label; an NVD level like
    "9.8 CRITICAL" keeps its numeric score and translates the
    severity word via the sev_* keys.
    """
    lvl = (level or "").strip()
    if not lvl:
        return lvl
    if lvl.upper() == "ACTIVELY EXPLOITED":
        return t(lang, "intel_level_exploited")
    m = re.match(r"^([\d.]+)\s+(\w+)\s*$", lvl)
    if m:
        score, word = m.group(1), m.group(2)
        # NVD severity words: CRITICAL reuses sev_critical; HIGH /
        # MEDIUM / LOW have their own intel_sev_* keys.
        w = word.upper()
        if w == "CRITICAL":
            key = "sev_critical"
        elif w in ("HIGH", "MEDIUM", "LOW"):
            key = "intel_sev_" + w.lower()
        else:
            return lvl
        if key in LANGS.get(lang, {}):
            return f"{score} {t(lang, key)}"
        return lvl
    return lvl


def _finding_text(f: Dict[str, Any], lang: str = "en") -> tuple:
    """Render a scan finding's title + detail in the HUD language.

    Key-based findings (v2.5.2+) render via t(); older stored rows
    fall back to their stored text (they were migrated on load, but
    an unmapped row still shows its original text rather than a key).
    """
    tkey = str(f.get("title_key", "") or "")
    dkey = str(f.get("detail_key", "") or "")
    params = f.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    if tkey:
        try:
            title = t(lang, tkey, **params)
        except Exception:
            title = str(f.get("title", tkey))
    else:
        title = str(f.get("title", ""))
    if dkey:
        try:
            detail = t(lang, dkey, **params)
        except Exception:
            detail = str(f.get("detail", dkey))
    else:
        detail = str(f.get("detail", ""))
    return title, detail


def build_analytical_hud_html(core, lang="en", query=None, active_tab="act") -> str:
    if lang not in {c for c, _ in SUPPORTED_LANGS}:
        lang = DEFAULT_LANG
    if active_tab not in ("act", "intel", "find", "arena"):
        active_tab = "act"
    posture = core.get_system_posture()
    st = posture["stats"]
    # R3: posture score + last arena / time-travel runs (persisted JSON).
    pscore = core.compute_posture_score()

    def _load_json(name):
        try:
            return json.loads((core.state_dir / name).read_text(encoding="utf-8"))
        except Exception:
            return None

    arena_last = _load_json("arena_last.json")
    tta_last = _load_json("tta_last.json")
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
    # Verdict strings are "HARD_BLOCK", "SYNTHESIZED_PATCH (Modify Args)",
    # "HONEYPOT_DECEIVED (Modify Args)" — match by substring, exactly like
    # get_last_simulation() and the posture counters do. Exact equality
    # ("BLOCK") matched nothing and showed 0/0/0 even after a real run
    # (bug found 2026-11-09 from MyLord's screenshot: 12 sim events,
    # all subcounts 0).
    sim_block = sum(
        1
        for e in core.events
        if e.get("source") == "simulation" and "BLOCK" in str(e.get("verdict", ""))
    )
    sim_modify = sum(
        1
        for e in core.events
        if e.get("source") == "simulation" and "SYNTHESIZED" in str(e.get("verdict", ""))
    )
    sim_deceive = sum(
        1
        for e in core.events
        if e.get("source") == "simulation" and "HONEYPOT" in str(e.get("verdict", ""))
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
        sev_pill = _sev_pill_class(sev)
        ftitle, fdetail = _finding_text(f, lang)
        ffile = str(f.get("file", ""))
        fline = f.get("line")
        file_cell = html.escape(ffile)
        if fline is not None:
            file_cell += f":{fline}"
        # R2.5.2: the check name is a translated label (was a raw
        # English id), and the Detail cell shows the finding's title
        # + detail (both translated) instead of the detail alone.
        check = str(f.get("check", ""))
        check_key = "check_" + check
        check_label = t(lang, check_key) if check_key in LANGS.get(lang, {}) else check
        find_rows += (
            f'<tr><td>{html.escape(str(f.get("timestamp", "")))}</td>'
            f"<td>{html.escape(check_label)}</td>"
            f'<td><span class="pill {sev_pill}">{html.escape(sev_label)}</span></td>'
            f"<td><strong>{html.escape(ftitle)}</strong><br>"
            f'<span class="muted">{html.escape(fdetail)}</span></td>'
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
            f'<td><span class="pill {_intel_level_pill(str(item.get("level", "")))}">{html.escape(_intel_level_label(str(item.get("level", "")), lang))}</span></td>' 
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
            "theme_dark": t(lang, "theme_dark"),
            "theme_light": t(lang, "theme_light"),
        }
    )

    q_esc = html.escape(query or "")
    clear_q = f"?lang={lang}" if lang != "en" else "/"

    # R3: Posture Score as a compact minimalist box (score + grade on the
    # left, five small component chips on the right). Rendered ONLY inside
    # the Activity tab panel -- never in the shared <main> flow.
    _comp = pscore["components"]

    def _pmini(label, value, maximum):
        pct = int(round(100.0 * value / maximum)) if maximum else 0
        return (
            f'<span class="ps-comp">{html.escape(label)} '
            f'<span class="bar"><span style="width:{pct}%"></span></span> '
            f"<b>{value}/{maximum}</b></span>"
        )

    posture_html = (
        f'<div class="posture-mini"><div><div class="ps-title">{t(lang, "posture_score")}</div>'
        f'<div class="ps-score">{pscore["score"]} <span class="grade">{html.escape(pscore["grade"])}</span></div></div>'
        f'<div class="ps-comps">'
        + _pmini(t(lang, "posture_rules"), _comp["rules"], 25)
        + _pmini(t(lang, "posture_enforcement"), _comp["enforcement"], 25)
        + _pmini(t(lang, "posture_hygiene"), _comp["hygiene"], 20)
        + _pmini(t(lang, "posture_intel"), _comp["intel"], 15)
        + _pmini(t(lang, "posture_activity"), _comp["activity"], 15)
        + "</div></div>"
    )

    # R3: Arena panel rows (last persisted run, if any).
    if arena_last and arena_last.get("results"):
        _arows = ""
        for _r in arena_last["results"]:
            _pill = "pill-pass" if _r.get("passed") else "pill-fail"
            _plabel = t(lang, "arena_pass") if _r.get("passed") else t(lang, "arena_fail")
            _arows += (
                f"<tr><td>{html.escape(str(_r.get('name', '')))}</td>"
                f"<td>{html.escape(str(_r.get('expect', '')))}</td>"
                f"<td>{html.escape(str(_r.get('actual', '')))}</td>"
                f'<td><span class="pill {_pill}">{html.escape(_plabel)}</span></td></tr>'
            )
        arena_html = (
            f'<div class="tablewrap"><table><tr><th>{t(lang, "arena_scenario")}</th>'
            f"<th>{t(lang, 'arena_expected')}</th><th>{t(lang, 'arena_result')}</th><th></th></tr>"
            f"{_arows}</table></div>"
            f'<div class="hist">{html.escape(t(lang, "arena_last", passed=str(arena_last.get("passed", 0)), total=str(arena_last.get("total", 0))))}</div>'
        )
    else:
        arena_html = f'<div class="empty">{t(lang, "arena_none")}</div>'

    # R3: Time-travel audit rows (last persisted run, if any).
    if tta_last and tta_last.get("results"):
        _trows = ""
        for _r in tta_last["results"]:
            if not _r.get("newly_caught"):
                continue
            _trows += (
                f"<tr><td>{html.escape(str(_r.get('timestamp', '')))}</td>"
                f"<td>{html.escape(str(_r.get('tool', '')))}</td>"
                f"<td>{html.escape(str(_r.get('old_rule', '')))}</td>"
                f"<td>{html.escape(', '.join(_r.get('new_hits') or []))}</td></tr>"
            )
        if _trows:
            tta_html = (
                f'<div class="tablewrap"><table><tr><th>{t(lang, "col_time")}</th>'
                f"<th>{t(lang, 'table_source')}</th><th>{t(lang, 'col_rule')}</th>"
                f"<th>{t(lang, 'tta_new_rule')}</th></tr>{_trows}</table></div>"
                f'<div class="hist">{html.escape(t(lang, "tta_last", newly=str(tta_last.get("newly_caught", 0)), total=str(tta_last.get("total", 0))))}</div>'
            )
        else:
            tta_html = f'<div class="note">{html.escape(t(lang, "tta_last", newly="0", total=str(tta_last.get("total", 0))))}</div>'
    else:
        tta_html = f'<div class="empty">{t(lang, "tta_none")}</div>'

    html_out = f"""<!DOCTYPE html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="{_CSRF_TOKEN}">
<title>MANAS AEGIS — {html.escape(t(lang, "title_sub"))}</title>
<script>try{{var _th=localStorage.getItem('manas-aegis-theme');if(_th==='light'||_th==='dark'){{document.documentElement.setAttribute('data-theme',_th);}}}}catch(e){{}}</script>
<style>{_HUD_CSS}</style></head>
<body>
<div class="app">
<aside class="sidebar">
<div class="brand">
<span class="brand-mark">{_svg(_SVG_SHIELD, 20)}</span>
<div><div class="brand-name">MANAS AEGIS</div><div class="brand-sub">{html.escape(t(lang, "title_sub"))}</div></div>
</div>
<div class="nav-label">{html.escape(t(lang, "nav_monitor"))}</div>
<button class="tab{" active" if active_tab == "act" else ""}" onclick="showTab('act',this)">{_svg(_SVG_ACTIVITY)}<span>{t(lang, "tab_activity")}</span></button>
<button class="tab{" active" if active_tab == "intel" else ""}" onclick="showTab('intel',this)">{_svg(_SVG_SHIELD)}<span>{t(lang, "tab_intel")}</span></button>
<button class="tab{" active" if active_tab == "find" else ""}" onclick="showTab('find',this)">{_svg(_SVG_SEARCH)}<span>{t(lang, "tab_findings")}</span></button>
<button class="tab{" active" if active_tab == "arena" else ""}" onclick="showTab('arena',this)">{_svg(_SVG_TARGET)}<span>{t(lang, "nav_arena")}</span></button>
<div class="sidebar-foot">
<div>{html.escape(str(posture["codename"]))}</div>
<div>{html.escape(status_line)}</div>
</div>
</aside>
<main class="main">
<div class="topbar">
<div>
<h1>MANAS AEGIS</h1>
<div class="sub">{t(lang, "title_sub")}</div>
<div class="sub2">{t(lang, "title_sub2")}</div>
</div>
<div class="actions">
<label>{t(lang, "lang_label")}</label>
<select id="langSel" onchange="setLang(this.value)">{lang_options}</select>
<button class="btn" id="themeBtn" onclick="toggleTheme()">{_svg(_SVG_SUN)}<span>{t(lang, "theme_light")}</span></button>
<button class="btn" onclick="toggleSound()">{_svg(_SVG_VOLUME)}<span>{t(lang, "sound")}</span></button>
<button class="btn btn-primary" onclick="triggerBarrage()">{_svg(_SVG_PLAY)}<span>{t(lang, "run_sim")}</span></button>
</div>
</div>
<div class="status"><span class="dot"></span><span>{html.escape(status_line)}</span></div>
<div class="kpis">
<div class="kpi" style="--acc:var(--crit)"><div class="n">{st["hard_blocked"]}</div><div class="l">{t(lang, "kpi_blocked")}</div><div class="f">{t(lang, "kpi_blocked_foot")}</div><div class="s">{t(lang, "kpi_sim", n=sim_block)}</div></div>
<div class="kpi" style="--acc:var(--high)"><div class="n">{st["virtual_patched"]}</div><div class="l">{t(lang, "kpi_modified")}</div><div class="f">{t(lang, "kpi_modified_foot")}</div><div class="s">{t(lang, "kpi_sim", n=sim_modify)}</div></div>
<div class="kpi" style="--acc:var(--med)"><div class="n">{st["honeypot_deceived"]}</div><div class="l">{t(lang, "kpi_honeypot")}</div><div class="f">{t(lang, "kpi_honeypot_foot")}</div><div class="s">{t(lang, "kpi_sim", n=sim_deceive)}</div></div>
<div class="kpi" style="--acc:var(--info)"><div class="n">{posture["rules_defined"]}</div><div class="l">{t(lang, "kpi_rules")}</div><div class="f">{t(lang, "kpi_events", n=total)}</div><div class="s">{t(lang, "kpi_rules_sub", exp=str(len(experimental)), custom=str(len(custom)), planned=str(len(planned)))}</div></div>
</div>
<div class="hist">{html.escape(range_label)}</div>
<div class="hist">{html.escape(t(lang, "history_line", real=str(hist["real"]), sim=str(hist["sim"])))}</div>
<div class="hist">{html.escape(sim_line)}</div>
<div class="card">
<h3>{t(lang, "scope_monitored")}</h3>
<p>{t(lang, "scope_monitored_text", n=str(len(experimental)))}</p>
{"<p>" + html.escape(custom_line) + "</p>" if custom_line else ""}
<h3>{t(lang, "scope_not")}</h3>
<p>{t(lang, "scope_not_text")}</p>
</div>
<div class="card">
<h3>{t(lang, "scan_title")}</h3>
<div class="scanrow">
<button class="btn" onclick="runScan('quick')">{_svg(_SVG_SCAN)}<span>{t(lang, "scan_quick")}</span></button>
<button class="btn" onclick="runScan('full')">{_svg(_SVG_SCAN)}<span>{t(lang, "scan_full")}</span></button>
<button class="btn" onclick="runScan('network')">{_svg(_SVG_SCAN)}<span>{t(lang, "scan_network")}</span></button>
</div>
<div class="scanline">{html.escape(scan_line)}</div>
</div>
<div class="panel{" active" if active_tab == "act" else ""}" id="tab-act">
{posture_html}
<form class="search" method="get" action="">
<input type="hidden" name="lang" value="{lang}">
<input type="hidden" name="tab" value="act">
<input name="q" value="{q_esc}" placeholder="{html.escape(t(lang, 'search_placeholder'))}">
<button class="btn" type="submit">{_svg(_SVG_SEARCH)}<span>{t(lang, "search_button")}</span></button>
{f'<a href="{clear_q}">{t(lang, "search_clear")}</a>' if query else ""}
</form>
{f'<div class="hist">{html.escape(search_note)}</div>' if search_note else ""}
{empty_html if empty_html else ""}
{f'<div class="tablewrap"><table><tr><th>{t(lang, "col_time")}</th><th>{t(lang, "table_source")}</th><th>{t(lang, "col_rule")}</th><th>{t(lang, "col_action")}</th><th>{t(lang, "col_detail")}</th></tr>{rows}</table></div>' if rows else ("" if empty_html else f'<div class="empty">{t(lang, "no_activity")}</div>')}
<div style="margin-top:12px"><button class="btn" onclick="clearHistory()">{_svg(_SVG_TRASH)}<span>{t(lang, "clear_history")}</span></button></div>
</div>
<div class="panel{" active" if active_tab == "intel" else ""}" id="tab-intel">
<h3 class="section-title">{t(lang, "intel_global_title")}</h3>
<div class="note">{t(lang, "intel_global_note", sources=sources)}</div>
{f'<div class="note">{html.escape(intel_status)}</div>' if intel_status else ""}
<div style="margin:10px 0"><button class="btn" onclick="refreshIntel()">{_svg(_SVG_REFRESH)}<span>{t(lang, "intel_refresh")}</span></button></div>
{f'<div class="tablewrap"><table><tr><th>{t(lang, "intel_col_id")}</th><th>{t(lang, "intel_col_product")}</th><th>{t(lang, "intel_col_level")}</th><th>{t(lang, "intel_col_date")}</th><th>{t(lang, "intel_explain")}</th></tr>{intel_rows}</table></div>' if intel_rows else f'<div class="empty">{t(lang, "intel_none")}</div>'}
<h3 class="section-title">{t(lang, "tab_intel")}</h3>
<div class="tablewrap"><table><tr><th>{t(lang, "col_rule")}</th><th>{t(lang, "intel_advisory")}</th><th>{t(lang, "intel_status")}</th><th>{t(lang, "col_action")}</th><th>{t(lang, "intel_explain")}</th><th>{t(lang, "intel_note_col")}</th></tr>{cat_rows}</table></div>
<div class="note">{t(lang, "intel_note")}</div>
</div>
<div class="panel{" active" if active_tab == "find" else ""}" id="tab-find">
{f'<div class="tablewrap"><table><tr><th>{t(lang, "findings_time")}</th><th>{t(lang, "findings_check")}</th><th>{t(lang, "findings_severity")}</th><th>{t(lang, "findings_detail")}</th><th>{t(lang, "findings_file")}</th></tr>{find_rows}</table></div>' if find_rows else f'<div class="empty">{t(lang, "findings_empty")}</div>'}
</div>
<div class="panel{" active" if active_tab == "arena" else ""}" id="tab-arena">
<h3 class="section-title">{t(lang, "arena_title")}</h3>
<div style="margin:10px 0"><button class="btn btn-primary" onclick="runArena()">{_svg(_SVG_TARGET)}<span>{t(lang, "arena_run")}</span></button></div>
{arena_html}
<h3 class="section-title">{t(lang, "tta_title")}</h3>
<div style="margin:10px 0"><button class="btn" onclick="runTimeTravel()">{_svg(_SVG_SEARCH)}<span>{t(lang, "tta_run")}</span></button></div>
{tta_html}
</div>
</main>
</div>
<script>
const I18N = {i18n_js};
const CSRF = (document.querySelector('meta[name="csrf-token"]') || {{content: ''}}).content;
const ICON_SUN = `{_svg(_SVG_SUN, 14)}`;
const ICON_MOON = `{_svg(_SVG_MOON, 14)}`;
let soundOn = localStorage.getItem('manas-aegis-sound') === '1';
function setLang(v){{localStorage.setItem('manas-aegis-lang', v); const u = new URL(location.href); u.searchParams.set('lang', v); location.href = u.toString();}}
(function(){{const s = localStorage.getItem('manas-aegis-lang'); const u = new URL(location.href); if(!u.searchParams.get('lang') && s && s !== document.documentElement.lang){{u.searchParams.set('lang', s); location.replace(u.toString());}}}})();
function applyTheme(theme){{document.documentElement.setAttribute('data-theme', theme); localStorage.setItem('manas-aegis-theme', theme); const b = document.getElementById('themeBtn'); if(b){{ b.innerHTML = (theme === 'light' ? ICON_MOON + '<span>' + I18N.theme_dark + '</span>' : ICON_SUN + '<span>' + I18N.theme_light + '</span>'); }}}}
function toggleTheme(){{const cur = document.documentElement.getAttribute('data-theme') || 'dark'; applyTheme(cur === 'dark' ? 'light' : 'dark');}}
(function(){{const saved = localStorage.getItem('manas-aegis-theme'); applyTheme(saved === 'light' ? 'light' : 'dark');}})();
function showTab(id, el){{document.querySelectorAll('.panel').forEach(p => p.classList.remove('active')); document.getElementById('tab-' + id).classList.add('active'); document.querySelectorAll('.tab').forEach(b => b.classList.remove('active')); el.classList.add('active');}}
function toggleSound(){{soundOn = !soundOn; localStorage.setItem('manas-aegis-sound', soundOn ? '1' : '0');}}
async function triggerBarrage(){{if(!confirm(I18N.confirm_barrage)) return; try{{const r = await fetch('/api/barrage', {{method: 'POST', headers: {{'X-CSRF-Token': CSRF}}}}); const d = await r.json(); if(d.status === 'ok'){{alert(I18N.barrage_done.replace('{{matched}}', d.results.filter(x => x.verdict === 'block' || x.verdict === 'modify').length)); location.reload();}} else {{alert(I18N.alert_barrage_fail);}}}} catch(e){{alert(I18N.alert_barrage_fail);}}}}
async function clearHistory(){{if(!confirm(I18N.confirm_clear)) return; try{{const r = await fetch('/api/clear-history', {{method: 'POST', headers: {{'X-CSRF-Token': CSRF}}}}); const d = await r.json(); if(d.status === 'ok'){{location.reload();}} else {{alert(I18N.alert_clear_fail);}}}} catch(e){{alert(I18N.alert_clear_fail);}}}}
async function runScan(scope){{try{{const r = await fetch('/api/scan', {{method: 'POST', headers: {{'Content-Type': 'application/json', 'X-CSRF-Token': CSRF}}, body: JSON.stringify({{scope}})}}); const d = await r.json(); if(d.status === 'ok'){{const s = d.scan; alert(s.findings === 0 ? I18N.scan_done_clean.replace('{{scope}}', scope) : I18N.scan_done.replace('{{scope}}', scope).replace('{{findings}}', s.findings).replace('{{critical}}', s.critical)); const u = new URL(location.href); u.searchParams.set('tab', 'find'); u.searchParams.delete('q'); location.href = u.toString();}} else {{alert(I18N.alert_scan_fail);}}}} catch(e){{alert(I18N.alert_scan_fail);}}}}
async function refreshIntel(){{try{{await fetch('/api/intel-refresh', {{method: 'POST', headers: {{'X-CSRF-Token': CSRF}}}}); setTimeout(() => location.reload(), 4000);}} catch(e){{}}}}
async function runArena(){{try{{const r = await fetch('/api/arena', {{method: 'POST', headers: {{'X-CSRF-Token': CSRF}}}}); const d = await r.json(); if(d.status === 'ok'){{const u = new URL(location.href); u.searchParams.set('tab', 'arena'); location.href = u.toString();}} else {{alert(I18N.alert_scan_fail);}}}} catch(e){{alert(I18N.alert_scan_fail);}}}}
async function runTimeTravel(){{try{{const r = await fetch('/api/time-travel', {{method: 'POST', headers: {{'X-CSRF-Token': CSRF}}}}); const d = await r.json(); if(d.status === 'ok'){{const u = new URL(location.href); u.searchParams.set('tab', 'arena'); location.href = u.toString();}} else {{alert(I18N.alert_scan_fail);}}}} catch(e){{alert(I18N.alert_scan_fail);}}}}
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
        if not _authed(self, core):
            login_html = (
                "<!doctype html><html><head><meta charset='utf-8'>"
                "<title>Manas Aegis — Login</title></head><body>"
                "<h1>Manas Aegis</h1>"
                "<p>This HUD is protected. Enter the HUD token to continue.</p>"
                "<form method='POST' action='/api/login'>"
                "<input type='password' name='token' autocomplete='off' />"
                "<button type='submit'>Login</button></form></body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(login_html)
            return
        # Re-read on-disk state so events/findings written by other
        # processes (a live Hermes agent, another session's scan) show
        # up without a server restart.
        core.reload_state()
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
        tab = (qs.get("tab", ["act"])[0] or "act").strip()
        core.last_lang = lang
        html_bytes = build_analytical_hud_html(core, lang=lang, query=q or None, active_tab=tab).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_bytes)

    def do_POST(self) -> None:
        core = get_core()
        ip = self.client_address[0] if self.client_address else "unknown"
        if self.path != "/api/login" and _rate_limited(ip):
            payload = json.dumps({"status": "error", "error": "rate_limited"}).encode("utf-8")
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "60")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/login":
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8") if length else ""
            qs = parse_qs(body)
            submitted = (qs.get("token", [""])[0] or "").strip()
            want = str(core.config.get("hud_auth_token") or "")
            if want and hmac.compare_digest(submitted, want):
                sess = _session_for(want)
                _SESSIONS[sess] = time.time() + 24 * 3600
                self.send_response(302)
                self.send_header("Set-Cookie", f"manas_session={sess}; HttpOnly; Path=/; Max-Age=86400")
                self.send_header("Location", "/")
                self.end_headers()
                return
            payload = json.dumps({"status": "error", "error": "bad_token"}).encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if not _authed(self, core):
            payload = json.dumps({"status": "error", "error": "unauthorized"}).encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if not _csrf_ok(self):
            payload = json.dumps({"status": "error", "error": "bad_csrf_token"}).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/arena":
            result = core.run_arena()
            write_hud_snapshot(core)
            payload = json.dumps({"status": "ok", "arena": result}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/time-travel":
            result = core.run_time_travel_audit()
            write_hud_snapshot(core)
            payload = json.dumps({"status": "ok", "audit": result}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
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
