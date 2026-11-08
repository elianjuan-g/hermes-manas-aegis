"""
Hermes Manas-Aegis Plugin Package Entrypoint & Live Analytical Matrix UI Server.
"""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from .core_engine import ManasAegisCore, THREAT_MATRIX


_CORE: Optional[ManasAegisCore] = None
_SERVER_STARTED = False
_SERVER_OK: Optional[bool] = None  # None = belum dicoba, True = bind berhasil, False = bind gagal


def get_core(config: Optional[Dict[str, Any]] = None) -> ManasAegisCore:
    global _CORE
    if _CORE is None:
        state_dir = Path.home() / ".hermes" / "plugins" / "hermes-manas-aegis"
        _CORE = ManasAegisCore(state_dir=state_dir, config=config or {})
    return _CORE


def _action_label(verdict: str) -> str:
    if "HARD_BLOCK" in verdict:
        return "Diblokir"
    if "SYNTHESIZED" in verdict:
        return "Argumen diubah"
    if "HONEYPOT" in verdict:
        return "Konten disamarkan"
    return verdict or "Dicatat"


def _strategy_label(strategy: str) -> str:
    return {
        "HARD_BLOCK": "Diblokir",
        "SYNTHESIZE_PATCH": "Argumen diubah",
        "HONEYPOT_DECEIVE": "Konten disamarkan",
    }.get(strategy, strategy)


def _plain_reason(ev: Dict[str, Any]) -> str:
    verdict = str(ev.get("verdict", ""))
    rule = str(ev.get("codename", "aturan ini"))
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


def build_analytical_hud_html(core: ManasAegisCore) -> str:
    posture = core.get_system_posture()
    stats = posture["stats"]
    runtime_total = stats["total_intercepted"]
    sim_total = stats["simulation_events"]
    total_stored = stats["total_stored"]
    events = list(reversed(core.events[-15:]))

    # --- Activity rows (Waktu / Sumber / Aturan / Tindakan / Detail) ---
    rows = ""
    for ev in events:
        verdict = str(ev.get("verdict", ""))
        source = str(ev.get("source", "runtime"))
        if source == "simulation":
            source_badge = '<span class="pill pill-sim">SIMULASI</span>'
        else:
            source_badge = '<span class="pill pill-real">Nyata</span>'
        ts_esc = html.escape(str(ev.get("timestamp", "")))
        adv_esc = html.escape(str(ev.get("cve_id", "")))
        rule_esc = html.escape(str(ev.get("codename", "")))
        action_esc = html.escape(_action_label(verdict))
        reason_esc = html.escape(_plain_reason(ev))
        cwe_esc = html.escape(str(ev.get("cwe_id", "")))
        score_esc = html.escape(str(ev.get("composite_score", "")))
        cvss_esc = html.escape(str(ev.get("cvss_base", "")))
        epss_esc = html.escape(str(round(float(ev.get("epss_prob", 0.0)) * 100, 1)))
        cwss_esc = html.escape(str(ev.get("cwss_score", "")))
        ssvc_esc = html.escape(str(ev.get("ssvc_decision", "TRACK")))
        tool_esc = html.escape(str(ev.get("tool_name", "")))
        evidence_esc = html.escape(str(ev.get("evidence", ""))[:95])
        rows += f"""
        <tr class="event-row">
          <td><code>{ts_esc}</code></td>
          <td>{source_badge}</td>
          <td><b style="color:#fff;">{adv_esc}</b><br><small>{rule_esc}</small></td>
          <td>{action_esc}</td>
          <td>
            <details>
              <summary>Lihat detail</summary>
              <p>{reason_esc}</p>
              <p class="tech">ID advisori internal: {adv_esc}<br>
              CWE: {cwe_esc}<br>
              Tool: <code>{tool_esc}</code><br>
              Evidence (teredaksi): <code>{evidence_esc}</code><br>
              Skor komposit {score_esc}/100 (CVSS {cvss_esc} | EPSS {epss_esc}% | CWSS {cwss_esc}) &mdash; nilai referensi aturan<br>
              SSVC: {ssvc_esc} &mdash; nilai referensi aturan, bukan keputusan penegakan</p>
            </details>
          </td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="5" style="text-align:center;padding:30px;color:#6c93b8;">Belum ada aktivitas tercatat.</td></tr>'

    # --- Rule catalogue rows (tab "Intelijen ancaman") ---
    catalog_rows = ""
    for spec in THREAT_MATRIX.values():
        status = str(getattr(spec, "status", "experimental"))
        if status == "planned":
            status_cell = "planned &mdash; direncanakan, belum diterapkan"
            action_cell = "&mdash; (belum diterapkan)"
        else:
            status_cell = "experimental &mdash; diperiksa oleh engine"
            action_cell = html.escape(_strategy_label(spec.strategy))
        catalog_rows += f"""
        <tr>
          <td><b style="color:#fff;">{html.escape(spec.codename)}</b><br><small>{html.escape(spec.rule_id)}</small></td>
          <td>{html.escape(spec.advisory_id)}</td>
          <td>{status_cell}</td>
          <td>{action_cell}</td>
          <td>{html.escape(spec.cwe_id)}<br><small>CVSS {html.escape(str(spec.cvss_base))} | EPSS {html.escape(str(round(spec.epss_prob * 100, 1)))}% | CWSS {html.escape(str(spec.cwss_score))} &mdash; nilai referensi aturan</small></td>
        </tr>
        """

    # --- Connection status (honest: only "connected" when hooks verified) ---
    if getattr(core, "hooks_verified", False):
        status_html = '<span class="dot-ok">&#9679;</span> Terhubung ke sesi Hermes'
    else:
        status_html = "Status koneksi belum dapat diverifikasi &mdash; perlindungan belum dipastikan aktif."
    if _SERVER_OK is False:
        status_html += " Server HUD tidak dapat dimulai."

    # --- Empty state (no RUNTIME events) ---
    if runtime_total == 0:
        empty_html = """
    <div class="empty-state">
      <b>Belum ada aktivitas yang cocok dengan aturan perlindungan.</b>
      <p>Ini bukan pemindaian seluruh komputer atau daftar kerentanan perangkat.</p>
    </div>
"""
    else:
        empty_html = ""

    # --- Stored-history range label ---
    if core.events:
        first_ts = html.escape(str(core.events[0].get("timestamp", "")))
        last_ts = html.escape(str(core.events[-1].get("timestamp", "")))
        range_label = f"Riwayat tersimpan: {first_ts} s.d. {last_ts} &middot; maks. 120 event"
    else:
        range_label = "Riwayat kosong &middot; maks. 120 event tersimpan"

    css = """
  :root {
    --bg: #040811;
    --panel: rgba(10, 20, 38, 0.86);
    --border: #16365f;
    --cyan: #00f5d4;
    --gold: #f59e0b;
    --crimson: #ff2a5f;
    --text: #e6f4ff;
    --muted: #7295b8;
  }
  * { box-sizing: border-box; font-family: 'JetBrains Mono', 'Fira Code', monospace; }
  body {
    margin: 0; padding: 24px; background: radial-gradient(circle at 50% 10%, #0c2142 0%, var(--bg) 75%);
    color: var(--text); min-height: 100vh; overflow-x: hidden;
  }
  .container { position: relative; z-index: 1; max-width: 1440px; margin: 0 auto; }
  .topbar {
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 16px;
  }
  .brand { display: flex; align-items: center; gap: 14px; }
  .core-badge {
    width: 44px; height: 44px; border-radius: 50%; border: 2px solid var(--cyan);
    display: grid; place-items: center; color: var(--cyan); font-weight: 700;
    box-shadow: 0 0 18px rgba(0,245,212,0.45), inset 0 0 10px rgba(0,245,212,0.25);
  }
  .title { font-size: 20px; font-weight: 800; letter-spacing: 1.5px; color: var(--cyan); text-shadow: 0 0 14px rgba(0,245,212,0.4); }
  .sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
  .top-actions { display: flex; align-items: center; gap: 12px; }
  .sound-toggle { font-size: 12px; color: var(--muted); cursor: pointer; }
  .btn-secondary {
    background: rgba(0,245,212,0.08); color: var(--text); border: 1px solid var(--border);
    padding: 11px 20px; border-radius: 6px; font-size: 12px; font-weight: 700; cursor: pointer; letter-spacing: 0.5px;
  }
  .btn-secondary:hover { border-color: var(--cyan); }
  .btn-danger {
    background: transparent; color: var(--crimson); border: 1px solid var(--crimson);
    padding: 8px 14px; border-radius: 6px; font-size: 12px; cursor: pointer;
  }
  .status-line { font-size: 13px; margin-bottom: 16px; color: var(--text); }
  .dot-ok { color: var(--cyan); }
  .sim-status { font-size: 13px; color: var(--cyan); margin-bottom: 12px; min-height: 18px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 12px; }
  .kpi {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; position: relative; backdrop-filter: blur(8px);
  }
  .kpi::after { content: ""; position: absolute; top: 0; left: 0; width: 100%; height: 2px; background: linear-gradient(90deg, var(--cyan), transparent); }
  .kpi-label { font-size: 10px; text-transform: uppercase; color: var(--muted); letter-spacing: 1px; }
  .kpi-val { font-size: 28px; font-weight: 800; margin: 8px 0 4px; }
  .kpi-foot { font-size: 11px; color: var(--cyan); }
  .history-line { font-size: 12px; color: var(--muted); margin-bottom: 16px; }
  .scope-panel {
    display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 22px;
  }
  .scope-panel > div {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px;
  }
  .scope-panel b { font-size: 12px; color: var(--cyan); }
  .scope-panel p { font-size: 12px; color: var(--text); margin: 6px 0 0; line-height: 1.5; }
  .tabs { display: flex; gap: 8px; margin-bottom: 14px; }
  .tab {
    background: transparent; color: var(--muted); border: 1px solid var(--border);
    padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer;
  }
  .tab.active { color: var(--cyan); border-color: var(--cyan); }
  .empty-state {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 20px; margin-bottom: 16px; font-size: 13px; line-height: 1.6;
  }
  .empty-state p { color: var(--muted); margin: 6px 0 0; }
  .intel-note { font-size: 12px; color: var(--muted); margin-bottom: 12px; }
  .table-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
  .range-label { font-size: 12px; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; font-size: 12px; }
  th { background: rgba(16, 36, 66, 0.95); color: var(--cyan); text-align: left; padding: 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; }
  td { padding: 12px; border-top: 1px solid rgba(22, 54, 95, 0.65); vertical-align: top; }
  .pill { display: inline-block; padding: 3px 8px; border: 1px solid; border-radius: 4px; font-size: 10px; font-weight: 700; }
  .pill-real { border-color: var(--cyan); color: var(--cyan); }
  .pill-sim { border-color: var(--gold); color: var(--gold); }
  details summary { cursor: pointer; color: var(--cyan); font-size: 12px; }
  details p { font-size: 12px; line-height: 1.6; }
  .tech { color: var(--muted); }
  """

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Manas Aegis &mdash; Perlindungan aktivitas Hermes Agent</title>
<style>{css}</style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div class="brand">
        <div class="core-badge">&#9670;</div>
        <div>
          <div class="title">MANAS AEGIS</div>
          <div class="sub">Perlindungan aktivitas Hermes Agent &mdash; ALPHA</div>
          <div class="sub">STIX 2.1 lokal &middot; Tanpa feed TAXII eksternal</div>
        </div>
      </div>
      <div class="top-actions">
        <label class="sound-toggle"><input type="checkbox" id="soundToggle"> Suara</label>
        <button class="btn-secondary" onclick="triggerBarrage()">Jalankan simulasi lokal</button>
      </div>
    </div>

    <div class="status-line">{status_html}</div>
    <div id="sim-status" class="sim-status" role="status"></div>

    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-label">Aktivitas yang diubah agar lebih aman</div>
        <div class="kpi-val" style="color:var(--cyan);">{stats['virtual_patched']}</div>
        <div class="kpi-foot">Diubah oleh aturan lokal</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Aktivitas dialihkan ke honeypot</div>
        <div class="kpi-val" style="color:var(--gold);">{stats['honeypot_deceived']}</div>
        <div class="kpi-foot">Dialihkan ke data umpan</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Aktivitas diblokir oleh aturan</div>
        <div class="kpi-val" style="color:var(--crimson);">{stats['hard_blocked']}</div>
        <div class="kpi-foot">Diblokir oleh aturan lokal</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Aturan terdefinisi</div>
        <div class="kpi-val">{posture['rules_defined']}</div>
        <div class="kpi-foot">{total_stored} event dicatat (riwayat tersimpan, maks. 120)</div>
      </div>
    </div>
    <div class="history-line">{runtime_total} aktivitas nyata ditangani dalam riwayat lokal &middot; {sim_total} event simulasi (tidak dihitung sebagai aktivitas nyata)</div>

    <div class="scope-panel">
      <div>
        <b>Yang dipantau</b>
        <p>Sebagian aktivitas tool Hermes Agent yang cocok dengan {posture['rules_enforced']} aturan eksperimental (lihat tabel guard di README).</p>
      </div>
      <div>
        <b>Yang tidak dipindai</b>
        <p>Plugin ini TIDAK memindai seluruh komputer, semua aplikasi, atau seluruh kerentanan pada perangkat.</p>
      </div>
    </div>

    <div class="tabs">
      <button id="tab-btn-aktivitas" class="tab active" onclick="showTab('aktivitas')">Aktivitas</button>
      <button id="tab-btn-intel" class="tab" onclick="showTab('intel')">Intelijen ancaman</button>
    </div>

    <div id="tab-aktivitas">
      {empty_html}
      <div class="table-bar">
        <span class="range-label">{range_label}</span>
        <button class="btn-danger" onclick="clearHistory()">Hapus riwayat</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Waktu</th>
            <th>Sumber</th>
            <th>Aturan cocok</th>
            <th>Tindakan</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>

    <div id="tab-intel" style="display:none;">
      <p class="intel-note">Informasi global dari katalog aturan &mdash; belum ditemukan pada perangkat ini.</p>
      <table>
        <thead>
          <tr>
            <th>Aturan</th>
            <th>ID advisori internal</th>
            <th>Status</th>
            <th>Tindakan</th>
            <th>Catatan</th>
          </tr>
        </thead>
        <tbody>
          {catalog_rows}
        </tbody>
      </table>
    </div>
  </div>

<script>
function showTab(name) {{
  document.getElementById('tab-aktivitas').style.display = name === 'aktivitas' ? '' : 'none';
  document.getElementById('tab-intel').style.display = name === 'intel' ? '' : 'none';
  document.getElementById('tab-btn-aktivitas').classList.toggle('active', name === 'aktivitas');
  document.getElementById('tab-btn-intel').classList.toggle('active', name === 'intel');
}}

function soundEnabled() {{
  try {{
    return localStorage.getItem('manas-aegis-sound') === 'on';
  }} catch (e) {{ return false; }}
}}

(function initSoundToggle() {{
  var toggle = document.getElementById('soundToggle');
  if (!toggle) return;
  toggle.checked = soundEnabled();
  toggle.addEventListener('change', function () {{
    try {{ localStorage.setItem('manas-aegis-sound', toggle.checked ? 'on' : 'off'); }} catch (e) {{}}
  }});
}})();

function playChime() {{
  if (!soundEnabled()) return;
  try {{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [528, 792, 1056].forEach((freq, idx) => {{
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, ctx.currentTime + idx * 0.07);
      gain.gain.setValueAtTime(0.12, ctx.currentTime + idx * 0.07);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + idx * 0.07 + 0.35);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(ctx.currentTime + idx * 0.07);
      osc.stop(ctx.currentTime + idx * 0.07 + 0.35);
    }});
  }} catch (e) {{}}
}}

async function triggerBarrage() {{
  var ok = confirm('Jalankan simulasi lokal? Plugin akan menguji enam contoh input terhadap aturan lokal dan menambahkan hasil berlabel SIMULASI ke riwayat. Ini tidak memindai komputer, tidak menjalankan serangan sungguhan, dan tidak membuktikan semua serangan dapat dicegah.');
  if (!ok) return;
  playChime();
  try {{
    const res = await fetch('/api/barrage', {{ method: 'POST' }});
    if (res.ok) {{
      const data = await res.json();
      const results = (data && data.results) || [];
      var matched = 0;
      results.forEach(function (r) {{
        var action = r && r.manas_verdict && r.manas_verdict.action;
        if (action === 'block' || action === 'modify') matched += 1;
      }});
      document.getElementById('sim-status').textContent = 'Simulasi selesai — ' + matched + ' dari 6 contoh cocok dengan aturan.';
      setTimeout(() => window.location.reload(), 2000);
    }}
  }} catch (e) {{
    alert('Simulasi tidak dapat dijalankan dari HUD. Coba perintah /manas-barrage di Hermes.');
  }}
}}

async function clearHistory() {{
  var ok = confirm('Hapus seluruh riwayat aktivitas lokal? Tindakan ini tidak dapat dibatalkan.');
  if (!ok) return;
  try {{
    const res = await fetch('/api/clear-history', {{ method: 'POST' }});
    if (res.ok) {{
      window.location.reload();
    }}
  }} catch (e) {{
    alert('Riwayat tidak dapat dihapus saat ini.');
  }}
}}
</script>
</body>
</html>"""



def write_hud_snapshot(core: ManasAegisCore) -> Path:
    html_str = build_analytical_hud_html(core)
    hud_file = core.state_dir / "dashboard.html"
    hud_file.write_text(html_str, encoding="utf-8")
    return hud_file


class _ManasHUDHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        core = get_core()
        if self.path == "/api/stix":
            payload = json.dumps([e["stix_bundle"] for e in core.events[-25:]], indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return

        html_bytes = build_analytical_hud_html(core).encode("utf-8")
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
            cleared = len(core.events)
            core.events = []
            telemetry_file = core.state_dir / "manas_telemetry.json"
            try:
                if telemetry_file.exists():
                    telemetry_file.unlink()
            except Exception:
                pass
            stix_file = core.state_dir / "stix21_taxii_feed.json"
            try:
                if stix_file.exists():
                    stix_file.unlink()
            except Exception:
                pass
            write_hud_snapshot(core)
            payload = json.dumps({"status": "ok", "cleared": cleared}).encode("utf-8")
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
