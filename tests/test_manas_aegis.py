"""
Automated Self-Test Suite for Hermes Manas-Aegis v2.3.0-alpha.

R1 additions (TestManasAegisR1): redaction before storage, simulation /
runtime counter separation, planned-rule status, honest HUD empty state.
All new test inputs are plain text written for the test — no new encoded
payloads are introduced.
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from hermes_manas_aegis import build_analytical_hud_html
from hermes_manas_aegis.core_engine import THREAT_MATRIX, ManasAegisCore


def _d(s: str) -> str:
    return base64.b64decode(s.encode("ascii")).decode("utf-8")


class TestManasAegisV22(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.core = ManasAegisCore(state_dir=Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_git_virtual_patch(self) -> None:
        res = self.core.intercept_tool_call("terminal", {"command": _d("Z2l0IHN0YXR1cw==")}, "cli:test")
        self.assertEqual(res.get("action"), "modify")
        self.assertIn("core.fsmonitor=false", res["args"]["command"])

    def test_honeypot_deception(self) -> None:
        res = self.core.intercept_tool_call("read_file", {"path": _d("fi8uaGVybWVzL2F1dGguanNvbg==")}, "group:pub")
        self.assertEqual(res.get("action"), "modify")
        self.assertIn("decoy_auth.json", res["args"]["path"])

    def test_ssrf_block(self) -> None:
        res = self.core.intercept_tool_call("browser_snapshot", {"url": _d("aHR0cDovLzE2OS4yNTQuMTY5LjI1NC9sYXRlc3QvbWV0YS1kYXRhLw==")}, "webhook:ext:1")
        self.assertEqual(res.get("action"), "block")

    def test_sqli_block(self) -> None:
        res = self.core.intercept_tool_call("sqlite_query", {"query": _d("U0VMRUNUICogRlJPTSB0IFdIRVJFIGE9JzEnIE9SICcxJz0nMScgVU5JT04gU0VMRUNUIGIgRlJPTSBjLS0=")}, "webhook:ext:2")
        self.assertEqual(res.get("action"), "block")

    def test_webhook_colon_guard(self) -> None:
        res = self.core.intercept_tool_call("terminal", {"command": "whoami"}, "webhook:admin:extra_colon:99")
        self.assertEqual(res.get("action"), "block")

    def test_hud_html_escaping_prevents_self_xss(self) -> None:
        self.core.intercept_tool_call("sqlite_query", {"query": _d("U0VMRUNUICogRlJPTSB0IFdIRVJFIGE9JzEnIE9SICcxJz0nMScgVU5JT04gU0VMRUNUIGIgRlJPTSBjLS0=") + "<img src=x onerror=alert(1)>"}, "webhook:ext:3")
        hud_html = build_analytical_hud_html(self.core)
        self.assertNotIn("<img src=x", hud_html)
        self.assertIn("&lt;img src=x", hud_html)


class TestManasAegisR1(unittest.TestCase):
    """R1: honest claims, redaction, simulation separation, honest HUD."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.core = ManasAegisCore(state_dir=Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_redaction_recursive_before_storage(self) -> None:
        fake_token = "ghp_" + "x" * 36
        redacted = self.core._redact_evidence(
            {"nested": {"token": fake_token}, "urls": ["https://user:secretpass@example.com/x"]}
        )
        self.assertNotIn(fake_token, json.dumps(redacted))
        self.assertNotIn("secretpass", json.dumps(redacted))
        self.assertIn("user:***@", json.dumps(redacted))

    def test_redacted_evidence_in_stored_telemetry(self) -> None:
        fake_token = "ghp_" + "y" * 36
        query = "SELECT * FROM t WHERE a='1' OR '1'='1' UNION SELECT b FROM c-- " + fake_token
        res = self.core.intercept_tool_call("sqlite_query", {"query": query}, "webhook:ext:9")
        self.assertEqual(res.get("action"), "block")
        stored = (Path(self.tmp.name) / "manas_telemetry.json").read_text(encoding="utf-8")
        self.assertNotIn(fake_token, stored)

    def test_simulation_events_do_not_inflate_real_counters(self) -> None:
        query = "SELECT * FROM t WHERE a='1' OR '1'='1' UNION SELECT b FROM c--"
        self.core.intercept_tool_call("sqlite_query", {"query": query}, "webhook:ext:1")
        self.core.intercept_tool_call(
            "sqlite_query", {"query": query}, "webhook:ext:2", event_source="simulation"
        )
        stats = self.core.get_system_posture()["stats"]
        self.assertEqual(stats["total_intercepted"], 1)
        self.assertEqual(stats["simulation_events"], 1)
        self.assertEqual(stats["total_stored"], 2)
        self.assertEqual(stats["hard_blocked"], 1)

    def test_planned_rules_have_no_enforcement(self) -> None:
        self.assertEqual(THREAT_MATRIX["MANAS-SYMLINK-GUARD"].status, "planned")
        self.assertEqual(THREAT_MATRIX["MANAS-CALLID-RACE"].status, "planned")
        experimental = [k for k, v in THREAT_MATRIX.items() if v.status == "experimental"]
        self.assertEqual(len(experimental), 8)
        posture = self.core.get_system_posture()
        self.assertEqual(posture["rules_defined"], 10)
        self.assertEqual(posture["rules_enforced"], 8)
        self.assertTrue(posture.get("alpha"))

    def test_hud_empty_state_on_fresh_core(self) -> None:
        hud_html = build_analytical_hud_html(self.core)
        self.assertIn("Belum ada aktivitas yang cocok dengan aturan perlindungan.", hud_html)
        self.assertIn("Yang dipantau", hud_html)
        self.assertIn("Yang tidak dipindai", hud_html)
        self.assertIn("Aturan terdefinisi", hud_html)
        self.assertNotIn("TAXII LIVE", hud_html)
        self.assertNotIn("Absolute", hud_html)

    def test_hud_simulation_badge_and_real_counter(self) -> None:
        query = "SELECT * FROM t WHERE a='1' OR '1'='1' UNION SELECT b FROM c--"
        self.core.intercept_tool_call("sqlite_query", {"query": query}, "webhook:ext:1")
        self.core.intercept_tool_call(
            "sqlite_query", {"query": query}, "webhook:ext:2", event_source="simulation"
        )
        hud_html = build_analytical_hud_html(self.core)
        self.assertIn("SIMULASI", hud_html)
        self.assertIn("Nyata", hud_html)
        self.assertIn("tidak dihitung sebagai aktivitas nyata", hud_html)


if __name__ == "__main__":
    unittest.main()
