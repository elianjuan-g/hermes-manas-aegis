"""
Contract tests for Hermes Manas-Aegis (R3, v2.6.2-alpha).

These verify the plugin's PUBLIC interface — what Hermes, the catalog
validator, and the Desktop actually consume — not internals:
- plugin.yaml / pyproject.toml / core codename versions agree.
- plugin.yaml carries the required catalog fields.
- register(ctx) exists, is callable, and registers every declared hook
  and tool with a fake context.
- Every declared hook/tool function exists with a compatible signature.
- get_core() returns a ManasAegisCore; the HUD renders.
- HUD hardening constants are sane (CSRF token present, rate limit on).
"""

import inspect
import os
import re
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _read_version_yaml(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^version:\s*\"?([0-9]+\.[0-9]+\.[0-9]+[^\"]*)\"?\s*$", line)
        if m:
            return m.group(1)
    raise AssertionError(f"no version in {path}")


class TestPluginContract(unittest.TestCase):
    def test_versions_agree(self) -> None:
        from hermes_manas_aegis.core_engine import ManasAegisCore

        yaml_ver = _read_version_yaml(REPO / "plugin.yaml")
        toml_text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'^version = "([^"]+)"', toml_text, re.M)
        self.assertIsNotNone(m, "no version in pyproject.toml")
        self.assertEqual(m.group(1), yaml_ver)
        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            core = ManasAegisCore(state_dir=Path(d) / "state")
            codename = core.get_system_posture()["codename"]
        self.assertIn(yaml_ver, codename, f"codename {codename!r} lacks version {yaml_ver}")

    def test_plugin_yaml_required_fields(self) -> None:
        text = (REPO / "plugin.yaml").read_text(encoding="utf-8")
        for field in ("name:", "version:", "description:", "entrypoint:", "min_hermes_version:"):
            self.assertIn(field, text, f"plugin.yaml missing {field}")
        self.assertIn("hermes-manas-aegis", text)
        self.assertIn("hermes_manas_aegis:register", text)

    def test_register_registers_declared_hooks_and_tools(self) -> None:
        import hermes_manas_aegis as pkg

        self.assertTrue(callable(pkg.register))
        seen_hooks: list = []
        seen_tools: list = []

        class FakeCtx:
            config = {}

            def register_hook(self, name, fn):
                seen_hooks.append((name, fn))

            def register_tool(self, name=None, handler=None, **kw):
                seen_tools.append((name, handler))

        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            pkg._CORE = None
            pkg.register(FakeCtx())
        hook_names = {n for n, _ in seen_hooks}
        for expected in ("on_session_start", "pre_llm_call", "pre_tool_call"):
            self.assertIn(expected, hook_names, f"hook not registered: {expected}")
        for _, fn in seen_hooks:
            self.assertTrue(callable(fn))
        tool_names = {n for n, _ in seen_tools}
        for expected in ("manas_tactical_core", "manas_stix_intelligence"):
            self.assertIn(expected, tool_names, f"tool not registered: {expected}")
        for _, fn in seen_tools:
            self.assertTrue(callable(fn))

    def test_hook_signatures(self) -> None:
        import hermes_manas_aegis as pkg

        for name in (
            "on_session_start_hook",
            "pre_llm_call_hook",
            "pre_tool_call_hook",
            "transform_tool_result_hook",
            "transform_llm_output_hook",
            "tool_manas_tactical_core",
            "tool_manas_stix_intelligence",
        ):
            fn = getattr(pkg, name, None)
            self.assertTrue(callable(fn), f"missing hook/tool: {name}")
            sig = inspect.signature(fn)
            self.assertGreaterEqual(len(sig.parameters), 0)

    def test_get_core_and_hud_render(self) -> None:
        import hermes_manas_aegis as pkg

        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            pkg._CORE = None
            core = pkg.get_core()
            self.assertIsInstance(core, pkg.ManasAegisCore)
            html_out = pkg.build_analytical_hud_html(core, lang="en")
            self.assertIn("MANAS AEGIS", html_out)
            self.assertIn('name="csrf-token"', html_out)

    def test_hud_hardening_constants(self) -> None:
        import hermes_manas_aegis as pkg

        token = pkg._CSRF_TOKEN
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in token))
        self.assertGreaterEqual(pkg._RATE_MAX, 1)
        self.assertGreater(pkg._RATE_WINDOW, 0)

    def test_no_non_stdlib_dependencies(self) -> None:
        toml_text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r"dependencies = \[(.*?)\]", toml_text, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1).strip(), "")

    def test_packaging_manifest_and_config_schema(self) -> None:
        # v2.6.2 (P2a): the sdist must carry the plugin manifest +
        # desktop assets, and the five R3 config keys must be declared
        # in plugin.yaml config_schema (they existed only in code).
        manifest = (REPO / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("plugin.yaml", manifest)
        # recursive-include carries the whole dir (incl. plugin.js).
        self.assertIn("recursive-include desktop *", manifest)
        self.assertIn("recursive-include honeypot_sandbox *", manifest)
        text = (REPO / "plugin.yaml").read_text(encoding="utf-8")
        for key in (
            "taint_ttl_minutes",
            "ssrf_allowlist",
            "callid_race_window_s",
            "callid_race_enabled",
            "hud_auth_token",
        ):
            self.assertIn(f"  {key}:", text, f"plugin.yaml config_schema missing {key}")


if __name__ == "__main__":
    unittest.main()
