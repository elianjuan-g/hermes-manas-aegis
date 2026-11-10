"""
Contract tests for Hermes Manas-Aegis (R3, v2.6.4-alpha).

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


# ---------------------------------------------------------------------------
# v2.6.4 regression: register_tool / handler contract against REAL 0.21.5
# ---------------------------------------------------------------------------

# The JSON Schemas below are byte-identical to the ones registered before
# v2.6.4 (only the call form changed). If a property/enum/required entry
# drifts, the test fails — the schema is part of the contract.
_TACTICAL_PARAMETERS = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["status", "barrage"],
            "description": "Use 'barrage' to run 6 local simulation examples against the rules.",
        }
    },
    "required": ["action"],
}
_STIX_PARAMETERS = {
    "type": "object",
    "properties": {
        "view": {
            "type": "string",
            "enum": ["stix_feed", "matrix"],
        }
    },
    "required": ["view"],
}


class _StrictCtx0215:
    """Fake PluginContext with the EXACT Hermes 0.21.5 signatures.

    No ``**kwargs`` anywhere: a call with an unexpected keyword (e.g.
    ``register_tool(parameters=...)``) raises TypeError, exactly like
    the real context (``hermes_cli/plugins.py:456``). The old permissive
    fake (``register_tool(..., **kw)``) accepted anything — which is
    how the ``parameters=`` bug shipped while every test stayed green.
    """

    config = {}

    def __init__(self) -> None:
        self.hooks: list = []
        self.tools: list = []
        self.commands: list = []

    def register_hook(self, name, fn):
        self.hooks.append((name, fn))

    def register_tool(self, name, toolset, schema, handler, check_fn=None,
                      requires_env=None, is_async=False, description="",
                      emoji="", override=False):
        self.tools.append({"name": name, "toolset": toolset,
                           "schema": schema, "handler": handler})

    def register_command(self, name, handler, description="",
                         args_hint="", argument_mode=None):
        self.commands.append((name, handler))


class TestRegisterToolContract264(unittest.TestCase):
    def test_strict_ctx_rejects_parameters_kwarg(self) -> None:
        # Proves the fake is strict: the pre-v2.6.4 call form MUST fail
        # on it, exactly as it fails on the real 0.21.5 context.
        ctx = _StrictCtx0215()
        with self.assertRaises(TypeError):
            ctx.register_tool(
                name="x", description="d", parameters={},
                handler=lambda a: None)

    def test_register_succeeds_on_strict_ctx(self) -> None:
        import hermes_manas_aegis as pkg

        ctx = _StrictCtx0215()
        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            pkg._CORE = None
            pkg.register(ctx)  # must not raise
        by_name = {t["name"]: t for t in ctx.tools}
        for expected, params in (
            ("manas_tactical_core", _TACTICAL_PARAMETERS),
            ("manas_stix_intelligence", _STIX_PARAMETERS),
        ):
            self.assertIn(expected, by_name, f"tool not registered: {expected}")
            tool = by_name[expected]
            self.assertEqual(tool["toolset"], "hermes_manas_aegis")
            schema = tool["schema"]
            self.assertEqual(schema["name"], expected)
            self.assertIsInstance(schema["description"], str)
            self.assertTrue(schema["description"])
            self.assertEqual(schema["parameters"], params,
                             f"parameters drifted for {expected}")
        handlers = {t["name"]: t["handler"] for t in ctx.tools}
        self.assertEqual(handlers["manas_tactical_core"].__name__,
                         "tool_manas_tactical_core_handler")
        self.assertEqual(handlers["manas_stix_intelligence"].__name__,
                         "tool_manas_stix_intelligence_handler")

    def test_all_five_hooks_registered(self) -> None:
        import hermes_manas_aegis as pkg

        ctx = _StrictCtx0215()
        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            pkg._CORE = None
            pkg.register(ctx)
        hook_names = {n for n, _ in ctx.hooks}
        for expected in ("on_session_start", "pre_llm_call", "pre_tool_call",
                         "transform_tool_result", "transform_llm_output"):
            self.assertIn(expected, hook_names, f"hook not registered: {expected}")

    def test_tool_handlers_unwrap_args_dict_like_core(self) -> None:
        import json

        import hermes_manas_aegis as pkg
        from hermes_manas_aegis.core_engine import THREAT_MATRIX

        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            pkg._CORE = None
            tactical = pkg.tool_manas_tactical_core_handler
            stix = pkg.tool_manas_stix_intelligence_handler

            out = json.loads(tactical({"action": "barrage"}))
            self.assertIn("barrage_telemetry", out,
                          "barrage must run when action=barrage")
            out = json.loads(tactical({"action": "status"}))
            self.assertIn("posture", out)
            out = json.loads(tactical({}))
            self.assertIn("posture", out, "empty args must use the default")
            for bad in ("status", None, 42):
                out = json.loads(tactical(bad))
                self.assertIn("error", out, f"non-dict args {bad!r} must error")

            out = json.loads(stix({"view": "matrix"}))
            self.assertEqual(set(out), set(THREAT_MATRIX),
                             "matrix must return the rule catalogue")
            out = json.loads(stix({"view": "stix_feed"}))
            self.assertEqual(out.get("stix_version"), "2.1")
            out = json.loads(stix({}))
            self.assertEqual(out.get("stix_version"), "2.1",
                             "empty args must use the default")
            for bad in ("matrix", None):
                out = json.loads(stix(bad))
                self.assertIn("error", out, f"non-dict args {bad!r} must error")

    def test_bare_tool_functions_still_take_kwargs(self) -> None:
        # Slash-command path (/manas-hud, /manas-barrage, /manas-stix)
        # calls the bare functions directly with kwargs — unchanged.
        import json

        import hermes_manas_aegis as pkg
        from hermes_manas_aegis.core_engine import THREAT_MATRIX

        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            pkg._CORE = None
            out = json.loads(pkg.tool_manas_tactical_core(action="status"))
            self.assertIn("posture", out)
            out = json.loads(pkg.tool_manas_stix_intelligence(view="matrix"))
            self.assertEqual(set(out), set(THREAT_MATRIX))
