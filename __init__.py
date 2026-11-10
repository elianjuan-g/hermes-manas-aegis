"""
Root-level plugin shim for Hermes 0.21.x & 0.23.x dual compatibility.
Ensures `hermes plugins validate` finds `__init__.py` at the plugin root
while also supporting `hermes_manas_aegis:register` package entrypoint.
"""

from __future__ import annotations

from .hermes_manas_aegis import (
    build_analytical_hud_html,
    ensure_hud_server_running,
    get_core,
    on_session_start_hook,
    pre_llm_call_hook,
    pre_tool_call_hook,
    register,
    tool_manas_stix_intelligence,
    tool_manas_tactical_core,
    transform_llm_output_hook,
    transform_tool_result_hook,
    write_hud_snapshot,
)

__all__ = [
    "register",
    "get_core",
    "build_analytical_hud_html",
    "write_hud_snapshot",
    "ensure_hud_server_running",
    "on_session_start_hook",
    "pre_llm_call_hook",
    "pre_tool_call_hook",
    "transform_tool_result_hook",
    "transform_llm_output_hook",
    "tool_manas_tactical_core",
    "tool_manas_stix_intelligence",
]
