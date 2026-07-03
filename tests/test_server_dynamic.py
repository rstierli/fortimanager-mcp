"""Tests for dynamic-mode tool discovery and execution.

In dynamic mode the tool submodules are never imported at startup, so
``execute_fortimanager_tool`` must import the owning module itself. These
tests register the discovery tools on a stub registry and drive them
directly.
"""

from typing import Any

import pytest

from fortimanager_mcp import server


class _ToolCollector:
    """Minimal stand-in for FastMCP that captures registered tool functions."""

    def __init__(self) -> None:
        self.fns: dict[str, Any] = {}

    def tool(self) -> Any:
        def decorator(fn: Any) -> Any:
            self.fns[fn.__name__] = fn
            return fn

        return decorator


@pytest.fixture
def dynamic_tools() -> dict[str, Any]:
    collector = _ToolCollector()
    server.register_dynamic_tools(collector)  # type: ignore[arg-type]
    return collector.fns


class TestExecuteFortimanagerTool:
    """execute_fortimanager_tool must resolve allowlisted tools even though
    dynamic mode never imports the tool submodules at startup."""

    @pytest.mark.asyncio
    async def test_resolves_allowlisted_tool(self, dynamic_tools: dict[str, Any]) -> None:
        """A valid tool name resolves and executes (no client connected, so the
        tool itself reports not-connected — the point is it is FOUND)."""
        result = await dynamic_tools["execute_fortimanager_tool"]("list_adoms")

        assert "not found" not in str(result.get("error", ""))

    @pytest.mark.asyncio
    async def test_unknown_tool_reports_not_found(self, dynamic_tools: dict[str, Any]) -> None:
        result = await dynamic_tools["execute_fortimanager_tool"]("no_such_tool")

        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_discovery_finds_tools(self, dynamic_tools: dict[str, Any]) -> None:
        result = await dynamic_tools["find_fortimanager_tool"]("policy")

        assert result["found"] is True
        assert any(t["name"] == "create_firewall_policy" for t in result["tools"])
