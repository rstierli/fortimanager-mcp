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
    """Minimal stand-in for MCPServer that captures registered tool functions."""

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


#: Tools added by the lvenet port (1.13.0). Each must be reachable through
#: execute_fortimanager_tool; list_policy_blocks and
#: list_policy_block_policies were not (allowlisted under system_tools).
_PORTED_TOOLS = [
    "list_policy_blocks",
    "list_policy_block_policies",
    "list_metadata_variables",
    "check_device_variables",
    "set_metadata_variable",
    "get_package_install_status",
    "check_device_policy_sync",
    "list_cli_templates",
    "get_cli_template",
    "get_sdwan_template_config",
    "get_bgp_template",
    "update_bgp_template",
    "get_device_bgp",
    "get_device_static_routes",
    "get_device_bgp_status",
    "diagnose_ipsec_tunnel",
    "get_profile_group",
    "create_firmware_template",
    "delete_firmware_template",
    "list_firmware_templates",
    "query_device_api",
]


class TestPortedToolsDispatch:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", _PORTED_TOOLS)
    async def test_ported_tool_is_found(
        self, dynamic_tools: dict[str, Any], tool_name: str
    ) -> None:
        """No arguments: the call fails on the signature or the missing client,
        never on the lookup."""
        result = await dynamic_tools["execute_fortimanager_tool"](tool_name)

        assert "not found" not in str(result.get("error", "")), result

    @pytest.mark.asyncio
    async def test_policy_block_tool_reaches_the_client(
        self, dynamic_tools: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End to end through the dispatcher, with a stub client."""
        from fortimanager_mcp.tools import policy_tools

        class _Client:
            async def list_policy_blocks(self, adom: str) -> list[dict[str, Any]]:
                return [{"name": "shared-rules"}]

        monkeypatch.setattr(policy_tools, "get_fmg_client", lambda: _Client())

        result = await dynamic_tools["execute_fortimanager_tool"](
            "list_policy_blocks", {"adom": "demo"}
        )

        assert result["success"] is True
        assert result["result"]["blocks"] == [{"name": "shared-rules"}]

    @pytest.mark.asyncio
    async def test_policy_sync_is_its_own_category(self, dynamic_tools: dict[str, Any]) -> None:
        cats = await dynamic_tools["list_fortimanager_categories"]()
        found = await dynamic_tools["find_fortimanager_tool"]("policy_sync")

        assert cats["categories"]["policy_sync"]["count"] == 2
        assert {t["name"] for t in found["tools"]} >= {
            "get_package_install_status",
            "check_device_policy_sync",
        }
