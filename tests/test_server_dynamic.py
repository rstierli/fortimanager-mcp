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


class TestArgumentValidation:
    """The dispatcher validates and coerces ``parameters`` the way a direct
    MCP call does, so a badly typed value never reaches a tool body."""

    @pytest.mark.asyncio
    async def test_a_false_string_does_not_open_a_confirm_gate(
        self, dynamic_tools: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-empty string is truthy: ``"false"`` used to pass
        ``if not confirm`` and start the restore."""
        from fortimanager_mcp.tools import fmg_ops_tools

        sent: list[str] = []

        class _Client:
            async def execute(self, url: str, data: Any = None) -> dict[str, Any]:
                sent.append(url)
                return {}

        monkeypatch.setattr(fmg_ops_tools, "get_fmg_client", lambda: _Client())

        result = await dynamic_tools["execute_fortimanager_tool"](
            "trigger_fmg_restore",
            {
                "service": "sftp",
                "server": "backup.example.com",
                "filename": "fmg.dat",
                "confirm": "false",
            },
        )

        assert sent == []
        assert result["result"]["error_code"] == "confirmation_required"

    @pytest.mark.asyncio
    async def test_a_string_is_not_iterated_as_a_list_of_ids(
        self, dynamic_tools: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``policyids="12"`` used to delete policies "1" and "2"."""
        from fortimanager_mcp.tools import policy_tools

        deleted: list[Any] = []

        class _Client:
            async def delete_firewall_policy(self, adom: str, package: str, policyid: Any) -> None:
                deleted.append(policyid)

        monkeypatch.setattr(policy_tools, "get_fmg_client", lambda: _Client())

        result = await dynamic_tools["execute_fortimanager_tool"](
            "delete_firewall_policies_bulk",
            {"adom": "demo", "package": "default", "policyids": "12"},
        )

        assert deleted == []
        assert "policyids" in result["error"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("policyid", "reached"), [("12", [12]), ("12a", [])])
    async def test_a_string_id_is_coerced_or_refused(
        self,
        dynamic_tools: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        policyid: str,
        reached: list[int],
    ) -> None:
        """The id is formatted into the API URL: a numeric string arrives
        as an int, anything else never reaches the client."""
        from fortimanager_mcp.tools import policy_tools

        seen: list[Any] = []

        class _Client:
            async def get_firewall_policy(
                self, adom: str, package: str, policyid: Any, scope_member: bool = False
            ) -> dict[str, Any]:
                seen.append(policyid)
                return {"policyid": policyid}

        monkeypatch.setattr(policy_tools, "get_fmg_client", lambda: _Client())

        await dynamic_tools["execute_fortimanager_tool"](
            "get_firewall_policy",
            {"adom": "demo", "package": "default", "policyid": policyid},
        )

        assert seen == reached

    @pytest.mark.asyncio
    async def test_an_unknown_argument_is_refused_by_name(
        self, dynamic_tools: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The SDK model drops a name it does not know, and a misspelt
        ``adom`` would then run against the default ADOM."""
        from fortimanager_mcp.tools import policy_tools

        asked: list[str] = []

        class _Client:
            async def list_policy_blocks(self, adom: str) -> list[dict[str, Any]]:
                asked.append(adom)
                return []

        monkeypatch.setattr(policy_tools, "get_fmg_client", lambda: _Client())

        result = await dynamic_tools["execute_fortimanager_tool"](
            "list_policy_blocks", {"adon": "demo"}
        )

        assert asked == []
        assert result["error_code"] == "validation_error"
        assert "adon" in result["error"]

    @pytest.mark.asyncio
    async def test_a_refused_value_is_not_repeated(self, dynamic_tools: dict[str, Any]) -> None:
        """The refusal names the argument and the reason, not what was sent."""
        result = await dynamic_tools["execute_fortimanager_tool"](
            "get_firewall_policy",
            {"adom": "demo", "package": "default", "policyid": "not-a-number-7f3a"},
        )

        assert result["error_code"] == "validation_error"
        assert "policyid" in result["error"]
        assert "7f3a" not in result["error"]


class TestEnvelope:
    """``success`` says whether the dispatched tool succeeded, and a raised
    error is scrubbed the way the tools scrub their own."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("module_name", "tool_name", "parameters"),
        [
            # reports failure as {"status": "error", ...}
            ("system_tools", "list_adoms", {}),
            # reports failure as {"error": ...}
            ("device_proxy_tools", "query_device_api", {"path": "/api/v2/monitor/router/ipv4"}),
        ],
    )
    async def test_an_inner_error_is_not_a_success(
        self,
        dynamic_tools: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        module_name: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> None:
        import importlib

        module = importlib.import_module(f"fortimanager_mcp.tools.{module_name}")
        monkeypatch.setattr(module, "get_fmg_client", lambda: None)

        result = await dynamic_tools["execute_fortimanager_tool"](tool_name, parameters)

        inner = result["result"]
        assert "error" in inner or inner["status"] == "error"
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_a_raised_api_error_loses_its_endpoint(
        self, dynamic_tools: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The tools catch their own API errors, so this stands in for one
        that does not: the dispatcher is then the last handler."""
        from fortimanager_mcp.tools import policy_tools
        from fortimanager_mcp.utils.errors import parse_fmg_error

        async def list_policy_blocks(adom: str = "root") -> dict[str, Any]:
            raise parse_fmg_error(-3, "Object does not exist", f"/pm/pblock/adom/{adom}")

        monkeypatch.setattr(policy_tools, "list_policy_blocks", list_policy_blocks)

        result = await dynamic_tools["execute_fortimanager_tool"](
            "list_policy_blocks", {"adom": "demo"}
        )

        assert result["error"] == "Object does not exist"
        assert result["error_code"] == "not_found"
        assert result["tool"] == "list_policy_blocks"
