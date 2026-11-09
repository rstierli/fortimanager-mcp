"""The tool boundary: outputs masked, token arguments refused.

These tests drive real MCPServer registration rather than calling wrapped
functions directly. A bare function is not a valid stand-in for a
registered tool in this repo, and a stub is exactly what hid a middleware
bug once before.
"""

import json
import os
import subprocess
import sys
from typing import Any
from unittest.mock import AsyncMock

import pytest
from mcp.server.mcpserver import MCPServer

from fortimanager_mcp.masking.fpe_engine import FPEEngine
from fortimanager_mcp.masking.wrapper import install_masking

KEY = "2DE79D232DF5585D68CE47882AE256D6"
REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


@pytest.fixture()
def engine() -> FPEEngine:
    return FPEEngine(KEY)


@pytest.fixture()
def masked_server(monkeypatch: pytest.MonkeyPatch) -> MCPServer:
    monkeypatch.setenv("FMG_MASKING_KEY", KEY)
    monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
    mcp = MCPServer("test-masking")
    install_masking(mcp)
    return mcp


def payload(result: Any) -> Any:
    """Pull the structured payload out of an MCPServer call_tool result.

    mcp 2.x returns a ``CallToolResult`` where 1.x returned a
    ``(content, structured)`` tuple, so the structured half is now an
    attribute rather than an element.
    """
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        result = structured
    elif hasattr(result, "content"):
        result = result.content
    if isinstance(result, tuple):
        result = result[1]
    if isinstance(result, dict):
        return result.get("result", result)
    if isinstance(result, list) and result:
        return json.loads(result[0].text)
    return result


class TestOutboundMasking:
    @pytest.mark.asyncio
    async def test_output_is_masked_through_real_registration(
        self, masked_server: MCPServer, engine: FPEEngine
    ) -> None:
        @masked_server.tool()
        async def get_thing(name: str) -> dict[str, str]:
            return {"name": name, "ip": "192.0.2.19", "sn": "FGVM020000123456"}

        out = payload(await masked_server.call_tool("get_thing", {"name": "srv-web"}))

        assert out["name"] == "srv-web"
        assert engine.unmask_ip_token(out["ip"]) == "192.0.2.19"
        assert engine.unseal_serial(out["sn"]) == "FGVM020000123456"

    @pytest.mark.asyncio
    async def test_inner_tool_call_is_masked_once(self, masked_server: MCPServer) -> None:
        """Double masking would break every token's round trip."""

        @masked_server.tool()
        async def inner() -> dict[str, str]:
            return {"ip": "192.0.2.19"}

        @masked_server.tool()
        async def outer() -> dict[str, Any]:
            return {"nested": await inner()}

        direct = payload(await masked_server.call_tool("inner", {}))
        through = payload(await masked_server.call_tool("outer", {}))

        assert through["nested"]["ip"] == direct["ip"]


class TestDynamicDispatch:
    """A tool reached through ``execute_fortimanager_tool`` is masked the way
    a direct call masks it, although the boundary is the dispatcher's."""

    SRC = "198.51.100.40"
    PEER = "192.0.2.252"
    MAC = "00:00:5e:00:53:01"
    ARGS = {"path": "/api/v2/monitor/firewall/session", "device": "branch1", "adom": "demo"}

    @pytest.fixture()
    def dispatching_server(
        self, masked_server: MCPServer, monkeypatch: pytest.MonkeyPatch
    ) -> MCPServer:
        """The discovery tools and ``query_device_api`` on one masked server.

        With masking on, a tool module's own name is the wrapped function,
        and that name is what the dispatcher resolves and calls.
        """
        from fortimanager_mcp import server
        from fortimanager_mcp.tools import device_proxy_tools

        client = AsyncMock()
        client.proxy_call = AsyncMock(
            return_value=[
                {
                    "response": {
                        "http_status": 200,
                        "results": {
                            "details": [{"saddr": self.SRC, "srcmac": self.MAC, "dport": 443}],
                            self.PEER: {"state": "established"},
                        },
                    },
                    "status": {"code": 0, "message": "OK"},
                }
            ]
        )
        monkeypatch.setattr(device_proxy_tools, "get_fmg_client", lambda: client)
        monkeypatch.setattr(
            device_proxy_tools,
            "query_device_api",
            masked_server.tool()(device_proxy_tools.query_device_api),
        )
        server.register_dynamic_tools(masked_server)
        return masked_server

    @pytest.mark.asyncio
    async def test_a_passthrough_tool_keeps_its_value_shape_masking(
        self, dispatching_server: MCPServer, engine: FPEEngine
    ) -> None:
        """FortiOS keys no table names came back in clear: the result was
        masked under the dispatcher's name, which is not a passthrough tool."""
        direct = payload(await dispatching_server.call_tool("query_device_api", self.ARGS))
        dispatched: Any = await dispatching_server.call_tool(
            "execute_fortimanager_tool",
            {"tool_name": "query_device_api", "parameters": self.ARGS},
        )
        envelope = dispatched.structured_content

        for value in (self.SRC, self.MAC, self.PEER):
            assert value not in json.dumps(envelope)
        assert envelope["result"] == direct
        session = envelope["result"]["results"]["details"][0]
        assert engine.unmask_ip_token(session["saddr"]) == self.SRC
        assert session["dport"] == 443

    @pytest.mark.asyncio
    async def test_a_named_key_tool_is_not_masked_by_shape(
        self, dispatching_server: MCPServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Value-shape masking stays scoped to the passthrough tools."""
        from fortimanager_mcp.tools import policy_tools

        block = {"name": "shared-rules", "saddr": self.SRC, "ip": self.PEER}

        class _Client:
            async def list_policy_blocks(self, adom: str) -> list[dict[str, Any]]:
                return [dict(block)]

        monkeypatch.setattr(policy_tools, "get_fmg_client", lambda: _Client())
        monkeypatch.setattr(
            policy_tools,
            "list_policy_blocks",
            dispatching_server.tool()(policy_tools.list_policy_blocks),
        )

        dispatched: Any = await dispatching_server.call_tool(
            "execute_fortimanager_tool",
            {"tool_name": "list_policy_blocks", "parameters": {"adom": "demo"}},
        )

        masked = dispatched.structured_content["result"]["blocks"][0]
        assert masked["saddr"] == self.SRC
        assert masked["ip"] != self.PEER


class TestInboundGuard:
    @pytest.fixture(autouse=True)
    def _tool(self, masked_server: MCPServer, body_saw: dict[str, Any]) -> None:
        @masked_server.tool()
        async def create_thing(
            name: str, subnet: str = "", comment: str = "", options: dict[str, Any] | None = None
        ) -> dict[str, Any]:
            body_saw.update(subnet=subnet, comment=comment)
            return {"status": "success"}

    @pytest.fixture()
    def body_saw(self) -> dict[str, Any]:
        """What the tool body actually received, before output masking."""
        return {}

    @pytest.mark.asyncio
    async def test_token_argument_is_refused(
        self, masked_server: MCPServer, engine: FPEEngine, body_saw: dict[str, Any]
    ) -> None:
        token = engine.mask_ip_token("192.0.2.19")

        out = payload(await masked_server.call_tool("create_thing", {"name": "x", "subnet": token}))

        assert out["error"] == "masking_token_in_input"
        assert body_saw == {}, "the tool body must not run once a token is seen"

    @pytest.mark.asyncio
    async def test_token_embedded_in_free_text_is_refused(
        self, masked_server: MCPServer, engine: FPEEngine
    ) -> None:
        """A token pasted into a comment would be written verbatim as config."""
        token = engine.mask_ip_token("192.0.2.19")

        out = payload(
            await masked_server.call_tool(
                "create_thing", {"name": "x", "comment": f"replaces {token} next week"}
            )
        )

        assert out["error"] == "masking_token_in_input"

    @pytest.mark.asyncio
    async def test_token_nested_in_a_dict_argument_is_refused(
        self, masked_server: MCPServer, engine: FPEEngine
    ) -> None:
        """The dynamic dispatcher passes caller-supplied parameter mappings."""
        token = engine.seal_serial("FGVM020000123456")

        out = payload(
            await masked_server.call_tool(
                "create_thing", {"name": "x", "options": {"device": {"sn": token}}}
            )
        )

        assert out["error"] == "masking_token_in_input"

    @pytest.mark.asyncio
    async def test_domain_token_is_refused(
        self, masked_server: MCPServer, engine: FPEEngine
    ) -> None:
        """Domain tokens carry a suffix marker, not a prefix one."""
        token = engine.mask_domain("mail.example.com")

        out = payload(
            await masked_server.call_tool("create_thing", {"name": "x", "comment": token})
        )

        assert out["error"] == "masking_token_in_input"

    @pytest.mark.asyncio
    async def test_literal_values_reach_the_body_untouched(
        self, masked_server: MCPServer, body_saw: dict[str, Any]
    ) -> None:
        """An operator typing a real address must not be second-guessed.

        Asserted on what the body received: the same value echoed back in
        a result is masked on the way out, which is the output side doing
        its job, not the guard rewriting an input.
        """
        out = payload(
            await masked_server.call_tool(
                "create_thing",
                {"name": "srv", "subnet": "203.0.113.0/24", "comment": "site B uplink"},
            )
        )

        assert out["status"] == "success"
        assert body_saw["subnet"] == "203.0.113.0/24"
        assert body_saw["comment"] == "site B uplink"

    @pytest.mark.asyncio
    async def test_refusal_message_carries_no_token(
        self, masked_server: MCPServer, engine: FPEEngine
    ) -> None:
        token = engine.mask_ip_token("192.0.2.19")

        out = payload(await masked_server.call_tool("create_thing", {"name": "x", "subnet": token}))

        assert token not in json.dumps(out)


class TestPositionalCalls:
    def test_sync_tool_guards_positional_arguments(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """MCPServer passes keywords today; the wrapper is callable either way."""
        monkeypatch.setenv("FMG_MASKING_KEY", KEY)
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        mcp = MCPServer("test-positional")
        install_masking(mcp)
        seen: list[str] = []

        @mcp.tool()
        def echo(value: str) -> dict[str, str]:
            seen.append(value)
            return {"value": value}

        token = FPEEngine(KEY).mask_ip_token("192.0.2.19")

        assert echo(token)["error"] == "masking_token_in_input"
        assert seen == []
        assert echo("203.0.113.9")["value"] == "203.0.113.9"


class TestStartup:
    @pytest.mark.parametrize("mode", ["full", "dynamic"])
    def test_masking_on_imports_cleanly_in_both_tool_modes(self, mode: str) -> None:
        env = {
            **os.environ,
            "PYTHONPATH": REPO_SRC,
            "FORTIMANAGER_HOST": "test-fmg.example.com",
            "FMG_TOOL_MODE": mode,
            "MASKING_ENABLED": "true",
            "FMG_MASKING_KEY": KEY,
        }
        done = subprocess.run(
            [sys.executable, "-c", "import fortimanager_mcp.server"],
            env=env,
            capture_output=True,
            text=True,
        )
        assert done.returncode == 0, done.stderr

    @pytest.mark.parametrize("mode", ["full", "dynamic"])
    def test_masking_on_without_a_key_refuses_to_start(self, mode: str) -> None:
        """A deployment that asked for masking must not run unmasked."""
        env = {
            **os.environ,
            "PYTHONPATH": REPO_SRC,
            "FORTIMANAGER_HOST": "test-fmg.example.com",
            "FMG_TOOL_MODE": mode,
            "MASKING_ENABLED": "true",
        }
        env.pop("FMG_MASKING_KEY", None)
        done = subprocess.run(
            [sys.executable, "-c", "import fortimanager_mcp.server"],
            env=env,
            capture_output=True,
            text=True,
        )
        assert done.returncode != 0
        assert "FMG_MASKING_KEY" in done.stderr

    def test_masking_off_leaves_the_registration_path_untouched(self) -> None:
        env = {
            **os.environ,
            "PYTHONPATH": REPO_SRC,
            "FORTIMANAGER_HOST": "test-fmg.example.com",
            "MASKING_ENABLED": "false",
        }
        env.pop("FMG_MASKING_KEY", None)
        done = subprocess.run(
            [
                sys.executable,
                "-c",
                "import fortimanager_mcp.server as s;"
                "print(type(s.mcp).tool is type(s.mcp).__dict__['tool'])",
            ],
            env=env,
            capture_output=True,
            text=True,
        )
        assert done.returncode == 0, done.stderr
        assert "True" in done.stdout
