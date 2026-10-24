"""Live tests through the MCP protocol itself.

The other integration tests call tool functions directly. These spawn the
server over stdio, the way Claude Desktop and Claude Code run it, and drive
it with a real MCP client: initialize, tools/list, tools/call. That covers
what a direct call cannot: the handshake, tool registration in both tool
modes, and the serialized output a client actually receives, which is where
the secret-leak sweep looks.

Read-only: every tool called here only reads. Requires FORTIMANAGER_HOST and
credentials (.env). Uses TEST_ADOM / TEST_DEVICE (defaults mcp-dev-test /
FGT-MCP-TEST-01). LEAK_SWEEP_TARGETS="adom:device,adom:device" adds devices
to the leak sweep; the release gate sweeps every lab device that way.

Assertion messages carry tool names, error codes, counts and key names,
never result values.
"""

import json
import os
import re
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from fortimanager_mcp import __version__

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.getenv("FORTIMANAGER_HOST"), reason="FORTIMANAGER_HOST not set"),
]

CALL_TIMEOUT = 180
ENC_RE = re.compile(r"ENC [A-Za-z0-9+/=]{16,}")
SECRET_KEYS = {
    "password", "passwd", "eap-password", "pptp-password", "wifi-key", "wifi-passphrase",
    "wifi-private-key-password", "psksecret", "psksecret-remote", "authpasswd",
    "group-authentication-secret", "ppk-secret", "passphrase", "sae-password", "login-passwd",
    "adm_pass", "adm_passwd", "psk", "private_key", "logon-password", "sso-password",
}  # fmt: skip
SWEEP_PREFIXES = ("list_", "get_", "search_")
# Read-only by name, but each needs a live task/capture/upgrade id to mean anything.
SWEEP_SKIP = {
    "get_task",
    "get_preview_result",
    "get_packet_capture_status",
    "get_firmware_upgrade_report",
}
DISCOVERY_TOOLS = {
    "health_check",
    "list_fortimanager_categories",
    "find_fortimanager_tool",
    "execute_fortimanager_tool",
}


@asynccontextmanager
async def mcp_session(tool_mode: str, log_dir: Path) -> AsyncIterator[ClientSession]:
    """Spawn the server over stdio in ``tool_mode`` and yield an open client session.

    The server's stderr goes to a file in ``log_dir`` (pytest's tmp_path),
    which is where to look when a call fails.
    """
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "fortimanager_mcp"],
        env={
            **os.environ,
            "MCP_SERVER_MODE": "stdio",
            "FMG_TOOL_MODE": tool_mode,
            "LOG_LEVEL": "WARNING",
        },
    )
    with (log_dir / f"server-{tool_mode}.log").open("w") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                yield session


def decode(result: Any) -> tuple[str, Any]:
    """Return the raw text a client received and the decoded payload."""
    text = "".join(getattr(c, "text", "") for c in result.content or [])
    payload = result.structured_content
    if payload is None:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = text
    if isinstance(payload, dict) and set(payload) == {"result"}:
        payload = payload["result"]
    return text, payload


def error_of(result: Any, payload: Any) -> str | None:
    """Return a short error label if the call failed, else None.

    Tools report failure three ways: MCP ``isError``, an ``error`` key, or
    ``status: "error"`` with an ``error_code``. Checking only one of them
    lets an ``api_error`` pass as success.
    """
    if result.is_error:
        return "isError"
    if isinstance(payload, dict):
        if "error" in payload or payload.get("status") == "error" or "error_code" in payload:
            return str(payload.get("error_code") or "error")
    return None


def secret_keys_in(node: Any, found: set[str]) -> set[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in SECRET_KEYS:
                found.add(key)
            secret_keys_in(value, found)
    elif isinstance(node, list):
        for item in node:
            secret_keys_in(item, found)
    return found


def leak_of(text: str, payload: Any) -> str | None:
    enc = len(ENC_RE.findall(text))
    keys = sorted(secret_keys_in(payload, set()))
    return f"ENC={enc} keys={keys}" if enc or keys else None


def read_only_plan(adom: str, device: str) -> list[tuple[str, dict[str, Any]]]:
    """Read-only calls that must succeed on the test ADOM/device.

    ``list_device_revisions`` is left out: the test device has no device
    revisions, and FortiManager answers that with an api_error.
    """
    return [
        ("get_system_status", {}),
        ("list_adoms", {}),
        ("list_devices", {"adom": adom}),
        ("list_device_groups", {"adom": adom}),
        ("get_device_interface_config", {"device": device}),
        ("list_antivirus_profiles", {"adom": adom}),
        ("list_webfilter_profiles", {"adom": adom}),
        ("list_ips_sensors", {"adom": adom}),
        ("list_ssl_ssh_profiles", {"adom": adom}),
        ("list_device_ipsec_phase1_interfaces", {"device": device}),
        ("get_device_sslvpn_settings", {"device": device}),
        ("list_adom_revisions", {"adom": adom}),
        ("list_policy_revisions", {"adom": adom, "package": "default"}),
        ("list_local_in_policies", {"adom": adom, "package": "default"}),
        ("list_firmware_images", {}),
        ("get_fmg_license", {}),
        ("list_packet_captures", {}),
        ("list_device_vaps", {"device": device}),
        ("list_device_wtp_profiles", {"device": device}),
        ("list_device_dhcp_servers", {"device": device}),
        ("find_duplicate_objects", {"adom": adom}),
        ("get_device_sdwan_monitor", {"adom": adom, "device": device}),
    ]


def sweep_targets() -> list[tuple[str, str]]:
    targets = [
        (os.getenv("TEST_ADOM", "mcp-dev-test"), os.getenv("TEST_DEVICE", "FGT-MCP-TEST-01"))
    ]
    for pair in os.getenv("LEAK_SWEEP_TARGETS", "").split(","):
        adom, _, device = pair.strip().partition(":")
        if adom and device:
            targets.append((adom, device))
    return targets


class TestHandshake:
    async def test_full_mode(self, tmp_path: Path) -> None:
        async with mcp_session("full", tmp_path) as session:
            init = await session.initialize()
            names = {t.name for t in (await session.list_tools()).tools}

        assert init.server_info.name == "fortimanager-mcp"
        assert init.server_info.version == __version__
        assert {"health_check", "get_system_status", "list_adoms"} <= names
        assert "execute_fortimanager_tool" not in names

    async def test_dynamic_mode_lists_only_the_discovery_tools(self, tmp_path: Path) -> None:
        async with mcp_session("dynamic", tmp_path) as session:
            await session.initialize()
            names = {t.name for t in (await session.list_tools()).tools}

        assert names == DISCOVERY_TOOLS


class TestReadOnlyCalls:
    async def test_full_mode(self, tmp_path: Path, test_adom: str, test_device: str) -> None:
        failures: list[str] = []
        async with mcp_session("full", tmp_path) as session:
            await session.initialize()
            for name, args in read_only_plan(test_adom, test_device):
                result = await session.call_tool(name, args, read_timeout_seconds=CALL_TIMEOUT)
                text, payload = decode(result)
                if err := error_of(result, payload):
                    failures.append(f"{name}: {err}")
                if leak := leak_of(text, payload):
                    failures.append(f"{name}: leak {leak}")

            result = await session.call_tool(
                "get_device_interface_config", {"device": "bad name; drop"}
            )
            _, payload = decode(result)

        assert not failures, failures
        assert error_of(result, payload) == "validation_error"

    async def test_dynamic_mode_dispatches_through_execute(
        self, tmp_path: Path, test_adom: str, test_device: str
    ) -> None:
        failures: list[str] = []
        async with mcp_session("dynamic", tmp_path) as session:
            await session.initialize()
            for name, args in read_only_plan(test_adom, test_device):
                result = await session.call_tool(
                    "execute_fortimanager_tool",
                    {"tool_name": name, "parameters": args},
                    read_timeout_seconds=CALL_TIMEOUT,
                )
                text, wrapper = decode(result)
                payload = wrapper.get("result") if isinstance(wrapper, dict) else wrapper
                if err := error_of(result, wrapper) or error_of(result, payload):
                    failures.append(f"{name}: {err}")
                if leak := leak_of(text, payload):
                    failures.append(f"{name}: leak {leak}")

            # The dispatcher succeeds and the tool's own validation error sits in
            # ``result``; a check of the top level alone would call this a pass.
            result = await session.call_tool(
                "execute_fortimanager_tool",
                {
                    "tool_name": "get_device_interface_config",
                    "parameters": {"device": "bad name; drop"},
                },
            )
            _, wrapper = decode(result)

        assert not failures, failures
        assert error_of(result, wrapper["result"]) == "validation_error"


@pytest.mark.parametrize(("adom", "device"), sweep_targets())
async def test_leak_sweep(tmp_path: Path, adom: str, device: str) -> None:
    """No read-only tool hands a client an ENC blob or a credential key.

    Calls every list_/get_/search_ tool whose required arguments can be
    filled from the ADOM and device, then the two that need an object name,
    named after the first interface and phase1 the earlier calls returned.
    Tool errors are tolerated (some tables are empty on some devices); a
    leak is not.
    """
    context = {"adom": adom, "device": device, "package": "default", "vdom": "root"}
    leaks: list[str] = []
    called = 0
    async with mcp_session("full", tmp_path) as session:
        await session.initialize()
        plan = []
        for tool in sorted((await session.list_tools()).tools, key=lambda t: t.name):
            if not tool.name.startswith(SWEEP_PREFIXES) or tool.name in SWEEP_SKIP:
                continue
            required = tool.input_schema.get("required", [])
            properties = tool.input_schema.get("properties", {})
            if all(arg in context for arg in required):
                plan.append((tool.name, {a: context[a] for a in properties if a in context}))

        first: dict[str, str] = {}
        for name, args in plan:
            result = await session.call_tool(name, args, read_timeout_seconds=CALL_TIMEOUT)
            text, payload = decode(result)
            called += 1
            if leak := leak_of(text, payload):
                leaks.append(f"{name}: {leak}")
            if name == "get_device_interface_config" and isinstance(payload, dict):
                summary = payload.get("summary") or []
                first["interface"] = next((i["name"] for i in summary if i.get("name")), "")
            if name == "list_device_ipsec_phase1_interfaces" and isinstance(payload, dict):
                phase1 = payload.get("interfaces") or []
                first["phase1"] = phase1[0].get("name", "") if phase1 else ""

        named = [
            ("get_device_interface_config", first.get("interface")),
            ("get_device_ipsec_phase1_interface", first.get("phase1")),
        ]
        for name, object_name in named:
            if not object_name:
                continue
            result = await session.call_tool(
                name, {"device": device, "name": object_name}, read_timeout_seconds=CALL_TIMEOUT
            )
            text, payload = decode(result)
            called += 1
            if leak := leak_of(text, payload):
                leaks.append(f"{name}(name=...): {leak}")

    # A schema change that stopped the plan from filling would otherwise pass
    # by calling nothing.
    assert called >= 40, f"only {called} tools swept on {adom}/{device}"
    assert not leaks, leaks
