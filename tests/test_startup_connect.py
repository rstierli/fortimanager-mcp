"""The server serves at once and connects to FortiManager in the background.

Awaiting the connect before serving made ``initialize`` wait out the whole
connect timeout when FortiManager was unreachable, past Claude Code's own
30 s MCP connect timeout, and a failed startup connect left every tool
answering "client not initialized" until a restart.
"""

import asyncio
import os
import sys
import time
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import fortimanager_mcp.server as server
from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import system_tools
from fortimanager_mcp.utils.errors import ConnectionError

REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
# RFC 5737 TEST-NET-1: never routed, so a connect to it hangs until the timeout.
UNREACHABLE_HOST = "192.0.2.1"
CONNECT_TIMEOUT = 20


@pytest.fixture
def fmg_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server.settings, "FORTIMANAGER_HOST", "test-fmg.example.com")
    monkeypatch.setattr(server, "_fmg_client", None)


def _connected(client: FortiManagerClient) -> None:
    fmg = MagicMock()
    fmg.get.return_value = (0, {"Hostname": "fmg-01", "Version": "v7.6.5"})
    client._fmg = fmg
    client._connected = True
    client._ever_connected = True


class TestStartupDoesNotBlock:
    async def test_start_returns_before_the_connect_finishes(
        self, fmg_host: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = asyncio.Event()

        async def slow_connect(self_: FortiManagerClient) -> None:
            await release.wait()
            _connected(self_)

        monkeypatch.setattr(FortiManagerClient, "connect", slow_connect)
        task = server._start_fmg_client()
        assert task is not None
        await asyncio.sleep(0)
        assert not task.done()
        assert server.get_fmg_client() is not None

        release.set()
        await task
        assert server.get_fmg_client().is_connected

    async def test_stop_cancels_a_pending_connect(
        self, fmg_host: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def hanging_connect(self_: FortiManagerClient) -> None:
            await asyncio.Event().wait()

        monkeypatch.setattr(FortiManagerClient, "connect", hanging_connect)
        task = server._start_fmg_client()
        await asyncio.sleep(0)
        await asyncio.wait_for(server._stop_fmg_client(task), timeout=2)
        assert task is not None and task.cancelled()

    async def test_no_host_starts_no_connect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server.settings, "FORTIMANAGER_HOST", "")
        monkeypatch.setattr(server, "_fmg_client", None)
        assert server._start_fmg_client() is None
        assert server.get_fmg_client() is None
        await server._stop_fmg_client(None)


class TestRecoveryAfterAFailedStartup:
    async def test_tool_connects_once_fortimanager_is_reachable(
        self, fmg_host: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reachable = False

        async def connect(self_: FortiManagerClient) -> None:
            if not reachable:
                raise ConnectionError("Failed to connect to FortiManager: timed out")
            _connected(self_)

        monkeypatch.setattr(FortiManagerClient, "connect", connect)
        task = server._start_fmg_client()
        assert task is not None
        await task  # the startup attempt fails and only logs

        down: dict[str, Any] = await system_tools.get_system_status()
        assert down["status"] == "error"
        assert down["error_code"] == "connection_error"

        reachable = True
        up: dict[str, Any] = await system_tools.get_system_status()
        assert up["status"] == "success"


class TestStdioHandshake:
    async def test_initialize_does_not_wait_for_an_unreachable_fortimanager(self) -> None:
        """The real stdio path, with FortiManager unreachable.

        Before the fix ``initialize`` was answered only after the connect
        timeout. The dummy credentials also keep the repo's .env token from
        being sent anywhere.
        """
        env = {
            **os.environ,
            "PYTHONPATH": REPO_SRC,
            "MCP_SERVER_MODE": "stdio",
            "LOG_LEVEL": "WARNING",
            "FORTIMANAGER_HOST": UNREACHABLE_HOST,
            "FORTIMANAGER_API_TOKEN": "dummy",
            "FORTIMANAGER_USERNAME": "",
            "FORTIMANAGER_PASSWORD": "",
            "FORTIMANAGER_TIMEOUT": str(CONNECT_TIMEOUT),
            "MASKING_ENABLED": "false",
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "fortimanager_mcp"], env=env
        )
        with open(os.devnull, "w") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    started = time.monotonic()
                    result = await session.initialize()
                    elapsed = time.monotonic() - started

        assert result.server_info.name == "fortimanager-mcp"
        assert elapsed < CONNECT_TIMEOUT / 2, f"initialize took {elapsed:.1f}s"
