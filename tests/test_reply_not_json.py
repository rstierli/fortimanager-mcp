"""A reply that is not JSON is not an answer from FortiManager.

A proxy in front of FortiManager that cannot reach it answers with its own
page (a 502 or 503). pyfmg hands that back as code 100 with the HTTP response
itself. The client took any code for "FortiManager answered", so ``/health``
kept saying ``fortimanager_connected: true`` while every tool call failed,
and the error a tool returned was ``<Response [502]>``.
"""

import json
from typing import Any

import pytest

import fortimanager_mcp.server as server
from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import system_tools
from fortimanager_mcp.utils.errors import FortiManagerMCPError, ResourceNotFoundError
from tests.appliance_wire import AUTH, BAD_GATEWAY, UNAVAILABLE, Wire, new_client
from tests.test_server_auth import built_app

PAGES = pytest.mark.parametrize("page", [BAD_GATEWAY, UNAVAILABLE], ids=["502 page", "503 empty"])


@pytest.fixture(params=list(AUTH))
async def client(request: pytest.FixtureRequest, wire: Wire) -> FortiManagerClient:
    """Connected over the wire, with token and with session authentication."""
    connected = new_client(request.param)
    await connected.connect()
    assert connected.is_reachable
    return connected


async def health(app: Any) -> dict[str, Any]:
    """GET /health on the app run_http hands to uvicorn."""
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/health",
        "raw_path": b"/health",
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": [],
        "client": ("198.51.100.7", 55000),
        "server": ("mcp.example.com", 80),
    }
    await app(scope, receive, send)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    answer: dict[str, Any] = json.loads(body)
    return answer


@PAGES
async def test_a_proxy_page_marks_fortimanager_unreachable(
    client: FortiManagerClient, wire: Wire, page: tuple[int, bytes]
) -> None:
    wire.page = page
    with pytest.raises(FortiManagerMCPError):
        await client.get_system_status()
    assert client.is_connected
    assert not client.is_reachable

    wire.page = None
    await client.get_system_status()
    assert client.is_reachable


@PAGES
async def test_health_follows_it(
    client: FortiManagerClient,
    wire: Wire,
    page: tuple[int, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Through the tool and the app run_http serves, as an operator sees it."""
    app, _ = built_app(monkeypatch, "secret-token")
    monkeypatch.setattr(server, "_fmg_client", client)
    monkeypatch.setattr(system_tools, "get_fmg_client", lambda: client)
    assert (await health(app))["fortimanager_connected"] is True

    wire.page = page
    for _ in range(3):
        assert (await system_tools.get_system_status())["status"] == "error"
        assert (await health(app))["fortimanager_connected"] is False

    wire.page = None
    assert (await system_tools.get_system_status())["status"] == "success"
    assert (await health(app))["fortimanager_connected"] is True


@PAGES
async def test_the_error_says_what_answered(
    client: FortiManagerClient, wire: Wire, page: tuple[int, bytes]
) -> None:
    wire.page = page
    with pytest.raises(FortiManagerMCPError) as refused:
        await client.get_system_status()
    text = str(refused.value)
    assert f"HTTP {page[0]}" in text
    assert "not JSON" in text
    assert "<Response" not in text


@PAGES
async def test_a_proxy_page_starts_no_new_login(
    client: FortiManagerClient, wire: Wire, page: tuple[int, bytes]
) -> None:
    """It is not a session error: logging in again would only hit the same page."""
    logins = wire.logins()
    wire.page = page
    with pytest.raises(FortiManagerMCPError):
        await client.get_system_status()
    assert wire.logins() == logins
    assert wire.calls[-1] == ("get", "/sys/status")


async def test_an_error_code_is_still_an_answer(client: FortiManagerClient, wire: Wire) -> None:
    """Control: FortiManager answering with one of its own codes is reachable."""
    client._unreachable = True
    wire.answers["/sys/status"] = (-3, "Object does not exist", None)
    with pytest.raises(ResourceNotFoundError):
        await client.get_system_status()
    assert client.is_reachable
