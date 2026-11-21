"""A login FortiManager rejects is an authentication error, in both auth modes.

With a user name and password, pyfmg drops FortiManager's reply to the login
(-22 "Login fail") and goes on to read the workspace mode. Without a session
that read raises pyfmg's "no valid session" exception, and ``connect()``
wrapped it as a connection error whose text was the path of that read and
pyfmg's parameter dump. With an API token the first request is refused with
-11, which ``connect()`` reported as a connection error as well.
"""

from typing import Any

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import script_tools, system_tools
from fortimanager_mcp.utils.errors import AuthenticationError, ConnectionError
from tests.appliance_wire import AUTH, BAD_GATEWAY, Wire, new_client

BOTH = pytest.mark.parametrize("auth", list(AUTH))
#: What pyfmg's exception put into the error text.
PYFMG_DUMP = ("/cli/global/system/global", "valid session", "Paramaters", "workspace-mode")


def reject(wire: Wire, auth: str) -> tuple[int, str]:
    """Make FortiManager reject the credentials of ``auth``; its code and message."""
    if auth == "session":
        wire.login = (-22, "Login fail")
        return wire.login
    wire.answers["/sys/status"] = (-11, "No permission for the resource", None)
    return -11, "No permission for the resource"


def attempts(wire: Wire, auth: str) -> int:
    """Requests that presented the credentials."""
    return wire.logins() if auth == "session" else wire.calls.count(("get", "/sys/status"))


@BOTH
async def test_a_rejected_login_is_an_authentication_error(wire: Wire, auth: str) -> None:
    code, said = reject(wire, auth)
    client = new_client(auth)
    with pytest.raises(AuthenticationError) as refused:
        await client.connect()
    text = str(refused.value)
    assert said in text
    assert refused.value.code == code
    assert not any(part in text for part in PYFMG_DUMP)
    assert not client.is_connected
    assert attempts(wire, auth) == 1


@BOTH
async def test_a_tool_reports_it_as_one(
    wire: Wire, auth: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, said = reject(wire, auth)
    client = new_client(auth)
    monkeypatch.setattr(system_tools, "get_fmg_client", lambda: client)
    result = await system_tools.get_system_status()
    assert result["status"] == "error"
    assert result["error_code"] == "authentication_error"
    assert said in result["message"]
    assert not any(part in result["message"] for part in PYFMG_DUMP)


@BOTH
async def test_each_tool_call_still_presents_the_credentials_once(
    wire: Wire, auth: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One attempt per call, as before: a second one inside the same call would
    reach FortiManager's admin lockout twice as fast. A script tool is in the
    list because it asks for the FortiManager version first, which is a
    request of its own."""
    reject(wire, auth)
    client = new_client(auth)
    monkeypatch.setattr(system_tools, "get_fmg_client", lambda: client)
    monkeypatch.setattr(script_tools, "get_fmg_client", lambda: client)
    calls: list[Any] = [
        system_tools.get_system_status,
        lambda: script_tools.list_scripts(adom="root"),
        system_tools.get_system_status,
    ]
    for number, call in enumerate(calls, start=1):
        result = await call()
        assert result["error_code"] == "authentication_error", result
        assert attempts(wire, auth) == number


@BOTH
async def test_a_proxy_page_at_login_is_not_an_authentication_error(wire: Wire, auth: str) -> None:
    """What answered was not FortiManager, so nothing rejected the credentials."""
    wire.page = BAD_GATEWAY
    client = new_client(auth)
    with pytest.raises(ConnectionError) as refused:
        await client.connect()
    assert not isinstance(refused.value, AuthenticationError)
    assert not any(part in str(refused.value) for part in PYFMG_DUMP)


async def test_a_login_answered_without_a_session_is_refused_in_pyfmg_words(wire: Wire) -> None:
    """FortiManager's reply holds no error to quote, so the text is pyfmg's,
    as the branch for a failed login always worded it."""
    wire.session = None
    with pytest.raises(AuthenticationError) as refused:
        await new_client("session").connect()
    assert refused.value.code is None
    assert "no valid connection" in str(refused.value)
    assert "OK" not in str(refused.value)


@BOTH
async def test_a_refused_connection_is_not_an_authentication_error(wire: Wire, auth: str) -> None:
    wire.refuses = True
    with pytest.raises(ConnectionError):
        await new_client(auth).connect()


@BOTH
async def test_an_accepted_login_connects(wire: Wire, auth: str) -> None:
    client: FortiManagerClient = new_client(auth)
    await client.connect()
    assert client.is_connected
    assert attempts(wire, auth) == 1


async def test_a_session_login_is_one_request(wire: Wire) -> None:
    """pyfmg's read of the workspace mode after the login is switched off, as
    it already was with an API token: it serves lock helpers of pyfmg that the
    client does not use, and it is what raised after a rejected login."""
    await new_client("session").connect()
    assert wire.calls == [("exec", "sys/login/user")]
