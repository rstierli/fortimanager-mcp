"""What answers on the wire instead of FortiManager, under the real pyfmg.

A test that swaps pyfmg's ``FortiManager`` for a mock decides itself what
pyfmg makes of a reply. These helpers leave pyfmg and ``requests`` in place
and answer the HTTP request pyfmg sends, so a test sees what the client does
with pyfmg's real outcome: its code 100 for a body that is not JSON, or the
exception it raises after a login that opened no session. The ``wire``
fixture (conftest.py) puts a ``Wire`` in place for one test.
"""

import io
import json
from typing import Any

import requests

from fortimanager_mcp.api.client import FortiManagerClient

HOST = "fmg.example.com"
#: Constructor arguments per authentication mode.
AUTH: dict[str, dict[str, str]] = {
    "token": {"api_token": "token-for-tests"},
    "session": {"username": "admin", "password": "password-for-tests"},
}
BAD_GATEWAY = (502, b"<html><body><h1>502 Bad Gateway</h1></body></html>")
UNAVAILABLE = (503, b"")


class Wire:
    """Answers each JSON-RPC request the way a FortiManager would, until told otherwise."""

    def __init__(self) -> None:
        #: (method, url) of every request sent, in order.
        self.calls: list[tuple[str, str]] = []
        #: (HTTP status, body) sent in place of FortiManager's answer, as a
        #: proxy in front of it does when it cannot reach it.
        self.page: tuple[int, bytes] | None = None
        #: Nothing listens: the connection is refused.
        self.refuses = False
        #: FortiManager's status for a login; a rejected one opens no session.
        self.login = (0, "OK")
        #: The session an accepted login opens.
        self.session: str | None = "session-for-tests"
        #: url -> (code, message, data) for everything that is not a login.
        self.answers: dict[str, tuple[int, str, Any]] = {
            "/sys/status": (0, "OK", {"Hostname": "fmg-01", "Version": "v7.6.5-build3653"}),
        }

    def logins(self) -> int:
        return self.calls.count(("exec", "sys/login/user"))

    def send(self, request: requests.PreparedRequest) -> requests.Response:
        call = json.loads(request.body or b"{}")
        url = call["params"][0]["url"]
        self.calls.append((call["method"], url))
        if self.refuses:
            raise requests.exceptions.ConnectionError("connection refused")
        if self.page is not None:
            return _response(request, *self.page, "text/html")
        reply: dict[str, Any] = {"id": call["id"]}
        if url == "sys/login/user":
            code, message = self.login
            result: dict[str, Any] = {"status": {"code": code, "message": message}, "url": url}
            if code == 0 and self.session:
                reply["session"] = self.session
        else:
            code, message, data = self.answers.get(url, (0, "OK", {}))
            result = {"status": {"code": code, "message": message}, "url": url}
            if code == 0:
                result["data"] = data
        reply["result"] = [result]
        return _response(request, 200, json.dumps(reply).encode(), "application/json")


def _response(
    request: requests.PreparedRequest, status: int, body: bytes, content_type: str
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.raw = io.BytesIO(body)
    response.headers["Content-Type"] = content_type
    response.request = request
    response.url = request.url or ""
    return response


def new_client(auth: str) -> FortiManagerClient:
    """A client as the server builds it, not yet connected."""
    return FortiManagerClient(host=HOST, connect_on_demand=True, **AUTH[auth])
