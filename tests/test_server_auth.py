"""Fail-closed HTTP auth guard (security regression).

The HTTP transport fronts the full tool surface (incl. destructive device
add/delete, policy install, and script execution on managed devices), so it
must refuse to start unauthenticated unless the operator explicitly opts out
with MCP_ALLOW_NO_AUTH=true.
"""

from typing import Any

import pytest

import fortimanager_mcp.server as server


def built_app(monkeypatch: pytest.MonkeyPatch, token: str) -> tuple[Any, list[str]]:
    """The app run_http hands to uvicorn, and a record of what got past its auth.

    The Bearer check is a closure inside run_http, so the app is taken from the
    uvicorn.run call. The MCP transport behind it is swapped for a recorder: a
    rejected request must never reach it.
    """
    import uvicorn

    reached: list[str] = []

    async def transport(scope: Any, receive: Any, send: Any) -> None:
        reached.append(scope["method"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    captured: dict[str, Any] = {}
    monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", token)
    monkeypatch.setattr(server.mcp, "streamable_http_app", lambda **kwargs: transport)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: captured.update(app=app))
    server.run_http()
    return captured["app"], reached


async def status_for(app: Any, authorization: bytes | None) -> int:
    """POST /mcp with the given raw Authorization header bytes; the response status."""
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": [] if authorization is None else [(b"authorization", authorization)],
        "client": ("198.51.100.7", 55000),
        "server": ("mcp.example.com", 80),
    }
    await app(scope, receive, send)
    return next(int(m["status"]) for m in sent if m["type"] == "http.response.start")


class TestHttpAuthFailClosed:
    def test_token_set_allows_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A configured token satisfies the guard."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", False)
        server._ensure_http_auth_or_die()  # must not raise

    def test_no_token_no_optout_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No token + no opt-out => refuse to start (SystemExit)."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", None)
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", False)
        with pytest.raises(SystemExit) as exc:
            server._ensure_http_auth_or_die()
        assert "MCP_AUTH_TOKEN" in str(exc.value)

    def test_no_token_empty_string_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty-string token (the Docker default) is treated as unset."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "")
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", False)
        with pytest.raises(SystemExit):
            server._ensure_http_auth_or_die()

    def test_explicit_optout_allows_no_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Explicit MCP_ALLOW_NO_AUTH=true permits unauthenticated start (logged)."""
        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", None)
        monkeypatch.setattr(server.settings, "MCP_ALLOW_NO_AUTH", True)
        server._ensure_http_auth_or_die()  # must not raise


class TestBearerAuthMiddleware:
    """The Bearer check in the app run_http builds, fed raw header bytes.

    The Authorization header is the caller's to choose and need not be text.
    Whatever it holds, a request without the configured token is a 401.
    """

    @pytest.mark.asyncio
    async def test_only_the_configured_token_reaches_the_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Control: a missing or wrong token is 401, the right one passes."""
        app, reached = built_app(monkeypatch, "secret-token")

        assert await status_for(app, None) == 401
        assert await status_for(app, b"Bearer wrong-token") == 401
        assert reached == []
        assert await status_for(app, b"Bearer secret-token") == 200
        assert reached == ["POST"]

    @pytest.mark.asyncio
    async def test_header_that_is_not_utf8_is_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Header bytes that are not UTF-8 are a wrong token, not a server error."""
        app, reached = built_app(monkeypatch, "secret-token")

        assert await status_for(app, b"Bearer \xff\xfe") == 401
        assert reached == []

    @pytest.mark.asyncio
    async def test_non_ascii_header_is_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """So is valid UTF-8 outside ASCII, which hmac.compare_digest refuses as str."""
        app, reached = built_app(monkeypatch, "secret-token")

        assert await status_for(app, "Bearer t\u00f6k\u00e9n".encode()) == 401
        assert reached == []

    @pytest.mark.asyncio
    async def test_stray_byte_in_the_right_token_is_401(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No bypass: dropping the undecodable byte would leave the configured token."""
        app, reached = built_app(monkeypatch, "secret-token")

        assert await status_for(app, b"Bearer secret-\xfftoken") == 401
        assert await status_for(app, b"Bearer secret-token\xff") == 401
        assert reached == []

    @pytest.mark.asyncio
    async def test_non_ascii_token_matches_its_utf8_bytes_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-ASCII MCP_AUTH_TOKEN is compared too, instead of failing every request."""
        app, reached = built_app(monkeypatch, "t\u00f6k\u00e9n")

        assert await status_for(app, None) == 401
        assert await status_for(app, b"Bearer wrong-token") == 401
        assert await status_for(app, "Bearer t\u00f6k\u00e9n".encode("latin-1")) == 401
        assert reached == []
        assert await status_for(app, "Bearer t\u00f6k\u00e9n".encode()) == 200
        assert reached == ["POST"]
