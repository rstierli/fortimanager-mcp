"""Fail-closed HTTP auth guard (security regression).

The HTTP transport fronts the full tool surface (incl. destructive device
add/delete, policy install, and script execution on managed devices), so it
must refuse to start unauthenticated unless the operator explicitly opts out
with MCP_ALLOW_NO_AUTH=true.
"""

import pytest

import fortimanager_mcp.server as server


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
