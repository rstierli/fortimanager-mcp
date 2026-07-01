"""Tests that the MCP server wires the MCP_STATELESS_HTTP flag through to FastMCP.

The ``mcp`` FastMCP instance is constructed at module import, so these tests
reload the server module after setting the environment variable, then assert the
flag reached FastMCP's own settings (``mcp.settings.stateless_http``).
"""

import importlib

import pytest


def _reload_server(monkeypatch: pytest.MonkeyPatch, value: str | None):
    monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
    if value is None:
        monkeypatch.delenv("MCP_STATELESS_HTTP", raising=False)
    else:
        monkeypatch.setenv("MCP_STATELESS_HTTP", value)

    from fortimanager_mcp.utils import config

    config.get_settings.cache_clear()
    import fortimanager_mcp.server as server

    return importlib.reload(server)


@pytest.fixture(autouse=True)
def _restore_server_module(monkeypatch: pytest.MonkeyPatch):
    """Reload server with a clean cache so module-global state doesn't leak.

    Owns FORTIMANAGER_HOST itself so the post-yield reload still has the required
    setting after each test body's own monkeypatch has unwound.
    """
    monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
    yield
    from fortimanager_mcp.utils import config

    config.get_settings.cache_clear()
    import fortimanager_mcp.server as server

    importlib.reload(server)


def test_stateless_http_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _reload_server(monkeypatch, None)
    assert server.mcp.settings.stateless_http is False


def test_stateless_http_enabled_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _reload_server(monkeypatch, "true")
    assert server.mcp.settings.stateless_http is True
