"""Tests that the MCP server wires the MCP_STATELESS_HTTP flag to the transport.

On mcp 2.x ``stateless_http`` is an argument to ``streamable_http_app()``,
not a constructor kwarg, and it is no longer readable back off the server
object: ``MCPServer.settings`` has no such field. So the assertion has to
watch the call ``run_http`` actually makes, which is also the only place
the value has any effect.

The ``mcp`` instance is constructed at module import, so these tests reload
the server module after setting the environment variable.
"""

import importlib

import pytest


def _reload_server(monkeypatch: pytest.MonkeyPatch, value: str | None):
    monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
    # run_http refuses to start unauthenticated, and these tests get far
    # enough into it to hit that guard.
    monkeypatch.setenv("MCP_AUTH_TOKEN", "not-a-real-token")
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


def _transport_kwargs(server, monkeypatch: pytest.MonkeyPatch) -> dict:
    """Run ``run_http`` far enough to capture the transport arguments.

    ``streamable_http_app`` is recorded rather than stubbed blind: it still
    returns a real ASGI app, so the Starlette mount it feeds is built for
    real and a wrong argument name would raise here rather than pass.
    """
    captured: dict = {}
    real_app = server.mcp.streamable_http_app

    def recording_app(**kwargs):
        captured.update(kwargs)
        return real_app(**kwargs)

    monkeypatch.setattr(server.mcp, "streamable_http_app", recording_app)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    server.run_http()
    return captured


def test_stateless_http_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _reload_server(monkeypatch, None)
    assert _transport_kwargs(server, monkeypatch)["stateless_http"] is False


def test_stateless_http_enabled_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _reload_server(monkeypatch, "true")
    assert _transport_kwargs(server, monkeypatch)["stateless_http"] is True


def test_allowed_hosts_reach_the_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other kwarg that moved, and the one that fails open if dropped.

    Losing ``stateless_http`` changes performance characteristics; losing
    ``transport_security`` unbinds the server from MCP_ALLOWED_HOSTS, so it
    is pinned in the same place.
    """
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", '["mcp.example.com"]')
    server = _reload_server(monkeypatch, None)
    security = _transport_kwargs(server, monkeypatch)["transport_security"]
    assert security is not None
    assert security.allowed_hosts == ["mcp.example.com"]
