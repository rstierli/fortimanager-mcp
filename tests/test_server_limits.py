"""Request-bound guards for the HTTP transport (availability regression).

The Streamable HTTP handler buffers the whole request body before decoding it,
and every FortiManager call serializes behind one process-wide lock. Without
bounds, a single authenticated client can exhaust memory or park an unbounded
queue of requests. These tests pin the two guards that bound it.
"""

from typing import Any

import pytest
from pydantic import ValidationError

import fortimanager_mcp.server as server
from fortimanager_mcp.utils.config import Settings


async def drive(
    app: Any,
    scope: dict[str, Any],
    body_chunks: list[bytes],
) -> list[dict[str, Any]]:
    """Run an ASGI app to completion, feeding body_chunks, collecting sent messages."""
    pending = list(body_chunks)
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if pending:
            chunk = pending.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


def http_scope(headers: list[tuple[bytes, bytes]] | None = None) -> dict[str, Any]:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": headers or [],
        "client": ("198.51.100.7", 55000),
        "server": ("testserver", 80),
    }


def mounted_echo_app(max_bytes: int) -> Any:
    """The real deployed shape: the guard wrapping a Starlette app that mounts another.

    The mounted app brings its own ServerErrorMiddleware, which swallows and
    re-raises exceptions after emitting a 500. The guard has to win anyway.
    """
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route

    async def echo(request: Request) -> JSONResponse:
        body = await request.body()
        return JSONResponse({"len": len(body)})

    inner = Starlette(routes=[Route("/", echo, methods=["POST"])])
    return server.BodyLimitMiddleware(
        Starlette(routes=[Mount("/", app=inner)]), max_bytes=max_bytes
    )


def status_of(sent: list[dict[str, Any]]) -> int | None:
    for message in sent:
        if message["type"] == "http.response.start":
            return int(message["status"])
    return None


class TestBodyLimitMiddleware:
    @pytest.mark.asyncio
    async def test_declared_oversize_body_rejected_before_downstream(self) -> None:
        """Content-Length above the cap short-circuits to 413; downstream never runs."""
        reached = False

        async def downstream(scope: Any, receive: Any, send: Any) -> None:
            nonlocal reached
            reached = True

        app = server.BodyLimitMiddleware(downstream, max_bytes=100)
        sent = await drive(app, http_scope([(b"content-length", b"101")]), [])

        assert status_of(sent) == 413
        assert reached is False

    @pytest.mark.asyncio
    async def test_undeclared_oversize_body_rejected_while_streaming(self) -> None:
        """A chunked body with no Content-Length is capped on the actual bytes read."""

        async def downstream(scope: Any, receive: Any, send: Any) -> None:
            while True:
                message = await receive()
                if not message.get("more_body"):
                    break

        app = server.BodyLimitMiddleware(downstream, max_bytes=100)
        sent = await drive(app, http_scope(), [b"x" * 60, b"x" * 60])

        assert status_of(sent) == 413

    @pytest.mark.asyncio
    async def test_oversize_through_real_stack_still_returns_413(self) -> None:
        """The mounted app's ServerErrorMiddleware must not turn the 413 into a 500."""
        app = mounted_echo_app(max_bytes=100)
        scope = http_scope()
        scope["path"] = "/"
        scope["raw_path"] = b"/"
        sent = await drive(app, scope, [b"x" * 60, b"x" * 60])

        assert status_of(sent) == 413
        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert len(starts) == 1  # exactly one response, no ASGI protocol violation

    @pytest.mark.asyncio
    async def test_within_cap_through_real_stack_is_served(self) -> None:
        """The same real stack serves normal traffic untouched."""
        app = mounted_echo_app(max_bytes=100)
        scope = http_scope()
        scope["path"] = "/"
        scope["raw_path"] = b"/"
        sent = await drive(app, scope, [b"x" * 40])

        assert status_of(sent) == 200

    @pytest.mark.asyncio
    async def test_body_within_cap_reaches_downstream_intact(self) -> None:
        """Traffic under the cap is passed through byte-for-byte."""
        seen = bytearray()

        async def downstream(scope: Any, receive: Any, send: Any) -> None:
            while True:
                message = await receive()
                seen.extend(message.get("body", b""))
                if not message.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        app = server.BodyLimitMiddleware(downstream, max_bytes=100)
        sent = await drive(app, http_scope([(b"content-length", b"80")]), [b"a" * 40, b"b" * 40])

        assert status_of(sent) == 200
        assert bytes(seen) == b"a" * 40 + b"b" * 40

    @pytest.mark.asyncio
    async def test_zero_cap_disables_the_guard(self) -> None:
        """max_bytes=0 is the operator escape hatch: no bound at all."""
        seen = bytearray()

        async def downstream(scope: Any, receive: Any, send: Any) -> None:
            while True:
                message = await receive()
                seen.extend(message.get("body", b""))
                if not message.get("more_body"):
                    break

        app = server.BodyLimitMiddleware(downstream, max_bytes=0)
        sent = await drive(app, http_scope([(b"content-length", b"999999")]), [b"z" * 5000])

        assert status_of(sent) is None  # never rejected
        assert len(seen) == 5000


class TestLimitSettings:
    def test_defaults_are_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Both guards ship on by default; an operator must opt out explicitly."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        monkeypatch.delenv("MCP_MAX_REQUEST_BYTES", raising=False)
        monkeypatch.delenv("MCP_MAX_CONCURRENT_REQUESTS", raising=False)

        settings = Settings()
        assert settings.MCP_MAX_REQUEST_BYTES > 0
        assert settings.MCP_MAX_CONCURRENT_REQUESTS > 0

    def test_zero_opts_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Zero disables each guard; negative values are rejected outright."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test-fmg.example.com")
        monkeypatch.setenv("MCP_MAX_REQUEST_BYTES", "0")
        monkeypatch.setenv("MCP_MAX_CONCURRENT_REQUESTS", "0")

        settings = Settings()
        assert settings.MCP_MAX_REQUEST_BYTES == 0
        assert settings.MCP_MAX_CONCURRENT_REQUESTS == 0

        monkeypatch.setenv("MCP_MAX_REQUEST_BYTES", "-1")
        with pytest.raises(ValidationError):
            Settings()


class TestHttpWiring:
    def test_run_http_applies_both_bounds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_http installs the body cap and hands the concurrency ceiling to uvicorn."""
        import uvicorn

        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
        monkeypatch.setattr(server.settings, "MCP_MAX_REQUEST_BYTES", 1234)
        monkeypatch.setattr(server.settings, "MCP_MAX_CONCURRENT_REQUESTS", 7)

        captured: dict[str, Any] = {}

        def fake_run(app: Any, **kwargs: Any) -> None:
            captured["app"] = app
            captured["kwargs"] = kwargs

        monkeypatch.setattr(uvicorn, "run", fake_run)
        server.run_http()

        assert captured["kwargs"]["limit_concurrency"] == 7
        installed = [
            m for m in captured["app"].user_middleware if m.cls is server.BodyLimitMiddleware
        ]
        assert len(installed) == 1
        assert installed[0].kwargs["max_bytes"] == 1234

    def test_run_http_bounds_the_graceful_shutdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An open client stream must not hold the stop until the supervisor's SIGKILL.

        At shutdown uvicorn waits for every open connection before it runs the
        lifespan shutdown, with no limit unless one is configured ("Waiting for
        connections to close."). MCP clients hold a standing event stream per
        session, so under systemd every stop sat out TimeoutStopSec (90 s) and
        ended in SIGKILL.
        """
        import uvicorn

        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
        captured: dict[str, Any] = {}
        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kwargs=kw))
        server.run_http()

        assert captured["kwargs"]["timeout_graceful_shutdown"] == 3

    def test_the_stop_fits_dockers_window(self) -> None:
        """docker stop sends SIGKILL after 10 s. A stop first waits for open
        connections, then the lifespan shutdown spends up to the client's
        shutdown budget on the ADOM unlocks and the logout."""
        from fortimanager_mcp.api.client import FortiManagerClient

        total = server.GRACEFUL_SHUTDOWN_TIMEOUT + FortiManagerClient._SHUTDOWN_IO_BUDGET
        # Leave room for process start-up of the shutdown path and exit.
        assert total <= 8

    def test_zero_concurrency_leaves_uvicorn_unbounded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """0 means opt out: uvicorn gets None, its own unbounded default."""
        import uvicorn

        monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
        monkeypatch.setattr(server.settings, "MCP_MAX_CONCURRENT_REQUESTS", 0)

        captured: dict[str, Any] = {}
        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kwargs=kw))
        server.run_http()

        assert captured["kwargs"]["limit_concurrency"] is None


async def _mcp_post_status(
    monkeypatch: pytest.MonkeyPatch, size: int, max_bytes: int
) -> tuple[int, bytes]:
    """Status and body the app ``run_http`` builds answers a POST /mcp of
    ``size`` bytes with, sent in chunks and without a Content-Length."""
    import asyncio

    import uvicorn

    monkeypatch.setattr(server.settings, "MCP_AUTH_TOKEN", "secret-token")
    monkeypatch.setattr(server.settings, "MCP_MAX_REQUEST_BYTES", max_bytes)

    # No FortiManager behind this app: the lifespan starts the session
    # manager only.
    async def idle() -> None:
        return None

    async def no_stop(_task: Any) -> None:
        return None

    monkeypatch.setattr(server, "_start_fmg_client", lambda: asyncio.ensure_future(idle()))
    monkeypatch.setattr(server, "_stop_fmg_client", no_stop)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(app=app))
    server.run_http()
    app = captured["app"]

    scope = http_scope(
        [
            (b"host", b"127.0.0.1:8000"),
            (b"authorization", b"Bearer secret-token"),
            (b"accept", b"application/json, text/event-stream"),
            (b"content-type", b"application/json"),
        ]
    )
    body = b"x" * size
    chunks = [body[i : i + 65536] for i in range(0, size, 65536)]
    sent: list[dict[str, Any]] = []
    answered = asyncio.Event()

    async def receive() -> dict[str, Any]:
        if chunks:
            chunk = chunks.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
        await answered.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if message["type"] == "http.response.start":
            answered.set()

    async with app.router.lifespan_context(app):
        await asyncio.wait_for(app(scope, receive, send), timeout=10)
    status = status_of(sent)
    assert status is not None
    text = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, text


class TestTheSdkBodyLimit:
    """The MCP SDK refuses a body over 4 MiB itself, inside the app this
    server mounts (measured with mcp 2.0.0, 2.1.1 and 2.3.0). So
    MCP_MAX_REQUEST_BYTES above 4 MiB has no effect, and 0 turns off only
    this server's own check (#139 item 14). The README, .env.example and the
    setting's description say so; if this fails after an SDK upgrade, they
    need changing too."""

    @pytest.mark.parametrize("max_bytes", [10 * 1024 * 1024, 0])
    @pytest.mark.asyncio
    async def test_a_body_over_4_mib_gets_the_sdks_413(
        self, monkeypatch: pytest.MonkeyPatch, max_bytes: int
    ) -> None:
        status, text = await _mcp_post_status(monkeypatch, 4 * 1024 * 1024 + 1, max_bytes)

        assert (status, text) == (413, b"Request body too large")

    @pytest.mark.asyncio
    async def test_a_body_of_4_mib_reaches_the_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The control: one byte less is read and parsed (it is not JSON)."""
        status, _ = await _mcp_post_status(monkeypatch, 4 * 1024 * 1024, 10 * 1024 * 1024)

        assert status == 400
