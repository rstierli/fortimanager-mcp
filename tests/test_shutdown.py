"""Stopping the server once FortiManager has stopped answering.

Every stop releases still-held ADOM locks and disconnects. Against an
appliance that went away after the connect, each of those requests waited
out FORTIMANAGER_TIMEOUT, and the token-mode logout had no server session to
end in the first place. These tests stop a real server process against a
localhost HTTPS stand-in for FortiManager that answers until it is told to go
silent.
"""

import asyncio
import contextlib
import datetime
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import GRACEFUL_SHUTDOWN_TIMEOUT

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="stops the server with SIGTERM")

REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
# FORTIMANAGER_TIMEOUT of the server under test. Before the fix a stop took
# this long, and twice this with an ADOM lock held.
REQUEST_TIMEOUT = 20
LOGOUT = FortiManagerClient._LOGOUT_TIMEOUT
BUDGET = FortiManagerClient._SHUTDOWN_IO_BUDGET
# docker stop sends SIGKILL after this many seconds.
DOCKER_STOP = 10
# Process start, imports and interpreter exit on a slow CI runner.
MARGIN = 2.0


def _self_signed_cert(directory: Path) -> tuple[Path, Path]:
    """A throwaway certificate for the stub, made at test time."""
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "stub-cert.pem"
    key_path = directory / "stub-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _Handler(BaseHTTPRequestHandler):
    # Keep-alive, so the server under test reuses its connection as it would
    # against a real appliance.
    protocol_version = "HTTP/1.1"
    server: "_FortiManagerStub"

    def setup(self) -> None:
        if self.server.silent.is_set():
            # A new connection never completes TLS.
            self.server.released.wait()
        self.request.do_handshake()
        super().setup()

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.server.silent.is_set():
            # Read the request, never answer it.
            self.server.released.wait()
            self.close_connection = True
            return
        url = body["params"][0]["url"]
        self.server.urls.append(url)
        data = {"Hostname": "stub", "Version": "v7.6.5"} if url == "/sys/status" else {}
        out = json.dumps(
            {
                "id": body.get("id"),
                "session": "stub-session",
                "result": [{"status": {"code": 0, "message": "OK"}, "url": url, "data": data}],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class _FortiManagerStub(ThreadingHTTPServer):
    """JSON-RPC over HTTPS on 127.0.0.1 that answers code 0 until ``silent``.

    From then on it reads requests and never answers them, on open
    connections and new ones alike. That is how an appliance looks once it
    has gone away behind a stateful firewall.
    """

    daemon_threads = True

    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.context = context
        self.silent = threading.Event()
        self.released = threading.Event()
        self.urls: list[str] = []

    def get_request(self) -> tuple[Any, Any]:
        sock, addr = super().get_request()
        # The handshake runs in the handler thread, so a silent stub can hold it.
        return self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # connections the stub abandons at teardown

    def wait_for(self, url: str, timeout: float = 15) -> None:
        deadline = time.monotonic() + timeout
        while url not in self.urls:
            assert time.monotonic() < deadline, f"server never sent {url}: {self.urls}"
            time.sleep(0.05)


@pytest.fixture
def fmg_stub(tmp_path: Path) -> Iterator[_FortiManagerStub]:
    cert, key = _self_signed_cert(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    stub = _FortiManagerStub(context)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    yield stub
    stub.released.set()
    stub.shutdown()
    stub.server_close()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _server_env(stub: _FortiManagerStub, *, token: bool, **extra: str) -> dict[str, str]:
    return {
        **os.environ,
        "PYTHONPATH": REPO_SRC,
        "LOG_LEVEL": "WARNING",
        "FORTIMANAGER_HOST": f"127.0.0.1:{stub.server_port}",
        # Dummy credentials, set explicitly so none from the repo's .env are used.
        "FORTIMANAGER_API_TOKEN": "dummy" if token else "",
        "FORTIMANAGER_USERNAME": "" if token else "admin",
        "FORTIMANAGER_PASSWORD": "" if token else "dummy",
        "FORTIMANAGER_VERIFY_SSL": "false",
        "FORTIMANAGER_CA_BUNDLE": "",
        "FORTIMANAGER_TIMEOUT": str(REQUEST_TIMEOUT),
        "FMG_TOOL_MODE": "full",
        "MASKING_ENABLED": "false",
        **extra,
    }


class _HttpServer:
    def __init__(self, stub: _FortiManagerStub, *, token: bool) -> None:
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.bearer = secrets.token_urlsafe(16)
        env = _server_env(
            stub,
            token=token,
            MCP_SERVER_MODE="http",
            MCP_SERVER_HOST="127.0.0.1",
            MCP_SERVER_PORT=str(self.port),
            MCP_AUTH_TOKEN=self.bearer,
        )
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "fortimanager_mcp"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def wait_connected(self, timeout: float = 15) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            assert self.proc.poll() is None, "server exited during startup"
            try:
                with urllib.request.urlopen(f"{self.base}/health", timeout=1) as r:
                    if json.load(r)["fortimanager_connected"]:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        pytest.fail("server never reported fortimanager_connected")

    def stop(self) -> float:
        """SIGTERM, then the seconds until the process has exited."""
        started = time.monotonic()
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(timeout=6 * REQUEST_TIMEOUT)
        return time.monotonic() - started

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


async def _lock_adom(server: _HttpServer, adom: str) -> None:
    import httpx2
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    headers = {"Authorization": f"Bearer {server.bearer}"}
    async with httpx2.AsyncClient(headers=headers, timeout=30) as http:
        async with streamable_http_client(f"{server.base}/mcp", http_client=http) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool("lock_adom", {"adom": adom})
    assert not result.is_error, result


async def _stop_with_a_listen_stream(server: _HttpServer) -> float:
    """SIGTERM while a client holds a 2026-07-28 ``subscriptions/listen``
    stream open, as real MCP clients do; the seconds until the exit."""
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    ready = asyncio.Event()

    async def hold() -> None:
        headers = {"Authorization": f"Bearer {server.bearer}"}
        http = httpx2.AsyncClient(headers=headers, timeout=None)
        transport = streamable_http_client(f"{server.base}/mcp", http_client=http)
        try:
            async with Client(transport, mode="2026-07-28") as client:
                async with client.listen(tools_list_changed=True) as stream:
                    ready.set()
                    async for _ in stream:
                        pass
        finally:
            ready.set()  # the stream ending early fails the assertion below

    holder = asyncio.create_task(hold())
    try:
        await asyncio.wait_for(ready.wait(), 15)
        assert not holder.done(), "the listen stream ended before the stop"
        await asyncio.sleep(0.5)
        return await asyncio.to_thread(server.stop)
    finally:
        holder.cancel()
        with contextlib.suppress(BaseException):
            await holder


class TestHttpStop:
    def test_token_mode_does_not_wait_for_a_logout(self, fmg_stub: _FortiManagerStub) -> None:
        server = _HttpServer(fmg_stub, token=True)
        try:
            server.wait_connected()
            fmg_stub.silent.set()
            elapsed = server.stop()
        finally:
            server.kill()
        assert elapsed < MARGIN + 1, f"stop took {elapsed:.1f}s"

    def test_session_logout_is_capped(self, fmg_stub: _FortiManagerStub) -> None:
        server = _HttpServer(fmg_stub, token=False)
        try:
            server.wait_connected()
            fmg_stub.silent.set()
            elapsed = server.stop()
        finally:
            server.kill()
        # The logout waits out its cap: the stub never answers it.
        assert elapsed < LOGOUT + MARGIN, f"stop took {elapsed:.1f}s"

    def test_a_held_adom_lock_is_released_within_the_budget(
        self, fmg_stub: _FortiManagerStub
    ) -> None:
        server = _HttpServer(fmg_stub, token=True)
        try:
            server.wait_connected()
            asyncio.run(_lock_adom(server, "root"))
            assert "/dvmdb/adom/root/workspace/lock" in fmg_stub.urls
            fmg_stub.silent.set()
            elapsed = server.stop()
        finally:
            server.kill()
        # One unlock, which the stub never answers, then no logout.
        assert elapsed < BUDGET + MARGIN, f"stop took {elapsed:.1f}s"

    def test_the_worst_case_fits_dockers_stop_window(self, fmg_stub: _FortiManagerStub) -> None:
        """Everything that adds to a stop at once: a client stream held open,
        username/password, two ADOMs locked, FortiManager silent."""
        server = _HttpServer(fmg_stub, token=False)
        try:
            server.wait_connected()
            for adom in ("root", "branch"):
                asyncio.run(_lock_adom(server, adom))
            fmg_stub.silent.set()
            elapsed = asyncio.run(_stop_with_a_listen_stream(server))
        finally:
            server.kill()
        assert elapsed < GRACEFUL_SHUTDOWN_TIMEOUT + BUDGET + MARGIN, f"stop took {elapsed:.1f}s"
        assert elapsed < DOCKER_STOP, f"stop took {elapsed:.1f}s"


class TestStdioStop:
    def test_token_mode_does_not_wait_for_a_logout(self, fmg_stub: _FortiManagerStub) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-m", "fortimanager_mcp"],
            env=_server_env(fmg_stub, token=True, MCP_SERVER_MODE="stdio"),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # The token probe is the last request of the connect.
            fmg_stub.wait_for("/sys/status")
            time.sleep(0.2)
            fmg_stub.silent.set()
            started = time.monotonic()
            assert proc.stdin is not None
            proc.stdin.close()
            proc.wait(timeout=3 * REQUEST_TIMEOUT)
            elapsed = time.monotonic() - started
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        assert elapsed < MARGIN + 1, f"stop took {elapsed:.1f}s"
