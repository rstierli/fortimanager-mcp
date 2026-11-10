"""Tests for FortiManager API client."""

from collections.abc import Awaitable, Callable
from http.client import RemoteDisconnected
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from pyFMG.fortimgr import FMGBaseException, FMGConnectionError
from urllib3.exceptions import (
    ConnectTimeoutError,
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
)

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils.errors import (
    APIError,
    ConnectionError,
    FortiManagerMCPError,
    parse_fmg_error,
)


class TestClientInitialization:
    """Test client initialization."""

    def test_init_with_api_token(self) -> None:
        """Test initialization with API token."""
        client = FortiManagerClient(
            host="test-fmg.example.com",
            api_token="test-token",
        )
        assert client.host == "test-fmg.example.com"
        assert client.api_token == "test-token"
        assert not client.is_connected

    def test_init_with_credentials(self) -> None:
        """Test initialization with username/password."""
        client = FortiManagerClient(
            host="https://test-fmg.example.com/",
            username="admin",
            password="password",
        )
        # Should strip protocol and trailing slash
        assert client.host == "test-fmg.example.com"
        assert client.username == "admin"
        assert client.password == "password"

    def test_init_default_values(self) -> None:
        """Test default configuration values."""
        client = FortiManagerClient(host="test-fmg.example.com")
        assert client.verify_ssl is True
        assert client.timeout == 30
        assert client.max_retries == FortiManagerClient._TRANSIENT_RETRIES == 2


class TestClientConnection:
    """Test client connection methods."""

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, mock_client: FortiManagerClient) -> None:
        """Test connecting when already connected logs warning."""
        # Client is already connected via fixture
        assert mock_client.is_connected
        # Calling connect again should not raise
        await mock_client.connect()
        assert mock_client.is_connected

    @pytest.mark.asyncio
    async def test_disconnect(self, mock_client: FortiManagerClient) -> None:
        """Test disconnection."""
        assert mock_client.is_connected
        await mock_client.disconnect()
        assert not mock_client.is_connected

    @pytest.mark.asyncio
    async def test_ensure_connected_raises_when_disconnected(
        self, mock_client_disconnected: FortiManagerClient
    ) -> None:
        """Test that operations fail when disconnected."""
        with pytest.raises(ConnectionError):
            mock_client_disconnected._ensure_connected()


class TestVerifySSLWarning:
    """`FORTIMANAGER_VERIFY_SSL=false` must surface a visible warning at connect
    time so an operator running insecure cannot do so silently.
    """

    @pytest.mark.asyncio
    async def test_warns_when_verify_ssl_disabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Connect with verify_ssl=False must emit a clear logger.warning."""
        # Stub the FortiManager constructor so connect() doesn't try the network.
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0, "message": "OK"}})
        # Token-auth connect() probes /sys/status to confirm reachability.
        stub.get.return_value = (0, {"status": {"code": 0}})
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        client = FortiManagerClient(host="test-fmg.example.com", api_token="t", verify_ssl=False)
        # Skip version detection (it calls .get on the stub) — not what we're testing.
        monkeypatch.setattr(FortiManagerClient, "_detect_version", lambda self: None)

        caplog.clear()
        with caplog.at_level("WARNING", logger="fortimanager_mcp.api.client"):
            await client.connect()

        msgs = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any("FORTIMANAGER_VERIFY_SSL=false" in m for m in msgs), (
            f"expected verify_ssl warning, got: {msgs}"
        )
        # Names the affected host so an operator can identify which connection.
        assert any("test-fmg.example.com" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_no_warning_when_verify_ssl_enabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Default verify_ssl=True path must NOT emit the verify_ssl warning."""
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0, "message": "OK"}})
        # Token-auth connect() probes /sys/status to confirm reachability.
        stub.get.return_value = (0, {"status": {"code": 0}})
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)
        monkeypatch.setattr(FortiManagerClient, "_detect_version", lambda self: None)

        client = FortiManagerClient(host="test-fmg.example.com", api_token="t", verify_ssl=True)

        caplog.clear()
        with caplog.at_level("WARNING", logger="fortimanager_mcp.api.client"):
            await client.connect()

        msgs = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert not any("FORTIMANAGER_VERIFY_SSL=false" in m for m in msgs), (
            f"verify_ssl warning leaked on the secure path: {msgs}"
        )


class TestEnsureConnectedReconnectOnce:
    """`ensure_connected()` connects a client that is not connected; with
    `connect_on_demand` (the server's client) every request runs it first.
    Reconnect is serialized via `_force_reconnect()` so concurrent
    dropped-session callers don't race.
    """

    @pytest.mark.asyncio
    async def test_ensure_connected_noop_when_connected(
        self, mock_client: FortiManagerClient
    ) -> None:
        """When already connected, ensure_connected() returns without action."""
        assert mock_client.is_connected
        gen_before = mock_client._reconnect_generation
        await mock_client.ensure_connected()
        assert mock_client.is_connected
        assert mock_client._reconnect_generation == gen_before

    @pytest.mark.asyncio
    async def test_ensure_connected_reconnects_when_disconnected(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the session has dropped, ensure_connected() calls connect()."""
        calls = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")
            self_._connected = True
            self_._fmg = MagicMock()
            self_._ever_connected = True

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        assert not mock_client_disconnected.is_connected
        await mock_client_disconnected.ensure_connected()
        assert mock_client_disconnected.is_connected
        assert calls == ["connect"]

    @pytest.mark.asyncio
    async def test_concurrent_callers_share_one_failed_attempt(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Callers queued behind a failed connect get its error instead of
        each waiting out another connect timeout of their own."""
        import asyncio

        calls: list[str] = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")
            await asyncio.sleep(0)
            raise ConnectionError("Failed to connect to FortiManager: timed out")

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        results = await asyncio.gather(
            mock_client_disconnected.ensure_connected(),
            mock_client_disconnected.ensure_connected(),
            mock_client_disconnected.ensure_connected(),
            return_exceptions=True,
        )
        assert calls == ["connect"]
        assert all(isinstance(r, ConnectionError) for r in results)

    @pytest.mark.asyncio
    async def test_call_after_a_failed_attempt_tries_again(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed attempt is not cached: the next call connects anew, so
        the client recovers once FortiManager is reachable."""
        calls: list[str] = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")
            if len(calls) == 1:
                raise ConnectionError("Failed to connect to FortiManager: timed out")
            self_._connected = True
            self_._fmg = MagicMock()
            self_._ever_connected = True

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        with pytest.raises(ConnectionError):
            await mock_client_disconnected.ensure_connected()
        await mock_client_disconnected.ensure_connected()
        assert mock_client_disconnected.is_connected
        assert calls == ["connect", "connect"]

    @pytest.mark.asyncio
    async def test_caller_behind_a_cancelled_attempt_connects_itself(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A cancelled attempt has no outcome to share, not even an older
        failure: the caller waiting behind it makes its own attempt."""
        import asyncio

        calls: list[str] = []
        started = asyncio.Event()

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")
            if len(calls) == 1:
                raise ConnectionError("Failed to connect to FortiManager: timed out")
            if len(calls) == 2:
                started.set()
                await asyncio.Event().wait()  # hangs until cancelled
            self_._connected = True
            self_._fmg = MagicMock()
            self_._ever_connected = True

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        with pytest.raises(ConnectionError):
            await mock_client_disconnected.ensure_connected()

        first = asyncio.create_task(mock_client_disconnected.ensure_connected())
        await started.wait()
        second = asyncio.create_task(mock_client_disconnected.ensure_connected())
        await asyncio.sleep(0)
        first.cancel()
        await second
        assert first.cancelled()
        assert mock_client_disconnected.is_connected
        assert calls == ["connect", "connect", "connect"]

    def test_is_transient_error_oserror(self, mock_client: FortiManagerClient) -> None:
        """OSError (network problems) is transient."""
        assert mock_client._is_transient_error(OSError("connection reset"), verb="get") is True

    def test_is_transient_error_known_codes(self, mock_client: FortiManagerClient) -> None:
        """Only FMG code -1 (internal error) is transient."""

        class _CodedExc(Exception):
            def __init__(self, code: int) -> None:
                super().__init__("err")
                self.code = code

        assert mock_client._is_transient_error(_CodedExc(-1), verb="get") is True
        # -11 is permission/stale-session: owned by the reconnect path, not
        # transient retry (verified live against FMG 7.6.7).
        assert mock_client._is_transient_error(_CodedExc(-11), verb="get") is False
        # -3 (not found), -4, -8 (invalid parameter) are NOT transient.
        assert mock_client._is_transient_error(_CodedExc(-3), verb="get") is False
        assert mock_client._is_transient_error(_CodedExc(-4), verb="get") is False
        assert mock_client._is_transient_error(_CodedExc(-8), verb="get") is False

    def test_is_session_error_auth(self, mock_client: FortiManagerClient) -> None:
        """AuthenticationError always indicates a dropped session."""
        from fortimanager_mcp.utils.errors import AuthenticationError

        assert mock_client._is_session_error(AuthenticationError("stale")) is True

    def test_is_session_error_not_connected_after_ever_connected(
        self, mock_client: FortiManagerClient
    ) -> None:
        """Raw ConnectionError("Not connected. ...") after a successful initial
        login means the local session was torn down mid-request -- recoverable.
        """
        from fortimanager_mcp.utils.errors import ConnectionError as FMGConnError

        mock_client._ever_connected = True
        assert (
            mock_client._is_session_error(FMGConnError("Not connected. Call connect() first."))
            is True
        )

    def test_is_session_error_not_connected_when_never_connected(
        self, mock_client_disconnected: FortiManagerClient
    ) -> None:
        """Same not-connected error from a NEVER-connected client must surface
        as-is, not silently trigger a first-time login on an arbitrary API call.
        """
        from fortimanager_mcp.utils.errors import ConnectionError as FMGConnError

        mock_client_disconnected._ever_connected = False
        assert (
            mock_client_disconnected._is_session_error(
                FMGConnError("Not connected. Call connect() first.")
            )
            is False
        )

    def test_is_session_error_reconnectable_codes(self, mock_client: FortiManagerClient) -> None:
        """FMG -11 means stale session (verified live 7.6.7): revive once.

        -2 means "Object already exists" — a duplicate create must NOT
        trigger a re-login (it previously did).
        """

        class _CodedExc(Exception):
            def __init__(self, code: int) -> None:
                super().__init__("err")
                self.code = code

        assert mock_client._is_session_error(_CodedExc(-11)) is True
        # Other coded errors are NOT session errors.
        assert mock_client._is_session_error(_CodedExc(-2)) is False
        assert mock_client._is_session_error(_CodedExc(-3)) is False

    @pytest.mark.asyncio
    async def test_force_reconnect_serializes_concurrent_callers(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two concurrent _force_reconnect() callers result in EXACTLY ONE
        connect() -- the second observes the bumped generation and bails out.
        """
        import asyncio

        calls: list[str] = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")
            await asyncio.sleep(0)
            self_._connected = True
            self_._fmg = MagicMock()
            self_._ever_connected = True

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        gen_before = mock_client_disconnected._reconnect_generation
        await asyncio.gather(
            mock_client_disconnected._force_reconnect(),
            mock_client_disconnected._force_reconnect(),
        )
        assert calls == ["connect"]
        assert mock_client_disconnected._reconnect_generation == gen_before + 1


class TestExecuteResilient:
    """`_execute_resilient` wraps an async factory with reconnect-once +
    bounded transient-retry. Validated by injecting a synthetic factory and
    asserting on attempt count + retry/reconnect calls.
    """

    @pytest.mark.asyncio
    async def test_returns_immediately_on_success(self, mock_client: FortiManagerClient) -> None:
        """A factory that succeeds on first attempt is invoked exactly once."""
        calls = []

        async def _factory() -> str:
            calls.append("call")
            return "ok"

        result = await mock_client._execute_resilient(_factory, verb="get")
        assert result == "ok"
        assert calls == ["call"]

    @pytest.mark.asyncio
    async def test_retries_transient_then_succeeds(self, mock_client: FortiManagerClient) -> None:
        """A transient (code -1) failure is retried; second attempt succeeds.
        Backoff is short-circuited by an injected sleeper.
        """

        class _CodedExc(Exception):
            def __init__(self, code: int) -> None:
                super().__init__("transient")
                self.code = code

        attempts = []
        sleeps: list[float] = []

        async def _factory() -> str:
            attempts.append("call")
            if len(attempts) == 1:
                raise _CodedExc(-1)
            return "ok"

        async def _no_sleep(d: float) -> None:
            sleeps.append(d)

        result = await mock_client._execute_resilient(_factory, verb="get", sleep=_no_sleep)
        assert result == "ok"
        assert len(attempts) == 2
        # First retry uses _TRANSIENT_BACKOFF_BASE * 2^0 = 0.5
        assert sleeps == [0.5]

    @pytest.mark.asyncio
    async def test_bounded_retries_then_raises_with_retries_attempted(
        self, mock_client: FortiManagerClient
    ) -> None:
        """All transient retries exhausted: original exc raised with
        ``retries_attempted`` annotation matching the actual retry count.
        """

        class _CodedExc(Exception):
            def __init__(self, code: int) -> None:
                super().__init__("transient")
                self.code = code

        attempts = []
        sleeps: list[float] = []

        async def _factory() -> None:
            attempts.append("call")
            raise _CodedExc(-1)

        async def _no_sleep(d: float) -> None:
            sleeps.append(d)

        with pytest.raises(_CodedExc) as exc_info:
            await mock_client._execute_resilient(_factory, verb="get", sleep=_no_sleep)

        # 1 initial + _TRANSIENT_RETRIES = 1 + 2 = 3 attempts
        assert len(attempts) == 1 + mock_client._TRANSIENT_RETRIES
        # retries_attempted equals number of retries actually performed
        assert exc_info.value.retries_attempted == mock_client._TRANSIENT_RETRIES
        # exponential backoff: 0.5, 1.0 (for _TRANSIENT_RETRIES=2)
        assert sleeps == [0.5, 1.0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("max_retries", [0, 4])
    async def test_max_retries_sets_the_transient_retry_count(self, max_retries: int) -> None:
        """FORTIMANAGER_MAX_RETRIES reaches the client as max_retries and
        bounds the transient retries; it was read and then never used."""
        client = FortiManagerClient(host="test-fmg.example.com", max_retries=max_retries)
        attempts = []

        class _CodedExc(Exception):
            code = -1

        async def _factory() -> None:
            attempts.append("call")
            raise _CodedExc("transient")

        async def _no_sleep(_: float) -> None:
            return None

        with pytest.raises(_CodedExc) as exc_info:
            await client._execute_resilient(_factory, verb="get", sleep=_no_sleep)
        assert len(attempts) == 1 + max_retries
        assert exc_info.value.retries_attempted == max_retries

    @pytest.mark.asyncio
    async def test_does_not_retry_validation_error(self, mock_client: FortiManagerClient) -> None:
        """A validation error (code -5) is NOT transient -- surface immediately."""

        class _CodedExc(Exception):
            def __init__(self, code: int) -> None:
                super().__init__("invalid")
                self.code = code

        attempts = []

        async def _factory() -> None:
            attempts.append("call")
            raise _CodedExc(-5)

        with pytest.raises(_CodedExc):
            await mock_client._execute_resilient(_factory, verb="get")

        assert attempts == ["call"]

    @pytest.mark.asyncio
    async def test_session_error_triggers_reconnect_then_retry(
        self,
        mock_client: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A session-gone error reconnects exactly once and retries the factory.
        Second attempt succeeds; only ONE _force_reconnect call.
        """
        from fortimanager_mcp.utils.errors import AuthenticationError

        reconnects = []

        async def fake_force_reconnect(self_: FortiManagerClient) -> None:
            reconnects.append("reconnect")

        monkeypatch.setattr(FortiManagerClient, "_force_reconnect", fake_force_reconnect)

        attempts: list[str] = []

        async def _factory() -> str:
            attempts.append("call")
            if len(attempts) == 1:
                raise AuthenticationError("session invalid")
            return "ok"

        result = await mock_client._execute_resilient(_factory, verb="get")
        assert result == "ok"
        assert reconnects == ["reconnect"]
        assert len(attempts) == 2

    @pytest.mark.asyncio
    async def test_repeated_session_error_does_not_loop(
        self,
        mock_client: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If the reconnect succeeds but the next attempt ALSO raises a session
        error, we do NOT reconnect again -- we surface the error. Bounded.
        """
        from fortimanager_mcp.utils.errors import AuthenticationError

        reconnects = []

        async def fake_force_reconnect(self_: FortiManagerClient) -> None:
            reconnects.append("reconnect")

        monkeypatch.setattr(FortiManagerClient, "_force_reconnect", fake_force_reconnect)

        attempts: list[str] = []

        async def _factory() -> None:
            attempts.append("call")
            raise AuthenticationError("session invalid")

        with pytest.raises(AuthenticationError):
            await mock_client._execute_resilient(_factory, verb="get")

        # Exactly ONE reconnect happened. Initial attempt + one retry after
        # the reconnect = 2 attempts. The second AuthenticationError is
        # surfaced (no second reconnect).
        assert reconnects == ["reconnect"]
        assert len(attempts) == 2

    @pytest.mark.asyncio
    async def test_never_connected_client_does_not_connect_by_default(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without connect_on_demand a direct API call on a never-connected
        client still raises "Not connected" instead of logging in."""
        calls: list[str] = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")

        async def _factory() -> None:
            mock_client_disconnected._ensure_connected()

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        with pytest.raises(ConnectionError, match="Not connected"):
            await mock_client_disconnected._execute_resilient(_factory, verb="get")
        assert calls == []

    @pytest.mark.asyncio
    async def test_connect_on_demand_connects_a_never_connected_client_first(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The server's client, whose startup connect failed, connects on its
        next call instead of answering "Not connected" until a restart."""
        mock_client_disconnected.connect_on_demand = True
        calls: list[str] = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")
            self_._connected = True
            self_._fmg = MagicMock()
            self_._ever_connected = True

        async def _factory() -> str:
            calls.append("call")
            return "ok"

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        assert await mock_client_disconnected._execute_resilient(_factory, verb="get") == "ok"
        assert calls == ["connect", "call"]

    @pytest.mark.asyncio
    async def test_failed_connect_on_demand_skips_the_request(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One connect attempt per call; the request itself never runs."""
        mock_client_disconnected.connect_on_demand = True
        calls: list[str] = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            calls.append("connect")
            raise ConnectionError("Failed to connect to FortiManager: timed out")

        async def _factory() -> str:
            calls.append("call")
            return "ok"

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        with pytest.raises(ConnectionError):
            await mock_client_disconnected._execute_resilient(_factory, verb="get")
        assert calls == ["connect"]


class TestClientOperations:
    """Test client API operations."""

    @pytest.mark.asyncio
    async def test_get_system_status(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test getting system status."""
        result = await mock_client.get_system_status()
        assert result["Version"] == "v7.6.5"
        assert result["Hostname"] == "FMG-TEST"

    @pytest.mark.asyncio
    async def test_list_adoms(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing ADOMs."""
        result = await mock_client.list_adoms()
        assert len(result) == 2
        assert result[0]["name"] == "root"
        assert result[1]["name"] == "demo"

    @pytest.mark.asyncio
    async def test_list_devices(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing devices."""
        result = await mock_client.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"

    @pytest.mark.asyncio
    async def test_list_packages(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing packages."""
        result = await mock_client.list_packages(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "default"

    @pytest.mark.asyncio
    async def test_install_package_returns_task(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test package installation returns task ID."""
        result = await mock_client.install_package(
            adom="root",
            pkg="default",
            scope=[{"name": "FGT-01", "vdom": "root"}],
        )
        assert "task" in result
        assert result["task"] == 123


class TestErrorHandling:
    """Test error handling."""

    def test_parse_fmg_error_known_code(self) -> None:
        """Test parsing known error codes (-3 = not found, verified live)."""
        from fortimanager_mcp.utils.errors import ResourceNotFoundError

        error = parse_fmg_error(-3, "Not found", "GET /test")
        assert isinstance(error, ResourceNotFoundError)
        assert "Object does not exist" in str(error)

    def test_parse_fmg_error_unknown_code(self) -> None:
        """Test parsing unknown error codes."""
        error = parse_fmg_error(-999, "Unknown error", "GET /test")
        assert isinstance(error, APIError)
        assert "Unknown error" in str(error)

    @pytest.mark.asyncio
    async def test_handle_error_response(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test handling error responses from API."""
        mock_fmg_instance.get.return_value = (-3, {"status": {"message": "Not found"}})

        with pytest.raises(FortiManagerMCPError) as exc_info:
            await mock_client.get("/test/url")

        assert "Object does not exist" in str(exc_info.value)


class TestScriptTargetMapping:
    """Regression tests for GitHub issue #3.

    The FMG 7.6+ /pm/config/.../script endpoint expects an integer `target`
    and silently coerces unknown values (including legacy strings) to 0
    (device_database). The client must map strings -> ints when talking to
    the new endpoint, and leave strings untouched on the legacy /dvmdb
    endpoint. Responses go the other way to keep the public surface
    string-typed.
    """

    @pytest.mark.asyncio
    async def test_create_script_maps_target_on_new_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.6+: target string must be converted to integer."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, {"Version": "v7.6.5"})
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={
                "name": "reboot-fgt",
                "content": "execute reboot",
                "type": "cli",
                "target": "remote_device",
            },
        )

        mock_fmg_instance.add.assert_called_once()
        call_args = mock_fmg_instance.add.call_args
        url = call_args.args[0]
        body = call_args.kwargs["data"]
        assert url == "/pm/config/adom/root/obj/fmg/script"
        assert body["target"] == 1, "remote_device must map to 1 on FMG 7.6+"
        assert isinstance(body["target"], int)

    @pytest.mark.asyncio
    async def test_create_script_maps_all_known_targets(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Each documented target string maps to the expected integer."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        expected = {
            "device_database": 0,
            "remote_device": 1,
            "adom_database": 2,
        }

        for target_str, target_int in expected.items():
            mock_fmg_instance.add.reset_mock()
            await mock_client.create_script(
                adom="root",
                script={"name": f"s-{target_str}", "content": "noop", "target": target_str},
            )
            body = mock_fmg_instance.add.call_args.kwargs["data"]
            assert body["target"] == target_int, (
                f"{target_str} should map to {target_int}, got {body['target']!r}"
            )

    @pytest.mark.asyncio
    async def test_create_script_passes_target_through_on_legacy_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.0-7.4: legacy endpoint accepts strings, must not be remapped."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={
                "name": "reboot-fgt",
                "content": "execute reboot",
                "type": "cli",
                "target": "remote_device",
            },
        )

        call_args = mock_fmg_instance.add.call_args
        url = call_args.args[0]
        body = call_args.kwargs["data"]
        assert url == "/dvmdb/adom/root/script"
        assert body["target"] == "remote_device"
        assert isinstance(body["target"], str)

    @pytest.mark.asyncio
    async def test_create_script_unknown_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Unknown target strings are not silently rewritten to 0."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={"name": "weird", "content": "noop", "target": "not_a_real_target"},
        )

        body = mock_fmg_instance.add.call_args.kwargs["data"]
        assert body["target"] == "not_a_real_target"

    @pytest.mark.asyncio
    async def test_create_script_integer_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A caller passing an int already (advanced use) is left alone."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={"name": "preformatted", "content": "noop", "target": 2},
        )

        body = mock_fmg_instance.add.call_args.kwargs["data"]
        assert body["target"] == 2

    @pytest.mark.asyncio
    async def test_create_script_no_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Scripts without a target field are unaffected."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={"name": "no-target", "content": "noop"},
        )

        body = mock_fmg_instance.add.call_args.kwargs["data"]
        assert "target" not in body

    @pytest.mark.asyncio
    async def test_update_script_maps_target_on_new_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """update_script must also apply the mapping on FMG 7.6+."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.update.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.update_script(
            adom="root",
            name="existing",
            data={"target": "adom_database", "desc": "updated"},
        )

        call_args = mock_fmg_instance.update.call_args
        url = call_args.args[0]
        body = call_args.kwargs["data"]
        assert url == "/pm/config/adom/root/obj/fmg/script/existing"
        assert body["target"] == 2
        assert body["desc"] == "updated"

    @pytest.mark.asyncio
    async def test_update_script_passes_target_through_on_legacy_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """update_script leaves string targets alone on FMG 7.0-7.4."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.update.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.update_script(
            adom="root",
            name="existing",
            data={"target": "remote_device"},
        )

        body = mock_fmg_instance.update.call_args.kwargs["data"]
        assert body["target"] == "remote_device"

    @pytest.mark.asyncio
    async def test_list_scripts_reverse_maps_int_target(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Responses from FMG 7.6+ contain int targets; callers see strings."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (
            0,
            [
                {"name": "s1", "target": 0},
                {"name": "s2", "target": 1},
                {"name": "s3", "target": 2},
            ],
        )

        scripts = await mock_client.list_scripts(adom="root")
        targets = {s["name"]: s["target"] for s in scripts}
        assert targets == {
            "s1": "device_database",
            "s2": "remote_device",
            "s3": "adom_database",
        }

    @pytest.mark.asyncio
    async def test_list_scripts_leaves_string_targets_alone(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Legacy responses already contain string targets; pass them through."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "s1", "target": "device_database"}],
        )

        scripts = await mock_client.list_scripts(adom="root")
        assert scripts[0]["target"] == "device_database"

    @pytest.mark.asyncio
    async def test_get_script_reverse_maps_int_target(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """get_script reverses the mapping on FMG 7.6+ for the single result."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, {"name": "s1", "target": 2})

        script = await mock_client.get_script(adom="root", name="s1")
        assert script["target"] == "adom_database"

    def test_uses_new_script_endpoint_predicate(self) -> None:
        """The version predicate matches the script endpoint branch exactly."""
        client = FortiManagerClient(host="test.example.com", api_token="t")
        cases: list[tuple[Any, bool]] = [
            (None, False),
            ((7, 0, 0), False),
            ((7, 4, 5), False),
            ((7, 5, 99), False),
            ((7, 6, 0), True),
            ((7, 6, 5), True),
            ((8, 0, 0), True),
        ]
        for version, expected in cases:
            client._fmg_version = version
            assert client._uses_new_script_endpoint() is expected, (
                f"version {version} should yield {expected}"
            )

    @pytest.mark.asyncio
    async def test_list_scripts_maps_all_target_filter_values(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.6+: each documented target string maps to int in filter."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        expected = {"device_database": 0, "remote_device": 1, "adom_database": 2}
        for target_str, target_int in expected.items():
            mock_fmg_instance.get.reset_mock()
            await mock_client.list_scripts(
                adom="root",
                filter=[["target", "==", target_str]],
            )
            params = mock_fmg_instance.get.call_args.kwargs
            assert params["filter"] == [["target", "==", target_int]], (
                f"filter target=={target_str} should send int {target_int}, "
                f"got {params['filter']!r}"
            )

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_passes_through_on_legacy_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.0-7.4: legacy endpoint stores strings; filter unchanged."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "==", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "==", "remote_device"]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_with_compound_conditions(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Target mapping must coexist with other conditions in the filter."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[
                ["type", "==", "cli"],
                ["target", "==", "remote_device"],
            ],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [
            ["type", "==", "cli"],
            ["target", "==", 1],
        ]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_unknown_value_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Unknown target values are left for FMG to reject explicitly."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "==", "not_a_real_target"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "==", "not_a_real_target"]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_non_eq_operator_mapped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Non-`==` operators (e.g. `!=`) on target are still mapped."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "!=", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "!=", 1]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_int_value_unchanged(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A caller passing an int already (advanced use) is left alone."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "==", 2]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "==", 2]]

    @pytest.mark.asyncio
    async def test_list_scripts_no_filter_unchanged(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Calling without a filter must not forward one."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(adom="root")

        params = mock_fmg_instance.get.call_args.kwargs
        assert "filter" not in params

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_mapped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """`["target", "in", v1, v2, ...]` maps each known string value."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "in", "device_database", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "in", 0, 1]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_not_in_operator_mapped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """`["target", "!in", ...]` is treated the same as `in`."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "!in", "remote_device", "adom_database"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "!in", 1, 2]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_mixed_values(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Unknown values inside `in` are left untouched; known ones mapped."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "in", "device_database", "not_a_real_target", 2]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "in", 0, "not_a_real_target", 2]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_legacy_passthrough(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Legacy /dvmdb endpoint stores strings — `in` filter unchanged."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "in", "device_database", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "in", "device_database", "remote_device"]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_inside_compound(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """`in` filter on target coexists with other compound conditions."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[
                ["type", "==", "cli"],
                ["target", "in", "remote_device", "adom_database"],
            ],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [
            ["type", "==", "cli"],
            ["target", "in", 1, 2],
        ]

    @pytest.mark.asyncio
    async def test_list_scripts_unknown_operator_on_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """3-element list with an unrecognized operator is left alone."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        # "weird_op" is not a known FMG comparison operator
        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "weird_op", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "weird_op", "remote_device"]]


class TestVersionDetection:
    """A failed version probe must not pin the legacy script endpoint.

    The version picks the script endpoint (7.6+ uses /pm/config, older uses
    /dvmdb). A probe that fails because FortiManager cannot be reached raises:
    the real request would fail the same way, and a script write must not go
    to a guessed endpoint. Any other failure says nothing about the version,
    so that call takes the legacy endpoint and the next call probes again.
    """

    @pytest.mark.asyncio
    async def test_failed_probe_is_retried_by_the_next_script_call(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """First probe fails, second succeeds: the second call reaches the 7.6+ endpoint."""
        status_replies: list[Any] = [
            RuntimeError("FortiManager unreachable"),
            (0, {"Version": "v7.6.5-build3653 251215 (GA.M)"}),
        ]

        def fake_get(url: str, **kwargs: Any) -> tuple[int, Any]:
            if url == "/sys/status":
                reply = status_replies.pop(0)
                if isinstance(reply, Exception):
                    raise reply
                return reply
            return (0, [])

        mock_fmg_instance.get.side_effect = fake_get

        await mock_client.list_scripts(adom="root")
        await mock_client.list_scripts(adom="root")

        script_urls = [
            c.args[0] for c in mock_fmg_instance.get.call_args_list if c.args[0] != "/sys/status"
        ]
        assert script_urls == [
            "/dvmdb/adom/root/script",
            "/pm/config/adom/root/obj/fmg/script",
        ]
        assert mock_client.fmg_version == (7, 6, 5)

    @pytest.mark.asyncio
    async def test_unreachable_fortimanager_raises_from_the_probe(
        self,
        mock_client_disconnected: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The on-demand connect fails: one connect wait per script call, not two."""
        mock_client_disconnected.connect_on_demand = True
        connects: list[str] = []

        async def fake_connect(self_: FortiManagerClient) -> None:
            connects.append("connect")
            raise ConnectionError("Failed to connect to FortiManager: timed out")

        monkeypatch.setattr(FortiManagerClient, "connect", fake_connect)
        with pytest.raises(ConnectionError):
            await mock_client_disconnected.list_scripts(adom="root")
        assert connects == ["connect"]
        assert mock_client_disconnected.fmg_version is None

    @pytest.mark.asyncio
    async def test_dropped_session_raises_from_the_probe(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The session dropped: the transient error is raised and no script
        request goes to a guessed endpoint."""
        monkeypatch.setattr(mock_client, "_TRANSIENT_BACKOFF_BASE", 0.0)
        mock_fmg_instance.get.side_effect = OSError("connection reset")

        with pytest.raises(OSError, match="connection reset"):
            await mock_client.list_scripts(adom="root")

        urls = [c.args[0] for c in mock_fmg_instance.get.call_args_list]
        assert urls == ["/sys/status"] * (1 + mock_client._TRANSIENT_RETRIES)
        assert mock_client.fmg_version is None


class TestMoveResilience:
    """`move()` must get the same reconnect-once + retry treatment as the
    other verbs (it previously bypassed `_execute_resilient` entirely)."""

    @pytest.mark.asyncio
    async def test_move_reconnects_on_stale_session(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A stale-session (-11) response on move triggers one reconnect and a retry."""
        reconnects: list[str] = []

        async def fake_force_reconnect(self_: FortiManagerClient) -> None:
            reconnects.append("reconnect")

        monkeypatch.setattr(FortiManagerClient, "_force_reconnect", fake_force_reconnect)

        mock_fmg_instance.move.side_effect = [
            (-11, {"status": {"message": "No permission for the resource"}}),
            (0, {"status": {"message": "OK"}}),
        ]

        result = await mock_client.move(
            "/pm/config/adom/root/pkg/default/firewall/policy/10",
            option="before",
            target="5",
        )

        assert result == {"status": {"message": "OK"}}
        assert reconnects == ["reconnect"]
        assert mock_fmg_instance.move.call_count == 2

    @pytest.mark.asyncio
    async def test_move_passes_option_target_as_positional_dict(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Option/target must merge at the datagram top level (positional dict),
        not inside 'data' (kwargs)."""
        mock_fmg_instance.move.return_value = (0, {})

        await mock_client.move("/pm/config/x", option="after", target="7")

        args, kwargs = mock_fmg_instance.move.call_args
        assert args == ("/pm/config/x", {"option": "after", "target": "7"})
        assert kwargs == {}


class TestTokenAuthLivenessProbe:
    """API-token login is a no-op network-wise in pyfmg, so connect() probes
    /sys/status once to confirm the FMG is actually reachable before reporting
    connected -- otherwise /health would show connected against a dead FMG."""

    @pytest.mark.asyncio
    async def test_token_connect_probes_sys_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0}})
        stub.get.return_value = (0, {"status": {"code": 0}})
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        await client.connect()

        assert client.is_connected
        stub.get.assert_called_once()
        assert stub.get.call_args.args[0] == "/sys/status"

    @pytest.mark.asyncio
    async def test_token_connect_fails_when_probe_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unreachable FMG: the probe raises, so connect() fails instead of
        falsely reporting connected."""
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0}})
        stub.get.side_effect = OSError("connection refused")
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        with pytest.raises(ConnectionError):
            await client.connect()
        assert not client.is_connected

    @pytest.mark.asyncio
    async def test_token_connect_fails_when_probe_returns_error_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-zero status from the probe (e.g. token lacks access) also fails
        the connect rather than reporting connected."""
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0}})
        stub.get.return_value = (-11, {"status": {"message": "No permission for the resource"}})
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        with pytest.raises(ConnectionError):
            await client.connect()
        assert not client.is_connected

    @pytest.mark.asyncio
    async def test_token_connect_probe_detail_from_non_dict_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A probe failure with a non-dict body still fails closed with a
        useful message instead of crashing on the detail extraction."""
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0}})
        stub.get.return_value = (-1, "unexpected string body")
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        with pytest.raises(ConnectionError, match="unexpected string body"):
            await client.connect()
        assert not client.is_connected

    @pytest.mark.asyncio
    async def test_session_connect_does_not_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Username/password login already round-trips, so no extra probe."""
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0}})
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        client = FortiManagerClient(host="fmg.example.com", username="admin", password="pw")
        await client.connect()

        assert client.is_connected
        stub.get.assert_not_called()


class TestRunFmgCallCancellation:
    """_run_fmg_call must never let two calls touch the non-thread-safe pyfmg
    session at once, even when an outer wait_for cancels a call mid-flight."""

    @pytest.mark.asyncio
    async def test_lock_released_after_normal_call(self) -> None:
        """A completed call leaves the request lock free."""
        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        result = await client._run_fmg_call(lambda: (0, {"ok": True}))
        assert result == (0, {"ok": True})
        assert not client._request_lock.locked()

    @pytest.mark.asyncio
    async def test_cancel_hands_off_lock_until_worker_finishes(self) -> None:
        """When a call is cancelled, the lock stays held until the orphaned
        worker thread finishes, then is released."""
        import asyncio
        import threading

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        release_worker = threading.Event()
        entered = threading.Event()

        def blocking_call() -> tuple[int, dict]:
            entered.set()
            release_worker.wait(5)
            return (0, {"done": True})

        task = asyncio.ensure_future(client._run_fmg_call(blocking_call))
        await asyncio.to_thread(entered.wait, 5)

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # Cancelled caller has returned, but the worker still holds the session,
        # so the lock must remain held.
        assert client._request_lock.locked()

        # Let the orphan finish; the completion callback releases the lock.
        release_worker.set()

        async def _lock_free() -> bool:
            for _ in range(500):
                if not client._request_lock.locked():
                    return True
                await asyncio.sleep(0.01)
            return False

        assert await _lock_free()

    @pytest.mark.asyncio
    async def test_next_call_waits_for_orphaned_worker(self) -> None:
        """A follow-up call after a cancel does not start on the shared session
        until the orphaned worker releases the lock."""
        import asyncio
        import threading

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        release_worker = threading.Event()
        first_entered = threading.Event()
        second_ran = threading.Event()

        def first_call() -> tuple[int, dict]:
            first_entered.set()
            release_worker.wait(5)
            return (0, {"first": True})

        def second_call() -> tuple[int, dict]:
            second_ran.set()
            return (0, {"second": True})

        first = asyncio.ensure_future(client._run_fmg_call(first_call))
        await asyncio.to_thread(first_entered.wait, 5)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

        # Start the follow-up while the orphan is still in-flight.
        second = asyncio.ensure_future(client._run_fmg_call(second_call))
        await asyncio.sleep(0.05)
        # State-based check first: a broken handoff releases the lock, which
        # would let the second call through regardless of scheduler timing.
        assert client._request_lock.locked()
        assert not second_ran.is_set(), "second call started while session was busy"

        release_worker.set()
        assert await second == (0, {"second": True})
        assert second_ran.is_set()

    @pytest.mark.asyncio
    async def test_orphaned_failure_does_not_leak_and_releases_lock(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """If an abandoned worker call raises, the lock is still released and
        its exception is retrieved (logged at debug) so no unretrieved-exception
        warning is produced."""
        import asyncio
        import threading

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        release_worker = threading.Event()
        entered = threading.Event()

        def failing_call() -> tuple[int, dict]:
            entered.set()
            release_worker.wait(5)
            raise OSError("connection reset")

        task = asyncio.ensure_future(client._run_fmg_call(failing_call))
        await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        async def _lock_free() -> bool:
            for _ in range(500):
                if not client._request_lock.locked():
                    return True
                await asyncio.sleep(0.01)
            return False

        with caplog.at_level("DEBUG", logger="fortimanager_mcp.api.client"):
            release_worker.set()
            assert await _lock_free()

        # The completion callback must retrieve the orphan's exception; the
        # debug log is the observable proof of that retrieval.
        msgs = [r.getMessage() for r in caplog.records]
        assert any("Abandoned FortiManager call failed after cancellation" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_cancel_while_queued_leaves_holders_lock_intact(self) -> None:
        """Cancelling a call that is still WAITING for the lock must not
        release the lock the in-flight call holds -- otherwise a follow-up
        call could start on the shared session while the first is still
        using it, which is exactly the corruption the lock exists to stop."""
        import asyncio
        import threading

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        release_worker = threading.Event()
        first_entered = threading.Event()

        def first_call() -> tuple[int, dict]:
            first_entered.set()
            release_worker.wait(5)
            return (0, {"first": True})

        first = asyncio.ensure_future(client._run_fmg_call(first_call))
        await asyncio.to_thread(first_entered.wait, 5)

        # Queue a second call behind the lock, then cancel it while it waits.
        second = asyncio.ensure_future(client._run_fmg_call(lambda: (0, {"second": True})))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second

        # The queued caller never owned the lock, so the holder's lock must
        # be untouched and the first call must complete normally.
        assert client._request_lock.locked()
        release_worker.set()
        assert await first == (0, {"first": True})
        assert not client._request_lock.locked()

        # Session idle again: a fresh call runs normally.
        assert await client._run_fmg_call(lambda: (0, {"third": True})) == (0, {"third": True})

    @pytest.mark.asyncio
    async def test_failing_call_propagates_error_and_releases_lock(self) -> None:
        """A call that raises without any cancellation propagates the error
        to the caller and leaves the lock free for the next call."""

        def failing_call() -> tuple[int, dict]:
            raise OSError("connection reset")

        client = FortiManagerClient(host="fmg.example.com", api_token="t")
        with pytest.raises(OSError, match="connection reset"):
            await client._run_fmg_call(failing_call)
        assert not client._request_lock.locked()


def _connected_client(fmg: MagicMock, **kwargs: Any) -> FortiManagerClient:
    client = FortiManagerClient(host="fmg.example.com", **kwargs)
    # pyfmg's timeout is a number; a bare MagicMock attribute is not.
    if not isinstance(fmg.timeout, int | float):
        fmg.timeout = client.timeout
    client._fmg = fmg
    client._connected = True
    client._ever_connected = True
    return client


class TestShutdownIsBounded:
    """disconnect() runs on every server shutdown. Against a FortiManager that
    stopped answering, a request there waited out the full request timeout,
    and the logout of a token "session" had nothing to end anyway."""

    async def test_token_disconnect_skips_the_logout(self) -> None:
        fmg = MagicMock()
        client = _connected_client(fmg, api_token="t")

        await client.disconnect()

        fmg.logout.assert_not_called()
        fmg.sess.close.assert_called_once()
        assert client._fmg is None
        assert not client.is_connected

    async def test_session_disconnect_logs_out_on_a_capped_timeout(self) -> None:
        """Username/password has a real server session, so it still logs out,
        on pyfmg's own timeout (which bounds the request itself) capped well
        below the request timeout."""
        fmg = MagicMock()
        fmg.timeout = 30
        seen: list[float] = []
        fmg.logout.side_effect = lambda: seen.append(fmg.timeout)
        client = _connected_client(fmg, username="admin", password="pw", timeout=30)

        await client.disconnect()

        assert seen == [FortiManagerClient._LOGOUT_TIMEOUT]
        assert client._fmg is None
        assert not client.is_connected

    async def test_session_logout_keeps_a_shorter_configured_timeout(self) -> None:
        fmg = MagicMock()
        fmg.timeout = 1
        seen: list[float] = []
        fmg.logout.side_effect = lambda: seen.append(fmg.timeout)
        client = _connected_client(fmg, username="admin", password="pw", timeout=1)

        await client.disconnect()

        assert seen == [1]

    async def test_a_failed_session_logout_still_clears_the_state(self) -> None:
        fmg = MagicMock()
        fmg.logout.side_effect = OSError("read timeout")
        client = _connected_client(fmg, username="admin", password="pw")

        await client.disconnect()

        assert client._fmg is None
        assert not client.is_connected

    async def test_after_prepare_shutdown_a_request_runs_on_what_is_left(self) -> None:
        """pyfmg's timeout, which requests gets, is lowered to the rest of
        the shutdown budget before each request."""
        fmg = MagicMock()
        fmg.timeout = 30
        seen: list[float] = []

        def execute(url: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
            seen.append(fmg.timeout)
            return 0, {}

        fmg.execute.side_effect = execute
        client = _connected_client(fmg, api_token="t", timeout=30)
        client.prepare_shutdown()

        await client.unlock_adom("root")

        budget = FortiManagerClient._SHUTDOWN_IO_BUDGET
        assert len(seen) == 1
        assert budget - 1 < seen[0] <= budget

    async def test_after_prepare_shutdown_a_shorter_timeout_is_kept(self) -> None:
        fmg = MagicMock()
        fmg.timeout = 1
        seen: list[float] = []

        def execute(url: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
            seen.append(fmg.timeout)
            return 0, {}

        fmg.execute.side_effect = execute
        client = _connected_client(fmg, api_token="t", timeout=1)
        client.prepare_shutdown()

        await client.unlock_adom("root")

        assert seen == [1]

    async def test_a_request_after_the_budget_is_used_up_is_not_sent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(FortiManagerClient, "_SHUTDOWN_IO_BUDGET", 0)
        fmg = MagicMock()
        client = _connected_client(fmg, api_token="t")
        client.prepare_shutdown()

        with pytest.raises(ConnectionError, match="time for FortiManager requests is used up"):
            await client.unlock_adom("root")

        fmg.execute.assert_not_called()
        # The refusal releases the request lock like any failed call.
        assert not client._request_lock.locked()

    def test_the_budget_ends_an_unlock_before_its_wait_for(self) -> None:
        """Otherwise wait_for gives up first, and the thread it leaves running
        holds the request lock the logout then queues behind."""
        from fortimanager_mcp.utils.adom_locks import UNLOCK_TIMEOUT

        assert FortiManagerClient._SHUTDOWN_IO_BUDGET < UNLOCK_TIMEOUT

    async def test_after_prepare_shutdown_a_transient_error_is_not_retried(self) -> None:
        fmg = MagicMock()
        fmg.execute.side_effect = OSError("read timeout")
        client = _connected_client(fmg, api_token="t")
        client.prepare_shutdown()

        with pytest.raises(OSError, match="read timeout"):
            await client.unlock_adom("root")

        assert fmg.execute.call_count == 1

    async def test_after_prepare_shutdown_a_session_error_does_not_reconnect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fmg = MagicMock()
        fmg.execute.return_value = (-11, {"status": {"message": "No permission"}})
        client = _connected_client(fmg, api_token="t")
        reconnects: list[None] = []

        async def _reconnect() -> None:
            reconnects.append(None)

        monkeypatch.setattr(client, "_force_reconnect", _reconnect)
        client.prepare_shutdown()

        with pytest.raises(FortiManagerMCPError):
            await client.unlock_adom("root")

        assert reconnects == []
        assert fmg.execute.call_count == 1

    async def test_after_prepare_shutdown_no_connect_on_demand(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = FortiManagerClient(host="fmg.example.com", api_token="t", connect_on_demand=True)
        connects: list[None] = []

        async def _connect() -> None:
            connects.append(None)

        monkeypatch.setattr(client, "connect", _connect)
        client.prepare_shutdown()

        with pytest.raises(ConnectionError, match="Not connected"):
            await client.unlock_adom("root")

        assert connects == []


class TestCaBundleAndVerifyGuidance:
    """`FORTIMANAGER_CA_BUNDLE` and the warning that points at it (#89).

    The warning this replaces told the operator to import the FortiManager CA
    into the system trust store and set ``FORTIMANAGER_VERIFY_SSL=true``.
    Measured against a stock appliance, that does not work: the certificate is
    self-signed with the serial as CN and carries **no** subjectAltName, so with
    the appliance's own certificate trusted as the CA bundle a request by IP
    still fails ``CERTIFICATE_VERIFY_FAILED: IP address mismatch``. Trust was
    never the failing check. An operator following the old advice takes an
    outage and learns to ignore the warning.
    """

    def test_ca_bundle_path_reaches_the_transport(self, tmp_path: Any) -> None:
        """A CA bundle path must be handed to pyfmg verbatim.

        ``requests`` accepts either a bool or a path for ``verify=``, and pyfmg
        stores the value and forwards it unchanged, so a path needs no pyfmg
        change. This asserts we do not coerce it to a bool on the way past.
        """
        bundle = tmp_path / "corp-ca.pem"
        bundle.write_text("-----BEGIN CERTIFICATE-----\n")

        client = FortiManagerClient(
            host="test-fmg.example.com", api_token="t", verify_ssl=True, ca_bundle=str(bundle)
        )

        assert client.resolve_verify() == str(bundle)

    def test_verify_disabled_beats_a_ca_bundle(self, tmp_path: Any) -> None:
        """Explicitly disabled verification wins, and is not silently re-enabled."""
        bundle = tmp_path / "corp-ca.pem"
        bundle.write_text("-----BEGIN CERTIFICATE-----\n")

        client = FortiManagerClient(
            host="test-fmg.example.com", api_token="t", verify_ssl=False, ca_bundle=str(bundle)
        )

        assert client.resolve_verify() is False

    def test_no_bundle_keeps_the_system_trust_store(self) -> None:
        client = FortiManagerClient(host="test-fmg.example.com", api_token="t", verify_ssl=True)
        assert client.resolve_verify() is True

    def test_a_missing_bundle_fails_closed(self) -> None:
        """A path that does not exist must refuse at construction.

        Passing it through would hand ``requests`` a bad path and fail at the
        first call instead of at startup; worse, a typo'd path that happened to
        be falsy-adjacent would silently fall back to the system store and
        verify against the wrong trust root.
        """
        with pytest.raises(ValueError, match="CA bundle"):
            FortiManagerClient(
                host="test-fmg.example.com",
                api_token="t",
                verify_ssl=True,
                ca_bundle="/nonexistent/corp-ca.pem",
            )

    @pytest.mark.asyncio
    async def test_the_warning_does_not_promise_the_trust_store_is_enough(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The remediation sentence must name the real blocker.

        Pinning the correction rather than the exact wording: it must stop
        telling the operator that importing the CA is sufficient, and must say
        a certificate naming the address is required.
        """
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0, "message": "OK"}})
        stub.get.return_value = (0, {"status": {"code": 0}})
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)
        monkeypatch.setattr(FortiManagerClient, "_detect_version", lambda self: None)

        client = FortiManagerClient(host="test-fmg.example.com", api_token="t", verify_ssl=False)

        caplog.clear()
        with caplog.at_level("WARNING", logger="fortimanager_mcp.api.client"):
            await client.connect()

        blob = " ".join(r.getMessage() for r in caplog.records if r.levelname == "WARNING")

        # The diagnosis stays.
        assert "FORTIMANAGER_VERIFY_SSL=false" in blob
        # The false promise goes.
        assert "importing the FortiManager CA into the system trust store and" not in blob
        # The real blocker is named.
        assert "subjectAltName" in blob or "SAN" in blob
        # And the setting that makes true reachable is named.
        assert "FORTIMANAGER_CA_BUNDLE" in blob


class TestPortedClientMethods:
    """Request shapes of the client methods added by the lvenet port (1.13.0)."""

    @pytest.mark.asyncio
    async def test_clone_package_without_scope_omits_it(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """No ``scope`` key at all is what makes FMG copy the source's targets."""
        mock_fmg_instance.execute.return_value = (0, {"task": 9})

        result = await mock_client.clone_package("demo", "branch", "branch-v2")

        assert result == {"task": 9}
        assert mock_fmg_instance.execute.call_args.args[0] == "/securityconsole/package/clone"
        assert mock_fmg_instance.execute.call_args.kwargs == {
            "adom": "demo",
            "pkg": "branch",
            "dst_name": "branch-v2",
        }

    @pytest.mark.asyncio
    async def test_list_firewall_policies_scope_member_option(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_firewall_policies("demo", "branch", scope_member=True)
        assert mock_fmg_instance.get.call_args.kwargs["option"] == ["scope member"]

        await mock_client.list_firewall_policies("demo", "branch")
        assert "option" not in mock_fmg_instance.get.call_args.kwargs

    @pytest.mark.asyncio
    async def test_policy_block_reads_normalise_to_lists(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {"name": "shared"})
        assert await mock_client.list_policy_blocks("demo") == [{"name": "shared"}]

        mock_fmg_instance.get.return_value = (0, None)
        assert await mock_client.list_policy_block_policies("demo", "shared") == []
        assert mock_fmg_instance.get.call_args.kwargs == {}

    @pytest.mark.asyncio
    async def test_cli_template_list_asks_for_no_script(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_cli_templates("demo")

        assert mock_fmg_instance.get.call_args.args[0] == "/pm/config/adom/demo/obj/cli/template"
        assert "script" not in mock_fmg_instance.get.call_args.kwargs["fields"]

    @pytest.mark.asyncio
    async def test_profile_group_url(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {"name": "g1"})

        assert await mock_client.get_profile_group("demo", "g1") == {"name": "g1"}
        assert mock_fmg_instance.get.call_args.args[0] == (
            "/pm/config/adom/demo/obj/firewall/profile-group/g1"
        )


# ---------------------------------------------------------------------------
# Verb-aware retry (audit M3)
# ---------------------------------------------------------------------------


def _raise_chained(*excs: BaseException) -> BaseException:
    """Raise each exception inside the handler of the one before and return the last.

    Rebuilds the ``__context__``/``__cause__`` chain the real stack produces:
    urllib3 raises ``MaxRetryError(...) from reason``, requests re-raises it
    inside its handler as ``requests.ConnectionError``, and pyfmg re-raises
    that inside its own handler as ``FMGConnectionError``.
    """

    def _raise_at(i: int, prev: BaseException | None) -> BaseException:
        try:
            if isinstance(excs[i], MaxRetryError):
                raise excs[i] from prev
            raise excs[i]
        except BaseException as caught:  # noqa: BLE001 - test helper
            if i + 1 == len(excs):
                return caught
            # Still inside this handler, so the next raise gets __context__.
            return _raise_at(i + 1, caught)

    return _raise_at(0, None)


def _dropped_after_send() -> BaseException:
    """The connection closed after the request body went out (RemoteDisconnected)."""
    return _raise_chained(
        RemoteDisconnected("Remote end closed connection without response"),
        ProtocolError(
            "Connection aborted.",
            RemoteDisconnected("Remote end closed connection without response"),
        ),
        requests.exceptions.ConnectionError("('Connection aborted.', RemoteDisconnected(...))"),
        FMGConnectionError("Connection error: RemoteDisconnected"),
    )


def _connection_refused() -> BaseException:
    """The TCP connect was refused: nothing was sent."""
    reason = NewConnectionError(None, "Failed to establish a new connection: [Errno 61] refused")  # type: ignore[arg-type]
    return _raise_chained(
        ConnectionRefusedError(61, "Connection refused"),
        reason,
        MaxRetryError(None, "/jsonrpc", reason),  # type: ignore[arg-type]
        requests.exceptions.ConnectionError("Max retries exceeded (NewConnectionError)"),
        FMGConnectionError("Connection error: NewConnectionError"),
    )


def _connect_timed_out() -> BaseException:
    """The TCP connect timed out: nothing was sent."""
    reason = ConnectTimeoutError(None, "Connection to fmg timed out. (connect timeout=30)")
    return _raise_chained(
        TimeoutError("timed out"),
        reason,
        MaxRetryError(None, "/jsonrpc", reason),  # type: ignore[arg-type]
        requests.exceptions.ConnectTimeout("Max retries exceeded (ConnectTimeoutError)"),
        FMGConnectionError("Connection error: ConnectTimeout"),
    )


class _Coded(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(f"code {code}")
        self.code = code


class TestVerbAwareRetry:
    """A verb that can change state twice is replayed only when the request
    provably never reached FortiManager; get/set/update/delete keep the full
    transient retry (audit M3)."""

    @pytest.fixture(autouse=True)
    def _no_backoff(self, mock_client: FortiManagerClient) -> None:
        mock_client._TRANSIENT_BACKOFF_BASE = 0.0

    @pytest.mark.parametrize("verb", ["execute", "add", "clone", "move"])
    def test_post_send_drop_is_not_transient_for_state_changing_verbs(
        self, mock_client: FortiManagerClient, verb: str
    ) -> None:
        assert mock_client._is_transient_error(_dropped_after_send(), verb=verb) is False

    @pytest.mark.parametrize("verb", ["execute", "add", "clone", "move"])
    def test_code_minus_one_is_not_transient_for_state_changing_verbs(
        self, mock_client: FortiManagerClient, verb: str
    ) -> None:
        assert mock_client._is_transient_error(_Coded(-1), verb=verb) is False

    @pytest.mark.parametrize("verb", ["execute", "add", "clone", "move"])
    @pytest.mark.parametrize("make_exc", [_connection_refused, _connect_timed_out])
    def test_never_sent_errors_stay_transient_for_state_changing_verbs(
        self, mock_client: FortiManagerClient, verb: str, make_exc: Callable[[], BaseException]
    ) -> None:
        assert mock_client._is_transient_error(make_exc(), verb=verb) is True

    @pytest.mark.parametrize("verb", ["get", "set", "update", "delete"])
    def test_replay_safe_verbs_keep_full_retry(
        self, mock_client: FortiManagerClient, verb: str
    ) -> None:
        assert mock_client._is_transient_error(_dropped_after_send(), verb=verb) is True
        assert mock_client._is_transient_error(_Coded(-1), verb=verb) is True

    def test_a_bare_oserror_is_not_proof_the_request_never_left(
        self, mock_client: FortiManagerClient
    ) -> None:
        assert mock_client._is_transient_error(OSError("reset"), verb="execute") is False

    @pytest.mark.asyncio
    async def test_install_runs_once_when_connection_drops_after_send(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.side_effect = _dropped_after_send()
        with pytest.raises(FMGConnectionError) as exc_info:
            await mock_client.install_package(
                adom="root", pkg="default", scope=[{"name": "FGT-01", "vdom": "root"}]
            )
        assert mock_fmg_instance.execute.call_count == 1
        assert exc_info.value.retries_attempted == 0

    @pytest.mark.asyncio
    async def test_script_execute_not_replayed_on_code_minus_one(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (-1, {"status": {"message": "internal"}})
        with pytest.raises(FortiManagerMCPError):
            await mock_client.execute("/dvmdb/adom/root/script/execute", script="s")
        assert mock_fmg_instance.execute.call_count == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("verb", "call"),
        [
            ("add", lambda c: c.add("/pm/config/adom/root/obj/firewall/address", data={})),
            ("clone", lambda c: c.clone("/dvmdb/adom/root/revision/1", data={})),
            (
                "move",
                lambda c: c.move("/pm/config/adom/root/pkg/p/firewall/policy/1", "before", "2"),
            ),
            ("execute", lambda c: c.cache_diff_end("tok")),
        ],
    )
    async def test_every_state_changing_path_reaches_the_classifier(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        verb: str,
        call: Callable[[FortiManagerClient], Awaitable[Any]],
    ) -> None:
        getattr(mock_fmg_instance, verb).side_effect = _dropped_after_send()
        with pytest.raises(FMGConnectionError):
            await call(mock_client)
        assert getattr(mock_fmg_instance, verb).call_count == 1

    @pytest.mark.asyncio
    async def test_execute_retried_when_the_connect_was_refused(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.side_effect = [_connection_refused(), (0, {"task": 7})]
        result = await mock_client.execute("/securityconsole/install/package", adom="root")
        assert result == {"task": 7}
        assert mock_fmg_instance.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_get_still_retried_after_a_post_send_drop(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.side_effect = [_dropped_after_send(), (0, {"ok": 1})]
        assert await mock_client.get("/sys/status") == {"ok": 1}
        assert mock_fmg_instance.get.call_count == 2

    @pytest.mark.asyncio
    async def test_stale_session_still_reconnects_once_for_execute(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """-11 is rejected before FMG acts, so the reconnect-once path stays."""
        reconnects: list[str] = []

        async def fake_force_reconnect(self_: FortiManagerClient) -> None:
            reconnects.append("reconnect")

        monkeypatch.setattr(FortiManagerClient, "_force_reconnect", fake_force_reconnect)
        mock_fmg_instance.execute.side_effect = [
            (-11, {"status": {"message": "No permission"}}),
            (0, {"task": 9}),
        ]
        assert await mock_client.execute("/securityconsole/install/package") == {"task": 9}
        assert reconnects == ["reconnect"]

    @pytest.mark.asyncio
    async def test_read_only_exec_keeps_full_retry(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.side_effect = [_dropped_after_send(), (0, {"message": "[]"})]
        assert await mock_client.get_preview_result("root", scope=[]) == {"message": "[]"}
        assert mock_fmg_instance.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_proxy_get_retried_but_proxy_write_is_not(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        target = ["/adom/root/device/FGT1"]
        mock_fmg_instance.execute.side_effect = [(-1, {}), (0, [{"response": {}}])]
        await mock_client.proxy_call("get", "/api/v2/monitor/system/status", target)
        assert mock_fmg_instance.execute.call_count == 2

        mock_fmg_instance.execute.reset_mock()
        mock_fmg_instance.execute.side_effect = [(-1, {}), (0, [{"response": {}}])]
        with pytest.raises(FortiManagerMCPError):
            await mock_client.proxy_call("post", "/api/v2/monitor/system/os/reboot", target)
        assert mock_fmg_instance.execute.call_count == 1


class TestReachability:
    """``is_reachable`` turns False when a request fails to reach FortiManager
    and True again on the next answer. ``is_connected`` alone stays True for
    as long as the appliance is down, since only a session error or
    ``disconnect()`` clears it, so ``/health`` reads ``is_reachable``."""

    @staticmethod
    async def _no_sleep(_: float) -> None:
        return None

    @pytest.mark.asyncio
    async def test_transport_error_marks_unreachable_until_next_success(
        self, mock_client: FortiManagerClient
    ) -> None:
        async def _down() -> None:
            raise FMGConnectionError("connection refused")

        async def _up() -> str:
            return "ok"

        with pytest.raises(FMGConnectionError):
            await mock_client._execute_resilient(_down, verb="get", sleep=self._no_sleep)
        assert mock_client.is_connected
        assert not mock_client.is_reachable

        await mock_client._execute_resilient(_up, verb="get")
        assert mock_client.is_reachable

    @pytest.mark.asyncio
    async def test_wrapped_read_timeout_marks_unreachable(
        self, mock_client: FortiManagerClient
    ) -> None:
        """pyfmg re-raises a read timeout as a plain FMGBaseException inside its
        handler, so the timeout survives only as ``__context__``."""

        async def _timeout() -> None:
            try:
                raise requests.exceptions.ReadTimeout("read timed out")
            except requests.exceptions.ReadTimeout as err:
                raise FMGBaseException(str(err)) from None

        with pytest.raises(FMGBaseException):
            await mock_client._execute_resilient(_timeout, verb="get", sleep=self._no_sleep)
        assert not mock_client.is_reachable

    @pytest.mark.asyncio
    async def test_error_code_counts_as_reachable(self, mock_client: FortiManagerClient) -> None:
        """An error code is an answer: the appliance is up."""
        mock_client._unreachable = True

        async def _not_found() -> None:
            raise parse_fmg_error(-3, "Object does not exist", "GET /dvmdb/device/x")

        with pytest.raises(FortiManagerMCPError):
            await mock_client._execute_resilient(_not_found, verb="get")
        assert mock_client.is_reachable

    @pytest.mark.asyncio
    async def test_local_not_connected_leaves_flag_alone(
        self, mock_client: FortiManagerClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A local "Not connected" whose forced reconnect fails says nothing
        about the appliance, so the flag keeps its value."""
        mock_client._ever_connected = True
        mock_client._unreachable = True
        stub = MagicMock()
        stub.login.side_effect = ConnectionError("login failed")
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        async def _lost() -> None:
            raise ConnectionError("Not connected. Call connect() first.")

        with pytest.raises(ConnectionError):
            await mock_client._execute_resilient(_lost, verb="get")
        assert mock_client._unreachable

    @pytest.mark.asyncio
    async def test_reconnect_clears_flag(
        self, mock_client: FortiManagerClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_client._unreachable = True
        stub = MagicMock()
        stub.login.return_value = (0, {"status": {"code": 0}})
        monkeypatch.setattr("fortimanager_mcp.api.client.FortiManager", lambda *a, **kw: stub)

        mock_client._connected = False
        await mock_client.connect()
        assert mock_client.is_reachable
