"""FortiManager API client wrapper using pyfmg library.

Based on FNDN FortiManager 7.6.5 API specifications.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from pyFMG.fortimgr import FortiManager

from fortimanager_mcp.utils.config import Settings
from fortimanager_mcp.utils.errors import (
    AuthenticationError,
    ConnectionError,
    parse_fmg_error,
)

logger = logging.getLogger(__name__)


def _sanitize_for_logging(data: Any, depth: int = 0) -> Any:
    """Sanitize sensitive data before logging."""
    SENSITIVE_FIELDS = {
        "password",
        "passwd",
        "pass",
        "adm_pass",
        "api_token",
        "apikey",
        "token",
        "session",
        "sid",
        "authorization",
        "secret",
    }
    MASK = "***REDACTED***"

    if depth > 10:
        return "<MAX_DEPTH>"

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = key.lower().replace("-", "_")
            if any(s in key_lower for s in SENSITIVE_FIELDS):
                result[key] = MASK
            else:
                result[key] = _sanitize_for_logging(value, depth + 1)
        return result
    elif isinstance(data, list):
        return [_sanitize_for_logging(item, depth + 1) for item in data]
    return data


class FortiManagerClient:
    """Client for FortiManager JSON RPC API using pyfmg library.

    This client wraps the pyfmg FortiManager class for accessing
    FortiManager's JSON-RPC API.

    Based on FNDN FortiManager 7.6.5 specifications.
    """

    # FMG error codes that mean the server session is gone (revive once).
    # Verified live against FMG 7.6.7: a stale/invalid session surfaces as
    # -11 "No permission for the resource" (the same code a genuinely
    # unauthorized request gets, so the reconnect is attempted once and a real
    # permission problem still surfaces right after). -2 was previously listed
    # here, but on the FMG it actually means "Object already exists" -- a
    # duplicate create must NOT trigger a re-login.
    _RECONNECTABLE_ERROR_CODES = frozenset({-11})
    # FMG error codes worth a bounded transient retry.
    # -1 internal error. (-11 was previously listed as "task timeout", but it
    # is really permission/stale-session -- retrying it without a reconnect
    # just replays the failure; it is handled by the reconnect path above.)
    _TRANSIENT_ERROR_CODES = frozenset({-1})
    # Bounded transient retry: at most this many retries with exponential backoff.
    _TRANSIENT_RETRIES = 2
    _TRANSIENT_BACKOFF_BASE = 0.5  # seconds; doubled each retry

    def __init__(
        self,
        host: str,
        api_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize FortiManager client."""
        self.host = host.replace("https://", "").replace("http://", "").rstrip("/")
        self.api_token = api_token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries

        self._fmg: FortiManager | None = None
        self._connected = False
        # True once a login has succeeded at least once. Distinguishes a session
        # that dropped after being connected (revive it) from a client that was
        # never connected (a direct API call should still raise "Not connected").
        self._ever_connected = False
        self._fmg_version: tuple[int, int, int] | None = None  # (major, minor, patch)
        # Serialize forced reconnects so concurrent requests that all hit a
        # dropped session perform a single re-login instead of racing to clear
        # and rebuild _fmg underneath one another. The generation counter lets
        # a waiter detect that a peer already reconnected while it blocked.
        self._reconnect_lock = asyncio.Lock()
        self._reconnect_generation = 0
        # pyfmg is a synchronous requests-based library and its session is not
        # thread-safe, so every pyfmg call runs in a worker thread (keeping the
        # event loop responsive) but under this lock (keeping calls serialized,
        # matching the single-session semantics the FMG expects).
        self._request_lock = asyncio.Lock()

        logger.info(f"Initialized FortiManager client for {self.host}")

    @classmethod
    def from_settings(cls, settings: Settings) -> "FortiManagerClient":
        """Create client from settings."""
        return cls(
            host=settings.FORTIMANAGER_HOST,
            api_token=settings.FORTIMANAGER_API_TOKEN or None,
            username=settings.FORTIMANAGER_USERNAME or None,
            password=settings.FORTIMANAGER_PASSWORD or None,
            verify_ssl=settings.FORTIMANAGER_VERIFY_SSL,
            timeout=settings.FORTIMANAGER_TIMEOUT,
            max_retries=settings.FORTIMANAGER_MAX_RETRIES,
        )

    async def connect(self) -> None:
        """Establish connection and authenticate."""
        if self._connected:
            logger.warning("Client already connected")
            return

        if not self.verify_ssl:
            # Visible nudge: FORTIMANAGER_VERIFY_SSL=false silently drops TLS
            # verification, exposing the API token and every config push / script
            # output to anyone in the connection path. Prefer importing the FMG
            # CA cert into the system trust store and leaving verify on.
            logger.warning(
                "FORTIMANAGER_VERIFY_SSL=false: TLS certificate verification is "
                "DISABLED for %s. API token and all configuration data are "
                "exposed to anyone able to intercept this connection. Prefer "
                "importing the FortiManager CA into the system trust store and "
                "setting FORTIMANAGER_VERIFY_SSL=true.",
                self.host,
            )

        logger.info("Connecting to FortiManager")

        try:
            if self.api_token:
                self._fmg = FortiManager(
                    self.host,
                    apikey=self.api_token,
                    debug=False,
                    use_ssl=True,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                    check_adom_workspace=False,
                )
            elif self.username and self.password:
                self._fmg = FortiManager(
                    self.host,
                    self.username,
                    self.password,
                    debug=False,
                    use_ssl=True,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout,
                )
            else:
                raise AuthenticationError(
                    "No authentication provided. Set API token or username/password."
                )

            code, response = await self._run_fmg_call(self._fmg.login)

            if code != 0:
                error_msg = response.get("status", {}).get("message", "Login failed")
                raise AuthenticationError(f"FortiManager login failed: {error_msg}")

            # With an API token, pyfmg's login() performs no network round-trip
            # (it just stores the key), so an unreachable FMG or a bad token is
            # not detected until the first real request -- which would leave
            # connect() reporting success and /health reporting connected while
            # nothing actually works. Probe once here so both reflect reality.
            # Session (username/password) auth already round-trips in login().
            if self.api_token:
                vcode, vresp = await self._run_fmg_call(self._fmg.get, "/sys/status")
                if vcode != 0:
                    detail = (
                        vresp.get("status", {}).get("message", "verification failed")
                        if isinstance(vresp, dict)
                        else str(vresp)
                    )
                    raise ConnectionError(f"FortiManager token verification failed: {detail}")

            self._connected = True
            self._ever_connected = True
            logger.info("Successfully connected to FortiManager")

        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            raise ConnectionError(f"Failed to connect to FortiManager: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect and cleanup resources."""
        if not self._connected or not self._fmg:
            return

        logger.info("Disconnecting from FortiManager")

        try:
            await self._run_fmg_call(self._fmg.logout)
        except Exception as e:
            logger.warning(f"Logout failed: {e}")
        finally:
            self._fmg = None
            self._connected = False
            logger.info("Disconnected from FortiManager")

    async def __aenter__(self) -> "FortiManagerClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self._fmg is not None

    @property
    def fmg_version(self) -> tuple[int, int, int] | None:
        """Get cached FortiManager version tuple (major, minor, patch)."""
        return self._fmg_version

    async def _detect_version(self) -> tuple[int, int, int]:
        """Detect and cache FortiManager version.

        Returns tuple of (major, minor, patch).
        """
        if self._fmg_version is not None:
            return self._fmg_version

        try:
            status = await self.get_system_status()
            version_str = status.get("Version", "7.0.0")
            # Version format: "v7.6.5-build3653 251215 (GA.M)"
            version_part = version_str.split("-")[0].split()[0]
            # Strip leading 'v' if present
            version_part = version_part.lstrip("v")
            parts = version_part.split(".")
            self._fmg_version = (
                int(parts[0]) if len(parts) > 0 else 7,
                int(parts[1]) if len(parts) > 1 else 0,
                int(parts[2]) if len(parts) > 2 else 0,
            )
            logger.info(f"Detected FortiManager version: {self._fmg_version}")
        except Exception as e:
            logger.warning(f"Failed to detect FMG version, assuming 7.0.0: {e}")
            self._fmg_version = (7, 0, 0)

        return self._fmg_version

    def _script_base_url(self, adom: str) -> str:
        """Get the appropriate script endpoint URL based on FMG version.

        FMG 7.6+: /pm/config/adom/{adom}/obj/fmg/script
        FMG 7.0-7.4: /dvmdb/adom/{adom}/script
        """
        if self._uses_new_script_endpoint():
            return f"/pm/config/adom/{adom}/obj/fmg/script"
        return f"/dvmdb/adom/{adom}/script"

    def _uses_new_script_endpoint(self) -> bool:
        """Whether the FMG 7.6+ /pm/config script endpoint is in use.

        Used as the branch condition for the script target string<->int mapping.
        Must mirror the version check in :meth:`_script_base_url`.
        """
        return self._fmg_version is not None and self._fmg_version >= (7, 6, 0)

    # Script target mapping for FMG 7.6+ /pm/config endpoint.
    #
    # The legacy /dvmdb endpoint accepts string targets verbatim. The new
    # /pm/config endpoint expects integers and silently coerces unknown values
    # (including strings) to 0 (device_database). See GitHub issue #3.
    #
    # Verified live against FMG 7.6.7 by EXECUTION (issue #21; a create+get
    # round-trip cannot detect a swapped map because it is symmetric):
    #   - target=2 script executes against a policy package (adom_database
    #     semantics) and spawns a task; 0 and 1 are rejected with -8.
    #   - target=1 script accepts a device-scoped execute (remote_device).
    # The previous map had adom_database=1 / remote_device=2 (from the doc
    # round-trip), which made every execute_script_on_package call fail with
    # -8 "Invalid parameter".
    _SCRIPT_TARGET_MAP: dict[str, int] = {
        "device_database": 0,
        "remote_device": 1,
        "adom_database": 2,
    }
    _SCRIPT_TARGET_REVERSE: dict[int, str] = {
        0: "device_database",
        1: "remote_device",
        2: "adom_database",
    }

    def _map_script_target(self, script: dict[str, Any]) -> dict[str, Any]:
        """Map string `target` to int for the FMG 7.6+ script endpoint.

        No-op for the legacy /dvmdb endpoint (which accepts strings) and for
        scripts whose target is already an int or absent. Unknown string
        values are passed through unchanged so the API surface still
        reports an error rather than silently rewriting to 0.
        """
        target = script.get("target")
        if not isinstance(target, str):
            return script
        if not self._uses_new_script_endpoint():
            return script
        if target not in self._SCRIPT_TARGET_MAP:
            return script
        mapped = dict(script)
        mapped["target"] = self._SCRIPT_TARGET_MAP[target]
        return mapped

    def _unmap_script_target(self, script: Any) -> Any:
        """Map int `target` back to string for the FMG 7.6+ script endpoint.

        Keeps the public API surface string-typed for callers. No-op for
        legacy endpoint responses (already strings), non-dict inputs, and
        unknown integer values.
        """
        if not isinstance(script, dict):
            return script
        target = script.get("target")
        if not isinstance(target, int) or isinstance(target, bool):
            return script
        if target not in self._SCRIPT_TARGET_REVERSE:
            return script
        unmapped = dict(script)
        unmapped["target"] = self._SCRIPT_TARGET_REVERSE[target]
        return unmapped

    # FMG filter operators that compare a single value (3-element triplet).
    # Used to recognize ["field", op, value] in script target filter mapping.
    _FMG_BINARY_FILTER_OPS: frozenset[str] = frozenset(
        {"==", "!=", "<", "<=", ">", ">=", "like", "!like", "contain", "!contain"}
    )

    def _map_script_target_filter(self, filter_expr: Any) -> Any:
        """Translate string `target` values in a filter expression to ints
        for the FMG 7.6+ script endpoint.

        FMG 7.6+ stores `target` as an integer, so filters like
        `["target", "==", "remote_device"]` or `["target", "in",
        "device_database", "remote_device"]` never match — FMG silently
        coerces unknown strings to 0 and returns wrong rows.

        Handles two filter shapes for the `target` field:
            * binary operator triplet: `["target", op, <str>]`
              (op in :attr:`_FMG_BINARY_FILTER_OPS`)
            * multi-value `in`/`!in`: `["target", "in"|"!in", v1, v2, ...]`
              (flat list, see existing usage at `list_devices` filter site)

        No-op on the legacy /dvmdb endpoint (strings are accepted there),
        for non-list inputs, unknown operators, and unknown target string
        values (left for FMG to surface explicitly).
        """
        if not self._uses_new_script_endpoint():
            return filter_expr
        return self._walk_script_target_filter(filter_expr)

    def _walk_script_target_filter(self, expr: Any) -> Any:
        if not isinstance(expr, list):
            return expr
        # Binary operator triplet: ["target", op, value]
        if (
            len(expr) == 3
            and expr[0] == "target"
            and isinstance(expr[1], str)
            and expr[1] in self._FMG_BINARY_FILTER_OPS
        ):
            return [expr[0], expr[1], self._map_target_value(expr[2])]
        # Multi-value list operator: ["target", "in"|"!in", v1, v2, ...]
        if len(expr) >= 3 and expr[0] == "target" and expr[1] in ("in", "!in"):
            return [expr[0], expr[1]] + [self._map_target_value(v) for v in expr[2:]]
        return [self._walk_script_target_filter(item) for item in expr]

    def _map_target_value(self, value: Any) -> Any:
        """Map a single `target` string value to its int counterpart, or
        return unchanged for ints and unknown strings."""
        if isinstance(value, str) and value in self._SCRIPT_TARGET_MAP:
            return self._SCRIPT_TARGET_MAP[value]
        return value

    async def _run_fmg_call(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        """Run a synchronous pyfmg call without blocking the event loop.

        pyfmg does blocking ``requests`` I/O, so the call is offloaded to a
        worker thread; the lock keeps calls serialized because the shared
        pyfmg session is not thread-safe.

        Cancellation (e.g. an outer ``asyncio.wait_for`` timeout) cannot
        interrupt the worker thread. Releasing the lock at that point would
        let the next call start a second thread on the same session while the
        orphan is still using it, so instead lock ownership is handed to the
        in-flight call: the cancelled caller returns immediately (preserving
        the timeout bound) and the thread's completion callback releases the
        lock, making any follow-up call queue until the session is idle again.
        """
        await self._request_lock.acquire()
        handed_off = False
        try:
            worker = asyncio.ensure_future(asyncio.to_thread(func, *args, **kwargs))
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                if worker.done():
                    # Completed just as the cancel landed: consume the outcome
                    # so a failed result does not warn, then propagate.
                    if not worker.cancelled():
                        worker.exception()
                    raise
                handed_off = True
                worker.add_done_callback(self._release_after_orphaned_call)
                raise
        finally:
            if not handed_off:
                self._request_lock.release()

    def _release_after_orphaned_call(self, worker: "asyncio.Task[Any]") -> None:
        """Release the request lock once an abandoned worker thread finishes.

        Retrieves the worker's outcome so a failed orphan does not emit an
        "exception was never retrieved" warning; the caller that abandoned it
        already surfaced its own timeout/cancellation to the user.
        """
        if not worker.cancelled():
            exc = worker.exception()
            if exc is not None:
                logger.debug(f"Abandoned FortiManager call failed after cancellation: {exc}")
        self._request_lock.release()

    def _ensure_connected(self) -> FortiManager:
        """Ensure client is connected and return pyfmg instance."""
        if not self._connected or not self._fmg:
            raise ConnectionError("Not connected. Call connect() first.")
        return self._fmg

    async def ensure_connected(self) -> None:
        """Reconnect once if the session has dropped.

        Tools call this before issuing requests so an idle-closed session is
        transparently revived rather than surfacing a raw "Not connected" error.
        FortiManager can report the session gone after a streamable-HTTP session
        closes; a fresh request should re-login rather than fail. Raises
        ConnectionError if the single reconnect attempt fails.
        """
        if self.is_connected:
            return
        logger.warning("FortiManager session not connected; reconnecting once")
        await self.connect()

    def _is_transient_error(self, exc: Exception) -> bool:
        """Classify whether an error is worth a bounded transient retry.

        Network errors and ``-1`` internal error are transient. Validation,
        permission, not-found, ADOM-locked, and authentication errors are NOT
        retried — stale-session ``-11`` is owned by :meth:`_is_session_error`
        (reconnect path), where a retry without a fresh login would be useless.
        """
        if isinstance(exc, OSError):
            return True
        return getattr(exc, "code", None) in self._TRANSIENT_ERROR_CODES

    def _is_session_error(self, exc: Exception) -> bool:
        """Classify whether an error means the server session is gone.

        A stale/expired session (e.g. the appliance closed an idle session)
        surfaces as an auth error while the local client still believes it is
        connected. A raw ``ConnectionError("Not connected. ...")`` from
        :meth:`_ensure_connected` means the local client lost its session
        mid-request (e.g. another path disconnected it). Both are recoverable by
        re-logging in once.
        """
        if isinstance(exc, AuthenticationError):
            return True
        # A local not-connected error means the session dropped mid-request --
        # but only revive it if we were genuinely connected before. A client
        # that never connected must still surface "Not connected" rather than
        # silently attempting a first login on an arbitrary API call.
        if (
            self._ever_connected
            and isinstance(exc, ConnectionError)
            and "not connected" in str(exc).lower()
        ):
            return True
        return getattr(exc, "code", None) in self._RECONNECTABLE_ERROR_CODES

    async def _execute_resilient(
        self,
        factory: Callable[[], Awaitable[Any]],
        *,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> Any:
        """Run an async request factory with reconnect-once + transient retry.

        A stale-session error triggers exactly one forced reconnect (re-login)
        and a retry — this revives a session the appliance dropped while the
        local client still believed it was connected. Transient FMG/network
        errors are then retried up to ``_TRANSIENT_RETRIES`` with exponential
        backoff. Validation, not-found, permission, ADOM-locked, and not-
        connected errors (when never connected) are surfaced immediately so
        callers can handle them.

        The number of transient retries actually performed is annotated on the
        finally-raised exception as ``retries_attempted`` (best-effort) so the
        ``error_response()`` envelope can surface ``retry_count`` to a caller.
        Reconnect attempts are not counted (they're a distinct recovery axis).

        Tests inject ``sleep=`` to avoid real sleeps; production uses the real
        ``asyncio.sleep``.
        """
        sleeper = sleep or asyncio.sleep
        retries_left = self._TRANSIENT_RETRIES
        reconnect_left = 1
        attempt = 0
        while True:
            try:
                return await factory()
            except Exception as exc:
                if reconnect_left > 0 and self._is_session_error(exc):
                    reconnect_left -= 1
                    logger.warning("FortiManager session invalid; reconnecting once and retrying")
                    await self._force_reconnect()
                    continue
                if retries_left <= 0 or not self._is_transient_error(exc):
                    # Best-effort annotation for the response envelope. Paths
                    # that bypass this raise (force-reconnect failure, etc.)
                    # carry no attribute and read back as 0 via getattr.
                    exc.retries_attempted = attempt  # type: ignore[attr-defined]
                    raise
                retries_left -= 1
                delay = self._TRANSIENT_BACKOFF_BASE * (2**attempt)
                attempt += 1
                logger.warning(f"Transient FortiManager error; retrying in {delay:.1f}s: {exc}")
                await sleeper(delay)

    async def _generic_request(self, verb: str, url: str, **kwargs: Any) -> Any:
        """Run a standard pyfmg verb with bounded reconnect + transient-retry resilience.

        The factory closes over the verb/url/kwargs and re-executes them on
        each retry attempt, so a reconnect picks up a fresh pyfmg handle from
        ``_ensure_connected()`` rather than reusing a stale one.
        """

        async def _factory() -> Any:
            fmg = self._ensure_connected()
            method = getattr(fmg, verb)
            code, response = await self._run_fmg_call(method, url, **kwargs)
            return self._handle_response(code, response, f"{verb.upper()} {url}")

        return await self._execute_resilient(_factory)

    async def _force_reconnect(self) -> None:
        """Drop stale connection state and reconnect (re-login), serialized.

        The lock ensures that when several concurrent requests all hit a dropped
        session, only the first re-logs in; the others observe the bumped
        generation counter and return without tearing the revived connection
        back down. A stale session still reports ``is_connected`` locally, so
        the generation counter — not ``is_connected`` — is what detects a
        peer's reconnect.
        """
        observed = self._reconnect_generation
        async with self._reconnect_lock:
            if self._reconnect_generation != observed:
                # A concurrent caller already reconnected while we waited.
                return
            self._connected = False
            self._fmg = None
            await self.connect()
            self._reconnect_generation += 1

    def _handle_response(self, code: int, response: Any, operation: str = "operation") -> Any:
        """Handle pyfmg response and raise appropriate exceptions."""
        if code == 0:
            return response

        if isinstance(response, dict):
            error_msg = response.get("status", {}).get("message", str(response))
        else:
            error_msg = str(response)

        raise parse_fmg_error(code, error_msg, operation)

    # =========================================================================
    # Generic Operations
    # =========================================================================

    async def get(self, url: str, **kwargs: Any) -> Any:
        """Execute GET request with bounded reconnect + transient-retry resilience."""
        return await self._generic_request("get", url, **kwargs)

    async def add(self, url: str, **kwargs: Any) -> Any:
        """Execute ADD request with bounded reconnect + transient-retry resilience."""
        return await self._generic_request("add", url, **kwargs)

    async def set(self, url: str, **kwargs: Any) -> Any:
        """Execute SET request with bounded reconnect + transient-retry resilience."""
        return await self._generic_request("set", url, **kwargs)

    async def update(self, url: str, **kwargs: Any) -> Any:
        """Execute UPDATE request with bounded reconnect + transient-retry resilience."""
        return await self._generic_request("update", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> Any:
        """Execute DELETE request with bounded reconnect + transient-retry resilience."""
        return await self._generic_request("delete", url, **kwargs)

    async def execute(self, url: str, **kwargs: Any) -> Any:
        """Execute EXEC request with bounded reconnect + transient-retry resilience."""
        return await self._generic_request("execute", url, **kwargs)

    async def move(self, url: str, option: str, target: str) -> Any:
        """Execute MOVE request with bounded reconnect + transient-retry resilience.

        Args:
            url: The URL of the object to move
            option: "before" or "after"
            target: Target object ID (as string)
        """

        async def _factory() -> Any:
            fmg = self._ensure_connected()
            # Pass as dict in args (not kwargs) so it merges at top level, not in 'data'
            code, response = await self._run_fmg_call(
                fmg.move, url, {"option": option, "target": target}
            )
            return self._handle_response(code, response, f"MOVE {url}")

        return await self._execute_resilient(_factory)

    async def clone(self, url: str, **kwargs: Any) -> Any:
        """Execute CLONE request with bounded reconnect + transient-retry resilience."""
        return await self._generic_request("clone", url, **kwargs)

    async def _flat_request(self, verb: str, url: str, payload: dict[str, Any]) -> Any:
        """Run `verb` with `payload` merged at the params top level, not under 'data'.

        pyfmg's ``common_datagram_params`` only flat-merges kwargs for the
        'get'/'clone' method types; every other verb (exec, update, ...) always
        wraps kwargs one level deeper, under a ``data`` key. Passing `payload`
        positionally -- the same trick ``move()`` above uses -- bypasses that
        wrapping, so a key the FMG How-To guide shows as a *sibling* of 'data'
        (``token`` on a ``/cache/diff/*`` exec call, ``revision note`` on a
        firewall-policy revert) lands where the guide's own examples put it,
        instead of nested one level too deep where FortiManager would not find
        it.
        """

        async def _factory() -> Any:
            fmg = self._ensure_connected()
            method = getattr(fmg, verb)
            code, response = await self._run_fmg_call(method, url, payload)
            return self._handle_response(code, response, f"{verb.upper()} {url}")

        return await self._execute_resilient(_factory)

    # =========================================================================
    # System Status (from sys.json)
    # =========================================================================

    async def get_system_status(self) -> dict[str, Any]:
        """Get FortiManager system status.

        FNDN: GET /sys/status
        """
        return await self.get("/sys/status")

    async def get_ha_status(self) -> dict[str, Any]:
        """Get HA status.

        FNDN: GET /sys/ha/status
        """
        return await self.get("/sys/ha/status")

    # =========================================================================
    # DVMDB - Device Manager Database
    # =========================================================================

    async def list_adoms(
        self,
        fields: list[str] | None = None,
        filter: list | None = None,
        loadsub: int = 0,
    ) -> list[dict[str, Any]]:
        """List all ADOMs.

        FNDN: GET /dvmdb/adom
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get("/dvmdb/adom", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_adom(self, name: str, loadsub: int = 0) -> dict[str, Any]:
        """Get specific ADOM.

        FNDN: GET /dvmdb/adom/{adom}
        """
        return await self.get(f"/dvmdb/adom/{name}", loadsub=loadsub)

    # =========================================================================
    # ADOM Revisions (issue: revision-tools)
    # =========================================================================

    async def list_adom_revisions(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List the ADOM DB revision history for an ADOM.

        FNDN: GET /dvmdb/adom/{adom}/revision (dvmdb.json)
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/dvmdb/adom/{adom}/revision", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_adom_revision(self, adom: str, revision: int) -> dict[str, Any]:
        """Get a single ADOM DB revision's metadata.

        FNDN: GET /dvmdb/adom/{adom}/revision/{revision} (dvmdb.json)
        """
        return await self.get(f"/dvmdb/adom/{adom}/revision/{revision}")

    async def clone_adom_revision(
        self,
        adom: str,
        revision: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Clone an ADOM DB revision -- the documented "revert" mechanism.

        FortiManager has no dedicated revert-ADOM-revision call; the How-To
        guide's "How to revert an ADOM Revision?" section instead clones the
        target past revision, which both restores the live ADOM DB to that
        historical state and records the clone as a brand-new revision (see
        docs/guides/.../013_adom_management.rst).

        FNDN: CLONE /dvmdb/adom/{adom}/revision/{revision} (dvmdb.json)

        Returns:
            {"version": <new revision number>}
        """
        return await self.clone(f"/dvmdb/adom/{adom}/revision/{revision}", data=data)

    async def list_devices(
        self,
        adom: str = "root",
        fields: list[str] | None = None,
        filter: list | None = None,
        loadsub: int = 0,
    ) -> list[dict[str, Any]]:
        """List devices in ADOM.

        FNDN: GET /dvmdb/adom/{adom}/device
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/dvmdb/adom/{adom}/device", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_device(self, device: str, adom: str = "root", loadsub: int = 0) -> dict[str, Any]:
        """Get specific device.

        FNDN: GET /dvmdb/adom/{adom}/device/{device}
        """
        return await self.get(f"/dvmdb/adom/{adom}/device/{device}", loadsub=loadsub)

    async def list_device_vdoms(self, device: str, adom: str = "root") -> list[dict[str, Any]]:
        """List VDOMs for a device.

        FNDN: GET /dvmdb/adom/{adom}/device/{device}/vdom
        """
        result = await self.get(f"/dvmdb/adom/{adom}/device/{device}/vdom")
        return result if isinstance(result, list) else [result] if result else []

    async def list_device_groups(self, adom: str = "root") -> list[dict[str, Any]]:
        """List device groups.

        FNDN: GET /dvmdb/adom/{adom}/group
        """
        result = await self.get(f"/dvmdb/adom/{adom}/group")
        return result if isinstance(result, list) else [result] if result else []

    async def create_device_group(
        self,
        adom: str,
        name: str,
        os_type: str = "unknown",
        description: str | None = None,
    ) -> dict[str, Any]:
        """Create a device group.

        Only ``name``, ``os_type`` and ``desc`` are writable on the dvmdb
        group object -- ``type``, ``cluster_type`` and ``id`` are read-only.

        FNDN: ADD /dvmdb/adom/{adom}/group
        """
        data: dict[str, Any] = {"name": name, "os_type": os_type}
        if description is not None:
            data["desc"] = description
        return await self.add(f"/dvmdb/adom/{adom}/group", data=data)

    async def delete_device_group(self, adom: str, name: str) -> dict[str, Any]:
        """Delete a device group.

        FNDN: DELETE /dvmdb/adom/{adom}/group/{group}
        """
        return await self.delete(f"/dvmdb/adom/{adom}/group/{name}")

    async def add_group_members(
        self,
        adom: str,
        group: str,
        members: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Add member(s) to a device group without disturbing existing members.

        A member is either a device (``{"name": <device>, "vdom": <vdom>}``)
        or a nested group (``{"name": <group>}``, no vdom).

        FNDN: ADD /dvmdb/adom/{adom}/group/{group}/object member
        """
        return await self.add(
            f"/dvmdb/adom/{adom}/group/{group}/object member",
            data=members,
        )

    async def remove_group_members(
        self,
        adom: str,
        group: str,
        members: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Remove member(s) from a device group.

        FNDN: DELETE /dvmdb/adom/{adom}/group/{group}/object member
        """
        return await self.delete(
            f"/dvmdb/adom/{adom}/group/{group}/object member",
            data=members,
        )

    # =========================================================================
    # DVM Commands (Device Virtual Manager)
    # =========================================================================

    async def add_device(
        self,
        adom: str,
        device: dict[str, Any],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add a device to FortiManager.

        FNDN: EXEC /dvm/cmd/add/device

        Args:
            adom: ADOM name
            device: Device configuration dict with:
                - name: Device name (required)
                - ip: Device IP
                - adm_usr: Admin username
                - adm_pass: Admin password
                - sn: Serial number
                - mgmt_mode: Management mode (fmg, faz, fmgfaz)
                - device action: "add_model" for offline provisioning
        """
        data: dict[str, Any] = {"adom": adom, "device": device}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/add/device", **data)

    async def delete_device(
        self,
        adom: str,
        device: str,
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Delete a device from FortiManager.

        FNDN: EXEC /dvm/cmd/del/device
        """
        data: dict[str, Any] = {"adom": adom, "device": device}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/del/device", **data)

    async def reload_device_list(self, adom: str = "root") -> dict[str, Any]:
        """Reload device list.

        FNDN: EXEC /dvm/cmd/reload/dev-list
        """
        return await self.execute("/dvm/cmd/reload/dev-list", adom=adom)

    async def add_device_list(
        self,
        adom: str,
        devices: list[dict[str, Any]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add multiple devices.

        FNDN: EXEC /dvm/cmd/add/dev-list
        """
        data: dict[str, Any] = {"adom": adom, "add-dev-list": devices}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/add/dev-list", **data)

    async def delete_device_list(
        self,
        adom: str,
        devices: list[dict[str, Any]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Delete multiple devices.

        FNDN: EXEC /dvm/cmd/del/dev-list
        """
        data: dict[str, Any] = {"adom": adom, "del-dev-member-list": devices}
        if flags:
            data["flags"] = flags

        return await self.execute("/dvm/cmd/del/dev-list", **data)

    async def update_device(
        self,
        adom: str,
        device: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update device properties.

        FNDN: UPDATE /dvmdb/adom/{adom}/device/{device}
        """
        return await self.update(f"/dvmdb/adom/{adom}/device/{device}", **data)

    async def get_device_status(
        self,
        adom: str = "root",
        device: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get device status (config sync, connection status).

        FNDN: GET /dvmdb/adom/{adom}/device with status fields
        """
        fields = [
            "name",
            "ip",
            "sn",
            "conn_status",
            "conf_status",
            "db_status",
            "dev_status",
            "os_ver",
            "platform_str",
        ]
        filter_param = [["name", "==", device]] if device else None
        return await self.list_devices(adom, fields=fields, filter=filter_param)

    # =========================================================================
    # Task Management
    # =========================================================================

    async def list_tasks(
        self,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List all tasks.

        FNDN: GET /task/task
        """
        params: dict[str, Any] = {}
        if filter:
            params["filter"] = filter

        result = await self.get("/task/task", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_task(self, task_id: int) -> dict[str, Any]:
        """Get task details.

        FNDN: GET /task/task/{task_id}
        """
        return await self.get(f"/task/task/{task_id}")

    async def get_task_line(self, task_id: int) -> list[dict[str, Any]]:
        """Get task line details.

        FNDN: GET /task/task/{task_id}/line
        """
        result = await self.get(f"/task/task/{task_id}/line")
        return result if isinstance(result, list) else [result] if result else []

    # =========================================================================
    # Device DB Revisions (issue: revision-tools)
    #
    # Live-published, non-deprecated "Deployment Manager" daemon commands --
    # docs/fndn/{7.6.7,8.0.0}/json_api_reference/swagger/dmserver.json (public
    # swagger, not just html-internal) and the matching FNDN HTML reference
    # both list get/device/revision, checkout/revision, export/config, and
    # revert with the exact request/response shape used below, with no
    # deprecation marker. (An earlier version of this comment claimed these
    # don't appear in the swagger set at all -- that search only grepped
    # cdb-device*/pkg*/dvmdb.json and missed dmserver.json, which doesn't have
    # an obviously-named file. The separate /dmworker/* daemon -- a different,
    # internal-only command family with similar-looking names like
    # config/checkout and get/dev/revision -- IS uniformly marked "depreciated
    # or not published" in html-internal/dmworker-objects.htm; don't confuse
    # the two.) Also confirmed against the How-To guide's "Device revisions"
    # section (docs/guides/.../007_device_management/007_device_management.rst).
    #
    # Live-verified 2026-08-14 against fmg-prod-01 (7.6.7-build3737): all four
    # calls succeed against a device with real device-DB revision history
    # (trafsim-fw-prod01, base_ver 151). get/device/revision and
    # checkout/revision return "Internal server error: runtime error 0:
    # invalid value" against a device that has never been installed to /
    # retrieved from and so has zero revisions on record (e.g. a freshly
    # added model device) -- that is an FMG-side edge case for an empty
    # revision table, not evidence the command itself is broken or removed.
    #
    # These operate on the device DB copy FortiManager keeps for each managed
    # device, never the live FortiGate: install_device_settings is still the
    # only path that pushes a device DB change to the appliance.
    # =========================================================================

    async def get_device_revisions(self, device: str) -> dict[str, Any]:
        """List the device DB revision history for one managed device.

        FNDN: EXEC /deployment/get/device/revision (How-To 007, "How to get
        the list of device revisions for a particular device?")

        Returns:
            {"base_ver": <int>, "revinfo": [{"revision": <int>, ...}, ...]}
        """
        return await self.execute("/deployment/get/device/revision", device=device)

    async def get_device_revision_content(self, device: str, revision: int) -> dict[str, Any]:
        """Check out one device DB revision's stored configuration text.

        FNDN: EXEC /deployment/checkout/revision (How-To 007, "How to get a
        specific device revision for a particular device?")

        Args:
            device: Managed device name
            revision: Revision number, or -1 for the latest revision

        Returns:
            {"content": <str>, "revision": <int>}
        """
        return await self.execute("/deployment/checkout/revision", device=device, revision=revision)

    async def get_device_current_config(self, device: str) -> dict[str, Any]:
        """Export the device's CURRENT device DB configuration (not a past revision).

        FNDN: EXEC /deployment/export/config (How-To 007, "How to get the
        current device database configuration for a particular device?")

        Returns:
            {"content": <str>}
        """
        return await self.execute("/deployment/export/config", device=device)

    async def revert_device_revision(self, device: str, revision: int) -> dict[str, Any]:
        """Revert a device's device DB to a past revision.

        This only rewrites FortiManager's own device DB copy for `device` --
        it does not touch the live FortiGate. Push the reverted device DB with
        install_device_settings the same way any other device DB edit is
        pushed.

        FNDN: EXEC /deployment/revert (How-To 007, "How to revert to a
        specific device revision?")
        """
        return await self.execute("/deployment/revert", device=device, revision=revision)

    # =========================================================================
    # Security Console - Installation Operations
    # =========================================================================

    async def install_package(
        self,
        adom: str,
        pkg: str,
        scope: list[dict[str, str]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Install a policy package to devices.

        FNDN: EXEC /securityconsole/install/package

        Args:
            adom: ADOM name
            pkg: Package name
            scope: Target devices [{"name": "FGT1", "vdom": "root"}, ...]
            flags: Install flags (e.g., ["none"], ["preview"])

        Returns:
            {"task": <task_id>} - Task ID for monitoring
        """
        data: dict[str, Any] = {
            "adom": adom,
            "pkg": pkg,
            "scope": scope,
        }
        if flags:
            data["flags"] = flags

        return await self.execute("/securityconsole/install/package", **data)

    async def install_device(
        self,
        adom: str,
        scope: list[dict[str, str]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Install device settings only (without policy package).

        FNDN: EXEC /securityconsole/install/device
        """
        data: dict[str, Any] = {
            "adom": adom,
            "scope": scope,
        }
        if flags:
            data["flags"] = flags

        return await self.execute("/securityconsole/install/device", **data)

    async def install_preview(
        self,
        adom: str,
        scope: list[dict[str, str]],
        flags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Preview installation before applying.

        FNDN: EXEC /securityconsole/install/preview

        Args:
            flags: Preview flags (e.g., ["json"] for JSON output)
        """
        data: dict[str, Any] = {
            "adom": adom,
            "scope": scope,
        }
        if flags:
            data["flags"] = flags

        return await self.execute("/securityconsole/install/preview", **data)

    async def get_preview_result(
        self,
        adom: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Get preview result after install/preview completes.

        FNDN: EXEC /securityconsole/preview/result
        """
        return await self.execute(
            "/securityconsole/preview/result",
            adom=adom,
            scope=scope,
        )

    # =========================================================================
    # Cache Diff -- ADOM/package revision comparison (issue: revision-tools)
    #
    # Not in the FNDN swagger set -- no cache*.json exists there. Confirmed
    # against the How-To guide's "How to diff an ADOM revision with current
    # configuration?" section (docs/guides/.../013_adom_management.rst), the
    # only documented way to diff a past revision against the live ADOM/
    # package. Read-only: nothing here writes to the ADOM, device, or package.
    # =========================================================================

    async def cache_diff_start(self, dst: str, src: str) -> dict[str, Any]:
        """Start an ADOM-DB diff job between two revision paths.

        FNDN: EXEC /cache/diff/start (How-To 013, "How to diff an ADOM
        revision with current configuration?")

        Args:
            dst: Comparison target, e.g. "adom/{adom}" for the live ADOM
            src: Comparison source, e.g. "adom/{adom}/revision/{revision}"

        Returns:
            {"token": <str>} -- pass to cache_diff_get_summary/cache_diff_end
        """
        return await self.execute("/cache/diff/start", dst=dst, src=src)

    async def cache_diff_get_summary(self, token: str, pkg: str | None = None) -> dict[str, Any]:
        """Poll a diff job's summary; check `percent` for completion.

        FNDN: EXEC /cache/diff/get/summary[/pkg/{pkg}] (How-To 013). `token`
        must be a sibling of `url` in the request body, not nested under
        `data` -- see FortiManagerClient._flat_request.

        Args:
            token: Token returned by cache_diff_start
            pkg: Scope the summary to one policy package instead of the
                whole ADOM (matches /cache/diff/get/summary/pkg/{pkg})

        Returns:
            {"percent": <int 0-100>, "obj": {...}, "pkg": {...}} -- the diff is
            not ready until "percent" reaches 100
        """
        url = "/cache/diff/get/summary"
        if pkg:
            url = f"{url}/pkg/{pkg}"
        return await self._flat_request("execute", url, {"token": token})

    async def cache_diff_end(self, token: str) -> dict[str, Any]:
        """Close a diff job and free its server-side cache entry.

        FNDN: EXEC cache/diff/end (How-To 013: "Always good to end the diff
        task")
        """
        return await self._flat_request("execute", "cache/diff/end", {"token": token})

    async def where_used_start(self, mkey: str, obj: str) -> dict[str, Any]:
        """Start a where-used search job for an ADOM object.

        FNDN: EXEC /cache/search/where/used/start (How-To 002, "Operations
        on objects"). `mkey`/`obj` are start-time parameters, not a
        token -- unlike the summary/detail polling calls below, this one
        matches cache_diff_start's shape (plain nested-under-'data' exec),
        not the sibling-of-'url' shape those need.

        Returns:
            {"token": <str>} -- pass to where_used_get_summary/get_detail
        """
        return await self.execute("/cache/search/where/used/start", mkey=mkey, obj=obj)

    async def where_used_get_summary(self, token: str) -> dict[str, Any]:
        """Poll a where-used search job's progress; check `percent` for completion.

        FNDN: EXEC /cache/search/where/used/get/summary (How-To 002).
        `token` must be a sibling of `url` in the request body, not nested
        under `data` -- same shape requirement as cache_diff_get_summary,
        same underlying cache-daemon token-polling family -- see
        FortiManagerClient._flat_request.
        """
        return await self._flat_request(
            "execute", "/cache/search/where/used/get/summary", {"token": token}
        )

    async def where_used_get_detail(self, token: str) -> dict[str, Any]:
        """Fetch a completed where-used search job's results.

        FNDN: EXEC /cache/search/where/used/get/detail (How-To 002). Same
        sibling-of-'url' token shape as where_used_get_summary -- see
        FortiManagerClient._flat_request.
        """
        return await self._flat_request(
            "execute", "/cache/search/where/used/get/detail", {"token": token}
        )

    # =========================================================================
    # Policy Package Management
    # =========================================================================

    async def list_packages(
        self,
        adom: str = "root",
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List policy packages in ADOM.

        FNDN: GET /pm/pkg/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/pkg/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_package(
        self,
        adom: str,
        pkg: str,
        loadsub: int = 0,
    ) -> dict[str, Any]:
        """Get policy package details.

        FNDN: GET /pm/pkg/adom/{adom}/{pkg}
        """
        return await self.get(f"/pm/pkg/adom/{adom}/{pkg}", loadsub=loadsub)

    async def create_package(
        self,
        adom: str,
        name: str,
        package_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new policy package.

        FNDN: ADD /pm/pkg/adom/{adom}
        """
        data: dict[str, Any] = {
            "name": name,
            "type": "pkg",
        }
        if package_settings:
            data["package settings"] = package_settings

        return await self.add(f"/pm/pkg/adom/{adom}", data=data)

    async def delete_package(
        self,
        adom: str,
        pkg: str,
    ) -> dict[str, Any]:
        """Delete a policy package.

        FNDN: DELETE /pm/pkg/adom/{adom}/{pkg}
        """
        return await self.delete(f"/pm/pkg/adom/{adom}/{pkg}")

    async def clone_package(
        self,
        adom: str,
        pkg: str,
        new_name: str,
    ) -> dict[str, Any]:
        """Clone a policy package.

        FNDN: EXEC /securityconsole/package/clone
        """
        return await self.execute(
            "/securityconsole/package/clone",
            adom=adom,
            pkg=pkg,
            new_name=new_name,
        )

    async def assign_package(
        self,
        adom: str,
        pkg: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign package to devices.

        FNDN: UPDATE /pm/pkg/adom/{adom}/{pkg}
        """
        return await self.update(f"/pm/pkg/adom/{adom}/{pkg}", **{"scope member": scope})

    # =========================================================================
    # Firewall Policies
    # =========================================================================

    async def list_firewall_policies(
        self,
        adom: str,
        pkg: str,
        fields: list[str] | None = None,
        filter: list | None = None,
        loadsub: int = 0,
        range: list[int] | None = None,
    ) -> list[dict[str, Any]]:
        """List firewall policies in a package.

        FNDN: GET /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy
        """
        params: dict[str, Any] = {"loadsub": loadsub}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter
        if range:
            params["range"] = range

        result = await self.get(f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
        loadsub: int = 0,
    ) -> dict[str, Any]:
        """Get a specific firewall policy.

        FNDN: GET /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}
        """
        return await self.get(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
            loadsub=loadsub,
        )

    async def get_firewall_policy_count(
        self,
        adom: str,
        pkg: str,
    ) -> int:
        """Get count of firewall policies in a package.

        FNDN: GET /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy with option=count
        """
        result = await self.get(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
            option=["count"],
        )
        return result if isinstance(result, int) else 0

    async def create_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policy: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a new firewall policy.

        FNDN: ADD /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy
        """
        return await self.add(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
            data=policy,
        )

    async def update_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a firewall policy.

        FNDN: UPDATE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
            **data,
        )

    async def delete_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
    ) -> dict[str, Any]:
        """Delete a firewall policy.

        FNDN: DELETE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
        )

    async def delete_firewall_policies(
        self,
        adom: str,
        pkg: str,
        policyids: list[int],
    ) -> dict[str, Any]:
        """Delete multiple firewall policies.

        FNDN: DELETE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy with filter
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",
            confirm=1,
            filter=["policyid", "in"] + policyids,
        )

    async def move_firewall_policy(
        self,
        adom: str,
        pkg: str,
        policyid: int,
        target: int,
        option: str = "before",
    ) -> dict[str, Any]:
        """Move a firewall policy before or after another policy.

        FNDN: MOVE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}

        Args:
            adom: ADOM name
            pkg: Policy package name
            policyid: Policy ID to move
            target: Target policy ID (move before/after this)
            option: "before" or "after"

        Returns:
            {"policyid": <moved_policyid>}
        """
        return await self.move(
            f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
            option,
            str(target),
        )

    # =========================================================================
    # Firewall Policy Revisions (issue: revision-tools)
    #
    # Not in the FNDN swagger set -- no path in pkg*.json covers `_objrev`.
    # Confirmed against the How-To guide's "Policy Package Revision" /
    # "Firewall Policy Revision" sections (docs/guides/.../
    # 008_policy_package_management.rst). There is no dedicated revert
    # endpoint for a firewall policy; the guide's documented mechanism is to
    # capture a past change's `config` snapshot from this change log and
    # `update` the live policy with it.
    # =========================================================================

    async def list_policy_revisions(
        self,
        adom: str,
        pkg: str,
        policyid: int | None = None,
    ) -> list[dict[str, Any]]:
        """List the change log for a package's firewall policies, or one policy.

        FNDN: GET /pm/config/adom/{adom}/_objrev/pkg/{pkg}/firewall/policy[/{policyid}]
        (How-To 008, "How to get list of changes made on a Policy Package?" /
        "How to get list of changes made in a firewall policy?")

        Each entry's ``act`` is 1 (created), 2 (deleted) or 3 (modified);
        ``key`` is the policyid; ``config`` is the JSON-encoded policy
        snapshot at that change -- the value to hand to
        revert_firewall_policy_snapshot.

        Returns:
            List of change-log entries, oldest first
        """
        url = f"/pm/config/adom/{adom}/_objrev/pkg/{pkg}/firewall/policy"
        if policyid is not None:
            url = f"{url}/{policyid}"
        result = await self.get(url)
        return result if isinstance(result, list) else [result] if result else []

    async def revert_firewall_policy_snapshot(
        self,
        adom: str,
        pkg: str,
        config: dict[str, Any],
        revision_note: str | None = None,
    ) -> dict[str, Any]:
        """Restore a firewall policy to a past change-log snapshot.

        `config` must be a snapshot captured from list_policy_revisions
        (its ``policyid`` selects which policy is updated; no policyid is
        appended to the URL -- the guide's example targets the package's
        policy collection directly). `revision_note` must be a sibling of
        `url`/`data`, not nested inside `data` -- see
        FortiManagerClient._flat_request.

        FNDN: UPDATE /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy (How-To
        008, "How to revert a firewall policy from a past changes?")
        """
        url = f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy"
        payload: dict[str, Any] = {"data": config}
        if revision_note:
            payload["revision note"] = revision_note
        return await self._flat_request("update", url, payload)

    # =========================================================================
    # Firewall Objects - Addresses
    # =========================================================================

    async def list_addresses(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List firewall address objects.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/address
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/firewall/address", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_address(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific firewall address.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/address/{name}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/firewall/address/{name}")

    async def create_address(
        self,
        adom: str,
        address: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a firewall address object.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/address
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/address",
            data=address,
        )

    async def update_address(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a firewall address object.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/address/{name}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/address/{name}",
            **data,
        )

    async def delete_address(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a firewall address object.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/address/{name}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/firewall/address/{name}")

    # =========================================================================
    # Firewall Objects - Address Groups
    # =========================================================================

    async def list_address_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List firewall address groups.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/addrgrp
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/firewall/addrgrp", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_address_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific address group.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/addrgrp/{name}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{name}")

    async def create_address_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an address group.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/addrgrp
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/addrgrp",
            data=group,
        )

    async def update_address_group(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an address group.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/addrgrp/{name}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{name}",
            **data,
        )

    async def delete_address_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete an address group.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/addrgrp/{name}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/firewall/addrgrp/{name}")

    # =========================================================================
    # Firewall Objects - Services
    # =========================================================================

    async def list_services(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List custom service objects.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/custom
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/firewall/service/custom", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_service(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific service object.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/custom/{name}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/firewall/service/custom/{name}")

    async def create_service(
        self,
        adom: str,
        service: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a custom service object.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/service/custom
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/service/custom",
            data=service,
        )

    async def update_service(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a service object.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/service/custom/{name}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/service/custom/{name}",
            **data,
        )

    async def delete_service(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a service object.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/service/custom/{name}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/firewall/service/custom/{name}")

    # =========================================================================
    # Firewall Objects - Service Groups
    # =========================================================================

    async def list_service_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List service groups.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/group
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/firewall/service/group", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_service_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific service group.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/service/group/{name}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/firewall/service/group/{name}")

    async def create_service_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a service group.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/service/group
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/firewall/service/group",
            data=group,
        )

    async def update_service_group(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a service group.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/service/group/{name}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/service/group/{name}",
            **data,
        )

    async def delete_service_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a service group.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/service/group/{name}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/firewall/service/group/{name}")

    # =========================================================================
    # Security Profiles - IPS Sensor
    # =========================================================================

    async def list_ips_sensors(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List IPS sensors.

        FNDN: GET /pm/config/adom/{adom}/obj/ips/sensor
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/ips/sensor", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_ips_sensor(self, adom: str, name: str) -> dict[str, Any]:
        """Get a specific IPS sensor.

        FNDN: GET /pm/config/adom/{adom}/obj/ips/sensor/{sensor}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/ips/sensor/{name}")

    async def create_ips_sensor(self, adom: str, sensor: dict[str, Any]) -> dict[str, Any]:
        """Create an IPS sensor.

        FNDN: ADD /pm/config/adom/{adom}/obj/ips/sensor
        """
        return await self.add(f"/pm/config/adom/{adom}/obj/ips/sensor", data=sensor)

    async def update_ips_sensor(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an IPS sensor.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/ips/sensor/{sensor}
        """
        return await self.update(f"/pm/config/adom/{adom}/obj/ips/sensor/{name}", **data)

    async def delete_ips_sensor(self, adom: str, name: str) -> dict[str, Any]:
        """Delete an IPS sensor.

        FNDN: DELETE /pm/config/adom/{adom}/obj/ips/sensor/{sensor}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/ips/sensor/{name}")

    async def list_ips_sensor_entries(self, adom: str, sensor: str) -> list[dict[str, Any]]:
        """List the signature-override entries of an IPS sensor.

        FNDN: GET /pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries
        """
        result = await self.get(f"/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries")
        return result if isinstance(result, list) else [result] if result else []

    async def add_ips_sensor_entry(
        self,
        adom: str,
        sensor: str,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Add a signature-override entry to an IPS sensor.

        This is the entries sub-resource's own ADD endpoint, not a
        read-modify-write of the parent sensor -- FMG exposes
        ``entries`` as an addressable nested collection with its own
        add/get/set/update/delete/move verbs (confirmed in the FNDN
        swagger), so appending here does not require reading the sensor
        first the way a plain array field would.

        FNDN: ADD /pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries
        """
        return await self.add(f"/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries", data=entry)

    async def delete_ips_sensor_entry(
        self,
        adom: str,
        sensor: str,
        entry_id: int,
    ) -> dict[str, Any]:
        """Remove a signature-override entry from an IPS sensor.

        FNDN: DELETE /pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}
        """
        return await self.delete(
            f"/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entry_id}"
        )

    # =========================================================================
    # Security Profiles - SSL/SSH Inspection Profile
    # =========================================================================

    async def list_ssl_ssh_profiles(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List SSL/SSH inspection profiles.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_ssl_ssh_profile(self, adom: str, name: str) -> dict[str, Any]:
        """Get a specific SSL/SSH inspection profile.

        FNDN: GET /pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{name}")

    async def create_ssl_ssh_profile(self, adom: str, profile: dict[str, Any]) -> dict[str, Any]:
        """Create an SSL/SSH inspection profile.

        FNDN: ADD /pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile
        """
        return await self.add(f"/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile", data=profile)

    async def update_ssl_ssh_profile(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an SSL/SSH inspection profile.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}
        """
        return await self.update(
            f"/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{name}", **data
        )

    async def delete_ssl_ssh_profile(self, adom: str, name: str) -> dict[str, Any]:
        """Delete an SSL/SSH inspection profile.

        FNDN: DELETE /pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{name}")

    # =========================================================================
    # Security Profiles - DLP Profile
    # =========================================================================

    async def list_dlp_profiles(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List DLP profiles.

        FNDN: GET /pm/config/adom/{adom}/obj/dlp/profile
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/dlp/profile", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_dlp_profile(self, adom: str, name: str) -> dict[str, Any]:
        """Get a specific DLP profile.

        FNDN: GET /pm/config/adom/{adom}/obj/dlp/profile/{profile}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/dlp/profile/{name}")

    async def create_dlp_profile(self, adom: str, profile: dict[str, Any]) -> dict[str, Any]:
        """Create a DLP profile.

        FNDN: ADD /pm/config/adom/{adom}/obj/dlp/profile
        """
        return await self.add(f"/pm/config/adom/{adom}/obj/dlp/profile", data=profile)

    async def update_dlp_profile(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a DLP profile.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/dlp/profile/{profile}
        """
        return await self.update(f"/pm/config/adom/{adom}/obj/dlp/profile/{name}", **data)

    async def delete_dlp_profile(self, adom: str, name: str) -> dict[str, Any]:
        """Delete a DLP profile.

        FNDN: DELETE /pm/config/adom/{adom}/obj/dlp/profile/{profile}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/dlp/profile/{name}")

    # =========================================================================
    # Security Profiles - WAF Profile
    # =========================================================================

    async def list_waf_profiles(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List WAF profiles.

        FNDN: GET /pm/config/adom/{adom}/obj/waf/profile
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = filter

        result = await self.get(f"/pm/config/adom/{adom}/obj/waf/profile", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_waf_profile(self, adom: str, name: str) -> dict[str, Any]:
        """Get a specific WAF profile.

        FNDN: GET /pm/config/adom/{adom}/obj/waf/profile/{profile}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/waf/profile/{name}")

    async def create_waf_profile(self, adom: str, profile: dict[str, Any]) -> dict[str, Any]:
        """Create a WAF profile.

        FNDN: ADD /pm/config/adom/{adom}/obj/waf/profile
        """
        return await self.add(f"/pm/config/adom/{adom}/obj/waf/profile", data=profile)

    async def update_waf_profile(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a WAF profile.

        FNDN: UPDATE /pm/config/adom/{adom}/obj/waf/profile/{profile}
        """
        return await self.update(f"/pm/config/adom/{adom}/obj/waf/profile/{name}", **data)

    async def delete_waf_profile(self, adom: str, name: str) -> dict[str, Any]:
        """Delete a WAF profile.

        FNDN: DELETE /pm/config/adom/{adom}/obj/waf/profile/{profile}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/waf/profile/{name}")

    # =========================================================================
    # Workspace Mode (ADOM Locking)
    # =========================================================================

    async def lock_adom(self, adom: str) -> dict[str, Any]:
        """Lock an ADOM for editing (workspace mode).

        FNDN: EXEC /dvmdb/adom/{adom}/workspace/lock
        """
        return await self.execute(f"/dvmdb/adom/{adom}/workspace/lock")

    async def unlock_adom(self, adom: str) -> dict[str, Any]:
        """Unlock an ADOM (workspace mode).

        FNDN: EXEC /dvmdb/adom/{adom}/workspace/unlock
        """
        return await self.execute(f"/dvmdb/adom/{adom}/workspace/unlock")

    async def commit_adom(self, adom: str) -> dict[str, Any]:
        """Commit changes to an ADOM (workspace mode).

        FNDN: EXEC /dvmdb/adom/{adom}/workspace/commit
        """
        return await self.execute(f"/dvmdb/adom/{adom}/workspace/commit")

    # =========================================================================
    # Device Proxy - Execute Commands on Managed Devices
    # =========================================================================

    async def proxy_call(
        self,
        action: str,
        resource: str,
        target: list[str],
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute REST API call on managed device via FortiManager proxy.

        FNDN: EXEC /sys/proxy/json

        Args:
            action: HTTP method (get, post, put, delete)
            resource: FortiGate API endpoint (e.g., /api/v2/monitor/system/status)
            target: Target path ["/adom/{adom}/device/{device}"]
            data: Request data for POST/PUT operations

        Example:
            >>> # Get device status
            >>> result = await client.proxy_call(
            ...     action="get",
            ...     resource="/api/v2/monitor/system/status",
            ...     target=["/adom/root/device/FGT1"]
            ... )
        """
        params: dict[str, Any] = {
            "action": action,
            "resource": resource,
            "target": target,
        }
        if data:
            params["data"] = data

        return await self.execute("/sys/proxy/json", **params)

    # =========================================================================
    # CLI Script Management
    # =========================================================================

    async def list_scripts(
        self,
        adom: str,
        fields: list[str] | None = None,
        filter: list | None = None,
    ) -> list[dict[str, Any]]:
        """List CLI scripts in an ADOM.

        Uses version-aware endpoint:
        - FMG 7.6+: /pm/config/adom/{adom}/obj/fmg/script
        - FMG 7.0-7.4: /dvmdb/adom/{adom}/script
        """
        await self._detect_version()
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if filter:
            params["filter"] = self._map_script_target_filter(filter)

        result = await self.get(self._script_base_url(adom), **params)
        if isinstance(result, list):
            scripts = result
        elif result:
            scripts = [result]
        else:
            scripts = []
        # Reverse-map int targets to strings so the public API stays
        # string-typed regardless of the underlying endpoint version.
        return [self._unmap_script_target(s) for s in scripts]

    async def get_script(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific CLI script.

        Uses version-aware endpoint (see list_scripts).
        """
        await self._detect_version()
        result = await self.get(f"{self._script_base_url(adom)}/{name}")
        return self._unmap_script_target(result)

    async def create_script(
        self,
        adom: str,
        script: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a CLI script.

        Uses version-aware endpoint (see list_scripts).

        Script dict should contain:
            - name: Script name (required)
            - content: Script content (required)
            - type: cli, tcl, cligrp, tclgrp, jinja
            - target: device_database, remote_device, adom_database
            - desc: Description
        """
        await self._detect_version()
        script = self._map_script_target(script)
        return await self.add(self._script_base_url(adom), data=script)

    async def update_script(
        self,
        adom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a CLI script.

        Uses version-aware endpoint (see list_scripts).
        """
        await self._detect_version()
        data = self._map_script_target(data)
        return await self.update(f"{self._script_base_url(adom)}/{name}", data=data)

    async def delete_script(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a CLI script.

        Uses version-aware endpoint (see list_scripts).
        """
        await self._detect_version()
        return await self.delete(f"{self._script_base_url(adom)}/{name}")

    async def execute_script(
        self,
        adom: str,
        script: str,
        scope: list[dict[str, str]] | None = None,
        package: str | int | None = None,
    ) -> dict[str, Any]:
        """Execute a CLI script.

        FNDN: EXEC /dvmdb/adom/{adom}/script/execute

        Args:
            adom: ADOM name
            script: Script name to execute
            scope: Target devices [{"name": "device", "vdom": "global"}] for remote execution
                   Or device groups [{"name": "group_name"}] (no vdom means device group)
            package: Package name or OID for adom_database target scripts

        Returns:
            {"task": <task_id>} - Task ID for monitoring execution
        """
        data: dict[str, Any] = {
            "adom": adom,
            "script": script,
        }
        if scope:
            data["scope"] = scope
        if package:
            data["package"] = package

        return await self.execute(f"/dvmdb/adom/{adom}/script/execute", **data)

    async def get_script_log_latest(
        self,
        adom: str,
        device: str | None = None,
    ) -> dict[str, Any]:
        """Get latest script execution log.

        FNDN: GET /dvmdb/adom/{adom}/script/log/latest[/device/{device}]
        """
        url = f"/dvmdb/adom/{adom}/script/log/latest"
        if device:
            url += f"/device/{device}"
        return await self.get(url)

    async def get_script_log_summary(
        self,
        adom: str,
        device: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get script execution log summary.

        FNDN: GET /dvmdb/adom/{adom}/script/log/summary[/device/{device}]
        """
        url = f"/dvmdb/adom/{adom}/script/log/summary"
        if device:
            url += f"/device/{device}"
        result = await self.get(url)
        return result if isinstance(result, list) else [result] if result else []

    async def get_script_log_output(
        self,
        adom: str,
        log_id: int,
        device: str | None = None,
    ) -> dict[str, Any]:
        """Get specific script execution output.

        FNDN: GET /dvmdb/adom/{adom}/script/log/output/[device/{device}/]logid/{log_id}
        """
        if device:
            url = f"/dvmdb/adom/{adom}/script/log/output/device/{device}/logid/{log_id}"
        else:
            url = f"/dvmdb/adom/{adom}/script/log/output/logid/{log_id}"
        return await self.get(url)

    # =========================================================================
    # Provisioning Templates
    # =========================================================================

    async def list_templates(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List all provisioning templates in an ADOM.

        FNDN: GET /pm/template/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/template/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific provisioning template.

        FNDN: GET /pm/template/adom/{adom}/{name}
        """
        return await self.get(f"/pm/template/adom/{adom}/{name}")

    async def list_system_templates(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List system templates (devprof) in an ADOM.

        FNDN: GET /pm/devprof/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/devprof/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_system_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific system template.

        FNDN: GET /pm/devprof/adom/{adom}/{name}
        """
        return await self.get(f"/pm/devprof/adom/{adom}/{name}")

    async def assign_system_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign system template to devices.

        FNDN: ADD /pm/devprof/adom/{adom}/{template}/scope member

        Args:
            scope: [{"name": "device", "vdom": "root"}, ...]
        """
        return await self.add(
            f"/pm/devprof/adom/{adom}/{template}/scope member",
            data=scope,
        )

    async def unassign_system_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Unassign system template from devices.

        FNDN: DELETE /pm/devprof/adom/{adom}/{template}/scope member
        """
        return await self.delete(
            f"/pm/devprof/adom/{adom}/{template}/scope member",
            data=scope,
        )

    async def list_cli_template_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List CLI template groups.

        FNDN: GET /pm/config/adom/{adom}/obj/cli/template-group
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/config/adom/{adom}/obj/cli/template-group", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_cli_template_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific CLI template group.

        FNDN: GET /pm/config/adom/{adom}/obj/cli/template-group/{name}
        """
        return await self.get(f"/pm/config/adom/{adom}/obj/cli/template-group/{name}")

    async def create_cli_template_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a CLI template group.

        FNDN: ADD /pm/config/adom/{adom}/obj/cli/template-group
        """
        return await self.add(
            f"/pm/config/adom/{adom}/obj/cli/template-group",
            data=group,
        )

    async def delete_cli_template_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a CLI template group.

        FNDN: DELETE /pm/config/adom/{adom}/obj/cli/template-group/{name}
        """
        return await self.delete(f"/pm/config/adom/{adom}/obj/cli/template-group/{name}")

    async def list_template_groups(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List template groups (tmplgrp).

        FNDN: GET /pm/tmplgrp/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/tmplgrp/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_template_group(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific template group.

        FNDN: GET /pm/tmplgrp/adom/{adom}/{name}
        """
        return await self.get(f"/pm/tmplgrp/adom/{adom}/{name}")

    async def create_template_group(
        self,
        adom: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a template group.

        FNDN: ADD /pm/tmplgrp/adom/{adom}
        """
        return await self.add(f"/pm/tmplgrp/adom/{adom}", data=group)

    async def assign_template_group(
        self,
        adom: str,
        template_group: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign template group to devices.

        FNDN: ADD /pm/tmplgrp/adom/{adom}/{template_group}/scope member
        """
        return await self.add(
            f"/pm/tmplgrp/adom/{adom}/{template_group}/scope member",
            data=scope,
        )

    async def validate_template(
        self,
        adom: str,
        pkg: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Validate a template for devices.

        FNDN: EXEC /securityconsole/template/validate

        Args:
            pkg: Template path (e.g., "adom/demo/tmplgrp/template_group_001")
            scope: Target devices [{"name": "device", "vdom": "root"}]

        Returns:
            {"task": <task_id>} for monitoring validation
        """
        return await self.execute(
            "/securityconsole/template/validate",
            adom=adom,
            flag="json",
            pkg=pkg,
            scope=scope,
        )

    # =========================================================================
    # SD-WAN Templates
    # =========================================================================

    async def list_sdwan_templates(
        self,
        adom: str,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List SD-WAN templates (wanprof).

        FNDN: GET /pm/wanprof/adom/{adom}
        """
        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        result = await self.get(f"/pm/wanprof/adom/{adom}", **params)
        return result if isinstance(result, list) else [result] if result else []

    async def get_sdwan_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Get a specific SD-WAN template.

        FNDN: GET /pm/wanprof/adom/{adom}/{name}
        """
        return await self.get(f"/pm/wanprof/adom/{adom}/{name}")

    async def get_device_sdwan(
        self,
        device: str,
        vdom: str = "root",
    ) -> dict[str, Any]:
        """Get the device-DB SD-WAN config for a managed device.

        Reads the SD-WAN configuration FortiManager holds in its device
        database -- members/zones, health-checks and service (steering)
        rules -- which is local to the device rather than a wanprof template.
        Use when a device runs SD-WAN but no template is assigned
        (``list_sdwan_templates`` returns nothing).

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/system/sdwan
        """
        return await self.get(f"/pm/config/device/{device}/vdom/{vdom}/system/sdwan")

    async def get_device_interface_config(
        self,
        device: str,
        vlanids: list[int] | None = None,
        name: str | None = None,
    ) -> Any:
        """Get device-DB interface config objects, optionally filtered.

        Reads the interface CONFIG objects FortiManager holds in its device
        database (distinct from the live monitor proxy used by
        ``get_device_interfaces``). Supports server-side filtering by exact
        interface name and/or by VLAN id.

        The ``filter`` param uses the FMG filter-array dialect (see
        ``common.filter.object`` in cdb-device76.json). A single clause is a
        flat array (``["name", "==", "wan1"]`` /
        ``["vlanid", "in", 10, 20]``); combining both uses the compound form
        ``[<clause>, "&&", <clause>]``.

        FNDN: GET /pm/config/device/{device}/global/system/interface
        """
        url = f"/pm/config/device/{device}/global/system/interface"
        name_clause = ["name", "==", name] if name else None
        vlan_clause = ["vlanid", "in", *vlanids] if vlanids else None
        params: dict[str, Any] = {}
        if name_clause and vlan_clause:
            params["filter"] = [name_clause, "&&", vlan_clause]
        elif name_clause:
            params["filter"] = name_clause
        elif vlan_clause:
            params["filter"] = vlan_clause
        return await self.get(url, **params)

    async def resolve_datasource(
        self,
        url: str,
        attr: str,
    ) -> Any:
        """Resolve the objects an attribute can reference (``option: datasrc``).

        Generic config-DB introspection: for a given cdb table ``url`` and an
        attribute name ``attr``, FortiManager returns every object that
        ``attr`` is allowed to reference. Documented generically in the swagger
        cdb get-params (``params.cdb.get.table.option.opts`` -> ``datasrc``,
        which requires the ``attr`` parameter).

        FNDN: GET <cdb url> with option=datasrc, attr=<attr>
        """
        return await self.get(url, attr=attr, option="datasrc")

    async def create_sdwan_template(
        self,
        adom: str,
        template: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an SD-WAN template.

        FNDN: ADD /pm/wanprof/adom/{adom}
        """
        return await self.add(f"/pm/wanprof/adom/{adom}", data=template)

    async def delete_sdwan_template(
        self,
        adom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete an SD-WAN template.

        FNDN: DELETE /pm/wanprof/adom/{adom}/{name}
        """
        return await self.delete(f"/pm/wanprof/adom/{adom}/{name}")

    async def assign_sdwan_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Assign SD-WAN template to devices.

        FNDN: ADD /pm/wanprof/adom/{adom}/{template}/scope member
        """
        return await self.add(
            f"/pm/wanprof/adom/{adom}/{template}/scope member",
            data=scope,
        )

    async def unassign_sdwan_template(
        self,
        adom: str,
        template: str,
        scope: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Unassign SD-WAN template from devices.

        FNDN: DELETE /pm/wanprof/adom/{adom}/{template}/scope member
        """
        return await self.delete(
            f"/pm/wanprof/adom/{adom}/{template}/scope member",
            data=scope,
        )

    # =========================================================================
    # Device-DB Configuration (issue #45)
    # =========================================================================

    async def create_device_interface(
        self,
        device: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create an interface object in a device's device DB (global scope).

        FNDN: ADD /pm/config/device/{device}/global/system/interface
        """
        return await self.add(
            f"/pm/config/device/{device}/global/system/interface",
            data=data,
        )

    async def update_device_interface(
        self,
        device: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device-DB interface object.

        FNDN: UPDATE /pm/config/device/{device}/global/system/interface/{name}
        """
        return await self.update(
            f"/pm/config/device/{device}/global/system/interface/{name}",
            data=data,
        )

    async def delete_device_interface(
        self,
        device: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a device-DB interface object.

        FNDN: DELETE /pm/config/device/{device}/global/system/interface/{name}
        """
        return await self.delete(
            f"/pm/config/device/{device}/global/system/interface/{name}",
        )

    async def list_device_dhcp_servers(
        self,
        device: str,
        vdom: str = "root",
    ) -> Any:
        """List DHCP servers in a device's device DB (vdom scope).

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/system/dhcp/server
        """
        return await self.get(f"/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server")

    async def create_device_dhcp_server(
        self,
        device: str,
        vdom: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a DHCP server in a device's device DB.

        FNDN: ADD /pm/config/device/{device}/vdom/{vdom}/system/dhcp/server
        """
        return await self.add(
            f"/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server",
            data=data,
        )

    async def update_device_dhcp_server(
        self,
        device: str,
        vdom: str,
        server_id: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device-DB DHCP server by id.

        FNDN: UPDATE /pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{id}
        """
        return await self.update(
            f"/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server_id}",
            data=data,
        )

    async def delete_device_dhcp_server(
        self,
        device: str,
        vdom: str,
        server_id: int,
    ) -> dict[str, Any]:
        """Delete a device-DB DHCP server by id.

        FNDN: DELETE /pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{id}
        """
        return await self.delete(
            f"/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server_id}",
        )

    async def list_device_vaps(
        self,
        device: str,
        vdom: str = "root",
    ) -> Any:
        """List wireless VAPs (SSIDs) in a device's device DB.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap
        """
        return await self.get(f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap")

    async def get_device_vap(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> Any:
        """Get a device-DB wireless VAP (SSID) by name.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{name}

        Separate from ``list_device_vaps`` on purpose: reading one VAP's
        security mode through the collection would haul every VAP on the
        device across the wire, each carrying its encrypted ``passphrase``
        and ``sae-password`` blobs, to look at a single field.
        """
        return await self.get(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{name}",
        )

    async def create_device_vap(
        self,
        device: str,
        vdom: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a wireless VAP (SSID) in a device's device DB.

        FNDN: ADD /pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap
        """
        return await self.add(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap",
            data=data,
        )

    async def delete_device_vap(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a device-DB wireless VAP by name.

        FNDN: DELETE /pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{name}
        """
        return await self.delete(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{name}",
        )

    async def get_device_wtp_profile(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> Any:
        """Get a device-DB FortiAP (WTP) profile by name.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{name}
        """
        return await self.get(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{name}",
        )

    async def update_device_wtp_profile(
        self,
        device: str,
        vdom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device-DB FortiAP (WTP) profile.

        FNDN: UPDATE /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{name}
        """
        return await self.update(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{name}",
            data=data,
        )

    async def list_device_wtp_profiles(
        self,
        device: str,
        vdom: str = "root",
    ) -> Any:
        """List device-DB FortiAP (WTP) profiles.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile
        """
        return await self.get(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile",
        )

    async def list_device_wtps(
        self,
        device: str,
        vdom: str = "root",
    ) -> Any:
        """List managed FortiAPs (wireless-controller wtp) in a device's device DB.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp
        """
        return await self.get(f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp")

    async def get_device_wtp(
        self,
        device: str,
        vdom: str,
        wtp_id: str,
    ) -> Any:
        """Get one managed FortiAP by wtp-id (serial number).

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp_id}
        """
        return await self.get(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp_id}",
        )

    async def create_device_wtp(
        self,
        device: str,
        vdom: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Register a managed FortiAP in a device's device DB.

        FNDN: ADD /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp
        """
        return await self.add(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp",
            data=data,
        )

    async def update_device_wtp(
        self,
        device: str,
        vdom: str,
        wtp_id: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device-DB managed FortiAP by wtp-id (serial number).

        FNDN: UPDATE /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp_id}
        """
        return await self.update(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp_id}",
            data=data,
        )

    async def delete_device_wtp(
        self,
        device: str,
        vdom: str,
        wtp_id: str,
    ) -> dict[str, Any]:
        """Delete a device-DB managed FortiAP by wtp-id (serial number).

        FNDN: DELETE /pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp_id}
        """
        return await self.delete(
            f"/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp_id}",
        )

    # =========================================================================
    # VPN: IPsec phase1/phase2 interfaces, SSL-VPN settings/portal (device DB)
    # =========================================================================

    async def list_device_ipsec_phase1_interfaces(
        self,
        device: str,
        vdom: str = "root",
    ) -> Any:
        """List device-DB IPsec phase1-interface (remote gateway) definitions.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface
        """
        return await self.get(f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface")

    async def get_device_ipsec_phase1_interface(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> Any:
        """Get a device-DB IPsec phase1-interface by name.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{name}
        """
        return await self.get(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{name}",
        )

    async def create_device_ipsec_phase1_interface(
        self,
        device: str,
        vdom: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a device-DB IPsec phase1-interface (remote gateway).

        FNDN: ADD /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface
        """
        return await self.add(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface",
            data=data,
        )

    async def update_device_ipsec_phase1_interface(
        self,
        device: str,
        vdom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device-DB IPsec phase1-interface.

        FNDN: UPDATE /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{name}
        """
        return await self.update(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{name}",
            data=data,
        )

    async def delete_device_ipsec_phase1_interface(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a device-DB IPsec phase1-interface.

        FNDN: DELETE /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{name}
        """
        return await self.delete(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{name}",
        )

    async def list_device_ipsec_phase2_interfaces(
        self,
        device: str,
        vdom: str = "root",
    ) -> Any:
        """List device-DB IPsec phase2-interface (tunnel/selector) definitions.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface
        """
        return await self.get(f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface")

    async def get_device_ipsec_phase2_interface(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> Any:
        """Get a device-DB IPsec phase2-interface by name.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{name}
        """
        return await self.get(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{name}",
        )

    async def create_device_ipsec_phase2_interface(
        self,
        device: str,
        vdom: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a device-DB IPsec phase2-interface (tunnel/selector).

        FNDN: ADD /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface
        """
        return await self.add(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface",
            data=data,
        )

    async def update_device_ipsec_phase2_interface(
        self,
        device: str,
        vdom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device-DB IPsec phase2-interface.

        FNDN: UPDATE /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{name}
        """
        return await self.update(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{name}",
            data=data,
        )

    async def delete_device_ipsec_phase2_interface(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> dict[str, Any]:
        """Delete a device-DB IPsec phase2-interface.

        FNDN: DELETE /pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{name}
        """
        return await self.delete(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{name}",
        )

    async def get_device_sslvpn_settings(
        self,
        device: str,
        vdom: str,
    ) -> Any:
        """Get the device-DB SSL-VPN (Agentless VPN) settings object.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings
        """
        return await self.get(f"/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings")

    async def update_device_sslvpn_settings(
        self,
        device: str,
        vdom: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update the device-DB SSL-VPN (Agentless VPN) settings object.

        FNDN: UPDATE /pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings
        """
        return await self.update(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings",
            data=data,
        )

    async def get_device_sslvpn_web_portal(
        self,
        device: str,
        vdom: str,
        name: str,
    ) -> Any:
        """Get a device-DB SSL-VPN web portal by name.

        FNDN: GET /pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{name}
        """
        return await self.get(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{name}",
        )

    async def update_device_sslvpn_web_portal(
        self,
        device: str,
        vdom: str,
        name: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a device-DB SSL-VPN web portal.

        FNDN: UPDATE /pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{name}
        """
        return await self.update(
            f"/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{name}",
            data=data,
        )

    # =========================================================================
    # Firmware Management (um) -- swagger/um.json covers only the two
    # /um/image/upgrade* paths; the version/list, list, and upgrade/report
    # endpoints below have no bundled swagger schema in any FNDN version
    # under docs/fndn/, so their shape is taken from the How-To Guide's
    # captured request/response examples (007_device_management.rst,
    # "Firmware upgrade" section) rather than a machine schema.
    # =========================================================================

    async def get_firmware_upgrade_path(
        self,
        adom: str,
        device: list[dict[str, str]],
        release: str,
    ) -> Any:
        """Preview the multi-step upgrade path to a target firmware release.

        Passes flags="f_preview" so FortiManager returns the path without
        starting an upgrade -- confirmed both by swagger/um.json (um.image.upgrade
        "flags" enum includes "f_preview") and by the How-To Guide's captured
        example for this exact request.

        FNDN: EXEC /um/image/upgrade (swagger/um.json: um.image.upgrade)
        """
        return await self.execute(
            "/um/image/upgrade",
            adom=adom,
            device=device,
            flags="f_preview",
            image={"release": release},
        )

    async def upgrade_device_firmware(
        self,
        adom: str,
        device: list[dict[str, str]],
        release: str,
        flags: str | None = None,
        schedule_time: str | None = None,
    ) -> Any:
        """Trigger a device firmware upgrade. Asynchronous: returns a task id
        (create_task="enable") to poll with get_task/wait_for_task.

        FNDN: EXEC /um/image/upgrade (swagger/um.json: um.image.upgrade). The
        How-To Guide's captured "how to upgrade a device" example shows
        "flags" as a JSON array (e.g. ["none"]), which conflicts with
        swagger/um.json's declared type (a single enum string) -- this
        method follows the swagger type since it is the machine-checked
        source, so `flags` here is one flag name, not a list.
        """
        data: dict[str, Any] = {
            "adom": adom,
            "device": device,
            "image": {"release": release},
            "create_task": "enable",
        }
        if flags:
            data["flags"] = flags
        if schedule_time:
            data["schedule_time"] = schedule_time
        return await self.execute("/um/image/upgrade", **data)

    async def list_available_firmware(
        self,
        platform: str | None = None,
        product: str | None = None,
    ) -> Any:
        """List firmware versions available from FortiGuard servers plus any
        versions imported by an administrator (device-reported catalog, not
        limited to what's already on the FortiManager's local disk).

        FNDN: EXEC /um/image/version/list (How-To Guide 007_device_management.rst
        "How to get list of available firmware for a specific platform?";
        no bundled swagger schema -- see section note above)
        """
        data: dict[str, Any] = {}
        if platform:
            data["platform"] = platform
        if product:
            data["product"] = product
        return await self.execute("/um/image/version/list", **data)

    async def list_firmware_images(
        self,
        system: str | None = None,
    ) -> Any:
        """List firmware image files present on the FortiManager's local disk
        (imported by an administrator and/or downloaded from FortiGuard).

        FNDN: EXEC /um/image/list (How-To Guide 007_device_management.rst
        "How to get list of firmwares available on FortiManager drive?";
        no bundled swagger schema -- see section note above)
        """
        data: dict[str, Any] = {}
        if system:
            data["system"] = system
        return await self.execute("/um/image/list", **data)

    async def get_firmware_upgrade_report(
        self,
        adom: str,
        devices: list[dict[str, str]],
        profile_name: str,
    ) -> Any:
        """Get the firmware upgrade report for a named upgrade profile.

        The How-To Guide lists a separate "how to get the upgrade history"
        question but marks it TBD with no confirmed distinct URL/shape (it
        speculates the same "um/image/upgrade/report" URL) -- this method
        wraps only the one endpoint the guide actually captured traffic for.

        FNDN: GET um/image/upgrade/report (How-To Guide 007_device_management.rst
        "How to get the Upgrade Report for managed devices?"; no bundled
        swagger schema -- see section note above)
        """
        return await self.get(
            "um/image/upgrade/report",
            adom=adom,
            devices=devices,
            flags=0,
            name=profile_name,
        )
