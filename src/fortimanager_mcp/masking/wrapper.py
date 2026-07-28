"""Tool-boundary masking: outputs are masked, token inputs are refused.

There is no central tool-registration hook to use (tool modules
self-register with module-level ``@mcp.tool()`` at import time), so
``install_masking`` patches ``mcp.tool`` on the shared FastMCP instance
BEFORE the tool modules are imported. Every tool registered afterwards is
wrapped.

Two things happen at the boundary:

1. **Inbound, the guard.** Any argument carrying a reserved masking
   marker is refused before the tool body runs. FortiManager arguments
   become estate configuration, so a token that reached a write would be
   stored as literal configuration text, and a token that were *decrypted*
   into a write would be worse: format-preserving encryption is a
   permutation with no integrity tag, so a stale, rotated or foreign
   token decrypts to a plausible wrong address that no error would catch.
   Refusing is the only answer that cannot corrupt an estate. This is why
   the port carries no argument restoration; see the module docstring in
   ``tokens``.

2. **Outbound, the masker.** Allowlisted keys are masked by type at any
   nesting depth, and composite keys are parsed so only the identifying
   part masks.

Fail-closed by construction. A value that cannot be masked (outside the
cipher alphabet, malformed) becomes an irreversible keyed placeholder,
never the raw value, and is never logged. If masking a whole result fails
unexpectedly, the tool returns an error envelope and the raw result is
withheld.
"""

import contextvars
import hashlib
import hmac
import inspect
import ipaddress
import logging
import os
import re
from functools import wraps
from typing import Any

from fortimanager_mcp.masking.fields import (
    COMPOSITE_FQDN,
    COMPOSITE_SUBNET,
    COMPOSITE_WILDCARD_IP,
    DOMAIN,
    EMAIL,
    FIELD_TYPES,
    HOSTNAME,
    IP,
    IP_OR_HOST,
    MAC,
    SERIAL,
    SKIP_VALUES,
    USERNAME,
    canonical_key,
)
from fortimanager_mcp.masking.fpe_engine import MASKING_KEY_ENV, FPEEngine, MaskingError
from fortimanager_mcp.masking.tokens import (
    PLACEHOLDER_MARK,
    contains_token,
    looks_token_shaped,
    strict_pattern,
)

logger = logging.getLogger(__name__)


class TokenInInput(Exception):
    """A masking token was supplied as a tool argument."""


class OutputMasker:
    """Recursive result masker bound to one engine."""

    def __init__(self, engine: FPEEngine) -> None:
        self._engine = engine
        # Keyed so placeholders are deterministic (the model can still
        # correlate two occurrences of one unmaskable value) but not
        # brute-forceable from a leaked transcript.
        self._placeholder_key = os.environ.get(MASKING_KEY_ENV, "").encode()

    def placeholder(self, value: str) -> str:
        """Irreversible, deterministic stand-in for an unmaskable value."""
        digest = hmac.new(self._placeholder_key, value.encode(), hashlib.sha256).hexdigest()[:10]
        return f"{PLACEHOLDER_MARK}{digest}"

    # -- scalars -------------------------------------------------------- #

    def _mask_ip_or_host(self, value: str) -> str:
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return self._engine.mask_hostname(value)
        return self._engine.mask_ip_token(value)

    def _mask_one(self, vtype: str, value: str) -> str:
        try:
            if vtype == IP:
                return self._engine.mask_ip_token(value)
            if vtype == MAC:
                return self._engine.mask_mac_token(value)
            if vtype == SERIAL:
                return self._engine.seal_serial(value)
            if vtype == IP_OR_HOST:
                return self._mask_ip_or_host(value)
            if vtype == HOSTNAME:
                return self._engine.mask_hostname(value)
            if vtype == USERNAME:
                return self._engine.mask_username(value)
            if vtype == DOMAIN:
                return self._engine.mask_domain(value)
            if vtype == EMAIL:
                if "@" in value:
                    return self._engine.mask_email(value)
                return self._engine.mask_username(value)
        except MaskingError:
            return self.placeholder(value)
        except Exception:
            # Never let a masking bug leak the raw value. The value itself
            # is deliberately not logged.
            logger.exception("unexpected error masking a %s value; placeholder used", vtype)
            return self.placeholder(value)
        return self.placeholder(value)  # unknown tag: fail closed

    def _mask_scalar(self, vtype: str, value: str) -> str:
        if value.strip().lower() in SKIP_VALUES:
            return value
        return self._mask_one(vtype, value)

    # -- composites ----------------------------------------------------- #

    def _mask_subnet(self, value: Any) -> Any:
        """Mask the network part of a subnet, keep the mask or prefix.

        FortiManager returns address-object subnets as a two-element
        ``[network, netmask]`` list (observed live on 8.0.0) and as
        ``"net/prefix"`` or ``"net mask"`` strings elsewhere. A netmask is
        not an identifier, so masking it would cost a round trip and buy
        no privacy.
        """
        if isinstance(value, list) and len(value) == 2 and all(isinstance(p, str) for p in value):
            net, mask = value
            if net.strip().lower() in SKIP_VALUES:
                return value
            return [self._mask_scalar(IP, net), mask]
        if isinstance(value, str):
            if value.strip().lower() in SKIP_VALUES:
                return value
            for sep in ("/", " "):
                net, found, tail = value.partition(sep)
                if found and net and tail:
                    if net.strip().lower() in SKIP_VALUES:
                        return value
                    return f"{self._mask_scalar(IP, net)}{sep}{tail}"
            return self._mask_scalar(IP, value)
        return value

    def _mask_wildcard_ip(self, value: Any) -> Any:
        """Wildcard ADDRESS (an IP plus a wildcard mask): mask the address.

        Same shapes as a subnet; distinct from a wildcard FQDN, which is a
        domain string that happens to share the word.
        """
        return self._mask_subnet(value)

    def _mask_fqdn(self, value: Any) -> Any:
        """Mask a DNS name, preserving a wildcard label.

        FortiManager puts wildcard FQDNs in the same key as ordinary ones
        (8.0.0 returns both ``"*.google.com"`` and ``"gmail.com"`` under
        ``fqdn``). ``*`` is outside every cipher alphabet, so masking the
        raw value would burn every wildcard entry to a placeholder.
        """
        if not isinstance(value, str):
            return value
        if value.strip().lower() in SKIP_VALUES:
            return value
        if not value.startswith("*."):
            return self._mask_scalar(DOMAIN, value)
        rest = value[2:]
        if not rest or rest.strip().lower() in SKIP_VALUES:
            return value
        masked = self._mask_scalar(DOMAIN, rest)
        if masked.startswith(PLACEHOLDER_MARK):
            # One bare placeholder, never "*." + placeholder: every value
            # this masker emits has to be recognizable to the guard, and
            # a decorated placeholder would not be.
            return masked
        return f"*.{masked}"

    # -- walk ----------------------------------------------------------- #

    def _mask_entry(self, key: str, value: Any) -> Any:
        ckey = canonical_key(key)
        if ckey in COMPOSITE_SUBNET:
            return self._mask_subnet(value)
        if ckey in COMPOSITE_WILDCARD_IP:
            return self._mask_wildcard_ip(value)
        if ckey in COMPOSITE_FQDN:
            return self._mask_fqdn(value)
        vtype = FIELD_TYPES.get(ckey)
        if vtype is None:
            return self.mask_result(value)
        if isinstance(value, str):
            return self._mask_scalar(vtype, value)
        if isinstance(value, list):
            return [self._mask_scalar(vtype, v) if isinstance(v, str) else v for v in value]
        return value

    def mask_result(self, obj: Any) -> Any:
        """Mask allowlisted and composite keys at any nesting depth."""
        if isinstance(obj, dict):
            return {key: self._mask_entry(key, value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self.mask_result(item) for item in obj]
        return obj

    def mask_tool_result(self, result: Any, tool_name: str) -> Any:
        """Mask a result, withholding it entirely if masking fails."""
        try:
            return self.mask_result(result)
        except Exception:
            logger.exception("output masking failed for %s; raw result withheld", tool_name)
            return {
                "status": "error",
                "error": "masking_failed",
                "message": f"{tool_name}: output masking failed; raw result withheld (fail-closed)",
            }


def guard_args(value: Any, pattern: re.Pattern[str], suffix: str) -> None:
    """Refuse any reserved-marker value anywhere in the arguments.

    Nothing is decrypted, so foreign, stale and corrupted tokens are all
    refused identically and there is no decryption oracle.

    Two tiers, because the failure modes differ. A complete token
    ANYWHERE inside a string matters: one pasted into a comment or a
    script body would otherwise be written verbatim into the estate. A
    whole scalar merely carrying a marker matters too, since a truncated
    or corrupted token is still an attempt to use one as an input.

    Dict keys are checked as well as values: the dynamic dispatcher takes
    a caller-supplied ``parameters`` mapping, so a token can arrive as a
    key there.
    """
    if isinstance(value, str):
        if contains_token(value, pattern) or looks_token_shaped(value, suffix):
            raise TokenInInput
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                guard_args(key, pattern, suffix)
            guard_args(item, pattern, suffix)
    elif isinstance(value, list | tuple | set):
        for item in value:
            guard_args(item, pattern, suffix)


#: True while a wrapped tool call is inside its masking boundary. Tools
#: call other registered tools through their module-level names, and
#: those names are the WRAPPED functions, so without a guard the inner
#: result is masked twice: a second pass over a token stops it round
#: tripping and can fail it closed into a placeholder.
_AT_BOUNDARY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "fmg_masking_boundary", default=False
)

_TOKEN_REFUSED = {
    "status": "error",
    "error": "masking_token_in_input",
    "message": (
        "a masking token was supplied as an argument; masked values are "
        "read-only context and cannot be sent back to FortiManager"
    ),
}


def install_masking(mcp: Any) -> OutputMasker:
    """Patch ``mcp.tool`` so every tool registered afterwards is masked.

    Must run BEFORE the tool modules are imported, since they register at
    import time. Raises MaskingError at startup if the key is absent or
    invalid: a deployment that asked for masking must not run without it.
    """
    from fortimanager_mcp.utils.config import get_settings

    settings = get_settings()
    # The engine and the placeholder key both read the key from the
    # process environment. Settings additionally resolves it from .env,
    # so bridge it here when it is set there but not exported, otherwise a
    # deployment that put both the flag and the key in .env would enable
    # masking and then fail closed on a missing key. A real environment
    # variable still wins.
    if settings.FMG_MASKING_KEY and not os.environ.get(MASKING_KEY_ENV):
        os.environ[MASKING_KEY_ENV] = settings.FMG_MASKING_KEY

    engine = FPEEngine.from_env()
    masker = OutputMasker(engine)
    pattern = strict_pattern(engine.str_alphabet, engine.mask_suffix)
    suffix = engine.mask_suffix
    original_tool = mcp.tool

    def patched_tool(*args: Any, **kwargs: Any) -> Any:
        decorator = original_tool(*args, **kwargs)

        def register(fn: Any) -> Any:
            name = getattr(fn, "__name__", "tool")

            if inspect.iscoroutinefunction(fn):

                @wraps(fn)
                async def async_wrapped(*fa: Any, **fk: Any) -> Any:
                    if _AT_BOUNDARY.get():
                        return await fn(*fa, **fk)
                    try:
                        guard_args(list(fa), pattern, suffix)
                        guard_args(fk, pattern, suffix)
                    except TokenInInput:
                        logger.warning("refused a masking token supplied to %s", name)
                        return dict(_TOKEN_REFUSED)
                    token = _AT_BOUNDARY.set(True)
                    try:
                        result = await fn(*fa, **fk)
                    finally:
                        _AT_BOUNDARY.reset(token)
                    return masker.mask_tool_result(result, name)

                return decorator(async_wrapped)

            @wraps(fn)
            def sync_wrapped(*fa: Any, **fk: Any) -> Any:
                if _AT_BOUNDARY.get():
                    return fn(*fa, **fk)
                try:
                    guard_args(list(fa), pattern, suffix)
                    guard_args(fk, pattern, suffix)
                except TokenInInput:
                    logger.warning("refused a masking token supplied to %s", name)
                    return dict(_TOKEN_REFUSED)
                token = _AT_BOUNDARY.set(True)
                try:
                    result = fn(*fa, **fk)
                finally:
                    _AT_BOUNDARY.reset(token)
                return masker.mask_tool_result(result, name)

            return decorator(sync_wrapped)

        return register

    mcp.tool = patched_tool
    return masker
