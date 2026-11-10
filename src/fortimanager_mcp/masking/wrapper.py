"""Tool-boundary masking: outputs are masked, token inputs are refused.

There is no central tool-registration hook to use (tool modules
self-register with module-level ``@mcp.tool()`` at import time), so
``install_masking`` patches ``mcp.tool`` on the shared MCPServer instance
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
   part masks. On the passthrough tools (``fields.PASSTHROUGH_TOOLS``),
   whose keys are whatever the device API uses, unnamed keys are also
   masked by value shape: addresses and MACs, never free text, and a name
   only when it is wholly an address. Dict keys shaped like an address
   are masked there too.

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
from collections.abc import Iterable
from functools import wraps
from typing import Any

from fortimanager_mcp.masking.fields import (
    COMPOSITE_ADDRESS_OR_NAME,
    COMPOSITE_FQDN,
    COMPOSITE_RANGE,
    COMPOSITE_SUBNET,
    COMPOSITE_WILDCARD_IP,
    DOMAIN,
    EMAIL,
    FIELD_TYPES,
    FREE_TEXT_KEYS,
    HOSTNAME,
    IP,
    IP_OR_HOST,
    MAC,
    PASSTHROUGH_TOOLS,
    REDACT_KEYS,
    ROUTING_KEYS_NEVER_MASK,
    SERIAL,
    SKIP_VALUES,
    USERNAME,
    canonical_key,
)
from fortimanager_mcp.masking.fpe_engine import MASKING_KEY_ENV, FPEEngine, MaskingError
from fortimanager_mcp.masking.tokens import (
    PLACEHOLDER_MARK,
    REDACTED,
    contains_token,
    looks_token_shaped,
    strict_pattern,
)

logger = logging.getLogger(__name__)


class TokenInInput(Exception):
    """A masking token was supplied as a tool argument."""


#: True while masking the result of a PASSTHROUGH_TOOLS tool, whose keys
#: no table can name. A context variable rather than a parameter threaded
#: through every handler, so the composites that recurse back into
#: ``mask_result`` keep the mode without each having to carry it.
_PASSTHROUGH: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "fmg_masking_passthrough", default=False
)

#: A dotted quad anywhere in a string, not part of a longer dotted run
#: (so a ``7.4.12.2795`` build string or an SNMP OID does not count). A
#: dot only extends the run when a digit sits beyond it: refusing any dot
#: let the full stop in ``cannot reach 10.4.4.4.`` and the label in
#: ``x.10.3.3.3`` keep the address in clear.
_IPV4_IN_TEXT = re.compile(r"(?<!\d)(?<!\d\.)\d{1,3}(?:\.\d{1,3}){3}(?!\d)(?!\.\d)")
_TEXT_SEPARATORS = re.compile(r"[\s,;\"'()\[\]<>=]+")
_MAC_SHAPE = re.compile(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}")


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

    def _mask_address_and_mask(self, value: Any, *, discriminate: bool) -> Any:
        """Mask the address part of an address-plus-mask value.

        FortiManager returns address-object subnets as a two-element
        ``[network, netmask]`` list (observed live on 8.0.0) and as
        ``"net/prefix"`` or ``"net mask"`` strings elsewhere. A netmask is
        not an identifier, so masking it would cost a round trip and buy
        no privacy.

        ``discriminate`` says whether the second part has to prove it is a
        mask before being kept. It does on the subnet route, where the
        round-3 review moved keys whose second part could be an ADDRESS.
        It must NOT on the wildcard route: a wildcard address exists
        precisely to carry a non-contiguous mask like ``0.255.0.255``, so
        the second part is a mask by definition of the key, and applying
        the test there turned real masks into random-looking addresses,
        which is the very complaint the round-3 review raised.
        """
        if (
            isinstance(value, list)
            and len(value) == 2
            and all(isinstance(p, str) for p in value)
            and (not discriminate or self._is_mask(value[1]))
        ):
            net, mask = value
            if net.strip().lower() in SKIP_VALUES:
                return value
            return [self._mask_scalar(IP, net), mask]
        if isinstance(value, str):
            if value.strip().lower() in SKIP_VALUES:
                return value
            for sep in ("/", " "):
                net, found, tail = value.partition(sep)
                if found and net and tail and (not discriminate or self._is_mask(tail)):
                    if net.strip().lower() in SKIP_VALUES:
                        return value
                    return f"{self._mask_scalar(IP, net)}{sep}{tail}"
            return self._mask_scalar(IP, value)
        return self._each(
            lambda item: self._mask_address_and_mask(item, discriminate=discriminate), value
        )

    def _mask_subnet(self, value: Any) -> Any:
        """Subnet or interface address: the second part must prove itself."""
        return self._mask_address_and_mask(value, discriminate=True)

    def _mask_wildcard_ip(self, value: Any) -> Any:
        """Wildcard ADDRESS (an IP plus a wildcard mask): mask the address.

        Same shapes as a subnet; distinct from a wildcard FQDN, which is a
        domain string that happens to share the word.
        """
        return self._mask_address_and_mask(value, discriminate=False)

    def _mask_range(self, value: Any) -> Any:
        """Mask both ends of a start-end address range.

        ``firewall/service/custom`` returns ``iprange`` holding either a
        single address or a ``start-end`` pair. Masking each side
        independently keeps the pair reversible; masking the raw string
        would fail closed on the hyphen and lose both addresses.

        Fail-closed on anything else. A value that is neither a pair of
        addresses nor a single one is not a range we understand, and
        emitting it unchanged would be the one outcome this layer exists
        to prevent.

        The masked pair is rejoined with the same hyphen it was split on,
        which is only reversible because a token holds no spare one:
        ``<kind>-<kid>-<ct>`` where the kinds are ip4/ip6, the key id is
        hex and a masked address prints as a dotted quad or a v6 address.
        Nothing in the engine enforces that, so a test asserts it.
        """
        if not isinstance(value, str):
            return self._each(self._mask_range, value)
        if value.strip().lower() in SKIP_VALUES:
            return value
        start, found, end = value.partition("-")
        if found:
            if self._is_ip(start) and self._is_ip(end):
                return f"{self._mask_scalar(IP, start)}-{self._mask_scalar(IP, end)}"
            return self.placeholder(value)
        if self._is_ip(value):
            return self._mask_scalar(IP, value)
        return self.placeholder(value)

    @staticmethod
    def _is_mask(value: str) -> bool:
        """True for a netmask, a hostmask, or a bare prefix length.

        The pair and separator forms keep whatever follows the address,
        which is only correct when that part is a mask. If it is another
        ADDRESS, keeping it publishes one. Measured before this existed,
        and reachable because ``ip`` and ``remote-ip`` moved onto this
        handler in the round-3 review::

            {"ip": ["192.0.2.50", "192.0.2.51"]}  ->  second kept verbatim

        A mask is a contiguous run of set bits from one end of the word:
        ``255.255.255.0`` from the left, and the ``0.0.0.255`` hostmask a
        wildcard address carries from the right. An address is neither,
        apart from the all-ones and all-zeros values that ``SKIP_VALUES``
        already passes through before this is consulted.
        """
        candidate = value.strip()
        if candidate.isdigit():
            # Bare prefix length, the form an IPv6 address pair uses.
            return int(candidate) <= 128
        for family, width in ((ipaddress.IPv4Address, 32), (ipaddress.IPv6Address, 128)):
            try:
                bits = int(family(candidate))
            except ValueError:
                continue
            inverted = bits ^ ((1 << width) - 1)
            # x is 2**k - 1 exactly when x & (x + 1) == 0.
            return bits & (bits + 1) == 0 or inverted & (inverted + 1) == 0
        return False

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return False
        return True

    def _mask_fqdn(self, value: Any) -> Any:
        """Mask a DNS name, preserving a wildcard label.

        FortiManager puts wildcard FQDNs in the same key as ordinary ones
        (8.0.0 returns both ``"*.google.com"`` and ``"gmail.com"`` under
        ``fqdn``). ``*`` is outside every cipher alphabet, so masking the
        raw value would burn every wildcard entry to a placeholder.
        """
        if not isinstance(value, str):
            return self._each(self._mask_fqdn, value)
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

    @staticmethod
    def _carries_address(text: str) -> bool:
        """True when an address sits anywhere in ``text``.

        IPv4 by pattern; IPv6 by parsing each separator-delimited word, since
        a pattern for it would also catch times and MACs.
        """
        if _IPV4_IN_TEXT.search(text):
            return True
        for word in _TEXT_SEPARATORS.split(text):
            if ":" not in word:
                continue
            # The word as split, then without the punctuation a sentence
            # puts around it (``via 2001:db8::5.``, ``2001:db8::5: down``).
            for candidate in (word, word.strip(".:")):
                try:
                    ipaddress.IPv6Address(candidate.partition("/")[0].partition("%")[0])
                except ValueError:
                    continue
                return True
        return False

    def _mask_if_address(self, value: str, *, embedded: bool = True) -> str:
        """Mask a string shaped like an address; leave anything else alone.

        Shapes: a bare address, ``ip/len`` or ``ip mask`` (through the
        discriminating subnet handler, so a second ADDRESS after the
        separator fails closed rather than being kept), a ``start-end``
        range and a MAC. A string that carries an address in any other form
        becomes a placeholder: under an address-or-name key that is not a
        name, and keeping it would publish the address.

        ``embedded=False`` drops that last rule, for a routing name: a name
        that IS an address is masked, one that only contains one
        (``srv-192.0.2.10``) stays, as names do everywhere else (see the
        ``fields`` module docstring).
        """
        candidate = value.strip()
        if candidate.lower() in SKIP_VALUES:
            return value
        if _MAC_SHAPE.fullmatch(candidate):
            return self._mask_scalar(MAC, candidate)
        if self._is_ip(candidate):
            return self._mask_scalar(IP, candidate)
        for sep in ("/", " "):
            net, found, _ = candidate.partition(sep)
            if found and self._is_ip(net):
                return str(self._mask_subnet(candidate))
        start, found, end = candidate.partition("-")
        if found and self._is_ip(start) and self._is_ip(end):
            return str(self._mask_range(candidate))
        if embedded and self._carries_address(candidate):
            return self.placeholder(value)
        return value

    def _mask_routing_name(self, value: str) -> str:
        return self._mask_if_address(value, embedded=False)

    def _mask_key(self, key: Any) -> Any:
        """A passthrough dict key shaped like an address, masked like a value.

        FortiOS keys some monitor answers by address (a peer, a prefix, a
        MAC), so the key carried what the value beside it no longer did.
        A key is not a routing name, so an embedded address fails closed.
        """
        if not isinstance(key, str):
            return key
        return self._mask_if_address(key)

    def _mask_address_or_name(self, value: Any) -> Any:
        """Address-or-name handler, through whatever container it arrived in.

        Its own recursion rather than ``_each``: the ``[ip, mask]`` pair has
        to be seen as one value, or the netmask would mask as an address.
        """
        if isinstance(value, str):
            return self._mask_if_address(value)
        if isinstance(value, list):
            if (
                len(value) == 2
                and all(isinstance(p, str) for p in value)
                and self._is_ip(value[0])
                and self._is_mask(value[1])
            ):
                return self._mask_subnet(value)
            return [self._mask_address_or_name(item) for item in value]
        if isinstance(value, dict):
            return self.mask_result(value)
        return value

    # -- walk ----------------------------------------------------------- #

    def _each(self, handler: Any, value: Any) -> Any:
        """Apply a key's handler through whatever container it arrived in.

        Every composite below special-cases the shapes FortiManager is
        known to use and returned anything else unchanged, which is the
        one thing this layer must never do: a list of addresses under a
        composite key reached the caller verbatim. Measured, before this
        existed::

            {"iprange": ["198.51.100.10-198.51.100.20"]}  -> unchanged
            {"ip6-address": ["2001:db8::1", 64]}          -> unchanged

        Both are plausible FortiManager shapes (multi-valued fields are
        lists, and a prefix length is as likely to arrive as an int as a
        string).

        The first fix covered one level of list and only strings, so two
        shapes still passed whole, and the walk stopped at them rather
        than merely skipping them::

            {"subnet": [{"ip": "203.0.113.5"}]}       -> unchanged
            {"iprange": [["192.0.2.1-192.0.2.10"]]}   -> unchanged

        The second is why nesting recurses with the SAME handler instead
        of going back through :meth:`mask_result`: a bare string in a
        nested list has no key of its own, so only the key above it says
        how it should mask. A dict is the opposite case, since its
        contents are named by its own keys, so it goes back through the
        key walk. Anything else is returned as it is: an int or a bool
        cannot carry an address.
        """
        if isinstance(value, str):
            return handler(value)
        if isinstance(value, list):
            return [self._each(handler, item) for item in value]
        if isinstance(value, dict):
            return self.mask_result(value)
        return value

    def _mask_entry(self, key: str, value: Any) -> Any:
        ckey = canonical_key(key)
        if ckey in REDACT_KEYS:
            if not value:
                # An unset field holds no secret. Replacing it would
                # report a withheld credential where none existed, which
                # matters most for ``password``: a broad key that lands
                # on shapes carrying nothing.
                return value
            # Otherwise first, and without looking at the value: a secret
            # is replaced whatever shape it arrives in (FortiManager
            # returns adm_pass as a list of encrypted strings), and
            # recursing into it would be a chance to emit part of it.
            return REDACTED
        if ckey in COMPOSITE_SUBNET:
            return self._mask_subnet(value)
        if ckey in COMPOSITE_WILDCARD_IP:
            return self._mask_wildcard_ip(value)
        if ckey in COMPOSITE_FQDN:
            return self._mask_fqdn(value)
        if ckey in COMPOSITE_RANGE:
            return self._mask_range(value)
        if ckey in COMPOSITE_ADDRESS_OR_NAME:
            return self._mask_address_or_name(value)
        vtype = FIELD_TYPES.get(ckey)
        if vtype is None:
            if _PASSTHROUGH.get() and ckey not in FREE_TEXT_KEYS:
                if ckey in ROUTING_KEYS_NEVER_MASK:
                    # FortiOS keys some tables by address, so ``name``,
                    # ``q_origin_key`` and ``mkey`` repeat the very address
                    # (a BGP neighbor's peer IP) the ``ip`` beside them
                    # masks. A name that is an address is masked; any other
                    # name stays.
                    return self._each(self._mask_routing_name, value)
                return self._mask_address_or_name(value)
            return self.mask_result(value)
        # Same container walk the composites use. The scalar route had the
        # original form of this hole and kept it through the first fix: a
        # dict under a carrier key was returned whole AND never walked, so
        # a carrier nested inside it leaked too.
        return self._each(lambda v: self._mask_scalar(vtype, v), value)

    def mask_result(self, obj: Any) -> Any:
        """Mask allowlisted and composite keys at any nesting depth.

        On a passthrough tool an address-shaped dict key is masked too.
        """
        if isinstance(obj, dict):
            if _PASSTHROUGH.get():
                return {
                    self._mask_key(key): self._mask_entry(key, value) for key, value in obj.items()
                }
            return {key: self._mask_entry(key, value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self.mask_result(item) for item in obj]
        return obj

    def mask_tool_result(self, result: Any, tool_name: str, inner_tools: Iterable[str] = ()) -> Any:
        """Mask a result, withholding it entirely if masking fails.

        A PASSTHROUGH_TOOLS result additionally has its unnamed keys masked
        by value shape (see ``_mask_address_or_name``). So does the result
        of a tool that called one: ``inner_tools`` names the tools that ran
        inside this one's boundary.
        """
        mode = _PASSTHROUGH.set(not PASSTHROUGH_TOOLS.isdisjoint((tool_name, *inner_tools)))
        try:
            return self.mask_result(result)
        except Exception:
            logger.exception("output masking failed for %s; raw result withheld", tool_name)
            return {
                "status": "error",
                "error": "masking_failed",
                "message": f"{tool_name}: output masking failed; raw result withheld (fail-closed)",
            }
        finally:
            _PASSTHROUGH.reset(mode)


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


#: The names of the tools called inside the current masking boundary, or
#: None outside one. Tools call other registered tools through their
#: module-level names, and those names are the WRAPPED functions, so
#: without a guard the inner result is masked twice: a second pass over a
#: token stops it round tripping and can fail it closed into a
#: placeholder.
#:
#: The names are kept because the tool that masks is then not the tool
#: that produced the result. The dynamic dispatcher reaches every tool
#: that way, and a PASSTHROUGH_TOOLS result has to keep its value-shape
#: masking under the dispatcher's name. One set shared by reference, so
#: a call made from a child task, which gets a copy of the context, is
#: still recorded.
_AT_BOUNDARY: contextvars.ContextVar[set[str] | None] = contextvars.ContextVar(
    "fmg_masking_boundary", default=None
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
                    # Guarded on every call, a nested one included: the
                    # dynamic dispatcher validates and decodes its
                    # ``parameters`` before it calls the tool, so the tool's
                    # own arguments are the only place to see what the tool
                    # body receives.
                    try:
                        guard_args(list(fa), pattern, suffix)
                        guard_args(fk, pattern, suffix)
                    except TokenInInput:
                        logger.warning("refused a masking token supplied to %s", name)
                        return dict(_TOKEN_REFUSED)
                    inner = _AT_BOUNDARY.get()
                    if inner is not None:
                        inner.add(name)
                        return await fn(*fa, **fk)
                    inner = set()
                    token = _AT_BOUNDARY.set(inner)
                    try:
                        result = await fn(*fa, **fk)
                    finally:
                        _AT_BOUNDARY.reset(token)
                    return masker.mask_tool_result(result, name, inner)

                return decorator(async_wrapped)

            @wraps(fn)
            def sync_wrapped(*fa: Any, **fk: Any) -> Any:
                try:
                    guard_args(list(fa), pattern, suffix)
                    guard_args(fk, pattern, suffix)
                except TokenInInput:
                    logger.warning("refused a masking token supplied to %s", name)
                    return dict(_TOKEN_REFUSED)
                inner = _AT_BOUNDARY.get()
                if inner is not None:
                    inner.add(name)
                    return fn(*fa, **fk)
                inner = set()
                token = _AT_BOUNDARY.set(inner)
                try:
                    result = fn(*fa, **fk)
                finally:
                    _AT_BOUNDARY.reset(token)
                return masker.mask_tool_result(result, name, inner)

            return decorator(sync_wrapped)

        return register

    mcp.tool = patched_tool
    return masker
