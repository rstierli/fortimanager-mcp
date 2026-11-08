"""Read-only FortiOS REST API access to managed devices through FortiManager.

``EXEC /sys/proxy/json`` forwards a FortiOS API call to a managed device, so a
device can be queried without a direct route or credentials to it. The
purpose-built tools (``get_device_sdwan_monitor``, ``policy_lookup``, ...) cover
known questions; ``query_device_api`` reaches the rest of the diagnostic API.

Reads only, and only from an allowlist. The tool sends GET and nothing else,
and the path must sit under one of ``_ALLOWED_PREFIXES``: the live-state
``monitor`` endpoints and the ``cmdb`` tables a troubleshooting session reads
(routing, interfaces, SD-WAN, VPN, policy and objects, switch and wireless
controller). Everything else is refused, in particular the endpoints that
return a file rather than API data (``system/config/backup``,
``system/config-revision/file``, ``system/com-log/dump``, debug downloads):
a config backup carries every secret of the device as CLI text.

A cmdb read returns the device's own configuration, so secrets are redacted
by field name, by value (``ENC`` blobs, PEM keys) and, for SNMP communities,
by position: a community string is the ``name`` of its entry. The name match
is deliberately wider than ``CONFIG_TEXT_SECRET_DIRECTIVES``: a field wrongly
masked costs a value, a field wrongly kept leaks a secret.

The query parameters that select rows (``filter``, ``key``/``pattern``,
``sort``) are held to the same line, since a selector that matches on a
redacted value answers yes or no about it, one query at a time. They are
refused on community tables and on secret field names, and refused outright
when output masking is on (see ``_validate_params``).
"""

import logging
import re
from typing import Any
from urllib.parse import urlencode

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom, get_default_device, get_settings
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.redaction import safe_device_message
from fortimanager_mcp.utils.validation import (
    CONFIG_TEXT_SECRET_DIRECTIVES,
    MASK_VALUE,
    ValidationError,
    redact_config_text_secrets,
    validate_adom,
    validate_device_name,
    validate_object_name,
)

logger = logging.getLogger(__name__)

#: A monitor or cmdb path. No query string, percent-encoding or traversal:
#: parameters go through ``params`` so they meet _ALLOWED_PARAMS. A segment
#: cannot start with a dot, so ``.`` and ``..`` never match. ASCII, because
#: ``re.I`` alone folds the Kelvin sign onto ``k`` (and the dotless i and
#: long s onto ``i``/``s``), and ``str.lower`` then maps the Kelvin sign
#: onto an allowlisted spelling the device never sees.
_API_PATH = re.compile(
    r"/api/v2/(?:monitor|cmdb)(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)+", re.I | re.ASCII
)

#: What the tool may read, relative to ``/api/v2/``. An entry admits the path
#: itself and everything below it (``monitor/router`` admits
#: ``monitor/router/bgp/neighbors``), never a sibling that merely shares its
#: spelling (``cmdb/system/ha`` does not admit ``cmdb/system/ha-monitor``).
#: Matched case-insensitively. Chosen from what the bundled skills call
#: (switch-controller detected devices and managed-switch status, router
#: lookup, ARP, sessions, IPsec, HA peers) plus the neighbouring diagnostic
#: reads; extend it here, deliberately, rather than widening a prefix.
_ALLOWED_PREFIXES: tuple[str, ...] = (
    # Live state.
    "monitor/system/status",
    "monitor/system/resource/usage",
    "monitor/system/interface",
    "monitor/system/available-interfaces",
    "monitor/system/ha-peer",
    "monitor/system/ha-statistics",
    "monitor/system/ha-checksums",
    "monitor/system/ha-history",
    "monitor/system/performance/status",
    "monitor/system/link-monitor",
    "monitor/system/dhcp",
    "monitor/system/sensor-info",
    "monitor/system/vdom-resource",
    "monitor/system/global-resources",
    "monitor/system/fortimanager/status",
    "monitor/license/status",
    "monitor/router",
    "monitor/network/arp",
    "monitor/network/lldp",
    "monitor/network/dns",
    "monitor/firewall/session",
    # FortiOS 7.6 serves the session table here; firewall/session answers
    # "Invalid url" on 7.6.7.
    "monitor/firewall/sessions",
    "monitor/firewall/policy",
    "monitor/firewall/proxy-policy",
    "monitor/firewall/security-policy",
    "monitor/firewall/local-in",
    "monitor/firewall/shaper",
    "monitor/firewall/per-ip-shaper",
    "monitor/firewall/address-fqdns",
    "monitor/firewall/address-dynamic",
    "monitor/firewall/internet-service-match",
    "monitor/vpn/ipsec",
    "monitor/vpn/ssl",
    "monitor/virtual-wan",
    # Not the whole of managed-switch: some GETs below it act on the switch
    # (cable-status runs a cable diagnostic on the port it names). Add its
    # other read endpoints here one at a time, each checked first.
    "monitor/switch-controller/managed-switch/status",
    "monitor/switch-controller/detected-device",
    "monitor/wifi/client",
    "monitor/wifi/managed_ap",
    "monitor/wifi/ap_status",
    "monitor/wifi/interfering_ap",
    "monitor/wifi/rogue_ap",
    "monitor/user/device",
    "monitor/user/firewall",
    "monitor/user/banned",
    # Configuration.
    "cmdb/firewall",
    "cmdb/firewall.service",
    "cmdb/firewall.schedule",
    "cmdb/firewall.shaper",
    "cmdb/router",
    "cmdb/system/interface",
    "cmdb/system/zone",
    "cmdb/system/sdwan",
    "cmdb/system/virtual-wan-link",
    "cmdb/system/ha",
    "cmdb/system/global",
    "cmdb/system/settings",
    "cmdb/system/dns",
    "cmdb/system/ntp",
    "cmdb/system/central-management",
    "cmdb/system/link-monitor",
    "cmdb/system/gre-tunnel",
    "cmdb/system/ipip-tunnel",
    "cmdb/system/vxlan",
    "cmdb/system/switch-interface",
    "cmdb/system.dhcp/server",
    "cmdb/system.snmp",
    "cmdb/vpn.ipsec",
    "cmdb/switch-controller",
    "cmdb/wireless-controller",
    "cmdb/user/group",
    "cmdb/application/list",
    "cmdb/ips/sensor",
    "cmdb/webfilter/profile",
    "cmdb/antivirus/profile",
    "cmdb/dnsfilter/profile",
)

#: Segments that name a file export or a dump. None of the allowed prefixes
#: has one today; this stops a future prefix from admitting one by accident.
_FILE_SEGMENTS = frozenset(
    {"backup", "download", "dump", "export", "file", "raw", "restore", "upload"}
)

#: GET parameters the tool forwards. An allowlist because FortiOS has
#: parameters that widen what a read returns, such as ``plain-text-password``.
_ALLOWED_PARAMS = frozenset(
    {
        "count",
        "datasource",
        "destination",
        "exclude-default-values",
        "filter",
        "format",
        "include_vlan",
        "ip_version",
        "key",
        "pattern",
        "scope",
        "skip",
        "sort",
        "source",
        "start",
        "summary",
        "with_meta",
    }
)

_SECRET_KEY = re.compile(r"passw|passphrase|secret|psk|private[-_]?key|api[-_]?key|token", re.I)

#: Path segments that name an SNMP community table. The community string
#: is the entry's ``name`` (``config system snmp community`` / ``edit 1`` /
#: ``set name <community>``), so a field-name match cannot see it. Matched
#: as any segment rather than as fixed paths, because the same table also
#: sits below other entries: ``switch-controller/managed-switch/<sw>/
#: snmp-community`` and ``wireless-controller/snmp/community`` both
#: returned community names in clear while only the top-level spellings
#: were listed.
_COMMUNITY_SEGMENTS = frozenset({"community", "snmp-community"})

#: Everything under this is treated as a community table, whatever the
#: child: the SNMP subtree is small, and an over-masked ``name`` there (an
#: SNMPv3 user, say) costs less than a community found under a child the
#: segment list does not know.
_SNMP_TREE = "cmdb/system.snmp"

#: The same tables met as a sub-table, e.g. ``snmp-community[]`` on a
#: ``switch-controller managed-switch`` entry. ``community`` itself already
#: matches CONFIG_TEXT_SECRET_DIRECTIVES and is masked whole.
_COMMUNITY_KEYS = frozenset({"snmp-community"})

#: The copies FortiOS makes of an entry's key. On a table keyed by name
#: they carry the community too.
_ENTRY_KEY_FIELDS = ("name", "q_origin_key", "mkey")

#: Parameters that select or order rows by a field's value. Each is an
#: oracle for a value the response hides: ``filter=name=@a`` on a community
#: table answers whether the redacted name contains ``a``.
_SELECTOR_PARAMS = frozenset({"filter", "key", "pattern", "sort"})

#: One ``filter`` clause: a field name, then a FortiOS operator. Anything
#: else is refused, since a field that cannot be read cannot be checked.
_FILTER_CLAUSE = re.compile(r"\s*([A-Za-z0-9_.-]+)\s*(?:==|!=|=@|!@|<=|>=|<|>)", re.ASCII)

#: One ``sort`` term: a field name with an optional direction around it.
#: Fullmatched, as is the bare field name ``key`` takes.
_SORT_TERM = re.compile(r"\s*[-+]?([A-Za-z0-9_.-]+)(?::(?:asc|desc))?\s*", re.ASCII | re.I)
_KEY_FIELD = re.compile(r"\s*([A-Za-z0-9_.-]+)\s*", re.ASCII)

_MAX_DEPTH = 32


def _is_secret_key(key: str) -> bool:
    """True for a field name that holds, or may hold, a secret."""
    return key.replace("_", "-").lower() in CONFIG_TEXT_SECRET_DIRECTIVES or bool(
        _SECRET_KEY.search(key)
    )


def _redact_community(entry: Any, depth: int) -> Any:
    """One SNMP community entry: its ``name`` is the community string.

    A bare string is taken for a community too, and a list stays in
    community mode, so a table that comes back as plain values or nested
    lists is masked rather than passed through as "not an entry".
    """
    if depth > _MAX_DEPTH:
        return MASK_VALUE
    if isinstance(entry, str):
        return MASK_VALUE
    if isinstance(entry, list):
        return [_redact_community(item, depth + 1) for item in entry]
    if not isinstance(entry, dict):
        return _redact(entry, depth)
    redacted = _redact(entry, depth)
    if "name" in redacted:
        redacted["name"] = MASK_VALUE
    # The key copies only when they are strings: an integer id is the
    # usual mkey here and carries nothing.
    for field in _ENTRY_KEY_FIELDS:
        if isinstance(redacted.get(field), str):
            redacted[field] = MASK_VALUE
    return redacted


def _redact(value: Any, depth: int = 0, community: bool = False) -> Any:
    """Copy a device response with its secrets masked.

    ``community`` marks a value whose entries are SNMP communities.
    """
    if depth > _MAX_DEPTH:
        return MASK_VALUE
    if community:
        return _redact_community(value, depth + 1)
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_secret_key(key):
                out[key] = MASK_VALUE
            elif isinstance(key, str) and key.lower() in _COMMUNITY_KEYS:
                out[key] = _redact(item, depth + 1, community=True)
            else:
                out[key] = _redact(item, depth + 1)
        return out
    if isinstance(value, list):
        return [_redact(item, depth + 1) for item in value]
    if isinstance(value, str):
        if value.startswith("ENC ") or "PRIVATE KEY" in value:
            return MASK_VALUE
        return redact_config_text_secrets(value) if "\n" in value else value
    return value


def _relative(path: str) -> str:
    """The path below ``/api/v2/``, lowercased for matching."""
    return path[len("/api/v2/") :].lower()


def _under(relative: str, prefix: str) -> bool:
    return relative == prefix or relative.startswith(prefix + "/")


def _validate_path(path: str) -> str:
    """Accept an allowlisted read path on the device API, or raise ValidationError."""
    if not isinstance(path, str) or not _API_PATH.fullmatch(path):
        raise ValidationError(
            "path must be a FortiOS API path such as /api/v2/monitor/system/status "
            "or /api/v2/cmdb/firewall/address, without a query string"
        )
    relative = _relative(path)
    if _FILE_SEGMENTS.intersection(relative.split("/")):
        raise ValidationError(
            "file export and dump paths (backup, download, dump, file, ...) are refused"
        )
    if not any(_under(relative, prefix) for prefix in _ALLOWED_PREFIXES):
        # Relative spellings on purpose: client_safe_error scrubs anything
        # that starts with /api/ from a message.
        allowed = ", ".join(_ALLOWED_PREFIXES)
        raise ValidationError(
            f"path api/v2/{relative} is not in the read allowlist. Allowed, relative "
            f"to api/v2 and each with everything below it: {allowed}"
        )
    return path


def _is_community_table(path: str) -> bool:
    """True for a cmdb path whose entries are, or may be, SNMP communities."""
    relative = _relative(path)
    if not relative.startswith("cmdb/"):
        return False
    return _under(relative, _SNMP_TREE) or bool(
        _COMMUNITY_SEGMENTS.intersection(relative.split("/"))
    )


def _masking_enabled() -> bool:
    return bool(get_settings().MASKING_ENABLED)


def _is_secret_field(field: str) -> bool:
    """A selector field naming a secret, whole or as any dotted/slashed part."""
    return _is_secret_key(field) or any(
        _is_secret_key(part) for part in re.split(r"[./]", field) if part
    )


def _selector_fields(name: str, value: str) -> list[str]:
    """The field names a selector parameter reads, or ValidationError.

    Every comma starts a clause, escaped or not: a value that holds a comma
    is refused rather than parsed the way the device might not.
    """
    if name == "pattern":
        # A value, not a field: ``key`` names the field it is matched on.
        return []
    terms = [value] if name == "key" else value.split(",")
    fields: list[str] = []
    for term in terms:
        if name == "filter":
            match = _FILTER_CLAUSE.match(term)
        else:
            match = (_KEY_FIELD if name == "key" else _SORT_TERM).fullmatch(term)
        if not match:
            raise ValidationError(
                f"could not read the field name in {name} {term!r}; use field==value "
                "clauses (==, !=, =@, !@, <, <=, >, >=) separated by commas"
            )
        fields.append(match.group(1))
    return fields


def _check_selector(name: str, value: Any, path: str) -> None:
    """Refuse a row selector that could reveal a redacted or masked value.

    Three refusals, in order: any selector on a community table (the
    community is the entry's name, the field every selector reaches); any
    selector when output masking is on (a substring filter or a sort on an
    address field recovers the address one query at a time, and in this
    tool's free-form output every field may carry one); and, otherwise, a
    selector on a field whose name marks a secret.
    """
    if _is_community_table(path):
        raise ValidationError(
            f"parameter {name!r} is refused on SNMP community tables: it would match "
            "on the community strings the response redacts"
        )
    if _masking_enabled():
        raise ValidationError(
            f"parameter {name!r} is refused while output masking is on: it would match "
            "on the values the masking hides. Read the table with count/start and "
            "select the rows from the masked result"
        )
    for field in _selector_fields(name, str(value)):
        if _is_secret_field(field):
            raise ValidationError(
                f"parameter {name!r} names the secret field {field!r}; selecting on a "
                "redacted field is refused"
            )


def _validate_params(
    params: dict[str, Any] | None, vdom: str | None, path: str = ""
) -> dict[str, Any]:
    """Build the query parameters, refusing any name outside the allowlist."""
    query: dict[str, Any] = {}
    for name, value in (params or {}).items():
        if name not in _ALLOWED_PARAMS:
            allowed = ", ".join(sorted(_ALLOWED_PARAMS))
            raise ValidationError(f"parameter {name!r} is not allowed (allowed: {allowed})")
        if not isinstance(value, str | int | bool):
            raise ValidationError(f"parameter {name!r} must be a string, number or boolean")
        if name in _SELECTOR_PARAMS:
            _check_selector(name, value, path)
        query[name] = str(value).lower() if isinstance(value, bool) else value
    if vdom:
        query["vdom"] = validate_object_name(vdom, "VDOM")
    return query


@mcp.tool()
async def query_device_api(
    path: str,
    device: str | None = None,
    adom: str | None = None,
    vdom: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read a diagnostic FortiOS REST API path on a managed device through FortiManager.

    Proxies a GET through ``/sys/proxy/json``, so the device needs no direct
    route or credentials. Use it for what no dedicated tool covers: live state
    from ``monitor`` paths, the running configuration from ``cmdb`` paths.

    Read-only: only GET is sent, and only to an allowlist of paths (each
    with everything below it): monitor system status/resource/interface/
    ha-peer/dhcp/link-monitor, router (ipv4, lookup, bgp, ospf, ...), network
    arp/lldp, firewall session/policy hit counts, vpn ipsec/ssl, virtual-wan,
    switch-controller managed-switch/status and detected-device, wifi clients
    and APs,
    user device/firewall; cmdb firewall, router, system interface/zone/sdwan/
    ha/global/dns/snmp, vpn.ipsec, switch-controller, wireless-controller,
    user group and the security profiles. Anything else, and every file
    export or dump, is refused with the full list. Secrets are redacted by
    field name and value, SNMP community strings included, and ``params``
    accepts the listed query parameters only.

    Args:
        path: API path without query string, e.g.
            ``/api/v2/monitor/router/ipv4`` or ``/api/v2/cmdb/firewall/address``
        device: Managed device name. Defaults to DEFAULT_DEVICE when omitted.
        adom: ADOM name (default: DEFAULT_ADOM or "root")
        vdom: VDOM to query (default: the device's own default)
        params: Query parameters, from: count, datasource, destination,
            exclude-default-values, filter, format, include_vlan, ip_version,
            key, pattern, scope, skip, sort, source, start, summary, with_meta.
            Use ``count`` and ``format`` to keep large tables small, e.g.
            ``{"count": 50, "format": "name|subnet"}``. ``filter`` applies to
            cmdb paths; ``monitor/firewall/session`` ignores it and takes
            ``source`` or ``destination``.

            The row selectors ``filter``, ``key``, ``pattern`` and ``sort``
            are refused where they could reveal what the response hides: on
            SNMP community tables (any ``community``/``snmp-community``
            segment, anything under ``system.snmp``), on a field whose name
            marks a secret (``filter=password=@a``), and entirely while
            output masking is on, since a substring match or a sort on an
            address field recovers a masked address one query at a time.
            ``filter`` must be ``field<op>value`` clauses joined by commas
            (ops ``==``, ``!=``, ``=@``, ``!@``, ``<``, ``<=``, ``>``,
            ``>=``); a comma inside a value is refused, not guessed at.
            ``source``/``destination`` stay available with masking on: they
            take one whole address, the same exact lookup
            ``get_device_client_location`` accepts.

    Returns:
        dict with keys:
            - adom, device, path
            - http_status, version, build: as reported by the device
            - results: the device's answer, secrets redacted
            - error / error_code: on failure

    Example:
        >>> await query_device_api("/api/v2/monitor/router/bgp/neighbors", "branch1")
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    adom = adom or get_default_adom()
    device = device or get_default_device()
    if not device:
        return {
            "error": "device is required (pass it, or configure DEFAULT_DEVICE)",
            "error_code": "device_required",
        }

    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        path = _validate_path(path)
        query = _validate_params(params, vdom, path)
        raw = await client.proxy_call(
            action="get",
            resource=f"{path}?{urlencode(query)}" if query else path,
            target=[f"/adom/{adom}/device/{device}"],
        )
    except Exception as e:
        logger.error(f"Device API read failed for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}

    entry = raw[0] if isinstance(raw, list) and raw else raw
    if not isinstance(entry, dict):
        return {"error": "no data returned by the device", "error_code": "device_proxy_error"}

    response = entry.get("response")
    status = entry.get("status")
    if isinstance(status, dict) and status.get("code") not in (0, None):
        error: dict[str, Any] = {
            "error": safe_device_message(status.get("message")),
            "error_code": "device_proxy_error",
        }
        # An unknown path comes back as a proxy error ("Invalid url") with
        # the device's own HTTP status beside it; keep that, it says why.
        if isinstance(response, dict) and response.get("http_status") is not None:
            error["http_status"] = response.get("http_status")
        return error

    community = _is_community_table(path)
    if not isinstance(response, dict):
        return {
            "adom": adom,
            "device": device,
            "path": path,
            "results": _redact(response, community=community),
        }
    if response.get("status") == "error":
        return {
            "error": f"device answered HTTP {response.get('http_status')}",
            "error_code": "device_api_error",
            "http_status": response.get("http_status"),
        }
    return {
        "adom": adom,
        "device": device,
        "path": path,
        "http_status": response.get("http_status"),
        "version": response.get("version"),
        "build": response.get("build"),
        "results": _redact(response.get("results"), community=community),
    }
