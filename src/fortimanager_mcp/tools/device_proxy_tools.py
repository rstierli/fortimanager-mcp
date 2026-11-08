"""Read-only FortiOS REST API access to managed devices through FortiManager.

``EXEC /sys/proxy/json`` forwards a FortiOS API call to a managed device, so a
device can be queried without a direct route or credentials to it. The
purpose-built tools (``get_device_sdwan_monitor``, ``policy_lookup``, ...) cover
known questions; ``query_device_api`` reaches the rest of the API.

Reads only: the tool sends GET and nothing else, and it accepts ``monitor`` and
``cmdb`` paths. A cmdb read returns the device's own configuration, so secrets
are redacted by field name and by value before the result leaves this module.
The name match is deliberately wider than ``CONFIG_TEXT_SECRET_DIRECTIVES``: a
field wrongly masked costs a value, a field wrongly kept leaks a secret.
"""

import logging
import re
from typing import Any
from urllib.parse import urlencode

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom, get_default_device
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    CONFIG_TEXT_SECRET_DIRECTIVES,
    MASK_VALUE,
    ValidationError,
    redact_config_text_secrets,
    validate_adom,
    validate_device_name,
)

logger = logging.getLogger(__name__)

#: A monitor or cmdb path. No query string, percent-encoding or traversal:
#: parameters go through ``params`` so they meet _ALLOWED_PARAMS.
_API_PATH = re.compile(r"/api/v2/(?:monitor|cmdb)(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)+")

#: Path segments that return a whole file instead of API data. A config backup
#: carries every secret of the device as CLI text.
_BLOCKED_SEGMENTS = frozenset({"backup", "download"})

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

_MAX_DEPTH = 32


def _is_secret_key(key: str) -> bool:
    """True for a field name that holds, or may hold, a secret."""
    return key.replace("_", "-").lower() in CONFIG_TEXT_SECRET_DIRECTIVES or bool(
        _SECRET_KEY.search(key)
    )


def _redact(value: Any, depth: int = 0) -> Any:
    """Copy a device response with its secrets masked."""
    if depth > _MAX_DEPTH:
        return MASK_VALUE
    if isinstance(value, dict):
        return {
            key: MASK_VALUE
            if isinstance(key, str) and _is_secret_key(key)
            else _redact(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, depth + 1) for item in value]
    if isinstance(value, str):
        if value.startswith("ENC ") or "PRIVATE KEY" in value:
            return MASK_VALUE
        return redact_config_text_secrets(value) if "\n" in value else value
    return value


def _validate_path(path: str) -> str:
    """Accept a read path on the device API, or raise ValidationError."""
    if not isinstance(path, str) or not _API_PATH.fullmatch(path):
        raise ValidationError(
            "path must be a FortiOS API path such as /api/v2/monitor/system/status "
            "or /api/v2/cmdb/firewall/address, without a query string"
        )
    segments = path.split("/")
    if ".." in path or _BLOCKED_SEGMENTS.intersection(segments):
        raise ValidationError("traversal and file export paths (backup, download) are refused")
    return path


def _validate_params(params: dict[str, Any] | None, vdom: str | None) -> dict[str, Any]:
    """Build the query parameters, refusing any name outside the allowlist."""
    query: dict[str, Any] = {}
    for name, value in (params or {}).items():
        if name not in _ALLOWED_PARAMS:
            allowed = ", ".join(sorted(_ALLOWED_PARAMS))
            raise ValidationError(f"parameter {name!r} is not allowed (allowed: {allowed})")
        if not isinstance(value, str | int | bool):
            raise ValidationError(f"parameter {name!r} must be a string, number or boolean")
        query[name] = str(value).lower() if isinstance(value, bool) else value
    if vdom:
        query["vdom"] = validate_adom(vdom)
    return query


@mcp.tool()
async def query_device_api(
    path: str,
    device: str | None = None,
    adom: str | None = None,
    vdom: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read any FortiOS REST API path on a managed device through FortiManager.

    Proxies a GET through ``/sys/proxy/json``, so the device needs no direct
    route or credentials. Use it for what no dedicated tool covers: live state
    from ``monitor`` paths, the running configuration from ``cmdb`` paths.

    Read-only: only GET is sent. Secrets are redacted by field name and value,
    file exports (``backup``, ``download``) are refused, and ``params`` accepts
    the listed query parameters only.

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
        query = _validate_params(params, vdom)
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

    status = entry.get("status")
    if isinstance(status, dict) and status.get("code") not in (0, None):
        message = str(status.get("message") or "device proxy error")
        return {"error": message, "error_code": "device_proxy_error"}

    response = entry.get("response")
    if not isinstance(response, dict):
        return {"adom": adom, "device": device, "path": path, "results": _redact(response)}
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
        "results": _redact(response.get("results")),
    }
