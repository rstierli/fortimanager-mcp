"""Shared helpers that keep device secrets and raw device text out of tool output.

``strip_secret_fields`` removes named credential fields from a FortiManager
config read at any depth. ``safe_device_message`` makes a message a managed
device (or the FortiManager proxy in front of it) sent back safe to return
to the caller.
"""

import re
from typing import Any

from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.responses import redact

#: Longest device message echoed back. A FortiOS error is one line; anything
#: longer is a dump nobody asked for.
_MAX_DEVICE_MESSAGE = 300

_WHITESPACE = re.compile(r"\s+")


def strip_secret_fields(result: Any, secret_fields: frozenset[str]) -> Any:
    """Strip named credential fields from anything FortiManager echoes back.

    Recurses through dict values and list items at any depth. A strip of
    the top level only is not safe: the secrets this is used for sit one
    table down (``health-check[].password`` under ``system sdwan``,
    ``neighbor[].password`` under ``router bgp``, ``wifi-networks[]`` under
    ``system interface``).

    The field is dropped, not replaced by ``MASK_VALUE``: the caller sees
    the record without it, which is what the long-standing copies of this
    helper in ``device_config_tools`` and ``vpn_tools`` do as well.

    ``secret_fields`` is matched against keys as-is (FortiOS field names
    such as ``"password"`` or ``"eap-password"``), not normalized.
    """
    if isinstance(result, dict):
        return {
            k: strip_secret_fields(v, secret_fields)
            for k, v in result.items()
            if k not in secret_fields
        }
    if isinstance(result, list):
        return [strip_secret_fields(item, secret_fields) for item in result]
    return result


def safe_device_message(message: Any, default: str = "device proxy error") -> str:
    """A message from a device or the FMG proxy, made safe to return.

    FortiManager relays the device's own text (``"branch1(228) error: No
    tunnel 80."``). It is not ours to trust: it goes through the same API
    path scrub as every other error (``client_safe_error``), then the
    free-text secret redactor, and is folded to one bounded line.
    """
    text = str(message or "").strip()
    if not text:
        return default
    scrubbed, _ = client_safe_error(RuntimeError(text))
    folded = _WHITESPACE.sub(" ", redact(scrubbed)).strip()
    if len(folded) > _MAX_DEVICE_MESSAGE:
        folded = folded[: _MAX_DEVICE_MESSAGE - 3] + "..."
    return folded or default
