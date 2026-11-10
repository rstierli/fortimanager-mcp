"""Shared readers for the envelope ``/sys/proxy/json`` answers with.

FortiManager answers a proxied device call with one entry per target, and
the JSON-RPC call succeeds even when the device was never reached. A tool
that proxies a read asks ``proxy_error`` first and only then trusts
``proxy_results``: a device that did not answer is not an empty answer.
An off-shape envelope that reports no failure still reads as no results.
"""

from typing import Any

from fortimanager_mcp.utils.redaction import safe_device_message


def proxy_results(raw: Any) -> Any:
    """Extract the FortiGate payload from a FMG proxy-response envelope.

    ``proxy_call`` returns ``[{"response": {"results": <data>, ...}, ...}]``.
    Returns the inner ``results`` (list or dict), or ``None`` if the envelope
    is off-shape (defensive: the proxy layer can return errors or empties).
    """
    if isinstance(raw, list) and raw:
        raw = raw[0]
    if isinstance(raw, dict):
        response = raw.get("response")
        if isinstance(response, dict):
            return response.get("results")
    return None


def proxy_error(raw: Any) -> str | None:
    """Why the device did not answer, or None when it did.

    Two layers can fail: the FMG proxy (``status.code`` non-zero, e.g. "No
    tunnel" for an offline device, or "Invalid url" for a path the device
    does not serve) and the device's own API (``response.status`` "error").
    The device's HTTP status rides beside either and is kept: a 404 (no
    such endpoint on this FortiOS) and a 500 (feature not configured, as
    ``router/bgp/neighbors`` answers on a device without BGP, measured on
    FortiOS 7.4 through FMG 8.0.2) call for different next steps. The
    message is the device's text, so it goes through ``safe_device_message``.
    """
    entry = raw[0] if isinstance(raw, list) and raw else raw
    if not isinstance(entry, dict):
        return None
    status = entry.get("status")
    response = entry.get("response")
    http_status = response.get("http_status") if isinstance(response, dict) else None
    message: str | None = None
    if isinstance(status, dict) and status.get("code") not in (0, None):
        message = safe_device_message(status.get("message"))
    elif isinstance(response, dict) and response.get("status") == "error":
        message = "device API error"
    if message is None:
        return None
    return f"{message} (HTTP {http_status})" if http_status is not None else message
