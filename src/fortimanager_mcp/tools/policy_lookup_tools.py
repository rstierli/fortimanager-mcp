"""Policy lookup (traffic simulation) tool for FortiManager.

Based on the FortiManager JSON-RPC How-To Guide, "How to do a policy lookup?"
(``008_policy_package_management.rst``). FortiManager itself has no dedicated
policy-lookup RPC object -- the FMG UI performs this by proxying a FortiGate
monitor-API call (``/api/v2/monitor/firewall/policy-lookup/select``) to the
managed device through ``EXEC /sys/proxy/json``, the same device-proxy
mechanism already used by ``get_device_realtime_status`` and
``get_device_client_location`` (see ``dvm_tools.py``) via
``FortiManagerClient.proxy_call``.

This is a read-only simulation against the device's currently installed
policy -- it does not accept a policy-package selector, because the
documented endpoint has no such parameter (it reflects whatever package is
actually installed on the device/VDOM at query time, not an arbitrary one).
No install/preview flow applies here.
"""

import logging
from typing import Any
from urllib.parse import urlencode

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_device_name,
    validate_interface_name,
    validate_ipv4_address,
)

logger = logging.getLogger(__name__)

# IP protocol numbers accepted by the FortiGate policy-lookup monitor API,
# per the How-To Guide example (TCP=6). UDP/ICMP are the standard IANA
# protocol numbers for the same field; not independently confirmed against
# a live device for this specific endpoint, but these are the only protocol
# values a firewall policy lookup is meaningful for.
_KNOWN_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


def _proxy_results(raw: Any) -> Any:
    """Extract the FortiGate payload from a FMG proxy-response envelope.

    ``proxy_call`` returns ``[{"response": {"results": <data>, ...}, ...}]``.
    Returns the inner ``results``, or ``None`` if the envelope is off-shape.
    """
    if isinstance(raw, list) and raw:
        raw = raw[0]
    if isinstance(raw, dict):
        response = raw.get("response")
        if isinstance(response, dict):
            return response.get("results")
    return None


def _validate_port(port: int | None, label: str) -> int | None:
    """Validate an optional port number is in the 0-65535 range.

    0 is accepted (and is the documented "any" value for destport in the
    How-To Guide example) in addition to the normal 1-65535 port range.
    """
    if port is None:
        return None
    if not (0 <= port <= 65535):
        raise ValidationError(f"{label} must be between 0 and 65535")
    return port


@mcp.tool()
async def policy_lookup(
    adom: str,
    device: str,
    dest: str,
    protocol: int,
    srcintf: str | None = None,
    sourceip: str | None = None,
    sourceport: int | None = None,
    destport: int | None = None,
    package: str | None = None,
) -> dict[str, Any]:
    """Simulate a firewall policy lookup for a traffic 5-tuple against a managed device.

    Proxies FortiGate's ``policy-lookup`` monitor API through FortiManager to
    ask "which policy would match this traffic right now" -- the same
    operation the FortiManager UI's Policy Lookup dialog performs. This
    queries the device's currently installed/active policy; it does not
    take a policy-package argument (the documented endpoint has none -- see
    module docstring).

    Args:
        adom: ADOM name
        device: Managed device name (e.g. "FGT-HQ"). Accepts the
            "device[vdom]" bracket suffix used elsewhere in this codebase
            to target a specific VDOM.
        dest: Destination IPv4 address to test (e.g. "8.8.8.8")
        protocol: IP protocol number to test -- 6=TCP, 17=UDP, 1=ICMP.
            Sent to the device as both the ``protocol`` and
            ``protocol_number`` query fields, mirroring the one documented
            request/response pair in the How-To Guide where both fields
            carried the same value; the guide does not show a case where
            they differ.
        srcintf: Ingress interface name the traffic would arrive on (e.g.
            "internal"). Optional -- omitted from the query when not given,
            matching the FortiGate monitor API default.
        sourceip: Source IPv4 address to test (optional; omitted from the
            query when not given -- the How-To Guide's own example queried
            with this field empty)
        sourceport: Source port to test (optional; omitted when not given)
        destport: Destination port to test (optional; 0 -- "any port",
            per the How-To Guide example -- when not given)
        package: Informational only, NOT sent to the device. The FortiGate
            policy-lookup endpoint has no package selector; it always
            reflects whatever package is currently installed. Pass this if
            you want it echoed back in the result to cross-check against
            what you expect to be installed.

    Returns:
        dict: Lookup result with keys:
            - status: "success" or "error"
            - adom, device, package (as provided)
            - query: the traffic-tuple fields actually sent to the device
            - matched: bool from the device's ``results.success`` field
              when present, else None (the How-To Guide only documents the
              no-match case: ``{"success": false}``; a positive match's
              full field set is not documented here, so it is not
              reshaped -- see ``result``)
            - result: the raw ``results`` payload returned by the device,
              passed through unchanged
            - message: Error message if failed

    Example:
        >>> result = await policy_lookup(
        ...     adom="root",
        ...     device="branch1_fgt",
        ...     srcintf="vl_lan",
        ...     protocol=6,
        ...     dest="8.8.8.8",
        ... )
        >>> result["matched"]
        False
    """
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        dest = validate_ipv4_address(dest)
        if protocol not in _KNOWN_PROTOCOLS:
            raise ValidationError(
                f"Invalid protocol '{protocol}'. Must be one of "
                f"{sorted(_KNOWN_PROTOCOLS)} ({', '.join(_KNOWN_PROTOCOLS.values())})."
            )
        if srcintf is not None:
            srcintf = validate_interface_name(srcintf)
        if sourceip is not None and sourceip != "":
            sourceip = validate_ipv4_address(sourceip)
        sourceport = _validate_port(sourceport, "sourceport")
        destport = _validate_port(destport, "destport")

        client = _get_client()

        query: dict[str, Any] = {
            "protocol": protocol,
            "protocol_number": protocol,
            "dest": dest,
            "destport": destport if destport is not None else 0,
        }
        if srcintf is not None:
            query["srcintf"] = srcintf
        if sourceip is not None:
            query["sourceip"] = sourceip
        if sourceport is not None:
            query["sourceport"] = sourceport

        resource = f"/api/v2/monitor/firewall/policy-lookup/select?{urlencode(query)}"

        raw = await client.proxy_call(
            action="get",
            resource=resource,
            target=[f"/adom/{adom}/device/{device}"],
        )
        results = _proxy_results(raw)
        matched = results.get("success") if isinstance(results, dict) else None

        return {
            "status": "success",
            "adom": adom,
            "device": device,
            "package": package,
            "query": query,
            "matched": matched,
            "result": results,
        }
    except Exception as e:
        logger.error(f"Policy lookup failed for {device} in {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
