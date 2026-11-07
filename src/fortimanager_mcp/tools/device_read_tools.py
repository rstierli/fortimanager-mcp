"""Read-only routes, policy counters, IPsec state, and package comparison.

These proxy the managed FortiGate through FortiManager. They do not change
configuration and they do not install a policy package.
"""

import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.tools.device_health_summary import unwrap_proxy
from fortimanager_mcp.tools.device_read_summary import (
    compare_policies,
    summarize_hit_counters,
    summarize_ipsec_tunnels,
    summarize_routes,
    summarize_static_routes,
)
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    validate_adom,
    validate_device_name,
    validate_package_name,
)

logger = logging.getLogger(__name__)


def _get_client():
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


async def _proxy_results(resource: str, adom: str, device: str) -> tuple[Any, dict[str, Any] | None]:
    raw = await _get_client().proxy_call(
        action="get",
        resource=resource,
        target=[f"/adom/{adom}/device/{device}"],
    )
    return unwrap_proxy(raw)


@mcp.tool()
async def get_device_routes(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get the live IPv4 routing table and configured static routes.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name

    Returns:
        Live routes (type, destination, gateway, interface) and the static
        routes configured on the firewall.
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        live, err = await _proxy_results("/api/v2/monitor/router/ipv4", adom, device)
        if err:
            return err
        static, static_err = await _proxy_results("/api/v2/cmdb/router/static", adom, device)
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "count": len(summarize_routes(live)),
            "routes": summarize_routes(live),
            "static_routes": [] if static_err else summarize_static_routes(static),
            "static_routes_note": static_err.get("message") if static_err else None,
        }
    except Exception as e:
        logger.error("Failed to get routes for %s: %s", device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_policy_hit_counters(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get current packet, byte, and session counts for each firewall policy.

    policyid 0 is the implicit rule when the firewall includes it. Counts are
    since the firewall last cleared them. This is not a 30-day hit history.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        results, err = await _proxy_results("/api/v2/monitor/firewall/policy", adom, device)
        if err:
            return err
        counters = summarize_hit_counters(results)
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "count": len(counters),
            "note": "Current counters since they were last cleared. Not a 30-day history.",
            "policies": counters,
        }
    except Exception as e:
        logger.error("Failed to get policy counters for %s: %s", device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_device_ipsec_tunnel_status(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get whether each IPsec tunnel on a FortiGate is up or down now.

    This is live tunnel state, not the saved phase-1 configuration.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        results, err = await _proxy_results("/api/v2/monitor/vpn/ipsec", adom, device)
        if err:
            return err
        tunnels = summarize_ipsec_tunnels(results)
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "count": len(tunnels),
            "down": sum(1 for tunnel in tunnels if tunnel["status"] == "down"),
            "tunnels": tunnels,
        }
    except Exception as e:
        logger.error("Failed to get IPsec status for %s: %s", device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def compare_package_with_device(
    package: str = "default",
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Compare a FortiManager policy package with the policy on the firewall.

    This reads the live firewall policy. It does not install anything.
    Package status 0 and action 0 are the same as disable and deny.

    Args:
        package: Policy package name (default: default)
        adom: ADOM name (default: root)
        device: FortiManager device name
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        device = validate_device_name(device or "")
        package_rows = await _get_client().list_firewall_policies(adom, package)
        device_rows, err = await _proxy_results("/api/v2/cmdb/firewall/policy", adom, device)
        if err:
            return err
        compared = compare_policies(package_rows, device_rows)
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "package": package,
            "note": "Live firewall policy compared with the FortiManager package.",
            **compared,
        }
    except Exception as e:
        logger.error("Failed to compare package %s with %s: %s", package, device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
