"""Read-only firewall topology view and health alerts.

Both read the managed FortiGate through FortiManager. They do not change
configuration. Alerts are findings computed from live data; FortiManager
has no alert list unless its FortiAnalyzer features are enabled.
"""

import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.tools.device_health_summary import summarize_performance, unwrap_proxy
from fortimanager_mcp.tools.device_insight_summary import (
    alert_counts,
    evaluate_alerts,
    interface_index_map,
    latest_patch,
    static_gateways,
    summarize_neighbors,
    topology_mermaid,
)
from fortimanager_mcp.tools.device_read_summary import summarize_ipsec_tunnels
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import validate_adom, validate_device_name

logger = logging.getLogger(__name__)

_DEVICE_FIELDS = [
    "name",
    "ip",
    "conn_status",
    "conf_status",
    "os_ver",
    "mr",
    "patch",
    "build",
    "platform_str",
]


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


async def _device_record(adom: str, device: str) -> dict[str, Any]:
    record = await _get_client().get(f"/dvmdb/adom/{adom}/device/{device}", fields=_DEVICE_FIELDS)
    return record if isinstance(record, dict) else {}


@mcp.tool()
async def get_device_topology(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get a topology view of one FortiGate: what it is connected to.

    Combines LLDP neighbors (which switch or firewall is on each port),
    static next-hop gateways from the live route table, and IPsec peers.
    This is the firewall's own view, not a full network map.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name

    Returns:
        links (local port, neighbor, neighbor port, neighbor IP), gateways,
        vpn_peers, and a Mermaid diagram the chat can render.
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        unavailable = []

        neighbors, err = await _proxy_results("/api/v2/monitor/network/lldp/neighbors", adom, device)
        if err:
            return err
        cmdb, cmdb_err = await _proxy_results(
            "/api/v2/cmdb/system/interface?format=name|devindex", adom, device
        )
        if cmdb_err:
            unavailable.append("interface names")
        interfaces, if_err = await _proxy_results("/api/v2/monitor/system/interface", adom, device)
        if if_err:
            unavailable.append("interface addresses")
        routes, route_err = await _proxy_results("/api/v2/monitor/router/ipv4", adom, device)
        if route_err:
            unavailable.append("routes")
        ipsec, ipsec_err = await _proxy_results("/api/v2/monitor/vpn/ipsec", adom, device)
        if ipsec_err:
            unavailable.append("IPsec peers")

        record = await _device_record(adom, device)
        links = summarize_neighbors(
            neighbors,
            interface_index_map(None if cmdb_err else cmdb),
            None if if_err else interfaces,
        )
        gateways = [] if route_err else static_gateways(routes)
        vpn_peers = [] if ipsec_err else [
            {"name": t["name"], "remote_gateway": t["remote_gateway"], "status": t["status"]}
            for t in summarize_ipsec_tunnels(ipsec)
        ]
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "management_ip": record.get("ip"),
            "neighbor_count": len(links),
            "links": links,
            "gateways": gateways,
            "vpn_peers": vpn_peers,
            "mermaid": topology_mermaid(device, record.get("ip"), links, gateways, vpn_peers),
            "unavailable": unavailable,
            "note": (
                "Neighbors come from LLDP, so devices that do not send LLDP are not shown."
            ),
        }
    except Exception as e:
        logger.error("Failed to get topology for %s: %s", device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_device_alerts(
    adom: str | None = None,
    device: str | None = None,
    cpu_threshold: float = 80,
    memory_threshold: float = 85,
) -> dict[str, Any]:
    """Check a FortiGate for problems and return health alerts.

    Checks: FortiManager connection and sync, CPU and memory thresholds,
    interfaces with an address but no link, IPsec tunnels down, warning or
    worse events in the system log, recent IPS and antivirus detections,
    expired FortiGuard services, and a newer FortiOS patch on the same branch.
    These are findings computed from live data, not FortiManager alerts.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name
        cpu_threshold: CPU percent that counts as high (default 80)
        memory_threshold: Memory percent that counts as high (default 85)

    Returns:
        counts by severity (high, medium, low), alerts, and checks that
        could not run.
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        unavailable = []

        record = await _device_record(adom, device)
        if not record:
            return {"status": "error", "message": f"Device {device} not found in ADOM {adom}"}

        performance, perf_err = await _proxy_results(
            "/api/v2/monitor/system/performance/status", adom, device
        )
        perf = None
        if perf_err:
            unavailable.append("CPU and memory")
        else:
            perf = summarize_performance(performance, None, None)

        interfaces, if_err = await _proxy_results("/api/v2/monitor/system/interface", adom, device)
        if if_err:
            unavailable.append("interfaces")
        ipsec, ipsec_err = await _proxy_results("/api/v2/monitor/vpn/ipsec", adom, device)
        if ipsec_err:
            unavailable.append("IPsec tunnels")
        events, event_err = await _proxy_results(
            "/api/v2/log/disk/event/system?rows=200", adom, device
        )
        if event_err:
            unavailable.append("system log")

        threat_counts = {}
        for kind, resource in (("IPS", "/api/v2/log/disk/ips?rows=50"),
                               ("antivirus", "/api/v2/log/disk/virus?rows=50")):
            rows, threat_err = await _proxy_results(resource, adom, device)
            if threat_err:
                unavailable.append(f"{kind} log")
            else:
                threat_counts[kind] = len(rows) if isinstance(rows, list) else 0

        licenses, lic_err = await _proxy_results("/api/v2/monitor/license/status", adom, device)
        if lic_err:
            unavailable.append("licenses")

        installed = None
        newer = None
        if all(isinstance(record.get(k), int) for k in ("os_ver", "mr", "patch")):
            version = (record["os_ver"], record["mr"], record["patch"])
            installed = "{}.{}.{}".format(*version)
            try:
                catalog = await _get_client().list_available_firmware(
                    platform=record.get("platform_str"), product="FGT"
                )
                newer = latest_patch(version, catalog)
            except Exception:
                unavailable.append("firmware catalog")

        findings = evaluate_alerts(
            device_record=record,
            performance=perf,
            monitor_interfaces=None if if_err else interfaces,
            tunnels=None if ipsec_err else summarize_ipsec_tunnels(ipsec),
            system_events=None if event_err else events,
            threat_counts=threat_counts,
            licenses=None if lic_err else licenses,
            newer_patch=newer,
            installed_version=installed,
            cpu_threshold=cpu_threshold,
            memory_threshold=memory_threshold,
        )
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "counts": alert_counts(findings),
            "alerts": findings,
            "unavailable": unavailable,
            "note": (
                "Computed from live firewall data. FortiManager has no alert list "
                "unless its FortiAnalyzer features are enabled."
            ),
        }
    except Exception as e:
        logger.error("Failed to get alerts for %s: %s", device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
