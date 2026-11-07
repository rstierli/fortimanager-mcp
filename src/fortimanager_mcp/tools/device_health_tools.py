"""Live FortiGate health, interface counters, and on-box logs.

These read the managed device through FortiManager's proxy. They do not
change configuration. Syslog servers are not queried: traffic, system, and
threat rows are the logs stored on the FortiGate disk.
"""

import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.tools.device_health_summary import (
    clamp_rows,
    log_resource,
    summarize_interface_counters,
    summarize_logs,
    summarize_performance,
    unwrap_proxy,
)
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import validate_adom, validate_device_name

logger = logging.getLogger(__name__)


def _get_client():
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


async def _proxy_results(resource: str, adom: str, device: str) -> tuple[Any, dict[str, Any] | None]:
    client = _get_client()
    raw = await client.proxy_call(
        action="get",
        resource=resource,
        target=[f"/adom/{adom}/device/{device}"],
    )
    return unwrap_proxy(raw)


@mcp.tool()
async def get_device_performance(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get live CPU, memory, session count, and uptime for a managed FortiGate.

    This is the health call. get_device_realtime_status does not include
    CPU, memory, or uptime.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name

    Returns:
        dict with cpu utilization, memory used/total, current sessions,
        and uptime. Missing fields are null rather than invented.
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        performance, perf_err = await _proxy_results(
            "/api/v2/monitor/system/performance/status", adom, device
        )
        if perf_err:
            return perf_err
        usage, usage_err = await _proxy_results(
            "/api/v2/monitor/system/resource/usage", adom, device
        )
        ui_state, _ui_err = await _proxy_results("/api/v2/monitor/web-ui/state", adom, device)
        summary = summarize_performance(
            performance,
            None if usage_err else usage,
            None if _ui_err else ui_state,
        )
        return {"status": "success", "device": device, "adom": adom, **summary}
    except Exception as e:
        logger.error("Failed to get performance for %s: %s", device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_device_interface_counters(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get live packet and byte counters for each interface on a FortiGate.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name

    Returns:
        One row per interface: link up/down, IP, speed, tx/rx packets,
        tx/rx bytes, and tx/rx errors.
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        results, err = await _proxy_results("/api/v2/monitor/system/interface", adom, device)
        if err:
            return err
        interfaces = summarize_interface_counters(results)
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "count": len(interfaces),
            "interfaces": interfaces,
        }
    except Exception as e:
        logger.error("Failed to get interface counters for %s: %s", device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_device_logs(
    adom: str | None = None,
    device: str | None = None,
    log_type: str = "traffic",
    rows: int = 20,
) -> dict[str, Any]:
    """Read recent logs stored on a managed FortiGate.

    log_type is one of: traffic, system, ips, virus, webfilter, app-ctrl.
    traffic is the traffic log. system is the system/event log. ips, virus,
    webfilter, and app-ctrl are the threat logs. This does not query a
    separate syslog server; these are the on-box disk logs.

    Args:
        adom: ADOM name (default: root)
        device: FortiManager device name
        log_type: Which log to read
        rows: How many recent rows to return (1-50, default 20)

    Returns:
        count and a short table. count 0 means the device has no matching rows.
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device or "")
        kind = (log_type or "traffic").strip().lower()
        resource = log_resource(kind, rows)
        results, err = await _proxy_results(resource, adom, device)
        if err:
            return err
        entries = summarize_logs(kind, results)
        return {
            "status": "success",
            "device": device,
            "adom": adom,
            "log_type": kind,
            "count": len(entries),
            "rows": clamp_rows(rows),
            "entries": entries,
            "note": (
                "On-box FortiGate disk log. This is not a query of an external syslog server."
            ),
        }
    except ValueError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error("Failed to get %s logs for %s: %s", log_type, device, e)
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
