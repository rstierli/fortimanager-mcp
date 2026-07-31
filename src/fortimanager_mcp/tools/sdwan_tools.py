"""SD-WAN template management tools for FortiManager MCP.

Provides tools for managing SD-WAN templates (wanprof) including:
- Listing and viewing SD-WAN templates
- Creating and deleting templates
- Assigning templates to devices

Based on FNDN FortiManager 7.6.5 API specifications.
"""

import logging
import re
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom, get_default_device
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    validate_adom,
    validate_device_name,
    validate_object_name,
)

logger = logging.getLogger(__name__)

# =============================================================================
# SD-WAN Template Operations
# =============================================================================


@mcp.tool()
async def list_sdwan_templates(
    adom: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List SD-WAN templates in an ADOM.

    SD-WAN templates define WAN interface configurations, performance SLAs,
    and traffic steering rules for SD-WAN deployments.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        limit: Maximum number of templates to return

    Returns:
        List of SD-WAN templates with name, type, and assigned devices
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        templates = await client.list_sdwan_templates(adom=adom)
        templates = templates[:limit] if templates else []

        return {
            "adom": adom,
            "count": len(templates),
            "sdwan_templates": templates,
        }
    except Exception as e:
        logger.error(f"SD-WAN tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_sdwan_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a specific SD-WAN template.

    Args:
        adom: ADOM name
        name: SD-WAN template name

    Returns:
        SD-WAN template details including interfaces, SLAs, and rules
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "SD-WAN template")
        template = await client.get_sdwan_template(adom=adom, name=name)
        return {"sdwan_template": template}
    except Exception as e:
        logger.error(f"SD-WAN tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


def _as_list(value: Any) -> list[Any]:
    """Normalize an FMG field that may be a list, a single dict, or absent."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _summarize_sdwan(sdwan: dict[str, Any]) -> dict[str, Any]:
    """Condense a raw ``system/sdwan`` object into a compact summary.

    Defensive by design: every field is optional and the exact shapes vary by
    FortiOS version, so each lookup tolerates missing keys and off-shape values.
    """
    members = [
        {
            "seq_num": m.get("seq-num"),
            "interface": m.get("interface"),
            "gateway": m.get("gateway"),
            "zone": m.get("zone"),
            "weight": m.get("weight"),
            "priority": m.get("priority"),
            "status": m.get("status"),
        }
        for m in _as_list(sdwan.get("members"))
        if isinstance(m, dict)
    ]
    zones = [z.get("name") for z in _as_list(sdwan.get("zone")) if isinstance(z, dict)]
    health_checks = [
        {"name": h.get("name"), "server": h.get("server"), "members": h.get("members")}
        for h in _as_list(sdwan.get("health-check"))
        if isinstance(h, dict)
    ]
    services = [
        {"id": s.get("id"), "name": s.get("name"), "mode": s.get("mode"), "dst": s.get("dst")}
        for s in _as_list(sdwan.get("service"))
        if isinstance(s, dict)
    ]
    return {
        "status": sdwan.get("status"),
        "load_balance_mode": sdwan.get("load-balance-mode"),
        "member_count": len(members),
        "members": members,
        "zones": zones,
        "health_checks": health_checks,
        "service_rule_count": len(services),
        "services": services,
    }


@mcp.tool()
async def get_device_sdwan(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get a managed device's SD-WAN configuration from FortiManager's device DB.

    Unlike ``get_sdwan_template`` (which reads wanprof templates in an ADOM),
    this reads the SD-WAN config local to the device itself -- members/zones,
    health-checks and service (steering) rules -- from the device database
    FortiManager keeps in sync with the FortiGate. Use this when a device runs
    SD-WAN but has no wanprof template assigned (``list_sdwan_templates``
    returns nothing) yet you still need its members, zones and steering rules.

    Args:
        device: Managed device name (e.g. "myfw01")
        vdom: VDOM name (default: "root")

    Returns:
        dict with keys:
            - device, vdom
            - sdwan: raw system/sdwan config object
            - summary: condensed members/zones/health-checks/service rules
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        sdwan = await client.get_device_sdwan(device=device, vdom=vdom)
        summary = _summarize_sdwan(sdwan) if isinstance(sdwan, dict) else None
        return {
            "device": device,
            "vdom": vdom,
            "sdwan": sdwan,
            "summary": summary,
        }
    except Exception as e:
        logger.error(f"SD-WAN device-config read failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


def _proxy_results(raw: Any) -> Any:
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


def _summarize_sdwan_monitor(members_raw: Any, health_raw: Any) -> dict[str, Any]:
    """Condense the live SD-WAN member + health-check monitor payloads.

    Defensive by design: proxy envelopes vary and health-check results are a
    nested ``{health_check: {member: {...}}}`` map, so every level tolerates
    missing/off-shape values.
    """
    members_results = _proxy_results(members_raw)
    members = [
        {
            "interface": m.get("interface"),
            "seq_num": m.get("seq_num"),
            "link": m.get("link"),
            "tx_bandwidth": m.get("tx_bandwidth"),
            "rx_bandwidth": m.get("rx_bandwidth"),
            "tx_bytes": m.get("tx_bytes"),
            "rx_bytes": m.get("rx_bytes"),
        }
        for m in (members_results if isinstance(members_results, list) else [])
        if isinstance(m, dict)
    ]

    hc_results = _proxy_results(health_raw)
    sla: list[dict[str, Any]] = []
    if isinstance(hc_results, dict):
        for hc_name, per_member in hc_results.items():
            if not isinstance(per_member, dict):
                continue
            for member, stats in per_member.items():
                if not isinstance(stats, dict):
                    continue
                sla.append(
                    {
                        "health_check": hc_name,
                        "interface": member,
                        "status": stats.get("status"),
                        "latency": stats.get("latency"),
                        "jitter": stats.get("jitter"),
                        "packet_loss": stats.get("packet_loss"),
                        "sla_targets_met": stats.get("sla_targets_met"),
                    }
                )

    return {
        "member_count": len(members),
        "members_up": sum(1 for m in members if m.get("link") == "up"),
        "members": members,
        "health_checks": sorted({s["health_check"] for s in sla}),
        "sla": sla,
        "sla_entry_count": len(sla),
    }


@mcp.tool()
async def get_device_sdwan_monitor(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Read a device's LIVE SD-WAN Monitor status through the FortiManager proxy.

    Unlike ``get_device_sdwan`` (which reads the device-DB SD-WAN *config*),
    this proxies the device's live monitor API to return current SD-WAN
    *runtime* state -- the data the FortiManager "SD-WAN Monitor" view shows:

    - per-member link status and up/down bandwidth (``virtual-wan/members``)
    - per-member SLA health for each health-check: latency, jitter, packet
      loss and which SLA targets are met (``virtual-wan/health-check``)

    Use it to answer "how are the uplinks doing right now / which member is
    breaching SLA", which the config read cannot answer.

    Args:
        adom: ADOM name (defaults to DEFAULT_ADOM / "root" when omitted)
        device: Managed device name (e.g. "FGT-HQ"). Defaults to DEFAULT_DEVICE
            when omitted; required if that is not configured.

    Returns:
        dict with keys:
            - adom, device
            - members: raw virtual-wan/members proxy response
            - health_check: raw virtual-wan/health-check proxy response
            - summary: condensed member links/bandwidth + per-member SLA
            - error / error_code: on failure
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
        target = [f"/adom/{adom}/device/{device}"]
        members = await client.proxy_call(
            action="get",
            resource="/api/v2/monitor/virtual-wan/members",
            target=target,
        )
        health = await client.proxy_call(
            action="get",
            resource="/api/v2/monitor/virtual-wan/health-check",
            target=target,
        )
        return {
            "adom": adom,
            "device": device,
            "members": members,
            "health_check": health,
            "summary": _summarize_sdwan_monitor(members, health),
        }
    except Exception as e:
        logger.error(f"SD-WAN monitor read failed for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def resolve_datasource(
    url: str,
    attr: str,
    adom: str | None = None,
) -> dict[str, Any]:
    """Resolve the objects a config attribute is allowed to reference.

    Generic config-DB introspection built on FortiManager's ``option: datasrc``
    mechanism: given a cdb table ``url`` and an attribute name ``attr``, FMG
    returns every object ``attr`` may reference. For example, the objects an
    SD-WAN ``service`` (steering) rule can point at -- internet-service-names,
    address groups, etc. Documented generically in the swagger cdb get-params
    (``params.cdb.get.table.option.opts`` -> ``datasrc``, requires ``attr``).

    Only ``pm/config`` endpoints are accepted -- arbitrary URLs are rejected.

    Args:
        url: A cdb config path, e.g. "pm/config/adom/root/obj/system/sdwan"
        attr: The attribute whose referenceable objects to resolve, e.g.
            "internet-service-name" or "service"
        adom: ADOM name (informational; default: DEFAULT_ADOM env var or "root")

    Returns:
        dict with keys:
            - url, attr, adom
            - datasource: raw list/dict of referenceable objects
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    normalized = url.strip()
    if not (normalized.startswith("pm/config") or normalized.startswith("/pm/config")):
        return {
            "error": "url must be a config-DB endpoint starting with 'pm/config' or '/pm/config'",
            "error_code": "invalid_url",
        }

    # A datasrc attr is an attribute path, not an object name: it may be nested
    # with a slash (e.g. "service/internet-service-name"), which the object-name
    # validator would reject. Allow the object-name character set plus "/".
    attr = attr.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-/ ]{1,120}", attr):
        return {
            "error": "attr must be an attribute name or path (alphanumerics, '_', '.', '-', '/', space)",
            "error_code": "invalid_attr",
        }

    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        datasource = await client.resolve_datasource(url=normalized, attr=attr)
        return {
            "url": normalized,
            "attr": attr,
            "adom": adom,
            "datasource": datasource,
        }
    except Exception as e:
        logger.error(f"Datasource resolve failed for {url}/{attr}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_sdwan_template(
    adom: str,
    name: str,
    description: str | None = None,
) -> dict[str, Any]:
    """Create a new SD-WAN template.

    Creates an empty SD-WAN template that can be configured with
    interfaces, SLAs, and routing rules.

    Args:
        adom: ADOM name
        name: SD-WAN template name
        description: Optional description

    Returns:
        Created SD-WAN template
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "SD-WAN template")
        template_data: dict[str, Any] = {
            "name": name,
            "type": "wanprof",
        }
        if description:
            template_data["description"] = description

        result = await client.create_sdwan_template(adom=adom, template=template_data)
        return {
            "success": True,
            "message": f"SD-WAN template '{name}' created",
            "result": result,
        }
    except Exception as e:
        logger.error(f"SD-WAN tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_sdwan_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete an SD-WAN template.

    Note: Template must not be assigned to any devices before deletion.

    Args:
        adom: ADOM name
        name: SD-WAN template name

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "SD-WAN template")
        result = await client.delete_sdwan_template(adom=adom, name=name)
        return {
            "success": True,
            "message": f"SD-WAN template '{name}' deleted",
            "result": result,
        }
    except Exception as e:
        logger.error(f"SD-WAN tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# SD-WAN Template Assignment
# =============================================================================


@mcp.tool()
async def assign_sdwan_template(
    adom: str,
    template: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Assign an SD-WAN template to a device.

    Args:
        adom: ADOM name
        template: SD-WAN template name
        device: Device name to assign
        vdom: VDOM name (default: root)

    Returns:
        Assignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template = validate_object_name(template, "SD-WAN template")
        device = validate_device_name(device)
        scope = [{"name": device, "vdom": vdom}]
        result = await client.assign_sdwan_template(adom=adom, template=template, scope=scope)
        return {
            "success": True,
            "message": f"SD-WAN template '{template}' assigned to device '{device}'",
            "result": result,
        }
    except Exception as e:
        logger.error(f"SD-WAN tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def assign_sdwan_template_bulk(
    adom: str,
    template: str,
    devices: list[dict[str, str]],
) -> dict[str, Any]:
    """Assign an SD-WAN template to multiple devices.

    Args:
        adom: ADOM name
        template: SD-WAN template name
        devices: List of devices [{"name": "dev1", "vdom": "root"}, ...]

    Returns:
        Assignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template = validate_object_name(template, "SD-WAN template")
        result = await client.assign_sdwan_template(adom=adom, template=template, scope=devices)
        return {
            "success": True,
            "message": f"SD-WAN template '{template}' assigned to {len(devices)} devices",
            "result": result,
        }
    except Exception as e:
        logger.error(f"SD-WAN tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def unassign_sdwan_template(
    adom: str,
    template: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Unassign an SD-WAN template from a device.

    Args:
        adom: ADOM name
        template: SD-WAN template name
        device: Device name to unassign
        vdom: VDOM name (default: root)

    Returns:
        Unassignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template = validate_object_name(template, "SD-WAN template")
        device = validate_device_name(device)
        scope = [{"name": device, "vdom": vdom}]
        result = await client.unassign_sdwan_template(adom=adom, template=template, scope=scope)
        return {
            "success": True,
            "message": f"SD-WAN template '{template}' unassigned from device '{device}'",
            "result": result,
        }
    except Exception as e:
        logger.error(f"SD-WAN tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}
