"""SD-WAN template management tools for FortiManager MCP.

Provides tools for managing SD-WAN templates (wanprof) including:
- Listing and viewing SD-WAN templates
- Creating and deleting templates
- Assigning templates to devices
- Reading SD-WAN template bodies, BGP template bodies, and device-DB
  SD-WAN / BGP / static-route config for overlay documentation
- Diagnosing a down overlay tunnel, underlay first (diagnose_ipsec_tunnel)

Based on FNDN FortiManager 7.6.5 API specifications.
"""

import logging
import re
from datetime import UTC, datetime
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom, get_default_device
from fortimanager_mcp.utils.device_proxy import proxy_error as _proxy_error
from fortimanager_mcp.utils.device_proxy import proxy_results as _proxy_results
from fortimanager_mcp.utils.errors import ResourceNotFoundError, client_safe_error
from fortimanager_mcp.utils.redaction import strip_secret_fields
from fortimanager_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_device_name,
    validate_limit,
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
        limit: Maximum number of templates to return (default: 100, minimum: 1)

    Returns:
        List of SD-WAN templates with name, type, and assigned devices.
        ``count`` is the number returned and ``total`` the number before
        ``limit``: if ``total`` is larger the list was cut, raise ``limit``
        for the rest.
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        limit = validate_limit(limit)
        templates = await client.list_sdwan_templates(adom=adom)
        total = len(templates) if templates else 0
        templates = templates[:limit] if templates else []

        return {
            "adom": adom,
            "count": len(templates),
            "total": total,
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


#: Fields FMG stores as ``format=password`` under ``system sdwan`` (confirmed
#: against the bundled 8.0 swagger: ``system.sdwan.health-check.password``,
#: the credential an HTTP/FTP probe authenticates with). Applies to both the
#: device-DB copy and the wanprof template copy, which share the schema.
_SDWAN_SECRET_FIELDS = frozenset({"password"})

#: Fields FMG stores as ``format=password`` under ``router bgp`` (confirmed
#: against the bundled 7.4 and 8.0 swaggers: ``router.bgp.neighbor.password``
#: and ``router.bgp.neighbor-group.password``, the TCP-MD5 session key).
_BGP_SECRET_FIELDS = frozenset({"password"})


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
        device: Managed device name (e.g. "branch1")
        vdom: VDOM name (default: "root")

    Returns:
        dict with keys:
            - device, vdom
            - sdwan: raw system/sdwan config object (health-check
              ``password`` stripped -- see _SDWAN_SECRET_FIELDS)
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
        sdwan = strip_secret_fields(sdwan, _SDWAN_SECRET_FIELDS)
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


@mcp.tool()
async def get_sdwan_template_config(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get the SD-WAN configuration inside a wanprof (SD-WAN) template.

    ``get_sdwan_template`` returns only the template's metadata (name, type,
    scope). This reads the configuration the template pushes -- members,
    zones, health-checks with their SLA thresholds, and service (steering)
    rules -- from the template's own config subtree.

    Args:
        adom: ADOM name
        name: SD-WAN template name (as listed by ``list_sdwan_templates``)

    Returns:
        dict with keys:
            - adom, name
            - sdwan: raw system/sdwan config object (health-check
              ``password`` stripped -- see _SDWAN_SECRET_FIELDS)
            - summary: condensed members/zones/health-checks/service rules
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "SD-WAN template")
        sdwan = await client.get_sdwan_template_config(adom=adom, name=name)
        sdwan = strip_secret_fields(sdwan, _SDWAN_SECRET_FIELDS)
        summary = _summarize_sdwan(sdwan) if isinstance(sdwan, dict) else None
        return {"adom": adom, "name": name, "sdwan": sdwan, "summary": summary}
    except Exception as e:
        logger.error(f"SD-WAN template config read failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


def _summarize_bgp(bgp: dict[str, Any]) -> dict[str, Any]:
    """Condense a raw ``router/bgp`` object into a compact summary.

    Defensive like ``_summarize_sdwan``: every field is optional and shapes
    vary by FortiOS version, and a template body may hold ``$(var)``
    placeholders where a device holds literal values.
    """
    neighbors = [
        {
            "ip": n.get("ip"),
            "remote_as": n.get("remote-as"),
            "interface": n.get("interface"),
            "update_source": n.get("update-source"),
            "route_map_in": n.get("route-map-in"),
            "route_map_out": n.get("route-map-out"),
        }
        for n in _as_list(bgp.get("neighbor"))
        if isinstance(n, dict)
    ]
    neighbor_groups = [
        {
            "name": g.get("name"),
            "remote_as": g.get("remote-as"),
            "interface": g.get("interface"),
            "update_source": g.get("update-source"),
            "route_reflector_client": g.get("route-reflector-client"),
            "next_hop_self": g.get("next-hop-self"),
        }
        for g in _as_list(bgp.get("neighbor-group"))
        if isinstance(g, dict)
    ]
    neighbor_ranges = [
        {"id": r.get("id"), "prefix": r.get("prefix"), "neighbor_group": r.get("neighbor-group")}
        for r in _as_list(bgp.get("neighbor-range"))
        if isinstance(r, dict)
    ]
    networks = [
        {"id": n.get("id"), "prefix": n.get("prefix"), "route_map": n.get("route-map")}
        for n in _as_list(bgp.get("network"))
        if isinstance(n, dict)
    ]
    return {
        "as": bgp.get("as"),
        "router_id": bgp.get("router-id"),
        "ibgp_multipath": bgp.get("ibgp-multipath"),
        "ebgp_multipath": bgp.get("ebgp-multipath"),
        "neighbor_count": len(neighbors),
        "neighbors": neighbors,
        "neighbor_groups": neighbor_groups,
        "neighbor_ranges": neighbor_ranges,
        "network_count": len(networks),
        "networks": networks,
    }


@mcp.tool()
async def get_bgp_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get the ``router bgp`` configuration inside a BGP provisioning template.

    ``get_template`` returns only a template's metadata. This reads the BGP
    body a ``router_bgp`` template pushes -- AS, router-id, neighbors,
    neighbor-groups, neighbor-ranges and networks -- e.g. the templates an
    SD-WAN Overlay Template generates for its hub and branches. Values may
    be ``$(variable)`` placeholders resolved per device at install.

    The template body path is not in the bundled FNDN specs; it is verified
    live on FortiManager 8.0.2 (see ``get_bgp_template_config`` in the
    client for the details and the 7.x fallback).

    Args:
        adom: ADOM name
        name: BGP template name (``list_templates`` entries whose
            ``template setting.stype`` is router_bgp)

    Returns:
        dict with keys:
            - adom, name
            - bgp: raw router/bgp config object (neighbor ``password``
              stripped -- see _BGP_SECRET_FIELDS)
            - summary: condensed AS/router-id/neighbors/networks
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "template")
        bgp = await client.get_bgp_template_config(adom=adom, name=name)
        bgp = strip_secret_fields(bgp, _BGP_SECRET_FIELDS)
        summary = _summarize_bgp(bgp) if isinstance(bgp, dict) else None
        return {"adom": adom, "name": name, "bgp": bgp, "summary": summary}
    except Exception as e:
        logger.error(f"BGP template read failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


#: Neighbor-group options update_bgp_template can change. An allowlist: AS
#: numbers, neighbor ranges and passwords can take a whole overlay down.
_BGP_GROUP_TOGGLES = frozenset(
    {"next-hop-self", "next-hop-self-rr", "route-reflector-client", "soft-reconfiguration"}
)
_BGP_GROUP_NUMBERS = frozenset({"advertisement-interval"})


def _bgp_group_data(settings: dict[str, Any]) -> dict[str, Any]:
    """Validate neighbor-group settings into API values, or raise ValidationError."""
    if not settings:
        raise ValidationError("settings must name at least one option")
    data: dict[str, Any] = {}
    for key, value in settings.items():
        if key in _BGP_GROUP_TOGGLES:
            if value not in ("enable", "disable"):
                raise ValidationError(f"{key} must be 'enable' or 'disable'")
            data[key] = value
        elif key in _BGP_GROUP_NUMBERS:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 600:
                raise ValidationError(f"{key} must be a number of seconds from 0 to 600")
            data[key] = value
        else:
            allowed = ", ".join(sorted(_BGP_GROUP_TOGGLES | _BGP_GROUP_NUMBERS))
            raise ValidationError(f"option {key!r} is not allowed (allowed: {allowed})")
    return data


@mcp.tool()
async def update_bgp_template(
    adom: str,
    name: str,
    neighbor_group: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Change neighbor-group options inside a BGP provisioning template.

    Only FortiManager changes here: the devices follow at the next install, so
    run preview_install(package=None) first. BGP then needs a route refresh,
    for example ``execute router clear bgp all soft out``, before peers receive
    what a new route-reflector client should get.

    The neighbor-group path is not in the bundled FNDN specs; it is verified
    live on FortiManager 8.0.2 only.

    Args:
        adom: ADOM name
        name: BGP template name (``list_templates`` entries whose
            ``template setting.stype`` is router_bgp)
        neighbor_group: Neighbor group name, e.g. "EDGE"
        settings: Options to change: route-reflector-client, next-hop-self,
            next-hop-self-rr, soft-reconfiguration ("enable"/"disable") and
            advertisement-interval (seconds). Anything else is refused.

    Returns:
        dict: adom, name, neighbor_group, before, after (values read back from
        FortiManager, 1/0 for enable/disable), or error / error_code on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "BGP template")
        neighbor_group = validate_object_name(neighbor_group, "BGP neighbor group")
        data = _bgp_group_data(settings)
        fields = sorted(data)
        before = await client.get_bgp_template_neighbor_group(adom, name, neighbor_group, fields)
        await client.update_bgp_template_neighbor_group(adom, name, neighbor_group, data)
        after = await client.get_bgp_template_neighbor_group(adom, name, neighbor_group, fields)
        return {
            "adom": adom,
            "name": name,
            "neighbor_group": neighbor_group,
            "before": {field: before.get(field) for field in fields},
            "after": {field: after.get(field) for field in fields},
            "message": "Saved in the template. Run preview_install before installing.",
        }
    except Exception as e:
        logger.error(f"BGP template update failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_device_bgp(
    device: str,
    vdom: str = "root",
    summary_only: bool = False,
) -> dict[str, Any]:
    """Get a managed device's BGP configuration from FortiManager's device DB.

    Reads the ``router bgp`` config FortiManager holds for the device --
    the result of any BGP template plus local settings, with variables
    resolved. This is configuration, not runtime state: it says which
    neighbors are configured, not whether they are established.

    Args:
        device: Managed device name (e.g. "FGT-HQ")
        vdom: VDOM name (default: "root")
        summary_only: Leave out the raw ``bgp`` object, which lists some 150
            fields per neighbor (default: False)

    Returns:
        dict with keys:
            - device, vdom
            - bgp: raw router/bgp config object (neighbor ``password``
              stripped -- see _BGP_SECRET_FIELDS), unless ``summary_only``
            - summary: condensed AS/router-id/neighbors/networks
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        bgp = await client.get_device_bgp(device=device, vdom=vdom)
        bgp = strip_secret_fields(bgp, _BGP_SECRET_FIELDS)
        summary = _summarize_bgp(bgp) if isinstance(bgp, dict) else None
        if summary_only:
            return {"device": device, "vdom": vdom, "summary": summary}
        return {"device": device, "vdom": vdom, "bgp": bgp, "summary": summary}
    except Exception as e:
        logger.error(f"BGP device-config read failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_device_static_routes(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get a managed device's IPv4 static routes from FortiManager's device DB.

    Complements ``get_device_bgp`` for a full routing picture: on an SD-WAN
    overlay the default route usually points at an SD-WAN zone and the
    overlay summaries are often blackholed here.

    Args:
        device: Managed device name (e.g. "FGT-HQ")
        vdom: VDOM name (default: "root")

    Returns:
        dict with keys:
            - device, vdom
            - routes: raw router/static entries
            - summary: condensed per-route list
            - route_count
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        routes = await client.get_device_static_routes(device=device, vdom=vdom)
        summary = [
            {
                "seq_num": r.get("seq-num"),
                "status": r.get("status"),
                "dst": r.get("dst"),
                "dstaddr": r.get("dstaddr"),
                "gateway": r.get("gateway"),
                "device": r.get("device"),
                "sdwan_zone": r.get("sdwan-zone"),
                "distance": r.get("distance"),
                "priority": r.get("priority"),
                "blackhole": r.get("blackhole"),
                "comment": r.get("comment"),
            }
            for r in _as_list(routes)
            if isinstance(r, dict)
        ]
        return {
            "device": device,
            "vdom": vdom,
            "routes": routes,
            "summary": summary,
            "route_count": len(summary),
        }
    except Exception as e:
        logger.error(f"Static-route device-config read failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        # The JSON-RPC call succeeds for a device that did not answer, and
        # summarizing that envelope reads as "no members, no health checks".
        failed = {
            label: error
            for label, error in (
                ("SD-WAN members", _proxy_error(members)),
                ("SD-WAN health checks", _proxy_error(health)),
            )
            if error
        }
        if failed:
            # One text for a device that answered neither read; otherwise
            # say which read failed, the other one's data is not returned.
            texts = set(failed.values())
            message = (
                texts.pop()
                if len(failed) == 2 and len(texts) == 1
                else "; ".join(f"{label}: {error}" for label, error in failed.items())
            )
            return {"error": message, "error_code": "device_proxy_error"}
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


def _summarize_bgp_status(neighbors: Any, paths: Any, routes: Any) -> dict[str, Any]:
    """Condense the live BGP neighbor, path and routing-table monitor results.

    A path with ``learned_from`` 0.0.0.0 is the device's own, anything else
    came from a peer. Only ``type: bgp`` routes reached the routing table.
    """
    peers = [
        {
            "neighbor_ip": n.get("neighbor_ip"),
            "local_ip": n.get("local_ip"),
            "remote_as": n.get("remote_as"),
            "admin_status": n.get("admin_status"),
            "state": n.get("state"),
            "type": n.get("type"),
        }
        for n in (neighbors if isinstance(neighbors, list) else [])
        if isinstance(n, dict)
    ]
    all_paths = [p for p in (paths if isinstance(paths, list) else []) if isinstance(p, dict)]
    # "0.0.0.0" is a route field value (no BGP source), not a bind address.
    learned = [
        p
        for p in all_paths
        if p.get("learned_from") not in (None, "0.0.0.0")  # nosec B104
    ]
    bgp_routes = [
        {
            "prefix": r.get("ip_mask"),
            "gateway": r.get("gateway"),
            "interface": r.get("interface"),
            "distance": r.get("distance"),
            "metric": r.get("metric"),
        }
        for r in (routes if isinstance(routes, list) else [])
        if isinstance(r, dict) and r.get("type") == "bgp"
    ]
    return {
        "neighbor_count": len(peers),
        "established_count": sum(1 for p in peers if p["state"] == "Established"),
        "neighbors": peers,
        "local_path_count": len(all_paths) - len(learned),
        "learned_path_count": len(learned),
        "learned_paths": [
            {
                "prefix": f"{p.get('nlri_prefix')}/{p.get('nlri_prefix_len')}",
                "learned_from": p.get("learned_from"),
                "next_hop": p.get("next_hop"),
                "is_best": p.get("is_best"),
            }
            for p in learned
        ],
        "bgp_route_count": len(bgp_routes),
        "bgp_routes": bgp_routes,
    }


@mcp.tool()
async def get_device_bgp_status(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Read a device's LIVE BGP state through the FortiManager proxy.

    Unlike ``get_device_bgp`` (which reads the device-DB BGP *config*), this
    proxies the device's monitor API to answer "are the peers established and
    which routes did they bring":

    - peer state (``router/bgp/neighbors``)
    - local and learned paths (``router/bgp/paths``)
    - BGP routes in the routing table (``router/ipv4``)

    Dynamic peers from a neighbor-range are not configured neighbors: a hub
    lists none until a spoke connects, so an empty list there means no spoke
    is up, not that BGP is unconfigured. Check the spoke's state too.

    Args:
        adom: ADOM name (defaults to DEFAULT_ADOM / "root" when omitted)
        device: Managed device name (e.g. "FGT-HQ"). Defaults to DEFAULT_DEVICE
            when omitted; required if that is not configured.

    Returns:
        dict with keys:
            - adom, device
            - summary: neighbors with state, established_count, learned paths,
              BGP routes in the routing table
            - unverified: sources that could not be read
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
    except Exception as e:
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}

    unverified: list[str] = []
    neighbors, err = await _live_get(client, adom, device, "/api/v2/monitor/router/bgp/neighbors")
    if err:
        unverified.append(f"BGP neighbors: {err}")
    paths, err = await _live_get(client, adom, device, "/api/v2/monitor/router/bgp/paths")
    if err:
        unverified.append(f"BGP paths: {err}")
    routes, err = await _live_get(client, adom, device, "/api/v2/monitor/router/ipv4")
    if err:
        unverified.append(f"routing table: {err}")

    if len(unverified) == 3:
        return {"error": "; ".join(unverified), "error_code": "device_proxy_error"}
    return {
        "adom": adom,
        "device": device,
        "summary": _summarize_bgp_status(neighbors, paths, routes),
        "unverified": unverified,
    }


# =============================================================================
# IPsec overlay tunnel diagnosis
# =============================================================================

#: Phase1 ``type`` values meaning a dial-up (hub-side) gateway: the FMG
#: integer encoding and the FortiOS keyword.
_DIALUP_TYPES = frozenset({1, "1", "dynamic"})

#: Interface ``status`` values meaning administratively down.
_ADMIN_DOWN = frozenset({0, "0", "down"})


def _first(value: Any) -> Any:
    """First element of a list field, or the value itself."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _since(epoch: Any) -> str | None:
    """Render a FortiOS ``state_changed`` epoch as ISO-8601 UTC."""
    if isinstance(epoch, int | float) and epoch > 0:
        return datetime.fromtimestamp(epoch, tz=UTC).isoformat()
    return None


async def _live_get(client: Any, adom: str, device: str, resource: str) -> tuple[Any, str | None]:
    """GET a FortiOS monitor endpoint through the FMG proxy.

    Returns ``(results, None)`` or ``(None, reason)``; never raises, so one
    unreadable source leaves the rest of the diagnosis intact.
    """
    try:
        raw = await client.proxy_call(
            action="get",
            resource=resource,
            target=[f"/adom/{adom}/device/{device}"],
        )
    except Exception as e:
        msg, _ = client_safe_error(e)
        return None, msg
    error = _proxy_error(raw)
    if error:
        return None, error
    results = _proxy_results(raw)
    if results is None:
        return None, "no data returned"
    return results, None


def _live_tunnel(vpn_results: Any, name: str) -> dict[str, Any] | None:
    """Pick one tunnel out of ``monitor/vpn/ipsec`` and condense it."""
    if not isinstance(vpn_results, list):
        return None
    for entry in vpn_results:
        if isinstance(entry, dict) and entry.get("name") == name:
            return _condense_tunnel(entry)
    return None


def _condense_tunnel(entry: dict[str, Any]) -> dict[str, Any]:
    selectors = [
        {"name": p.get("p2name"), "status": p.get("status")}
        for p in _as_list(entry.get("proxyid"))
        if isinstance(p, dict)
    ]
    return {
        "name": entry.get("name"),
        "remote_gateway": entry.get("rgwy"),
        "up": any(s["status"] == "up" for s in selectors),
        "phase2": selectors,
        "incoming_bytes": entry.get("incoming_bytes"),
        "outgoing_bytes": entry.get("outgoing_bytes"),
    }


def _sdwan_member(members: Any, interface: str | None) -> dict[str, Any] | None:
    if not isinstance(members, list) or not interface:
        return None
    for m in members:
        if isinstance(m, dict) and m.get("interface") == interface:
            return {"link": m.get("link"), "since": _since(m.get("state_changed"))}
    return None


def _health_for(health: Any, interface: str | None) -> list[dict[str, Any]]:
    """Every health-check's verdict for one SD-WAN member."""
    if not isinstance(health, dict) or not interface:
        return []
    out = []
    for hc_name, per_member in health.items():
        stats = per_member.get(interface) if isinstance(per_member, dict) else None
        if isinstance(stats, dict):
            out.append(
                {
                    "health_check": hc_name,
                    "status": stats.get("status"),
                    "latency": stats.get("latency"),
                    "packet_loss": stats.get("packet_loss"),
                    "sla_targets_met": stats.get("sla_targets_met"),
                }
            )
    return out


async def _hub_side(
    client: Any,
    adom: str,
    hub: str,
    vdom: str,
    network_id: Any,
    spoke_ip: str | None,
    unverified: list[str],
) -> dict[str, Any]:
    """Find the hub's dial-up gateway for this overlay and read its state.

    The hub gateway is matched on ``network-id``, which is what pairs a
    spoke tunnel with a hub dial-up gateway on FortiOS 7.x overlays. The
    spoke's dial-up instance on the hub is the one whose remote gateway is
    the spoke's underlay address.
    """
    hub_info: dict[str, Any] = {"device": hub}
    if network_id in (None, 0, "0"):
        unverified.append("hub tunnel: the spoke gateway has no network-id to match on")
        return hub_info
    try:
        gateways = await client.list_device_ipsec_phase1_interfaces(device=hub, vdom=vdom)
    except Exception as e:
        msg, _ = client_safe_error(e)
        unverified.append(f"hub phase1 config: {msg}")
        return hub_info
    match = next(
        (
            g
            for g in _as_list(gateways)
            if isinstance(g, dict)
            and g.get("network-id") == network_id
            and g.get("type") in _DIALUP_TYPES
        ),
        None,
    )
    if match is None:
        hub_info["tunnel"] = None
        unverified.append(f"hub tunnel: no dial-up gateway with network-id {network_id} on {hub}")
        return hub_info

    hub_tunnel = match.get("name")
    hub_underlay = _first(match.get("interface"))
    hub_info.update({"tunnel": hub_tunnel, "underlay": hub_underlay})

    interfaces, err = await _live_get(client, adom, hub, "/api/v2/monitor/system/interface")
    if err:
        unverified.append(f"hub interface status: {err}")
    elif isinstance(interfaces, dict) and isinstance(interfaces.get(hub_underlay), dict):
        hub_info["underlay_link"] = interfaces[hub_underlay].get("link")

    vpn, err = await _live_get(client, adom, hub, "/api/v2/monitor/vpn/ipsec")
    if err:
        unverified.append(f"hub tunnel status: {err}")
    elif isinstance(vpn, list):
        instances = [
            _condense_tunnel(e)
            for e in vpn
            if isinstance(e, dict)
            and (
                e.get("parent") == hub_tunnel or str(e.get("name", "")).startswith(f"{hub_tunnel}_")
            )
        ]
        hub_info["instances_up"] = sum(1 for i in instances if i["up"])
        hub_info["instances"] = len(instances)
        if spoke_ip:
            hub_info["spoke_instance"] = next(
                (i for i in instances if i["remote_gateway"] == spoke_ip), None
            )
    return hub_info


def _verdict(
    tunnel: str,
    underlay: str | None,
    ev: dict[str, Any],
) -> tuple[str, str, list[str]]:
    """Turn the gathered evidence into (verdict, explanation, next steps)."""
    u = ev["underlay"]
    t = ev["tunnel"]
    hub = ev.get("hub") or {}
    hcs = ev["health_checks"]

    if u.get("admin_status") in _ADMIN_DOWN:
        return (
            "underlay_admin_down",
            f"{underlay} is administratively disabled, so {tunnel} has no path.",
            [f"Enable {underlay} (set status up) and install device settings."],
        )
    if u.get("link") is False:
        since = (u.get("sdwan") or {}).get("since")
        return (
            "underlay_link_down",
            f"{underlay} has no physical link"
            + (f" (down since {since})" if since else "")
            + f"; {tunnel} rides on it and cannot negotiate. The IPsec config is not the cause.",
            [
                f"Restore the link on {underlay}: cable, switch port, or the VM's virtual NIC.",
                f"The tunnel auto-negotiates once {underlay} is back; recheck with this tool.",
            ],
        )
    # "0.0.0.0" is how FortiOS reports an interface without an address.
    if u.get("link") is True and "ip" in u and u["ip"] in ("0.0.0.0", "", None):  # nosec B104
        return (
            "underlay_no_address",
            f"{underlay} is up but has no IPv4 address, so IKE cannot be sourced from it.",
            [f"Check DHCP/PPPoE or the static address on {underlay}."],
        )
    if hub.get("underlay_link") is False:
        return (
            "hub_underlay_link_down",
            f"The hub's {hub.get('underlay')} has no link; every spoke tunnel on "
            f"{hub.get('tunnel')} is affected, not only this one.",
            [f"Restore {hub.get('underlay')} on {hub.get('device')}."],
        )
    if t.get("up") is False:
        # The peer address stays out of the prose: free text is not masked,
        # so an address written into it would pass FMG_MASKING in clear. It
        # is in evidence.gateway.remote_gw, where masking reaches it.
        steps = [
            f"From the device: execute ping-options source <{underlay} IP>; "
            "execute ping <evidence.gateway.remote_gw>",
            f"diagnose vpn ike gateway list name {tunnel}",
            "diagnose debug application ike -1; diagnose debug enable (PSK, proposal, "
            "peer ID or network-id mismatch shows here)",
        ]
        if hub.get("tunnel") and hub.get("spoke_instance") is None and "instances" in hub:
            steps.insert(0, f"The hub has no {hub['tunnel']} instance from this spoke yet.")
        return (
            "tunnel_down",
            f"{underlay} is up but {tunnel} is not established: the remote gateway "
            "(evidence.gateway.remote_gw) is unreachable over this underlay or IKE "
            "negotiation fails.",
            steps,
        )
    down_hcs = [h["health_check"] for h in hcs if h.get("status") == "down"]
    if t.get("up") and down_hcs:
        return (
            "health_check_down",
            f"{tunnel} is established but health-check {', '.join(down_hcs)} sees no "
            "replies through it, so SD-WAN treats the member as dead.",
            [
                "Check the probe server is reachable through the tunnel and answers "
                "(routing on the hub, firewall policy for the probe).",
            ],
        )
    degraded = [
        h["health_check"] for h in hcs if h.get("status") == "up" and not h.get("sla_targets_met")
    ]
    if t.get("up") and degraded:
        return (
            "sla_not_met",
            f"{tunnel} is up but misses its SLA on {', '.join(degraded)}.",
            ["Compare latency/jitter/loss with the SLA thresholds (get_device_sdwan)."],
        )
    if t.get("up"):
        return "healthy", f"{tunnel} and {underlay} are up and health checks pass.", []
    return (
        "undetermined",
        "The live state could not be read; see unverified.",
        ["Check the device is connected to FortiManager (get_device_status)."],
    )


@mcp.tool()
async def diagnose_ipsec_tunnel(
    device: str,
    tunnel: str,
    adom: str | None = None,
    vdom: str = "root",
    hub_device: str | None = None,
) -> dict[str, Any]:
    """Diagnose why an IPsec overlay tunnel is down, underlay first.

    Gathers, in one call, what an engineer checks before comparing IPsec
    proposals: the underlay interface the gateway is bound to (admin status
    in the device DB, live link and address), the tunnel's live IKE/phase2
    state, its SD-WAN member state and health-check results and, with
    ``hub_device``, the hub's matching dial-up gateway (matched on
    ``network-id``) and whether the hub holds an instance from this spoke.
    Read-only: config comes from the FMG device DB, live state from the
    device's monitor API through the FMG proxy.

    The verdict follows the first failing layer: ``underlay_admin_down``,
    ``underlay_link_down``, ``underlay_no_address``, ``hub_underlay_link_down``,
    ``tunnel_down`` (underlay fine, IKE not up), ``health_check_down``,
    ``sla_not_met``, ``healthy``, or ``undetermined`` when live state could
    not be read.

    Args:
        device: Device the tunnel lives on (e.g. "branch2")
        tunnel: Phase1-interface name (e.g. "HUB1-VPN2")
        adom: ADOM of the device (default: DEFAULT_ADOM or "root")
        vdom: VDOM of the tunnel (default "root")
        hub_device: Optional hub device to check the far side on

    Returns:
        dict: device, tunnel, verdict, explanation, next_steps, evidence
        (gateway, underlay, tunnel, health_checks, hub) and unverified
        (sources that could not be read)
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom or get_default_adom())
        device = validate_device_name(device)
        tunnel = validate_object_name(tunnel, "phase1-interface")
        vdom = validate_object_name(vdom, "VDOM")
        if hub_device is not None:
            hub_device = validate_device_name(hub_device)

        try:
            gateway = await client.get_device_ipsec_phase1_interface(
                device=device, vdom=vdom, name=tunnel
            )
        except ResourceNotFoundError:
            gateway = None
        gateway = _first(gateway) if isinstance(gateway, list) else gateway
        if not isinstance(gateway, dict) or not gateway:
            return {
                "error": f"phase1-interface '{tunnel}' not found on {device} (vdom {vdom})",
                "error_code": "not_found",
            }
    except Exception as e:
        logger.error(f"IPsec tunnel diagnosis failed for {device}/{tunnel}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}

    unverified: list[str] = []
    underlay = _first(gateway.get("interface"))
    remote_gw = gateway.get("remote-gw")
    network_id = gateway.get("network-id")

    underlay_ev: dict[str, Any] = {"name": underlay}
    if underlay:
        try:
            config = await client.get_device_interface_config(device=device, name=underlay)
            config = _first(config) if isinstance(config, list) else config
            if isinstance(config, dict):
                underlay_ev["admin_status"] = config.get("status")
        except Exception as e:
            msg, _ = client_safe_error(e)
            unverified.append(f"underlay config: {msg}")

    interfaces, err = await _live_get(client, adom, device, "/api/v2/monitor/system/interface")
    if err:
        unverified.append(f"interface status: {err}")
    elif isinstance(interfaces, dict) and isinstance(interfaces.get(underlay), dict):
        live = interfaces[underlay]
        underlay_ev["link"] = live.get("link")
        underlay_ev["ip"] = live.get("ip")

    vpn, err = await _live_get(client, adom, device, "/api/v2/monitor/vpn/ipsec")
    tunnel_ev: dict[str, Any] = {}
    if err:
        unverified.append(f"tunnel status: {err}")
    else:
        live_tunnel = _live_tunnel(vpn, tunnel)
        # A configured tunnel the monitor does not list has no IKE SA at all.
        tunnel_ev = live_tunnel or {"name": tunnel, "up": False, "phase2": []}

    members, err = await _live_get(client, adom, device, "/api/v2/monitor/virtual-wan/members")
    if err:
        unverified.append(f"SD-WAN members: {err}")
    else:
        underlay_ev["sdwan"] = _sdwan_member(members, underlay)
        tunnel_ev["sdwan"] = _sdwan_member(members, tunnel)

    health, err = await _live_get(client, adom, device, "/api/v2/monitor/virtual-wan/health-check")
    if err:
        unverified.append(f"SD-WAN health checks: {err}")
    health_ev = _health_for(health, tunnel)

    evidence: dict[str, Any] = {
        "gateway": {
            "interface": underlay,
            "remote_gw": remote_gw,
            "network_id": network_id,
            "type": gateway.get("type"),
            "auto_negotiate": gateway.get("auto-negotiate"),
        },
        "underlay": underlay_ev,
        "tunnel": tunnel_ev,
        "health_checks": health_ev,
    }
    if hub_device:
        evidence["hub"] = await _hub_side(
            client, adom, hub_device, vdom, network_id, underlay_ev.get("ip"), unverified
        )

    verdict, explanation, next_steps = _verdict(tunnel, underlay, evidence)
    return {
        "adom": adom,
        "device": device,
        "tunnel": tunnel,
        "verdict": verdict,
        "explanation": explanation,
        "next_steps": next_steps,
        "evidence": evidence,
        "unverified": unverified,
    }


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
        dict: Assignment result with keys:
            - success: True
            - requested_count: Number of devices in the request. NOT a
              count of assignments actually made: FortiManager reports no
              per-device result for this scope-member ADD, and the client
              raises on any non-zero code, so everything reaching this
              line is a code 0 that says nothing about individual devices
              (same shape as #78's device-group bulk tools).
            - result: Raw client result
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
            "requested_count": len(devices),
            "message": (
                f"Requested assignment of SD-WAN template '{template}' to "
                f"{len(devices)} device(s). FortiManager does not report "
                "per-device results, so this does not confirm the assignments "
                "were made."
            ),
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
