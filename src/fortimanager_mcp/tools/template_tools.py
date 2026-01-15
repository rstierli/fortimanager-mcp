"""Provisioning template management tools for FortiManager MCP.

Provides tools for managing provisioning templates including:
- System templates (devprof) - device configuration templates
- CLI template groups - CLI command templates
- Template groups - combined template packages

Based on FNDN FortiManager 7.6.5 API specifications.
"""

from typing import Any

from fortimanager_mcp.server import mcp, get_fmg_client


# =============================================================================
# Provisioning Templates (General)
# =============================================================================


@mcp.tool()
async def list_templates(
    adom: str = "root",
    limit: int = 100,
) -> dict[str, Any]:
    """List all provisioning templates in an ADOM.

    Returns all template types: IPsec, BGP, system, etc.

    Args:
        adom: ADOM name (default: root)
        limit: Maximum number of templates to return

    Returns:
        List of templates with name, type, and settings
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        templates = await client.list_templates(adom=adom)
        templates = templates[:limit] if templates else []

        return {
            "adom": adom,
            "count": len(templates),
            "templates": templates,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def get_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a specific provisioning template.

    Args:
        adom: ADOM name
        name: Template name

    Returns:
        Template details including settings and scope
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        template = await client.get_template(adom=adom, name=name)
        return {"template": template}
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# System Templates (devprof)
# =============================================================================


@mcp.tool()
async def list_system_templates(
    adom: str = "root",
    limit: int = 100,
) -> dict[str, Any]:
    """List system templates (device profiles) in an ADOM.

    System templates configure device settings like DNS, NTP, logging, etc.

    Args:
        adom: ADOM name (default: root)
        limit: Maximum number to return

    Returns:
        List of system templates with name, type, and assigned devices
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        templates = await client.list_system_templates(adom=adom)
        templates = templates[:limit] if templates else []

        return {
            "adom": adom,
            "count": len(templates),
            "templates": templates,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def get_system_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a specific system template.

    Args:
        adom: ADOM name
        name: System template name

    Returns:
        System template details including widgets and assigned devices
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        template = await client.get_system_template(adom=adom, name=name)
        return {"template": template}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def assign_system_template(
    adom: str,
    template: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Assign a system template to a device.

    Args:
        adom: ADOM name
        template: System template name
        device: Device name to assign
        vdom: VDOM name (default: root)

    Returns:
        Assignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        scope = [{"name": device, "vdom": vdom}]
        result = await client.assign_system_template(
            adom=adom, template=template, scope=scope
        )
        return {
            "success": True,
            "message": f"System template '{template}' assigned to device '{device}'",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def assign_system_template_bulk(
    adom: str,
    template: str,
    devices: list[dict[str, str]],
) -> dict[str, Any]:
    """Assign a system template to multiple devices.

    Args:
        adom: ADOM name
        template: System template name
        devices: List of devices [{"name": "dev1", "vdom": "root"}, ...]

    Returns:
        Assignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        result = await client.assign_system_template(
            adom=adom, template=template, scope=devices
        )
        return {
            "success": True,
            "message": f"System template '{template}' assigned to {len(devices)} devices",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def unassign_system_template(
    adom: str,
    template: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Unassign a system template from a device.

    Args:
        adom: ADOM name
        template: System template name
        device: Device name to unassign
        vdom: VDOM name (default: root)

    Returns:
        Unassignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        scope = [{"name": device, "vdom": vdom}]
        result = await client.unassign_system_template(
            adom=adom, template=template, scope=scope
        )
        return {
            "success": True,
            "message": f"System template '{template}' unassigned from device '{device}'",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# CLI Template Groups
# =============================================================================


@mcp.tool()
async def list_cli_template_groups(
    adom: str = "root",
    limit: int = 100,
) -> dict[str, Any]:
    """List CLI template groups in an ADOM.

    CLI template groups contain CLI commands to be executed on devices.

    Args:
        adom: ADOM name (default: root)
        limit: Maximum number to return

    Returns:
        List of CLI template groups
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        groups = await client.list_cli_template_groups(adom=adom)
        groups = groups[:limit] if groups else []

        return {
            "adom": adom,
            "count": len(groups),
            "cli_template_groups": groups,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def get_cli_template_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a CLI template group.

    Args:
        adom: ADOM name
        name: CLI template group name

    Returns:
        CLI template group details
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        group = await client.get_cli_template_group(adom=adom, name=name)
        return {"cli_template_group": group}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def create_cli_template_group(
    adom: str,
    name: str,
    description: str | None = None,
) -> dict[str, Any]:
    """Create a new CLI template group.

    Args:
        adom: ADOM name
        name: CLI template group name
        description: Optional description

    Returns:
        Created CLI template group
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        group_data: dict[str, Any] = {"name": name}
        if description:
            group_data["description"] = description

        result = await client.create_cli_template_group(adom=adom, group=group_data)
        return {
            "success": True,
            "message": f"CLI template group '{name}' created",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def delete_cli_template_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a CLI template group.

    Args:
        adom: ADOM name
        name: CLI template group name

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        result = await client.delete_cli_template_group(adom=adom, name=name)
        return {
            "success": True,
            "message": f"CLI template group '{name}' deleted",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# Template Groups (Combined Templates)
# =============================================================================


@mcp.tool()
async def list_template_groups(
    adom: str = "root",
    limit: int = 100,
) -> dict[str, Any]:
    """List template groups in an ADOM.

    Template groups combine multiple templates (system, CLI, SD-WAN, etc.)
    into a single package for device assignment.

    Args:
        adom: ADOM name (default: root)
        limit: Maximum number to return

    Returns:
        List of template groups
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        groups = await client.list_template_groups(adom=adom)
        groups = groups[:limit] if groups else []

        return {
            "adom": adom,
            "count": len(groups),
            "template_groups": groups,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def get_template_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a template group.

    Args:
        adom: ADOM name
        name: Template group name

    Returns:
        Template group details including member templates
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        group = await client.get_template_group(adom=adom, name=name)
        return {"template_group": group}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def assign_template_group(
    adom: str,
    template_group: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Assign a template group to a device.

    Args:
        adom: ADOM name
        template_group: Template group name
        device: Device name
        vdom: VDOM name (default: root)

    Returns:
        Assignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        scope = [{"name": device, "vdom": vdom}]
        result = await client.assign_template_group(
            adom=adom, template_group=template_group, scope=scope
        )
        return {
            "success": True,
            "message": f"Template group '{template_group}' assigned to device '{device}'",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# Template Validation
# =============================================================================


@mcp.tool()
async def validate_template(
    adom: str,
    template_group: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Validate a template group for a device.

    Checks that all metadata variables are resolved for the device.

    Args:
        adom: ADOM name
        template_group: Template group name
        device: Target device name
        vdom: VDOM name (default: root)

    Returns:
        Task ID for monitoring validation progress
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        pkg = f"adom/{adom}/tmplgrp/{template_group}"
        scope = [{"name": device, "vdom": vdom}]
        result = await client.validate_template(adom=adom, pkg=pkg, scope=scope)
        return {
            "success": True,
            "message": f"Template validation started for '{template_group}' on '{device}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}
