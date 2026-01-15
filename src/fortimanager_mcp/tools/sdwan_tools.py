"""SD-WAN template management tools for FortiManager MCP.

Provides tools for managing SD-WAN templates (wanprof) including:
- Listing and viewing SD-WAN templates
- Creating and deleting templates
- Assigning templates to devices

Based on FNDN FortiManager 7.6.5 API specifications.
"""

from typing import Any

from fortimanager_mcp.server import mcp, get_fmg_client


# =============================================================================
# SD-WAN Template Operations
# =============================================================================


@mcp.tool()
async def list_sdwan_templates(
    adom: str = "root",
    limit: int = 100,
) -> dict[str, Any]:
    """List SD-WAN templates in an ADOM.

    SD-WAN templates define WAN interface configurations, performance SLAs,
    and traffic steering rules for SD-WAN deployments.

    Args:
        adom: ADOM name (default: root)
        limit: Maximum number of templates to return

    Returns:
        List of SD-WAN templates with name, type, and assigned devices
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        templates = await client.list_sdwan_templates(adom=adom)
        templates = templates[:limit] if templates else []

        return {
            "adom": adom,
            "count": len(templates),
            "sdwan_templates": templates,
        }
    except Exception as e:
        return {"error": str(e)}


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
        template = await client.get_sdwan_template(adom=adom, name=name)
        return {"sdwan_template": template}
    except Exception as e:
        return {"error": str(e)}


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
        return {"error": str(e)}


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
        result = await client.delete_sdwan_template(adom=adom, name=name)
        return {
            "success": True,
            "message": f"SD-WAN template '{name}' deleted",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


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
        scope = [{"name": device, "vdom": vdom}]
        result = await client.assign_sdwan_template(
            adom=adom, template=template, scope=scope
        )
        return {
            "success": True,
            "message": f"SD-WAN template '{template}' assigned to device '{device}'",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


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
        result = await client.assign_sdwan_template(
            adom=adom, template=template, scope=devices
        )
        return {
            "success": True,
            "message": f"SD-WAN template '{template}' assigned to {len(devices)} devices",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


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
        scope = [{"name": device, "vdom": vdom}]
        result = await client.unassign_sdwan_template(
            adom=adom, template=template, scope=scope
        )
        return {
            "success": True,
            "message": f"SD-WAN template '{template}' unassigned from device '{device}'",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}
