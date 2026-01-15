"""CLI Script management tools for FortiManager MCP.

Provides tools for managing and executing CLI scripts on FortiManager.
Scripts can target device database, ADOM database, or remote devices.

Based on FNDN FortiManager 7.6.5 API specifications.
"""

from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp

# =============================================================================
# Script CRUD Operations
# =============================================================================


@mcp.tool()
async def list_scripts(
    adom: str = "root",
    script_type: str | None = None,
    target: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List CLI scripts in an ADOM.

    Args:
        adom: ADOM name (default: root)
        script_type: Filter by type (cli, tcl, cligrp, tclgrp, jinja)
        target: Filter by target (device_database, remote_device, adom_database)
        limit: Maximum number of scripts to return

    Returns:
        List of scripts with name, type, target, and description
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        # Build filter if type or target specified
        filter_conditions = []
        if script_type:
            filter_conditions.append(["type", "==", script_type])
        if target:
            filter_conditions.append(["target", "==", target])

        filter_param = filter_conditions if filter_conditions else None

        scripts = await client.list_scripts(
            adom=adom,
            fields=["name", "type", "target", "desc", "content", "modification_time"],
            filter=filter_param,
        )

        # Limit results
        scripts = scripts[:limit] if scripts else []

        return {
            "adom": adom,
            "count": len(scripts),
            "scripts": scripts,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def get_script(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a specific CLI script.

    Args:
        adom: ADOM name
        name: Script name

    Returns:
        Script details including content
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        script = await client.get_script(adom=adom, name=name)
        return {"script": script}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def create_script(
    adom: str,
    name: str,
    content: str,
    script_type: str = "cli",
    target: str = "device_database",
    description: str | None = None,
) -> dict[str, Any]:
    """Create a new CLI script.

    Args:
        adom: ADOM name
        name: Script name
        content: Script content (CLI commands)
        script_type: Script type - cli, tcl, cligrp, tclgrp, jinja (default: cli)
        target: Execution target (default: device_database)
            - device_database: Device Database
            - adom_database: Policy Package or ADOM Database
            - remote_device: Remote FortiGate Directly (via CLI)
        description: Script description

    Returns:
        Created script details
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        script_data: dict[str, Any] = {
            "name": name,
            "content": content,
            "type": script_type,
            "target": target,
        }
        if description:
            script_data["desc"] = description

        result = await client.create_script(adom=adom, script=script_data)
        return {
            "success": True,
            "message": f"Script '{name}' created successfully",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def update_script(
    adom: str,
    name: str,
    content: str | None = None,
    description: str | None = None,
    script_type: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    """Update an existing CLI script.

    Args:
        adom: ADOM name
        name: Script name to update
        content: New script content
        description: New description
        script_type: New script type
        target: New target

    Returns:
        Updated script details
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        update_data: dict[str, Any] = {}
        if content is not None:
            update_data["content"] = content
        if description is not None:
            update_data["desc"] = description
        if script_type is not None:
            update_data["type"] = script_type
        if target is not None:
            update_data["target"] = target

        if not update_data:
            return {"error": "No update parameters provided"}

        result = await client.update_script(adom=adom, name=name, data=update_data)
        return {
            "success": True,
            "message": f"Script '{name}' updated successfully",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def delete_script(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a CLI script.

    Args:
        adom: ADOM name
        name: Script name to delete

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        result = await client.delete_script(adom=adom, name=name)
        return {
            "success": True,
            "message": f"Script '{name}' deleted successfully",
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# Script Execution
# =============================================================================


@mcp.tool()
async def execute_script_on_device(
    adom: str,
    script: str,
    device: str,
) -> dict[str, Any]:
    """Execute a CLI script on a specific device.

    The script must have target=remote_device to run directly on the device.
    Script execution creates a task that should be monitored for completion.

    IMPORTANT: Keep the session alive while script executes on remote devices.

    Args:
        adom: ADOM name
        script: Script name to execute
        device: Target device name

    Returns:
        Task ID for monitoring execution progress
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        # vdom: global means target is a device (not a VDOM)
        scope = [{"name": device, "vdom": "global"}]
        result = await client.execute_script(adom=adom, script=script, scope=scope)
        return {
            "success": True,
            "message": f"Script '{script}' execution started on device '{device}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def execute_script_on_devices(
    adom: str,
    script: str,
    devices: list[str],
) -> dict[str, Any]:
    """Execute a CLI script on multiple devices.

    Args:
        adom: ADOM name
        script: Script name to execute
        devices: List of device names

    Returns:
        Task ID for monitoring execution progress
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        scope = [{"name": device, "vdom": "global"} for device in devices]
        result = await client.execute_script(adom=adom, script=script, scope=scope)
        return {
            "success": True,
            "message": f"Script '{script}' execution started on {len(devices)} devices",
            "task_id": result.get("task"),
            "devices": devices,
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def execute_script_on_device_group(
    adom: str,
    script: str,
    group: str,
) -> dict[str, Any]:
    """Execute a CLI script on a device group.

    Args:
        adom: ADOM name
        script: Script name to execute
        group: Device group name

    Returns:
        Task ID for monitoring execution progress
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        # No vdom attribute means it's a device group
        scope = [{"name": group}]
        result = await client.execute_script(adom=adom, script=script, scope=scope)
        return {
            "success": True,
            "message": f"Script '{script}' execution started on device group '{group}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def execute_script_on_package(
    adom: str,
    script: str,
    package: str,
) -> dict[str, Any]:
    """Execute a CLI script against a policy package or ADOM database.

    The script must have target=adom_database.
    This modifies the package/ADOM DB, not a live device.

    Args:
        adom: ADOM name
        script: Script name to execute
        package: Policy package name

    Returns:
        Task ID for monitoring execution progress
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        result = await client.execute_script(adom=adom, script=script, package=package)
        return {
            "success": True,
            "message": f"Script '{script}' execution started on package '{package}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# Script Execution Logs
# =============================================================================


@mcp.tool()
async def get_script_log_latest(
    adom: str,
    device: str | None = None,
) -> dict[str, Any]:
    """Get the latest script execution log.

    Args:
        adom: ADOM name
        device: Optional device name to filter logs

    Returns:
        Latest script execution log with content and execution time
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        result = await client.get_script_log_latest(adom=adom, device=device)
        return {"log": result}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def get_script_log_summary(
    adom: str,
    device: str | None = None,
) -> dict[str, Any]:
    """Get script execution log summary.

    Lists all script executions with log IDs for detailed retrieval.

    Args:
        adom: ADOM name
        device: Optional device name to filter logs

    Returns:
        List of script execution summaries with log_id, script_name, exec_time
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        logs = await client.get_script_log_summary(adom=adom, device=device)
        return {
            "adom": adom,
            "device": device,
            "count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def get_script_log_output(
    adom: str,
    log_id: int,
    device: str | None = None,
) -> dict[str, Any]:
    """Get specific script execution output by log ID.

    Log ID can be derived from task ID:
    - Scripts on Device DB or Package: log_id = str(task_id) + "1"
    - Scripts on remote device: log_id = str(task_id) + "0"

    Args:
        adom: ADOM name
        log_id: Log ID from execution task or log summary
        device: Optional device name (required for device-specific logs)

    Returns:
        Script execution output content
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        result = await client.get_script_log_output(adom=adom, log_id=log_id, device=device)
        return {"log": result}
    except Exception as e:
        return {"error": str(e)}
