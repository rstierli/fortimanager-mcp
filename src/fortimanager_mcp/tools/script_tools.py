"""CLI Script management tools for FortiManager MCP.

Provides tools for managing and executing CLI scripts on FortiManager.
Scripts can target device database, ADOM database, or remote devices.

Based on FNDN FortiManager 7.6.5 API specifications.
"""

import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom, get_settings
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.responses import error_response
from fortimanager_mcp.utils.task_guard import TaskSlotsExhausted, spawn_guarded
from fortimanager_mcp.utils.validation import (
    validate_adom,
    validate_device_name,
    validate_object_name,
    validate_package_name,
    validate_script_content,
)

logger = logging.getLogger(__name__)

# Script types whose commands can be assembled at runtime (Tcl), so static
# regex screening of their content is meaningless. Blocked under strict safety.
UNSCREENABLE_SCRIPT_TYPES = {"tcl", "tclgrp"}


def _check_script_type_safety(script_type: str | None) -> dict[str, Any] | None:
    """Block script types that defeat static content screening.

    Under strict safety, Tcl scripts (tcl, tclgrp) are rejected because their
    commands can be built dynamically at execution time — the regex content
    check cannot see what they will actually run.

    Returns error dict if blocked, None if OK.
    """
    settings = get_settings()
    if settings.FMG_SCRIPT_SAFETY != "strict":
        return None

    if script_type and script_type.lower() in UNSCREENABLE_SCRIPT_TYPES:
        logger.warning(f"Script blocked — unscreenable script type: {script_type}")
        return {
            "error": f"Script type '{script_type}' cannot be safety-screened because its "
            "commands can be assembled at runtime. "
            "Set FMG_SCRIPT_SAFETY=disabled to override.",
        }
    return None


def _check_script_safety(content: str) -> dict[str, Any] | None:
    """Check script content for dangerous commands based on safety config.

    Returns error dict if blocked, None if OK.
    """
    settings = get_settings()
    if settings.FMG_SCRIPT_SAFETY == "disabled":
        return None

    matches = validate_script_content(content)
    if matches:
        blocked = ", ".join(matches)
        logger.warning(f"Script blocked — dangerous commands detected: {blocked}")
        return {
            "error": f"Script contains dangerous commands: {blocked}. "
            "These commands can cause device outages or data loss. "
            "Set FMG_SCRIPT_SAFETY=disabled to override.",
        }
    return None


async def _check_stored_script_safety(client: Any, adom: str, script: str) -> dict[str, Any] | None:
    """Re-validate the body of a stored script before executing it.

    Execute tools run a script that already exists on the FortiManager. That
    script may have been created while safety was disabled, or pre-existed on
    the FMG, so its content must be re-checked at execution time — not just at
    create/update time.

    Fetches the stored script content and runs it through the safety check.
    Returns an error dict if the script is blocked (or cannot be resolved when
    safety is enabled), None if OK or safety is disabled.
    """
    settings = get_settings()
    if settings.FMG_SCRIPT_SAFETY == "disabled":
        return None

    try:
        stored = await client.get_script(adom=adom, name=script)
    except Exception as e:
        # Fail closed: if we can't verify the script body while safety is on,
        # do not execute it. Log the detail server-side, return a generic note.
        logger.warning(f"Script safety pre-check could not resolve script '{script}': {e}")
        return {
            "error": f"Could not verify script '{script}' content before execution. "
            "Execution blocked by script safety. "
            "Set FMG_SCRIPT_SAFETY=disabled to override.",
        }

    content = ""
    stored_type = ""
    if isinstance(stored, dict):
        content = stored.get("content") or ""
        stored_type = stored.get("type") or ""

    type_error = _check_script_type_safety(str(stored_type))
    if type_error:
        return type_error

    if not isinstance(content, str):
        content = str(content)

    return _check_script_safety(content)


# =============================================================================
# Script CRUD Operations
# =============================================================================


@mcp.tool()
async def list_scripts(
    adom: str | None = None,
    script_type: str | None = None,
    target: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List CLI scripts in an ADOM.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        script_type: Filter by type (cli, tcl, cligrp, tclgrp, jinja)
        target: Filter by target (device_database, remote_device, adom_database)
        limit: Maximum number of scripts to return

    Returns:
        List of scripts with name, type, target, and description
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
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
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        name = validate_object_name(name, "script")
        script = await client.get_script(adom=adom, name=name)
        return {"script": script}
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
    # Safety check before creating
    type_error = _check_script_type_safety(script_type)
    if type_error:
        return type_error
    safety_error = _check_script_safety(content)
    if safety_error:
        return safety_error

    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "script")
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
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
    # Block unscreenable script types (e.g. Tcl) when they are being set
    type_error = _check_script_type_safety(script_type)
    if type_error:
        return type_error
    # Safety check if content is being updated
    if content is not None:
        safety_error = _check_script_safety(content)
        if safety_error:
            return safety_error

    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "script")
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
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        name = validate_object_name(name, "script")
        result = await client.delete_script(adom=adom, name=name)
        return {
            "success": True,
            "message": f"Script '{name}' deleted successfully",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        script = validate_object_name(script, "script")
        device = validate_device_name(device)
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}

    # Re-validate the resolved script body before execution
    safety_error = await _check_stored_script_safety(client, adom, script)
    if safety_error:
        return safety_error

    try:
        # vdom: global means target is a device (not a VDOM)
        scope = [{"name": device, "vdom": "global"}]
        result = await spawn_guarded(
            "execute_script_on_device",
            lambda: client.execute_script(adom=adom, script=script, scope=scope),
        )
        return {
            "success": True,
            "message": f"Script '{script}' execution started on device '{device}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="execute_script_on_device",
            adom=adom,
            device=device,
        )
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        script = validate_object_name(script, "script")
        devices = [validate_device_name(d) for d in devices]
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}

    # Re-validate the resolved script body before execution
    safety_error = await _check_stored_script_safety(client, adom, script)
    if safety_error:
        return safety_error

    try:
        scope = [{"name": device, "vdom": "global"} for device in devices]
        result = await spawn_guarded(
            "execute_script_on_devices",
            lambda: client.execute_script(adom=adom, script=script, scope=scope),
        )
        return {
            "success": True,
            "message": f"Script '{script}' execution started on {len(devices)} devices",
            "task_id": result.get("task"),
            "devices": devices,
            "result": result,
        }
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="execute_script_on_devices",
            adom=adom,
        )
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        script = validate_object_name(script, "script")
        group = validate_object_name(group, "device group")
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}

    # Re-validate the resolved script body before execution
    safety_error = await _check_stored_script_safety(client, adom, script)
    if safety_error:
        return safety_error

    try:
        # No vdom attribute means it's a device group
        scope = [{"name": group}]
        result = await spawn_guarded(
            "execute_script_on_device_group",
            lambda: client.execute_script(adom=adom, script=script, scope=scope),
        )
        return {
            "success": True,
            "message": f"Script '{script}' execution started on device group '{group}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="execute_script_on_device_group",
            adom=adom,
        )
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        script = validate_object_name(script, "script")
        package = validate_package_name(package)
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}

    # Re-validate the resolved script body before execution
    safety_error = await _check_stored_script_safety(client, adom, script)
    if safety_error:
        return safety_error

    try:
        result = await spawn_guarded(
            "execute_script_on_package",
            lambda: client.execute_script(adom=adom, script=script, package=package),
        )
        return {
            "success": True,
            "message": f"Script '{script}' execution started on package '{package}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="execute_script_on_package",
            adom=adom,
            package=package,
        )
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        if device is not None:
            device = validate_device_name(device)
        result = await client.get_script_log_latest(adom=adom, device=device)
        return {"log": result}
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        if device is not None:
            device = validate_device_name(device)
        logs = await client.get_script_log_summary(adom=adom, device=device)
        return {
            "adom": adom,
            "device": device,
            "count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


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
        adom = validate_adom(adom)
        if device is not None:
            device = validate_device_name(device)
        result = await client.get_script_log_output(adom=adom, log_id=log_id, device=device)
        return {"log": result}
    except Exception as e:
        logger.error(f"Script tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}
