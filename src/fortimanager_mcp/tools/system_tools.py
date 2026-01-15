"""System and ADOM management tools for FortiManager.

Based on FNDN FortiManager 7.6.5 SYS, DVMDB, and TASK API specifications.
"""

import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp

logger = logging.getLogger(__name__)


def _get_client():
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


# =============================================================================
# System Status
# =============================================================================


@mcp.tool()
async def get_system_status() -> dict[str, Any]:
    """Get FortiManager system status and version information.

    Returns comprehensive system status including:
    - FortiManager version and build
    - System hostname
    - Serial number
    - Admin domain mode
    - Platform information
    - HA status

    Returns:
        dict: System status with keys:
            - status: "success" or "error"
            - data: System status information
            - message: Error message if failed

    Example:
        >>> result = await get_system_status()
        >>> print(f"Version: {result['data']['Version']}")
        >>> print(f"Hostname: {result['data']['Hostname']}")
    """
    try:
        client = _get_client()
        data = await client.get_system_status()
        return {
            "status": "success",
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_ha_status() -> dict[str, Any]:
    """Get FortiManager High Availability (HA) status.

    Returns HA cluster status including:
    - HA mode (standalone, cluster)
    - Cluster members and their status
    - Sync status
    - Primary/secondary role

    Returns:
        dict: HA status with keys:
            - status: "success" or "error"
            - data: HA status information
            - message: Error message if failed

    Example:
        >>> result = await get_ha_status()
        >>> print(f"HA Mode: {result['data']['mode']}")
    """
    try:
        client = _get_client()
        data = await client.get_ha_status()
        return {
            "status": "success",
            "data": data,
        }
    except Exception as e:
        logger.error(f"Failed to get HA status: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# ADOM Management
# =============================================================================


@mcp.tool()
async def list_adoms(
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List all Administrative Domains (ADOMs) in FortiManager.

    ADOMs partition FortiManager into separate management domains,
    each with its own devices, policies, and configurations.

    Args:
        fields: Specific fields to return (optional, returns all if not specified)

    Returns:
        dict: ADOM list with keys:
            - status: "success" or "error"
            - count: Number of ADOMs
            - adoms: List of ADOM objects with name, desc, state, etc.
            - message: Error message if failed

    Example:
        >>> result = await list_adoms()
        >>> for adom in result["adoms"]:
        ...     print(f"{adom['name']}: {adom.get('desc', 'No description')}")
    """
    try:
        client = _get_client()
        adoms = await client.list_adoms(fields=fields)
        return {
            "status": "success",
            "count": len(adoms),
            "adoms": adoms,
        }
    except Exception as e:
        logger.error(f"Failed to list ADOMs: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_adom(
    name: str,
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific ADOM.

    Args:
        name: ADOM name (e.g., "root", "customer-a")
        include_details: Include sub-objects (default: False)

    Returns:
        dict: ADOM details with keys:
            - status: "success" or "error"
            - adom: ADOM object with full configuration
            - message: Error message if failed

    Example:
        >>> result = await get_adom("root")
        >>> print(f"State: {result['adom']['state']}")
    """
    try:
        client = _get_client()
        loadsub = 1 if include_details else 0
        adom = await client.get_adom(name, loadsub=loadsub)
        return {
            "status": "success",
            "adom": adom,
        }
    except Exception as e:
        logger.error(f"Failed to get ADOM {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Device Management
# =============================================================================


@mcp.tool()
async def list_devices(
    adom: str = "root",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List all managed devices in an ADOM.

    FortiManager manages FortiGate and other Fortinet devices.
    This lists all devices registered in the specified ADOM.

    Args:
        adom: ADOM name (default: "root")
        fields: Specific fields to return (optional)

    Returns:
        dict: Device list with keys:
            - status: "success" or "error"
            - count: Number of devices
            - devices: List of device objects with name, ip, os_ver, etc.
            - message: Error message if failed

    Example:
        >>> result = await list_devices("root")
        >>> for device in result["devices"]:
        ...     print(f"{device['name']}: {device.get('ip', 'N/A')}")
    """
    try:
        client = _get_client()
        devices = await client.list_devices(adom, fields=fields)
        return {
            "status": "success",
            "count": len(devices),
            "devices": devices,
        }
    except Exception as e:
        logger.error(f"Failed to list devices in ADOM {adom}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_device(
    name: str,
    adom: str = "root",
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific managed device.

    Args:
        name: Device name
        adom: ADOM name (default: "root")
        include_details: Include sub-objects like VDOMs (default: False)

    Returns:
        dict: Device details with keys:
            - status: "success" or "error"
            - device: Device object with full configuration
            - message: Error message if failed

    Example:
        >>> result = await get_device("FGT-HQ", "root")
        >>> print(f"Version: {result['device']['os_ver']}")
        >>> print(f"Platform: {result['device']['platform_str']}")
    """
    try:
        client = _get_client()
        loadsub = 1 if include_details else 0
        device = await client.get_device(name, adom, loadsub=loadsub)
        return {
            "status": "success",
            "device": device,
        }
    except Exception as e:
        logger.error(f"Failed to get device {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def list_device_groups(
    adom: str = "root",
) -> dict[str, Any]:
    """List all device groups in an ADOM.

    Device groups organize managed devices for bulk operations
    like policy installation or configuration deployment.

    Args:
        adom: ADOM name (default: "root")

    Returns:
        dict: Device groups with keys:
            - status: "success" or "error"
            - count: Number of groups
            - groups: List of device group objects
            - message: Error message if failed
    """
    try:
        client = _get_client()
        groups = await client.list_device_groups(adom)
        return {
            "status": "success",
            "count": len(groups),
            "groups": groups,
        }
    except Exception as e:
        logger.error(f"Failed to list device groups: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Task Management
# =============================================================================


@mcp.tool()
async def list_tasks(
    filter_state: str | None = None,
) -> dict[str, Any]:
    """List all tasks in FortiManager.

    Tasks represent background operations like policy installation,
    device provisioning, and other long-running processes.

    Args:
        filter_state: Filter by task state (optional):
            - "pending": Not started
            - "running": Currently executing
            - "done": Completed
            - "error": Failed
            - "cancelling": Being cancelled
            - "cancelled": Cancelled

    Returns:
        dict: Task list with keys:
            - status: "success" or "error"
            - count: Number of tasks
            - tasks: List of task objects with id, state, progress, etc.
            - message: Error message if failed

    Example:
        >>> # Get all tasks
        >>> result = await list_tasks()

        >>> # Get only running tasks
        >>> result = await list_tasks(filter_state="running")
    """
    try:
        client = _get_client()

        # Build filter if state specified
        filter_list = None
        if filter_state:
            filter_list = [["state", "==", filter_state]]

        tasks = await client.list_tasks(filter=filter_list)
        return {
            "status": "success",
            "count": len(tasks),
            "tasks": tasks,
        }
    except Exception as e:
        logger.error(f"Failed to list tasks: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_task(
    task_id: int,
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed status of a specific task.

    Args:
        task_id: Task ID number
        include_details: Include task line details (default: False)

    Returns:
        dict: Task details with keys:
            - status: "success" or "error"
            - task: Task object with id, state, progress, result, etc.
            - lines: Task line details (if include_details=True)
            - message: Error message if failed

    Example:
        >>> result = await get_task(12345)
        >>> print(f"State: {result['task']['state']}")
        >>> print(f"Progress: {result['task'].get('percent', 0)}%")
    """
    try:
        client = _get_client()
        task = await client.get_task(task_id)

        result: dict[str, Any] = {
            "status": "success",
            "task": task,
        }

        if include_details:
            lines = await client.get_task_line(task_id)
            result["lines"] = lines

        return result
    except Exception as e:
        logger.error(f"Failed to get task {task_id}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def wait_for_task(
    task_id: int,
    timeout: int = 300,
    poll_interval: int = 5,
) -> dict[str, Any]:
    """Wait for a task to complete.

    Polls the task status until it completes or times out.
    Useful for waiting on installation or provisioning operations.

    Args:
        task_id: Task ID number
        timeout: Maximum wait time in seconds (default: 300)
        poll_interval: Seconds between status checks (default: 5)

    Returns:
        dict: Final task status with keys:
            - status: "success" or "error"
            - task: Final task object
            - completed: Whether task completed (vs timeout)
            - message: Status or error message

    Example:
        >>> # Wait for policy installation
        >>> result = await wait_for_task(12345, timeout=600)
        >>> if result['completed']:
        ...     print("Installation finished!")
    """
    import asyncio

    try:
        client = _get_client()
        start_time = asyncio.get_event_loop().time()

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                return {
                    "status": "error",
                    "completed": False,
                    "message": f"Task {task_id} timed out after {timeout} seconds",
                }

            task = await client.get_task(task_id)
            state = task.get("state", "").lower() if isinstance(task.get("state"), str) else ""

            # Handle numeric state values
            if isinstance(task.get("state"), int):
                state_map = {0: "pending", 1: "running", 4: "done", 5: "error", 3: "cancelled"}
                state = state_map.get(task["state"], "unknown")

            # Check if completed
            if state in ("done", "error", "cancelled"):
                return {
                    "status": "success" if state == "done" else "error",
                    "task": task,
                    "completed": True,
                    "message": f"Task completed with state: {state}",
                }

            # Wait before next poll
            await asyncio.sleep(poll_interval)

    except Exception as e:
        logger.error(f"Failed to wait for task {task_id}: {e}")
        return {"status": "error", "completed": False, "message": str(e)}


# =============================================================================
# Policy Package Management
# =============================================================================


@mcp.tool()
async def list_packages(
    adom: str = "root",
) -> dict[str, Any]:
    """List all policy packages in an ADOM.

    Policy packages contain firewall policies, security profiles,
    and other configurations to be installed on managed devices.

    Args:
        adom: ADOM name (default: "root")

    Returns:
        dict: Package list with keys:
            - status: "success" or "error"
            - count: Number of packages
            - packages: List of package objects
            - message: Error message if failed

    Example:
        >>> result = await list_packages("root")
        >>> for pkg in result["packages"]:
        ...     print(f"{pkg['name']}: {pkg.get('type', 'policy')}")
    """
    try:
        client = _get_client()
        packages = await client.list_packages(adom)
        return {
            "status": "success",
            "count": len(packages),
            "packages": packages,
        }
    except Exception as e:
        logger.error(f"Failed to list packages in ADOM {adom}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_package(
    name: str,
    adom: str = "root",
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a policy package.

    Args:
        name: Package name
        adom: ADOM name (default: "root")
        include_details: Include policies and settings (default: False)

    Returns:
        dict: Package details with keys:
            - status: "success" or "error"
            - package: Package object
            - message: Error message if failed
    """
    try:
        client = _get_client()
        loadsub = 1 if include_details else 0
        package = await client.get_package(adom, name, loadsub=loadsub)
        return {
            "status": "success",
            "package": package,
        }
    except Exception as e:
        logger.error(f"Failed to get package {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Installation Operations
# =============================================================================


@mcp.tool()
async def install_package(
    adom: str,
    package: str,
    devices: list[dict[str, str]],
    preview: bool = False,
) -> dict[str, Any]:
    """Install a policy package to managed devices.

    Deploys firewall policies and configurations from a policy package
    to the specified devices. This is an asynchronous operation -
    use wait_for_task() to monitor completion.

    Args:
        adom: ADOM name
        package: Policy package name
        devices: Target devices [{"name": "FGT1", "vdom": "root"}, ...]
        preview: If True, only preview changes without applying (default: False)

    Returns:
        dict: Installation result with keys:
            - status: "success" or "error"
            - task_id: Task ID for monitoring (if successful)
            - message: Status or error message

    Example:
        >>> # Install to single device
        >>> result = await install_package(
        ...     adom="root",
        ...     package="default",
        ...     devices=[{"name": "FGT-HQ", "vdom": "root"}]
        ... )
        >>> if result["status"] == "success":
        ...     await wait_for_task(result["task_id"])

        >>> # Preview installation first
        >>> result = await install_package(
        ...     adom="root",
        ...     package="default",
        ...     devices=[{"name": "FGT-HQ", "vdom": "root"}],
        ...     preview=True
        ... )
    """
    try:
        client = _get_client()

        flags = ["preview"] if preview else ["none"]

        result = await client.install_package(
            adom=adom,
            pkg=package,
            scope=devices,
            flags=flags,
        )

        task_id = result.get("task")
        return {
            "status": "success",
            "task_id": task_id,
            "preview": preview,
            "message": f"Installation {'preview ' if preview else ''}started, task ID: {task_id}",
        }
    except Exception as e:
        logger.error(f"Failed to install package {package}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def install_device_settings(
    adom: str,
    devices: list[dict[str, str]],
) -> dict[str, Any]:
    """Install device settings only (without policy package).

    Deploys device-level configurations like interfaces, DNS, NTP
    without reinstalling the full policy package.

    Args:
        adom: ADOM name
        devices: Target devices [{"name": "FGT1", "vdom": "root"}, ...]

    Returns:
        dict: Installation result with keys:
            - status: "success" or "error"
            - task_id: Task ID for monitoring
            - message: Status or error message
    """
    try:
        client = _get_client()

        result = await client.install_device(
            adom=adom,
            scope=devices,
        )

        task_id = result.get("task")
        return {
            "status": "success",
            "task_id": task_id,
            "message": f"Device settings installation started, task ID: {task_id}",
        }
    except Exception as e:
        logger.error(f"Failed to install device settings: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Workspace Mode (ADOM Locking)
# =============================================================================


@mcp.tool()
async def lock_adom(adom: str) -> dict[str, Any]:
    """Lock an ADOM for editing (workspace mode).

    In workspace mode, ADOMs must be locked before making changes.
    This prevents conflicts from multiple administrators editing
    the same ADOM simultaneously.

    Args:
        adom: ADOM name to lock

    Returns:
        dict: Lock result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await lock_adom("root")
        >>> if result["status"] == "success":
        ...     # Make changes...
        ...     await commit_adom("root")
        ...     await unlock_adom("root")
    """
    try:
        client = _get_client()
        await client.lock_adom(adom)
        return {
            "status": "success",
            "message": f"ADOM '{adom}' locked successfully",
        }
    except Exception as e:
        logger.error(f"Failed to lock ADOM {adom}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def unlock_adom(adom: str) -> dict[str, Any]:
    """Unlock an ADOM (workspace mode).

    Release the lock on an ADOM. Changes should be committed
    before unlocking to persist them.

    Args:
        adom: ADOM name to unlock

    Returns:
        dict: Unlock result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()
        await client.unlock_adom(adom)
        return {
            "status": "success",
            "message": f"ADOM '{adom}' unlocked successfully",
        }
    except Exception as e:
        logger.error(f"Failed to unlock ADOM {adom}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def commit_adom(adom: str) -> dict[str, Any]:
    """Commit changes to an ADOM (workspace mode).

    Saves all pending changes made to the ADOM. Must be called
    before unlocking to persist changes.

    Args:
        adom: ADOM name to commit

    Returns:
        dict: Commit result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()
        await client.commit_adom(adom)
        return {
            "status": "success",
            "message": f"ADOM '{adom}' changes committed successfully",
        }
    except Exception as e:
        logger.error(f"Failed to commit ADOM {adom}: {e}")
        return {"status": "error", "message": str(e)}
