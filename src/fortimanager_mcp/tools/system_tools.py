"""System and ADOM management tools for FortiManager.

Based on FNDN FortiManager 7.6.5 SYS, DVMDB, and TASK API specifications.
"""

import logging
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.adom_locks import record_lock, record_unlock
from fortimanager_mcp.utils.config import get_default_adom, get_settings
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.install_gate import (
    PREVIEW_VALIDITY_TTL,
    consume_preview,
    find_preview,
    package_revision,
    recorded_revision,
    task_state,
)
from fortimanager_mcp.utils.responses import error_response
from fortimanager_mcp.utils.task_guard import (
    MAX_TASK_POLL_FAILURES,
    MAX_TASK_WAIT_TIMEOUT,
    POLL_CALL_TIMEOUT,
    TaskSlotsExhausted,
    mark_task_done,
    spawn_guarded,
)
from fortimanager_mcp.utils.validation import (
    validate_adom,
    validate_device_name,
    validate_package_name,
)

logger = logging.getLogger(__name__)


def _get_client() -> FortiManagerClient:
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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        name = validate_adom(name)
        client = _get_client()
        loadsub = 1 if include_details else 0
        adom = await client.get_adom(name, loadsub=loadsub)
        return {
            "status": "success",
            "adom": adom,
        }
    except Exception as e:
        logger.error(f"Failed to get ADOM {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Device Management
# =============================================================================


@mcp.tool()
async def list_devices(
    adom: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List all managed devices in an ADOM.

    FortiManager manages FortiGate and other Fortinet devices.
    This lists all devices registered in the specified ADOM.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
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
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()
        devices = await client.list_devices(adom, fields=fields)
        return {
            "status": "success",
            "count": len(devices),
            "devices": devices,
        }
    except Exception as e:
        logger.error(f"Failed to list devices in ADOM {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_device(
    name: str,
    adom: str | None = None,
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a specific managed device.

    Args:
        name: Device name
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
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
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        name = validate_device_name(name)
        client = _get_client()
        loadsub = 1 if include_details else 0
        device = await client.get_device(name, adom, loadsub=loadsub)
        return {
            "status": "success",
            "device": device,
        }
    except Exception as e:
        logger.error(f"Failed to get device {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def list_device_groups(
    adom: str | None = None,
) -> dict[str, Any]:
    """List all device groups in an ADOM.

    Device groups organize managed devices for bulk operations
    like policy installation or configuration deployment.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")

    Returns:
        dict: Device groups with keys:
            - status: "success" or "error"
            - count: Number of groups
            - groups: List of device group objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()
        groups = await client.list_device_groups(adom)
        return {
            "status": "success",
            "count": len(groups),
            "groups": groups,
        }
    except Exception as e:
        logger.error(f"Failed to list device groups: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        timeout: Maximum wait time in seconds (default: 300, capped at 3600)
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
        # Deadline-bound the whole wait and each poll (bundle C of #11): a
        # huge timeout must not park the request for hours, a poll_interval
        # of 0 must not hot-loop, and one wedged poll must not eat the budget.
        timeout = min(timeout, MAX_TASK_WAIT_TIMEOUT)
        poll_interval = max(1, min(poll_interval, 60))
        poll_failures_left = MAX_TASK_POLL_FAILURES
        start_time = asyncio.get_event_loop().time()

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                return {
                    "status": "error",
                    "completed": False,
                    "message": f"Task {task_id} timed out after {timeout} seconds",
                }

            try:
                task = await asyncio.wait_for(
                    client.get_task(task_id),
                    timeout=min(POLL_CALL_TIMEOUT, max(1.0, timeout - elapsed)),
                )
            except TimeoutError:
                # A wedged poll, not a task failure: re-poll on a shared
                # budget. API errors are NOT retried here — get_task already
                # retries transients internally before surfacing.
                if poll_failures_left <= 0:
                    return error_response(
                        error="task_poll_failed",
                        message=(
                            f"Polling task {task_id} timed out {MAX_TASK_POLL_FAILURES + 1} "
                            "times; giving up. The task itself may still be running on the "
                            "FortiManager — retry wait_for_task or check get_task."
                        ),
                        operation="wait_for_task",
                        task_id=task_id,
                        completed=False,
                    )
                poll_failures_left -= 1
                continue

            state = task.get("state", "").lower() if isinstance(task.get("state"), str) else ""

            # Handle numeric state values
            if isinstance(task.get("state"), int):
                state_map = {0: "pending", 1: "running", 4: "done", 5: "error", 3: "cancelled"}
                state = state_map.get(task["state"], "unknown")

            # Check if completed
            if state in ("done", "error", "cancelled"):
                # Terminal state observed: release this task's spawn slot (a
                # no-op for tasks not spawned through this server).
                mark_task_done(task_id)
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
        msg, code = client_safe_error(e)
        return {"status": "error", "completed": False, "message": msg, "error_code": code}


# =============================================================================
# Policy Package Management
# =============================================================================


@mcp.tool()
async def list_packages(
    adom: str | None = None,
) -> dict[str, Any]:
    """List all policy packages in an ADOM.

    Policy packages contain firewall policies, security profiles,
    and other configurations to be installed on managed devices.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")

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
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()
        packages = await client.list_packages(adom)
        return {
            "status": "success",
            "count": len(packages),
            "packages": packages,
        }
    except Exception as e:
        logger.error(f"Failed to list packages in ADOM {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_package(
    name: str,
    adom: str | None = None,
    include_details: bool = False,
) -> dict[str, Any]:
    """Get detailed information about a policy package.

    Args:
        name: Package name
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        include_details: Include policies and settings (default: False)

    Returns:
        dict: Package details with keys:
            - status: "success" or "error"
            - package: Package object
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        name = validate_package_name(name)
        client = _get_client()
        loadsub = 1 if include_details else 0
        package = await client.get_package(adom, name, loadsub=loadsub)
        return {
            "status": "success",
            "package": package,
        }
    except Exception as e:
        logger.error(f"Failed to get package {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Installation Operations
# =============================================================================


async def _check_install_preview(
    client: FortiManagerClient,
    adom: str,
    package: str,
    devices: list[dict[str, str]],
) -> tuple[str, str] | None:
    """Verify a usable preview exists for this install target.

    Returns ``None`` when a recorded preview's task finished successfully and
    the package is unchanged since the preview, otherwise an
    ``(error_code, problem)`` pair describing what is missing.
    """
    preview_task = find_preview(adom, package, devices)
    if preview_task is None:
        return (
            "preview_required",
            "no preview_install is on record for this package/device set "
            f"(previews expire after {int(PREVIEW_VALIDITY_TTL // 60)} minutes)",
        )
    try:
        task = await client.get_task(preview_task)
    except Exception as e:
        logger.warning(f"Could not verify preview task {preview_task}: {e}")
        return ("preview_required", f"preview task {preview_task} could not be verified")
    state = task_state(task)
    if state in ("pending", "running"):
        return (
            "preview_required",
            f"preview task {preview_task} has not finished yet (state: {state}) — "
            "wait_for_task first",
        )
    if state != "done":
        return ("preview_required", f"preview task {preview_task} ended in state '{state}'")

    # Revision check (issue #25): the package must be unchanged since the
    # preview, or its diff no longer describes what would be installed.
    previewed_rev = recorded_revision(adom, package, devices)
    if previewed_rev is not None:
        current_rev = await package_revision(client, adom, package)
        if current_rev is None:
            return (
                "preview_required",
                f"the revision of package '{package}' could not be verified against the preview",
            )
        if current_rev != previewed_rev:
            # The recorded preview no longer describes this package: expire it
            # so the next attempt reports "no preview on record".
            consume_preview(adom, package, devices)
            return (
                "preview_stale",
                f"package '{package}' changed since the preview (revision "
                f"{previewed_rev} -> {current_rev}) — its diff no longer describes "
                "what would be installed; run preview_install again",
            )
    return None


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

    By default (FMG_INSTALL_SAFETY=strict) a real install requires a
    verified preview first: run preview_install for the same ADOM, package,
    and devices, wait for its task to finish, then install. Each preview
    authorizes one install, and only while the package is unchanged — if the
    package was edited after the preview, the install is refused
    (preview_stale) and a fresh preview is required.

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
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        # Preview-before-install gate (bundle D of #11): a real install needs
        # a verified preview_install for the same ADOM/package/device set,
        # unless FMG_INSTALL_SAFETY says otherwise.
        gate_warning: str | None = None
        gate_mode = get_settings().FMG_INSTALL_SAFETY
        if not preview and gate_mode != "disabled":
            gate_result = await _check_install_preview(client, adom, package, devices)
            if gate_result:
                gate_error, gate_problem = gate_result
                if gate_mode == "strict":
                    return error_response(
                        error=gate_error,
                        message=(
                            f"Refusing to install package '{package}': {gate_problem}. "
                            "Run preview_install, wait_for_task, and review "
                            "get_preview_result first — or set FMG_INSTALL_SAFETY=warn/"
                            "disabled to override."
                        ),
                        operation="install_package",
                        adom=adom,
                        package=package,
                        recommendation="preview_install",
                    )
                gate_warning = f"Installing without a verified preview: {gate_problem}"

        flags = ["preview"] if preview else ["none"]

        result = await spawn_guarded(
            "install_package",
            lambda: client.install_package(
                adom=adom,
                pkg=package,
                scope=devices,
                flags=flags,
            ),
        )

        if not preview:
            # The preview that authorized this install is spent: the next
            # install needs a fresh one (the package may change in between).
            consume_preview(adom, package, devices)

        task_id = result.get("task")
        response = {
            "status": "success",
            "task_id": task_id,
            "preview": preview,
            "message": f"Installation {'preview ' if preview else ''}started, task ID: {task_id}",
        }
        if gate_warning:
            response["warning"] = gate_warning
        return response
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="install_package",
            adom=adom,
            package=package,
        )
    except Exception as e:
        logger.error(f"Failed to install package {package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        client = _get_client()

        result = await spawn_guarded(
            "install_device_settings",
            lambda: client.install_device(
                adom=adom,
                scope=devices,
            ),
        )

        task_id = result.get("task")
        return {
            "status": "success",
            "task_id": task_id,
            "message": f"Device settings installation started, task ID: {task_id}",
        }
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="install_device_settings",
            adom=adom,
        )
    except Exception as e:
        logger.error(f"Failed to install device settings: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        client = _get_client()
        await client.lock_adom(adom)
        # Track the lock so a still-held one is released at server shutdown
        # instead of blocking other admins until the FMG session times out.
        record_lock(adom)
        return {
            "status": "success",
            "message": f"ADOM '{adom}' locked successfully",
        }
    except Exception as e:
        logger.error(f"Failed to lock ADOM {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        client = _get_client()
        await client.unlock_adom(adom)
        record_unlock(adom)
        return {
            "status": "success",
            "message": f"ADOM '{adom}' unlocked successfully",
        }
    except Exception as e:
        logger.error(f"Failed to unlock ADOM {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        client = _get_client()
        await client.commit_adom(adom)
        return {
            "status": "success",
            "message": f"ADOM '{adom}' changes committed successfully",
        }
    except Exception as e:
        logger.error(f"Failed to commit ADOM {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
