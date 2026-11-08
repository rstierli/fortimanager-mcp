"""System and ADOM management tools for FortiManager.

Based on FNDN FortiManager 7.6.5 SYS, DVMDB, and TASK API specifications.
"""

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.adom_locks import record_lock, record_unlock
from fortimanager_mcp.utils.config import get_default_adom, get_settings
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.install_gate import (
    PREVIEW_VALIDITY_TTL,
    TERMINAL_TASK_STATES,
    TakenPreview,
    install_lock,
    preview_fingerprint,
    take_preview,
    task_state,
)
from fortimanager_mcp.utils.install_preview import (
    DEFAULT_PREVIEW_TIMEOUT,
    preview_install_response,
)
from fortimanager_mcp.utils.responses import error_response, strip_device_credentials
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
    validate_install_scope,
    validate_package_name,
    validate_task_id,
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
    """Get FortiManager High Availability (HA) health.

    Returns what FortiManager reports at `/sys/ha/status`. On a standalone
    unit that is the HA health alone, `{"HA Health Status": "OK"}` (measured
    on 7.6.8 and 8.0.2): no HA mode, no peer list and no primary/secondary
    role. The HA mode is in get_system_status, under "HA Mode".

    Returns:
        dict: HA status with keys:
            - status: "success" or "error"
            - data: The HA status FortiManager returned
            - message: Error message if failed

    Example:
        >>> result = await get_ha_status()
        >>> print(result["data"].get("HA Health Status"))
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
            "devices": strip_device_credentials(devices),
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
            "device": strip_device_credentials(device),
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
    limit: int = 100,
    since_hours: float | None = None,
    include_lines: bool = False,
) -> dict[str, Any]:
    """List FortiManager tasks, newest first.

    Tasks represent background operations like policy installation,
    device provisioning, and other long-running processes.

    Changed in 1.13.0: returns the newest ``limit`` tasks (default 100;
    ``total`` says how many matched) and drops each task's ``line`` list
    unless ``include_lines`` is set. It used to return every task with its
    lines, which can reach hundreds of KB per call. Raise ``limit``
    or narrow with ``since_hours`` to see further back.

    Args:
        filter_state: Filter by task state (optional):
            - "pending": Not started
            - "running": Currently executing
            - "done": Completed
            - "error": Failed
            - "cancelling": Being cancelled
            - "cancelled": Cancelled
        limit: Maximum number of tasks to return (default: 100)
        since_hours: Only tasks started in the last N hours (optional)
        include_lines: Include each task's per-device lines and history
            (default: False, they can reach hundreds of KB; get_task reads
            them for one task)

    Returns:
        dict: Task list with keys:
            - status: "success" or "error"
            - count: Number of tasks returned
            - total: Number of tasks matching before ``limit``
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
        if since_hours is not None:
            cutoff = time.time() - since_hours * 3600
            tasks = [t for t in tasks if (t.get("start_tm") or 0) >= cutoff]
        tasks = sorted(tasks, key=lambda t: t.get("id") or 0, reverse=True)
        selected = tasks[: max(limit, 0)]
        if not include_lines:
            selected = [{k: v for k, v in t.items() if k != "line"} for t in selected]
        return {
            "status": "success",
            "count": len(selected),
            "total": len(tasks),
            "tasks": selected,
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
        task_id = validate_task_id(task_id)
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
            - status: "success" (task ended done or warning) or "error"
              (error, cancelled, aborted, timeout)
            - task: Final task object
            - task_state: Decoded end state (done, warning, error,
              cancelled, aborted)
            - completed: Whether task completed (vs timeout)
            - message: Status or error message

        A "warning" task finished; its lines (get_task) say what was
        skipped, e.g. an install that found nothing to push.

    Example:
        >>> # Wait for policy installation
        >>> result = await wait_for_task(12345, timeout=600)
        >>> if result['completed']:
        ...     print("Installation finished!")
    """
    import asyncio

    try:
        task_id = validate_task_id(task_id)
        client = _get_client()
        # Deadline-bound the whole wait and each poll (bundle C of #11): a
        # huge timeout must not park the request for hours, a poll_interval
        # of 0 must not hot-loop, and one wedged poll must not eat the budget.
        timeout = min(timeout, MAX_TASK_WAIT_TIMEOUT)
        poll_interval = max(1, min(poll_interval, 60))
        poll_failures_left = MAX_TASK_POLL_FAILURES
        loop = asyncio.get_running_loop()
        start_time = loop.time()

        while True:
            elapsed = loop.time() - start_time
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

            # Every /task/task state decodes (install_gate.TASK_STATES), so a
            # task ending in "warning" -- e.g. an install with nothing to push,
            # verified live -- or "aborted" ends the wait instead of being
            # polled until the timeout as an unknown state.
            state = task_state(task)

            # Check if completed
            if state in TERMINAL_TASK_STATES:
                # Terminal state observed: release this task's spawn slot (a
                # no-op for tasks not spawned through this server).
                mark_task_done(task_id)
                return {
                    # A warning task finished; its lines say what was skipped.
                    "status": "success" if state in ("done", "warning") else "error",
                    "task": task,
                    "completed": True,
                    "task_state": state,
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


def _target_label(package: str | None) -> str:
    return "device settings" if package is None else f"package '{package}'"


def _describe_change(previewed: dict[str, int], current: dict[str, int]) -> str:
    """Which fingerprint components moved, e.g. ``revision 5 -> 6``."""
    changed = [
        f"{'revision' if name == 'package' else name} {previewed.get(name)} -> {current.get(name)}"
        for name in sorted(set(previewed) | set(current))
        if previewed.get(name) != current.get(name)
    ]
    return ", ".join(changed)


async def _check_install_preview(
    client: FortiManagerClient,
    adom: str,
    package: str | None,
    taken: TakenPreview,
) -> tuple[str, str] | None:
    """Verify the preview an install took out of the registry is usable.

    ``package=None`` is a device-settings install. Returns ``None`` when the
    preview's task finished successfully and the fingerprint is unchanged
    since the preview, otherwise an ``(error_code, problem)`` pair
    describing what is missing.
    """
    label = _target_label(package)
    preview_task = taken.task_id
    if preview_task is None:
        return (
            "preview_required",
            f"no preview_install is on record for {label} on this device set "
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
            "wait_for_task on it first",
        )
    if state == "warning":
        # preview_install records the staging task when FortiManager found
        # nothing to install: there is no reviewed change to authorize.
        return (
            "preview_required",
            f"preview task {preview_task} found nothing to install (state 'warning'); "
            "change what is pending for these devices, then run preview_install again",
        )
    if state != "done":
        return ("preview_required", f"preview task {preview_task} ended in state '{state}'")

    # Fingerprint check (issue #25): the target must be unchanged since the
    # preview, or its diff no longer describes what would be installed.
    previewed = taken.fingerprint
    if previewed is not None:
        current = await preview_fingerprint(client, adom, package)
        if current is None:
            return (
                "preview_required",
                f"the revision of {label} could not be verified against the preview",
            )
        if current != previewed:
            return (
                "preview_stale",
                f"{label} changed since the preview ({_describe_change(previewed, current)}) "
                "— its diff no longer describes what would be installed; run "
                "preview_install again",
            )
    return None


async def _gated_install(
    client: FortiManagerClient,
    adom: str,
    package: str | None,
    devices: list[dict[str, str]],
    operation: str,
    start: Callable[[], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:
    """Run the preview-before-install gate, then start the install.

    Shared by install_package and install_device_settings (``package=None``).
    Returns the refusal envelope, or ``{"status": "success", "task_id"}``
    plus ``warning`` when FMG_INSTALL_SAFETY=warn let an unverified install
    through. Installs of one target run one at a time, and the preview is
    taken out of the registry before the first await, so a preview
    authorizes one install even when calls race. It goes back only when the
    gate refuses for a reason a later attempt can clear (not finished yet,
    not verifiable); a stale one, or one whose install was sent, is spent.
    """
    gate_mode = get_settings().FMG_INSTALL_SAFETY
    gate_warning: str | None = None
    async with install_lock(adom, package, devices):
        taken = take_preview(adom, package, devices)
        if gate_mode != "disabled":
            gate_result = await _check_install_preview(client, adom, package, taken)
            if gate_result:
                gate_error, gate_problem = gate_result
                # Only a refusal puts the record back: in warn mode the
                # install goes out below, and a sent install spends it.
                if gate_mode == "strict" and gate_error != "preview_stale":
                    taken.restore()
                if gate_mode == "strict":
                    if package is None:
                        what = "device settings"
                        how = "Run preview_install with package=None for the same ADOM and devices"
                    else:
                        what = f"package '{package}'"
                        how = "Run preview_install for the same ADOM, package and devices"
                    return error_response(
                        error=gate_error,
                        message=(
                            f"Refusing to install {what}: {gate_problem}. {how} and "
                            "review its result first (on FortiManager older than "
                            "7.6.7 / 8.0.2 it returns a task: wait_for_task, then "
                            "get_preview_result) — or set FMG_INSTALL_SAFETY=warn/"
                            "disabled to override."
                        ),
                        operation=operation,
                        adom=adom,
                        package=package,
                        recommendation="preview_install",
                    )
                gate_warning = f"Installing without a verified preview: {gate_problem}"

        try:
            result = await spawn_guarded(operation, start)
        except TaskSlotsExhausted:
            # Refused before anything was sent: the preview still holds.
            taken.restore()
            raise

    response: dict[str, Any] = {"status": "success", "task_id": result.get("task")}
    if gate_warning:
        response["warning"] = gate_warning
    return response


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
    and devices and review its result (on FortiManager builds older than
    7.6.7 / 8.0.2, preview_install returns a task: wait_for_task on it and
    read get_preview_result). Each preview authorizes one install, and only
    while the package is unchanged — if the package was edited after the
    preview, the install is refused (preview_stale) and a fresh preview is
    required. A preview that found nothing to install authorizes nothing.

    Args:
        adom: ADOM name
        package: Policy package name
        devices: Target devices [{"name": "FGT1", "vdom": "root"}, ...]
        preview: If True, run preview_install instead: nothing is installed
            (default: False). Changed in 1.13.0: this used to stage the
            install and return at once, leaving the devices held by an
            install-wizard session; it now runs the same full preview as
            preview_install, returns its result, and like it authorizes one
            install of the same target.

    Returns:
        dict: Installation result with keys:
            - status: "success" or "error"
            - task_id: Task ID for monitoring (if successful)
            - message: Status or error message
            With preview=True: the preview_install response plus
            ``preview: True``.

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
        # A non-empty, well-formed scope; also keeps the gate's key the same
        # as the one preview_install recorded.
        devices = validate_install_scope(devices)
        client = _get_client()

        if preview:
            # A bare flags=["preview"] install stages the package and leaves
            # the devices held by an install-wizard session that nothing
            # releases, so later installs queue behind it. Run the complete
            # preview instead -- the one preview_install runs.
            previewed = await preview_install_response(
                client,
                adom,
                package,
                devices,
                DEFAULT_PREVIEW_TIMEOUT,
                operation="install_package",
            )
            if previewed["status"] == "success":
                previewed["preview"] = True
            return previewed

        # Preview-before-install gate (bundle D of #11): a real install needs
        # a verified preview_install for the same ADOM/package/device set,
        # unless FMG_INSTALL_SAFETY says otherwise. The preview that
        # authorizes it is spent: the next install needs a fresh one.
        response = await _gated_install(
            client,
            adom,
            package,
            devices,
            "install_package",
            lambda: client.install_package(
                adom=adom,
                pkg=package,
                scope=devices,
                flags=["none"],
            ),
        )
        if response["status"] != "success":
            return response
        response["preview"] = False
        response["message"] = f"Installation started, task ID: {response['task_id']}"
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


# FMG stores dev_rev_comments in a 127-byte field.
_REV_COMMENT_MAX_BYTES = 127


def _validate_rev_comment(comment: str) -> str:
    """Return a trimmed revision comment, or raise ValueError."""
    if not isinstance(comment, str):
        raise ValueError("dev_rev_comments must be a string")
    comment = comment.strip()
    if not comment:
        raise ValueError("dev_rev_comments cannot be empty")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in comment):
        raise ValueError("dev_rev_comments cannot contain control characters or newlines")
    size = len(comment.encode("utf-8"))
    if size > _REV_COMMENT_MAX_BYTES:
        raise ValueError(
            f"dev_rev_comments is {size} bytes; FortiManager accepts at most "
            f"{_REV_COMMENT_MAX_BYTES}"
        )
    return comment


@mcp.tool()
async def install_device_settings(
    adom: str,
    devices: list[dict[str, str]],
    dev_rev_comments: str | None = None,
) -> dict[str, Any]:
    """Install device settings only (without policy package).

    Deploys device-level configurations like interfaces, DNS, NTP
    without reinstalling the full policy package.

    By default (FMG_INSTALL_SAFETY=strict) this requires a verified preview
    first, like install_package: run preview_install with package=None for
    the same ADOM and devices and review its result (on FortiManager builds
    older than 7.6.7 / 8.0.2, preview_install returns a task: wait_for_task
    on it and read get_preview_result). Each preview authorizes one install.
    A package preview does not authorize this install, nor the reverse.

    Args:
        adom: ADOM name
        devices: Target devices [{"name": "FGT1", "vdom": "root"}, ...]
        dev_rev_comments: Optional comment for the device revision the
            install creates (shown in Revision History, max 127 bytes)

    Returns:
        dict: Installation result with keys:
            - status: "success" or "error"
            - task_id: Task ID for monitoring
            - message: Status or error message
            - warning: Set when FMG_INSTALL_SAFETY=warn let an install
              without a verified preview through
            Refused by the gate: status "error", error "preview_required",
            recommendation "preview_install".
    """
    try:
        adom = validate_adom(adom)
        devices = validate_install_scope(devices)
        comment = _validate_rev_comment(dev_rev_comments) if dev_rev_comments is not None else None
        client = _get_client()

        response = await _gated_install(
            client,
            adom,
            None,
            devices,
            "install_device_settings",
            lambda: client.install_device(
                adom=adom,
                scope=devices,
                dev_rev_comments=comment,
            ),
        )
        if response["status"] != "success":
            return response
        response["message"] = (
            f"Device settings installation started, task ID: {response['task_id']}"
        )
        return response
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
