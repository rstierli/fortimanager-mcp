"""Device Manager (DVM) tools for FortiManager.

Based on FNDN FortiManager 7.6.5 DVM and DVMDB API specifications.
Provides device management operations including add/delete devices,
model device provisioning, and device group management.
"""

import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom

logger = logging.getLogger(__name__)


def _get_client():
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


# Status code mappings
CONN_STATUS = {0: "unknown", 1: "up", 2: "down"}
CONF_STATUS = {0: "unknown", 1: "in_sync", 2: "out_of_sync"}
DB_STATUS = {0: "unknown", 1: "no_changes", 2: "modified"}
DEV_STATUS = {
    0: "none",
    1: "unknown",
    2: "checkedin",
    3: "in_progress",
    4: "installed",
    5: "aborted",
}


def _decode_status(device: dict[str, Any]) -> dict[str, Any]:
    """Decode numeric status values to human-readable strings."""
    result = dict(device)
    if "conn_status" in result:
        result["conn_status_str"] = CONN_STATUS.get(result["conn_status"], "unknown")
    if "conf_status" in result:
        result["conf_status_str"] = CONF_STATUS.get(result["conf_status"], "unknown")
    if "db_status" in result:
        result["db_status_str"] = DB_STATUS.get(result["db_status"], "unknown")
    if "dev_status" in result:
        result["dev_status_str"] = DEV_STATUS.get(result["dev_status"], "unknown")
    return result


# =============================================================================
# Device Query Operations
# =============================================================================


@mcp.tool()
async def list_device_vdoms(
    device: str,
    adom: str | None = None,
) -> dict[str, Any]:
    """List VDOMs for a specific device.

    Virtual Domains (VDOMs) are independent virtual instances
    within a FortiGate device, each with its own configuration.

    Args:
        device: Device name
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")

    Returns:
        dict: VDOM list with keys:
            - status: "success" or "error"
            - count: Number of VDOMs
            - vdoms: List of VDOM objects with name, status, etc.
            - message: Error message if failed

    Example:
        >>> result = await list_device_vdoms("FGT-HQ", "root")
        >>> for vdom in result['vdoms']:
        ...     print(f"VDOM: {vdom['name']}")
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()
        vdoms = await client.list_device_vdoms(device, adom)

        return {
            "status": "success",
            "count": len(vdoms),
            "vdoms": vdoms,
        }
    except Exception as e:
        logger.error(f"Failed to list VDOMs for device {device}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_device_status(
    adom: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Get device status including connection and config sync status.

    Returns status information for all devices or a specific device:
    - Connection status (up/down)
    - Config sync status (in_sync/out_of_sync)
    - DB status (modified/no_changes)
    - Device status (installed/checkedin/etc.)

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        device: Specific device name (optional, returns all if not specified)

    Returns:
        dict: Device status with keys:
            - status: "success" or "error"
            - count: Number of devices
            - devices: List of device status objects
            - message: Error message if failed

    Example:
        >>> # Get all device status
        >>> result = await get_device_status("root")
        >>> for dev in result['devices']:
        ...     print(f"{dev['name']}: {dev['conn_status_str']}")

        >>> # Get specific device status
        >>> result = await get_device_status("root", "FGT-HQ")
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()
        devices = await client.get_device_status(adom, device)

        # Decode status values
        decoded_devices = [_decode_status(d) for d in devices]

        return {
            "status": "success",
            "count": len(decoded_devices),
            "devices": decoded_devices,
        }
    except Exception as e:
        logger.error(f"Failed to get device status: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def search_devices(
    adom: str | None = None,
    name_filter: str | None = None,
    platform_filter: str | None = None,
    os_version_filter: str | None = None,
    connection_status: str | None = None,
) -> dict[str, Any]:
    """Search for devices with filters.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by device name (partial match)
        platform_filter: Filter by platform type (e.g., "FortiGate-VM")
        os_version_filter: Filter by OS version (e.g., "7.4")
        connection_status: Filter by status ("up" or "down")

    Returns:
        dict: Search results with keys:
            - status: "success" or "error"
            - count: Number of matching devices
            - devices: List of matching device objects
            - message: Error message if failed

    Example:
        >>> # Find all FortiGate VMs
        >>> result = await search_devices(platform_filter="FortiGate-VM")

        >>> # Find offline devices
        >>> result = await search_devices(connection_status="down")

        >>> # Find devices by name pattern
        >>> result = await search_devices(name_filter="Branch")
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()

        # Build filter list
        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])
        if platform_filter:
            filters.append(["platform_str", "contain", platform_filter])
        if os_version_filter:
            filters.append(["os_ver", "contain", os_version_filter])
        if connection_status:
            status_val = 1 if connection_status.lower() == "up" else 2
            filters.append(["conn_status", "==", status_val])

        devices = await client.list_devices(
            adom=adom,
            filter=filters if filters else None,
        )

        # Decode status values
        decoded_devices = [_decode_status(d) for d in devices]

        return {
            "status": "success",
            "count": len(decoded_devices),
            "devices": decoded_devices,
        }
    except Exception as e:
        logger.error(f"Failed to search devices: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Device Management Operations
# =============================================================================


@mcp.tool()
async def add_device(
    adom: str,
    name: str,
    ip: str | None = None,
    serial_number: str | None = None,
    admin_user: str | None = None,
    admin_pass: str | None = None,
    description: str | None = None,
    platform: str = "FortiGate-VM64",
    mgmt_mode: str = "fmg",
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Add a new device to FortiManager.

    Registers a device with FortiManager for central management.
    Can add either a real device (with IP) or a model device (with serial number).

    Args:
        adom: ADOM name where device will be added
        name: Device display name
        ip: Device IP address (for real device connection)
        serial_number: Device serial number (for model device or validation)
        admin_user: Admin username for device connection
        admin_pass: Admin password for device connection
        description: Device description
        platform: Platform type (default: "FortiGate-VM64")
        mgmt_mode: Management mode - "fmg" (FortiManager only), or "fmgfaz" (both)
        flags: Additional flags like ["create_task"]

    Returns:
        dict: Add result with keys:
            - status: "success" or "error"
            - device: Added device information
            - task_id: Task ID if run as background task
            - message: Error message if failed

    Example:
        >>> # Add a FortiGate with IP
        >>> result = await add_device(
        ...     adom="root",
        ...     name="FGT-Branch1",
        ...     ip="192.168.1.1",
        ...     admin_user="admin",
        ...     admin_pass="password123"
        ... )

        >>> # Add a model device (offline provisioning)
        >>> result = await add_device(
        ...     adom="root",
        ...     name="FGT-Lab",
        ...     serial_number="FGVM020000123456"
        ... )
    """
    try:
        client = _get_client()

        # Build device configuration
        device_config: dict[str, Any] = {
            "name": name,
            "mgmt_mode": mgmt_mode,
        }

        # Real device with IP
        if ip:
            device_config["ip"] = ip
            if admin_user:
                device_config["adm_usr"] = admin_user
            if admin_pass:
                device_config["adm_pass"] = admin_pass

        # Model device with serial number
        if serial_number:
            device_config["sn"] = serial_number
            if not ip:
                device_config["device action"] = "add_model"

        # Optional fields
        if description:
            device_config["desc"] = description
        if platform:
            device_config["platform_str"] = platform

        result = await client.add_device(
            adom=adom,
            device=device_config,
            flags=flags,
        )

        # Sanitize: strip credentials before returning
        device_config_safe = {
            k: v for k, v in device_config.items() if k not in ("adm_pass", "adm_passwd")
        }

        return {
            "status": "success",
            "device": result.get("device", device_config_safe),
            "task_id": result.get("taskid"),
            "message": f"Device {name} added successfully",
        }
    except Exception as e:
        logger.error(f"Failed to add device {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def add_model_device(
    adom: str,
    name: str,
    serial_number: str,
    platform: str = "FortiGate-VM64",
    os_version: str = "7.0",
    description: str | None = None,
) -> dict[str, Any]:
    """Add a model device for offline provisioning.

    Model devices allow pre-configuring policies and settings
    before the actual device connects to FortiManager.
    Useful for zero-touch provisioning workflows.

    Args:
        adom: ADOM name where device will be added
        name: Device display name
        serial_number: Device serial number (e.g., "FGVM020000123456")
        platform: Platform type (default: "FortiGate-VM64")
        os_version: FortiOS version (default: "7.0")
        description: Device description

    Returns:
        dict: Add result with keys:
            - status: "success" or "error"
            - device: Added device information
            - message: Status or error message

    Example:
        >>> result = await add_model_device(
        ...     adom="root",
        ...     name="FGT-NewBranch",
        ...     serial_number="FGVM02TM12345678",
        ...     platform="FortiGate-60F",
        ...     os_version="7.4"
        ... )
    """
    try:
        client = _get_client()

        device_config: dict[str, Any] = {
            "name": name,
            "sn": serial_number,
            "platform_str": platform,
            "os_ver": os_version,
            "mgmt_mode": "fmg",
            "device action": "add_model",
        }

        if description:
            device_config["desc"] = description

        result = await client.add_device(
            adom=adom,
            device=device_config,
        )

        return {
            "status": "success",
            "device": result.get("device", device_config),
            "message": f"Model device {name} added successfully",
        }
    except Exception as e:
        logger.error(f"Failed to add model device {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_device(
    adom: str,
    device: str,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Delete a device from FortiManager.

    Removes a device registration. Does not affect the actual device
    or its configuration - only removes it from FortiManager management.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name where device is located
        device: Device name to delete
        flags: Additional flags like ["create_task"]

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - task_id: Task ID if run as background task
            - message: Status or error message

    Example:
        >>> result = await delete_device("root", "FGT-OldBranch")
        >>> if result['status'] == 'success':
        ...     print("Device removed from FortiManager")
    """
    try:
        client = _get_client()

        result = await client.delete_device(
            adom=adom,
            device=device,
            flags=flags,
        )

        return {
            "status": "success",
            "task_id": result.get("taskid"),
            "message": f"Device {device} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete device {device}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def add_devices_bulk(
    adom: str,
    devices: list[dict[str, Any]],
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Add multiple devices to FortiManager in bulk.

    Registers multiple devices at once for efficiency.

    Args:
        adom: ADOM name where devices will be added
        devices: List of device configurations. Each device dict can contain:
            - name: Device display name (required)
            - ip: Device IP address
            - sn: Serial number
            - adm_usr: Admin username
            - adm_pass: Admin password
            - desc: Description
            - platform_str: Platform type
            - os_ver: OS version
        flags: Additional flags like ["create_task"]

    Returns:
        dict: Bulk add result with keys:
            - status: "success" or "error"
            - added_count: Number of devices added
            - task_id: Task ID if run as background task
            - message: Error message if failed

    Example:
        >>> devices = [
        ...     {"name": "FGT-Site1", "ip": "10.0.1.1", "adm_usr": "admin", "adm_pass": "pass1"},
        ...     {"name": "FGT-Site2", "ip": "10.0.2.1", "adm_usr": "admin", "adm_pass": "pass2"},
        ... ]
        >>> result = await add_devices_bulk("root", devices)
    """
    try:
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        client = _get_client()

        result = await client.add_device_list(
            adom=adom,
            devices=devices,
            flags=flags,
        )

        # Sanitize: strip credentials from device dicts before returning
        devices_safe = [
            {k: v for k, v in d.items() if k not in ("adm_pass", "adm_passwd")} for d in devices
        ]

        return {
            "status": "success",
            "added_count": len(devices_safe),
            "devices": devices_safe,
            "task_id": result.get("taskid"),
            "message": f"Added {len(devices_safe)} devices",
        }
    except Exception as e:
        logger.error(f"Failed to add devices in bulk: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_devices_bulk(
    adom: str,
    devices: list[str],
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Delete multiple devices from FortiManager in bulk.

    Removes multiple device registrations at once.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name where devices are located
        devices: List of device names to delete
        flags: Additional flags like ["create_task"]

    Returns:
        dict: Bulk delete result with keys:
            - status: "success" or "error"
            - deleted_count: Number of devices deleted
            - task_id: Task ID if run as background task
            - message: Error message if failed

    Example:
        >>> result = await delete_devices_bulk("root", ["FGT-Old1", "FGT-Old2"])
    """
    try:
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        client = _get_client()

        # Convert device names to the expected format
        device_list = [{"name": name} for name in devices]

        result = await client.delete_device_list(
            adom=adom,
            devices=device_list,
            flags=flags,
        )

        return {
            "status": "success",
            "deleted_count": len(devices),
            "task_id": result.get("taskid"),
            "message": f"Deleted {len(devices)} devices",
        }
    except Exception as e:
        logger.error(f"Failed to delete devices in bulk: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def update_device(
    adom: str,
    device: str,
    description: str | None = None,
    latitude: float | None = None,
    longitude: float | None = None,
) -> dict[str, Any]:
    """Update device properties.

    Modify device metadata like description and location.

    Args:
        adom: ADOM name
        device: Device name
        description: New device description
        latitude: GPS latitude for device location
        longitude: GPS longitude for device location

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await update_device(
        ...     adom="root",
        ...     device="FGT-HQ",
        ...     description="Main headquarters firewall",
        ...     latitude=37.7749,
        ...     longitude=-122.4194
        ... )
    """
    try:
        client = _get_client()

        data: dict[str, Any] = {}
        if description is not None:
            data["desc"] = description
        if latitude is not None:
            data["latitude"] = latitude
        if longitude is not None:
            data["longitude"] = longitude

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_device(adom, device, data)

        return {
            "status": "success",
            "message": f"Device {device} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update device {device}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def reload_device_list(
    adom: str | None = None,
) -> dict[str, Any]:
    """Reload the device list from FortiManager database.

    Forces FortiManager to refresh its device cache. Useful after
    direct database changes or if device list appears stale.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")

    Returns:
        dict: Reload result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()
        await client.reload_device_list(adom)

        return {
            "status": "success",
            "message": f"Device list reloaded for ADOM {adom}",
        }
    except Exception as e:
        logger.error(f"Failed to reload device list: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Device Proxy Operations
# =============================================================================


@mcp.tool()
async def get_device_realtime_status(
    adom: str,
    device: str,
) -> dict[str, Any]:
    """Get real-time status from a managed device.

    Queries the actual device through FortiManager proxy to get
    current system status including CPU, memory, and uptime.

    Args:
        adom: ADOM name
        device: Device name

    Returns:
        dict: Real-time status with keys:
            - status: "success" or "error"
            - data: Device status from FortiGate API
            - message: Error message if failed

    Example:
        >>> result = await get_device_realtime_status("root", "FGT-HQ")
        >>> print(f"Uptime: {result['data'].get('uptime')}")
    """
    try:
        client = _get_client()

        result = await client.proxy_call(
            action="get",
            resource="/api/v2/monitor/system/status",
            target=[f"/adom/{adom}/device/{device}"],
        )

        return {
            "status": "success",
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get realtime status for {device}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_device_interfaces(
    adom: str,
    device: str,
) -> dict[str, Any]:
    """Get interface information from a managed device.

    Queries the actual device through FortiManager proxy to get
    current interface configuration and status.

    Args:
        adom: ADOM name
        device: Device name

    Returns:
        dict: Interface information with keys:
            - status: "success" or "error"
            - data: Interface list from FortiGate API
            - message: Error message if failed

    Example:
        >>> result = await get_device_interfaces("root", "FGT-HQ")
        >>> for iface in result['data']:
        ...     print(f"{iface['name']}: {iface.get('ip')}")
    """
    try:
        client = _get_client()

        result = await client.proxy_call(
            action="get",
            resource="/api/v2/monitor/system/interface",
            target=[f"/adom/{adom}/device/{device}"],
        )

        return {
            "status": "success",
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get interfaces for {device}: {e}")
        return {"status": "error", "message": str(e)}
