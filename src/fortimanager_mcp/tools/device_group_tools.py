"""Device group tools for FortiManager.

Based on the FNDN FortiManager 8.0.0 DVMDB group object specification
(``docs/fndn/8.0.0/json_api_reference/swagger/dvmdb.json`` paths
``/dvmdb/adom/{adom}/group`` and ``/dvmdb/adom/{adom}/group/{group}/object
member``, cross-checked against the worked examples in
``docs/fndn/8.0.0/json_api_reference/html/dvmdb-examples.htm``).

Device groups are dvmdb objects, not dvmcmd commands -- unlike device
add/delete (``/dvm/cmd/add/device`` etc.), group CRUD and membership go
through the generic dvmdb add/set/delete verbs against
``/dvmdb/adom/{adom}/group`` and its ``object member`` sub-resource. Groups
can nest other groups as members (a member entry with no ``vdom``), which is
how "nest a group inside another group" is implemented here.
"""

import logging
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    ADOM_PATTERN,
    ValidationError,
    coerce_device_name_list,
    validate_adom,
    validate_device_name,
    validate_object_name,
)

logger = logging.getLogger(__name__)


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


# Writable os_type values on the dvmdb group object. ``type`` and
# ``cluster_type`` are marked read-only in the same schema and are
# intentionally not exposed as parameters here.
VALID_GROUP_OS_TYPES = {
    "unknown",
    "fos",
    "fsw",
    "foc",
    "fml",
    "faz",
    "fwb",
    "fch",
    "fct",
    "log",
    "fmg",
    "fsa",
    "fdd",
    "fac",
    "fpx",
    "fna",
    "ffw",
    "fsr",
    "fad",
    "fdc",
    "fap",
    "fxt",
    "fts",
    "fai",
    "fwc",
    "fis",
    "fed",
    "fpa",
    "fca",
    "ftc",
    "fss",
    "fra",
    "sim",
    "fdt",
}


def _validate_group_name(name: str) -> str:
    """Validate a device group name (dvmdb group.name, master key)."""
    return validate_object_name(name, "device group")


def _validate_os_type(os_type: str) -> str:
    """Validate os_type against the dvmdb group schema enum."""
    if not os_type:
        raise ValidationError("os_type cannot be empty")
    os_type = os_type.strip().lower()
    if os_type not in VALID_GROUP_OS_TYPES:
        raise ValidationError(
            f"Invalid os_type '{os_type}'. Valid values: {', '.join(sorted(VALID_GROUP_OS_TYPES))}"
        )
    return os_type


def _validate_vdom_name(vdom: str) -> str:
    """Validate a VDOM name (same charset/length rules as an ADOM name)."""
    if not vdom:
        raise ValidationError("VDOM name cannot be empty")
    vdom = vdom.strip()
    if not ADOM_PATTERN.match(vdom):
        raise ValidationError(
            f"Invalid VDOM name '{vdom}'. "
            "Must be 1-64 characters, alphanumeric, underscore, or hyphen only."
        )
    return vdom


# =============================================================================
# Device Group CRUD
# =============================================================================


@mcp.tool()
async def create_device_group(
    adom: str,
    name: str,
    os_type: str = "unknown",
    description: str | None = None,
) -> dict[str, Any]:
    """Create a device group in FortiManager's device manager database.

    Device groups organize managed devices (and other groups) for bulk
    operations like policy installation. This is a dvmdb object -- creation
    does not touch any live device.

    Args:
        adom: ADOM name where the group will be created
        name: Group name (dvmdb group.name, master key)
        os_type: Device platform family the group targets (default:
            "unknown"). One of: unknown, fos, fsw, foc, fml, faz, fwb, fch,
            fct, log, fmg, fsa, fdd, fac, fpx, fna, ffw, fsr, fad, fdc, fap,
            fxt, fts, fai, fwc, fis, fed, fpa, fca, ftc, fss, fra, sim, fdt.
        description: Optional group description

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - group: Created group name/adom
            - message: Status or error message

    Example:
        >>> result = await create_device_group(
        ...     adom="root",
        ...     name="Branch-Firewalls",
        ...     os_type="fos",
        ...     description="All branch FortiGates",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = _validate_group_name(name)
        os_type = _validate_os_type(os_type)
        client = _get_client()

        await client.create_device_group(
            adom=adom,
            name=name,
            os_type=os_type,
            description=description,
        )

        return {
            "status": "success",
            "group": {"adom": adom, "name": name, "os_type": os_type},
            "message": f"Device group {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create device group {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_device_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a device group from FortiManager.

    Removes the group object itself. Member devices are not affected --
    only their group membership is removed.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name where the group is located
        name: Group name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await delete_device_group("root", "Branch-Firewalls")
    """
    try:
        adom = validate_adom(adom)
        name = _validate_group_name(name)
        client = _get_client()

        await client.delete_device_group(adom=adom, name=name)

        return {
            "status": "success",
            "message": f"Device group {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete device group {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Device Membership
# =============================================================================


@mcp.tool()
async def add_device_to_group(
    adom: str,
    group: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Add a single device to a device group.

    Non-destructive: existing group members are preserved.

    Args:
        adom: ADOM name
        group: Target device group name
        device: Device name to add
        vdom: Device VDOM to add (default: "root")

    Returns:
        dict: Add result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await add_device_to_group("root", "Branch-Firewalls", "FGT-Branch1")
    """
    try:
        adom = validate_adom(adom)
        group = _validate_group_name(group)
        device = validate_device_name(device)
        vdom = _validate_vdom_name(vdom)
        client = _get_client()

        await client.add_group_members(
            adom=adom,
            group=group,
            members=[{"name": device, "vdom": vdom}],
        )

        return {
            "status": "success",
            "message": f"Device {device} added to group {group}",
        }
    except Exception as e:
        logger.error(f"Failed to add device {device} to group {group}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def remove_device_from_group(
    adom: str,
    group: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Remove a single device from a device group.

    Args:
        adom: ADOM name
        group: Device group name
        device: Device name to remove
        vdom: Device VDOM to remove (default: "root")

    Returns:
        dict: Remove result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await remove_device_from_group("root", "Branch-Firewalls", "FGT-Branch1")
    """
    try:
        adom = validate_adom(adom)
        group = _validate_group_name(group)
        device = validate_device_name(device)
        vdom = _validate_vdom_name(vdom)
        client = _get_client()

        await client.remove_group_members(
            adom=adom,
            group=group,
            members=[{"name": device, "vdom": vdom}],
        )

        return {
            "status": "success",
            "message": f"Device {device} removed from group {group}",
        }
    except Exception as e:
        logger.error(f"Failed to remove device {device} from group {group}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def add_devices_to_group_bulk(
    adom: str,
    group: str,
    devices: list[str],
    vdom: str = "root",
) -> dict[str, Any]:
    """Add multiple devices to a device group in one call.

    Non-destructive: existing group members are preserved. All devices are
    added on the same VDOM; call ``add_device_to_group`` individually for
    devices that need a different VDOM.

    Args:
        adom: ADOM name
        group: Target device group name
        devices: List of device names to add
        vdom: VDOM to add each device on (default: "root")

    Returns:
        dict: Add result with keys:
            - status: "success" or "error"
            - added_count: Number of devices added
            - message: Status or error message

    Example:
        >>> result = await add_devices_to_group_bulk(
        ...     "root", "Branch-Firewalls", ["FGT-Site1", "FGT-Site2"]
        ... )
    """
    try:
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        adom = validate_adom(adom)
        group = _validate_group_name(group)
        vdom = _validate_vdom_name(vdom)
        devices = [validate_device_name(d) for d in coerce_device_name_list(devices)]
        client = _get_client()

        members = [{"name": d, "vdom": vdom} for d in devices]
        await client.add_group_members(adom=adom, group=group, members=members)

        return {
            "status": "success",
            "added_count": len(devices),
            "message": f"Added {len(devices)} device(s) to group {group}",
        }
    except Exception as e:
        logger.error(f"Failed to bulk add devices to group {group}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def remove_devices_from_group_bulk(
    adom: str,
    group: str,
    devices: list[str],
    vdom: str = "root",
) -> dict[str, Any]:
    """Remove multiple devices from a device group in one call.

    Args:
        adom: ADOM name
        group: Device group name
        devices: List of device names to remove
        vdom: VDOM the devices were added on (default: "root")

    Returns:
        dict: Remove result with keys:
            - status: "success" or "error"
            - removed_count: Number of devices removed
            - message: Status or error message

    Example:
        >>> result = await remove_devices_from_group_bulk(
        ...     "root", "Branch-Firewalls", ["FGT-Site1", "FGT-Site2"]
        ... )
    """
    try:
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        adom = validate_adom(adom)
        group = _validate_group_name(group)
        vdom = _validate_vdom_name(vdom)
        devices = [validate_device_name(d) for d in coerce_device_name_list(devices)]
        client = _get_client()

        members = [{"name": d, "vdom": vdom} for d in devices]
        await client.remove_group_members(adom=adom, group=group, members=members)

        return {
            "status": "success",
            "removed_count": len(devices),
            "message": f"Removed {len(devices)} device(s) from group {group}",
        }
    except Exception as e:
        logger.error(f"Failed to bulk remove devices from group {group}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Group Nesting
# =============================================================================


@mcp.tool()
async def add_group_to_group(
    adom: str,
    parent_group: str,
    child_group: str,
) -> dict[str, Any]:
    """Nest a device group inside another device group.

    A group member has no VDOM (unlike a device member), which is what
    distinguishes a nested-group entry from a device entry in the dvmdb
    group membership list.

    Args:
        adom: ADOM name
        parent_group: Group that will contain child_group
        child_group: Group to nest inside parent_group

    Returns:
        dict: Add result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await add_group_to_group("root", "All-Branches", "Branch-Firewalls")
    """
    try:
        adom = validate_adom(adom)
        parent_group = _validate_group_name(parent_group)
        child_group = _validate_group_name(child_group)
        if parent_group == child_group:
            raise ValidationError("A group cannot be nested inside itself")
        client = _get_client()

        await client.add_group_members(
            adom=adom,
            group=parent_group,
            members=[{"name": child_group}],
        )

        return {
            "status": "success",
            "message": f"Group {child_group} nested inside group {parent_group}",
        }
    except Exception as e:
        logger.error(f"Failed to nest group {child_group} inside {parent_group}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def remove_group_from_group(
    adom: str,
    parent_group: str,
    child_group: str,
) -> dict[str, Any]:
    """Remove a nested group from its parent device group.

    Args:
        adom: ADOM name
        parent_group: Group that currently contains child_group
        child_group: Nested group to remove from parent_group

    Returns:
        dict: Remove result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await remove_group_from_group("root", "All-Branches", "Branch-Firewalls")
    """
    try:
        adom = validate_adom(adom)
        parent_group = _validate_group_name(parent_group)
        child_group = _validate_group_name(child_group)
        client = _get_client()

        await client.remove_group_members(
            adom=adom,
            group=parent_group,
            members=[{"name": child_group}],
        )

        return {
            "status": "success",
            "message": f"Group {child_group} removed from group {parent_group}",
        }
    except Exception as e:
        logger.error(f"Failed to remove group {child_group} from {parent_group}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
