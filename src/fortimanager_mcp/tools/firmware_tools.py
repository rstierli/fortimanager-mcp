"""Firmware upgrade tools for FortiManager-managed devices.

Based on the FNDN FortiManager 8.0.0 JSON API swagger (``swagger/um.json``)
and the FortiManager API How-To Guide's "Firmware upgrade" section
(``007_device_management.rst``, under ``docs/guides/FortiManager API -
How-To Guide/``).

Only ``swagger/um.json`` (identical across every bundled FNDN version --
7.2.11 through 8.0.0) documents this subsystem, and it covers exactly two
paths: ``/um/image/upgrade`` and ``/um/image/upgrade/ext``. This module
builds on the plain ``/um/image/upgrade`` path only -- its swagger
definition (``um.image.upgrade``: adom, device, flags, image, schedule_time,
create_task) matches the How-To Guide's "how to get the upgrade path"
example field-for-field. ``/um/image/upgrade/ext`` (the newer "Firmware
Template" mechanism) is deliberately NOT wrapped here: its swagger schema
declares a single top-level "image" string for the whole device batch, but
the guide's own captured example for the same endpoint uses a "devices"
list with a *per-device* "image" field -- a real conflict between the two
sources, not a simple omission, and guessing which one a live 8.0.0
FortiManager actually expects is exactly the kind of unverified-field-name
risk this codebase has been burned by before. Firmware-Template upgrades
are left as an explicit follow-up once that can be confirmed against a live
device.

The three catalog/report endpoints (``/um/image/version/list``,
``/um/image/list``, ``um/image/upgrade/report``) have no bundled swagger
schema at all in any FNDN version under ``docs/fndn/`` -- their shapes come
only from the How-To Guide's captured request/response traffic, cited
per-function below.

Firmware upgrade is not a device-DB config write, so it does not go through
the preview_install/install_package(-settings) CDB push gate that
``device_config_tools.py`` uses for interfaces/DHCP/VAPs. It is FortiManager's
own image-management subsystem and is already asynchronous/task-based at the
API level (``create_task``), so the trigger tool instead mirrors
``system_tools.install_package``'s task pattern: ``spawn_guarded`` to bound
concurrent in-flight FMG tasks, returning a ``task_id`` for the caller to
poll with ``get_task``/``wait_for_task``.
"""

import logging
import re
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.responses import error_response
from fortimanager_mcp.utils.task_guard import TaskSlotsExhausted, spawn_guarded
from fortimanager_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_device_name,
    validate_object_name,
)

logger = logging.getLogger(__name__)

# swagger/um.json: um.image.upgrade / um.image.upgrade.ext "flags" enum,
# minus "f_preview" -- that value is reserved for get_firmware_upgrade_path,
# which sets it internally so the call stays a non-destructive preview.
VALID_UPGRADE_FLAGS = {
    "f_boot_alt_partition",
    "f_skip_retrieve",
    "f_skip_multi_steps",
    "f_skip_fortiguard_img",
}

# FortiOS firmware version strings as seen across every example in the
# How-To Guide's firmware section: "6.4.1", "6.4.1-1637", "7.2.9-b1688",
# "7.6.4-b3596-GA". Digits/dots for the version, optional hyphenated
# alphanumeric build/label suffixes.
FIRMWARE_VERSION_PATTERN = re.compile(r"^\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9]+)*$")


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


def _validate_firmware_version(version: str) -> str:
    """Validate a FortiOS firmware release/version string.

    Args:
        version: Version string, e.g. "6.4.1", "7.2.9-b1688", "7.6.4-b3596-GA"

    Returns:
        Validated version string (stripped)

    Raises:
        ValidationError: If the version string is malformed
    """
    if not version:
        raise ValidationError("Firmware version cannot be empty")
    version = version.strip()
    if not FIRMWARE_VERSION_PATTERN.match(version):
        raise ValidationError(
            f"Invalid firmware version '{version}'. Expected a dotted version, "
            "optionally with hyphenated build/label suffixes "
            "(e.g. '6.4.1', '7.2.9-b1688', '7.6.4-b3596-GA')."
        )
    return version


def _validate_flags(flags: str | None) -> str | None:
    """Validate an upgrade flag name against the swagger enum.

    Args:
        flags: Single flag name, or None

    Returns:
        Validated flag name, or None

    Raises:
        ValidationError: If flags is not one of VALID_UPGRADE_FLAGS
    """
    if flags is None:
        return None
    flags = flags.strip()
    if flags not in VALID_UPGRADE_FLAGS:
        raise ValidationError(
            f"Invalid flags '{flags}'. Must be one of {sorted(VALID_UPGRADE_FLAGS)}."
        )
    return flags


def _device_scope(device: str, vdom: str | None) -> list[dict[str, str]]:
    """Build the single-device common.scope.object entry FMG expects."""
    entry: dict[str, str] = {"name": device}
    if vdom:
        entry["vdom"] = vdom
    return [entry]


# =============================================================================
# Upgrade Path
# =============================================================================


@mcp.tool()
async def get_firmware_upgrade_path(
    device: str,
    target_version: str,
    adom: str | None = None,
    vdom: str | None = None,
) -> dict[str, Any]:
    """Preview the multi-step firmware upgrade path to a target version.

    Non-destructive: internally forces flags="f_preview" so FortiManager
    returns the intermediate versions it would step the device through
    without starting an upgrade. Some FortiOS upgrades cannot jump directly
    to the target release and must pass through intermediate builds first;
    this shows that path before you call upgrade_device_firmware.

    Args:
        device: Managed device name
        target_version: Target firmware version, e.g. "7.2.9-b1688"
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        vdom: VDOM to scope the request to (optional)

    Returns:
        dict: Upgrade path with keys:
            - status: "success" or "error"
            - upgrade_path: List of version strings FMG would step through
            - message: Error message if failed

    Example:
        >>> result = await get_firmware_upgrade_path("FGT-HQ", "7.2.9-b1688")
        >>> print(result["upgrade_path"])
        ['6.0.8-303', '6.2.4-1112', '7.2.9-1688']
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        target_version = _validate_firmware_version(target_version)
        if vdom is not None:
            vdom = validate_object_name(vdom, "VDOM")
        client = _get_client()

        data = await client.get_firmware_upgrade_path(
            adom=adom,
            device=_device_scope(device, vdom),
            release=target_version,
        )

        paths = data.get("upgrade_path", []) if isinstance(data, dict) else []
        device_path = paths[0] if paths else {}
        return {
            "status": "success",
            "device": device,
            "target_version": target_version,
            "upgrade_path": device_path.get("path", []),
            "raw": data,
        }
    except Exception as e:
        logger.error(f"Failed to get firmware upgrade path for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Firmware Catalog
# =============================================================================


@mcp.tool()
async def list_available_firmware(
    platform: str | None = None,
    product: str | None = None,
) -> dict[str, Any]:
    """List firmware versions available for a platform.

    Combines versions on FortiGuard (FDS) servers with any versions imported
    by a FortiManager administrator -- this is the device-reported catalog
    of what CAN be installed, not just what's already downloaded (see
    list_firmware_images for that).

    Args:
        platform: Platform string, e.g. "FortiGate-VM64-KVM" (omit to get
            firmware for all platforms)
        product: Product code, e.g. "FGT", "FMG" (optional)

    Returns:
        dict: Firmware catalog with keys:
            - status: "success" or "error"
            - version_list: List of {platform, product, versions: [...]}
            - message: Error message if failed

    Example:
        >>> result = await list_available_firmware(platform="FortiGate-VM64-KVM")
        >>> for entry in result["version_list"]:
        ...     print(entry["platform"], len(entry["versions"]))
    """
    try:
        client = _get_client()
        data = await client.list_available_firmware(platform=platform, product=product)
        version_list = data.get("version_list", []) if isinstance(data, dict) else []
        return {
            "status": "success",
            "count": len(version_list),
            "version_list": version_list,
        }
    except Exception as e:
        logger.error(f"Failed to list available firmware: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def list_firmware_images(
    system: str | None = None,
) -> dict[str, Any]:
    """List firmware image files stored on the FortiManager's local disk.

    These are the files already imported by an administrator and/or
    downloaded from FortiGuard -- a subset of what list_available_firmware
    reports, scoped to what FortiManager could push without first fetching
    it from FortiGuard.

    Args:
        system: Product code to filter by, e.g. "FMG", "FGT" (optional;
            FortiManager returns every stored image when omitted or when
            there's no match for the given code)

    Returns:
        dict: Local image list with keys:
            - status: "success" or "error"
            - image_list: List of {platform, product, version, build, date,
              image_path, image_size}
            - message: Error message if failed
    """
    try:
        client = _get_client()
        data = await client.list_firmware_images(system=system)
        image_list = data.get("image_list", []) if isinstance(data, dict) else []
        return {
            "status": "success",
            "count": len(image_list),
            "image_list": image_list,
        }
    except Exception as e:
        logger.error(f"Failed to list firmware images: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Upgrade Trigger (device-affecting, async task)
# =============================================================================


@mcp.tool()
async def upgrade_device_firmware(
    device: str,
    target_version: str,
    adom: str | None = None,
    vdom: str | None = None,
    flags: str | None = None,
    schedule_time: str | None = None,
) -> dict[str, Any]:
    """Trigger a firmware upgrade on a managed device.

    Device-affecting: this reboots the device onto the new firmware.
    Asynchronous -- FortiManager runs the upgrade as a background task
    (create_task="enable" is always sent) and this returns immediately with
    a task_id. Poll it with get_task/wait_for_task rather than assuming
    success from this call's return.

    Strongly recommended to call get_firmware_upgrade_path first: FMG may
    need to step the device through intermediate versions to reach the
    target, and this tool upgrades straight to target_version without
    walking that path itself.

    Args:
        device: Managed device name
        target_version: Target firmware version, e.g. "7.2.9-b1688"
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        vdom: VDOM to scope the request to (optional)
        flags: One upgrade flag (optional): "f_boot_alt_partition"
            (boot from alternate partition after upgrade), "f_skip_retrieve"
            (don't retrieve device config after upgrade), "f_skip_multi_steps"
            (skip the multi-step upgrade process), "f_skip_fortiguard_img"
            (let the device download firmware from FortiGuard itself)
        schedule_time: Schedule the upgrade for a future time instead of
            running it immediately (optional; FMG-native time format)

    Returns:
        dict: Trigger result with keys:
            - status: "success" or "error"
            - task_id: Task ID for monitoring (if successful)
            - message: Status or error message

    Example:
        >>> path = await get_firmware_upgrade_path("FGT-HQ", "7.2.9-b1688")
        >>> result = await upgrade_device_firmware("FGT-HQ", "7.2.9-b1688")
        >>> if result["status"] == "success":
        ...     await wait_for_task(result["task_id"], timeout=1800)
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        target_version = _validate_firmware_version(target_version)
        flags = _validate_flags(flags)
        if vdom is not None:
            vdom = validate_object_name(vdom, "VDOM")
        client = _get_client()

        result = await spawn_guarded(
            "upgrade_device_firmware",
            lambda: client.upgrade_device_firmware(
                adom=adom,
                device=_device_scope(device, vdom),
                release=target_version,
                flags=flags,
                schedule_time=schedule_time,
            ),
        )

        task_id = result.get("taskid", result.get("task")) if isinstance(result, dict) else None
        return {
            "status": "success",
            "device": device,
            "target_version": target_version,
            "task_id": task_id,
            "message": f"Firmware upgrade to {target_version} started for '{device}', "
            f"task ID: {task_id}",
        }
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="upgrade_device_firmware",
            adom=adom,
            device=device,
        )
    except Exception as e:
        logger.error(f"Failed to trigger firmware upgrade for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Upgrade Report / History
# =============================================================================


@mcp.tool()
async def get_firmware_upgrade_report(
    device: str,
    profile_name: str,
    adom: str | None = None,
) -> dict[str, Any]:
    """Get the firmware upgrade report for a device under a named profile.

    Reports per-step upgrade results (health checks, package status,
    timestamps) for an upgrade run tracked under profile_name. The How-To
    Guide separately lists a "get upgrade history" question but marks it
    TBD with no confirmed distinct endpoint -- it speculates the same URL
    this wraps, so no separate history tool is provided; this is the one
    confirmed endpoint for both purposes.

    profile_name must be a firmware upgrade profile FortiManager already
    knows about (e.g. one created through the GUI's Firmware Upgrade
    wizard, or the auto-created Firmware Template "key" a
    /um/image/upgrade/ext-style upgrade returns -- not something this
    module generates on its own).

    Args:
        device: Managed device name
        profile_name: Firmware upgrade profile name to report on
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")

    Returns:
        dict: Upgrade report with keys:
            - status: "success" or "error"
            - report: Raw report data (nested per-device task/step details)
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        profile_name = validate_object_name(profile_name, "firmware upgrade profile")
        client = _get_client()

        data = await client.get_firmware_upgrade_report(
            adom=adom,
            devices=[{"name": device}],
            profile_name=profile_name,
        )

        report = data.get("report", []) if isinstance(data, dict) else []
        return {
            "status": "success",
            "device": device,
            "profile_name": profile_name,
            "report": report,
        }
    except Exception as e:
        logger.error(f"Failed to get firmware upgrade report for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
