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

Firmware templates themselves (list/create/delete, at the end of this
module) are a separate surface: their ``/pm/fwmprof/adom/{adom}`` table is
not in the bundled API reference, so those tools rest on what FortiManager
8.0.2 accepted and returned live.

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
from fortimanager_mcp.utils.config import get_default_adom, get_settings
from fortimanager_mcp.utils.errors import FortiManagerMCPError, client_safe_error
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
    confirm: bool = False,
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

    Safety: governed by FMG_FIRMWARE_SAFETY (default "strict"), same
    pattern as trigger_fmg_restore -- refused unless confirm=True is also
    passed. A firmware upgrade reboots a real managed device onto new
    code; there is no dry-run and no content to screen, so the gate is a
    plain explicit confirmation. This is unrelated to spawn_guarded below,
    which only bounds concurrency, not whether the call is allowed to
    happen at all. Set FMG_FIRMWARE_SAFETY=disabled to remove the gate.

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
        confirm: Must be True to proceed under FMG_FIRMWARE_SAFETY=strict
            (default). Ignored when FMG_FIRMWARE_SAFETY=disabled.

    Returns:
        dict: Trigger result with keys:
            - status: "success" or "error"
            - task_id: Task ID for monitoring (if successful)
            - message: Status or error message

    Example:
        >>> path = await get_firmware_upgrade_path("FGT-HQ", "7.2.9-b1688")
        >>> result = await upgrade_device_firmware(
        ...     "FGT-HQ", "7.2.9-b1688", confirm=True
        ... )
        >>> if result["status"] == "success":
        ...     await wait_for_task(result["task_id"], timeout=1800)
    """
    adom = adom or get_default_adom()
    try:
        settings = get_settings()
        if settings.FMG_FIRMWARE_SAFETY == "strict" and not confirm:
            logger.warning(f"Firmware upgrade blocked for {device} — confirm=True not passed")
            return {
                "status": "error",
                "message": "Firmware upgrade refused: this reboots the real managed device "
                "onto new firmware. Pass confirm=True to proceed, or set "
                "FMG_FIRMWARE_SAFETY=disabled to remove this gate.",
                "error_code": "confirmation_required",
            }

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
        response: dict[str, Any] = {
            "status": "success",
            "device": device,
            "target_version": target_version,
            "task_id": task_id,
        }
        if task_id is None:
            # An upgrade reboots the device. Reporting "started ..., task ID:
            # None" reads as a clean start while leaving the caller nothing to
            # poll, so say plainly that tracking is unavailable rather than
            # formatting None into the happy-path sentence (upstream #71).
            response["tracking"] = "unavailable"
            response["warning"] = (
                "FortiManager returned no task ID for this upgrade, so it cannot be "
                "tracked with get_task or wait_for_task. Confirm the outcome on the "
                "device itself before assuming it succeeded."
            )
            response["message"] = (
                f"Firmware upgrade to {target_version} was accepted for '{device}', "
                "but FortiManager returned no task ID to track it with."
            )
        else:
            response["message"] = (
                f"Firmware upgrade to {target_version} started for '{device}', task ID: {task_id}"
            )
        return response
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


# =============================================================================
# Firmware Templates
# =============================================================================
#
# A firmware template enforces a firmware version per platform on the devices
# or groups it is assigned to.
#
# API coverage: the table these tools read and write, /pm/fwmprof/adom/{adom},
# is not in the bundled API reference (docs/fndn, 7.2 to 8.0). Only the
# "fwmprof setting" sub-object is, in the internal-only part of the
# reference ("Firmware Template Objects Reference", fwmprof/setting and
# fwmprof/setting/enforced/version, under a /pm/config/adom/... path); the
# enum values below come from there. The URL and the record shapes were
# verified on FortiManager 8.0.2 only, against templates made in the GUI.
# On 8.0.2 the table answers -6 "Invalid url" for an ADOM that does not
# exist (and for any /pm URL it does not know), which is also what a
# FortiManager without this API can be expected to answer; see
# _list_templates.

_IMAGE_SOURCES = {0: "fmg", 1: "fds"}
_SCHEDULE_TYPES = {0: "none", 1: "daily", 4: "weekly", 5: "once", 10: "onboard"}
_PRODUCTS = {1: "fgt", 2: "fap", 3: "fsw", 4: "fex", 5: "fem"}
_UPGRADE_PATHS = {0: "skip", 1: "auto", 2: "specify"}
_WEEKDAYS = ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday")
_TIME_PATTERN = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

#: ``flags`` on an enforced-version entry, as the GUI writes it: 104 on
#: FortiGate entries, 0 on FortiAP/FortiSwitch ones (read from GUI-made
#: templates on 8.0.2). The reference documents the field only as uint32.
_GUI_VERSION_FLAGS = {"fgt": 104}


#: FMG codes the template table answers when it cannot be read at all:
#: -6 "Invalid url" (seen live on 8.0.2 for a missing ADOM and for unknown
#: /pm URLs) and -3 "Object does not exist".
_TEMPLATE_TABLE_REFUSED = frozenset({-3, -6})


class _TemplatesUnavailable(Exception):
    """The firmware template table could not be addressed in this ADOM."""


async def _list_templates(client: FortiManagerClient, adom: str) -> list[dict[str, Any]]:
    """List the ADOM's firmware templates, naming the likely cause when the
    table URL itself is refused (instead of a bare "Invalid URL")."""
    try:
        return await client.list_firmware_templates(adom)
    except FortiManagerMCPError as e:
        if e.code in _TEMPLATE_TABLE_REFUSED:
            raise _TemplatesUnavailable(
                f"FortiManager refused the firmware template table for ADOM '{adom}' "
                f"(code {e.code}): either the ADOM does not exist, or this "
                "FortiManager version does not offer firmware templates over the "
                "JSON API (these tools were verified on FortiManager 8.0.2 only)"
            ) from e
        raise


def _unavailable(e: _TemplatesUnavailable, operation: str, adom: str) -> dict[str, Any]:
    return error_response(
        error="firmware_templates_unavailable",
        message=str(e),
        operation=operation,
        adom=adom,
        error_code="firmware_templates_unavailable",
    )


def _enum(value: Any, names: dict[int, str]) -> Any:
    return names.get(value, value) if isinstance(value, int) else value


def _template_summary(row: dict[str, Any]) -> dict[str, Any]:
    """A firmware template with its enums decoded."""
    setting = row.get("fwmprof setting") or {}
    days = setting.get("schedule-day")
    return {
        "name": row.get("name"),
        "description": setting.get("description"),
        "image_source": _enum(setting.get("image-source"), _IMAGE_SOURCES),
        "schedule": {
            "type": _enum(setting.get("schedule-type"), _SCHEDULE_TYPES),
            "start_time": setting.get("schedule-start-time"),
            "end_time": setting.get("schedule-end-time"),
            "days": (
                [d for i, d in enumerate(_WEEKDAYS) if days & (1 << i)]
                if isinstance(days, int)
                else days
            ),
        },
        "versions": [
            {
                "platform": v.get("platform"),
                "product": _enum(v.get("product"), _PRODUCTS),
                "version": v.get("version"),
                "upgrade_path": _enum(v.get("upgrade-path"), _UPGRADE_PATHS),
            }
            for v in setting.get("enforced version") or []
            if isinstance(v, dict)
        ],
        "assigned_to": [
            m.get("name") if "vdom" not in m else f"{m.get('name')}[{m.get('vdom')}]"
            for m in row.get("scope member") or []
            if isinstance(m, dict)
        ],
    }


async def _resolve_template_version(
    client: FortiManagerClient, platform: str, version: str
) -> tuple[str, str]:
    """Return (product, catalog version string) for a platform's firmware.

    ``version`` may be "7.4.9" or the catalog form "7.4.9-b2829"; either way
    it must exist in the platform's firmware catalog, so a template never
    enforces an image FortiManager cannot get.
    """
    data = await client.list_available_firmware(platform=platform)
    entries = [
        e
        for e in (data.get("version_list", []) if isinstance(data, dict) else [])
        if isinstance(e, dict) and e.get("platform") == platform
    ]
    if not entries:
        raise ValidationError(f"No firmware catalog for platform '{platform}'")
    product = str(entries[0].get("product", "")).lower()
    if product not in _PRODUCTS.values():
        raise ValidationError(f"Platform '{platform}' is a {product or 'unknown'} product")
    catalog = [
        str(v.get("version"))
        for e in entries
        for v in e.get("versions") or []
        if isinstance(v, dict) and v.get("version")
    ]
    matches = [c for c in catalog if c == version or c.split("-")[0] == version]
    if not matches:
        prefix = ".".join(version.split("-")[0].split(".")[:2])
        nearby = sorted(
            (c for c in catalog if c.startswith(prefix + ".")),
            key=lambda c: [int(p) for p in re.findall(r"\d+", c)],
        )
        raise ValidationError(
            f"Version '{version}' is not in the {platform} catalog"
            + (f"; available {prefix}.x: {nearby}" if nearby else "")
        )
    return product, matches[0]


@mcp.tool()
async def list_firmware_templates(adom: str | None = None) -> dict[str, Any]:
    """List firmware templates: enforced versions, schedule and assignment.

    Verified on FortiManager 8.0.2; the template table is not in the
    bundled API reference, so other versions may refuse it (reported as
    ``firmware_templates_unavailable``).

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")

    Returns:
        dict: status, count, templates: [{name, description, image_source,
        schedule {type, start_time, end_time, days}, versions [{platform,
        product, version, upgrade_path}], assigned_to [device or group names]}]
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()
        templates = [_template_summary(t) for t in await _list_templates(client, adom)]
        return {"status": "success", "count": len(templates), "templates": templates}
    except _TemplatesUnavailable as e:
        logger.error(f"Failed to list firmware templates: {e.__cause__}")
        return _unavailable(e, "list_firmware_templates", adom)
    except Exception as e:
        logger.error(f"Failed to list firmware templates: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_firmware_template(
    name: str,
    versions: list[dict[str, str]],
    adom: str | None = None,
    description: str | None = None,
    image_source: str = "fds",
    schedule_type: str = "daily",
    schedule_start_time: str = "00:00",
    schedule_end_time: str = "23:59",
    schedule_days: list[str] | None = None,
) -> dict[str, Any]:
    """Create a firmware template (not assigned to any device).

    Each version is checked against the platform's firmware catalog, so the
    template can only enforce an image FortiManager can actually get.
    Assigning the template is a separate step, done in the GUI: once
    assigned, FortiManager upgrades (or downgrades) the devices to the
    enforced version in the schedule window.

    Verified on FortiManager 8.0.2; the template table is not in the
    bundled API reference, so other versions may refuse it (reported as
    ``firmware_templates_unavailable``).

    Args:
        name: Template name
        versions: Enforced versions, one per platform:
            [{"platform": "FortiGate-VM64-KVM", "version": "7.4.9"}].
            The version may include the build ("7.4.9-b2829")
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        description: Optional description
        image_source: "fds" (FortiGuard, default) or "fmg" (images on
            FortiManager)
        schedule_type: "daily" (default) or "weekly"
        schedule_start_time: Window start, "HH:MM" (default "00:00")
        schedule_end_time: Window end, "HH:MM" (default "23:59")
        schedule_days: Days for a weekly schedule, e.g. ["saturday", "sunday"]

    Returns:
        dict: status, template (as list_firmware_templates shows it), message
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "firmware template")
        if image_source not in ("fds", "fmg"):
            raise ValidationError("image_source must be 'fds' or 'fmg'")
        if schedule_type not in ("daily", "weekly"):
            raise ValidationError("schedule_type must be 'daily' or 'weekly'")
        for label, value in (("start", schedule_start_time), ("end", schedule_end_time)):
            if not _TIME_PATTERN.match(value):
                raise ValidationError(f"schedule_{label}_time must be HH:MM, got {value!r}")
        days = [d.lower() for d in schedule_days or []]
        if schedule_type == "weekly":
            if not days or any(d not in _WEEKDAYS for d in days):
                raise ValidationError(f"A weekly schedule needs schedule_days from {_WEEKDAYS}")
        elif days:
            raise ValidationError("schedule_days only applies to a weekly schedule")
        if not isinstance(versions, list) or not versions:
            raise ValidationError("versions must list at least one {platform, version}")
        for index, entry in enumerate(versions):
            if not isinstance(entry, dict) or set(entry) != {"platform", "version"}:
                raise ValidationError(f"versions[{index}] must be {{'platform', 'version'}}")
            validate_object_name(entry["platform"], "platform")
            _validate_firmware_version(entry["version"])
        platforms = [v["platform"] for v in versions]
        if len(set(platforms)) != len(platforms):
            raise ValidationError("Each platform can appear only once in versions")

        client = _get_client()
        existing = {t.get("name") for t in await _list_templates(client, adom)}
        if name in existing:
            raise ValidationError(f"Firmware template '{name}' already exists in ADOM '{adom}'")

        enforced = []
        for entry in versions:
            product, version = await _resolve_template_version(
                client, entry["platform"], entry["version"].strip()
            )
            enforced.append(
                {
                    "platform": entry["platform"],
                    "product": product,
                    "upgrade-path": "auto",
                    "version": version,
                    "flags": _GUI_VERSION_FLAGS.get(product, 0),
                }
            )
        setting: dict[str, Any] = {
            "image-source": image_source,
            "schedule-type": schedule_type,
            "schedule-start-time": schedule_start_time,
            "schedule-end-time": schedule_end_time,
            "enforced version": enforced,
        }
        if days:
            setting["schedule-day"] = days
        if description:
            setting["description"] = description

        await client.create_firmware_template(
            adom, {"name": name, "type": "fwmprof", "fwmprof setting": setting}
        )
        created = next(
            (t for t in await client.list_firmware_templates(adom) if t.get("name") == name),
            None,
        )
        return {
            "status": "success",
            "template": _template_summary(created) if created else {"name": name},
            "message": f"Firmware template '{name}' created; it is not assigned to any device",
        }
    except _TemplatesUnavailable as e:
        logger.error(f"Failed to create firmware template {name}: {e.__cause__}")
        return _unavailable(e, "create_firmware_template", adom)
    except Exception as e:
        logger.error(f"Failed to create firmware template {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_firmware_template(name: str, adom: str | None = None) -> dict[str, Any]:
    """Delete a firmware template that is not assigned to any device or group.

    An assigned template is refused, with the assignment listed: unassign it
    in the GUI first, so a delete can never change what firmware a device
    is held to without that being a deliberate step.

    Verified on FortiManager 8.0.2; the template table is not in the
    bundled API reference.

    Args:
        name: Template name
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")

    Returns:
        dict: status, message (and assigned_to when refused)
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "firmware template")
        client = _get_client()
        template = next(
            (t for t in await _list_templates(client, adom) if t.get("name") == name),
            None,
        )
        if template is None:
            return error_response(
                error="not_found",
                message=f"Firmware template '{name}' does not exist in ADOM '{adom}'",
                operation="delete_firmware_template",
                adom=adom,
            )
        assigned = _template_summary(template)["assigned_to"]
        if assigned:
            return error_response(
                error="template_assigned",
                message=f"Firmware template '{name}' is assigned; unassign it first",
                operation="delete_firmware_template",
                adom=adom,
                assigned_to=assigned,
            )
        await client.delete_firmware_template(adom, name)
        return {"status": "success", "message": f"Firmware template '{name}' deleted"}
    except _TemplatesUnavailable as e:
        logger.error(f"Failed to delete firmware template {name}: {e.__cause__}")
        return _unavailable(e, "delete_firmware_template", adom)
    except Exception as e:
        logger.error(f"Failed to delete firmware template {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
