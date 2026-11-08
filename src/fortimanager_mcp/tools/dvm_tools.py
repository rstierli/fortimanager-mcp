"""Device Manager (DVM) tools for FortiManager.

Based on FNDN FortiManager 7.6.5 DVM and DVMDB API specifications.
Provides device management operations including add/delete devices,
model device provisioning, and device group management.
"""

import asyncio
import logging
import re
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom, get_default_device
from fortimanager_mcp.utils.errors import ResourceNotFoundError, client_safe_error
from fortimanager_mcp.utils.redaction import strip_secret_fields
from fortimanager_mcp.utils.responses import (
    DEVICE_CREDENTIAL_KEYS,
    strip_device_credentials,
)
from fortimanager_mcp.utils.validation import (
    ValidationError,
    and_filters,
    coerce_device_name_list,
    substring_filter,
    validate_adom,
    validate_device_dict_list,
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


#: A meta-variable name as FMG accepts it (``port1``, ``port1_gw``,
#: ``vm_interface_number``). Kept tight because the name is interpolated into
#: templates as ``$(name)``.
_META_VARIABLE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_\-]{0,63}")
_META_VARIABLE_MAX_VALUE = 255


def _validate_meta_variables(meta_variables: Any) -> dict[str, str]:
    """Validate per-device meta-variable values for a model device.

    FMG stores every value as a string, so numbers are coerced; anything
    else (a list, a dict, None) is refused rather than stringified into a
    value no template expects.
    """
    if not isinstance(meta_variables, dict):
        raise ValidationError("meta_variables must be an object of name -> value")
    validated: dict[str, str] = {}
    for key, value in meta_variables.items():
        if not isinstance(key, str) or not _META_VARIABLE_NAME.fullmatch(key):
            raise ValidationError(
                f"Invalid meta-variable name {key!r}: use letters, digits, '_' or '-' (max 64)"
            )
        if isinstance(value, bool) or not isinstance(value, str | int | float):
            raise ValidationError(f"Meta-variable {key!r} must be a string or number")
        text = str(value)
        if len(text) > _META_VARIABLE_MAX_VALUE:
            raise ValidationError(
                f"Meta-variable {key!r} is longer than {_META_VARIABLE_MAX_VALUE} characters"
            )
        validated[key] = text
    return validated


#: HA modes a model cluster can be declared with (the dvmcmd HA_MODE_OPTIONS
#: values that describe a FortiGate FGCP cluster).
_MODEL_HA_MODES = frozenset({"AP", "AA"})
_HA_PRIORITY_MAX = 255


def _validate_ha_priority(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{label} must be an integer")
    priority: int = value
    if not 0 <= priority <= _HA_PRIORITY_MAX:
        raise ValidationError(f"{label} must be between 0 and {_HA_PRIORITY_MAX}")
    return priority


def _build_ha_slave(
    primary_name: str,
    primary_sn: str,
    primary_priority: Any,
    members: Any,
) -> list[dict[str, Any]]:
    """Build the ``ha_slave`` table for a model HA cluster.

    The table lists every cluster member, the primary included (role
    "master"), which is how FMG stores ``/dvmdb/device/<name>/ha_slave``.
    """
    if not isinstance(members, list) or not members:
        raise ValidationError("ha_members must list at least one secondary member")
    table: list[dict[str, Any]] = [
        {
            "name": primary_name,
            "sn": primary_sn,
            "prio": _validate_ha_priority(primary_priority, "ha_priority"),
            "role": "master",
            "idx": 0,
        }
    ]
    seen_sn = {primary_sn}
    seen_names = {primary_name}
    for idx, member in enumerate(members, start=1):
        if not isinstance(member, dict):
            raise ValidationError("Each ha_members entry must be an object")
        name = validate_device_name(member.get("name", ""))
        sn = member.get("serial_number") or member.get("sn")
        if not isinstance(sn, str) or not sn:
            raise ValidationError(f"HA member {name!r} needs a serial_number")
        if sn in seen_sn or name in seen_names:
            raise ValidationError(f"HA member {name!r} repeats a name or serial in the cluster")
        seen_sn.add(sn)
        seen_names.add(name)
        table.append(
            {
                "name": name,
                "sn": sn,
                "prio": _validate_ha_priority(
                    member.get("priority", 128), f"priority of HA member {name!r}"
                ),
                "role": "slave",
                "idx": idx,
            }
        )
    return table


# ---------------------------------------------------------------------------
# Inline device blueprint (the GUI "Add Model Device" form with the blueprint
# option unchecked sends the blueprint settings as an object instead of a
# saved blueprint name). Attributes per the 8.0 fmg/device/blueprint schema.
# ---------------------------------------------------------------------------

_BLUEPRINT_OPTION_FIELDS = frozenset(
    {
        "autolink-retrieve",
        "enforce-device-config",
        "ha-config",
        "linked-to-model",
        "sdwan-management",
        "split-switch-port",
        "vm-log-disk",
    }
)
_BLUEPRINT_STRING_FIELDS = frozenset(
    {
        "description",
        "firmware-template",
        "folder",
        "ha-hbdev",
        "pkg",
        "platform",
        "prefer-img-ver",
        "template-group",
    }
)
#: Single-reference datasources. The schema types them as arrays; the GUI
#: sends a plain string, and so do we.
_BLUEPRINT_SINGLE_REF_FIELDS = frozenset({"auth-template", "cert-template", "prerun-cliprof"})
_BLUEPRINT_LIST_FIELDS = frozenset(
    {
        "cliprofs",
        "cluster-worker",
        "dev-group",
        "ha-monitor",
        "prerun-cliprof",
        "templates",
    }
)
#: dvm/cmd/add/device flags (8.0 dvmcmd ADD_DEV_FLAGS_OPTIONS subset).
_ADD_DEVICE_FLAGS = frozenset({"none", "create_task", "nonblocking", "log_dev"})
_BLUEPRINT_PROV_TYPES = frozenset({"none", "templates", "template-group"})
#: Sent by the GUI alongside the schema attributes; accepted and passed on.
_BLUEPRINT_GUI_FIELDS = frozenset({"download_from_fgd"})


def _blueprint_option(key: str, value: Any) -> str:
    if value in (True, 1, "1", "enable"):
        return "enable"
    if value in (False, 0, "0", "disable"):
        return "disable"
    raise ValidationError(f"Blueprint {key!r} must be enable/disable (or true/false)")


def _validate_inline_blueprint(blueprint: dict[str, Any]) -> dict[str, Any]:
    """Validate an inline blueprint object against the fmg/device/blueprint schema."""
    validated: dict[str, Any] = {}
    for key, value in blueprint.items():
        if key == "ha-password":
            raise ValidationError(
                "Blueprint 'ha-password' is not accepted here; set the HA password "
                "in FortiManager so it never travels through tool arguments"
            )
        if key in _BLUEPRINT_OPTION_FIELDS:
            validated[key] = _blueprint_option(key, value)
        elif key in _BLUEPRINT_STRING_FIELDS:
            if not isinstance(value, str):
                raise ValidationError(f"Blueprint {key!r} must be a string")
            if value:
                validated[key] = value
        elif key in _BLUEPRINT_SINGLE_REF_FIELDS:
            refs = [value] if isinstance(value, str) else value
            if not isinstance(refs, list) or not all(isinstance(i, str) for i in refs):
                raise ValidationError(f"Blueprint {key!r} must be a name")
            refs = [i for i in refs if i]
            if len(refs) > 1:
                raise ValidationError(f"Blueprint {key!r} takes a single name")
            if refs:
                validated[key] = refs[0]
        elif key in _BLUEPRINT_LIST_FIELDS:
            items = [value] if isinstance(value, str) else value
            if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
                raise ValidationError(f"Blueprint {key!r} must be a string or list of strings")
            validated[key] = [i for i in items if i]
        elif key == "prov-type":
            if value not in _BLUEPRINT_PROV_TYPES:
                raise ValidationError(
                    f"Blueprint 'prov-type' must be one of {sorted(_BLUEPRINT_PROV_TYPES)}"
                )
            validated[key] = value
        elif key == "port-provisioning":
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValidationError("Blueprint 'port-provisioning' must be a positive integer")
            validated[key] = value
        elif key in _BLUEPRINT_GUI_FIELDS:
            validated[key] = value
        else:
            raise ValidationError(f"Unknown device blueprint attribute {key!r}")

    prov_type = validated.get("prov-type")
    if prov_type == "template-group" and not validated.get("template-group"):
        raise ValidationError("prov-type 'template-group' needs a 'template-group'")
    if prov_type == "templates" and not validated.get("templates"):
        raise ValidationError("prov-type 'templates' needs 'templates'")
    return validated


def _as_list(value: Any) -> list[str]:
    return [value] if isinstance(value, str) else list(value or [])


async def _object_state(client: FortiManagerClient, urls: list[str]) -> bool | None:
    """True if any URL resolves, False if every one is not-found (-3),
    None if a lookup failed for another reason (existence unverified)."""
    unverified = False
    for url in urls:
        try:
            await client.get(url)
            return True
        except ResourceNotFoundError:
            continue
        except Exception:
            unverified = True
    return None if unverified else False


async def _check_blueprint_references(
    client: FortiManagerClient, adom: str, blueprint: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Look up every object an inline blueprint names.

    Returns (missing, unverified) as "kind 'name'" labels.
    """
    obj = f"/pm/config/adom/{adom}/obj"
    lookups: list[tuple[str, str, list[str]]] = []

    def add(kind: str, name: str, urls: list[str]) -> None:
        lookups.append((kind, name, urls))

    if blueprint.get("pkg"):
        add("policy package", blueprint["pkg"], [f"/pm/pkg/adom/{adom}/{blueprint['pkg']}"])
    if blueprint.get("template-group"):
        tg = blueprint["template-group"]
        add("template group", tg, [f"/pm/tmplgrp/adom/{adom}/{tg}"])
    for name in blueprint.get("dev-group", []):
        add("device group", name, [f"/dvmdb/adom/{adom}/group/{name}"])
    for name in _as_list(blueprint.get("auth-template")):
        add(
            "fabric authorization template",
            name,
            [f"{obj}/fmg/fabric/authorization/template/{name}"],
        )
    for name in _as_list(blueprint.get("prerun-cliprof")):
        add("pre-run CLI template", name, [f"{obj}/cli/template/{name}"])
    for name in blueprint.get("cliprofs", []):
        add(
            "CLI template",
            name,
            [f"{obj}/cli/template/{name}", f"{obj}/cli/template-group/{name}"],
        )
    for name in blueprint.get("templates", []):
        add(
            "template",
            name,
            [
                f"/pm/devprof/adom/{adom}/{name}",
                f"/pm/wanprof/adom/{adom}/{name}",
                f"/pm/template/adom/{adom}/{name}",
                f"/pm/crprof/adom/{adom}/{name}",
            ],
        )
    if blueprint.get("firmware-template"):
        fw = blueprint["firmware-template"]
        add("firmware template", fw, [f"/pm/fwmprof/adom/{adom}/{fw}"])

    missing: list[str] = []
    unverified: list[str] = []
    for kind, name, urls in lookups:
        state = await _object_state(client, urls)
        if state is False:
            missing.append(f"{kind} {name!r}")
        elif state is None:
            unverified.append(f"{kind} {name!r}")
    return missing, unverified


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


def _os_version_filters(version: str) -> list[list[Any]]:
    """Exact-match dvmdb filters for a "major[.minor[.patch]]" OS version.

    dvmdb stores the version split across three integer fields, ``os_ver``
    (7), ``mr`` (4) and ``patch`` (12), so no single field holds "7.4". The
    previous ``["os_ver", "contain", "7.4"]`` could never match; measured on
    FortiManager 7.6.7, neither ``contain`` nor ``like`` matches an integer
    field at all, while ``os_ver == 7`` with ``mr == 4`` returns the 7.4
    fleet.

    ``str.isdigit`` alone is not enough: it is true for a superscript two,
    which ``int()`` then rejects, and for Arabic-Indic digits, which it reads
    as Western ones, so a part must be ASCII as well.
    """
    parts = version.strip().lower().removeprefix("v").split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isascii() and p.isdigit() for p in parts):
        raise ValidationError(
            f"Invalid os_version_filter '{version}'. Expected major[.minor[.patch]], e.g. '7.4'."
        )
    fields = ("os_ver", "mr", "patch")
    return [[field, "==", int(part)] for field, part in zip(fields, parts, strict=False)]


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
        adom = validate_adom(adom)
        device = validate_device_name(device)
        client = _get_client()
        vdoms = await client.list_device_vdoms(device, adom)

        return {
            "status": "success",
            "count": len(vdoms),
            # Same record class get_device(include_details=True) returns as a
            # subobject, where it is stripped. Left raw here, the same VDOM
            # record would be safe by one route and not the other.
            "vdoms": strip_device_credentials(vdoms),
        }
    except Exception as e:
        logger.error(f"Failed to list VDOMs for device {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        if device is not None:
            device = validate_device_name(device)
        client = _get_client()
        devices = await client.get_device_status(adom, device)

        # Decode status values
        decoded_devices = [_decode_status(d) for d in devices]

        return {
            "status": "success",
            "count": len(decoded_devices),
            "devices": strip_device_credentials(decoded_devices),
        }
    except Exception as e:
        logger.error(f"Failed to get device status: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        os_version_filter: Filter by OS version as major[.minor[.patch]]
            (e.g., "7", "7.4" or "7.4.12"; a leading "v" is accepted)
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
        adom = validate_adom(adom)
        client = _get_client()

        # Build filter list (heterogeneous: values can be str or int)
        filters: list[list[Any]] = []
        if name_filter:
            filters.append(substring_filter("name", name_filter))
        if platform_filter:
            filters.append(substring_filter("platform_str", platform_filter))
        if os_version_filter:
            filters.extend(_os_version_filters(os_version_filter))
        if connection_status:
            # Reject typos/unexpected values instead of silently treating any
            # non-"up" string as "down".
            if connection_status.lower() not in ("up", "down"):
                raise ValidationError(
                    f"Invalid connection_status '{connection_status}'. Must be 'up' or 'down'."
                )
            status_val = 1 if connection_status.lower() == "up" else 2
            filters.append(["conn_status", "==", status_val])

        devices = await client.list_devices(
            adom=adom,
            filter=and_filters(filters),
        )
        # Decode status values
        decoded_devices = [_decode_status(d) for d in devices]

        return {
            "status": "success",
            "count": len(decoded_devices),
            "devices": strip_device_credentials(decoded_devices),
        }
    except Exception as e:
        logger.error(f"Failed to search devices: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        name = validate_device_name(name)
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

        # Sanitize: strip credentials before returning. FMG may echo the
        # submitted device object back (including plaintext credentials), so
        # sanitize that dict too rather than trusting it.
        echoed = result.get("device")
        device_safe = {
            k: v
            for k, v in (echoed if isinstance(echoed, dict) else device_config).items()
            if k not in DEVICE_CREDENTIAL_KEYS
        }

        return {
            "status": "success",
            "device": device_safe,
            "task_id": result.get("taskid"),
            "message": f"Device {name} added successfully",
        }
    except Exception as e:
        logger.error(f"Failed to add device {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


#: /task/task ``state`` values (8.0 task syntax).
_TASK_STATES = {
    0: "pending",
    1: "running",
    2: "cancelling",
    3: "cancelled",
    4: "done",
    5: "error",
    6: "aborting",
    7: "aborted",
    8: "warning",
    9: "to_continue",
    10: "unknown",
}
_TASK_RUNNING = frozenset({"pending", "running", "cancelling", "aborting"})
_ADD_TASK_TIMEOUT = 180.0
_ADD_TASK_POLL = 2.0


async def _wait_add_task(client: FortiManagerClient, task_id: int) -> tuple[str, list[str]]:
    """Poll an add-device task; return its final state and the failed steps.

    Each failed step is the history ``detail`` of an entry in error state,
    timestamp removed (e.g. "Pre-run CLI template [x] error: ...").
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _ADD_TASK_TIMEOUT
    while True:
        task = await client.get_task(task_id)
        raw_state = task.get("state")
        state = (
            _TASK_STATES.get(raw_state, str(raw_state))
            if isinstance(raw_state, int)
            else str(raw_state)
        )
        if state not in _TASK_RUNNING:
            break
        if loop.time() >= deadline:
            return "timeout", []
        await asyncio.sleep(_ADD_TASK_POLL)

    errors: list[str] = []
    for line in task.get("line") or []:
        for entry in line.get("history") or []:
            detail = str(entry.get("detail", "")).strip()
            if entry.get("state") != 5 or not detail or detail.endswith("devadderror"):
                continue
            # "2026-10-12 23:59:44:Pre-run CLI template ..." -> drop the stamp
            stamp = re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}:", detail)
            errors.append(detail[stamp.end() :] if stamp else detail)
    return state, errors


async def _device_exists(adom: str, name: str) -> bool:
    try:
        await _get_client().get_device(name, adom=adom)
        return True
    except Exception:
        return False


@mcp.tool()
async def add_model_device(
    adom: str,
    name: str,
    serial_number: str,
    platform: str = "FortiGate-VM64",
    os_version: str = "7.0",
    description: str | None = None,
    device_blueprint: str | dict[str, Any] | None = None,
    meta_variables: dict[str, str] | None = None,
    groups: list[str] | None = None,
    ha_mode: str | None = None,
    ha_group_name: str | None = None,
    ha_priority: int = 128,
    ha_members: list[dict[str, Any]] | None = None,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Add a model device for offline provisioning.

    Model devices allow pre-configuring policies and settings
    before the actual device connects to FortiManager.
    Useful for zero-touch provisioning workflows.

    With ``device_blueprint`` the new device inherits what the blueprint
    defines (template group, policy package, groups, enforced firmware...),
    and ``meta_variables`` supplies the per-device values its templates
    reference as ``$(name)`` -- the same fields the GUI "Add Model Device"
    dialog sends. Nothing is pushed to a real FortiGate: a model device is
    a placeholder until a FortiGate with this serial registers.

    Args:
        adom: ADOM name where device will be added
        name: Device display name
        serial_number: Device serial number (e.g., "FGVM020000123456")
        platform: Platform type (default: "FortiGate-VM64")
        os_version: FortiOS version, "7.4" or with patch "7.4.12"
            (default: "7.0")
        description: Device description
        device_blueprint: Name of a saved device blueprint, or an inline
            blueprint object (what the GUI sends with the blueprint option
            unchecked), e.g. {"pkg": "sites_BRANCH_PPKG",
            "prov-type": "template-group", "template-group": "sites_BRANCH",
            "dev-group": ["emea_spokes"], "prerun-cliprof": "bootstrap"}.
            Attributes follow fmg/device/blueprint; every object it names
            (package, template group, device groups, templates, CLI and
            authorization templates, firmware template) is looked up first
            and the add is refused if one does not exist. A saved blueprint
            name is checked the same way.
        meta_variables: Per-device meta-variable values, e.g.
            {"hostname": "b1", "branch_id": "1", "port3": "10.1.0.1/24"}
        groups: Device group names to add the device to (root VDOM)
        ha_mode: Declare a model HA cluster: "AP" (active-passive) or "AA".
            ``name``/``serial_number`` are then the primary member and the
            cluster's device name in FMG.
        ha_group_name: HA cluster group name (required with ha_mode)
        ha_priority: HA priority of the primary member (default 128)
        ha_members: Secondary members, each
            {"name": "branch3_jp-1", "serial_number": "FGVM...", "priority": 100}
        flags: dvm/cmd/add/device flags, e.g. ["create_task"] (the GUI sends
            ["create_task", "nonblocking"]); the task ID is returned

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

        >>> # From a blueprint, with the variables its templates use
        >>> result = await add_model_device(
        ...     adom="production",
        ...     name="branch1_jp",
        ...     serial_number="FGVMMLTM26014552",
        ...     platform="FortiGate-VM64-KVM",
        ...     os_version="7.4.12",
        ...     device_blueprint="sites_BRANCH_DBP_STANDALONE",
        ...     meta_variables={"hostname": "branch1_jp", "branch_id": "1"},
        ... )

        >>> # A two-member active-passive model cluster
        >>> result = await add_model_device(
        ...     adom="production",
        ...     name="branch3_jp",
        ...     serial_number="FGVMMLTM26014560",
        ...     platform="FortiGate-VM64-KVM",
        ...     os_version="7.4.12",
        ...     device_blueprint="sites_BRANCH_DBP_CLUSTER",
        ...     ha_mode="AP",
        ...     ha_group_name="branch3_cluster",
        ...     ha_priority=200,
        ...     ha_members=[{"name": "branch3_jp-1",
        ...                  "serial_number": "FGVMMLTM26014529", "priority": 100}],
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_device_name(name)
        inline_blueprint: dict[str, Any] | None = None
        if isinstance(device_blueprint, dict):
            inline_blueprint = _validate_inline_blueprint(device_blueprint)
        elif device_blueprint is not None:
            device_blueprint = validate_object_name(device_blueprint, "device blueprint")
        validated_meta = (
            _validate_meta_variables(meta_variables) if meta_variables is not None else None
        )
        group_names = [validate_object_name(g, "device group") for g in groups or []]
        bad_flags = set(flags or []) - _ADD_DEVICE_FLAGS
        if bad_flags:
            raise ValidationError(
                f"Unsupported flags {sorted(bad_flags)}; use {sorted(_ADD_DEVICE_FLAGS)}"
            )
        ha_slave: list[dict[str, Any]] | None = None
        if ha_mode is not None:
            if ha_mode not in _MODEL_HA_MODES:
                raise ValidationError(f"ha_mode must be one of {sorted(_MODEL_HA_MODES)}")
            if not ha_group_name:
                raise ValidationError("ha_group_name is required with ha_mode")
            ha_group_name = validate_object_name(ha_group_name, "HA group name")
            ha_slave = _build_ha_slave(name, serial_number, ha_priority, ha_members)
        elif ha_members or ha_group_name:
            raise ValidationError("ha_members and ha_group_name need ha_mode")
        client = _get_client()

        # Refuse a blueprint that names something absent rather than leave a
        # half-provisioned model device behind.
        if inline_blueprint is not None:
            missing, unverified = await _check_blueprint_references(client, adom, inline_blueprint)
        elif isinstance(device_blueprint, str):
            state = await _object_state(
                client, [f"/pm/config/adom/{adom}/obj/fmg/device/blueprint/{device_blueprint}"]
            )
            missing = [f"device blueprint {device_blueprint!r}"] if state is False else []
            unverified = [f"device blueprint {device_blueprint!r}"] if state is None else []
        else:
            missing, unverified = [], []
        if missing:
            return {
                "status": "error",
                "message": "Device blueprint references objects that do not exist in ADOM "
                f"{adom}: {', '.join(missing)}",
                "error_code": "blueprint_reference_missing",
                "missing": missing,
            }

        # FMG expects the major version in os_ver ("7.0") and the minor in a
        # separate mr field; passing "7.6" as os_ver fails with "Unsupported
        # device/ADOM version" (verified live against FMG 7.6.7). Split a
        # caller-friendly "7.6" into os_ver="7.0" + mr=6, and a "7.4.12"
        # into the same plus patch=12 (the 8.0 dvmcmd schema's ``patch``).
        major, _, rest = os_version.partition(".")
        minor, _, patch = rest.partition(".")
        device_config: dict[str, Any] = {
            "name": name,
            "sn": serial_number,
            "platform_str": platform,
            "os_ver": f"{major}.0" if major.isdigit() else os_version,
            "mr": int(minor) if minor.isdigit() else 0,
            "mgmt_mode": "fmg",
            "device action": "add_model",
        }
        if patch.isdigit():
            device_config["patch"] = int(patch)

        if description:
            device_config["desc"] = description
        if inline_blueprint is not None:
            device_config["device blueprint"] = inline_blueprint
        elif device_blueprint:
            device_config["device blueprint"] = device_blueprint
        if validated_meta:
            # "meta variables" is the key the FMG GUI sends for per-device
            # blueprint variables; the dvmcmd schema's "meta fields" is the
            # older device meta-field table and is not what templates read.
            device_config["meta variables"] = validated_meta
        if ha_slave is not None:
            # ha_mode / ha_group_name / ha_slave are add-model-only attributes
            # of the 8.0 dvmcmd ADD_DEV_ATTRS (flagged internal in the spec).
            device_config["ha_mode"] = ha_mode
            device_config["ha_group_name"] = ha_group_name
            device_config["ha_slave"] = ha_slave

        # A blueprint runs follow-up steps (pre-run CLI template, fabric
        # authorization, groups) after the device record is written. Run
        # inline, a failing step comes back only as -1 "Internal error"; run
        # as a task, its history says which step failed and why (verified
        # live on 8.0). So a blueprint add runs as a task unless the caller
        # chose flags.
        as_task = flags is None and (inline_blueprint is not None or bool(device_blueprint))
        result = await client.add_device(
            adom=adom,
            device=device_config,
            flags=["create_task", "nonblocking"] if as_task else flags or None,
            groups=[{"name": g, "vdom": "root"} for g in group_names] or None,
        )

        task_id = result.get("taskid") if isinstance(result, dict) else None
        if as_task and task_id:
            task_state, task_errors = await _wait_add_task(client, int(task_id))
            if task_errors or task_state not in ("done", "warning"):
                created = await _device_exists(adom, name)
                return {
                    "status": "error",
                    "error_code": "model_device_task_failed",
                    "task_id": task_id,
                    "task_state": task_state,
                    "task_errors": task_errors,
                    "partially_created": created,
                    "message": f"Adding model device {name} did not complete cleanly"
                    + (
                        "; FortiManager created the device -- fix the cause and "
                        "delete it before retrying, or keep it as is"
                        if created
                        else ""
                    ),
                }

        return {
            "status": "success",
            # Stripped for the same reason the read paths are: the echo
            # carries whatever the record holds, not only what was
            # submitted, and a model-device record can come back with
            # blanked or default-populated psk and private_key fields.
            "device": strip_device_credentials(result.get("device", device_config)),
            "message": f"Model device {name} added successfully",
            **({"task_id": task_id} if task_id else {}),
            **({"unverified_references": unverified} if unverified else {}),
        }
    except Exception as e:
        logger.error(f"Failed to add model device {name}: {e}")
        msg, code = client_safe_error(e)
        error: dict[str, Any] = {"status": "error", "message": msg, "error_code": code}
        # FMG can fail a blueprint step after the device record is written
        # (seen live: -1 "Internal error", device present). Say so, or the
        # retry fails with "Serial number already in use".
        if not isinstance(e, ValidationError) and await _device_exists(adom, name):
            error["partially_created"] = True
            error["message"] = (
                f"{msg}; FortiManager nevertheless created model device {name} -- check "
                "what the blueprint applied, or delete it before retrying"
            )
        return error


#: fmg/variable ``type`` values whose content must not be echoed back.
_SECRET_VARIABLE_TYPES = frozenset({1, "1", "password"})
_REDACTED = "<redacted>"


def _summarize_metadata_variable(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten one fmg/variable record; redact password-type values."""
    secret = raw.get("type") in _SECRET_VARIABLE_TYPES
    mappings = []
    for entry in raw.get("dynamic_mapping") or []:
        if not isinstance(entry, dict):
            continue
        for scope in entry.get("_scope") or []:
            if isinstance(scope, dict) and scope.get("name"):
                mappings.append(
                    {
                        "device": scope["name"],
                        "vdom": scope.get("vdom"),
                        "value": _REDACTED if secret else entry.get("value"),
                    }
                )
    default = raw.get("value")
    return {
        "name": raw.get("name"),
        "type": "password" if secret else raw.get("type"),
        "description": raw.get("description") or None,
        "default": _REDACTED if secret and default else default,
        "mappings": mappings,
    }


def _device_variable_values(
    variables: list[dict[str, Any]], device: str
) -> dict[str, dict[str, Any]]:
    """Effective value of every variable for ``device``: its own mapping when
    it has one, else the ADOM default."""
    values: dict[str, dict[str, Any]] = {}
    for var in variables:
        own = next((m for m in var["mappings"] if m["device"] == device), None)
        if own is not None:
            values[var["name"]] = {"value": own["value"], "source": "device"}
        else:
            values[var["name"]] = {"value": var["default"], "source": "default"}
    return values


async def _load_metadata_variables(adom: str) -> list[dict[str, Any]]:
    raw = await _get_client().get_metadata_variables(adom)
    records = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    return [_summarize_metadata_variable(r) for r in records if isinstance(r, dict)]


@mcp.tool()
async def list_metadata_variables(
    adom: str,
    device: str | None = None,
) -> dict[str, Any]:
    """List an ADOM's metadata variables and their per-device values.

    Metadata variables are what templates reference as ``$(name)``; a model
    device import (``add_model_device`` with ``meta_variables``) stores its
    values as per-device mappings. Password-type values are redacted.

    Args:
        adom: ADOM name
        device: Optional device name; when given, ``device_values`` holds the
            effective value of every variable for that device and where it
            comes from ("device" mapping or ADOM "default")

    Returns:
        dict: status, count, variables (name, type, description, default,
        mappings[{device, vdom, value}]) and, with ``device``, device_values
    """
    try:
        adom = validate_adom(adom)
        if device is not None:
            device = validate_device_name(device)
        variables = await _load_metadata_variables(adom)
        result: dict[str, Any] = {
            "status": "success",
            "count": len(variables),
            "variables": variables,
        }
        if device is not None:
            result["device"] = device
            result["device_values"] = _device_variable_values(variables, device)
        return result
    except Exception as e:
        logger.error(f"Failed to list metadata variables in {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def set_metadata_variable(
    adom: str,
    name: str,
    device: str,
    value: str,
    vdom: str | None = None,
) -> dict[str, Any]:
    """Set a device's value for an existing metadata variable.

    A device can hold one mapping per scope, for example "global" and "root",
    and templates can read either, so a value changed in one scope alone can
    leave the other behind. Without ``vdom`` every mapping the device has is
    changed; a device without any gets a "global" mapping.

    Only FortiManager changes here. Templates use the new value at the next
    install: run preview_install(package=None) first, because a variable such
    as ``branch_id`` can move LAN addresses and BGP identities.

    Args:
        adom: ADOM name
        name: Variable name (it must already exist)
        device: Managed device name
        value: New value
        vdom: Only this scope (optional, e.g. "global" or "root")

    Returns:
        dict: status, variable, device, changes[{vdom, old, new}] (password
        variables redacted), or message on failure
    """
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        text = _validate_meta_variables({name: value})[name]
        if vdom is not None:
            vdom = validate_adom(vdom)
        client = _get_client()

        raw = await client.get_metadata_variables(adom)
        records = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
        variable = next((v for v in records if v.get("name") == name), None)
        if variable is None:
            return {
                "status": "error",
                "message": f"Metadata variable '{name}' does not exist in ADOM '{adom}'",
                "error_code": "not_found",
            }

        current = {
            scope.get("vdom"): entry.get("value")
            for entry in variable.get("dynamic_mapping") or []
            for scope in entry.get("_scope") or []
            if scope.get("name") == device
        }
        scopes = [vdom] if vdom else sorted(current) or ["global"]
        changes = []
        for scope in scopes:
            if scope in current:
                await client.update_metadata_mapping(adom, name, device, scope, text)
            else:
                await client.add_metadata_mapping(adom, name, device, scope, text)
            secret = variable.get("type") in _SECRET_VARIABLE_TYPES
            changes.append(
                {
                    "vdom": scope,
                    "old": _REDACTED if secret else current.get(scope),
                    "new": _REDACTED if secret else text,
                }
            )
        return {
            "status": "success",
            "variable": name,
            "device": device,
            "changes": changes,
            "message": "Saved in FortiManager. Run preview_install before installing.",
        }
    except Exception as e:
        logger.error(f"Failed to set metadata variable {name} for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def check_device_variables(
    adom: str,
    device: str,
    expected: dict[str, str],
) -> dict[str, Any]:
    """Check a device's metadata variable values against what was imported.

    Use after ``add_model_device`` to confirm every ``meta_variables`` entry
    landed as a per-device mapping. A variable is reported as:
      - match: the device has its own mapping with the expected value
      - mismatch: the device mapping holds another value
      - not_mapped: no device mapping, so templates get the ADOM default
      - undefined: no such variable exists in the ADOM

    Args:
        adom: ADOM name
        device: Device name (e.g. "branch1_jp")
        expected: Variable name -> expected value, e.g. the CSV row
            {"branch_id": "1", "hostname": "branch1"}

    Returns:
        dict: status, ok (all match), match / mismatch / not_mapped /
        undefined lists
    """
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        wanted = _validate_meta_variables(expected)
        variables = await _load_metadata_variables(adom)
        values = _device_variable_values(variables, device)

        match: list[str] = []
        mismatch: list[dict[str, Any]] = []
        not_mapped: list[dict[str, Any]] = []
        undefined: list[str] = []
        for name, want in wanted.items():
            if name not in values:
                undefined.append(name)
                continue
            got = values[name]
            if got["source"] != "device":
                not_mapped.append({"name": name, "expected": want, "default": got["value"]})
            elif got["value"] == want:
                match.append(name)
            else:
                mismatch.append({"name": name, "expected": want, "actual": got["value"]})

        return {
            "status": "success",
            "device": device,
            "ok": not (mismatch or not_mapped or undefined),
            "match": match,
            "mismatch": mismatch,
            "not_mapped": not_mapped,
            "undefined": undefined,
        }
    except Exception as e:
        logger.error(f"Failed to check metadata variables of {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        device = validate_device_name(device)
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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
            - requested_count: Number of devices in the request. NOT a
              count of devices actually added: the add runs as a task,
              so per-device results only exist once it completes.
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
        # Shape first: a dict or a str is truthy, so the emptiness check
        # below cannot see either of them (#86).
        devices = validate_device_dict_list(devices)
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        adom = validate_adom(adom)

        # Validate each caller-supplied device name before building the payload
        # (parity with single-device add_device and delete_devices_bulk).
        devices = [
            {**device, "name": validate_device_name(device.get("name") or "")} for device in devices
        ]

        client = _get_client()

        result = await client.add_device_list(
            adom=adom,
            devices=devices,
            flags=flags,
        )

        # Sanitize: strip credentials from device dicts before returning
        devices_safe = [
            {k: v for k, v in d.items() if k not in DEVICE_CREDENTIAL_KEYS} for d in devices
        ]

        # The add is a TASK: its per-device results do not exist yet at
        # this point, so len() is the request size and nothing more.
        # Reporting it as "added" claimed an outcome the appliance had
        # not reached (#78 on the group tools, same class). task_id is
        # the channel that carries the real answer.
        task_id = result.get("taskid")
        return {
            "status": "success",
            "requested_count": len(devices_safe),
            "devices": devices_safe,
            "task_id": task_id,
            "message": (
                f"Submitted {len(devices_safe)} device(s) for add as task {task_id}. "
                "Poll the task for per-device results."
            ),
        }
    except Exception as e:
        logger.error(f"Failed to add devices in bulk: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
            - requested_count: Number of devices in the request. NOT a
              count of devices actually deleted: the delete runs as a
              task, so per-device results only exist once it completes.
            - task_id: Task ID if run as background task
            - message: Error message if failed

    Example:
        >>> result = await delete_devices_bulk("root", ["FGT-Old1", "FGT-Old2"])
    """
    try:
        if not devices:
            return {"status": "error", "message": "No devices provided"}

        adom = validate_adom(adom)
        devices = [validate_device_name(d) for d in coerce_device_name_list(devices)]
        client = _get_client()

        # Convert device names to the expected format
        device_list = [{"name": name} for name in devices]

        result = await client.delete_device_list(
            adom=adom,
            devices=device_list,
            flags=flags,
        )

        # Same as add_devices_bulk above: this is a task submission, not
        # a completed delete, so the only honest number is how many were
        # asked for.
        task_id = result.get("taskid")
        return {
            "status": "success",
            "requested_count": len(devices),
            "task_id": task_id,
            "message": (
                f"Submitted {len(devices)} device(s) for deletion as task {task_id}. "
                "Poll the task for per-device results."
            ),
        }
    except Exception as e:
        logger.error(f"Failed to delete devices in bulk: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        device = validate_device_name(device)
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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        client = _get_client()
        await client.reload_device_list(adom)

        return {
            "status": "success",
            "message": f"Device list reloaded for ADOM {adom}",
        }
    except Exception as e:
        logger.error(f"Failed to reload device list: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        device = validate_device_name(device)
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
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


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
        adom = validate_adom(adom)
        device = validate_device_name(device)
        client = _get_client()

        # Without include_vlan the monitor leaves VLAN interfaces out, so a LAN
        # on a VLAN such as branch3's vl_lan reads as missing.
        result = await client.proxy_call(
            action="get",
            resource="/api/v2/monitor/system/interface?include_vlan=true",
            target=[f"/adom/{adom}/device/{device}"],
        )

        return {
            "status": "success",
            "data": result,
        }
    except Exception as e:
        logger.error(f"Failed to get interfaces for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


def _summarize_interfaces(data: Any) -> list[dict[str, Any]]:
    """Condense raw device-DB interface config objects into a compact list.

    The device DB returns either a list of interface objects or a dict wrapping
    a ``data`` list (shapes vary by FortiOS/FMG version), so both are handled.
    Defensive by design: every field is optional and off-shape values are
    tolerated. The goal is to let a caller map a queried IP/client to its
    VLAN / interface / physical port.
    """
    if isinstance(data, dict):
        # Either a wrapper ({"data": [...]}) or a single bare interface object.
        inner = data.get("data")
        items = inner if inner is not None else data
    else:
        items = data
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return []

    summary: list[dict[str, Any]] = []
    for iface in items:
        if not isinstance(iface, dict):
            continue
        summary.append(
            {
                "name": iface.get("name"),
                "alias": iface.get("alias"),
                "vlanid": iface.get("vlanid"),
                "ip": iface.get("ip"),
                "type": iface.get("type"),
                # physical/aggregate members (e.g. VLAN parent, LAG members)
                "interface": iface.get("interface"),
                "vdom": iface.get("vdom"),
                "status": iface.get("status"),
                "role": iface.get("role"),
                "description": iface.get("description"),
            }
        )
    return summary


#: Fields FMG stores as ``format=password`` on ``system interface``, taken
#: from the bundled cdb-device swagger for 7.0 through 8.0 (the set is the
#: same in each, minus ``eap-password`` on 7.0 and ``wifi-private-key-password``
#: before 7.4). ``password`` (PPPoE), ``eap-password`` (802.1X supplicant),
#: ``pptp-password`` and ``wifi-key``/``wifi-passphrase`` sit at the top
#: level; ``password`` also appears inside ``l2tp-client-settings``, and
#: ``wifi-key``/``wifi-passphrase``/``wifi-private-key-password`` inside each
#: ``wifi-networks`` entry, which is why the strip has to recurse. These are
#: not limited to interfaces actually using PPPoE/PPTP/802.1X: a live 7.6.7
#: read of the 35 interfaces on FGT-MCP-TEST-01 returned ``password``,
#: ``eap-password`` and ``pptp-password`` with 71 ``ENC``-prefixed values
#: between them, on ordinary ports.
_INTERFACE_SECRET_FIELDS = frozenset(
    {
        "password",
        "eap-password",
        "pptp-password",
        "wifi-key",
        "wifi-passphrase",
        "wifi-private-key-password",
    }
)


@mcp.tool()
async def get_device_interface_config(
    device: str | None = None,
    vlanids: list[int] | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """Read a device's interface CONFIG objects from FortiManager's device DB.

    Unlike ``get_device_interfaces`` (which proxies the live FortiGate monitor
    API and cannot filter by VLAN), this reads the interface configuration
    FortiManager keeps in its device database and supports server-side
    filtering by VLAN id and/or exact interface name. Use it to map a queried
    IP / client to the VLAN, interface and physical port it belongs to.

    Args:
        device: Managed device name (e.g. "FGT-HQ"). Defaults to DEFAULT_DEVICE
            when omitted; required if that is not configured.
        vlanids: Optional list of VLAN ids to filter on (matches ``vlanid in``)
        name: Optional exact interface name to filter on (e.g. "port1")

    Returns:
        dict with keys:
            - device
            - interfaces: raw device-DB interface config (list or dict),
              credential fields stripped -- see _INTERFACE_SECRET_FIELDS
            - summary: condensed per-interface list (name/alias/vlanid/ip/...)
            - interface_count: number of summarized interfaces
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    device = device or get_default_device()
    if not device:
        return {
            "error": "device is required (pass it, or configure DEFAULT_DEVICE)",
            "error_code": "device_required",
        }

    try:
        device = validate_device_name(device)
        if name is not None:
            name = validate_object_name(name, "interface")
        interfaces = strip_secret_fields(
            await client.get_device_interface_config(
                device=device,
                vlanids=vlanids,
                name=name,
            ),
            _INTERFACE_SECRET_FIELDS,
        )
        summary = _summarize_interfaces(interfaces)
        return {
            "device": device,
            "interfaces": interfaces,
            "summary": summary,
            "interface_count": len(summary),
        }
    except Exception as e:
        logger.error(f"Device interface-config read failed for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


def _proxy_results(raw: Any) -> Any:
    """Extract the FortiGate payload from a FMG proxy-response envelope.

    ``proxy_call`` returns ``[{"response": {"results": <data>, ...}, ...}]``.
    Returns the inner ``results``, or ``None`` if the envelope is off-shape.
    """
    if isinstance(raw, list) and raw:
        raw = raw[0]
    if isinstance(raw, dict):
        response = raw.get("response")
        if isinstance(response, dict):
            return response.get("results")
    return None


def _summarize_detected_client(rec: dict[str, Any]) -> dict[str, Any]:
    """Condense a detected-device record to the 'where is it connected' fields."""
    return {
        "hostname": rec.get("hostname"),
        "ip": rec.get("ipv4_address"),
        "mac": rec.get("mac"),
        "vendor": rec.get("hardware_vendor"),
        "os": rec.get("os_name"),
        "hardware_type": rec.get("hardware_type"),
        "is_online": rec.get("is_online"),
        "detected_interface": rec.get("detected_interface"),
        "fortiap_id": rec.get("fortiap_id"),
        "fortiap_ssid": rec.get("fortiap_ssid"),
        "fortiap_name": rec.get("fortiap_name"),
        "fortiswitch_id": rec.get("fortiswitch_id"),
        "fortiswitch_serial": rec.get("fortiswitch_serial"),
        "fortiswitch_port": rec.get("fortiswitch_port_name"),
        "vlan_id": rec.get("fortiswitch_vlan_id"),
        "dhcp_lease_status": rec.get("dhcp_lease_status"),
        "total_vuln_count": rec.get("total_vuln_count"),
        "last_seen": rec.get("last_seen"),
    }


def _client_matches(
    rec: dict[str, Any], ip: str | None, mac: str | None, hostname: str | None
) -> bool:
    """True if the record satisfies every provided (non-empty) filter."""
    if ip and rec.get("ipv4_address") != ip.strip():
        return False
    if mac and str(rec.get("mac", "")).lower() != mac.strip().lower():
        return False
    if hostname and hostname.strip().lower() not in str(rec.get("hostname", "")).lower():
        return False
    return True


@mcp.tool()
async def get_device_client_location(
    adom: str | None = None,
    device: str | None = None,
    ip: str | None = None,
    mac: str | None = None,
    hostname: str | None = None,
) -> dict[str, Any]:
    """Locate a client on a device (Asset Identity Center): which FortiAP / FortiSwitch + VLAN it is connected through.

    Proxies the device's detected-device inventory
    (``/api/v2/monitor/user/device/query``) -- the data behind the FortiManager
    "Asset Identity Center" view -- and answers "where is this client connected".
    Each match resolves to the access point / switch + port and VLAN the client
    is on, plus hostname, vendor/OS, online state, DHCP lease and vuln count.

    Filter to one client by ``ip``, ``mac`` or ``hostname`` (each provided filter
    narrows; a hostname match is case-insensitive substring). With no filter, the
    full detected-client inventory is returned (summarized).

    Args:
        adom: ADOM name (defaults to DEFAULT_ADOM / "root" when omitted)
        device: Managed device name (e.g. "FGT-HQ"). Defaults to DEFAULT_DEVICE
            when omitted; required if that is not configured.
        ip: Client IPv4 address to locate (exact match)
        mac: Client MAC address to locate (case-insensitive)
        hostname: Client hostname to locate (case-insensitive substring)

    Returns:
        dict with keys:
            - adom, device
            - query: the filter used (or None for full inventory)
            - match_count
            - clients: summarized detected-client records (ap/switch/port/vlan/...)
            - error / error_code: on failure
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    adom = adom or get_default_adom()
    device = device or get_default_device()
    if not device:
        return {
            "error": "device is required (pass it, or configure DEFAULT_DEVICE)",
            "error_code": "device_required",
        }

    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        raw = await client.proxy_call(
            action="get",
            resource="/api/v2/monitor/user/device/query",
            target=[f"/adom/{adom}/device/{device}"],
        )
        results = _proxy_results(raw)
        records = [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []

        has_filter = bool(ip or mac or hostname)
        matched = [r for r in records if not has_filter or _client_matches(r, ip, mac, hostname)]
        return {
            "adom": adom,
            "device": device,
            "query": {"ip": ip, "mac": mac, "hostname": hostname} if has_filter else None,
            "match_count": len(matched),
            "clients": [_summarize_detected_client(r) for r in matched],
        }
    except Exception as e:
        logger.error(f"Client-location lookup failed for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}
