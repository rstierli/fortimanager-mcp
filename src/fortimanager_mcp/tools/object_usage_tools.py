"""Object usage-graph tools for FortiManager.

Answers two questions ``object_tools.py``'s attribute-based ``search_objects``
cannot: *where is this object referenced* (policies, groups, other objects)
and *which objects in this ADOM are configured identically under different
names*.

Both operations ride FortiManager's cache-daemon ``exec`` commands rather
than the CMDB ``get``/``add``/``set`` verbs the rest of ``object_tools.py``
uses:

- Where-used is a three-step async job: ``/cache/search/where/used/start``
  returns a ``token``; ``/cache/search/where/used/get/summary`` is polled
  until ``percent`` reaches 100; ``/cache/search/where/used/get/detail``
  then returns the match list.
- Duplicate detection is a single ``get`` on the object's own CMDB URL with
  ``"option": ["find duplicates"]`` -- FortiManager compares the requested
  ``fields`` across all objects of that type and adds a ``"duplicate
  entries"`` list to any object that shares its content with another.

These commands are documented only in the FortiManager API How-To Guide
(``docs/guides/FortiManager API - How-To Guide/howto_jsonrpc_api-main/
002_objects_management/002_objects_management.rst``, "Where Used" and "Find
duplicates objects" sections) -- they do not appear in the FNDN swagger/JSON
schema set for 8.0.0 (``docs/fndn/8.0.0/json_api_reference/``), and the
cache-daemon's own internal object catalog
(``json_api_reference/html-internal/cache-objects.htm``) documents only the
unrelated ``diff/*`` commands, not ``search/where/used/*``. The How-To guide
is therefore the sole verified source for both request shapes; there was
nothing to cross-check them against in the schema set.

The guide's only worked "where used" example targets a *global*-ADOM object
(``"obj": "global/obj/firewall/address"``). The per-ADOM form used here
(``"obj": "adom/{adom}/obj/{path}"``) is not separately demonstrated with a
live example, but follows directly from the URL template the same guide
documents for every other object operation (``/pm/config/adom/{adom}/obj/
{path_to_object}`` vs. ``/pm/config/global/obj/{path_to_object}`` -- see the
guide's introduction) with the ``/pm/config/`` prefix dropped, exactly as it
is dropped in the documented global example. ``adom="global"`` is passed
through as the documented global form.
"""

import asyncio
import logging
import time
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    ValidationError,
    validate_adom,
    validate_object_name,
)

logger = logging.getLogger(__name__)

# Maps the object_type argument to its CMDB path fragment under
# /pm/config/adom/{adom}/obj/{path} (mirrors the types object_tools.py
# already supports -- see its list_addresses/list_address_groups/
# list_services/list_service_groups client calls).
_OBJECT_TYPE_PATHS: dict[str, str] = {
    "address": "firewall/address",
    "address_group": "firewall/addrgrp",
    "service": "firewall/service/custom",
    "service_group": "firewall/service/group",
}

# Bounds for the where-used poll loop (mirrors system_tools.wait_for_task's
# clamping rationale: a huge timeout must not park the request, a
# poll_interval of 0 must not hot-loop).
_MAX_WHERE_USED_TIMEOUT = 300
_MIN_POLL_INTERVAL = 1
_MAX_POLL_INTERVAL = 30


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


def _object_type_path(object_type: str) -> str:
    """Resolve object_type to its CMDB path fragment, or raise ValidationError."""
    path = _OBJECT_TYPE_PATHS.get(object_type)
    if path is None:
        raise ValidationError(
            f"Unsupported object_type '{object_type}'. "
            f"Must be one of: {sorted(_OBJECT_TYPE_PATHS)}."
        )
    return path


def _obj_path(adom: str, object_type: str) -> str:
    """Build the object-database path for an ADOM, Global included.

    The Global ADOM is not addressed as an ADOM named "global": it has its
    own branch of the tree. Live-verified against a lab FortiManager --
    ``/pm/config/global/obj/firewall/address`` returns objects, while
    ``/pm/config/adom/global/obj/firewall/address`` is refused with
    "Invalid url". find_duplicate_objects built the second form and so
    could never work against Global (upstream #71); it and
    _where_used_obj_ref, which had the special case, now share this.
    """
    path = _object_type_path(object_type)
    if adom.lower() == "global":
        return f"global/obj/{path}"
    return f"adom/{adom}/obj/{path}"


def _where_used_obj_ref(adom: str, object_type: str) -> str:
    """Build the "obj" value for /cache/search/where/used/start.

    See the module docstring for why the per-ADOM form is derived rather
    than lifted verbatim from a worked example.
    """
    return _obj_path(adom, object_type)


@mcp.tool()
async def find_object_usage(
    adom: str,
    object_name: str,
    object_type: str = "address",
    timeout: int = 60,
    poll_interval: int = 2,
) -> dict[str, Any]:
    """Find everywhere an ADOM object is referenced (where-used).

    Runs FortiManager's cache-daemon where-used search: policies, groups,
    and other objects that reference the given object. This is a
    usage-graph lookup, distinct from object_tools.search_objects (which
    matches objects BY NAME, not by reference).

    Args:
        adom: ADOM name (use "global" to search a Global ADOM object)
        object_name: Name of the object to trace usage for
        object_type: One of "address", "address_group", "service",
            "service_group" (default: "address")
        timeout: Maximum seconds to wait for the search to complete
            (default: 60, capped at 300)
        poll_interval: Seconds between progress checks (default: 2,
            clamped to 1-30)

    Returns:
        dict: Usage result with keys:
            - status: "success" or "error"
            - object_name: The object searched for
            - object_type: The object type searched
            - total_matches: Number of referencing locations
            - used_in: List of where-used entries, each with the
              referencing object's root ADOM/package and the matching
              attr/mapping_name/mkey detail FortiManager returned
            - message: Error message if failed

    Example:
        >>> result = await find_object_usage("root", "WebServer")
        >>> for entry in result["used_in"]:
        ...     print(entry["root"], entry["data"])
    """
    try:
        adom = validate_adom(adom)
        object_name = validate_object_name(object_name, object_type)
        obj_ref = _where_used_obj_ref(adom, object_type)
        timeout = max(1, min(timeout, _MAX_WHERE_USED_TIMEOUT))
        poll_interval = max(_MIN_POLL_INTERVAL, min(poll_interval, _MAX_POLL_INTERVAL))
        client = _get_client()

        start = await client.where_used_start(mkey=object_name, obj=obj_ref)
        token = start.get("token") if isinstance(start, dict) else None
        if not token:
            return {
                "status": "error",
                "message": "FortiManager did not return a where-used search token",
                "error_code": "api_error",
            }

        deadline = time.monotonic() + timeout
        percent = 0
        while True:
            summary = await client.where_used_get_summary(token=token)
            percent = summary.get("percent", 0) if isinstance(summary, dict) else 0
            if percent >= 100:
                break
            if time.monotonic() >= deadline:
                return {
                    "status": "error",
                    "message": (
                        f"Where-used search for '{object_name}' timed out after "
                        f"{timeout}s at {percent}% complete"
                    ),
                    "error_code": "timeout",
                }
            await asyncio.sleep(poll_interval)

        detail = await client.where_used_get_detail(token=token)
        where_used = detail.get("where_used", []) if isinstance(detail, dict) else []
        total = (
            detail.get("total_num", len(where_used))
            if isinstance(detail, dict)
            else len(where_used)
        )

        return {
            "status": "success",
            "object_name": object_name,
            "object_type": object_type,
            "total_matches": total,
            "used_in": where_used,
        }
    except Exception as e:
        logger.error(f"Failed to find usage for object {object_name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def find_duplicate_objects(
    adom: str,
    object_type: str = "address",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Find objects with identical content configured under different names.

    Runs FortiManager's "find duplicates" option against every object of
    the given type in the ADOM. FortiManager compares the requested
    fields across all objects of that type and adds a "duplicate entries"
    list to each object that shares its content with at least one other
    object -- the field itself, not something computed client-side.

    Args:
        adom: ADOM name
        object_type: One of "address", "address_group", "service",
            "service_group" (default: "address")
        fields: Object fields to compare for duplication (e.g. ["name",
            "type", "subnet"] for addresses). Omit to let FortiManager use
            its default field set for the type.

    Returns:
        dict: Duplicate scan result with keys:
            - status: "success" or "error"
            - object_type: The object type scanned
            - objects: Full per-object list FortiManager returned (each
              entry has a "duplicate entries" list when it has a match)
            - duplicate_count: Number of objects that have at least one
              duplicate entry
            - message: Error message if failed

    Example:
        >>> result = await find_duplicate_objects("root", object_type="address")
        >>> for obj in result["objects"]:
        ...     if obj.get("duplicate entries"):
        ...         print(obj["name"], "duplicates:", obj["duplicate entries"])
    """
    try:
        adom = validate_adom(adom)
        # Built before the client is fetched: it validates object_type, and
        # doing that after _get_client() masks a bad type behind
        # "client not initialized" (caught by test_invalid_object_type).
        obj_path = _obj_path(adom, object_type)
        client = _get_client()

        params: dict[str, Any] = {
            "option": ["find duplicates"],
            "load assigned": 0,
            "loadsub": 0,
        }
        if fields:
            params["fields"] = fields

        objects = await client.get(f"/pm/config/{obj_path}", **params)
        if not isinstance(objects, list):
            objects = [objects] if objects else []

        duplicate_count = sum(1 for obj in objects if obj.get("duplicate entries"))

        return {
            "status": "success",
            "object_type": object_type,
            "objects": objects,
            "duplicate_count": duplicate_count,
        }
    except Exception as e:
        logger.error(f"Failed to find duplicate {object_type} objects: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
