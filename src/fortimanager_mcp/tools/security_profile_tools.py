"""Security-profile object management tools for FortiManager.

Based on FNDN FortiManager 8.0.0 PM/config API specifications
(swagger: docs/fndn/8.0.0/json_api_reference/swagger/cdb-obj80.json,
definitions pm.config.antivirus.profile, pm.config.webfilter.profile,
pm.config.dnsfilter.profile, pm.config.application.list).

Provides CRUD operations for ADOM-scoped security-profile objects:
- Antivirus profiles         (/pm/config/adom/{adom}/obj/antivirus/profile)
- Web filter profiles        (/pm/config/adom/{adom}/obj/webfilter/profile)
- DNS filter profiles        (/pm/config/adom/{adom}/obj/dnsfilter/profile)
- Application control lists  (/pm/config/adom/{adom}/obj/application/list)

These are pure ADOM object-store CRUD -- the same shape as the address and
service object tools in object_tools.py. No device DB path is touched and
no install/preview flow is required here: a security-profile object only
affects a live device once it is referenced by a firewall policy (see
policy_tools.create_firewall_policy's av_profile / webfilter_profile /
dnsfilter_profile / application_list arguments) and that policy's package
is installed. Creating, updating, or deleting a profile object through this
module is inert until that happens.

These tools call FortiManagerClient's generic get/add/update/delete methods
directly (rather than adding new per-object methods to api/client.py) to
keep this new surface self-contained in one file.
"""

import logging
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import validate_adom, validate_object_name

logger = logging.getLogger(__name__)

# Base ADOM object-store URLs (FNDN cdb-obj80.json).
_ANTIVIRUS_PROFILE_URL = "/pm/config/adom/{adom}/obj/antivirus/profile"
_WEBFILTER_PROFILE_URL = "/pm/config/adom/{adom}/obj/webfilter/profile"
_DNSFILTER_PROFILE_URL = "/pm/config/adom/{adom}/obj/dnsfilter/profile"
_APPLICATION_LIST_URL = "/pm/config/adom/{adom}/obj/application/list"


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


async def _list_objects(
    client: FortiManagerClient,
    base_url: str,
    adom: str,
    name_filter: str | None,
) -> list[dict[str, Any]]:
    """Shared GET-collection helper for the profile/list endpoints below.

    Every security-profile object type here is listed the same way: GET the
    base collection URL, optionally narrowed with a "name contains" filter.
    """
    params: dict[str, Any] = {}
    if name_filter:
        params["filter"] = [["name", "contain", name_filter]]

    result = await client.get(base_url.format(adom=adom), **params)
    return result if isinstance(result, list) else [result] if result else []


# =============================================================================
# Antivirus Profiles
# =============================================================================


@mcp.tool()
async def list_antivirus_profiles(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List antivirus profiles in an ADOM.

    Antivirus profiles define virus/malware scanning behavior per protocol
    (HTTP, FTP, SMTP, etc.) and are applied to firewall policies.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Profile list with keys:
            - status: "success" or "error"
            - count: Number of profiles
            - profiles: List of antivirus profile objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        profiles = await _list_objects(client, _ANTIVIRUS_PROFILE_URL, adom, name_filter)

        return {
            "status": "success",
            "count": len(profiles),
            "profiles": profiles,
        }
    except Exception as e:
        logger.error(f"Failed to list antivirus profiles: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_antivirus_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about an antivirus profile.

    Args:
        adom: ADOM name
        name: Antivirus profile name

    Returns:
        dict: Profile details with keys:
            - status: "success" or "error"
            - profile: Full antivirus profile configuration
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "antivirus profile")
        client = _get_client()
        profile = await client.get(f"{_ANTIVIRUS_PROFILE_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "profile": profile,
        }
    except Exception as e:
        logger.error(f"Failed to get antivirus profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_antivirus_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    feature_set: str | None = None,
    scan_mode: str | None = None,
    av_virus_log: str | None = None,
) -> dict[str, Any]:
    """Create an antivirus profile.

    Args:
        adom: ADOM name
        name: Profile name
        comment: Optional comment
        feature_set: Flow/proxy feature set - "proxy" or "flow" (optional)
        scan_mode: Scan mode - "default" or "legacy" (optional)
        av_virus_log: Enable/disable AntiVirus logging - "enable" or
            "disable" (optional)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created profile name
            - message: Status or error message

    Example:
        >>> result = await create_antivirus_profile(
        ...     adom="root",
        ...     name="strict-av",
        ...     feature_set="flow",
        ...     av_virus_log="enable",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "antivirus profile")
        client = _get_client()

        profile: dict[str, Any] = {"name": name}
        if comment:
            profile["comment"] = comment
        if feature_set:
            profile["feature-set"] = feature_set
        if scan_mode:
            profile["scan-mode"] = scan_mode
        if av_virus_log:
            profile["av-virus-log"] = av_virus_log

        await client.add(_ANTIVIRUS_PROFILE_URL.format(adom=adom), data=profile)

        return {
            "status": "success",
            "name": name,
            "message": f"Antivirus profile {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create antivirus profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_antivirus_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    feature_set: str | None = None,
    scan_mode: str | None = None,
    av_virus_log: str | None = None,
) -> dict[str, Any]:
    """Update an existing antivirus profile.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: Profile name
        comment: New comment (optional)
        feature_set: New flow/proxy feature set - "proxy" or "flow" (optional)
        scan_mode: New scan mode - "default" or "legacy" (optional)
        av_virus_log: New AntiVirus logging setting - "enable" or "disable"
            (optional)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "antivirus profile")
        client = _get_client()

        data: dict[str, Any] = {}
        if comment is not None:
            data["comment"] = comment
        if feature_set:
            data["feature-set"] = feature_set
        if scan_mode:
            data["scan-mode"] = scan_mode
        if av_virus_log:
            data["av-virus-log"] = av_virus_log

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update(f"{_ANTIVIRUS_PROFILE_URL.format(adom=adom)}/{name}", **data)

        return {
            "status": "success",
            "message": f"Antivirus profile {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update antivirus profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_antivirus_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete an antivirus profile.

    WARNING: This will fail if the profile is in use by firewall policies.

    Args:
        adom: ADOM name
        name: Profile name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "antivirus profile")
        client = _get_client()
        await client.delete(f"{_ANTIVIRUS_PROFILE_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "message": f"Antivirus profile {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete antivirus profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Web Filter Profiles
# =============================================================================


@mcp.tool()
async def list_webfilter_profiles(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List web filter profiles in an ADOM.

    Web filter profiles define URL category rating actions, FortiGuard web
    filtering behavior, and related web-content controls.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Profile list with keys:
            - status: "success" or "error"
            - count: Number of profiles
            - profiles: List of web filter profile objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        profiles = await _list_objects(client, _WEBFILTER_PROFILE_URL, adom, name_filter)

        return {
            "status": "success",
            "count": len(profiles),
            "profiles": profiles,
        }
    except Exception as e:
        logger.error(f"Failed to list web filter profiles: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_webfilter_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about a web filter profile.

    Args:
        adom: ADOM name
        name: Web filter profile name

    Returns:
        dict: Profile details with keys:
            - status: "success" or "error"
            - profile: Full web filter profile configuration
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "web filter profile")
        client = _get_client()
        profile = await client.get(f"{_WEBFILTER_PROFILE_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "profile": profile,
        }
    except Exception as e:
        logger.error(f"Failed to get web filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_webfilter_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    feature_set: str | None = None,
    log_all_url: str | None = None,
    web_content_log: str | None = None,
) -> dict[str, Any]:
    """Create a web filter profile.

    Args:
        adom: ADOM name
        name: Profile name
        comment: Optional comment
        feature_set: Flow/proxy feature set - "proxy" or "flow" (optional)
        log_all_url: Enable/disable logging all URLs visited - "enable" or
            "disable" (optional)
        web_content_log: Enable/disable logging blocked web content -
            "enable" or "disable" (optional)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created profile name
            - message: Status or error message

    Example:
        >>> result = await create_webfilter_profile(
        ...     adom="root",
        ...     name="strict-web",
        ...     feature_set="flow",
        ...     log_all_url="enable",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "web filter profile")
        client = _get_client()

        profile: dict[str, Any] = {"name": name}
        if comment:
            profile["comment"] = comment
        if feature_set:
            profile["feature-set"] = feature_set
        if log_all_url:
            profile["log-all-url"] = log_all_url
        if web_content_log:
            profile["web-content-log"] = web_content_log

        await client.add(_WEBFILTER_PROFILE_URL.format(adom=adom), data=profile)

        return {
            "status": "success",
            "name": name,
            "message": f"Web filter profile {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create web filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_webfilter_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    feature_set: str | None = None,
    log_all_url: str | None = None,
    web_content_log: str | None = None,
) -> dict[str, Any]:
    """Update an existing web filter profile.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: Profile name
        comment: New comment (optional)
        feature_set: New flow/proxy feature set - "proxy" or "flow" (optional)
        log_all_url: New "log all URLs" setting - "enable" or "disable"
            (optional)
        web_content_log: New blocked-content logging setting - "enable" or
            "disable" (optional)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "web filter profile")
        client = _get_client()

        data: dict[str, Any] = {}
        if comment is not None:
            data["comment"] = comment
        if feature_set:
            data["feature-set"] = feature_set
        if log_all_url:
            data["log-all-url"] = log_all_url
        if web_content_log:
            data["web-content-log"] = web_content_log

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update(f"{_WEBFILTER_PROFILE_URL.format(adom=adom)}/{name}", **data)

        return {
            "status": "success",
            "message": f"Web filter profile {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update web filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_webfilter_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a web filter profile.

    WARNING: This will fail if the profile is in use by firewall policies.

    Args:
        adom: ADOM name
        name: Profile name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "web filter profile")
        client = _get_client()
        await client.delete(f"{_WEBFILTER_PROFILE_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "message": f"Web filter profile {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete web filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# DNS Filter Profiles
# =============================================================================


@mcp.tool()
async def list_dnsfilter_profiles(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List DNS filter profiles in an ADOM.

    DNS filter profiles control FortiGuard DNS category rating actions,
    botnet C&C domain blocking, and DNS-level safe search.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Profile list with keys:
            - status: "success" or "error"
            - count: Number of profiles
            - profiles: List of DNS filter profile objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        profiles = await _list_objects(client, _DNSFILTER_PROFILE_URL, adom, name_filter)

        return {
            "status": "success",
            "count": len(profiles),
            "profiles": profiles,
        }
    except Exception as e:
        logger.error(f"Failed to list DNS filter profiles: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_dnsfilter_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about a DNS filter profile.

    Args:
        adom: ADOM name
        name: DNS filter profile name

    Returns:
        dict: Profile details with keys:
            - status: "success" or "error"
            - profile: Full DNS filter profile configuration
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "DNS filter profile")
        client = _get_client()
        profile = await client.get(f"{_DNSFILTER_PROFILE_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "profile": profile,
        }
    except Exception as e:
        logger.error(f"Failed to get DNS filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_dnsfilter_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    block_action: str | None = None,
    block_botnet: str | None = None,
    safe_search: str | None = None,
) -> dict[str, Any]:
    """Create a DNS filter profile.

    Args:
        adom: ADOM name
        name: Profile name
        comment: Optional comment
        block_action: Action for blocked domains - "block", "redirect", or
            "block-sevrfail" (optional)
        block_botnet: Enable/disable blocking botnet C&C DNS lookups -
            "enable" or "disable" (optional)
        safe_search: Enable/disable Google/Bing/YouTube/etc. safe search -
            "enable" or "disable" (optional)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created profile name
            - message: Status or error message

    Example:
        >>> result = await create_dnsfilter_profile(
        ...     adom="root",
        ...     name="strict-dns",
        ...     block_botnet="enable",
        ...     safe_search="enable",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "DNS filter profile")
        client = _get_client()

        profile: dict[str, Any] = {"name": name}
        if comment:
            profile["comment"] = comment
        if block_action:
            profile["block-action"] = block_action
        if block_botnet:
            profile["block-botnet"] = block_botnet
        if safe_search:
            profile["safe-search"] = safe_search

        await client.add(_DNSFILTER_PROFILE_URL.format(adom=adom), data=profile)

        return {
            "status": "success",
            "name": name,
            "message": f"DNS filter profile {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create DNS filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_dnsfilter_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    block_action: str | None = None,
    block_botnet: str | None = None,
    safe_search: str | None = None,
) -> dict[str, Any]:
    """Update an existing DNS filter profile.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: Profile name
        comment: New comment (optional)
        block_action: New blocked-domain action - "block", "redirect", or
            "block-sevrfail" (optional)
        block_botnet: New botnet C&C blocking setting - "enable" or
            "disable" (optional)
        safe_search: New safe search setting - "enable" or "disable"
            (optional)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "DNS filter profile")
        client = _get_client()

        data: dict[str, Any] = {}
        if comment is not None:
            data["comment"] = comment
        if block_action:
            data["block-action"] = block_action
        if block_botnet:
            data["block-botnet"] = block_botnet
        if safe_search:
            data["safe-search"] = safe_search

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update(f"{_DNSFILTER_PROFILE_URL.format(adom=adom)}/{name}", **data)

        return {
            "status": "success",
            "message": f"DNS filter profile {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update DNS filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_dnsfilter_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a DNS filter profile.

    WARNING: This will fail if the profile is in use by firewall policies.

    Args:
        adom: ADOM name
        name: Profile name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "DNS filter profile")
        client = _get_client()
        await client.delete(f"{_DNSFILTER_PROFILE_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "message": f"DNS filter profile {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete DNS filter profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Application Control Lists
# =============================================================================


@mcp.tool()
async def list_application_lists(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List application-control lists in an ADOM.

    Application control lists define pass/block/monitor actions for
    application signatures and categories, applied to firewall policies.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: List result with keys:
            - status: "success" or "error"
            - count: Number of application-control lists
            - lists: List of application-control list objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        app_lists = await _list_objects(client, _APPLICATION_LIST_URL, adom, name_filter)

        return {
            "status": "success",
            "count": len(app_lists),
            "lists": app_lists,
        }
    except Exception as e:
        logger.error(f"Failed to list application-control lists: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_application_list(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about an application-control list.

    Args:
        adom: ADOM name
        name: Application-control list name

    Returns:
        dict: List details with keys:
            - status: "success" or "error"
            - list: Full application-control list configuration
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "application list")
        client = _get_client()
        app_list = await client.get(f"{_APPLICATION_LIST_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "list": app_list,
        }
    except Exception as e:
        logger.error(f"Failed to get application list {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_application_list(
    adom: str,
    name: str,
    comment: str | None = None,
    deep_app_inspection: str | None = None,
    unknown_application_action: str | None = None,
    other_application_action: str | None = None,
) -> dict[str, Any]:
    """Create an application-control list.

    Args:
        adom: ADOM name
        name: List name
        comment: Optional comment
        deep_app_inspection: Enable/disable deep application inspection -
            "enable" or "disable" (optional)
        unknown_application_action: Pass or block traffic from unknown
            applications - "pass" or "block" (optional)
        other_application_action: Action for other applications - "pass"
            or "block" (optional)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created list name
            - message: Status or error message

    Example:
        >>> result = await create_application_list(
        ...     adom="root",
        ...     name="strict-appctrl",
        ...     unknown_application_action="block",
        ...     other_application_action="block",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "application list")
        client = _get_client()

        app_list: dict[str, Any] = {"name": name}
        if comment:
            app_list["comment"] = comment
        if deep_app_inspection:
            app_list["deep-app-inspection"] = deep_app_inspection
        if unknown_application_action:
            app_list["unknown-application-action"] = unknown_application_action
        if other_application_action:
            app_list["other-application-action"] = other_application_action

        await client.add(_APPLICATION_LIST_URL.format(adom=adom), data=app_list)

        return {
            "status": "success",
            "name": name,
            "message": f"Application list {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create application list {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_application_list(
    adom: str,
    name: str,
    comment: str | None = None,
    deep_app_inspection: str | None = None,
    unknown_application_action: str | None = None,
    other_application_action: str | None = None,
) -> dict[str, Any]:
    """Update an existing application-control list.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: List name
        comment: New comment (optional)
        deep_app_inspection: New deep-inspection setting - "enable" or
            "disable" (optional)
        unknown_application_action: New unknown-application action - "pass"
            or "block" (optional)
        other_application_action: New other-application action - "pass" or
            "block" (optional)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "application list")
        client = _get_client()

        data: dict[str, Any] = {}
        if comment is not None:
            data["comment"] = comment
        if deep_app_inspection:
            data["deep-app-inspection"] = deep_app_inspection
        if unknown_application_action:
            data["unknown-application-action"] = unknown_application_action
        if other_application_action:
            data["other-application-action"] = other_application_action

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update(f"{_APPLICATION_LIST_URL.format(adom=adom)}/{name}", **data)

        return {
            "status": "success",
            "message": f"Application list {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update application list {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_application_list(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete an application-control list.

    WARNING: This will fail if the list is in use by firewall policies.

    Args:
        adom: ADOM name
        name: List name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "application list")
        client = _get_client()
        await client.delete(f"{_APPLICATION_LIST_URL.format(adom=adom)}/{name}")

        return {
            "status": "success",
            "message": f"Application list {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete application list {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
