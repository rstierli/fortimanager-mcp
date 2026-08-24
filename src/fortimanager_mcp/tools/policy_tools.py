"""Policy and package management tools for FortiManager.

Based on FNDN FortiManager 7.6.5 PM and Security Console API specifications.
Provides policy package management, firewall policy CRUD operations,
and installation operations.
"""

import asyncio
import logging
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.errors import ResourceNotFoundError, client_safe_error
from fortimanager_mcp.utils.install_gate import package_revision, record_preview
from fortimanager_mcp.utils.responses import error_response
from fortimanager_mcp.utils.task_guard import TaskSlotsExhausted, spawn_guarded
from fortimanager_mcp.utils.validation import (
    check_policy_safety,
    redact_config_text_secrets,
    validate_adom,
    validate_move_position,
    validate_package_name,
    validate_policy_name,
    validate_security_profiles,
)

logger = logging.getLogger(__name__)


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


def _build_security_profile_fields(
    utm_status: bool | None,
    av_profile: str | None,
    ips_sensor: str | None,
    webfilter_profile: str | None,
    dnsfilter_profile: str | None,
    application_list: str | None,
    file_filter_profile: str | None,
    ssl_ssh_profile: str | None,
    profile_protocol_options: str | None,
    profile_group: str | None,
) -> dict[str, Any]:
    """Build the security-profile portion of a firewall policy payload.

    Caller must run `validate_security_profiles(...)` first -- this assumes
    the profile_group / individual-profile combination is already valid.

    `profile-type` is not itself a tool argument; it is derived here to
    match what the combination actually requires on the appliance
    (`"group"` when `profile_group` is set, `"single"` when any individual
    profile field is set, omitted otherwise) so a caller supplying
    `profile_group` doesn't also need to know to set `profile-type=group`
    for FortiOS to honor it.
    """
    fields: dict[str, Any] = {}

    if utm_status is not None:
        fields["utm-status"] = "enable" if utm_status else "disable"
    if av_profile is not None:
        fields["av-profile"] = av_profile
    if ips_sensor is not None:
        fields["ips-sensor"] = ips_sensor
    if webfilter_profile is not None:
        fields["webfilter-profile"] = webfilter_profile
    if dnsfilter_profile is not None:
        fields["dnsfilter-profile"] = dnsfilter_profile
    if application_list is not None:
        fields["application-list"] = application_list
    if file_filter_profile is not None:
        fields["file-filter-profile"] = file_filter_profile
    if ssl_ssh_profile is not None:
        fields["ssl-ssh-profile"] = ssl_ssh_profile
    if profile_protocol_options is not None:
        fields["profile-protocol-options"] = profile_protocol_options

    if profile_group is not None:
        fields["profile-group"] = profile_group
        fields["profile-type"] = "group"
    elif any(
        v is not None
        for v in (
            av_profile,
            ips_sensor,
            webfilter_profile,
            dnsfilter_profile,
            application_list,
            file_filter_profile,
            ssl_ssh_profile,
            profile_protocol_options,
        )
    ):
        fields["profile-type"] = "single"

    return fields


# =============================================================================
# Policy Package Management
# =============================================================================


@mcp.tool()
async def create_package(
    adom: str,
    name: str,
    ngfw_mode: str = "profile-based",
    central_nat: bool = False,
) -> dict[str, Any]:
    """Create a new policy package.

    Policy packages contain firewall policies, security profiles,
    and other configurations to be deployed to managed devices.

    Args:
        adom: ADOM name
        name: Package name
        ngfw_mode: NGFW mode - "profile-based" (default) or "policy-based"
        central_nat: Enable central NAT (default: False)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - package: Created package name
            - message: Status or error message

    Example:
        >>> result = await create_package(
        ...     adom="root",
        ...     name="Branch-Policy",
        ...     ngfw_mode="profile-based"
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_package_name(name)
        client = _get_client()

        package_settings = {
            "ngfw-mode": ngfw_mode,
            "central-nat": "enable" if central_nat else "disable",
        }

        await client.create_package(adom, name, package_settings)

        return {
            "status": "success",
            "package": name,
            "message": f"Package {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create package {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_package(
    adom: str,
    package: str,
) -> dict[str, Any]:
    """Delete a policy package.

    WARNING: This will delete the package and all its policies.
    This operation cannot be undone.

    Args:
        adom: ADOM name
        package: Package name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        await client.delete_package(adom, package)

        return {
            "status": "success",
            "message": f"Package {package} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete package {package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def clone_package(
    adom: str,
    package: str,
    new_name: str,
) -> dict[str, Any]:
    """Clone a policy package.

    Creates a copy of an existing package with all its policies.

    Args:
        adom: ADOM name
        package: Source package name
        new_name: Name for the cloned package

    Returns:
        dict: Clone result with keys:
            - status: "success" or "error"
            - package: New package name
            - message: Status or error message

    Example:
        >>> result = await clone_package(
        ...     adom="root",
        ...     package="default",
        ...     new_name="default-copy"
        ... )
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        new_name = validate_package_name(new_name)
        client = _get_client()
        await client.clone_package(adom, package, new_name)

        return {
            "status": "success",
            "package": new_name,
            "message": f"Package {package} cloned to {new_name}",
        }
    except Exception as e:
        logger.error(f"Failed to clone package {package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def assign_package(
    adom: str,
    package: str,
    devices: list[dict[str, str]],
) -> dict[str, Any]:
    """Assign a policy package to devices.

    Associates a policy package with specific devices/VDOMs.
    The package can then be installed to these devices.

    Args:
        adom: ADOM name
        package: Package name
        devices: Target devices [{"name": "FGT1", "vdom": "root"}, ...]

    Returns:
        dict: Assignment result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await assign_package(
        ...     adom="root",
        ...     package="Branch-Policy",
        ...     devices=[
        ...         {"name": "FGT-Branch1", "vdom": "root"},
        ...         {"name": "FGT-Branch2", "vdom": "root"}
        ...     ]
        ... )
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        await client.assign_package(adom, package, devices)

        return {
            "status": "success",
            "message": f"Package {package} assigned to {len(devices)} device(s)",
        }
    except Exception as e:
        logger.error(f"Failed to assign package {package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Firewall Policy Operations
# =============================================================================


@mcp.tool()
async def list_firewall_policies(
    adom: str,
    package: str,
    fields: list[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """List firewall policies in a policy package.

    Args:
        adom: ADOM name
        package: Policy package name
        fields: Specific fields to return (optional)
        limit: Maximum number of policies to return (optional)
        offset: Starting position for pagination (default: 0)

    Returns:
        dict: Policy list with keys:
            - status: "success" or "error"
            - count: Number of policies returned
            - total: Total number of policies in package
            - policies: List of policy objects
            - message: Error message if failed

    Example:
        >>> # Get all policies
        >>> result = await list_firewall_policies("root", "default")

        >>> # Get first 10 policies with specific fields
        >>> result = await list_firewall_policies(
        ...     adom="root",
        ...     package="default",
        ...     fields=["policyid", "name", "srcaddr", "dstaddr", "action"],
        ...     limit=10
        ... )
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        # Get total count first
        total = await client.get_firewall_policy_count(adom, package)

        # Build range parameter for pagination
        range_param = None
        if limit:
            range_param = [offset, limit]

        policies = await client.list_firewall_policies(
            adom=adom,
            pkg=package,
            fields=fields,
            range=range_param,
        )

        return {
            "status": "success",
            "count": len(policies),
            "total": total,
            "policies": policies,
        }
    except Exception as e:
        logger.error(f"Failed to list policies in {package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_firewall_policy(
    adom: str,
    package: str,
    policyid: int,
) -> dict[str, Any]:
    """Get detailed information about a specific firewall policy.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Policy ID number

    Returns:
        dict: Policy details with keys:
            - status: "success" or "error"
            - policy: Full policy configuration
            - message: Error message if failed

    Example:
        >>> result = await get_firewall_policy("root", "default", 1)
        >>> print(f"Policy name: {result['policy']['name']}")
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        policy = await client.get_firewall_policy(adom, package, policyid)

        return {
            "status": "success",
            "policy": policy,
        }
    except Exception as e:
        logger.error(f"Failed to get policy {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_firewall_policy(
    adom: str,
    package: str,
    name: str,
    srcintf: list[str],
    dstintf: list[str],
    srcaddr: list[str],
    dstaddr: list[str],
    service: list[str],
    action: str = "accept",
    schedule: str = "always",
    nat: bool = False,
    logtraffic: str = "utm",
    status: str = "enable",
    comments: str | None = None,
    policyid: int | None = None,
    srcaddr_negate: bool | None = None,
    dstaddr_negate: bool | None = None,
    service_negate: bool | None = None,
    utm_status: bool | None = None,
    av_profile: str | None = None,
    ips_sensor: str | None = None,
    webfilter_profile: str | None = None,
    dnsfilter_profile: str | None = None,
    application_list: str | None = None,
    file_filter_profile: str | None = None,
    ssl_ssh_profile: str | None = None,
    profile_protocol_options: str | None = None,
    profile_group: str | None = None,
) -> dict[str, Any]:
    """Create a new firewall policy.

    Creates a firewall policy in the specified policy package.
    The policy won't be active until the package is installed to devices.

    Args:
        adom: ADOM name
        package: Policy package name
        name: Policy name
        srcintf: Source interfaces (e.g., ["internal"])
        dstintf: Destination interfaces (e.g., ["wan1"])
        srcaddr: Source addresses (e.g., ["all"])
        dstaddr: Destination addresses (e.g., ["all"])
        service: Services (e.g., ["ALL", "HTTP", "HTTPS"])
        action: Policy action - "accept" or "deny" (default: "accept")
        schedule: Schedule object name (default: "always")
        nat: Enable NAT (default: False)
        logtraffic: Log mode - "all", "utm", or "disable" (default: "utm")
        status: Policy status - "enable" or "disable" (default: "enable")
        comments: Policy comments (optional)
        policyid: Specific policy ID (optional, auto-assigned if not set)
        srcaddr_negate: Match all sources EXCEPT srcaddr (optional; omitted
            from the payload when not set, leaving the FortiManager default)
        dstaddr_negate: Match all destinations EXCEPT dstaddr (optional)
        service_negate: Match all services EXCEPT service (optional)
        utm_status: Enable/disable security profile inspection on this policy
            (optional). Required (True) for any of the profile fields below
            to actually apply.
        av_profile: Antivirus profile name, e.g. "default" (optional)
        ips_sensor: IPS sensor name, e.g. "default" (optional)
        webfilter_profile: Web filter profile name (optional)
        dnsfilter_profile: DNS filter profile name (optional)
        application_list: Application control list name (optional)
        file_filter_profile: File filter profile name (optional)
        ssl_ssh_profile: SSL/SSH inspection profile name, e.g.
            "certificate-inspection" (optional)
        profile_protocol_options: Protocol options profile name (optional).
            Mutually exclusive with profile_group -- it is itself a member
            of the FortiOS `firewall profile-group` object, so FortiOS
            rejects setting both
        profile_group: Security profile group name (optional). Mutually
            exclusive with av_profile, ips_sensor, webfilter_profile,
            dnsfilter_profile, application_list, file_filter_profile,
            ssl_ssh_profile, and profile_protocol_options -- FortiOS rejects
            setting both

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - policyid: Created policy ID
            - message: Status or error message

    Example:
        >>> result = await create_firewall_policy(
        ...     adom="root",
        ...     package="default",
        ...     name="Allow-Web-Traffic",
        ...     srcintf=["internal"],
        ...     dstintf=["wan1"],
        ...     srcaddr=["LAN-Subnet"],
        ...     dstaddr=["all"],
        ...     service=["HTTP", "HTTPS"],
        ...     action="accept",
        ...     nat=True,
        ...     utm_status=True,
        ...     av_profile="default",
        ...     ips_sensor="default",
        ... )
    """
    # Safety check for overly permissive policies
    safety_warning = None
    safety_result = check_policy_safety(
        srcaddr,
        dstaddr,
        service,
        action,
        srcaddr_negate=bool(srcaddr_negate),
        dstaddr_negate=bool(dstaddr_negate),
        service_negate=bool(service_negate),
    )
    if safety_result:
        if safety_result.get("status") == "error":
            return safety_result
        safety_warning = safety_result.get("_safety_warning")

    # FortiManager rejects logtraffic=utm on deny policies
    if action == "deny" and logtraffic == "utm":
        logtraffic = "all"

    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        name = validate_policy_name(name)
        validate_security_profiles(
            utm_status=utm_status,
            profile_group=profile_group,
            av_profile=av_profile,
            ips_sensor=ips_sensor,
            webfilter_profile=webfilter_profile,
            dnsfilter_profile=dnsfilter_profile,
            application_list=application_list,
            file_filter_profile=file_filter_profile,
            ssl_ssh_profile=ssl_ssh_profile,
            profile_protocol_options=profile_protocol_options,
        )
        client = _get_client()

        policy: dict[str, Any] = {
            "name": name,
            "srcintf": srcintf,
            "dstintf": dstintf,
            "srcaddr": srcaddr,
            "dstaddr": dstaddr,
            "service": service,
            "action": action,
            "schedule": schedule,
            "nat": "enable" if nat else "disable",
            "logtraffic": logtraffic,
            "status": status,
        }

        if comments:
            policy["comments"] = comments
        if policyid is not None:
            policy["policyid"] = policyid
        if srcaddr_negate is not None:
            policy["srcaddr-negate"] = "enable" if srcaddr_negate else "disable"
        if dstaddr_negate is not None:
            policy["dstaddr-negate"] = "enable" if dstaddr_negate else "disable"
        if service_negate is not None:
            policy["service-negate"] = "enable" if service_negate else "disable"
        policy.update(
            _build_security_profile_fields(
                utm_status=utm_status,
                av_profile=av_profile,
                ips_sensor=ips_sensor,
                webfilter_profile=webfilter_profile,
                dnsfilter_profile=dnsfilter_profile,
                application_list=application_list,
                file_filter_profile=file_filter_profile,
                ssl_ssh_profile=ssl_ssh_profile,
                profile_protocol_options=profile_protocol_options,
                profile_group=profile_group,
            )
        )

        result = await client.create_firewall_policy(adom, package, policy)

        response = {
            "status": "success",
            "policyid": result.get("policyid", policyid),
            "message": f"Policy {name} created successfully",
        }
        if safety_warning:
            response["warning"] = safety_warning
        return response
    except Exception as e:
        logger.error(f"Failed to create policy {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_firewall_policy(
    adom: str,
    package: str,
    policyid: int,
    name: str | None = None,
    srcintf: list[str] | None = None,
    dstintf: list[str] | None = None,
    srcaddr: list[str] | None = None,
    dstaddr: list[str] | None = None,
    service: list[str] | None = None,
    action: str | None = None,
    schedule: str | None = None,
    nat: bool | None = None,
    logtraffic: str | None = None,
    status: str | None = None,
    comments: str | None = None,
    global_label: str | None = None,
    global_label_color: int | None = None,
    srcaddr_negate: bool | None = None,
    dstaddr_negate: bool | None = None,
    service_negate: bool | None = None,
    utm_status: bool | None = None,
    av_profile: str | None = None,
    ips_sensor: str | None = None,
    webfilter_profile: str | None = None,
    dnsfilter_profile: str | None = None,
    application_list: str | None = None,
    file_filter_profile: str | None = None,
    ssl_ssh_profile: str | None = None,
    profile_protocol_options: str | None = None,
    profile_group: str | None = None,
) -> dict[str, Any]:
    """Update an existing firewall policy.

    Only the specified fields will be updated; other fields remain unchanged.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Policy ID to update
        name: New policy name (optional)
        srcintf: New source interfaces (optional)
        dstintf: New destination interfaces (optional)
        srcaddr: New source addresses (optional)
        dstaddr: New destination addresses (optional)
        service: New services (optional)
        action: New action - "accept" or "deny" (optional)
        schedule: New schedule (optional)
        nat: Enable/disable NAT (optional)
        logtraffic: New log mode (optional)
        status: New status (optional)
        comments: New comments (optional)
        global_label: Policy section label (optional)
        global_label_color: Policy section color ID 0-31 (optional)
        srcaddr_negate: Match all sources EXCEPT srcaddr (optional; None
            leaves the field untouched, like every other optional field)
        dstaddr_negate: Match all destinations EXCEPT dstaddr (optional)
        service_negate: Match all services EXCEPT service (optional)
        utm_status: Enable/disable security profile inspection (optional)
        av_profile: Antivirus profile name (optional)
        ips_sensor: IPS sensor name (optional)
        webfilter_profile: Web filter profile name (optional)
        dnsfilter_profile: DNS filter profile name (optional)
        application_list: Application control list name (optional)
        file_filter_profile: File filter profile name (optional)
        ssl_ssh_profile: SSL/SSH inspection profile name (optional)
        profile_protocol_options: Protocol options profile name (optional).
            Mutually exclusive with profile_group in the same call -- it is
            itself a member of the FortiOS `firewall profile-group` object
        profile_group: Security profile group name (optional). Mutually
            exclusive with av_profile, ips_sensor, webfilter_profile,
            dnsfilter_profile, application_list, file_filter_profile,
            ssl_ssh_profile, and profile_protocol_options in the same call

    Note:
        Sending any individual security-profile field (av_profile,
        ssl_ssh_profile, profile_protocol_options, etc.) on a policy that is
        currently in group mode flips `profile-type` to "single" on the
        appliance. The previously-stored `profile-group` value becomes
        dormant (not deleted) rather than staying active alongside the new
        field -- FortiOS only honors one profile-type at a time.

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - policyid: Updated policy ID
            - message: Status or error message

    Example:
        >>> # Disable a policy
        >>> result = await update_firewall_policy(
        ...     adom="root",
        ...     package="default",
        ...     policyid=10,
        ...     status="disable"
        ... )

        >>> # Update source addresses
        >>> result = await update_firewall_policy(
        ...     adom="root",
        ...     package="default",
        ...     policyid=10,
        ...     srcaddr=["New-Subnet", "Other-Subnet"]
        ... )
    """
    # Safety check — permissiveness only when all critical fields are explicitly
    # provided (for partial updates we can't know existing values without an
    # extra API call). Negation flags are always checked so enabling one is
    # never silent, even on a negate-only partial update.
    safety_warning = None
    full_check = srcaddr is not None and dstaddr is not None and action is not None
    safety_result = check_policy_safety(
        srcaddr if full_check else None,
        dstaddr if full_check else None,
        service if full_check else None,
        action if full_check else None,
        srcaddr_negate=bool(srcaddr_negate),
        dstaddr_negate=bool(dstaddr_negate),
        service_negate=bool(service_negate),
    )
    if safety_result:
        if safety_result.get("status") == "error":
            return safety_result
        safety_warning = safety_result.get("_safety_warning")

    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        if name is not None:
            name = validate_policy_name(name)
        validate_security_profiles(
            utm_status=utm_status,
            profile_group=profile_group,
            av_profile=av_profile,
            ips_sensor=ips_sensor,
            webfilter_profile=webfilter_profile,
            dnsfilter_profile=dnsfilter_profile,
            application_list=application_list,
            file_filter_profile=file_filter_profile,
            ssl_ssh_profile=ssl_ssh_profile,
            profile_protocol_options=profile_protocol_options,
        )
        client = _get_client()

        data: dict[str, Any] = {}

        if name is not None:
            data["name"] = name
        if srcintf is not None:
            data["srcintf"] = srcintf
        if dstintf is not None:
            data["dstintf"] = dstintf
        if srcaddr is not None:
            data["srcaddr"] = srcaddr
        if dstaddr is not None:
            data["dstaddr"] = dstaddr
        if service is not None:
            data["service"] = service
        if action is not None:
            data["action"] = action
        if schedule is not None:
            data["schedule"] = schedule
        if nat is not None:
            data["nat"] = "enable" if nat else "disable"
        if logtraffic is not None:
            data["logtraffic"] = logtraffic
        if status is not None:
            data["status"] = status
        if comments is not None:
            data["comments"] = comments
        if global_label is not None:
            data["global-label"] = global_label
        if global_label_color is not None:
            data["_global-label-color"] = global_label_color
        if srcaddr_negate is not None:
            data["srcaddr-negate"] = "enable" if srcaddr_negate else "disable"
        if dstaddr_negate is not None:
            data["dstaddr-negate"] = "enable" if dstaddr_negate else "disable"
        if service_negate is not None:
            data["service-negate"] = "enable" if service_negate else "disable"
        data.update(
            _build_security_profile_fields(
                utm_status=utm_status,
                av_profile=av_profile,
                ips_sensor=ips_sensor,
                webfilter_profile=webfilter_profile,
                dnsfilter_profile=dnsfilter_profile,
                application_list=application_list,
                file_filter_profile=file_filter_profile,
                ssl_ssh_profile=ssl_ssh_profile,
                profile_protocol_options=profile_protocol_options,
                profile_group=profile_group,
            )
        )

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_firewall_policy(adom, package, policyid, data)

        response = {
            "status": "success",
            "policyid": policyid,
            "message": f"Policy {policyid} updated successfully",
        }
        if safety_warning:
            response["warning"] = safety_warning
        return response
    except Exception as e:
        logger.error(f"Failed to update policy {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_firewall_policy(
    adom: str,
    package: str,
    policyid: int,
) -> dict[str, Any]:
    """Delete a firewall policy.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Policy ID to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        await client.delete_firewall_policy(adom, package, policyid)

        return {
            "status": "success",
            "message": f"Policy {policyid} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete policy {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_firewall_policies_bulk(
    adom: str,
    package: str,
    policyids: list[int],
) -> dict[str, Any]:
    """Delete multiple firewall policies at once.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name
        package: Policy package name
        policyids: List of policy IDs to delete

    Returns:
        dict: Delete result with keys:
            - status: "success", "partial", or "error"
            - deleted_count: Number of policies deleted
            - deleted: Policy IDs that were deleted
            - failed: Per-item failures [{"policyid", "message", "error_code"}, ...]
            - message: Status or error message

    Example:
        >>> result = await delete_firewall_policies_bulk(
        ...     adom="root",
        ...     package="default",
        ...     policyids=[5, 6, 7, 8]
        ... )
    """
    try:
        if not policyids:
            return {"status": "error", "message": "No policy IDs provided"}

        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
    except Exception as e:
        logger.error(f"Failed to delete policies: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}

    # Per-item deletes so one bad ID doesn't abort (or mask) the rest. The
    # previous single filtered DELETE reported len(policyids) as deleted no
    # matter how many IDs actually matched (bundle D of #11).
    deleted: list[int] = []
    failed: list[dict[str, Any]] = []
    for policyid in policyids:
        try:
            await client.delete_firewall_policy(adom, package, policyid)
            deleted.append(policyid)
        except Exception as e:
            logger.error(f"Failed to delete policy {policyid}: {e}")
            msg, code = client_safe_error(e)
            failed.append({"policyid": policyid, "message": msg, "error_code": code})

    if not failed:
        status = "success"
    elif deleted:
        status = "partial"
    else:
        status = "error"
    return {
        "status": status,
        "deleted_count": len(deleted),
        "deleted": deleted,
        "failed": failed,
        "message": f"Deleted {len(deleted)} of {len(policyids)} policies",
    }


@mcp.tool()
async def move_firewall_policy(
    adom: str,
    package: str,
    policyid: int,
    target_policyid: int,
    position: str = "before",
) -> dict[str, Any]:
    """Move a firewall policy to a new position.

    Reorders a policy relative to another policy in the rule list.
    Policy order determines evaluation priority.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Policy ID to move
        target_policyid: Reference policy ID
        position: Where to place - "before" or "after" (default: "before")

    Returns:
        dict: Move result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> # Move policy 10 before policy 5
        >>> result = await move_firewall_policy(
        ...     adom="root",
        ...     package="default",
        ...     policyid=10,
        ...     target_policyid=5,
        ...     position="before"
        ... )
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        position = validate_move_position(position)
        client = _get_client()
        await client.move_firewall_policy(adom, package, policyid, target_policyid, position)

        return {
            "status": "success",
            "message": f"Policy {policyid} moved {position} policy {target_policyid}",
        }
    except Exception as e:
        logger.error(f"Failed to move policy {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def search_firewall_policies(
    adom: str,
    package: str,
    name_filter: str | None = None,
    srcaddr_filter: str | None = None,
    dstaddr_filter: str | None = None,
    service_filter: str | None = None,
    action_filter: str | None = None,
    status_filter: str | None = None,
) -> dict[str, Any]:
    """Search firewall policies with filters.

    Args:
        adom: ADOM name
        package: Policy package name
        name_filter: Filter by policy name (partial match)
        srcaddr_filter: Filter by source address (partial match)
        dstaddr_filter: Filter by destination address (partial match)
        service_filter: Filter by service (partial match)
        action_filter: Filter by action ("accept" or "deny")
        status_filter: Filter by status ("enable" or "disable")

    Returns:
        dict: Search results with keys:
            - status: "success" or "error"
            - count: Number of matching policies
            - policies: List of matching policy objects
            - message: Error message if failed

    Example:
        >>> # Find all deny policies
        >>> result = await search_firewall_policies(
        ...     adom="root",
        ...     package="default",
        ...     action_filter="deny"
        ... )

        >>> # Find policies using a specific address
        >>> result = await search_firewall_policies(
        ...     adom="root",
        ...     package="default",
        ...     srcaddr_filter="Server-Subnet"
        ... )
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        # Build filter list
        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])
        if srcaddr_filter:
            filters.append(["srcaddr", "contain", srcaddr_filter])
        if dstaddr_filter:
            filters.append(["dstaddr", "contain", dstaddr_filter])
        if service_filter:
            filters.append(["service", "contain", service_filter])
        if action_filter:
            filters.append(["action", "==", action_filter])
        if status_filter:
            filters.append(["status", "==", status_filter])

        policies = await client.list_firewall_policies(
            adom=adom,
            pkg=package,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(policies),
            "policies": policies,
        }
    except Exception as e:
        logger.error(f"Failed to search policies: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Service Resolution
# =============================================================================


def _extract_service_details(service_data: dict[str, Any]) -> dict[str, Any]:
    """Extract structured port/protocol info from a service object.

    Args:
        service_data: Raw service object from FortiManager API.

    Returns:
        dict with name, protocol, and port details.
    """
    details: dict[str, Any] = {
        "name": service_data.get("name", ""),
        "protocol": service_data.get("protocol", ""),
    }

    # FMG returns the service protocol as an integer enum whose TCP/UDP/SCTP
    # code is version-dependent (verified live: FMG 7.6.6=5, 7.6.7/8.0=15;
    # ICMP=1, ICMP6=6, IP=2 across all). Some endpoints also surface the string
    # alias, so match every observed representation rather than a single value.
    protocol = service_data.get("protocol", "")
    protocol_key = str(protocol).upper()
    tcp_udp = {"5", "15", "TCP/UDP/SCTP"}
    icmp = {"1", "ICMP"}
    icmp6 = {"6", "ICMP6"}

    if protocol_key in tcp_udp:
        ports: dict[str, str] = {}
        for key in ("tcp-portrange", "udp-portrange", "sctp-portrange"):
            value = service_data.get(key)
            if value:
                ports[key] = value
        details["ports"] = ports
        details["category"] = "TCP/UDP/SCTP"
    elif protocol_key in icmp or protocol_key in icmp6:
        details["category"] = "ICMP6" if protocol_key in icmp6 else "ICMP"
        if "icmptype" in service_data:
            details["icmp_type"] = service_data["icmptype"]
        if "icmpcode" in service_data:
            details["icmp_code"] = service_data["icmpcode"]
    else:
        details["category"] = "IP"
        if "protocol-number" in service_data:
            details["protocol_number"] = service_data["protocol-number"]

    return details


async def _resolve_single_service(
    client: Any,
    adom: str,
    service_name: str,
    _seen: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Resolve a single service name to its definition.

    Tries service custom first, then service group. Returns an error entry
    if neither exists. Only not-found errors fall through to the next lookup;
    real failures (permission, connection) propagate to the caller instead of
    being mislabeled as "not found". ``_seen`` carries the group names already
    being resolved on this path so a circular group reference terminates
    instead of recursing forever.
    """
    if service_name in _seen:
        return {
            "name": service_name,
            "type": "group",
            "error": f"Circular group reference: '{service_name}' is already being resolved",
        }

    # Try as individual service first
    try:
        svc = await client.get_service(adom, service_name)
        return _extract_service_details(svc)
    except ResourceNotFoundError:
        pass

    # Try as service group
    try:
        group = await client.get_service_group(adom, service_name)
    except ResourceNotFoundError:
        return {
            "name": service_name,
            "type": "unknown",
            "error": f"Service '{service_name}' not found as custom service or group",
        }

    members = group.get("member", [])
    # Recursively resolve group members
    resolved_members = []
    if members:
        child_seen = _seen | {service_name}
        tasks = [_resolve_single_service(client, adom, m, child_seen) for m in members]
        resolved_members = list(await asyncio.gather(*tasks))
    return {
        "name": service_name,
        "type": "group",
        "members": resolved_members,
    }


@mcp.tool()
async def get_policy_services(
    adom: str,
    package: str,
    policy_id: int,
    resolve: bool = True,
) -> dict[str, Any]:
    """Get services configured on a firewall policy with optional group resolution.

    Retrieves the service list from a firewall policy and optionally
    resolves each service/group into its detailed definition (ports,
    protocols, group members).

    Useful for policy hardening workflows where you need to compare
    actual traffic against configured services.

    Args:
        adom: ADOM name
        package: Policy package name
        policy_id: Policy ID number
        resolve: If True, resolve each service to its definition
                 including port ranges and group members (default: True)

    Returns:
        dict: Service information with keys:
            - status: "success" or "error"
            - policy_id: The policy ID queried
            - policy_name: Name of the policy
            - service_names: List of raw service names from the policy
            - services: Resolved service details (if resolve=True)
            - message: Error message if failed

    Example:
        >>> # Get resolved services for policy 10
        >>> result = await get_policy_services("root", "default", 10)

        >>> # Get just the service names without resolution
        >>> result = await get_policy_services("root", "default", 10, resolve=False)
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        policy = await client.get_firewall_policy(adom, package, policy_id)

        service_names = policy.get("service", [])
        policy_name = policy.get("name", "")

        if not resolve:
            return {
                "status": "success",
                "policy_id": policy_id,
                "policy_name": policy_name,
                "service_names": service_names,
            }

        # Handle "ALL" service specially
        if service_names == ["ALL"] or service_names == "ALL":
            return {
                "status": "success",
                "policy_id": policy_id,
                "policy_name": policy_name,
                "service_names": ["ALL"],
                "services": [
                    {
                        "name": "ALL",
                        "category": "wildcard",
                        "description": "All services/protocols (no restriction)",
                    }
                ],
            }

        # Resolve each service concurrently
        if isinstance(service_names, str):
            service_names = [service_names]

        tasks = [_resolve_single_service(client, adom, name) for name in service_names]
        resolved = list(await asyncio.gather(*tasks))

        return {
            "status": "success",
            "policy_id": policy_id,
            "policy_name": policy_name,
            "service_names": service_names,
            "services": resolved,
        }
    except Exception as e:
        logger.error(f"Failed to get policy services for policy {policy_id}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Installation Preview
# =============================================================================


@mcp.tool()
async def preview_install(
    adom: str,
    package: str,
    devices: list[dict[str, str]],
) -> dict[str, Any]:
    """Preview installation changes before applying.

    Shows what configuration changes would be made to devices
    without actually installing the package. Use this to verify
    changes before deployment.

    Args:
        adom: ADOM name
        package: Policy package name (optional, preview device settings if None)
        devices: Target devices [{"name": "FGT1", "vdom": "root"}, ...]

    Returns:
        dict: Preview result with keys:
            - status: "success" or "error"
            - task_id: Task ID for retrieving preview results
            - message: Status or error message

    Example:
        >>> # Start preview
        >>> result = await preview_install(
        ...     adom="root",
        ...     package="default",
        ...     devices=[{"name": "FGT-HQ", "vdom": "root"}]
        ... )
        >>> # Wait for preview to complete, then get results
        >>> if result["status"] == "success":
        ...     from fortimanager_mcp.tools.system_tools import wait_for_task
        ...     await wait_for_task(result["task_id"])
        ...     preview = await get_preview_result(...)
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        # Capture the package revision BEFORE submitting the preview (#25):
        # if the package changes between this read and the preview task's own
        # read, the recorded revision is older and the install gate fails
        # safe (forces a re-preview) instead of passing a stale one. None
        # (fetch failed / field absent) degrades the gate to TTL + single-use.
        revision = await package_revision(client, adom, package)

        result = await spawn_guarded(
            "preview_install",
            lambda: client.install_preview(
                adom=adom,
                scope=devices,
                flags=["json"],
            ),
        )

        task_id = result.get("task")
        if task_id is not None:
            # Record for the preview-before-install gate: install_package
            # verifies this task finished — and the package is unchanged —
            # before installing the same target.
            record_preview(adom, package, devices, task_id, revision=revision)
        return {
            "status": "success",
            "task_id": task_id,
            "message": f"Preview started, task ID: {task_id}",
        }
    except TaskSlotsExhausted as e:
        return error_response(
            error="task_slots_exhausted",
            message=e,
            operation="preview_install",
            adom=adom,
            package=package,
        )
    except Exception as e:
        logger.error(f"Failed to start preview: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


def _redact_preview(value: Any) -> Any:
    """Run the CLI-text redactor over every string in a preview result.

    An install preview is the pending device config rendered as FortiOS CLI,
    so it carries "set psksecret ...", "set password ..." and the rest in
    clear, exactly like the revision content get_device_revision already
    redacts. This tool returned it raw (upstream #71).

    Walks the structure instead of reaching for a known key: the endpoint's
    envelope is not pinned anywhere in this repo, and redacting only the key
    we happen to expect would leak the moment FortiManager nests it
    differently. redact_config_text_secrets only rewrites lines that match
    "set <secret-directive>", so running it over an unrelated string is a
    no-op rather than damage.

    Not measured against a preview that actually contains a credential --
    that needs a pending change carrying one, which is why the finding was
    filed unmeasured. The redactor itself is pinned by its own tests.
    """
    if isinstance(value, str):
        return redact_config_text_secrets(value)
    if isinstance(value, dict):
        return {k: _redact_preview(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_preview(v) for v in value]
    return value


@mcp.tool()
async def get_preview_result(
    adom: str,
    devices: list[dict[str, str]],
) -> dict[str, Any]:
    """Get the result of an installation preview.

    Call this after preview_install() task completes to see
    the detailed configuration changes.

    Args:
        adom: ADOM name
        devices: Target devices [{"name": "FGT1", "vdom": "root"}, ...]

    Returns:
        dict: Preview results with keys:
            - status: "success" or "error"
            - preview: Preview data with configuration changes
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        client = _get_client()

        result = await client.get_preview_result(adom, devices)

        return {
            "status": "success",
            "preview": _redact_preview(result),
        }
    except Exception as e:
        logger.error(f"Failed to get preview result: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Local-In Policy Operations (FortiGate management-plane access control)
# =============================================================================
#
# Based on FNDN FortiManager 8.0.0 PM/config API specifications
# (swagger: docs/fndn/8.0.0/json_api_reference/swagger/pkg80.json,
# operations "/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy" and
# ".../local-in-policy6", definitions pm.config.firewall.local-in-policy and
# pm.config.firewall.local-in-policy6).
#
# Local-in policies control traffic destined TO the FortiGate itself --
# GUI/SSH/API/ping/SNMP access to the management plane -- which is a
# separate object space from the regular firewall/policy table above (that
# table governs traffic passing THROUGH the device). Like a firewall
# policy, a local-in policy is package-scoped and only takes effect once
# its package is installed to a device, so it reuses the exact same
# preview_install / install_package flow used for firewall policies above
# -- no separate install path exists or is needed for this object type.
#
# These tools call FortiManagerClient's generic get/add/update/delete
# methods directly (rather than adding new per-object methods to
# api/client.py), the same approach security_profile_tools.py uses to keep
# a new object surface self-contained in one file.

_LOCAL_IN_POLICY_URL = "/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy"
_LOCAL_IN_POLICY6_URL = "/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6"


def _build_local_in_policy_fields(
    action: str | None,
    status: str | None,
    intf: list[str] | None,
    srcaddr: list[str] | None,
    dstaddr: list[str] | None,
    service: list[str] | None,
    schedule: list[str] | None,
    logtraffic: str | None,
    comments: str | None,
    srcaddr_negate: bool | None,
    dstaddr_negate: bool | None,
    service_negate: bool | None,
    virtual_patch: bool | None,
) -> dict[str, Any]:
    """Build the field set shared by local-in-policy and local-in-policy6.

    Every field here is common to both `pm.config.firewall.local-in-policy`
    and `pm.config.firewall.local-in-policy6` (verified against the 8.0.0
    swagger definitions -- they differ only in `ha-mgmt-intf-only`, which is
    IPv4-only and handled by each caller separately, and in the
    `internet-service(6)-src*` fields, which are out of scope here).
    Used for both create (required fields already validated as non-None by
    the caller's signature) and update (every field optional, None = leave
    unchanged) -- shared so the two policy families and both operations
    don't each repeat the same enable/disable translation.
    """
    fields: dict[str, Any] = {}
    if action is not None:
        fields["action"] = action
    if status is not None:
        fields["status"] = status
    if intf is not None:
        fields["intf"] = intf
    if srcaddr is not None:
        fields["srcaddr"] = srcaddr
    if dstaddr is not None:
        fields["dstaddr"] = dstaddr
    if service is not None:
        fields["service"] = service
    if schedule is not None:
        fields["schedule"] = schedule
    if logtraffic is not None:
        fields["logtraffic"] = logtraffic
    if comments is not None:
        fields["comments"] = comments
    if srcaddr_negate is not None:
        fields["srcaddr-negate"] = "enable" if srcaddr_negate else "disable"
    if dstaddr_negate is not None:
        fields["dstaddr-negate"] = "enable" if dstaddr_negate else "disable"
    if service_negate is not None:
        fields["service-negate"] = "enable" if service_negate else "disable"
    if virtual_patch is not None:
        fields["virtual-patch"] = "enable" if virtual_patch else "disable"
    return fields


@mcp.tool()
async def list_local_in_policies(
    adom: str,
    package: str,
    fields: list[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """List IPv4 local-in policies in a policy package.

    Local-in policies control access to the FortiGate's own management
    plane (GUI, SSH, ping, API, SNMP, etc.), not through-traffic.

    Args:
        adom: ADOM name
        package: Policy package name
        fields: Specific fields to return (optional)
        limit: Maximum number of policies to return (optional)
        offset: Starting position for pagination (default: 0)

    Returns:
        dict: Policy list with keys:
            - status: "success" or "error"
            - count: Number of policies returned
            - total: Total number of local-in policies in package
            - policies: List of local-in policy objects
            - message: Error message if failed

    Example:
        >>> result = await list_local_in_policies("root", "default")
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        base_url = _LOCAL_IN_POLICY_URL.format(adom=adom, pkg=package)

        total = await client.get(base_url, option=["count"])
        if not isinstance(total, int):
            total = 0

        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if limit:
            params["range"] = [offset, limit]

        result = await client.get(base_url, **params)
        policies = result if isinstance(result, list) else [result] if result else []

        return {
            "status": "success",
            "count": len(policies),
            "total": total,
            "policies": policies,
        }
    except Exception as e:
        logger.error(f"Failed to list local-in policies in {package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_local_in_policy(
    adom: str,
    package: str,
    policyid: int,
) -> dict[str, Any]:
    """Get detailed information about a specific IPv4 local-in policy.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Local-in policy ID number

    Returns:
        dict: Policy details with keys:
            - status: "success" or "error"
            - policy: Full local-in policy configuration
            - message: Error message if failed

    Example:
        >>> result = await get_local_in_policy("root", "default", 1)
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        policy = await client.get(
            f"{_LOCAL_IN_POLICY_URL.format(adom=adom, pkg=package)}/{policyid}"
        )

        return {
            "status": "success",
            "policy": policy,
        }
    except Exception as e:
        logger.error(f"Failed to get local-in policy {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_local_in_policy(
    adom: str,
    package: str,
    intf: list[str],
    srcaddr: list[str],
    dstaddr: list[str],
    service: list[str],
    action: str = "deny",
    schedule: list[str] | None = None,
    status: str = "enable",
    logtraffic: str | None = None,
    comments: str | None = None,
    policyid: int | None = None,
    srcaddr_negate: bool | None = None,
    dstaddr_negate: bool | None = None,
    service_negate: bool | None = None,
    ha_mgmt_intf_only: bool | None = None,
    virtual_patch: bool | None = None,
) -> dict[str, Any]:
    """Create a new IPv4 local-in policy.

    Local-in policies control traffic destined to the FortiGate's own
    management plane (GUI, SSH, ping, API, SNMP, etc.) -- a distinct object
    space from the regular firewall/policy table (create_firewall_policy),
    which governs traffic passing through the device. There is no
    srcintf/dstintf pair here: `intf` is the single incoming interface,
    since local-in traffic terminates on the FortiGate itself rather than
    being forwarded. A local-in policy only takes effect once its package
    is installed to a device (see preview_install / install_package).

    Args:
        adom: ADOM name
        package: Policy package name
        intf: Incoming interface(s) this policy applies to, e.g. ["port1"]
        srcaddr: Source addresses this policy matches (e.g. ["Admin-Subnet"])
        dstaddr: Destination addresses on the FortiGate itself (e.g. ["all"])
        service: Services this policy matches, e.g. ["HTTPS", "SSH"]
        action: Policy action - "accept" or "deny" (default: "deny", the
            FortiOS field default -- unlike create_firewall_policy this
            defaults closed since it governs management-plane access)
        schedule: Schedule object name(s) (default: ["always"] if omitted)
        status: Policy status - "enable" or "disable" (default: "enable")
        logtraffic: Local-in traffic logging - "enable" or "disable"
            (optional)
        comments: Policy comments (optional)
        policyid: Specific policy ID (optional, auto-assigned if not set)
        srcaddr_negate: Match all sources EXCEPT srcaddr (optional)
        dstaddr_negate: Match all destinations EXCEPT dstaddr (optional)
        service_negate: Match all services EXCEPT service (optional)
        ha_mgmt_intf_only: Restrict this policy to the HA management
            interface only (optional). IPv4-only field -- there is no
            equivalent on create_local_in_policy6.
        virtual_patch: Enable/disable virtual patching on this policy
            (optional)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - policyid: Created policy ID
            - message: Status or error message

    Example:
        >>> result = await create_local_in_policy(
        ...     adom="root",
        ...     package="default",
        ...     intf=["port1"],
        ...     srcaddr=["Admin-Subnet"],
        ...     dstaddr=["all"],
        ...     service=["HTTPS", "SSH"],
        ...     action="accept",
        ... )
    """
    safety_warning = None
    safety_result = check_policy_safety(
        srcaddr,
        dstaddr,
        service,
        action,
        srcaddr_negate=bool(srcaddr_negate),
        dstaddr_negate=bool(dstaddr_negate),
        service_negate=bool(service_negate),
    )
    if safety_result:
        if safety_result.get("status") == "error":
            return safety_result
        safety_warning = safety_result.get("_safety_warning")

    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        policy: dict[str, Any] = _build_local_in_policy_fields(
            action=action,
            status=status,
            intf=intf,
            srcaddr=srcaddr,
            dstaddr=dstaddr,
            service=service,
            schedule=schedule if schedule is not None else ["always"],
            logtraffic=logtraffic,
            comments=comments,
            srcaddr_negate=srcaddr_negate,
            dstaddr_negate=dstaddr_negate,
            service_negate=service_negate,
            virtual_patch=virtual_patch,
        )
        if policyid is not None:
            policy["policyid"] = policyid
        if ha_mgmt_intf_only is not None:
            policy["ha-mgmt-intf-only"] = "enable" if ha_mgmt_intf_only else "disable"

        result = await client.add(
            _LOCAL_IN_POLICY_URL.format(adom=adom, pkg=package),
            data=policy,
        )

        response = {
            "status": "success",
            "policyid": result.get("policyid", policyid),
            "message": "Local-in policy created successfully",
        }
        if safety_warning:
            response["warning"] = safety_warning
        return response
    except Exception as e:
        logger.error(f"Failed to create local-in policy: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_local_in_policy(
    adom: str,
    package: str,
    policyid: int,
    action: str | None = None,
    intf: list[str] | None = None,
    srcaddr: list[str] | None = None,
    dstaddr: list[str] | None = None,
    service: list[str] | None = None,
    schedule: list[str] | None = None,
    status: str | None = None,
    logtraffic: str | None = None,
    comments: str | None = None,
    srcaddr_negate: bool | None = None,
    dstaddr_negate: bool | None = None,
    service_negate: bool | None = None,
    ha_mgmt_intf_only: bool | None = None,
    virtual_patch: bool | None = None,
) -> dict[str, Any]:
    """Update an existing IPv4 local-in policy.

    Only the specified fields will be updated; other fields remain
    unchanged.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Local-in policy ID to update
        action: New action - "accept" or "deny" (optional)
        intf: New incoming interface(s) (optional)
        srcaddr: New source addresses (optional)
        dstaddr: New destination addresses (optional)
        service: New services (optional)
        schedule: New schedule (optional)
        status: New status - "enable" or "disable" (optional)
        logtraffic: New local-in traffic logging setting (optional)
        comments: New comments (optional)
        srcaddr_negate: Match all sources EXCEPT srcaddr (optional)
        dstaddr_negate: Match all destinations EXCEPT dstaddr (optional)
        service_negate: Match all services EXCEPT service (optional)
        ha_mgmt_intf_only: Restrict this policy to the HA management
            interface only (optional). IPv4-only field.
        virtual_patch: Enable/disable virtual patching on this policy
            (optional)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - policyid: Updated policy ID
            - message: Status or error message

    Example:
        >>> # Disable a local-in policy
        >>> result = await update_local_in_policy(
        ...     adom="root",
        ...     package="default",
        ...     policyid=1,
        ...     status="disable"
        ... )
    """
    safety_warning = None
    full_check = srcaddr is not None and dstaddr is not None and action is not None
    safety_result = check_policy_safety(
        srcaddr if full_check else None,
        dstaddr if full_check else None,
        service if full_check else None,
        action if full_check else None,
        srcaddr_negate=bool(srcaddr_negate),
        dstaddr_negate=bool(dstaddr_negate),
        service_negate=bool(service_negate),
    )
    if safety_result:
        if safety_result.get("status") == "error":
            return safety_result
        safety_warning = safety_result.get("_safety_warning")

    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        data = _build_local_in_policy_fields(
            action=action,
            status=status,
            intf=intf,
            srcaddr=srcaddr,
            dstaddr=dstaddr,
            service=service,
            schedule=schedule,
            logtraffic=logtraffic,
            comments=comments,
            srcaddr_negate=srcaddr_negate,
            dstaddr_negate=dstaddr_negate,
            service_negate=service_negate,
            virtual_patch=virtual_patch,
        )
        if ha_mgmt_intf_only is not None:
            data["ha-mgmt-intf-only"] = "enable" if ha_mgmt_intf_only else "disable"

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update(
            f"{_LOCAL_IN_POLICY_URL.format(adom=adom, pkg=package)}/{policyid}",
            **data,
        )

        response = {
            "status": "success",
            "policyid": policyid,
            "message": f"Local-in policy {policyid} updated successfully",
        }
        if safety_warning:
            response["warning"] = safety_warning
        return response
    except Exception as e:
        logger.error(f"Failed to update local-in policy {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_local_in_policy(
    adom: str,
    package: str,
    policyid: int,
) -> dict[str, Any]:
    """Delete an IPv4 local-in policy.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Local-in policy ID to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        await client.delete(f"{_LOCAL_IN_POLICY_URL.format(adom=adom, pkg=package)}/{policyid}")

        return {
            "status": "success",
            "message": f"Local-in policy {policyid} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete local-in policy {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def list_local_in_policies6(
    adom: str,
    package: str,
    fields: list[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """List IPv6 local-in policies in a policy package.

    Local-in policies control access to the FortiGate's own management
    plane (GUI, SSH, ping, API, SNMP, etc.) over IPv6, not through-traffic.

    Args:
        adom: ADOM name
        package: Policy package name
        fields: Specific fields to return (optional)
        limit: Maximum number of policies to return (optional)
        offset: Starting position for pagination (default: 0)

    Returns:
        dict: Policy list with keys:
            - status: "success" or "error"
            - count: Number of policies returned
            - total: Total number of local-in policies6 in package
            - policies: List of local-in policy6 objects
            - message: Error message if failed

    Example:
        >>> result = await list_local_in_policies6("root", "default")
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        base_url = _LOCAL_IN_POLICY6_URL.format(adom=adom, pkg=package)

        total = await client.get(base_url, option=["count"])
        if not isinstance(total, int):
            total = 0

        params: dict[str, Any] = {}
        if fields:
            params["fields"] = fields
        if limit:
            params["range"] = [offset, limit]

        result = await client.get(base_url, **params)
        policies = result if isinstance(result, list) else [result] if result else []

        return {
            "status": "success",
            "count": len(policies),
            "total": total,
            "policies": policies,
        }
    except Exception as e:
        logger.error(f"Failed to list local-in policies6 in {package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_local_in_policy6(
    adom: str,
    package: str,
    policyid: int,
) -> dict[str, Any]:
    """Get detailed information about a specific IPv6 local-in policy.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Local-in policy6 ID number

    Returns:
        dict: Policy details with keys:
            - status: "success" or "error"
            - policy: Full local-in policy6 configuration
            - message: Error message if failed

    Example:
        >>> result = await get_local_in_policy6("root", "default", 1)
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        policy = await client.get(
            f"{_LOCAL_IN_POLICY6_URL.format(adom=adom, pkg=package)}/{policyid}"
        )

        return {
            "status": "success",
            "policy": policy,
        }
    except Exception as e:
        logger.error(f"Failed to get local-in policy6 {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_local_in_policy6(
    adom: str,
    package: str,
    intf: list[str],
    srcaddr: list[str],
    dstaddr: list[str],
    service: list[str],
    action: str = "deny",
    schedule: list[str] | None = None,
    status: str = "enable",
    logtraffic: str | None = None,
    comments: str | None = None,
    policyid: int | None = None,
    srcaddr_negate: bool | None = None,
    dstaddr_negate: bool | None = None,
    service_negate: bool | None = None,
    virtual_patch: bool | None = None,
) -> dict[str, Any]:
    """Create a new IPv6 local-in policy.

    IPv6 counterpart of create_local_in_policy -- see that tool's docstring
    for the local-in-policy concept. `srcaddr`/`dstaddr` reference IPv6
    address objects here. There is no `ha_mgmt_intf_only` field on this
    object type (it is IPv4-only on the appliance).

    Args:
        adom: ADOM name
        package: Policy package name
        intf: Incoming interface(s) this policy applies to, e.g. ["port1"]
        srcaddr: Source IPv6 addresses this policy matches
        dstaddr: Destination IPv6 addresses on the FortiGate itself
            (e.g. ["all"])
        service: Services this policy matches, e.g. ["HTTPS", "SSH"]
        action: Policy action - "accept" or "deny" (default: "deny", the
            FortiOS field default)
        schedule: Schedule object name(s) (default: ["always"] if omitted)
        status: Policy status - "enable" or "disable" (default: "enable")
        logtraffic: Local-in traffic logging - "enable" or "disable"
            (optional)
        comments: Policy comments (optional)
        policyid: Specific policy ID (optional, auto-assigned if not set)
        srcaddr_negate: Match all sources EXCEPT srcaddr (optional)
        dstaddr_negate: Match all destinations EXCEPT dstaddr (optional)
        service_negate: Match all services EXCEPT service (optional)
        virtual_patch: Enable/disable virtual patching on this policy
            (optional)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - policyid: Created policy ID
            - message: Status or error message

    Example:
        >>> result = await create_local_in_policy6(
        ...     adom="root",
        ...     package="default",
        ...     intf=["port1"],
        ...     srcaddr=["Admin-Subnet-v6"],
        ...     dstaddr=["all"],
        ...     service=["HTTPS", "SSH"],
        ...     action="accept",
        ... )
    """
    safety_warning = None
    safety_result = check_policy_safety(
        srcaddr,
        dstaddr,
        service,
        action,
        srcaddr_negate=bool(srcaddr_negate),
        dstaddr_negate=bool(dstaddr_negate),
        service_negate=bool(service_negate),
    )
    if safety_result:
        if safety_result.get("status") == "error":
            return safety_result
        safety_warning = safety_result.get("_safety_warning")

    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        policy: dict[str, Any] = _build_local_in_policy_fields(
            action=action,
            status=status,
            intf=intf,
            srcaddr=srcaddr,
            dstaddr=dstaddr,
            service=service,
            schedule=schedule if schedule is not None else ["always"],
            logtraffic=logtraffic,
            comments=comments,
            srcaddr_negate=srcaddr_negate,
            dstaddr_negate=dstaddr_negate,
            service_negate=service_negate,
            virtual_patch=virtual_patch,
        )
        if policyid is not None:
            policy["policyid"] = policyid

        result = await client.add(
            _LOCAL_IN_POLICY6_URL.format(adom=adom, pkg=package),
            data=policy,
        )

        response = {
            "status": "success",
            "policyid": result.get("policyid", policyid),
            "message": "Local-in policy6 created successfully",
        }
        if safety_warning:
            response["warning"] = safety_warning
        return response
    except Exception as e:
        logger.error(f"Failed to create local-in policy6: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_local_in_policy6(
    adom: str,
    package: str,
    policyid: int,
    action: str | None = None,
    intf: list[str] | None = None,
    srcaddr: list[str] | None = None,
    dstaddr: list[str] | None = None,
    service: list[str] | None = None,
    schedule: list[str] | None = None,
    status: str | None = None,
    logtraffic: str | None = None,
    comments: str | None = None,
    srcaddr_negate: bool | None = None,
    dstaddr_negate: bool | None = None,
    service_negate: bool | None = None,
    virtual_patch: bool | None = None,
) -> dict[str, Any]:
    """Update an existing IPv6 local-in policy.

    Only the specified fields will be updated; other fields remain
    unchanged.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Local-in policy6 ID to update
        action: New action - "accept" or "deny" (optional)
        intf: New incoming interface(s) (optional)
        srcaddr: New source IPv6 addresses (optional)
        dstaddr: New destination IPv6 addresses (optional)
        service: New services (optional)
        schedule: New schedule (optional)
        status: New status - "enable" or "disable" (optional)
        logtraffic: New local-in traffic logging setting (optional)
        comments: New comments (optional)
        srcaddr_negate: Match all sources EXCEPT srcaddr (optional)
        dstaddr_negate: Match all destinations EXCEPT dstaddr (optional)
        service_negate: Match all services EXCEPT service (optional)
        virtual_patch: Enable/disable virtual patching on this policy
            (optional)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - policyid: Updated policy ID
            - message: Status or error message

    Example:
        >>> result = await update_local_in_policy6(
        ...     adom="root",
        ...     package="default",
        ...     policyid=1,
        ...     status="disable"
        ... )
    """
    safety_warning = None
    full_check = srcaddr is not None and dstaddr is not None and action is not None
    safety_result = check_policy_safety(
        srcaddr if full_check else None,
        dstaddr if full_check else None,
        service if full_check else None,
        action if full_check else None,
        srcaddr_negate=bool(srcaddr_negate),
        dstaddr_negate=bool(dstaddr_negate),
        service_negate=bool(service_negate),
    )
    if safety_result:
        if safety_result.get("status") == "error":
            return safety_result
        safety_warning = safety_result.get("_safety_warning")

    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()

        data = _build_local_in_policy_fields(
            action=action,
            status=status,
            intf=intf,
            srcaddr=srcaddr,
            dstaddr=dstaddr,
            service=service,
            schedule=schedule,
            logtraffic=logtraffic,
            comments=comments,
            srcaddr_negate=srcaddr_negate,
            dstaddr_negate=dstaddr_negate,
            service_negate=service_negate,
            virtual_patch=virtual_patch,
        )

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update(
            f"{_LOCAL_IN_POLICY6_URL.format(adom=adom, pkg=package)}/{policyid}",
            **data,
        )

        response = {
            "status": "success",
            "policyid": policyid,
            "message": f"Local-in policy6 {policyid} updated successfully",
        }
        if safety_warning:
            response["warning"] = safety_warning
        return response
    except Exception as e:
        logger.error(f"Failed to update local-in policy6 {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_local_in_policy6(
    adom: str,
    package: str,
    policyid: int,
) -> dict[str, Any]:
    """Delete an IPv6 local-in policy.

    WARNING: This operation cannot be undone.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Local-in policy6 ID to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        client = _get_client()
        await client.delete(f"{_LOCAL_IN_POLICY6_URL.format(adom=adom, pkg=package)}/{policyid}")

        return {
            "status": "success",
            "message": f"Local-in policy6 {policyid} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete local-in policy6 {policyid}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
