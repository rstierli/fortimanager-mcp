"""Policy and package management tools for FortiManager.

Based on FNDN FortiManager 7.6.5 PM and Security Console API specifications.
Provides policy package management, firewall policy CRUD operations,
and installation operations.
"""

import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp

logger = logging.getLogger(__name__)


def _get_client():
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


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
        return {"status": "error", "message": str(e)}


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
        client = _get_client()
        await client.delete_package(adom, package)

        return {
            "status": "success",
            "message": f"Package {package} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete package {package}: {e}")
        return {"status": "error", "message": str(e)}


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
        client = _get_client()
        await client.clone_package(adom, package, new_name)

        return {
            "status": "success",
            "package": new_name,
            "message": f"Package {package} cloned to {new_name}",
        }
    except Exception as e:
        logger.error(f"Failed to clone package {package}: {e}")
        return {"status": "error", "message": str(e)}


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
        client = _get_client()
        await client.assign_package(adom, package, devices)

        return {
            "status": "success",
            "message": f"Package {package} assigned to {len(devices)} device(s)",
        }
    except Exception as e:
        logger.error(f"Failed to assign package {package}: {e}")
        return {"status": "error", "message": str(e)}


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
        return {"status": "error", "message": str(e)}


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
        client = _get_client()
        policy = await client.get_firewall_policy(adom, package, policyid)

        return {
            "status": "success",
            "policy": policy,
        }
    except Exception as e:
        logger.error(f"Failed to get policy {policyid}: {e}")
        return {"status": "error", "message": str(e)}


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
        ...     nat=True
        ... )
    """
    try:
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

        result = await client.create_firewall_policy(adom, package, policy)

        return {
            "status": "success",
            "policyid": result.get("policyid", policyid),
            "message": f"Policy {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create policy {name}: {e}")
        return {"status": "error", "message": str(e)}


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
    try:
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

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_firewall_policy(adom, package, policyid, data)

        return {
            "status": "success",
            "policyid": policyid,
            "message": f"Policy {policyid} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update policy {policyid}: {e}")
        return {"status": "error", "message": str(e)}


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
        client = _get_client()
        await client.delete_firewall_policy(adom, package, policyid)

        return {
            "status": "success",
            "message": f"Policy {policyid} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete policy {policyid}: {e}")
        return {"status": "error", "message": str(e)}


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
            - status: "success" or "error"
            - deleted_count: Number of policies deleted
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

        client = _get_client()
        await client.delete_firewall_policies(adom, package, policyids)

        return {
            "status": "success",
            "deleted_count": len(policyids),
            "message": f"Deleted {len(policyids)} policies",
        }
    except Exception as e:
        logger.error(f"Failed to delete policies: {e}")
        return {"status": "error", "message": str(e)}


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
        client = _get_client()
        await client.move_firewall_policy(adom, package, policyid, target_policyid, position)

        return {
            "status": "success",
            "message": f"Policy {policyid} moved {position} policy {target_policyid}",
        }
    except Exception as e:
        logger.error(f"Failed to move policy {policyid}: {e}")
        return {"status": "error", "message": str(e)}


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
        return {"status": "error", "message": str(e)}


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
        client = _get_client()

        result = await client.install_preview(
            adom=adom,
            scope=devices,
            flags=["json"],
        )

        task_id = result.get("task")
        return {
            "status": "success",
            "task_id": task_id,
            "message": f"Preview started, task ID: {task_id}",
        }
    except Exception as e:
        logger.error(f"Failed to start preview: {e}")
        return {"status": "error", "message": str(e)}


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
        client = _get_client()

        result = await client.get_preview_result(adom, devices)

        return {
            "status": "success",
            "preview": result,
        }
    except Exception as e:
        logger.error(f"Failed to get preview result: {e}")
        return {"status": "error", "message": str(e)}
