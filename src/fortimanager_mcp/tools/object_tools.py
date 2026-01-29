"""Firewall object management tools for FortiManager.

Based on FNDN FortiManager 7.6.5 PM/config API specifications.
Provides CRUD operations for firewall objects including:
- Address objects (host, subnet, FQDN, range)
- Address groups
- Service objects
- Service groups
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


# =============================================================================
# Address Objects
# =============================================================================


@mcp.tool()
async def list_addresses(
    adom: str | None = None,
    name_filter: str | None = None,
    type_filter: str | None = None,
) -> dict[str, Any]:
    """List firewall address objects in an ADOM.

    Address objects define network entities (hosts, subnets, FQDNs)
    used in firewall policies.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)
        type_filter: Filter by type ("ipmask", "fqdn", "iprange", "wildcard")

    Returns:
        dict: Address list with keys:
            - status: "success" or "error"
            - count: Number of addresses
            - addresses: List of address objects
            - message: Error message if failed

    Example:
        >>> # List all addresses
        >>> result = await list_addresses("root")

        >>> # Find FQDN addresses
        >>> result = await list_addresses("root", type_filter="fqdn")
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])
        if type_filter:
            filters.append(["type", "==", type_filter])

        addresses = await client.list_addresses(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(addresses),
            "addresses": addresses,
        }
    except Exception as e:
        logger.error(f"Failed to list addresses: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_address(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about a firewall address object.

    Args:
        adom: ADOM name
        name: Address object name

    Returns:
        dict: Address details with keys:
            - status: "success" or "error"
            - address: Full address configuration
            - message: Error message if failed
    """
    try:
        client = _get_client()
        address = await client.get_address(adom, name)

        return {
            "status": "success",
            "address": address,
        }
    except Exception as e:
        logger.error(f"Failed to get address {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_address_subnet(
    adom: str,
    name: str,
    subnet: str,
    comment: str | None = None,
) -> dict[str, Any]:
    """Create a subnet/network address object.

    Args:
        adom: ADOM name
        name: Address object name
        subnet: IP/netmask (e.g., "10.0.0.0/24" or "10.0.0.0 255.255.255.0")
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created address name
            - message: Status or error message

    Example:
        >>> result = await create_address_subnet(
        ...     adom="root",
        ...     name="LAN-Subnet",
        ...     subnet="192.168.1.0/24",
        ...     comment="Local network"
        ... )
    """
    try:
        client = _get_client()

        # Parse subnet - handle both CIDR and space-separated formats
        if "/" in subnet:
            ip, prefix = subnet.split("/")
            # Convert CIDR to netmask
            prefix_int = int(prefix)
            netmask = ".".join(
                [str((0xFFFFFFFF << (32 - prefix_int) >> i) & 0xFF) for i in [24, 16, 8, 0]]
            )
            subnet_value = [ip, netmask]
        elif " " in subnet:
            subnet_value = subnet.split()
        else:
            # Assume single host
            subnet_value = [subnet, "255.255.255.255"]

        address: dict[str, Any] = {
            "name": name,
            "type": "ipmask",
            "subnet": subnet_value,
        }

        if comment:
            address["comment"] = comment

        await client.create_address(adom, address)

        return {
            "status": "success",
            "name": name,
            "message": f"Address {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create address {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_address_host(
    adom: str,
    name: str,
    ip: str,
    comment: str | None = None,
) -> dict[str, Any]:
    """Create a host address object (single IP).

    Args:
        adom: ADOM name
        name: Address object name
        ip: Host IP address (e.g., "10.0.0.100")
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created address name
            - message: Status or error message

    Example:
        >>> result = await create_address_host(
        ...     adom="root",
        ...     name="WebServer",
        ...     ip="192.168.1.100",
        ...     comment="Production web server"
        ... )
    """
    try:
        client = _get_client()

        address: dict[str, Any] = {
            "name": name,
            "type": "ipmask",
            "subnet": [ip, "255.255.255.255"],
        }

        if comment:
            address["comment"] = comment

        await client.create_address(adom, address)

        return {
            "status": "success",
            "name": name,
            "message": f"Host address {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create host address {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_address_fqdn(
    adom: str,
    name: str,
    fqdn: str,
    comment: str | None = None,
) -> dict[str, Any]:
    """Create an FQDN (Fully Qualified Domain Name) address object.

    FQDN addresses are resolved dynamically by FortiGate.

    Args:
        adom: ADOM name
        name: Address object name
        fqdn: Domain name (e.g., "www.example.com")
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created address name
            - message: Status or error message

    Example:
        >>> result = await create_address_fqdn(
        ...     adom="root",
        ...     name="Google-DNS",
        ...     fqdn="dns.google.com"
        ... )
    """
    try:
        client = _get_client()

        address: dict[str, Any] = {
            "name": name,
            "type": "fqdn",
            "fqdn": fqdn,
        }

        if comment:
            address["comment"] = comment

        await client.create_address(adom, address)

        return {
            "status": "success",
            "name": name,
            "message": f"FQDN address {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create FQDN address {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_address_range(
    adom: str,
    name: str,
    start_ip: str,
    end_ip: str,
    comment: str | None = None,
) -> dict[str, Any]:
    """Create an IP range address object.

    Args:
        adom: ADOM name
        name: Address object name
        start_ip: Start IP address
        end_ip: End IP address
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created address name
            - message: Status or error message

    Example:
        >>> result = await create_address_range(
        ...     adom="root",
        ...     name="DHCP-Pool",
        ...     start_ip="192.168.1.100",
        ...     end_ip="192.168.1.200"
        ... )
    """
    try:
        client = _get_client()

        address: dict[str, Any] = {
            "name": name,
            "type": "iprange",
            "start-ip": start_ip,
            "end-ip": end_ip,
        }

        if comment:
            address["comment"] = comment

        await client.create_address(adom, address)

        return {
            "status": "success",
            "name": name,
            "message": f"IP range address {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create IP range address {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def update_address(
    adom: str,
    name: str,
    new_name: str | None = None,
    subnet: str | None = None,
    fqdn: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Update an existing address object.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: Current address name
        new_name: New name (optional)
        subnet: New subnet for ipmask type (optional)
        fqdn: New FQDN for fqdn type (optional)
        comment: New comment (optional)

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()

        data: dict[str, Any] = {}

        if new_name:
            data["name"] = new_name
        if subnet:
            if "/" in subnet:
                ip, prefix = subnet.split("/")
                prefix_int = int(prefix)
                netmask = ".".join(
                    [str((0xFFFFFFFF << (32 - prefix_int) >> i) & 0xFF) for i in [24, 16, 8, 0]]
                )
                data["subnet"] = [ip, netmask]
            else:
                data["subnet"] = subnet.split()
        if fqdn:
            data["fqdn"] = fqdn
        if comment is not None:
            data["comment"] = comment

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_address(adom, name, data)

        return {
            "status": "success",
            "message": f"Address {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update address {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_address(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a firewall address object.

    WARNING: This will fail if the address is in use by policies or groups.

    Args:
        adom: ADOM name
        name: Address object name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()
        await client.delete_address(adom, name)

        return {
            "status": "success",
            "message": f"Address {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete address {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Address Groups
# =============================================================================


@mcp.tool()
async def list_address_groups(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List firewall address groups in an ADOM.

    Address groups contain multiple address objects for easier
    policy management.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Group list with keys:
            - status: "success" or "error"
            - count: Number of groups
            - groups: List of address group objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])

        groups = await client.list_address_groups(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(groups),
            "groups": groups,
        }
    except Exception as e:
        logger.error(f"Failed to list address groups: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_address_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about an address group.

    Args:
        adom: ADOM name
        name: Address group name

    Returns:
        dict: Group details with keys:
            - status: "success" or "error"
            - group: Full group configuration including members
            - message: Error message if failed
    """
    try:
        client = _get_client()
        group = await client.get_address_group(adom, name)

        return {
            "status": "success",
            "group": group,
        }
    except Exception as e:
        logger.error(f"Failed to get address group {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_address_group(
    adom: str,
    name: str,
    members: list[str],
    comment: str | None = None,
) -> dict[str, Any]:
    """Create an address group.

    Args:
        adom: ADOM name
        name: Group name
        members: List of address object names to include
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created group name
            - message: Status or error message

    Example:
        >>> result = await create_address_group(
        ...     adom="root",
        ...     name="Web-Servers",
        ...     members=["WebServer1", "WebServer2", "WebServer3"],
        ...     comment="Production web servers"
        ... )
    """
    try:
        client = _get_client()

        group: dict[str, Any] = {
            "name": name,
            "member": members,
        }

        if comment:
            group["comment"] = comment

        await client.create_address_group(adom, group)

        return {
            "status": "success",
            "name": name,
            "message": f"Address group {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create address group {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def update_address_group(
    adom: str,
    name: str,
    members: list[str] | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Update an address group.

    Args:
        adom: ADOM name
        name: Group name
        members: New member list (replaces existing)
        comment: New comment

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()

        data: dict[str, Any] = {}
        if members is not None:
            data["member"] = members
        if comment is not None:
            data["comment"] = comment

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_address_group(adom, name, data)

        return {
            "status": "success",
            "message": f"Address group {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update address group {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_address_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete an address group.

    WARNING: This will fail if the group is in use by policies.

    Args:
        adom: ADOM name
        name: Group name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()
        await client.delete_address_group(adom, name)

        return {
            "status": "success",
            "message": f"Address group {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete address group {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Service Objects
# =============================================================================


@mcp.tool()
async def list_services(
    adom: str | None = None,
    name_filter: str | None = None,
    protocol_filter: str | None = None,
) -> dict[str, Any]:
    """List custom service objects in an ADOM.

    Service objects define network protocols and ports used in policies.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)
        protocol_filter: Filter by protocol ("TCP/UDP/SCTP", "ICMP", "IP")

    Returns:
        dict: Service list with keys:
            - status: "success" or "error"
            - count: Number of services
            - services: List of service objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])
        if protocol_filter:
            filters.append(["protocol", "==", protocol_filter])

        services = await client.list_services(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(services),
            "services": services,
        }
    except Exception as e:
        logger.error(f"Failed to list services: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_service(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about a service object.

    Args:
        adom: ADOM name
        name: Service object name

    Returns:
        dict: Service details with keys:
            - status: "success" or "error"
            - service: Full service configuration
            - message: Error message if failed
    """
    try:
        client = _get_client()
        service = await client.get_service(adom, name)

        return {
            "status": "success",
            "service": service,
        }
    except Exception as e:
        logger.error(f"Failed to get service {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_service_tcp_udp(
    adom: str,
    name: str,
    tcp_portrange: str | None = None,
    udp_portrange: str | None = None,
    sctp_portrange: str | None = None,
    udplite_portrange: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Create a TCP/UDP/SCTP/UDP-Lite service object.

    Args:
        adom: ADOM name
        name: Service object name
        tcp_portrange: TCP port range (e.g., "80", "8080-8090", "80 443 8080")
        udp_portrange: UDP port range (e.g., "53", "500-502")
        sctp_portrange: SCTP port range (e.g., "3868", "2905-2907")
        udplite_portrange: UDP-Lite port range (e.g., "1234")
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created service name
            - message: Status or error message

    Example:
        >>> # Create HTTP/HTTPS service
        >>> result = await create_service_tcp_udp(
        ...     adom="root",
        ...     name="Custom-Web",
        ...     tcp_portrange="80 443 8080",
        ...     comment="Custom web ports"
        ... )

        >>> # Create DNS service
        >>> result = await create_service_tcp_udp(
        ...     adom="root",
        ...     name="Custom-DNS",
        ...     tcp_portrange="53",
        ...     udp_portrange="53"
        ... )

        >>> # Create SCTP service (Diameter)
        >>> result = await create_service_tcp_udp(
        ...     adom="root",
        ...     name="Diameter",
        ...     sctp_portrange="3868",
        ...     comment="Diameter protocol"
        ... )
    """
    try:
        if not any([tcp_portrange, udp_portrange, sctp_portrange, udplite_portrange]):
            return {"status": "error", "message": "At least one port range required"}

        client = _get_client()

        # FMG protocol field = service TYPE category, not IP protocol number
        # 15 = TCP/UDP/SCTP service type (covers all port-based services)
        # The actual protocol is determined by which portrange fields are set
        # Verified: TFTP (UDP-only, port 69) uses protocol=15 with empty tcp-portrange
        protocol = 15

        service: dict[str, Any] = {
            "name": name,
            "protocol": protocol,
        }
        # Only include portrange fields if they have values
        # GUI sends null for unused ranges, we simply omit them
        if tcp_portrange:
            service["tcp-portrange"] = tcp_portrange
        if udp_portrange:
            service["udp-portrange"] = udp_portrange
        if sctp_portrange:
            service["sctp-portrange"] = sctp_portrange
        if udplite_portrange:
            service["udplite-portrange"] = udplite_portrange

        if comment:
            service["comment"] = comment

        await client.create_service(adom, service)

        return {
            "status": "success",
            "name": name,
            "message": f"Service {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create service {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_service_icmp(
    adom: str,
    name: str,
    icmp_type: int | None = None,
    icmp_code: int | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Create an ICMP service object.

    Args:
        adom: ADOM name
        name: Service object name
        icmp_type: ICMP type (0-255, optional for all types)
        icmp_code: ICMP code (0-255, optional)
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created service name
            - message: Status or error message

    Example:
        >>> # Create ping service (ICMP echo request)
        >>> result = await create_service_icmp(
        ...     adom="root",
        ...     name="Custom-Ping",
        ...     icmp_type=8,
        ...     comment="ICMP Echo Request"
        ... )
    """
    try:
        client = _get_client()

        service: dict[str, Any] = {
            "name": name,
            "protocol": "ICMP",
        }

        if icmp_type is not None:
            service["icmptype"] = icmp_type
        if icmp_code is not None:
            service["icmpcode"] = icmp_code
        if comment:
            service["comment"] = comment

        await client.create_service(adom, service)

        return {
            "status": "success",
            "name": name,
            "message": f"ICMP service {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create ICMP service {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def update_service(
    adom: str,
    name: str,
    tcp_portrange: str | None = None,
    udp_portrange: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Update a service object.

    Args:
        adom: ADOM name
        name: Service name
        tcp_portrange: New TCP port range
        udp_portrange: New UDP port range
        comment: New comment

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()

        data: dict[str, Any] = {}
        if tcp_portrange is not None:
            data["tcp-portrange"] = tcp_portrange
        if udp_portrange is not None:
            data["udp-portrange"] = udp_portrange
        if comment is not None:
            data["comment"] = comment

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_service(adom, name, data)

        return {
            "status": "success",
            "message": f"Service {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update service {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_service(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a service object.

    WARNING: This will fail if the service is in use by policies.

    Args:
        adom: ADOM name
        name: Service name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()
        await client.delete_service(adom, name)

        return {
            "status": "success",
            "message": f"Service {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete service {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Service Groups
# =============================================================================


@mcp.tool()
async def list_service_groups(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List service groups in an ADOM.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Group list with keys:
            - status: "success" or "error"
            - count: Number of groups
            - groups: List of service group objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])

        groups = await client.list_service_groups(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(groups),
            "groups": groups,
        }
    except Exception as e:
        logger.error(f"Failed to list service groups: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_service_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about a service group.

    Args:
        adom: ADOM name
        name: Service group name

    Returns:
        dict: Group details with keys:
            - status: "success" or "error"
            - group: Full group configuration including members
            - message: Error message if failed
    """
    try:
        client = _get_client()
        group = await client.get_service_group(adom, name)

        return {
            "status": "success",
            "group": group,
        }
    except Exception as e:
        logger.error(f"Failed to get service group {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def create_service_group(
    adom: str,
    name: str,
    members: list[str],
    comment: str | None = None,
) -> dict[str, Any]:
    """Create a service group.

    Args:
        adom: ADOM name
        name: Group name
        members: List of service names to include
        comment: Optional comment

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created group name
            - message: Status or error message

    Example:
        >>> result = await create_service_group(
        ...     adom="root",
        ...     name="Web-Services",
        ...     members=["HTTP", "HTTPS", "DNS"],
        ...     comment="Common web services"
        ... )
    """
    try:
        client = _get_client()

        group: dict[str, Any] = {
            "name": name,
            "member": members,
        }

        if comment:
            group["comment"] = comment

        await client.create_service_group(adom, group)

        return {
            "status": "success",
            "name": name,
            "message": f"Service group {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create service group {name}: {e}")
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def delete_service_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a service group.

    WARNING: This will fail if the group is in use by policies.

    Args:
        adom: ADOM name
        name: Group name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        client = _get_client()
        await client.delete_service_group(adom, name)

        return {
            "status": "success",
            "message": f"Service group {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete service group {name}: {e}")
        return {"status": "error", "message": str(e)}


# =============================================================================
# Search Operations
# =============================================================================


@mcp.tool()
async def search_objects(
    adom: str,
    search_term: str,
) -> dict[str, Any]:
    """Search across all firewall objects by name.

    Searches addresses, address groups, services, and service groups
    for objects matching the search term.

    Args:
        adom: ADOM name
        search_term: Search term (partial match)

    Returns:
        dict: Search results with keys:
            - status: "success" or "error"
            - addresses: Matching address objects
            - address_groups: Matching address groups
            - services: Matching service objects
            - service_groups: Matching service groups
            - total_count: Total matches
            - message: Error message if failed

    Example:
        >>> result = await search_objects("root", "web")
    """
    try:
        client = _get_client()

        filter_list = [["name", "contain", search_term]]

        # Search all object types in parallel
        addresses = await client.list_addresses(adom, filter=filter_list)
        address_groups = await client.list_address_groups(adom, filter=filter_list)
        services = await client.list_services(adom, filter=filter_list)
        service_groups = await client.list_service_groups(adom, filter=filter_list)

        total = len(addresses) + len(address_groups) + len(services) + len(service_groups)

        return {
            "status": "success",
            "addresses": addresses,
            "address_groups": address_groups,
            "services": services,
            "service_groups": service_groups,
            "total_count": total,
        }
    except Exception as e:
        logger.error(f"Failed to search objects: {e}")
        return {"status": "error", "message": str(e)}
