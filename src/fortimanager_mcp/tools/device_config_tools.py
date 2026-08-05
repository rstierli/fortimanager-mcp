"""Device-level configuration tools for FortiManager MCP (issue #45).

Typed tools for configuring the device itself in FortiManager's device
database: interfaces/VLAN subinterfaces, DHCP servers, and wireless VAPs
(SSIDs). Everything writes to the FMG device DB only; nothing talks to the
FortiGate directly. Push staged changes with ``preview_install`` followed by
``install_device_settings``, the same flow the rest of the server uses.

Field names follow the FortiOS cmdb tables the device DB mirrors
(``system interface``, ``system dhcp server``, ``wireless-controller vap``,
``wireless-controller wtp-profile``).
"""

import ipaddress
import logging
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    ValidationError,
    validate_device_name,
    validate_interface_name,
    validate_ipv4_address,
    validate_ipv4_subnet,
    validate_object_name,
)

logger = logging.getLogger(__name__)

INTERFACE_ROLES = {"lan", "wan", "dmz", "undefined"}


def _ip_mask_pair(ip: str) -> list[str]:
    """Normalize an interface address to the [address, netmask] pair the
    device DB stores.

    Accepts CIDR ("192.0.2.254/24") or "address netmask" form.
    """
    ip = validate_ipv4_subnet(ip)
    if " " in ip:
        addr, mask = ip.split()
        return [addr, mask]
    iface = ipaddress.IPv4Interface(ip)
    return [str(iface.ip), str(iface.network.netmask)]


# =============================================================================
# Interfaces / VLAN subinterfaces (device DB, global scope)
# =============================================================================


@mcp.tool()
async def create_device_interface(
    device: str,
    name: str,
    parent: str,
    vlanid: int,
    ip: str | None = None,
    allowaccess: list[str] | None = None,
    role: str | None = None,
    alias: str | None = None,
    vdom: str = "root",
    description: str | None = None,
) -> dict[str, Any]:
    """Create a VLAN subinterface in a device's device DB.

    Reads back with ``get_device_interface_config``; push to the FortiGate
    with ``preview_install`` + ``install_device_settings``.

    Args:
        device: Managed device name
        name: New interface name (e.g. "vlan15")
        parent: Physical/aggregate parent interface (e.g. "internal")
        vlanid: VLAN id (1-4094)
        ip: Interface address, CIDR ("192.0.2.254/24") or "address netmask"
        allowaccess: Administrative access to allow (e.g. ["ping", "https"])
        role: Interface role: lan, wan, dmz or undefined
        alias: Short alias shown in the GUI
        vdom: VDOM the interface belongs to (default "root")
        description: Interface description

    Returns:
        Creation result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        name = validate_interface_name(name)
        parent = validate_interface_name(parent)
        if not 1 <= vlanid <= 4094:
            raise ValidationError(f"vlanid must be 1-4094, got {vlanid}")
        data: dict[str, Any] = {
            "name": name,
            "type": "vlan",
            "interface": parent,
            "vlanid": vlanid,
            "vdom": vdom,
        }
        if ip is not None:
            data["ip"] = _ip_mask_pair(ip)
            data["mode"] = "static"
        if allowaccess is not None:
            data["allowaccess"] = [a.strip().lower() for a in allowaccess]
        if role is not None:
            role = role.strip().lower()
            if role not in INTERFACE_ROLES:
                raise ValidationError(
                    f"role must be one of {sorted(INTERFACE_ROLES)}, got '{role}'"
                )
            data["role"] = role
        if alias is not None:
            data["alias"] = alias
        if description is not None:
            data["description"] = description

        result = await client.create_device_interface(device=device, data=data)
        return {
            "success": True,
            "message": f"Interface '{name}' (VLAN {vlanid} on '{parent}') created "
            f"in device DB of '{device}'. Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Device interface create failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_interface(
    device: str,
    name: str,
    ip: str | None = None,
    allowaccess: list[str] | None = None,
    role: str | None = None,
    alias: str | None = None,
    description: str | None = None,
    vlanid: int | None = None,
) -> dict[str, Any]:
    """Update fields on a device-DB interface. Only provided fields change.

    Args:
        device: Managed device name
        name: Interface name to update
        ip: New address, CIDR or "address netmask" form
        allowaccess: Replacement administrative-access list
        role: Interface role: lan, wan, dmz or undefined
        alias: Short alias shown in the GUI
        description: Interface description
        vlanid: New VLAN id (1-4094)

    Returns:
        Update result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        name = validate_interface_name(name)
        data: dict[str, Any] = {}
        if ip is not None:
            data["ip"] = _ip_mask_pair(ip)
            data["mode"] = "static"
        if allowaccess is not None:
            data["allowaccess"] = [a.strip().lower() for a in allowaccess]
        if role is not None:
            role = role.strip().lower()
            if role not in INTERFACE_ROLES:
                raise ValidationError(
                    f"role must be one of {sorted(INTERFACE_ROLES)}, got '{role}'"
                )
            data["role"] = role
        if alias is not None:
            data["alias"] = alias
        if description is not None:
            data["description"] = description
        if vlanid is not None:
            if not 1 <= vlanid <= 4094:
                raise ValidationError(f"vlanid must be 1-4094, got {vlanid}")
            data["vlanid"] = vlanid

        if not data:
            return {"error": "No update parameters provided"}

        result = await client.update_device_interface(device=device, name=name, data=data)
        return {
            "success": True,
            "message": f"Interface '{name}' updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Device interface update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_device_interface(
    device: str,
    name: str,
) -> dict[str, Any]:
    """Delete an interface from a device's device DB.

    Args:
        device: Managed device name
        name: Interface name to delete

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        name = validate_interface_name(name)
        result = await client.delete_device_interface(device=device, name=name)
        return {
            "success": True,
            "message": f"Interface '{name}' deleted from device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Device interface delete failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# DHCP servers (device DB, vdom scope)
# =============================================================================


@mcp.tool()
async def list_device_dhcp_servers(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """List DHCP servers configured in a device's device DB.

    Args:
        device: Managed device name
        vdom: VDOM to read (default "root")

    Returns:
        dict with device, vdom, count and dhcp_servers (raw device-DB objects,
        keyed by numeric id)
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        servers = await client.list_device_dhcp_servers(device=device, vdom=vdom)
        servers = servers if isinstance(servers, list) else [servers] if servers else []
        return {
            "device": device,
            "vdom": vdom,
            "count": len(servers),
            "dhcp_servers": servers,
        }
    except Exception as e:
        logger.error(f"DHCP server list failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_device_dhcp_server(
    device: str,
    interface: str,
    start_ip: str,
    end_ip: str,
    netmask: str,
    default_gateway: str | None = None,
    dns_servers: list[str] | None = None,
    lease_time: int | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Create a DHCP server scope in a device's device DB.

    Args:
        device: Managed device name
        interface: Interface the scope serves (e.g. "vlan15")
        start_ip: First address of the lease range
        end_ip: Last address of the lease range
        netmask: Scope netmask (e.g. "255.255.255.0")
        default_gateway: Gateway handed to clients (defaults to the
            interface address if omitted, per FortiOS behavior)
        dns_servers: Up to three DNS servers to hand out; omitted means the
            device's system DNS is used (dns-service default)
        lease_time: Lease time in seconds
        vdom: VDOM the scope lives in (default "root")

    Returns:
        Creation result including the new scope id
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        interface = validate_interface_name(interface)
        start_ip = validate_ipv4_address(start_ip)
        end_ip = validate_ipv4_address(end_ip)
        netmask = validate_ipv4_address(netmask)
        data: dict[str, Any] = {
            "interface": interface,
            "ip-range": [{"id": 1, "start-ip": start_ip, "end-ip": end_ip}],
            "netmask": netmask,
        }
        if default_gateway is not None:
            data["default-gateway"] = validate_ipv4_address(default_gateway)
        if dns_servers:
            if len(dns_servers) > 3:
                raise ValidationError(
                    f"dns_servers accepts at most 3 entries, got {len(dns_servers)}"
                )
            data["dns-service"] = "specify"
            for i, server in enumerate(dns_servers, start=1):
                data[f"dns-server{i}"] = validate_ipv4_address(server)
        else:
            data["dns-service"] = "default"
        if lease_time is not None:
            data["lease-time"] = lease_time

        result = await client.create_device_dhcp_server(device=device, vdom=vdom, data=data)
        return {
            "success": True,
            "message": f"DHCP scope {start_ip}-{end_ip} on '{interface}' created "
            f"in device DB of '{device}'. Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"DHCP server create failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_dhcp_server(
    device: str,
    dhcp_server_id: int,
    start_ip: str | None = None,
    end_ip: str | None = None,
    netmask: str | None = None,
    default_gateway: str | None = None,
    dns_servers: list[str] | None = None,
    lease_time: int | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Update a device-DB DHCP server scope by id. Only provided fields change.

    The lease range is replaced as a whole, so start_ip and end_ip must be
    given together.

    Args:
        device: Managed device name
        dhcp_server_id: Numeric scope id (see list_device_dhcp_servers)
        start_ip: New first address of the lease range
        end_ip: New last address of the lease range
        netmask: New scope netmask
        default_gateway: New gateway handed to clients
        dns_servers: Up to three DNS servers; replaces the served set
        lease_time: New lease time in seconds
        vdom: VDOM the scope lives in (default "root")

    Returns:
        Update result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        if (start_ip is None) != (end_ip is None):
            raise ValidationError("start_ip and end_ip must be provided together")
        data: dict[str, Any] = {}
        if start_ip is not None and end_ip is not None:
            data["ip-range"] = [
                {
                    "id": 1,
                    "start-ip": validate_ipv4_address(start_ip),
                    "end-ip": validate_ipv4_address(end_ip),
                }
            ]
        if netmask is not None:
            data["netmask"] = validate_ipv4_address(netmask)
        if default_gateway is not None:
            data["default-gateway"] = validate_ipv4_address(default_gateway)
        if dns_servers is not None:
            if len(dns_servers) > 3:
                raise ValidationError(
                    f"dns_servers accepts at most 3 entries, got {len(dns_servers)}"
                )
            data["dns-service"] = "specify"
            for i, server in enumerate(dns_servers, start=1):
                data[f"dns-server{i}"] = validate_ipv4_address(server)
        if lease_time is not None:
            data["lease-time"] = lease_time

        if not data:
            return {"error": "No update parameters provided"}

        result = await client.update_device_dhcp_server(
            device=device, vdom=vdom, server_id=dhcp_server_id, data=data
        )
        return {
            "success": True,
            "message": f"DHCP scope {dhcp_server_id} updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"DHCP server update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_device_dhcp_server(
    device: str,
    dhcp_server_id: int,
    vdom: str = "root",
) -> dict[str, Any]:
    """Delete a DHCP server scope from a device's device DB.

    Args:
        device: Managed device name
        dhcp_server_id: Numeric scope id (see list_device_dhcp_servers)
        vdom: VDOM the scope lives in (default "root")

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        result = await client.delete_device_dhcp_server(
            device=device, vdom=vdom, server_id=dhcp_server_id
        )
        return {
            "success": True,
            "message": f"DHCP scope {dhcp_server_id} deleted from device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"DHCP server delete failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# Wireless VAPs / SSIDs (device DB, vdom scope)
# =============================================================================


def _sanitize_vap_result(result: Any) -> Any:
    """Strip the passphrase from anything FMG echoes back."""
    if isinstance(result, dict):
        return {k: v for k, v in result.items() if k != "passphrase"}
    if isinstance(result, list):
        return [_sanitize_vap_result(item) for item in result]
    return result


@mcp.tool()
async def list_device_vaps(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """List wireless VAPs (SSIDs) in a device's device DB.

    Args:
        device: Managed device name
        vdom: VDOM to read (default "root")

    Returns:
        dict with device, vdom, count and vaps (passphrases stripped)
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vaps = await client.list_device_vaps(device=device, vdom=vdom)
        vaps = vaps if isinstance(vaps, list) else [vaps] if vaps else []
        return {
            "device": device,
            "vdom": vdom,
            "count": len(vaps),
            "vaps": _sanitize_vap_result(vaps),
        }
    except Exception as e:
        logger.error(f"VAP list failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_device_vap(
    device: str,
    name: str,
    ssid: str,
    security: str = "wpa2-only-personal",
    passphrase: str | None = None,
    vlanid: int | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Create a wireless VAP (SSID) in a device's device DB.

    The VAP becomes broadcastable once added to a FortiAP profile
    (assign_vap_to_wtp_profile).

    Args:
        device: Managed device name
        name: VAP object name
        ssid: SSID to broadcast
        security: Security mode, a FortiOS ``wireless-controller vap``
            security enum value (e.g. "wpa2-only-personal", "wpa3-sae",
            "open"); default "wpa2-only-personal"
        passphrase: WPA passphrase, 8-63 characters; required by the
            personal/SAE modes
        vlanid: VLAN id to map wireless clients into
        vdom: VDOM the VAP lives in (default "root")

    Returns:
        Creation result with any echoed passphrase stripped
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        name = validate_object_name(name, "vap")
        data: dict[str, Any] = {
            "name": name,
            "ssid": ssid,
            "security": security.strip().lower(),
        }
        if passphrase is not None:
            if not 8 <= len(passphrase) <= 63:
                raise ValidationError("passphrase must be 8-63 characters")
            data["passphrase"] = passphrase
        if vlanid is not None:
            if not 1 <= vlanid <= 4094:
                raise ValidationError(f"vlanid must be 1-4094, got {vlanid}")
            data["vlanid"] = vlanid

        result = await client.create_device_vap(device=device, vdom=vdom, data=data)
        return {
            "success": True,
            "message": f"VAP '{name}' (SSID '{ssid}') created in device DB of "
            f"'{device}'. Add it to a FortiAP profile with "
            "assign_vap_to_wtp_profile, then push with install_device_settings.",
            "result": _sanitize_vap_result(result),
        }
    except Exception as e:
        logger.error(f"VAP create failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_device_vap(
    device: str,
    name: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Delete a wireless VAP from a device's device DB.

    Args:
        device: Managed device name
        name: VAP object name to delete
        vdom: VDOM the VAP lives in (default "root")

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        name = validate_object_name(name, "vap")
        result = await client.delete_device_vap(device=device, vdom=vdom, name=name)
        return {
            "success": True,
            "message": f"VAP '{name}' deleted from device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"VAP delete failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def assign_vap_to_wtp_profile(
    device: str,
    profile: str,
    vap: str,
    radios: list[int] | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Add a VAP (SSID) to a FortiAP profile's radios so it gets broadcast.

    Reads the profile, appends the VAP to each selected radio's manual VAP
    list, and switches that radio's vap-all mode to "manual" (the mode that
    honors an explicit list). VAPs already present are left in place.

    Args:
        device: Managed device name
        profile: FortiAP (WTP) profile name
        vap: VAP object name to broadcast
        radios: Radios to add the SSID to, from 1-3 (default [1, 2])
        vdom: VDOM the profile lives in (default "root")

    Returns:
        Update result listing the radios changed
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        profile = validate_object_name(profile, "wtp-profile")
        vap = validate_object_name(vap, "vap")
        radios = radios or [1, 2]
        bad = [r for r in radios if r not in (1, 2, 3)]
        if bad:
            raise ValidationError(f"radios must be within 1-3, got {bad}")

        stored = await client.get_device_wtp_profile(device=device, vdom=vdom, name=profile)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict):
            return {
                "error": f"Unexpected wtp-profile shape for '{profile}'",
                "error_code": "unexpected_response",
            }

        data: dict[str, Any] = {}
        for radio_num in radios:
            key = f"radio-{radio_num}"
            radio = stored.get(key)
            radio = radio if isinstance(radio, dict) else {}
            vaps = radio.get("vaps") or []
            if isinstance(vaps, str):
                vaps = [vaps]
            vaps = [str(v) for v in vaps]
            if vap in vaps and radio.get("vap-all") == "manual":
                continue
            merged = vaps if vap in vaps else [*vaps, vap]
            data[key] = {"vap-all": "manual", "vaps": merged}

        if not data:
            return {
                "success": True,
                "message": f"VAP '{vap}' already assigned to "
                f"radio(s) {radios} of profile '{profile}'.",
            }

        result = await client.update_device_wtp_profile(
            device=device, vdom=vdom, name=profile, data=data
        )
        return {
            "success": True,
            "message": f"VAP '{vap}' added to {', '.join(sorted(data))} of profile "
            f"'{profile}' in device DB of '{device}'. Push with "
            "install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"VAP assignment failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}
