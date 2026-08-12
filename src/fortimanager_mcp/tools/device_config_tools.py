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
    validate_device_serial,
    validate_interface_name,
    validate_ipv4_address,
    validate_ipv4_subnet,
    validate_object_name,
)

logger = logging.getLogger(__name__)

INTERFACE_ROLES = {"lan", "wan", "dmz", "undefined"}

#: FortiOS wtp-profile radio channel-bonding (width) values confirmed across
#: 20/40/80/160MHz builds. Wi-Fi 7 profiles may add a 320MHz option on newer
#: FortiOS trains; it is intentionally left out here since it could not be
#: confirmed against a live appliance or schema dump (see PR description).
WTP_PROFILE_CHANNEL_BONDING_MODES = {"20MHz", "40MHz", "80MHz", "160MHz"}

#: FortiOS wireless-controller.wtp authorization states.
WTP_ADMIN_STATES = {"discovered", "disable", "enable"}


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
        vdom = validate_object_name(vdom, "VDOM")
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
        vdom = validate_object_name(vdom, "VDOM")
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
        vdom = validate_object_name(vdom, "VDOM")
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
        vdom = validate_object_name(vdom, "VDOM")
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
        vdom = validate_object_name(vdom, "VDOM")
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


#: Credential fields FMG stores as ``type=password`` on ``wireless-controller
#: vap``. WPA/WPA2 personal modes use ``passphrase``; WPA3-SAE keeps its own
#: ``sae-password``, and transition mode carries both.
_VAP_SECRET_FIELDS = ("passphrase", "sae-password")

#: Security modes that authenticate with an SAE password.
_VAP_SAE_MODES = frozenset({"wpa3-sae", "wpa3-sae-transition"})

#: Security modes that authenticate with a WPA pre-shared key.
_VAP_PSK_MODES = frozenset({"wpa-personal", "wpa-only-personal", "wpa2-only-personal"})


def _sanitize_vap_result(result: Any) -> Any:
    """Strip every credential field from anything FMG echoes back.

    Recurses through dict VALUES as well as list items. The first version
    stripped top-level keys only, so a credential one level down survived
    the function whose entire purpose is that it cannot::

        {"data": {"passphrase": "..."}}   ->   passphrase survived

    The echo is flat today, so that was latent rather than live. It is
    still wrong: the repo's own ``sanitize_for_logging`` recurses fully,
    and a sanitizer that depends on the shape it is handed is one
    response format away from leaking.
    """
    if isinstance(result, dict):
        return {
            k: _sanitize_vap_result(v) for k, v in result.items() if k not in _VAP_SECRET_FIELDS
        }
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
        vdom = validate_object_name(vdom, "VDOM")
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
            security enum value; default "wpa2-only-personal". Supported here:
            the personal modes ("wpa-personal", "wpa-only-personal",
            "wpa2-only-personal"), the SAE modes ("wpa3-sae",
            "wpa3-sae-transition"), "owe" and "open". Enterprise and WEP modes
            are refused, since neither a radius/user-group nor a WEP key is set
            by this tool.
        passphrase: Credential, 8-63 characters, required by the personal and
            SAE modes. It is sent as ``passphrase`` for the personal modes and
            as ``sae-password`` for SAE; transition mode carries both, since it
            runs a WPA2 leg alongside SAE.
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
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "vap")
        security = security.strip().lower()
        data: dict[str, Any] = {"name": name, "ssid": ssid, "security": security}

        def _credential(mode: str) -> str:
            if passphrase is None or not 8 <= len(passphrase) <= 63:
                raise ValidationError(f"{mode} requires a passphrase of 8-63 characters")
            return passphrase

        if security in _VAP_SAE_MODES:
            data["sae-password"] = _credential(security)
            # SAE is only defined with Protected Management Frames.
            data["pmf"] = "enable"
            if security == "wpa3-sae-transition":
                # Transition mode also runs a WPA2 leg off the PSK field.
                data["passphrase"] = _credential(security)
        elif security in _VAP_PSK_MODES:
            data["passphrase"] = _credential(security)
        elif security == "owe":
            data["pmf"] = "enable"
        elif security == "open":
            pass
        elif security.startswith("wep"):
            raise ValidationError(
                f"security '{security}' takes a WEP key, which this tool does not set"
            )
        else:
            raise ValidationError(
                f"security '{security}' needs radius or user-group auth, which this "
                "tool does not set"
            )

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
        vdom = validate_object_name(vdom, "VDOM")
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
        vdom = validate_object_name(vdom, "VDOM")
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
        if not stored:
            # An empty read is not a profile with no radios, it is a read
            # that told us nothing. Continuing would invent radio objects
            # from scratch and write them, so a typo in the profile name
            # would create configuration rather than fail.
            return {
                "error": f"wtp-profile '{profile}' not found or returned no configuration",
                "error_code": "not_found",
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
            # Carry the rest of the radio object through. This is a
            # read-modify-write, and writing back only the two keys we
            # touched discards everything else we just read: band,
            # channel, power-level, mode, channel-bonding. FortiManager
            # replaces a nested object rather than merging into it, so
            # those would reset to defaults and the next
            # install_device_settings would push the reset to a live AP.
            # Changing two fields must not be a way to reset the rest.
            data[key] = {**radio, "vap-all": "manual", "vaps": merged}

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


# =============================================================================
# WTP-profile radio configuration (device DB, vdom scope) (issue #52)
# =============================================================================


@mcp.tool()
async def list_device_wtp_profiles(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """List FortiAP (WTP) profiles in a device's device DB.

    Args:
        device: Managed device name
        vdom: VDOM to read (default "root")

    Returns:
        dict with device, vdom, count and profiles (raw device-DB objects)
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        profiles = await client.list_device_wtp_profiles(device=device, vdom=vdom)
        profiles = profiles if isinstance(profiles, list) else [profiles] if profiles else []
        return {
            "device": device,
            "vdom": vdom,
            "count": len(profiles),
            "profiles": profiles,
        }
    except Exception as e:
        logger.error(f"WTP profile list failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_device_wtp_profile(
    device: str,
    profile: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get a FortiAP (WTP) profile from a device's device DB, radios included.

    Args:
        device: Managed device name
        profile: FortiAP (WTP) profile name
        vdom: VDOM the profile lives in (default "root")

    Returns:
        dict with device, vdom and the stored profile object, or a
        not_found error if the profile does not exist
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        profile = validate_object_name(profile, "wtp-profile")
        stored = await client.get_device_wtp_profile(device=device, vdom=vdom, name=profile)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict) or not stored:
            return {
                "error": f"wtp-profile '{profile}' not found or returned no configuration",
                "error_code": "not_found",
            }
        return {"device": device, "vdom": vdom, "profile": stored}
    except Exception as e:
        logger.error(f"WTP profile read failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_wtp_profile_radio(
    device: str,
    profile: str,
    radio: int,
    channel: list[int] | None = None,
    channel_bonding: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Update a single radio's channel and/or channel width on a FortiAP profile.

    This is a read-modify-write, like assign_vap_to_wtp_profile: the profile
    is read first and every other field already on the target radio (band,
    power, vap-all, vaps, mode, ...) is carried through unchanged.
    FortiManager replaces a nested radio object rather than merging into it,
    so writing back only channel/channel-bonding would reset the rest to
    defaults on the next install_device_settings.

    Args:
        device: Managed device name
        profile: FortiAP (WTP) profile name
        radio: Radio to update, 1-3
        channel: Channel(s) to pin the radio to. FortiOS stores this as a
            list (it can also hold an auto-select candidate set); pass a
            single-element list, e.g. [15], to pin one channel.
        channel_bonding: Channel width/bonding, one of
            WTP_PROFILE_CHANNEL_BONDING_MODES ("20MHz", "40MHz", "80MHz",
            "160MHz")
        vdom: VDOM the profile lives in (default "root")

    Returns:
        Update result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        profile = validate_object_name(profile, "wtp-profile")
        if radio not in (1, 2, 3):
            raise ValidationError(f"radio must be 1-3, got {radio}")
        if channel is None and channel_bonding is None:
            return {"error": "No update parameters provided"}

        channel_values: list[str] | None = None
        if channel is not None:
            if not channel:
                raise ValidationError("channel must contain at least one channel number")
            for c in channel:
                if not 1 <= c <= 233:
                    raise ValidationError(f"channel values must be 1-233, got {c}")
            channel_values = [str(c) for c in channel]

        if channel_bonding is not None:
            channel_bonding = channel_bonding.strip()
            if channel_bonding not in WTP_PROFILE_CHANNEL_BONDING_MODES:
                raise ValidationError(
                    "channel_bonding must be one of "
                    f"{sorted(WTP_PROFILE_CHANNEL_BONDING_MODES)}, got '{channel_bonding}'"
                )

        stored = await client.get_device_wtp_profile(device=device, vdom=vdom, name=profile)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict):
            return {
                "error": f"Unexpected wtp-profile shape for '{profile}'",
                "error_code": "unexpected_response",
            }
        if not stored:
            # An empty read is not a profile with no radios, it is a read
            # that told us nothing. See assign_vap_to_wtp_profile for why
            # continuing would invent radio objects from scratch.
            return {
                "error": f"wtp-profile '{profile}' not found or returned no configuration",
                "error_code": "not_found",
            }

        key = f"radio-{radio}"
        existing = stored.get(key)
        if not isinstance(existing, dict) or not existing:
            return {
                "error": f"'{key}' not found on wtp-profile '{profile}'",
                "error_code": "not_found",
            }

        # Carry the rest of the radio object through; see the docstring and
        # assign_vap_to_wtp_profile for why a partial write is unsafe here.
        updated_radio = dict(existing)
        if channel_values is not None:
            updated_radio["channel"] = channel_values
        if channel_bonding is not None:
            updated_radio["channel-bonding"] = channel_bonding

        result = await client.update_device_wtp_profile(
            device=device, vdom=vdom, name=profile, data={key: updated_radio}
        )
        return {
            "success": True,
            "message": f"{key} of profile '{profile}' updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"WTP profile radio update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# Managed FortiAPs / wtp registration (device DB, vdom scope) (issue #52)
# =============================================================================


@mcp.tool()
async def list_device_wtps(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """List managed FortiAPs registered in a device's device DB.

    Args:
        device: Managed device name (the wireless controller / FortiGate)
        vdom: VDOM to read (default "root")

    Returns:
        dict with device, vdom, count and wtps (raw device-DB objects, keyed
        by wtp-id/serial)
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        wtps = await client.list_device_wtps(device=device, vdom=vdom)
        wtps = wtps if isinstance(wtps, list) else [wtps] if wtps else []
        return {
            "device": device,
            "vdom": vdom,
            "count": len(wtps),
            "wtps": wtps,
        }
    except Exception as e:
        logger.error(f"WTP list failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_device_wtp(
    device: str,
    wtp_id: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get one managed FortiAP by wtp-id (serial number).

    Args:
        device: Managed device name
        wtp_id: FortiAP serial number (the wtp-id / table mkey)
        vdom: VDOM the AP is registered in (default "root")

    Returns:
        dict with device, vdom and the stored wtp object, or a not_found
        error if it does not exist
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        wtp_id = validate_device_serial(wtp_id)
        stored = await client.get_device_wtp(device=device, vdom=vdom, wtp_id=wtp_id)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict) or not stored:
            return {
                "error": f"wtp '{wtp_id}' not found or returned no configuration",
                "error_code": "not_found",
            }
        return {"device": device, "vdom": vdom, "wtp": stored}
    except Exception as e:
        logger.error(f"WTP read failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_device_wtp(
    device: str,
    wtp_id: str,
    wtp_profile: str,
    name: str | None = None,
    admin: str = "discovered",
    location: str | None = None,
    comment: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Register a managed FortiAP in a device's device DB.

    This is the wireless-controller.wtp table: the mapping from a physical
    AP's serial number to the profile it runs. A wtp-profile that exists in
    the device DB but is not referenced by any wtp entry is pruned by
    FortiManager on install, so registering the AP here is required before
    a profile-only setup survives install_device_settings.

    Args:
        device: Managed device name
        wtp_id: FortiAP serial number (the wtp-id / table mkey)
        wtp_profile: FortiAP (WTP) profile name to assign
        name: Friendly display name
        admin: Authorization state: "discovered" (awaiting authorization),
            "enable" (authorized) or "disable"; default "discovered"
        location: Free-text location string
        comment: Free-text comment
        vdom: VDOM to register the AP in (default "root")

    Returns:
        Creation result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        wtp_id = validate_device_serial(wtp_id)
        wtp_profile = validate_object_name(wtp_profile, "wtp-profile")
        admin = admin.strip().lower()
        if admin not in WTP_ADMIN_STATES:
            raise ValidationError(f"admin must be one of {sorted(WTP_ADMIN_STATES)}, got '{admin}'")

        data: dict[str, Any] = {
            "wtp-id": wtp_id,
            "wtp-profile": wtp_profile,
            "admin": admin,
        }
        if name is not None:
            data["name"] = name
        if location is not None:
            data["location"] = location
        if comment is not None:
            data["comment"] = comment

        result = await client.create_device_wtp(device=device, vdom=vdom, data=data)
        return {
            "success": True,
            "message": f"WTP '{wtp_id}' registered on profile '{wtp_profile}' "
            f"in device DB of '{device}'. Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"WTP create failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_wtp(
    device: str,
    wtp_id: str,
    wtp_profile: str | None = None,
    name: str | None = None,
    admin: str | None = None,
    location: str | None = None,
    comment: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Update fields on a device-DB managed FortiAP. Only provided fields change.

    Args:
        device: Managed device name
        wtp_id: FortiAP serial number (the wtp-id / table mkey)
        wtp_profile: New FortiAP (WTP) profile name to assign
        name: New friendly display name
        admin: New authorization state: "discovered", "enable" or "disable"
        location: New free-text location string
        comment: New free-text comment
        vdom: VDOM the AP is registered in (default "root")

    Returns:
        Update result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        wtp_id = validate_device_serial(wtp_id)
        data: dict[str, Any] = {}
        if wtp_profile is not None:
            data["wtp-profile"] = validate_object_name(wtp_profile, "wtp-profile")
        if name is not None:
            data["name"] = name
        if admin is not None:
            admin = admin.strip().lower()
            if admin not in WTP_ADMIN_STATES:
                raise ValidationError(
                    f"admin must be one of {sorted(WTP_ADMIN_STATES)}, got '{admin}'"
                )
            data["admin"] = admin
        if location is not None:
            data["location"] = location
        if comment is not None:
            data["comment"] = comment

        if not data:
            return {"error": "No update parameters provided"}

        result = await client.update_device_wtp(device=device, vdom=vdom, wtp_id=wtp_id, data=data)
        return {
            "success": True,
            "message": f"WTP '{wtp_id}' updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"WTP update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_device_wtp(
    device: str,
    wtp_id: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Delete a managed FortiAP registration from a device's device DB.

    Args:
        device: Managed device name
        wtp_id: FortiAP serial number (the wtp-id / table mkey)
        vdom: VDOM the AP is registered in (default "root")

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        wtp_id = validate_device_serial(wtp_id)
        result = await client.delete_device_wtp(device=device, vdom=vdom, wtp_id=wtp_id)
        return {
            "success": True,
            "message": f"WTP '{wtp_id}' deleted from device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"WTP delete failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}
