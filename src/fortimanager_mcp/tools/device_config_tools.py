"""Device-level configuration tools for FortiManager MCP (issue #45).

Typed tools for configuring the device itself in FortiManager's device
database: interfaces/VLAN subinterfaces, DHCP servers, wireless VAPs
(SSIDs), and firewall sniffer definitions. Everything writes to the FMG
device DB only; nothing talks to the FortiGate directly. Push staged
changes with ``preview_install`` followed by ``install_device_settings``,
the same flow the rest of the server uses.

Field names follow the FortiOS cmdb tables the device DB mirrors
(``system interface``, ``system dhcp server``, ``wireless-controller vap``,
``wireless-controller wtp-profile``, ``firewall sniffer``).
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

#: Read-only / server-injected bookkeeping keys that show up in a wtp-profile
#: radio object as returned by a GET but break the whole request if echoed
#: back on a write. Confirmed live against the FGT-MCP-TEST-01 sandbox
#: (2026-08-13): an update payload that includes "oid" is rejected with a
#: generic "The data is invalid for the selected URL" error, independent of
#: anything else in the payload, on every radio (2.4/5/6GHz alike) -- not
#: just radio-3 or wide-bonding channels. "unset attrs" is the same kind of
#: read-only marker (lists fields the API has never had an explicit value
#: for) and gets stripped for the same reason.
_WTP_RADIO_READONLY_KEYS = ("oid", "unset attrs")


def _carry_through_radio(radio: dict[str, Any]) -> dict[str, Any]:
    """Copy a radio object for a read-modify-write, dropping keys the API
    injects on read but rejects on write (see _WTP_RADIO_READONLY_KEYS)."""
    return {k: v for k, v in radio.items() if k not in _WTP_RADIO_READONLY_KEYS}


#: FortiOS wtp-profile channel-bonding device-DB integer codes. 2=80MHz and
#: 5=160MHz confirmed live 2026-08-13 (FGT-MCP-TEST-01 sandbox and myfw01).
#: 4=20MHz and 3=40MHz confirmed live 2026-08-21 against myfw01's real
#: wtp-profiles: 4 on every radio-1 (2.4GHz) observed across all 4
#: profiles on the device, 3 on radio-2 (5GHz) on two of them. 6=320MHz is
#: still unconfirmed -- no profile on this fleet has ever used it -- and
#: filled in by the same enum ordering purely because the bundled 7.4+
#: swagger's string enum lists 320MHz as a valid channel-bonding value.
_CHANNEL_BONDING_INT_TO_MHZ = {2: 80, 3: 40, 4: 20, 5: 160, 6: 320}


def _channel_bonding_mhz(value: Any) -> int | None:
    """Resolve a stored or requested channel-bonding value to a width in
    MHz, whether it's the human string ("160MHz") or the device-DB integer
    code. Returns None if it can't be resolved."""
    if isinstance(value, str) and value.endswith("MHz"):
        try:
            return int(value[:-3])
        except ValueError:
            return None
    if isinstance(value, int):
        return _CHANNEL_BONDING_INT_TO_MHZ.get(value)
    return None


def _radio3_wide_channel_members(label: int, width_mhz: int) -> list[int] | None:
    """Expand a 6GHz wide-channel label (e.g. 15 at 160MHz) into its member
    20MHz sub-channels (e.g. 1,5,9,...,29).

    Confirmed live against myfw01's FAP23JK-AP1/AP2 wtp-profiles
    (2026-08-13): a working, FortiOS-accepted 160MHz pin to 6GHz channel 15
    is stored as `channel: ["1","5","9","13","17","21","25","29"]`, and
    channel 47 as `["33","37","41","45","49","53","57","61"]` -- NOT as a
    single-element `["15"]`/`["47"]`. FortiManager's device-DB write does
    NOT reject a single-element channel at wide bonding (confirmed on the
    FGT-MCP-TEST-01 sandbox: it writes `["15"]` at 160MHz bonding without
    complaint), so a caller relying on server-side validation to catch this
    would not be warned -- it is a silent misconfiguration, not a loud
    failure.

    This matches the general IEEE 802.11 6GHz channelization: a width-N*20
    MHz channel is N member 20MHz channels spaced 4 apart, and the
    conventional wide-channel label is the arithmetic midpoint of the first
    and last member (verified against both real examples above, and
    against the public 160MHz label sequence 15/47/79/111/...).

    Returns None if `label` is not a valid midpoint for `width_mhz` (i.e.
    the request doesn't line up with any real member-channel set).
    """
    n = width_mhz // 20
    if n <= 1:
        return None
    first = label - 2 * (n - 1)
    if first < 1 or (first - 1) % (4 * n) != 0:
        return None
    return [first + 4 * i for i in range(n)]


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
async def create_device_sniffer(
    device: str,
    interface: str,
    host: str | None = None,
    port: str | None = None,
    protocol: str | None = None,
    vlan: str | None = None,
    capture_ipv6: bool = False,
    capture_non_ip: bool = False,
    status: str = "enable",
    logtraffic: str | None = None,
    sniffer_id: int | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Create a firewall sniffer definition on a managed device.

    This targets the FortiGate's own persistent ``firewall sniffer`` object
    (device-DB, Configuration API firewall.json /firewall/sniffer) so the
    capture actually runs on the device's own traffic -- not
    FortiManager's separate, unrelated local diagnostic sniffer
    (``/cli/global/system/sniffer``, a different object that happens to
    share a name). Unlike FMG's local sniffer there is no packet-count cap
    or start/stop action: the definition captures continuously while
    ``status`` is "enable", same as any other persistent FortiOS config
    object -- disable or delete it to stop.

    Args:
        device: Managed device name
        interface: Interface name traffic sniffing takes place on
        host: Hosts to filter for (e.g. "1.1.1.1", "2.2.2.0/24")
        port: Ports to sniff (e.g. "80", "1-1024")
        protocol: IANA protocol number as a string (e.g. "6" for TCP)
        vlan: VLAN(s) to sniff
        capture_ipv6: Include IPv6 packets (default: False)
        capture_non_ip: Include non-IP packets (default: False)
        status: "enable" or "disable" (default: "enable")
        logtraffic: "all", "utm", or "disable" (optional)
        sniffer_id: Explicit sniffer ID (0-9999); omit to let FortiOS
            assign the next available one
        vdom: VDOM the sniffer lives in (default "root")

    Returns:
        Creation result including the new sniffer id
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        interface = validate_interface_name(interface)
        if status not in {"enable", "disable"}:
            raise ValidationError(f"status must be 'enable' or 'disable', got {status!r}")
        if logtraffic is not None and logtraffic not in {"all", "utm", "disable"}:
            raise ValidationError(
                f"logtraffic must be 'all', 'utm', or 'disable', got {logtraffic!r}"
            )
        if sniffer_id is not None and not (0 <= sniffer_id <= 9999):
            raise ValidationError(f"sniffer_id must be 0-9999, got {sniffer_id}")

        data: dict[str, Any] = {
            "interface": interface,
            "status": status,
            "ipv6": "enable" if capture_ipv6 else "disable",
            "non-ip": "enable" if capture_non_ip else "disable",
        }
        if sniffer_id is not None:
            data["id"] = sniffer_id
        if host:
            data["host"] = host
        if port:
            data["port"] = port
        if protocol:
            data["protocol"] = protocol
        if vlan:
            data["vlan"] = vlan
        if logtraffic is not None:
            data["logtraffic"] = logtraffic

        result = await client.create_device_sniffer(device=device, vdom=vdom, data=data)
        new_id = result.get("id") if isinstance(result, dict) else None
        return {
            "success": True,
            "message": f"Sniffer {new_id} created on interface '{interface}' in device DB "
            f"of '{device}'. Captures continuously while status=enable; push with "
            "install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Sniffer create failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_device_on_demand_sniffer(
    device: str,
    name: str,
    interface: str,
    max_packet_count: int = 4000,
    hosts: list[str] | None = None,
    ports: list[int] | None = None,
    protocols: list[int] | None = None,
    capture_non_ip: bool = False,
    vdom: str = "root",
) -> dict[str, Any]:
    """Create a bounded on-demand packet sniffer on a managed device.

    Distinct FortiOS object from create_device_sniffer's ``firewall
    sniffer``: this one (``firewall on-demand-sniffer``) is name-keyed
    rather than id-keyed, and bounded by ``max_packet_count`` rather than
    running continuously -- closer to a one-shot capture job than a
    standing diagnostic rule. Filters are lists (multiple hosts/ports/
    protocols at once), not the single range-string form the persistent
    sniffer uses.

    How to actually trigger the capture and retrieve packets once this
    definition exists is not part of FortiOS's Configuration API (this
    tool only stages the definition, config-CRUD like every other tool in
    this module) -- that would be a separate monitor-API or CLI mechanism,
    out of scope here.

    Args:
        device: Managed device name
        name: On-demand sniffer name
        interface: Interface name traffic sniffing takes place on
        max_packet_count: Maximum packets to capture (default: 4000)
        hosts: IPv4/IPv6 hosts to filter for
        ports: Ports to filter for (each 1-65535)
        protocols: IANA protocol numbers to filter for (each 0-255)
        capture_non_ip: Include non-IP packets (default: False)
        vdom: VDOM the sniffer lives in (default "root")

    Returns:
        Creation result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "on-demand sniffer name")
        interface = validate_interface_name(interface)
        if max_packet_count <= 0:
            raise ValidationError("max_packet_count must be a positive integer")
        if ports:
            for p in ports:
                if not (1 <= p <= 65535):
                    raise ValidationError(f"port must be 1-65535, got {p}")
        if protocols:
            for proto in protocols:
                if not (0 <= proto <= 255):
                    raise ValidationError(f"protocol must be 0-255, got {proto}")

        data: dict[str, Any] = {
            "name": name,
            "interface": interface,
            "max-packet-count": max_packet_count,
            "non-ip-packet": "enable" if capture_non_ip else "disable",
        }
        if hosts:
            data["hosts"] = hosts
        if ports:
            data["ports"] = ports
        if protocols:
            data["protocols"] = protocols

        result = await client.create_device_on_demand_sniffer(device=device, vdom=vdom, data=data)
        return {
            "success": True,
            "message": f"On-demand sniffer '{name}' created on interface '{interface}' in "
            f"device DB of '{device}'. Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"On-demand sniffer create failed on {device}: {e}")
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
_VAP_SECRET_FIELDS = frozenset({"passphrase", "sae-password"})

#: Security modes that authenticate with an SAE password.
_VAP_SAE_MODES = frozenset({"wpa3-sae", "wpa3-sae-transition"})

#: Security modes that authenticate with a WPA pre-shared key.
_VAP_PSK_MODES = frozenset({"wpa-personal", "wpa-only-personal", "wpa2-only-personal"})

#: Security modes certain to be refused on a 6 GHz radio.
#:
#: The authority for this set is the maintainer's review on #47, against a
#: live FortiGate 120G: "6GHz is WPA3-only ... a non-WPA3 SSID assigned to
#: radio-3 would be rejected at install time". Wi-Fi Alliance rules agree,
#: but those are recollection, and this list is cited to the measurement.
#:
#: Anything neither here nor in ``_VAP_6GHZ_KNOWN_GOOD`` warns rather than
#: refuses. That asymmetry is the design: an allow-tier mistake costs nothing
#: new, since the install still refuses and says why, which is exactly
#: today's behaviour. A refuse-tier mistake blocks a legitimate change and
#: tells the operator something false.
_VAP_6GHZ_REFUSED_MODES = frozenset(
    {"open", "wep64", "wep128", "wpa-personal", "wpa-only-personal", "wpa2-only-personal"}
)

#: Modes known good on 6 GHz, so they pass without a warning. SAE is the
#: maintainer's own words on #47: "SAE is the case that matters (it's
#: mandatory on 6 GHz)". OWE rests on weaker evidence -- this module already
#: treats it as PMF-mandatory alongside SAE, and the rest is recollection --
#: so it sits in the allow tier, where being wrong is harmless.
_VAP_6GHZ_KNOWN_GOOD = frozenset({"wpa3-sae", "owe"})

#: Substring identifying a 6 GHz band, matched case-insensitively against a
#: radio's ``band``. Observed values are ``802.11ax-6G`` and ``802.11be-6G``;
#: the maintainer's schema dump says the enum "includes" those, so the full
#: list is not known here and a substring keeps future 6 GHz bands covered.
#: No other FortiOS band token contains "6g" -- ``802.11g`` ends in a bare
#: "g" -- but that sweep is recollection rather than a measurement.
_SIX_GHZ_BAND_MARK = "6g"


def _radio_band(radio: dict[str, Any]) -> str | None:
    """A radio's band as a string, or None when it cannot be determined.

    FortiManager omits fields at their default and stores some scalars as
    one-element lists (``channel`` is documented that way in this module and
    ``vaps`` arrives as a list), so neither absence nor a list shape means
    the response is malformed.
    """
    band = radio.get("band")
    if isinstance(band, list):
        band = band[0] if len(band) == 1 else None
    return band if isinstance(band, str) and band.strip() else None


def _is_six_ghz(radio: dict[str, Any]) -> bool:
    """Is this a 6 GHz radio? False when the band cannot be determined.

    Fail-open, deliberately. A radio with no ``band`` is the ordinary case
    rather than a suspicious one: FortiManager omits defaults, and this tool
    invents an empty radio dict when the profile has no entry for an index.
    Treating unknown as 6 GHz would refuse the majority workflow. The guard
    is early warning; the install is the real gate and it tells the truth.
    """
    band = _radio_band(radio)
    return band is not None and _SIX_GHZ_BAND_MARK in band.lower()


async def _check_six_ghz_vap(
    client: Any,
    device: str,
    vdom: str,
    vap: str,
    six_ghz_radios: list[int],
) -> tuple[dict[str, Any] | None, str | None]:
    """Classify a VAP's security mode for assignment to a 6 GHz radio.

    Returns ``(refusal, warning)``. A refusal is an error envelope the caller
    must return before writing anything; a warning rides along with a
    successful write.

    Every uncertain outcome warns rather than refuses, including a VAP that
    cannot be read, one that does not exist, and one whose ``security`` key
    is absent. Refusing an unreadable VAP would make 6 GHz targets stricter
    about dangling VAP names than radios 1 and 2, which stage them happily
    today, and that is a scope change rather than a guard.

    The VAP object carries encrypted credential blobs, so only ``security``
    is read out of it and the object itself is never logged or echoed.
    """
    try:
        stored = await client.get_device_vap(device=device, vdom=vdom, name=vap)
    except Exception as exc:  # noqa: BLE001 - any read failure warns, never refuses
        logger.warning(f"could not read VAP '{vap}' to check 6 GHz security: {exc}")
        return None, (
            f"Radio(s) {six_ghz_radios} are 6 GHz, which is WPA3-only, and VAP "
            f"'{vap}' could not be read to confirm its security mode. Staged "
            "anyway; the install will refuse it if the mode is wrong."
        )

    if isinstance(stored, list):
        stored = stored[0] if stored else {}
    security = stored.get("security") if isinstance(stored, dict) else None
    if isinstance(security, list):
        security = security[0] if len(security) == 1 else None
    if not isinstance(security, str) or not security.strip():
        return None, (
            f"Radio(s) {six_ghz_radios} are 6 GHz, which is WPA3-only, and VAP "
            f"'{vap}' did not report a security mode. Staged anyway; the "
            "install will refuse it if the mode is wrong."
        )

    mode = security.strip().lower()
    if mode in _VAP_6GHZ_REFUSED_MODES:
        return {
            "error": (
                f"VAP '{vap}' uses security '{mode}', which a 6 GHz radio does not "
                f"accept, and radio(s) {six_ghz_radios} are 6 GHz. Nothing was "
                "staged. Either drop those radios from the request, or assign a "
                "WPA3 VAP (wpa3-sae) or an OWE one."
            ),
            "error_code": "validation_error",
        }, None
    if mode in _VAP_6GHZ_KNOWN_GOOD:
        return None, None
    return None, (
        f"Radio(s) {six_ghz_radios} are 6 GHz and VAP '{vap}' uses security "
        f"'{mode}', which has not been confirmed on a 6 GHz radio. It may be "
        "refused at install; 6 GHz typically wants wpa3-sae or owe."
    )


def _strip_secret_fields(result: Any, secret_fields: frozenset[str]) -> Any:
    """Strip named credential fields from anything FMG echoes back.

    Recurses through dict VALUES as well as list items, at any depth. An
    earlier version of this (in the VAP tools this was lifted from) stripped
    top-level keys only, so a credential one level down survived the
    function whose entire purpose is that it cannot::

        {"data": {"passphrase": "..."}}   ->   passphrase survived

    That was latent rather than live there, since the echo was flat. It
    would not be latent for a nested table: ``wireless-controller
    wtp-profile`` carries ``radio-1``..``radio-4`` sub-objects, and
    ``sam-private-key-password`` lives inside those, not at the top level.
    The repo's own ``sanitize_for_logging`` recurses fully for the same
    reason: a sanitizer that depends on the shape it is handed is one
    response format away from leaking.

    ``secret_fields`` is matched against keys as-is (FortiOS field names,
    e.g. ``"passphrase"``, ``"login-passwd"``), not normalized, matching
    every other exact-key lookup in this module.
    """
    if isinstance(result, dict):
        return {
            k: _strip_secret_fields(v, secret_fields)
            for k, v in result.items()
            if k not in secret_fields
        }
    if isinstance(result, list):
        return [_strip_secret_fields(item, secret_fields) for item in result]
    return result


def _sanitize_vap_result(result: Any) -> Any:
    """Strip every credential field from a ``wireless-controller vap`` echo."""
    return _strip_secret_fields(result, _VAP_SECRET_FIELDS)


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

        # 6 GHz radios are WPA3-only, so a VAP with the wrong security mode
        # is rejected at install time, possibly bundled with unrelated
        # changes. Check before staging anything, and refuse the WHOLE call
        # rather than skipping the 6 GHz radio: a partial write is a silent
        # change of scope, which is worse than an explicit refusal.
        #
        # Keyed off the radio's band, never the radio index. The index does
        # not determine the band -- the schema offers the 6 GHz bands on
        # every index, and the maintainer retracted the opposite claim on #47
        # after checking a live 120G.
        six_ghz = {
            n
            for n in radios
            if isinstance(stored.get(f"radio-{n}"), dict) and _is_six_ghz(stored[f"radio-{n}"])
        }
        warning: str | None = None
        if six_ghz:
            # Only reached when a targeted radio really is 6 GHz, so the
            # 2.4/5 GHz path costs no extra round trip.
            refusal, warning = await _check_six_ghz_vap(client, device, vdom, vap, sorted(six_ghz))
            if refusal:
                return refusal

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
            # _carry_through_radio drops read-only bookkeeping keys ("oid",
            # "unset attrs") the API injects on GET but rejects on write --
            # see update_device_wtp_profile_radio for how this was found.
            data[key] = {**_carry_through_radio(radio), "vap-all": "manual", "vaps": merged}

        if not data:
            response: dict[str, Any] = {
                "success": True,
                "message": f"VAP '{vap}' already assigned to "
                f"radio(s) {radios} of profile '{profile}'.",
            }
            if warning:
                response["warning"] = warning
            return response

        result = await client.update_device_wtp_profile(
            device=device, vdom=vdom, name=profile, data=data
        )
        response = {
            "success": True,
            "message": f"VAP '{vap}' added to {', '.join(sorted(data))} of profile "
            f"'{profile}' in device DB of '{device}'. Push with "
            "install_device_settings.",
            "result": result,
        }
        if warning:
            response["warning"] = warning
        return response
    except Exception as e:
        logger.error(f"VAP assignment failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# WTP-profile radio configuration (device DB, vdom scope) (issue #52)
# =============================================================================

#: Credential fields FMG stores as ``type=password`` on ``wireless-controller
#: wtp-profile``. Confirmed against a live 7.6.x FMG (schema dump via
#: ``option=syntax`` plus a real read-back on the mcp-dev-test sandbox,
#: device FGT-MCP-TEST-01): every one of these came back as an ``ENC``-
#: prefixed blob, the same shape ``adm_pass`` had in the dvmdb-device fix.
#:
#: ``login-passwd`` is the FortiAP admin password, set when
#: ``login-passwd-change`` is ``yes``/``default`` -- the field this PR's
#: review flagged. The rest were found alongside it while confirming that
#: finding, via the same schema dump, and leak the same way for the same
#: reason, so they are stripped here too rather than left for a second
#: report: ``apcfg-auto-cert-est-http-password``/``apcfg-auto-cert-scep-
#: password`` (cert-enrollment passwords), ``apcfg-mesh-passwd`` (AP mesh
#: PSK), ``wan-port-auth-password`` (WAN port PPPoE/PAP auth), and
#: ``sam-private-key-password`` -- nested under each ``radio-1``..``radio-4``
#: sub-object rather than at the top level, which is exactly the case
#: ``_strip_secret_fields`` recurses for.
_WTP_PROFILE_SECRET_FIELDS = frozenset(
    {
        "login-passwd",
        "apcfg-auto-cert-est-http-password",
        "apcfg-auto-cert-scep-password",
        "apcfg-mesh-passwd",
        "wan-port-auth-password",
        "sam-private-key-password",
    }
)

#: Credential field FMG stores as ``type=password`` on ``wireless-controller
#: wtp`` (the per-AP override of the profile setting above). Confirmed the
#: same way: live read-back on FGT-MCP-TEST-01 with ``override-login-passwd-
#: change`` and ``login-passwd-change`` both set returned ``login-passwd`` as
#: an ``ENC``-prefixed blob.
_WTP_SECRET_FIELDS = frozenset({"login-passwd"})


def _sanitize_wtp_profile_result(result: Any) -> Any:
    """Strip every credential field from a ``wireless-controller wtp-profile`` echo."""
    return _strip_secret_fields(result, _WTP_PROFILE_SECRET_FIELDS)


def _sanitize_wtp_result(result: Any) -> Any:
    """Strip every credential field from a ``wireless-controller wtp`` echo."""
    return _strip_secret_fields(result, _WTP_SECRET_FIELDS)


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
        dict with device, vdom, count and profiles (credential fields
        stripped -- see _WTP_PROFILE_SECRET_FIELDS)
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
            "profiles": _sanitize_wtp_profile_result(profiles),
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
        dict with device, vdom and the stored profile object (credential
        fields stripped -- see _WTP_PROFILE_SECRET_FIELDS), or a not_found
        error if the profile does not exist
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
        return {"device": device, "vdom": vdom, "profile": _sanitize_wtp_profile_result(stored)}
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
    power, vap-all, vaps, mode, ...) is carried through unchanged, minus a
    couple of read-only bookkeeping keys the API injects on GET but rejects
    on write (see _WTP_RADIO_READONLY_KEYS). FortiManager replaces a nested
    radio object rather than merging into it, so writing back only
    channel/channel-bonding would reset the rest to defaults on the next
    install_device_settings.

    Args:
        device: Managed device name
        profile: FortiAP (WTP) profile name
        radio: Radio to update, 1-3
        channel: Channel(s) to pin the radio to. For radio 1/2 (2.4/5GHz)
            this is a single-element list, e.g. [36], to pin one channel.
            For radio 3 (6GHz) at a bonding width above 20MHz, FortiOS
            represents the wide channel as the full list of its member
            20MHz sub-channels rather than a single label -- pass either
            the single conventional wide-channel label (e.g. [15] for
            160MHz channel 15) and it is expanded to the correct member
            list automatically, or the explicit member list itself
            (e.g. [1, 5, 9, 13, 17, 21, 25, 29]).
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

        # radio-3 (6GHz) at bonding widths above 20MHz needs the channel
        # expressed as its full set of member 20MHz sub-channels, not a
        # single wide-channel label -- see _radio3_wide_channel_members.
        if channel is not None and channel_values is not None and radio == 3:
            effective_bonding = (
                channel_bonding if channel_bonding is not None else existing.get("channel-bonding")
            )
            width_mhz = _channel_bonding_mhz(effective_bonding)
            if width_mhz and width_mhz > 20:
                n = width_mhz // 20
                if len(channel) == 1:
                    members = _radio3_wide_channel_members(channel[0], width_mhz)
                    if members is None:
                        raise ValidationError(
                            f"channel {channel[0]} is not a valid 6GHz {width_mhz}MHz "
                            f"wide-channel label for radio-3 -- either pass a valid "
                            "center label (e.g. 15 or 47 at 160MHz) or the full list "
                            f"of {n} member 20MHz sub-channels"
                        )
                    channel_values = [str(c) for c in members]
                elif len(channel) != n:
                    raise ValidationError(
                        f"radio-3 at {width_mhz}MHz bonding needs either 1 value (a "
                        f"wide-channel label, e.g. 15) or exactly {n} values (the full "
                        f"list of member 20MHz sub-channels) -- got {len(channel)}"
                    )
                # else: caller already passed the explicit n-member list; trust it.

        # Carry the rest of the radio object through; see the docstring and
        # assign_vap_to_wtp_profile for why a partial write is unsafe here.
        # _carry_through_radio drops read-only bookkeeping keys ("oid",
        # "unset attrs") the API injects on GET but rejects on write.
        updated_radio = _carry_through_radio(existing)
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
        dict with device, vdom, count and wtps (device-DB objects keyed by
        wtp-id/serial, credential fields stripped -- see _WTP_SECRET_FIELDS)
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
            "wtps": _sanitize_wtp_result(wtps),
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
        dict with device, vdom and the stored wtp object (credential fields
        stripped -- see _WTP_SECRET_FIELDS), or a not_found error if it
        does not exist
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
        return {"device": device, "vdom": vdom, "wtp": _sanitize_wtp_result(stored)}
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

    Repointing wtp_profile drops a reference from the old profile.
    FortiManager prunes a wtp-profile that no wtp entry references on
    install (see create_device_wtp), so moving the last AP off a profile
    loses that profile on the next install_device_settings.

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

    This drops the AP's reference to its wtp-profile. FortiManager prunes a
    wtp-profile that no wtp entry references on install (see
    create_device_wtp), so deleting the last AP on a profile loses that
    profile on the next install_device_settings.

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
