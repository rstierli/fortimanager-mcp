"""VPN device-level configuration tools for FortiManager MCP.

Typed tools for configuring IPsec and SSL-VPN in a device's device DB:
IPsec ``phase1-interface`` (remote gateway) and ``phase2-interface``
(tunnel/selector) tables, plus the SSL-VPN (branded "Agentless VPN" in the
FortiOS 8.0 device-DB schema) ``vpn/ssl/settings`` object and
``vpn/ssl/web/portal`` table. Everything writes to the FMG device DB only;
nothing talks to the FortiGate directly. Push staged changes with
``preview_install`` followed by ``install_device_settings``, the same flow
``device_config_tools.py`` uses.

Field names follow the FortiOS cmdb tables the device DB mirrors
(``vpn ipsec phase1-interface``, ``vpn ipsec phase2-interface``,
``vpn ssl settings``, ``vpn ssl web portal``), verified against the FNDN
8.0.0 device-level config schema
(``docs/fndn/8.0.0/json_api_reference/html-internal/devobj80-161-objects.htm``).

Deliberately scoped down from the full schema, which runs to 100+ attributes
per table (see the FNDN doc above for the complete list): each tool exposes
the fields needed to stand up an ordinary route-based site-to-site tunnel or
SSL-VPN portal, plus the ones the field is a table master key or foreign key
(``interface``, ``phase1name``). Fields not exposed here are left at the
FortiOS device default when omitted, same as ``device_config_tools.py``
does for interfaces, DHCP scopes and VAPs.

Multi-select enums (``proposal``, ``dhgrp``) run to 30-80 named values in
the schema and are passed through largely unvalidated -- normalized for
case/whitespace only, same as ``allowaccess`` in ``device_config_tools.py``
-- rather than hardcoded here where they would go stale. Small, tool-logic-
relevant enums (gateway ``type``, ``ike_version``, ``mode``, ...) are
validated against the literal enum values the schema documents.
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

# =============================================================================
# Enum validation (small, tool-logic-relevant enums only -- see module docstring)
# =============================================================================

#: vpn.ipsec.phase1-interface "type" -- remote gateway type.
PHASE1_GATEWAY_TYPES = {"static", "dynamic", "ddns"}

#: vpn.ipsec.phase1-interface "ike-version".
PHASE1_IKE_VERSIONS = {"1", "2"}

#: vpn.ipsec.phase1-interface "mode" -- ID protection mode (IKEv1 only).
PHASE1_MODES = {"main", "aggressive"}

#: vpn.ipsec.phase1-interface "peertype".
PHASE1_PEER_TYPES = {"any", "one", "dialup", "peer", "peergrp"}

#: vpn.ipsec.phase1-interface "nattraversal".
PHASE1_NAT_TRAVERSAL = {"disable", "enable", "forced"}

#: vpn.ipsec.phase1-interface "dpd" -- Dead Peer Detection mode.
PHASE1_DPD_MODES = {"disable", "on-idle", "on-demand"}

#: Plain enable/disable "option" fields shared across several tables
#: (phase1 auto-negotiate; phase2 auto-negotiate/pfs/replay/keepalive;
#: ssl/settings status/reqclientcert/https-redirect; ssl/web/portal
#: tunnel-mode/split-tunneling/web-mode).
_ENABLE_DISABLE = {"disable", "enable"}


def _validate_choice(value: str, field: str, choices: set[str]) -> str:
    value = value.strip().lower()
    if value not in choices:
        raise ValidationError(f"{field} must be one of {sorted(choices)}, got '{value}'")
    return value


def _normalize_list(values: list[str]) -> list[str]:
    """Strip/lowercase a multi-select enum list without validating membership.

    ``proposal`` and ``dhgrp`` carry 30-80 named values apiece in the FNDN
    schema (see module docstring); hardcoding that vocabulary here would go
    stale, so it is left to FortiManager/FortiOS to reject an unknown name.
    """
    return [v.strip().lower() for v in values]


def _subnet_pair(subnet: str) -> list[str]:
    """Normalize an "IPv4 address/mask" field to the [address, netmask] pair
    the device DB stores for this type (same shape as "ip" on system
    interface -- see ``_ip_mask_pair`` in device_config_tools.py).

    Accepts CIDR ("192.0.2.0/24") or "address netmask" form.
    """
    subnet = validate_ipv4_subnet(subnet)
    if " " in subnet:
        addr, mask = subnet.split()
        return [addr, mask]
    iface = ipaddress.IPv4Interface(subnet)
    return [str(iface.ip), str(iface.network.netmask)]


# =============================================================================
# Credential stripping
# =============================================================================

#: Fields FMG stores as ``type=password`` on ``vpn ipsec phase1-interface``.
#: ``psksecret``/``psksecret-remote`` are the ones this module's create/update
#: tools set; ``authpasswd`` (XAuth), ``group-authentication-secret`` (IKEv2
#: IDi group auth) and ``ppk-secret`` (IKEv2 Postquantum PSK) are not
#: exposed as parameters here but are stripped too, on the same defense-in-
#: depth basis as ``_WTP_PROFILE_SECRET_FIELDS`` in device_config_tools.py:
#: a GET of an existing tunnel configured via the FortiOS CLI can still
#: return them.
_PHASE1_SECRET_FIELDS = frozenset(
    {
        "psksecret",
        "psksecret-remote",
        "authpasswd",
        "group-authentication-secret",
        "ppk-secret",
    }
)


def _strip_secret_fields(result: Any, secret_fields: frozenset[str]) -> Any:
    """Strip named credential fields from anything FMG echoes back.

    Recurses through dict values and list items at any depth -- see the
    identical helper in device_config_tools.py for why a shallow strip is
    not safe here either.
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


def _sanitize_phase1_result(result: Any) -> Any:
    """Strip every credential field from a ``vpn ipsec phase1-interface`` echo."""
    return _strip_secret_fields(result, _PHASE1_SECRET_FIELDS)


def _sslvpn_field_matches(sent: Any, stored: Any) -> bool:
    """Compare a sent update value against the re-fetched stored value.

    FMG sometimes echoes a list of plain strings as a list of
    ``{"name": ...}`` refs -- normalize before comparing so that shape
    difference alone doesn't look like a persistence failure.
    """
    if isinstance(sent, list) and isinstance(stored, list):
        stored_names = [s.get("name") if isinstance(s, dict) else s for s in stored]
        return sorted(sent) == sorted(n for n in stored_names if n is not None)
    return sent == stored


async def _check_sslvpn_web_portal_persisted(
    client: Any, device: str, vdom: str, name: str, sent_data: dict[str, Any]
) -> list[str]:
    """Re-read an SSL-VPN web portal after an update and return field names
    from ``sent_data`` whose stored value doesn't match what was sent.

    Best-effort: if the re-read itself fails, don't mask the original
    update's success with an unrelated read error -- just report nothing
    rather than raise.
    """
    try:
        stored = await client.get_device_sslvpn_web_portal(device=device, vdom=vdom, name=name)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict):
            return []
        return [
            field
            for field, sent_value in sent_data.items()
            if not _sslvpn_field_matches(sent_value, stored.get(field))
        ]
    except Exception:
        return []


# =============================================================================
# IPsec phase1-interface (remote gateway) (device DB, vdom scope)
# =============================================================================


@mcp.tool()
async def list_device_ipsec_phase1_interfaces(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """List IPsec phase1-interface (remote gateway) definitions in a device's device DB.

    Args:
        device: Managed device name
        vdom: VDOM to read (default "root")

    Returns:
        dict with device, vdom, count and interfaces (credential fields
        stripped -- see _PHASE1_SECRET_FIELDS)
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        interfaces = await client.list_device_ipsec_phase1_interfaces(device=device, vdom=vdom)
        interfaces = (
            interfaces if isinstance(interfaces, list) else [interfaces] if interfaces else []
        )
        return {
            "device": device,
            "vdom": vdom,
            "count": len(interfaces),
            "interfaces": _sanitize_phase1_result(interfaces),
        }
    except Exception as e:
        logger.error(f"IPsec phase1-interface list failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_device_ipsec_phase1_interface(
    device: str,
    name: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get one IPsec phase1-interface (remote gateway) from a device's device DB.

    Args:
        device: Managed device name
        name: Phase1-interface (remote gateway) name
        vdom: VDOM it lives in (default "root")

    Returns:
        dict with device, vdom and the stored object (credential fields
        stripped -- see _PHASE1_SECRET_FIELDS), or a not_found error
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase1-interface")
        stored = await client.get_device_ipsec_phase1_interface(device=device, vdom=vdom, name=name)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict) or not stored:
            return {
                "error": f"phase1-interface '{name}' not found or returned no configuration",
                "error_code": "not_found",
            }
        return {"device": device, "vdom": vdom, "phase1_interface": _sanitize_phase1_result(stored)}
    except Exception as e:
        logger.error(f"IPsec phase1-interface read failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_device_ipsec_phase1_interface(
    device: str,
    name: str,
    interface: str,
    type: str = "static",  # noqa: A002 - mirrors the FortiOS field name
    remote_gw: str | None = None,
    psksecret: str | None = None,
    ike_version: str | None = None,
    mode: str | None = None,
    peertype: str | None = None,
    proposal: list[str] | None = None,
    dhgrp: list[str] | None = None,
    nattraversal: str | None = None,
    dpd: str | None = None,
    keylife: int | None = None,
    comments: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Create an IPsec phase1-interface (remote gateway / IKE SA) in a device's device DB.

    Route-based (interface-mode) tunnel only -- this always writes an
    ``interface`` (the outgoing local interface), matching the
    ``phase1-interface`` table this tool targets rather than the legacy
    policy-based ``phase1`` table.

    Args:
        device: Managed device name
        name: New phase1-interface (remote gateway) name
        interface: Local physical/aggregate/loopback/VLAN outgoing interface
        type: Remote gateway type: "static", "dynamic" or "ddns"; default "static"
        remote_gw: Remote gateway's external IPv4 address. Required when
            type is "static" -- a static gateway with no address cannot
            connect
        psksecret: Pre-shared key for PSK authentication, 6-128 characters
        ike_version: IKE protocol version, "1" or "2"
        mode: IKEv1 ID protection mode: "main" or "aggressive" (ignored on IKEv2)
        peertype: Peer ID acceptance: "any", "one", "dialup", "peer" or "peergrp".
            Defaults to "any" when type is "static" and no value is given --
            live-verified against FMG 7.6.7: a static PSK gateway created
            without peertype is rejected with "peer invalid value", so this
            tool supplies the working default rather than surfacing that
            error to the caller
        proposal: Phase1 encryption/authentication proposal list (e.g.
            ["aes256-sha256"]). Values are passed through to FortiManager
            largely unvalidated -- see module docstring
        dhgrp: Phase1 Diffie-Hellman group list (e.g. ["14", "21"]). Same
            pass-through as proposal
        nattraversal: NAT traversal: "disable", "enable" or "forced"
        dpd: Dead Peer Detection mode: "disable", "on-idle" or "on-demand"
        keylife: Phase1 key life in seconds
        comments: Free-text comment
        vdom: VDOM the gateway lives in (default "root")

    Returns:
        Creation result with any echoed credential stripped
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase1-interface")
        interface = validate_interface_name(interface)
        type = _validate_choice(type, "type", PHASE1_GATEWAY_TYPES)

        data: dict[str, Any] = {"name": name, "interface": interface, "type": type}

        if type == "static":
            if remote_gw is None:
                raise ValidationError("remote_gw is required when type is 'static'")
            data["remote-gw"] = validate_ipv4_address(remote_gw)
        elif remote_gw is not None:
            data["remote-gw"] = validate_ipv4_address(remote_gw)

        if psksecret is not None:
            if not 6 <= len(psksecret) <= 128:
                raise ValidationError("psksecret must be 6-128 characters")
            data["psksecret"] = psksecret
        if ike_version is not None:
            data["ike-version"] = _validate_choice(ike_version, "ike_version", PHASE1_IKE_VERSIONS)
        if mode is not None:
            data["mode"] = _validate_choice(mode, "mode", PHASE1_MODES)
        if peertype is None and type == "static":
            peertype = "any"
        if peertype is not None:
            data["peertype"] = _validate_choice(peertype, "peertype", PHASE1_PEER_TYPES)
        if proposal:
            data["proposal"] = _normalize_list(proposal)
        if dhgrp:
            data["dhgrp"] = _normalize_list(dhgrp)
        if nattraversal is not None:
            data["nattraversal"] = _validate_choice(
                nattraversal, "nattraversal", PHASE1_NAT_TRAVERSAL
            )
        if dpd is not None:
            data["dpd"] = _validate_choice(dpd, "dpd", PHASE1_DPD_MODES)
        if keylife is not None:
            if keylife <= 0:
                raise ValidationError(f"keylife must be positive, got {keylife}")
            data["keylife"] = keylife
        if comments is not None:
            data["comments"] = comments

        result = await client.create_device_ipsec_phase1_interface(
            device=device, vdom=vdom, data=data
        )
        return {
            "success": True,
            "message": f"Phase1-interface '{name}' created in device DB of '{device}'. "
            "Add a phase2-interface (create_device_ipsec_phase2_interface), then push "
            "with install_device_settings.",
            "result": _sanitize_phase1_result(result),
        }
    except Exception as e:
        logger.error(f"IPsec phase1-interface create failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_ipsec_phase1_interface(
    device: str,
    name: str,
    interface: str | None = None,
    type: str | None = None,  # noqa: A002
    remote_gw: str | None = None,
    psksecret: str | None = None,
    ike_version: str | None = None,
    mode: str | None = None,
    peertype: str | None = None,
    proposal: list[str] | None = None,
    dhgrp: list[str] | None = None,
    nattraversal: str | None = None,
    dpd: str | None = None,
    keylife: int | None = None,
    comments: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Update fields on a device-DB IPsec phase1-interface. Only provided fields change.

    Args:
        device: Managed device name
        name: Phase1-interface (remote gateway) name to update
        interface: New local outgoing interface
        type: New remote gateway type: "static", "dynamic" or "ddns"
        remote_gw: New remote gateway IPv4 address
        psksecret: New pre-shared key, 6-128 characters
        ike_version: New IKE protocol version, "1" or "2"
        mode: New IKEv1 ID protection mode: "main" or "aggressive"
        peertype: New peer ID acceptance mode
        proposal: Replacement phase1 proposal list
        dhgrp: Replacement phase1 DH group list
        nattraversal: New NAT traversal setting
        dpd: New Dead Peer Detection mode
        keylife: New phase1 key life in seconds
        comments: New free-text comment
        vdom: VDOM the gateway lives in (default "root")

    Returns:
        Update result with any echoed credential stripped
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase1-interface")

        data: dict[str, Any] = {}
        if interface is not None:
            data["interface"] = validate_interface_name(interface)
        if type is not None:
            data["type"] = _validate_choice(type, "type", PHASE1_GATEWAY_TYPES)
        if remote_gw is not None:
            data["remote-gw"] = validate_ipv4_address(remote_gw)
        if psksecret is not None:
            if not 6 <= len(psksecret) <= 128:
                raise ValidationError("psksecret must be 6-128 characters")
            data["psksecret"] = psksecret
        if ike_version is not None:
            data["ike-version"] = _validate_choice(ike_version, "ike_version", PHASE1_IKE_VERSIONS)
        if mode is not None:
            data["mode"] = _validate_choice(mode, "mode", PHASE1_MODES)
        if peertype is not None:
            data["peertype"] = _validate_choice(peertype, "peertype", PHASE1_PEER_TYPES)
        if proposal is not None:
            data["proposal"] = _normalize_list(proposal)
        if dhgrp is not None:
            data["dhgrp"] = _normalize_list(dhgrp)
        if nattraversal is not None:
            data["nattraversal"] = _validate_choice(
                nattraversal, "nattraversal", PHASE1_NAT_TRAVERSAL
            )
        if dpd is not None:
            data["dpd"] = _validate_choice(dpd, "dpd", PHASE1_DPD_MODES)
        if keylife is not None:
            if keylife <= 0:
                raise ValidationError(f"keylife must be positive, got {keylife}")
            data["keylife"] = keylife
        if comments is not None:
            data["comments"] = comments

        if not data:
            return {"error": "No update parameters provided"}

        result = await client.update_device_ipsec_phase1_interface(
            device=device, vdom=vdom, name=name, data=data
        )
        return {
            "success": True,
            "message": f"Phase1-interface '{name}' updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": _sanitize_phase1_result(result),
        }
    except Exception as e:
        logger.error(f"IPsec phase1-interface update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_device_ipsec_phase1_interface(
    device: str,
    name: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Delete an IPsec phase1-interface from a device's device DB.

    Any phase2-interface still pointing at this phase1name should be
    deleted first (delete_device_ipsec_phase2_interface) -- FortiManager
    rejects deleting a phase1-interface a phase2-interface still references.

    Args:
        device: Managed device name
        name: Phase1-interface (remote gateway) name to delete
        vdom: VDOM it lives in (default "root")

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase1-interface")
        result = await client.delete_device_ipsec_phase1_interface(
            device=device, vdom=vdom, name=name
        )
        return {
            "success": True,
            "message": f"Phase1-interface '{name}' deleted from device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"IPsec phase1-interface delete failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# IPsec phase2-interface (tunnel / traffic selector) (device DB, vdom scope)
# =============================================================================


@mcp.tool()
async def list_device_ipsec_phase2_interfaces(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """List IPsec phase2-interface (tunnel/selector) definitions in a device's device DB.

    Args:
        device: Managed device name
        vdom: VDOM to read (default "root")

    Returns:
        dict with device, vdom, count and interfaces
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        interfaces = await client.list_device_ipsec_phase2_interfaces(device=device, vdom=vdom)
        interfaces = (
            interfaces if isinstance(interfaces, list) else [interfaces] if interfaces else []
        )
        return {
            "device": device,
            "vdom": vdom,
            "count": len(interfaces),
            "interfaces": interfaces,
        }
    except Exception as e:
        logger.error(f"IPsec phase2-interface list failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_device_ipsec_phase2_interface(
    device: str,
    name: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get one IPsec phase2-interface (tunnel/selector) from a device's device DB.

    Args:
        device: Managed device name
        name: Phase2-interface (tunnel) name
        vdom: VDOM it lives in (default "root")

    Returns:
        dict with device, vdom and the stored object, or a not_found error
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase2-interface")
        stored = await client.get_device_ipsec_phase2_interface(device=device, vdom=vdom, name=name)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict) or not stored:
            return {
                "error": f"phase2-interface '{name}' not found or returned no configuration",
                "error_code": "not_found",
            }
        return {"device": device, "vdom": vdom, "phase2_interface": stored}
    except Exception as e:
        logger.error(f"IPsec phase2-interface read failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_device_ipsec_phase2_interface(
    device: str,
    name: str,
    phase1name: str,
    src_subnet: str | None = None,
    dst_subnet: str | None = None,
    proposal: list[str] | None = None,
    dhgrp: list[str] | None = None,
    pfs: str | None = None,
    replay: str | None = None,
    keepalive: str | None = None,
    auto_negotiate: str | None = None,
    keylifeseconds: int | None = None,
    comments: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Create an IPsec phase2-interface (tunnel/traffic selector) in a device's device DB.

    Args:
        device: Managed device name
        name: New phase2-interface (tunnel) name
        phase1name: Parent phase1-interface (remote gateway) name this
            tunnel is negotiated under
        src_subnet: Local proxy ID subnet, CIDR ("192.168.1.0/24") or
            "address netmask" form. Omitted means the FortiOS default
            (0.0.0.0/0, the whole local network)
        dst_subnet: Remote proxy ID subnet, same accepted forms. Omitted
            means the FortiOS default (0.0.0.0/0)
        proposal: Phase2 encryption/authentication proposal list (e.g.
            ["aes256-sha256"]). Pass-through, see module docstring
        dhgrp: Phase2 PFS Diffie-Hellman group list. Pass-through, see
            module docstring
        pfs: Perfect Forward Secrecy: "disable" or "enable"
        replay: Replay detection: "disable" or "enable"
        keepalive: Keep-alive: "disable" or "enable"
        auto_negotiate: IPsec SA auto-negotiation: "disable" or "enable"
        keylifeseconds: Phase2 key life in seconds (120-172800)
        comments: Free-text comment
        vdom: VDOM the tunnel lives in (default "root")

    Returns:
        Creation result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase2-interface")
        phase1name = validate_object_name(phase1name, "phase1-interface")

        data: dict[str, Any] = {"name": name, "phase1name": phase1name}

        if src_subnet is not None:
            data["src-subnet"] = _subnet_pair(src_subnet)
        if dst_subnet is not None:
            data["dst-subnet"] = _subnet_pair(dst_subnet)
        if proposal:
            data["proposal"] = _normalize_list(proposal)
        if dhgrp:
            data["dhgrp"] = _normalize_list(dhgrp)
        if pfs is not None:
            data["pfs"] = _validate_choice(pfs, "pfs", _ENABLE_DISABLE)
        if replay is not None:
            data["replay"] = _validate_choice(replay, "replay", _ENABLE_DISABLE)
        if keepalive is not None:
            data["keepalive"] = _validate_choice(keepalive, "keepalive", _ENABLE_DISABLE)
        if auto_negotiate is not None:
            data["auto-negotiate"] = _validate_choice(
                auto_negotiate, "auto_negotiate", _ENABLE_DISABLE
            )
        if keylifeseconds is not None:
            if not 120 <= keylifeseconds <= 172800:
                raise ValidationError(f"keylifeseconds must be 120-172800, got {keylifeseconds}")
            data["keylifeseconds"] = keylifeseconds
        if comments is not None:
            data["comments"] = comments

        result = await client.create_device_ipsec_phase2_interface(
            device=device, vdom=vdom, data=data
        )
        return {
            "success": True,
            "message": f"Phase2-interface '{name}' (under phase1 '{phase1name}') created "
            f"in device DB of '{device}'. Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"IPsec phase2-interface create failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_ipsec_phase2_interface(
    device: str,
    name: str,
    phase1name: str | None = None,
    src_subnet: str | None = None,
    dst_subnet: str | None = None,
    proposal: list[str] | None = None,
    dhgrp: list[str] | None = None,
    pfs: str | None = None,
    replay: str | None = None,
    keepalive: str | None = None,
    auto_negotiate: str | None = None,
    keylifeseconds: int | None = None,
    comments: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Update fields on a device-DB IPsec phase2-interface. Only provided fields change.

    Args:
        device: Managed device name
        name: Phase2-interface (tunnel) name to update
        phase1name: New parent phase1-interface name
        src_subnet: New local proxy ID subnet, CIDR or "address netmask" form
        dst_subnet: New remote proxy ID subnet, same accepted forms
        proposal: Replacement phase2 proposal list
        dhgrp: Replacement phase2 DH group list
        pfs: New Perfect Forward Secrecy setting
        replay: New replay detection setting
        keepalive: New keep-alive setting
        auto_negotiate: New IPsec SA auto-negotiation setting
        keylifeseconds: New phase2 key life in seconds (120-172800)
        comments: New free-text comment
        vdom: VDOM the tunnel lives in (default "root")

    Returns:
        Update result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase2-interface")

        data: dict[str, Any] = {}
        if phase1name is not None:
            data["phase1name"] = validate_object_name(phase1name, "phase1-interface")
        if src_subnet is not None:
            data["src-subnet"] = _subnet_pair(src_subnet)
        if dst_subnet is not None:
            data["dst-subnet"] = _subnet_pair(dst_subnet)
        if proposal is not None:
            data["proposal"] = _normalize_list(proposal)
        if dhgrp is not None:
            data["dhgrp"] = _normalize_list(dhgrp)
        if pfs is not None:
            data["pfs"] = _validate_choice(pfs, "pfs", _ENABLE_DISABLE)
        if replay is not None:
            data["replay"] = _validate_choice(replay, "replay", _ENABLE_DISABLE)
        if keepalive is not None:
            data["keepalive"] = _validate_choice(keepalive, "keepalive", _ENABLE_DISABLE)
        if auto_negotiate is not None:
            data["auto-negotiate"] = _validate_choice(
                auto_negotiate, "auto_negotiate", _ENABLE_DISABLE
            )
        if keylifeseconds is not None:
            if not 120 <= keylifeseconds <= 172800:
                raise ValidationError(f"keylifeseconds must be 120-172800, got {keylifeseconds}")
            data["keylifeseconds"] = keylifeseconds
        if comments is not None:
            data["comments"] = comments

        if not data:
            return {"error": "No update parameters provided"}

        result = await client.update_device_ipsec_phase2_interface(
            device=device, vdom=vdom, name=name, data=data
        )
        return {
            "success": True,
            "message": f"Phase2-interface '{name}' updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"IPsec phase2-interface update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_device_ipsec_phase2_interface(
    device: str,
    name: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Delete an IPsec phase2-interface from a device's device DB.

    Args:
        device: Managed device name
        name: Phase2-interface (tunnel) name to delete
        vdom: VDOM it lives in (default "root")

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "phase2-interface")
        result = await client.delete_device_ipsec_phase2_interface(
            device=device, vdom=vdom, name=name
        )
        return {
            "success": True,
            "message": f"Phase2-interface '{name}' deleted from device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"IPsec phase2-interface delete failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# SSL-VPN settings (device DB, vdom scope, singleton object)
# =============================================================================

#: vpn.ssl.settings "ssl-min-proto-ver" / "ssl-max-proto-ver".
SSLVPN_TLS_VERSIONS = {"tls1-0", "tls1-1", "tls1-2", "tls1-3"}


@mcp.tool()
async def get_device_sslvpn_settings(
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get the SSL-VPN (Agentless VPN) settings object from a device's device DB.

    This is a per-vdom singleton -- there is exactly one, so no list/create/
    delete tools exist for it, matching the FNDN schema's "object" (not
    "table") classification.

    Args:
        device: Managed device name
        vdom: VDOM to read (default "root")

    Returns:
        dict with device, vdom and the stored settings object
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        stored = await client.get_device_sslvpn_settings(device=device, vdom=vdom)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        return {
            "device": device,
            "vdom": vdom,
            "settings": stored if isinstance(stored, dict) else {},
        }
    except Exception as e:
        logger.error(f"SSL-VPN settings read failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_sslvpn_settings(
    device: str,
    status: str | None = None,
    port: int | None = None,
    source_interface: list[str] | None = None,
    default_portal: str | None = None,
    servercert: str | None = None,
    idle_timeout: int | None = None,
    auth_timeout: int | None = None,
    dns_server1: str | None = None,
    dns_server2: str | None = None,
    reqclientcert: str | None = None,
    https_redirect: str | None = None,
    ssl_min_proto_ver: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Update the SSL-VPN (Agentless VPN) settings object in a device's device DB.

    Only provided fields change -- see get_device_sslvpn_settings for the
    current state to base a partial update on.

    Args:
        device: Managed device name
        status: Enable/disable SSL-VPN: "disable" or "enable"
        port: SSL-VPN access port (1-65535)
        source_interface: Source interface names of incoming traffic
        default_portal: Default web portal name (see
            update_device_sslvpn_web_portal)
        servercert: Server certificate name to present to clients
        idle_timeout: Idle timeout in seconds before disconnect
        auth_timeout: Authentication timeout in seconds (1-259200, 0 = no timeout)
        dns_server1: Primary DNS server handed to clients
        dns_server2: Secondary DNS server handed to clients
        reqclientcert: Require client certificates: "disable" or "enable"
        https_redirect: Redirect port 80 to the SSL-VPN port: "disable" or "enable"
        ssl_min_proto_ver: Minimum TLS version: "tls1-0", "tls1-1", "tls1-2" or "tls1-3"
        vdom: VDOM the settings apply to (default "root")

    Returns:
        Update result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")

        data: dict[str, Any] = {}
        if status is not None:
            data["status"] = _validate_choice(status, "status", _ENABLE_DISABLE)
        if port is not None:
            if not 1 <= port <= 65535:
                raise ValidationError(f"port must be 1-65535, got {port}")
            data["port"] = port
        if source_interface is not None:
            data["source-interface"] = [validate_interface_name(i) for i in source_interface]
        if default_portal is not None:
            data["default-portal"] = validate_object_name(default_portal, "portal")
        if servercert is not None:
            data["servercert"] = servercert
        if idle_timeout is not None:
            if idle_timeout < 0:
                raise ValidationError(f"idle_timeout cannot be negative, got {idle_timeout}")
            data["idle-timeout"] = idle_timeout
        if auth_timeout is not None:
            if not 0 <= auth_timeout <= 259200:
                raise ValidationError(f"auth_timeout must be 0-259200, got {auth_timeout}")
            data["auth-timeout"] = auth_timeout
        if dns_server1 is not None:
            data["dns-server1"] = validate_ipv4_address(dns_server1)
        if dns_server2 is not None:
            data["dns-server2"] = validate_ipv4_address(dns_server2)
        if reqclientcert is not None:
            data["reqclientcert"] = _validate_choice(
                reqclientcert, "reqclientcert", _ENABLE_DISABLE
            )
        if https_redirect is not None:
            data["https-redirect"] = _validate_choice(
                https_redirect, "https_redirect", _ENABLE_DISABLE
            )
        if ssl_min_proto_ver is not None:
            data["ssl-min-proto-ver"] = _validate_choice(
                ssl_min_proto_ver, "ssl_min_proto_ver", SSLVPN_TLS_VERSIONS
            )

        if not data:
            return {"error": "No update parameters provided"}

        result = await client.update_device_sslvpn_settings(device=device, vdom=vdom, data=data)
        return {
            "success": True,
            "message": f"SSL-VPN settings updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }
    except Exception as e:
        logger.error(f"SSL-VPN settings update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# SSL-VPN web portal (device DB, vdom scope)
# =============================================================================


@mcp.tool()
async def get_device_sslvpn_web_portal(
    device: str,
    name: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Get an SSL-VPN web portal from a device's device DB.

    Args:
        device: Managed device name
        name: Web portal name
        vdom: VDOM it lives in (default "root")

    Returns:
        dict with device, vdom and the stored portal object, or a not_found error
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "portal")
        stored = await client.get_device_sslvpn_web_portal(device=device, vdom=vdom, name=name)
        if isinstance(stored, list):
            stored = stored[0] if stored else {}
        if not isinstance(stored, dict) or not stored:
            return {
                "error": f"SSL-VPN web portal '{name}' not found or returned no configuration",
                "error_code": "not_found",
            }
        return {"device": device, "vdom": vdom, "portal": stored}
    except Exception as e:
        logger.error(f"SSL-VPN web portal read failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def update_device_sslvpn_web_portal(
    device: str,
    name: str,
    tunnel_mode: str | None = None,
    split_tunneling: str | None = None,
    ip_pools: list[str] | None = None,
    web_mode: str | None = None,
    dns_server1: str | None = None,
    dns_server2: str | None = None,
    vdom: str = "root",
) -> dict[str, Any]:
    """Update an SSL-VPN web portal in a device's device DB.

    The portal itself must already exist in the device DB (created via the
    FortiOS CLI/GUI or a prior install) -- this tool only updates an
    existing entry, matching the "get/update" scope of this module. Only
    provided fields change.

    Args:
        device: Managed device name
        name: Web portal name to update
        tunnel_mode: Enable/disable full-tunnel mode: "disable" or "enable"
        split_tunneling: Enable/disable split tunneling: "disable" or "enable"
        ip_pools: Firewall address/address-group names to draw tunnel-mode
            client IPs from
        web_mode: Enable/disable web-mode (clientless HTML5) access:
            "disable" or "enable"
        dns_server1: Primary DNS server handed to portal clients
        dns_server2: Secondary DNS server handed to portal clients
        vdom: VDOM the portal lives in (default "root")

    Returns:
        Update result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        name = validate_object_name(name, "portal")

        data: dict[str, Any] = {}
        if tunnel_mode is not None:
            data["tunnel-mode"] = _validate_choice(tunnel_mode, "tunnel_mode", _ENABLE_DISABLE)
        if split_tunneling is not None:
            data["split-tunneling"] = _validate_choice(
                split_tunneling, "split_tunneling", _ENABLE_DISABLE
            )
        if ip_pools is not None:
            data["ip-pools"] = [validate_object_name(p, "address") for p in ip_pools]
        if web_mode is not None:
            data["web-mode"] = _validate_choice(web_mode, "web_mode", _ENABLE_DISABLE)
        if dns_server1 is not None:
            data["dns-server1"] = validate_ipv4_address(dns_server1)
        if dns_server2 is not None:
            data["dns-server2"] = validate_ipv4_address(dns_server2)

        if not data:
            return {"error": "No update parameters provided"}

        result = await client.update_device_sslvpn_web_portal(
            device=device, vdom=vdom, name=name, data=data
        )
        response: dict[str, Any] = {
            "success": True,
            "message": f"SSL-VPN web portal '{name}' updated in device DB of '{device}'. "
            "Push with install_device_settings.",
            "result": result,
        }

        # FMG 7.6.7 live-verified quirk: an update to this object can return
        # code 0 (success) while some fields (seen: tunnel-mode,
        # split-tunneling, dns-server1/2) silently don't persist. Re-read
        # and diff against what we sent so a caller isn't misled by a
        # success response that didn't actually change anything.
        not_persisted = await _check_sslvpn_web_portal_persisted(client, device, vdom, name, data)
        if not_persisted:
            response["warning"] = (
                f"{len(not_persisted)} field(s) did not persist after update: "
                f"{', '.join(not_persisted)} -- known FortiOS/FMG quirk on some "
                "fields for this object, verify manually or re-apply."
            )
        return response
    except Exception as e:
        logger.error(f"SSL-VPN web portal update failed on {device}: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}
