"""Advanced security-profile management tools for FortiManager.

Based on FNDN FortiManager 8.0.0 PM/config API specifications
(docs/fndn/8.0.0/json_api_reference/swagger/cdb-obj80.json). Provides
CRUD operations for four ADOM-scoped security-profile object types:
- IPS sensors (config ips sensor), including add/remove of a signature
  override entry within a sensor
- SSL/SSH inspection profiles (config firewall ssl-ssh-profile)
- DLP profiles (config dlp profile)
- WAF profiles (config waf profile)

All operations here are pure ADOM policy-object CRUD -- nothing writes to
a device DB and nothing installs to a live device. A profile only takes
effect on a FortiGate once it is referenced by a firewall policy and that
policy package is installed (see policy_tools.py / device_config_tools.py
for the install_package/preview_install flow).
"""

import logging
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import ValidationError, client_safe_error
from fortimanager_mcp.utils.validation import (
    validate_adom,
    validate_object_name,
    validate_status,
)

logger = logging.getLogger(__name__)


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


def _validate_enum(value: str, allowed: set[str], field_name: str) -> str:
    """Validate a value against a fixed set of API enum options.

    The shared validate_status() helper only covers plain enable/disable
    toggles (VALID_POLICY_STATUSES); the object types in this module also
    carry three- and four-way enums (e.g. ips.sensor.entries "action" is
    pass/block/reset/default) that need their own membership check against
    the exact enum values documented in the swagger definitions.
    """
    if not value:
        raise ValidationError(f"{field_name} cannot be empty")

    value = value.strip().lower()
    if value not in allowed:
        raise ValidationError(
            f"Invalid {field_name} '{value}'. Valid values: {', '.join(sorted(allowed))}"
        )
    return value


# =============================================================================
# IPS Sensor
# =============================================================================

# pm.config.ips.sensor.scan-botnet-connections
_IPS_BOTNET_SCAN_MODES = {"disable", "block", "monitor"}
# pm.config.ips.sensor.entries.status
_IPS_ENTRY_STATUSES = {"disable", "enable", "default"}
# pm.config.ips.sensor.entries.action
_IPS_ENTRY_ACTIONS = {"pass", "block", "reset", "default"}
# pm.config.ips.sensor.entries.default-status
_IPS_ENTRY_DEFAULT_STATUSES = {"disable", "enable", "all"}
# pm.config.ips.sensor.entries.default-action
_IPS_ENTRY_DEFAULT_ACTIONS = {"block", "pass", "all"}


@mcp.tool()
async def list_ips_sensors(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List IPS sensors in an ADOM.

    IPS sensors are collections of intrusion-prevention signature filters
    and overrides, referenced by firewall policies for the "IPS" security
    profile.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Sensor list with keys:
            - status: "success" or "error"
            - count: Number of sensors
            - sensors: List of IPS sensor objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])

        sensors = await client.list_ips_sensors(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(sensors),
            "sensors": sensors,
        }
    except Exception as e:
        logger.error(f"Failed to list IPS sensors: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_ips_sensor(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about an IPS sensor.

    Args:
        adom: ADOM name
        name: IPS sensor name

    Returns:
        dict: Sensor details with keys:
            - status: "success" or "error"
            - sensor: Full sensor configuration, including its "entries"
              list of signature filters/overrides
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "IPS sensor")
        client = _get_client()
        sensor = await client.get_ips_sensor(adom, name)

        return {
            "status": "success",
            "sensor": sensor,
        }
    except Exception as e:
        logger.error(f"Failed to get IPS sensor {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_ips_sensor(
    adom: str,
    name: str,
    comment: str | None = None,
    block_malicious_url: str | None = None,
    scan_botnet_connections: str | None = None,
    extended_log: str | None = None,
) -> dict[str, Any]:
    """Create an IPS sensor.

    The sensor is created empty (no signature filters/overrides). Use
    add_ips_sensor_signature_override to populate it afterward.

    Args:
        adom: ADOM name
        name: Sensor name
        comment: Optional comment
        block_malicious_url: Enable/disable malicious URL blocking
            ("enable" or "disable")
        scan_botnet_connections: Botnet-server connection handling
            ("disable", "block", or "monitor")
        extended_log: Enable/disable extended logging ("enable" or "disable")

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created sensor name
            - message: Status or error message

    Example:
        >>> result = await create_ips_sensor(
        ...     adom="root",
        ...     name="Custom-IPS",
        ...     scan_botnet_connections="block",
        ...     comment="Baseline IPS sensor",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "IPS sensor")
        if block_malicious_url is not None:
            block_malicious_url = validate_status(block_malicious_url)
        if scan_botnet_connections is not None:
            scan_botnet_connections = _validate_enum(
                scan_botnet_connections, _IPS_BOTNET_SCAN_MODES, "scan_botnet_connections"
            )
        if extended_log is not None:
            extended_log = validate_status(extended_log)
        client = _get_client()

        sensor: dict[str, Any] = {"name": name}
        if comment:
            sensor["comment"] = comment
        if block_malicious_url is not None:
            sensor["block-malicious-url"] = block_malicious_url
        if scan_botnet_connections is not None:
            sensor["scan-botnet-connections"] = scan_botnet_connections
        if extended_log is not None:
            sensor["extended-log"] = extended_log

        await client.create_ips_sensor(adom, sensor)

        return {
            "status": "success",
            "name": name,
            "message": f"IPS sensor {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create IPS sensor {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_ips_sensor(
    adom: str,
    name: str,
    comment: str | None = None,
    block_malicious_url: str | None = None,
    scan_botnet_connections: str | None = None,
    extended_log: str | None = None,
) -> dict[str, Any]:
    """Update an IPS sensor's top-level settings.

    Only specified fields will be updated. To change signature
    filters/overrides use add_ips_sensor_signature_override /
    remove_ips_sensor_signature_override instead.

    Args:
        adom: ADOM name
        name: Sensor name
        comment: New comment
        block_malicious_url: Enable/disable malicious URL blocking
        scan_botnet_connections: Botnet-server connection handling
            ("disable", "block", or "monitor")
        extended_log: Enable/disable extended logging

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "IPS sensor")
        if block_malicious_url is not None:
            block_malicious_url = validate_status(block_malicious_url)
        if scan_botnet_connections is not None:
            scan_botnet_connections = _validate_enum(
                scan_botnet_connections, _IPS_BOTNET_SCAN_MODES, "scan_botnet_connections"
            )
        if extended_log is not None:
            extended_log = validate_status(extended_log)
        client = _get_client()

        data: dict[str, Any] = {}
        if comment is not None:
            data["comment"] = comment
        if block_malicious_url is not None:
            data["block-malicious-url"] = block_malicious_url
        if scan_botnet_connections is not None:
            data["scan-botnet-connections"] = scan_botnet_connections
        if extended_log is not None:
            data["extended-log"] = extended_log

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_ips_sensor(adom, name, data)

        return {
            "status": "success",
            "message": f"IPS sensor {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update IPS sensor {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_ips_sensor(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete an IPS sensor.

    WARNING: This will fail if the sensor is in use by policies.

    Args:
        adom: ADOM name
        name: Sensor name to delete

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "IPS sensor")
        client = _get_client()
        await client.delete_ips_sensor(adom, name)

        return {
            "status": "success",
            "message": f"IPS sensor {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete IPS sensor {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def list_ips_sensor_signature_overrides(
    adom: str,
    sensor: str,
) -> dict[str, Any]:
    """List the signature-filter/override entries of an IPS sensor.

    Each entry is either a broad filter (matched by severity/protocol/OS/...)
    or a specific signature override (matched by an explicit "rule" list of
    signature names). Use the returned "id" values with
    remove_ips_sensor_signature_override.

    Args:
        adom: ADOM name
        sensor: IPS sensor name

    Returns:
        dict: Entry list with keys:
            - status: "success" or "error"
            - count: Number of entries
            - entries: List of entry objects
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        sensor = validate_object_name(sensor, "IPS sensor")
        client = _get_client()
        entries = await client.list_ips_sensor_entries(adom, sensor)

        return {
            "status": "success",
            "count": len(entries),
            "entries": entries,
        }
    except Exception as e:
        logger.error(f"Failed to list signature overrides of IPS sensor {sensor}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def add_ips_sensor_signature_override(
    adom: str,
    sensor: str,
    rule: list[str] | None = None,
    entry_id: int | None = None,
    status: str = "enable",
    action: str = "default",
    log: str | None = None,
    log_packet: str | None = None,
    severity: list[str] | None = None,
    default_action: str | None = None,
    default_status: str | None = None,
) -> dict[str, Any]:
    """Add a signature filter/override entry to an IPS sensor.

    FortiManager exposes an IPS sensor's "entries" list as its own
    addressable nested collection (its own add/get/set/update/delete/move
    endpoints under .../sensor/{sensor}/entries), so this calls that
    sub-resource's ADD endpoint directly rather than reading the whole
    sensor, splicing the list in Python, and writing it back -- unlike
    update_device_wtp_profile_radio's device-DB radio field, which has no
    such sub-resource and must be read-modify-written as a whole object.

    Pass `rule` with explicit signature names to override specific
    signatures (e.g. ["trojan.generic"]); omit it and use `severity` /
    `default_action` / `default_status` to add a broad filter entry
    instead (matches every signature meeting those criteria).

    Args:
        adom: ADOM name
        sensor: IPS sensor name (must already exist -- see create_ips_sensor)
        rule: Specific signature names to override (optional; omit for a
            broad filter entry)
        entry_id: Explicit entry ID (0-4294967295). If omitted, FortiManager
            assigns the next available ID.
        status: Status of the entry ("disable", "enable", or "default";
            default: "enable")
        action: Action for matched traffic ("pass", "block", "reset", or
            "default"; default: "default")
        log: Enable/disable logging for this entry ("enable" or "disable")
        log_packet: Enable/disable packet logging for this entry
            ("enable" or "disable")
        severity: Signature severities to match (e.g. ["critical", "high"])
        default_action: Broad-filter action filter ("block", "pass", or "all")
        default_status: Broad-filter status filter ("disable", "enable", or
            "all")

    Returns:
        dict: Add result with keys:
            - status: "success" or "error"
            - sensor: Sensor name
            - message: Status or error message

    Example:
        >>> # Override a specific signature to block+log
        >>> result = await add_ips_sensor_signature_override(
        ...     adom="root",
        ...     sensor="Custom-IPS",
        ...     rule=["trojan.generic"],
        ...     status="enable",
        ...     action="block",
        ...     log="enable",
        ... )

        >>> # Add a broad "block all critical signatures" filter
        >>> result = await add_ips_sensor_signature_override(
        ...     adom="root",
        ...     sensor="Custom-IPS",
        ...     severity=["critical"],
        ...     default_action="block",
        ...     status="enable",
        ...     action="block",
        ... )
    """
    try:
        adom = validate_adom(adom)
        sensor = validate_object_name(sensor, "IPS sensor")
        status = _validate_enum(status, _IPS_ENTRY_STATUSES, "status")
        action = _validate_enum(action, _IPS_ENTRY_ACTIONS, "action")
        if log is not None:
            log = validate_status(log)
        if log_packet is not None:
            log_packet = validate_status(log_packet)
        if default_action is not None:
            default_action = _validate_enum(
                default_action, _IPS_ENTRY_DEFAULT_ACTIONS, "default_action"
            )
        if default_status is not None:
            default_status = _validate_enum(
                default_status, _IPS_ENTRY_DEFAULT_STATUSES, "default_status"
            )
        if entry_id is not None and not (0 <= entry_id <= 4294967295):
            raise ValidationError(f"entry_id must be 0-4294967295, got {entry_id}")
        client = _get_client()

        entry: dict[str, Any] = {
            "status": status,
            "action": action,
        }
        if entry_id is not None:
            entry["id"] = entry_id
        if rule:
            entry["rule"] = rule
        if log is not None:
            entry["log"] = log
        if log_packet is not None:
            entry["log-packet"] = log_packet
        if severity:
            entry["severity"] = severity
        if default_action is not None:
            entry["default-action"] = default_action
        if default_status is not None:
            entry["default-status"] = default_status

        await client.add_ips_sensor_entry(adom, sensor, entry)

        return {
            "status": "success",
            "sensor": sensor,
            "message": f"Signature override added to IPS sensor {sensor}",
        }
    except Exception as e:
        logger.error(f"Failed to add signature override to IPS sensor {sensor}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def remove_ips_sensor_signature_override(
    adom: str,
    sensor: str,
    entry_id: int,
) -> dict[str, Any]:
    """Remove a signature filter/override entry from an IPS sensor.

    Use list_ips_sensor_signature_overrides to find the entry's "id"
    first if it is not already known.

    Args:
        adom: ADOM name
        sensor: IPS sensor name
        entry_id: ID of the entry to remove (as returned in its "id" field)

    Returns:
        dict: Remove result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        sensor = validate_object_name(sensor, "IPS sensor")
        if not (0 <= entry_id <= 4294967295):
            raise ValidationError(f"entry_id must be 0-4294967295, got {entry_id}")
        client = _get_client()
        await client.delete_ips_sensor_entry(adom, sensor, entry_id)

        return {
            "status": "success",
            "message": f"Signature override {entry_id} removed from IPS sensor {sensor}",
        }
    except Exception as e:
        logger.error(f"Failed to remove signature override from IPS sensor {sensor}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# SSL/SSH Inspection Profile
# =============================================================================

# pm.config.firewall.ssl-ssh-profile.ssl.inspect-all /
# pm.config.firewall.ssl-ssh-profile.https.status
_SSL_INSPECTION_LEVELS = {"disable", "certificate-inspection", "deep-inspection"}
# pm.config.firewall.ssl-ssh-profile.server-cert-mode
_SSL_SERVER_CERT_MODES = {"re-sign", "replace"}


@mcp.tool()
async def list_ssl_ssh_profiles(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List SSL/SSH inspection profiles in an ADOM.

    SSL/SSH inspection profiles control how a FortiGate decrypts and
    inspects TLS/SSH traffic, referenced by firewall policies for the
    "SSL/SSH Inspection" security profile.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Profile list with keys:
            - status: "success" or "error"
            - count: Number of profiles
            - profiles: List of SSL/SSH profile objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])

        profiles = await client.list_ssl_ssh_profiles(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(profiles),
            "profiles": profiles,
        }
    except Exception as e:
        logger.error(f"Failed to list SSL/SSH profiles: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_ssl_ssh_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about an SSL/SSH inspection profile.

    Args:
        adom: ADOM name
        name: SSL/SSH profile name

    Returns:
        dict: Profile details with keys:
            - status: "success" or "error"
            - profile: Full profile configuration
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "SSL/SSH profile")
        client = _get_client()
        profile = await client.get_ssl_ssh_profile(adom, name)

        return {
            "status": "success",
            "profile": profile,
        }
    except Exception as e:
        logger.error(f"Failed to get SSL/SSH profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


def _build_ssl_ssh_profile_data(
    comment: str | None,
    ssl_inspection: str | None,
    https_inspection: str | None,
    caname: list[str] | None,
    untrusted_caname: list[str] | None,
    server_cert: list[str] | None,
    server_cert_mode: str | None,
    mapi_over_https: str | None,
    rpc_over_https: str | None,
) -> dict[str, Any]:
    """Assemble the writable subset of an ssl-ssh-profile payload.

    Shared by create and update so both stay in sync on which fields are
    exposed. `ssl_inspection`/`https_inspection` map onto the profile's
    nested "ssl"/"https" sub-objects rather than top-level keys.

    PR #65 review (Christian, 08-18) raised this as the same read-modify-
    write risk class as the wtp-profile radio bug (#64): if FMG replaces a
    nested sub-object wholesale on write, sending only "inspect-all"/
    "status" here would reset every other field on "ssl"/"https" (there
    are 13+ others -- min-allowed-ssl-version, unsupported-ssl-cipher,
    etc.) to their defaults. Live-tested against the FGT-MCP-TEST-01/
    mcp-dev-test sandbox (2026-08-19) to check: a sibling field
    (unsupported-ssl-cipher) was set to a non-default value, then this
    tool's update path was called touching only inspect-all, then
    re-read -- the sibling field was unchanged. Unlike the wtp-profile
    radio object, FortiManager merges into "ssl"/"https" on
    firewall.ssl-ssh-profile rather than replacing it, so a single-key
    write here is safe in practice. (The old wording here claimed the
    same "replaces wholesale" premise as the radio case but concluded
    it was safe anyway, which was backwards reasoning that happened to
    reach the right answer for the wrong reason -- corrected.)
    """
    data: dict[str, Any] = {}
    if comment is not None:
        data["comment"] = comment
    if ssl_inspection is not None:
        data["ssl"] = {"inspect-all": ssl_inspection}
    if https_inspection is not None:
        data["https"] = {"status": https_inspection}
    if caname is not None:
        data["caname"] = caname
    if untrusted_caname is not None:
        data["untrusted-caname"] = untrusted_caname
    if server_cert is not None:
        data["server-cert"] = server_cert
    if server_cert_mode is not None:
        data["server-cert-mode"] = server_cert_mode
    if mapi_over_https is not None:
        data["mapi-over-https"] = mapi_over_https
    if rpc_over_https is not None:
        data["rpc-over-https"] = rpc_over_https
    return data


@mcp.tool()
async def create_ssl_ssh_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    ssl_inspection: str | None = None,
    https_inspection: str | None = None,
    caname: list[str] | None = None,
    untrusted_caname: list[str] | None = None,
    server_cert: list[str] | None = None,
    server_cert_mode: str | None = None,
    mapi_over_https: str | None = None,
    rpc_over_https: str | None = None,
) -> dict[str, Any]:
    """Create an SSL/SSH inspection profile.

    Args:
        adom: ADOM name
        name: Profile name
        comment: Optional comment
        ssl_inspection: Generic SSL inspection level ("disable",
            "certificate-inspection", or "deep-inspection")
        https_inspection: HTTPS inspection level ("disable",
            "certificate-inspection", or "deep-inspection")
        caname: CA certificate(s) used for SSL inspection (datasource names)
        untrusted_caname: Untrusted CA certificate(s) (datasource names)
        server_cert: Certificate(s) used to replace the server certificate
            (datasource names; only used when server_cert_mode="replace")
        server_cert_mode: Re-sign or replace the server's certificate
            ("re-sign" or "replace")
        mapi_over_https: Enable/disable inspection of MAPI over HTTPS
        rpc_over_https: Enable/disable inspection of RPC over HTTPS

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created profile name
            - message: Status or error message

    Example:
        >>> result = await create_ssl_ssh_profile(
        ...     adom="root",
        ...     name="Custom-Deep-Inspection",
        ...     ssl_inspection="deep-inspection",
        ...     https_inspection="deep-inspection",
        ...     server_cert_mode="re-sign",
        ...     comment="Deep inspection for outbound web traffic",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "SSL/SSH profile")
        if ssl_inspection is not None:
            ssl_inspection = _validate_enum(
                ssl_inspection, _SSL_INSPECTION_LEVELS, "ssl_inspection"
            )
        if https_inspection is not None:
            https_inspection = _validate_enum(
                https_inspection, _SSL_INSPECTION_LEVELS, "https_inspection"
            )
        if server_cert_mode is not None:
            server_cert_mode = _validate_enum(
                server_cert_mode, _SSL_SERVER_CERT_MODES, "server_cert_mode"
            )
        if mapi_over_https is not None:
            mapi_over_https = validate_status(mapi_over_https)
        if rpc_over_https is not None:
            rpc_over_https = validate_status(rpc_over_https)
        client = _get_client()

        profile = _build_ssl_ssh_profile_data(
            comment=comment,
            ssl_inspection=ssl_inspection,
            https_inspection=https_inspection,
            caname=caname,
            untrusted_caname=untrusted_caname,
            server_cert=server_cert,
            server_cert_mode=server_cert_mode,
            mapi_over_https=mapi_over_https,
            rpc_over_https=rpc_over_https,
        )
        profile["name"] = name

        await client.create_ssl_ssh_profile(adom, profile)

        return {
            "status": "success",
            "name": name,
            "message": f"SSL/SSH profile {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create SSL/SSH profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_ssl_ssh_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    ssl_inspection: str | None = None,
    https_inspection: str | None = None,
    caname: list[str] | None = None,
    untrusted_caname: list[str] | None = None,
    server_cert: list[str] | None = None,
    server_cert_mode: str | None = None,
    mapi_over_https: str | None = None,
    rpc_over_https: str | None = None,
) -> dict[str, Any]:
    """Update an SSL/SSH inspection profile.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: Profile name
        comment: New comment
        ssl_inspection: Generic SSL inspection level ("disable",
            "certificate-inspection", or "deep-inspection")
        https_inspection: HTTPS inspection level ("disable",
            "certificate-inspection", or "deep-inspection")
        caname: New CA certificate(s) (datasource names, replaces existing)
        untrusted_caname: New untrusted CA certificate(s) (replaces existing)
        server_cert: New server certificate(s) (replaces existing)
        server_cert_mode: Re-sign or replace the server's certificate
        mapi_over_https: Enable/disable inspection of MAPI over HTTPS
        rpc_over_https: Enable/disable inspection of RPC over HTTPS

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "SSL/SSH profile")
        if ssl_inspection is not None:
            ssl_inspection = _validate_enum(
                ssl_inspection, _SSL_INSPECTION_LEVELS, "ssl_inspection"
            )
        if https_inspection is not None:
            https_inspection = _validate_enum(
                https_inspection, _SSL_INSPECTION_LEVELS, "https_inspection"
            )
        if server_cert_mode is not None:
            server_cert_mode = _validate_enum(
                server_cert_mode, _SSL_SERVER_CERT_MODES, "server_cert_mode"
            )
        if mapi_over_https is not None:
            mapi_over_https = validate_status(mapi_over_https)
        if rpc_over_https is not None:
            rpc_over_https = validate_status(rpc_over_https)
        client = _get_client()

        data = _build_ssl_ssh_profile_data(
            comment=comment,
            ssl_inspection=ssl_inspection,
            https_inspection=https_inspection,
            caname=caname,
            untrusted_caname=untrusted_caname,
            server_cert=server_cert,
            server_cert_mode=server_cert_mode,
            mapi_over_https=mapi_over_https,
            rpc_over_https=rpc_over_https,
        )

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_ssl_ssh_profile(adom, name, data)

        return {
            "status": "success",
            "message": f"SSL/SSH profile {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update SSL/SSH profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_ssl_ssh_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete an SSL/SSH inspection profile.

    WARNING: This will fail if the profile is in use by policies.

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
        name = validate_object_name(name, "SSL/SSH profile")
        client = _get_client()
        await client.delete_ssl_ssh_profile(adom, name)

        return {
            "status": "success",
            "message": f"SSL/SSH profile {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete SSL/SSH profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# DLP Profile
# =============================================================================

# pm.config.dlp.profile.feature-set
_DLP_FEATURE_SETS = {"flow", "proxy"}


@mcp.tool()
async def list_dlp_profiles(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List DLP (Data Loss Prevention) profiles in an ADOM.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Profile list with keys:
            - status: "success" or "error"
            - count: Number of profiles
            - profiles: List of DLP profile objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])

        profiles = await client.list_dlp_profiles(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(profiles),
            "profiles": profiles,
        }
    except Exception as e:
        logger.error(f"Failed to list DLP profiles: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_dlp_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about a DLP profile.

    Args:
        adom: ADOM name
        name: DLP profile name

    Returns:
        dict: Profile details with keys:
            - status: "success" or "error"
            - profile: Full profile configuration
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "DLP profile")
        client = _get_client()
        profile = await client.get_dlp_profile(adom, name)

        return {
            "status": "success",
            "profile": profile,
        }
    except Exception as e:
        logger.error(f"Failed to get DLP profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_dlp_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    feature_set: str | None = None,
    dlp_log: str | None = None,
    extended_log: str | None = None,
) -> dict[str, Any]:
    """Create a DLP (Data Loss Prevention) profile.

    The profile is created without rules. Rule management (config dlp
    profile / rule) is out of scope for this tool; add rules via the
    FortiManager GUI/CLI or a follow-up tool once this profile exists.

    Args:
        adom: ADOM name
        name: Profile name
        comment: Optional comment
        feature_set: Flow or proxy-based inspection ("flow" or "proxy")
        dlp_log: Enable/disable DLP logging ("enable" or "disable")
        extended_log: Enable/disable extended logging ("enable" or "disable")

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created profile name
            - message: Status or error message

    Example:
        >>> result = await create_dlp_profile(
        ...     adom="root",
        ...     name="Custom-DLP",
        ...     feature_set="flow",
        ...     dlp_log="enable",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "DLP profile")
        if feature_set is not None:
            feature_set = _validate_enum(feature_set, _DLP_FEATURE_SETS, "feature_set")
        if dlp_log is not None:
            dlp_log = validate_status(dlp_log)
        if extended_log is not None:
            extended_log = validate_status(extended_log)
        client = _get_client()

        profile: dict[str, Any] = {"name": name}
        if comment:
            profile["comment"] = comment
        if feature_set is not None:
            profile["feature-set"] = feature_set
        if dlp_log is not None:
            profile["dlp-log"] = dlp_log
        if extended_log is not None:
            profile["extended-log"] = extended_log

        await client.create_dlp_profile(adom, profile)

        return {
            "status": "success",
            "name": name,
            "message": f"DLP profile {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create DLP profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_dlp_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    feature_set: str | None = None,
    dlp_log: str | None = None,
    extended_log: str | None = None,
) -> dict[str, Any]:
    """Update a DLP profile's top-level settings.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: Profile name
        comment: New comment
        feature_set: Flow or proxy-based inspection ("flow" or "proxy")
        dlp_log: Enable/disable DLP logging
        extended_log: Enable/disable extended logging

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "DLP profile")
        if feature_set is not None:
            feature_set = _validate_enum(feature_set, _DLP_FEATURE_SETS, "feature_set")
        if dlp_log is not None:
            dlp_log = validate_status(dlp_log)
        if extended_log is not None:
            extended_log = validate_status(extended_log)
        client = _get_client()

        data: dict[str, Any] = {}
        if comment is not None:
            data["comment"] = comment
        if feature_set is not None:
            data["feature-set"] = feature_set
        if dlp_log is not None:
            data["dlp-log"] = dlp_log
        if extended_log is not None:
            data["extended-log"] = extended_log

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_dlp_profile(adom, name, data)

        return {
            "status": "success",
            "message": f"DLP profile {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update DLP profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_dlp_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a DLP profile.

    WARNING: This will fail if the profile is in use by policies.

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
        name = validate_object_name(name, "DLP profile")
        client = _get_client()
        await client.delete_dlp_profile(adom, name)

        return {
            "status": "success",
            "message": f"DLP profile {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete DLP profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# WAF Profile
# =============================================================================


@mcp.tool()
async def list_waf_profiles(
    adom: str | None = None,
    name_filter: str | None = None,
) -> dict[str, Any]:
    """List WAF (Web Application Firewall) profiles in an ADOM.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        name_filter: Filter by name (partial match)

    Returns:
        dict: Profile list with keys:
            - status: "success" or "error"
            - count: Number of profiles
            - profiles: List of WAF profile objects
            - message: Error message if failed
    """
    adom = adom or get_default_adom()
    try:
        adom = validate_adom(adom)
        client = _get_client()

        filters = []
        if name_filter:
            filters.append(["name", "contain", name_filter])

        profiles = await client.list_waf_profiles(
            adom=adom,
            filter=filters if filters else None,
        )

        return {
            "status": "success",
            "count": len(profiles),
            "profiles": profiles,
        }
    except Exception as e:
        logger.error(f"Failed to list WAF profiles: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_waf_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get detailed information about a WAF profile.

    Args:
        adom: ADOM name
        name: WAF profile name

    Returns:
        dict: Profile details with keys:
            - status: "success" or "error"
            - profile: Full profile configuration
            - message: Error message if failed
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "WAF profile")
        client = _get_client()
        profile = await client.get_waf_profile(adom, name)

        return {
            "status": "success",
            "profile": profile,
        }
    except Exception as e:
        logger.error(f"Failed to get WAF profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def create_waf_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    external: str | None = None,
    extended_log: str | None = None,
) -> dict[str, Any]:
    """Create a WAF (Web Application Firewall) profile.

    The profile is created with FortiManager/FortiOS defaults for its
    nested signature/constraint/method/url-access sections. Fine-grained
    control of those sections is out of scope for this tool; adjust them
    via the FortiManager GUI/CLI or a follow-up tool once this profile
    exists.

    Args:
        adom: ADOM name
        name: Profile name
        comment: Optional comment
        external: Enable/disable external HTTP inspection
            ("enable" or "disable")
        extended_log: Enable/disable extended logging ("enable" or "disable")

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - name: Created profile name
            - message: Status or error message

    Example:
        >>> result = await create_waf_profile(
        ...     adom="root",
        ...     name="Custom-WAF",
        ...     extended_log="enable",
        ...     comment="Baseline WAF profile",
        ... )
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "WAF profile")
        if external is not None:
            external = validate_status(external)
        if extended_log is not None:
            extended_log = validate_status(extended_log)
        client = _get_client()

        profile: dict[str, Any] = {"name": name}
        if comment:
            profile["comment"] = comment
        if external is not None:
            profile["external"] = external
        if extended_log is not None:
            profile["extended-log"] = extended_log

        await client.create_waf_profile(adom, profile)

        return {
            "status": "success",
            "name": name,
            "message": f"WAF profile {name} created successfully",
        }
    except Exception as e:
        logger.error(f"Failed to create WAF profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def update_waf_profile(
    adom: str,
    name: str,
    comment: str | None = None,
    external: str | None = None,
    extended_log: str | None = None,
) -> dict[str, Any]:
    """Update a WAF profile's top-level settings.

    Only specified fields will be updated.

    Args:
        adom: ADOM name
        name: Profile name
        comment: New comment
        external: Enable/disable external HTTP inspection
        extended_log: Enable/disable extended logging

    Returns:
        dict: Update result with keys:
            - status: "success" or "error"
            - message: Status or error message
    """
    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "WAF profile")
        if external is not None:
            external = validate_status(external)
        if extended_log is not None:
            extended_log = validate_status(extended_log)
        client = _get_client()

        data: dict[str, Any] = {}
        if comment is not None:
            data["comment"] = comment
        if external is not None:
            data["external"] = external
        if extended_log is not None:
            data["extended-log"] = extended_log

        if not data:
            return {"status": "error", "message": "No update parameters provided"}

        await client.update_waf_profile(adom, name, data)

        return {
            "status": "success",
            "message": f"WAF profile {name} updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update WAF profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def delete_waf_profile(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a WAF profile.

    WARNING: This will fail if the profile is in use by policies.

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
        name = validate_object_name(name, "WAF profile")
        client = _get_client()
        await client.delete_waf_profile(adom, name)

        return {
            "status": "success",
            "message": f"WAF profile {name} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete WAF profile {name}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
