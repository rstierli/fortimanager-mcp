"""FortiManager-itself operations tools (not device operations).

Covers operations that act on the FortiManager appliance's own system state
-- backup/restore, packet capture (sniffer) lifecycle, license status, and
task-record cleanup -- as distinct from device DB / policy-package paths
that push configuration to managed FortiGates. None of the endpoints here
touch a device, so the install_device_settings/install_package +
preview_install gate (device_config_tools.py, system_tools.py) does not
apply: there is nothing to preview or install, only FMG's own state.

Based on FNDN FortiManager 8.0.0 SYS and CLI API specifications:
- docs/fndn/8.0.0/json_api_reference/swagger/sys.json
  (paths "/sys/backup (exec)", "/sys/restore (exec)"; definitions
  sys.backup, resp.sys.backup, sys.restore)
- docs/fndn/8.0.0/json_api_reference/swagger/cli.json
  (paths "/cli/global/system/sniffer (get)"/"(add)"; definition
  cli.system.sniffer)
- docs/fndn/8.0.0/json_api_reference/swagger/task.json
  (paths "/task/task (get)", "/task/task/{task} (get)")
- docs/fndn/8.0.0/json_api_reference/json/system_syntax.json
  (obj.backup, obj.restore -- confirms the same fields as the swagger)
- docs/fndn/8.0.0/json_api_reference/json/fmg_cmdb_syntax.json
  (obj["/system/sniffer"] -- confirms sniffer fields id, interface, host,
  port, protocol, vlan, ipv6, non-ip, max-packet-count)
- docs/fndn/8.0.0/json_api_reference/json/fmg_task_syntax.json
  (obj.task -- type "table", mkey "id", confirming /task/task/{id} is a
  standard CRUD table object)
- How-To guide: "docs/guides/FortiManager API - How-To
  Guide/howto_jsonrpc_api-main/017_fmg_operations.rst" -- sections "How to
  backup the FortiManager?", "How to restore the FortiManager?", "How to
  delete a task?", "FortiManager Packet capture" (add/start/restart/stop/
  progress), and "How to get the FortiManager license?". The packet-capture
  exec actions (start/restart/stop/progress) and the /um/license/self exec
  call are not present in the bundled swagger/json syntax files at all --
  they are sourced from this How-To guide's own tested request/response
  pairs, which is the authoritative source available for them.

Scope note -- two items named in the original ask were investigated and
deliberately NOT implemented here, because they are not JSON-RPC operations
at all and cannot work through FortiManagerClient (which wraps pyfmg's
JSON-RPC session only):

- Downloading a packet capture file. The How-To guide's own "How to
  download a FortiManager packet capture?" section (011_alternative_
  fortimanager_api.rst) shows this is a GUI proxy HTTP GET
  (``/flatui/api/gui/sniff/export``) authenticated with a browser cookie
  jar + ``Xsrf-Token`` header -- a different transport than the JSON-RPC
  session this client speaks.
- Retrieving FMG event logs. Same guide, "How to get the FortiManager Event
  Logs?" section: the only documented path is
  ``POST /cgi-bin/module/flatui_proxy`` with ``url: "/gui/sys/event-log"``,
  again the cookie+Xsrf-Token GUI proxy, not ``/sys/jsonrpc``.

Building either against the plain JSON-RPC client would mean guessing at a
request shape never verified for it -- exactly the class of mistake this
codebase has been burned by before. Adding cookie-session support to
FortiManagerClient is a real option but is a client-level transport change,
out of scope for this tools-file-only change; flagged as a follow-up.

These tools call FortiManagerClient's generic get/add/execute/delete methods
directly (rather than adding new per-operation methods to api/client.py),
matching the pattern already used by security_profile_tools.py to keep this
new surface self-contained in one file.
"""

import logging
import re
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_settings
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import ValidationError, validate_interface_name

logger = logging.getLogger(__name__)

# Transfer protocols accepted by /sys/backup and /sys/restore (swagger
# sys.json: sys.backup.service / sys.restore.service enum).
_REMOTE_SERVICES = {"ftp", "scp", "sftp", "tftp"}

# Remote backup/restore server: a hostname or IPv4/IPv6 literal, not an FMG
# object -- deliberately not validate_fqdn/validate_ipv4_address (both too
# narrow: one rejects bare hostnames without a dot, the other rejects IPv6).
_REMOTE_HOST_PATTERN = re.compile(r"[A-Za-z0-9.\-:]{1,255}")

# Remote path pattern for the /sys/backup and /sys/restore "filename" field.
# Deliberately not validate_filename() -- that helper strips "/" for
# local-filesystem safety, but this field is a path on the *remote*
# FTP/SCP/SFTP/TFTP server (the How-To guide's own example is
# "tmp/fmg_backup.dat"), so "/" must stay allowed as a path separator. This
# only screens out control characters and shell/CLI injection metacharacters
# before they reach a JSON-RPC field.
_REMOTE_PATH_PATTERN = re.compile(r"[\w.\-/ ]{1,255}")


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


def _validate_remote_service(service: str) -> str:
    """Validate the backup/restore transfer protocol."""
    service = (service or "").strip().lower()
    if service not in _REMOTE_SERVICES:
        raise ValidationError(
            f"Invalid transfer service '{service}'. Must be one of: "
            + ", ".join(sorted(_REMOTE_SERVICES))
        )
    return service


def _validate_remote_host(server: str) -> str:
    """Validate a remote FTP/SCP/SFTP/TFTP server address."""
    server = (server or "").strip()
    if not server:
        raise ValidationError("Remote server address cannot be empty")
    if not _REMOTE_HOST_PATTERN.fullmatch(server):
        raise ValidationError(f"Invalid remote server address '{server}'")
    return server


def _validate_remote_path(path: str, field_name: str) -> str:
    """Validate a remote file path for /sys/backup and /sys/restore."""
    path = (path or "").strip()
    if not path:
        raise ValidationError(f"{field_name} cannot be empty")
    if not _REMOTE_PATH_PATTERN.fullmatch(path):
        raise ValidationError(
            f"Invalid {field_name} '{path}': only alphanumeric, '.', '-', '_', "
            "'/' and spaces are allowed (max 255 characters)"
        )
    return path


def _validate_port(port: int | None) -> int | None:
    """Validate an optional remote-server port number."""
    if port is None:
        return None
    if not (1 <= port <= 65535):
        raise ValidationError(f"Invalid port {port}: must be between 1 and 65535")
    return port


# =============================================================================
# Backup / Restore
# =============================================================================


@mcp.tool()
async def trigger_fmg_backup(
    service: str,
    server: str,
    filename: str,
    username: str | None = None,
    userpasswd: str | None = None,
    port: int | None = None,
    passwd: str | None = None,
) -> dict[str, Any]:
    """Trigger a FortiManager system backup to a remote server.

    Starts an asynchronous backup of the FortiManager's own configuration to
    an external FTP/SCP/SFTP/TFTP server. This is a FortiManager-itself
    operation -- it does not touch any managed device. Use wait_for_task()
    or get_task() (system_tools.py) to monitor completion; once done, the
    backup file is on the remote server at the given filename.

    Args:
        service: Transfer protocol - "ftp", "scp", "sftp", or "tftp"
        server: Remote server hostname or IP address
        filename: Destination path and file name on the remote server
            (e.g. "tmp/fmg_backup.dat")
        username: Login username for the remote server (required for ftp/
            scp/sftp; optional)
        userpasswd: Login password for the remote server (optional)
        port: Remote server port (optional; protocol default used if unset)
        passwd: Password to encrypt the backup file with (optional; FMG
            7.0.11+/7.2.5+/7.4.2+ no longer allow an unencrypted backup)

    Returns:
        dict: Backup result with keys:
            - status: "success" or "error"
            - task_id: Task ID for monitoring (if returned)
            - message: Status or error message

    Example:
        >>> result = await trigger_fmg_backup(
        ...     service="ftp",
        ...     server="10.210.35.207",
        ...     filename="tmp/fmg_backup.dat",
        ...     username="tiger",
        ...     userpasswd="fortinet",
        ...     passwd="fortinet",
        ... )
        >>> if result["status"] == "success":
        ...     await wait_for_task(result["task_id"])
    """
    try:
        service = _validate_remote_service(service)
        server = _validate_remote_host(server)
        filename = _validate_remote_path(filename, "filename")
        port = _validate_port(port)

        client = _get_client()
        data: dict[str, Any] = {
            "service": service,
            "server": server,
            "filename": filename,
        }
        if username:
            data["username"] = username
        if userpasswd:
            data["userpasswd"] = userpasswd
        if port is not None:
            data["port"] = port
        if passwd:
            data["passwd"] = passwd

        result = await client.execute("/sys/backup", data=data)
        task_id = result.get("taskid") if isinstance(result, dict) else None

        return {
            "status": "success",
            "task_id": task_id,
            "message": (
                f"FortiManager backup to {server} via {service} started"
                + (f", task ID: {task_id}" if task_id is not None else "")
            ),
        }
    except Exception as e:
        logger.error(f"Failed to trigger FortiManager backup: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def trigger_fmg_restore(
    service: str,
    server: str,
    filename: str,
    username: str | None = None,
    userpasswd: str | None = None,
    port: int | None = None,
    passwd: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Restore the FortiManager system from a backup on a remote server.

    Restores the FortiManager's own configuration from a backup file
    previously uploaded to an external FTP/SCP/SFTP/TFTP server (see
    trigger_fmg_backup). This is a disruptive, FortiManager-itself
    operation -- it does not touch any managed device, but it does REPLACE
    FMG's ENTIRE configuration and will interrupt the FMG service.

    Safety: governed by FMG_RESTORE_SAFETY (default "strict"). Under
    strict, this call is refused unless confirm=True is also passed --
    unlike install_package (gated by a verified preview) or firewall
    policy writes (gated by content screening), there is no dry-run or
    content check possible for a restore, so the gate is a plain explicit
    confirmation instead. Set FMG_RESTORE_SAFETY=disabled to remove the
    gate entirely.

    Args:
        service: Transfer protocol - "ftp", "scp", "sftp", or "tftp"
        server: Remote server hostname or IP address
        filename: Path and file name of the backup on the remote server
        username: Login username for the remote server (optional)
        userpasswd: Login password for the remote server (optional)
        port: Remote server port (optional; protocol default used if unset)
        passwd: Password to decrypt the backup file, if it was encrypted
            (optional)
        confirm: Must be True to proceed under FMG_RESTORE_SAFETY=strict
            (default). Ignored when FMG_RESTORE_SAFETY=disabled.

    Returns:
        dict: Restore result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await trigger_fmg_restore(
        ...     service="ftp",
        ...     server="10.210.35.207",
        ...     filename="tmp/fmg_backup.dat",
        ...     username="tiger",
        ...     userpasswd="fortinet",
        ...     confirm=True,
        ... )
    """
    try:
        settings = get_settings()
        if settings.FMG_RESTORE_SAFETY == "strict" and not confirm:
            logger.warning("FortiManager restore blocked — confirm=True not passed")
            return {
                "status": "error",
                "message": "Restore refused: this replaces FortiManager's entire "
                "configuration and interrupts the service. Pass confirm=True to "
                "proceed, or set FMG_RESTORE_SAFETY=disabled to remove this gate.",
                "error_code": "confirmation_required",
            }

        service = _validate_remote_service(service)
        server = _validate_remote_host(server)
        filename = _validate_remote_path(filename, "filename")
        port = _validate_port(port)

        client = _get_client()
        data: dict[str, Any] = {
            "service": service,
            "server": server,
            "filename": filename,
        }
        if username:
            data["username"] = username
        if userpasswd:
            data["userpasswd"] = userpasswd
        if port is not None:
            data["port"] = port
        if passwd:
            data["passwd"] = passwd

        await client.execute("/sys/restore", data=data)

        return {
            "status": "success",
            "message": f"FortiManager restore from {server} via {service} started",
        }
    except Exception as e:
        logger.error(f"Failed to trigger FortiManager restore: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Packet Capture (Sniffer)
# =============================================================================


@mcp.tool()
async def list_packet_captures() -> dict[str, Any]:
    """List existing FortiManager packet capture definitions.

    Returns the packet capture (sniffer) definitions configured on the
    FortiManager itself, for traffic originating or destined to the FMG.
    These are configuration records, not live capture results -- use
    get_packet_capture_status() for running/packet-count state.

    Returns:
        dict: Capture list with keys:
            - status: "success" or "error"
            - count: Number of capture definitions
            - captures: List of capture objects (id, interface, host, port,
              protocol, vlan, ipv6, non-ip, max-packet-count)
            - message: Error message if failed

    Example:
        >>> result = await list_packet_captures()
        >>> for cap in result["captures"]:
        ...     print(f"{cap['id']}: {cap['interface']}")
    """
    try:
        client = _get_client()
        result = await client.get("/cli/global/system/sniffer")
        captures = result if isinstance(result, list) else [result] if result else []
        return {
            "status": "success",
            "count": len(captures),
            "captures": captures,
        }
    except Exception as e:
        logger.error(f"Failed to list packet captures: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def add_packet_capture(
    interface: str,
    host: str | None = None,
    port: str | None = None,
    protocol: str | None = None,
    vlan: str | None = None,
    capture_ipv6: bool = False,
    capture_non_ip: bool = False,
    max_packet_count: int = 4000,
) -> dict[str, Any]:
    """Add a new FortiManager packet capture definition.

    Creates a packet capture (sniffer) definition for traffic originating or
    destined to the FortiManager itself. The definition is created but not
    started -- call start_packet_capture() with the returned capture_id to
    begin capturing.

    Args:
        interface: Interface to capture on (e.g. "port1")
        host: Filter by host address (optional, matches any host if unset)
        port: Filter by port or port range as a string, e.g. "80" or
            "1-1024" (optional)
        protocol: Filter by IP protocol number as a string, e.g. "6" for
            TCP (optional)
        vlan: Filter by VLAN ID as a string (optional)
        capture_ipv6: Include IPv6 traffic (default: False)
        capture_non_ip: Include non-IP traffic (default: False)
        max_packet_count: Maximum number of packets to capture
            (default: 4000, matching the FMG default)

    Returns:
        dict: Create result with keys:
            - status: "success" or "error"
            - capture_id: ID of the created capture definition (FMG
              auto-assigns this)
            - message: Status or error message

    Example:
        >>> result = await add_packet_capture(interface="port8", max_packet_count=300)
        >>> if result["status"] == "success":
        ...     await start_packet_capture(result["capture_id"])
    """
    try:
        interface = validate_interface_name(interface)
        if max_packet_count <= 0:
            raise ValidationError("max_packet_count must be a positive integer")

        client = _get_client()
        data: dict[str, Any] = {
            # id=0 tells FMG to auto-assign the next available ID (How-To
            # guide: "FortiManager Packet capture" > "How to add a new
            # packet capture definition?").
            "id": 0,
            "interface": interface,
            "max-packet-count": max_packet_count,
            "ipv6": "enable" if capture_ipv6 else "disable",
            "non-ip": "enable" if capture_non_ip else "disable",
        }
        if host:
            data["host"] = host
        if port:
            data["port"] = port
        if protocol:
            data["protocol"] = protocol
        if vlan:
            data["vlan"] = vlan

        result = await client.add("/cli/global/system/sniffer", data=data)
        capture_id = result.get("id") if isinstance(result, dict) else None

        return {
            "status": "success",
            "capture_id": capture_id,
            "message": f"Packet capture definition created with ID {capture_id}",
        }
    except Exception as e:
        logger.error(f"Failed to add packet capture: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def start_packet_capture(capture_id: int) -> dict[str, Any]:
    """Start a packet capture from an existing definition.

    Args:
        capture_id: ID of an existing packet capture definition (see
            list_packet_captures() or add_packet_capture())

    Returns:
        dict: Start result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await start_packet_capture(1)
    """
    try:
        client = _get_client()
        await client.execute(
            "/cli/global/system/sniffer",
            data={"action": "start", "id": capture_id},
        )
        return {
            "status": "success",
            "message": f"Packet capture {capture_id} started",
        }
    except Exception as e:
        logger.error(f"Failed to start packet capture {capture_id}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def stop_packet_capture(capture_id: int) -> dict[str, Any]:
    """Stop a running packet capture.

    Args:
        capture_id: ID of an existing packet capture definition

    Returns:
        dict: Stop result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await stop_packet_capture(1)
    """
    try:
        client = _get_client()
        await client.execute(
            "/cli/global/system/sniffer",
            data={"action": "stop", "id": capture_id},
        )
        return {
            "status": "success",
            "message": f"Packet capture {capture_id} stopped",
        }
    except Exception as e:
        logger.error(f"Failed to stop packet capture {capture_id}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_packet_capture_status(capture_id: int | None = None) -> dict[str, Any]:
    """Get the running/packet-count status of packet captures.

    FortiManager reports capture progress for all definitions in one call;
    when capture_id is given this filters the response down to that one
    definition.

    Args:
        capture_id: ID of a specific capture definition to filter to
            (optional; returns all captures' status if unset)

    Returns:
        dict: Status result with keys:
            - status: "success" or "error"
            - count: Number of capture statuses returned
            - captures: List of {id, max_packets, packets, running} objects
            - message: Error message if failed

    Example:
        >>> result = await get_packet_capture_status(capture_id=2)
        >>> print(result["captures"][0]["running"])  # 1 if still running
    """
    try:
        client = _get_client()
        result = await client.execute(
            "/cli/global/system/sniffer",
            data={"action": "progress"},
        )
        statuses = result if isinstance(result, list) else [result] if result else []
        if capture_id is not None:
            statuses = [s for s in statuses if isinstance(s, dict) and s.get("id") == capture_id]
        return {
            "status": "success",
            "count": len(statuses),
            "captures": statuses,
        }
    except Exception as e:
        logger.error(f"Failed to get packet capture status: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# License
# =============================================================================


@mcp.tool()
async def get_fmg_license() -> dict[str, Any]:
    """Get the FortiManager license/contract status.

    Returns the FortiManager's own license contract details (support
    entitlements, expiry dates, serial number) -- not managed-device
    licensing.

    Returns:
        dict: License result with keys:
            - status: "success" or "error"
            - license: License data (contract list, count)
            - message: Error message if failed

    Example:
        >>> result = await get_fmg_license()
        >>> print(result["license"]["contract"][0]["serial"])
    """
    try:
        client = _get_client()
        result = await client.execute("/um/license/self", data={"flags": 0})
        return {
            "status": "success",
            "license": result,
        }
    except Exception as e:
        logger.error(f"Failed to get FortiManager license: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Task Cleanup
# =============================================================================


@mcp.tool()
async def delete_task(task_id: int) -> dict[str, Any]:
    """Delete a task record from FortiManager's task list.

    Deletes a completed task's record, or cancels/stops a still-running one
    (per the How-To guide: "Deleting a task could be used to delete a
    completed task or cancelling/stopping a running task."). Complements
    list_tasks/get_task/wait_for_task in system_tools.py.

    Args:
        task_id: Task ID number

    Returns:
        dict: Delete result with keys:
            - status: "success" or "error"
            - message: Status or error message

    Example:
        >>> result = await delete_task(11111)
    """
    try:
        client = _get_client()
        await client.delete(f"/task/task/{task_id}")
        return {
            "status": "success",
            "message": f"Task {task_id} deleted successfully",
        }
    except Exception as e:
        logger.error(f"Failed to delete task {task_id}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
