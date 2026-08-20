"""Input validation and log sanitization utilities.

Security utilities for:
- Sanitizing sensitive data from log output
- Validating ADOM, device, policy, and object input parameters
- Path validation for file operations
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from fortimanager_mcp.utils.config import get_settings

logger = logging.getLogger(__name__)

# =============================================================================
# Log Sanitization
# =============================================================================

# Sensitive fields that should be masked in logs
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pass",
    "adm_pass",
    "adm_passwd",
    "api_token",
    "apikey",
    "token",
    "session",
    "sid",
    "authorization",
    "auth",
    "secret",
    "key",
    "credential",
}

# Mask pattern for sensitive values
MASK_VALUE = "***REDACTED***"


def sanitize_for_logging(data: Any, depth: int = 0) -> Any:
    """Sanitize sensitive data from objects before logging.

    Recursively traverses dictionaries and lists to mask sensitive fields.

    Args:
        data: Data to sanitize (dict, list, or primitive)
        depth: Current recursion depth (prevents infinite recursion)

    Returns:
        Sanitized copy of the data with sensitive values masked

    Example:
        >>> params = {"user": "admin", "password": "secret123"}
        >>> sanitize_for_logging(params)
        {'user': 'admin', 'password': '***REDACTED***'}
    """
    if depth > 10:
        # Prevent infinite recursion
        return "<MAX_DEPTH>"

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = key.lower().replace("-", "_").replace(" ", "_")
            if any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS):
                result[key] = MASK_VALUE
            else:
                result[key] = sanitize_for_logging(value, depth + 1)
        return result

    elif isinstance(data, list):
        return [sanitize_for_logging(item, depth + 1) for item in data]

    elif isinstance(data, str):
        # Check if string looks like a session ID or token (hex string > 20 chars)
        if len(data) > 20 and re.match(r"^[a-fA-F0-9]+$", data):
            return MASK_VALUE
        return data

    return data


def sanitize_json_for_logging(data: Any, indent: int | None = None) -> str:
    """Sanitize and convert data to JSON string for logging.

    Args:
        data: Data to sanitize and serialize
        indent: JSON indent level (None for compact)

    Returns:
        JSON string with sensitive values masked
    """
    sanitized = sanitize_for_logging(data)
    return json.dumps(sanitized, indent=indent, default=str)


# FortiOS CLI directives whose value is a secret (config export text is a
# flat "set <directive> <value>" line format -- SENSITIVE_FIELDS/
# sanitize_for_logging above only handle structured dict fields, which can't
# see inside this kind of multi-line text blob). Exact-name match only
# (anchored by the trailing whitespace in the pattern below), not substring,
# so e.g. "passwd-time" is never mistaken for "passwd".
#
# Cross-checked 2026-08-15 against every OTHER secret-field list already in
# this codebase (_VAP_SECRET_FIELDS, _WTP_SECRET_FIELDS, _PHASE1_SECRET_FIELDS)
# rather than derived independently -- a PR review (upstream #65 review
# comment) found sae-password/login-passwd/authpasswd missing here despite
# being declared secret in those sibling lists, plus priv-pwd (SNMP,
# sibling to auth-pwd/auth-pwd-alt) and two more confirmed against the
# FNDN 7.6.6/8.0.0 CLI references. tacacs+-secret was removed: the
# documented tacacs+ secret directives are key/secondary-key/tertiary-key
# (type "password" in the FNDN schema, confirmed against
# devobj80-161-objects.htm), not a "secret" field, so the old entry never
# matched anything real.
#
# "key" is context-dependent -- type "password" for TACACS+/NTP-auth/WEP,
# but type "string" (non-secret) for a few unrelated tables (HTTP-header
# key, multipart form-data key, FortiView filter key). This matcher has no
# notion of which "config" block a line belongs to, so it cannot
# distinguish them and redacts all of them. Deliberate: over-redacting an
# occasional non-secret "key" line is a minor readability cost; under-
# redacting a real TACACS+/NTP/WEP key is the failure this function exists
# to prevent, so it favors over-redaction when a directive name is
# ambiguous like this.
CONFIG_TEXT_SECRET_DIRECTIVES = {
    "password",
    "passwd",
    "psksecret",
    "psksecret-remote",
    "private-key",
    "ppk-secret",
    "auth-pwd",
    "auth-pwd-alt",
    "priv-pwd",
    "community",
    "passphrase",
    "secret",
    "secondary-secret",
    "tertiary-secret",
    "radius-secret",
    "key",
    "secondary-key",
    "tertiary-key",
    "authkey",
    "enckey",
    "certificate-password",
    "preshared-key",
    "sae-password",
    "login-passwd",
    "authpasswd",
    "group-authentication-secret",
    # PR #65 review (Christian, 08-18): 8 more format=password directives
    # confirmed against the bundled 8.0.0 swagger, reachable via device DB
    # config-text export (sdn-connector, api-user, user fsso, user radius,
    # router key-chain/ospf) but missing from this set.
    "secret-key",
    "client-secret",
    "api-key",
    "password2",
    "password3",
    "password4",
    "password5",
    "rsso-secret",
    "key-string",
    "logon-password",
    "sso-password",
}

_CONFIG_TEXT_SECRET_LINE = re.compile(
    r"^(?P<prefix>\s*set\s+(?:"
    + "|".join(re.escape(d) for d in CONFIG_TEXT_SECRET_DIRECTIVES)
    + r")\s+)(?P<rest>.*)$"
)


def _has_unescaped_quote(text: str) -> bool:
    """True if text contains a double quote that is not backslash-escaped.

    ``'"' in text`` closed a quoted span on the first quote it saw,
    including an escaped one, so a value containing ``\\"`` ended its span
    early and everything after it leaked past the redactor (upstream #71).
    Measured before fixing: a PEM whose second line was ``body \\" still
    secret`` left the remaining body and the END line in clear.

    Tracks the escape state character by character rather than using a
    lookbehind, so ``\\\\"`` (an escaped backslash followed by a real
    closing quote) still closes the span.
    """
    escaped = False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return True
    return False


def redact_config_text_secrets(text: str) -> str:
    """Mask secret-bearing directive values in raw FortiOS CLI config text.

    Device DB revision content (get_device_revision, diff_device_revision)
    is a multi-line CLI config export, not a structured dict -- the
    dict-key-driven sanitize_for_logging above cannot see inside it.
    Replaces the value portion of each matching "set <directive> ..." line
    with MASK_VALUE, keeping the directive name visible so it's still clear
    what was masked and where.

    Line-scoped, not a single MULTILINE regex: a quoted value (e.g.
    ``set private-key "-----BEGIN ... KEY-----``) can legitimately span
    many lines before its closing quote -- a per-line pattern only ever
    caught the first one, leaking the PEM body and END line raw (a PR
    review, upstream #65, live-reproduced this against a real multi-line
    private-key export). When a matched line opens a quote that does not
    close on the same line, every line up to and including the one that
    closes it is dropped rather than partially kept -- those lines carry
    only secret content, nothing a reader needs.
    """
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = _CONFIG_TEXT_SECRET_LINE.match(line)
        if not match:
            out.append(line)
            i += 1
            continue

        out.append(match.group("prefix") + MASK_VALUE)
        rest = match.group("rest")
        i += 1
        if rest.startswith('"') and not _has_unescaped_quote(rest[1:]):
            # Unterminated quote: consume continuation lines until the one
            # that closes it (or end of text, if the export was truncated --
            # safer to over-redact than to guess a close that isn't there).
            while i < len(lines) and not _has_unescaped_quote(lines[i]):
                i += 1
            if i < len(lines):
                i += 1  # also drop the closing line itself
    return "\n".join(out)


# =============================================================================
# Validation Patterns
# =============================================================================

# ADOM name pattern: alphanumeric, underscore, hyphen, 1-64 chars
ADOM_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Device name pattern: alphanumeric, underscore, hyphen, dot, 1-64 chars
DEVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")

# Device serial number pattern: starts with device type prefix, alphanumeric.
#
# The prefix set is an allowlist, so a product line missing from it is
# refused rather than passed through, and the message does not explain
# why: it says the serial needs a device-type prefix, which it has.
#
# ``PU`` and ``PS`` are the FortiAP-U and FortiAP-S series, which do not
# use the ``FP`` of the mainline FortiAP models. Adding a product line
# here is the fix whenever one turns up; the alternative, relaxing the
# prefix to two arbitrary letters, would drop the check to a length test.
DEVICE_SERIAL_PATTERN = re.compile(r"^(FG|FM|FW|FA|FS|FD|FP|FC|FV|PU|PS)[A-Z0-9]{10,20}$")

# Object name pattern: alphanumeric, underscore, hyphen, dot, space, parens,
# colon; 1-79 chars. FortiManager object names allow parentheses (e.g. cloned
# "addr (1)") and colons; path/injection chars (/ \ ; quotes) stay blocked.
OBJECT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.:() -]{1,79}$")

# Package name pattern: one or more path segments, 1-35 chars each.
# FortiManager addresses a policy package nested in a folder by its full
# folder path (e.g. "Corporate/Branch Policy"), so "/" is allowed as a
# segment separator up to 10 levels deep. FortiManager package/folder names
# routinely contain spaces, so each segment may use alphanumeric, underscore,
# hyphen, or interior spaces -- but must start and end with a non-space
# character, so a lone/leading/trailing space can't create an ambiguous
# segment. Segments stay dot-free, so "..", "//", and leading/trailing
# slashes are rejected.
_PACKAGE_SEGMENT = r"[a-zA-Z0-9_-](?:[a-zA-Z0-9_ -]{0,33}[a-zA-Z0-9_-])?"
PACKAGE_NAME_PATTERN = re.compile(rf"^{_PACKAGE_SEGMENT}(?:/{_PACKAGE_SEGMENT}){{0,9}}$")

# Policy name pattern: alphanumeric, underscore, hyphen, dot, space, parens,
# colon; 1-35 chars. Path/injection chars (/ \ ; quotes) stay blocked.
POLICY_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.:() -]{1,35}$")

# Interface name pattern: alphanumeric, underscore, hyphen, 1-35 chars
INTERFACE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,35}$")

# FQDN pattern: valid domain name format
FQDN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

# IPv4 address pattern
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# IPv4 CIDR pattern
IPV4_CIDR_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$"
)

# Port range pattern: single port, port range, or space-separated ports
PORT_RANGE_PATTERN = re.compile(r"^(\d{1,5}(-\d{1,5})?(\s+\d{1,5}(-\d{1,5})?)*)$")

# =============================================================================
# Valid Values
# =============================================================================

# Valid policy actions
VALID_POLICY_ACTIONS = {"accept", "deny", "ipsec", "ssl-vpn"}

# Valid log traffic modes
VALID_LOG_TRAFFIC_MODES = {"all", "utm", "disable"}

# Valid policy statuses
VALID_POLICY_STATUSES = {"enable", "disable"}

# Valid NGFW modes
VALID_NGFW_MODES = {"profile-based", "policy-based"}

# Valid address types
VALID_ADDRESS_TYPES = {"ipmask", "fqdn", "iprange", "wildcard", "geography", "mac"}

# Valid service protocols
VALID_SERVICE_PROTOCOLS = {"TCP/UDP/SCTP", "ICMP", "ICMP6", "IP", "ALL"}

# Valid move positions
VALID_MOVE_POSITIONS = {"before", "after"}


# =============================================================================
# Validation Error
# =============================================================================


class ValidationError(ValueError):
    """Raised when input validation fails."""

    pass


# =============================================================================
# Input Validation Functions
# =============================================================================


def validate_adom(adom: str) -> str:
    """Validate ADOM name format.

    Args:
        adom: ADOM name to validate

    Returns:
        Validated ADOM name (stripped)

    Raises:
        ValidationError: If ADOM name is invalid
    """
    if not adom:
        raise ValidationError("ADOM name cannot be empty")

    adom = adom.strip()

    if not ADOM_PATTERN.match(adom):
        raise ValidationError(
            f"Invalid ADOM name '{adom}'. "
            "Must be 1-64 characters, alphanumeric, underscore, or hyphen only."
        )

    return adom


def validate_device_name(device: str) -> str:
    """Validate device name format.

    Args:
        device: Device name to validate

    Returns:
        Validated device name (stripped)

    Raises:
        ValidationError: If device name is invalid
    """
    if not device:
        raise ValidationError("Device name cannot be empty")

    device = device.strip()
    _reject_traversal_segment(device, "device name")

    # Check for VDOM suffix like "device[vdom]"
    if "[" in device:
        base_name = device.split("[")[0]
        vdom_part = device.split("[")[1].rstrip("]")
        _reject_traversal_segment(base_name, "device name")
        if not DEVICE_NAME_PATTERN.match(base_name):
            raise ValidationError(f"Invalid device name '{base_name}'")
        if not ADOM_PATTERN.match(vdom_part):
            raise ValidationError(f"Invalid VDOM name '{vdom_part}'")
        return device

    if not DEVICE_NAME_PATTERN.match(device):
        raise ValidationError(
            f"Invalid device name '{device}'. "
            "Must be 1-64 characters, alphanumeric, underscore, hyphen, or dot."
        )

    return device


def validate_device_serial(serial: str) -> str:
    """Validate device serial number format.

    Args:
        serial: Serial number to validate

    Returns:
        Validated serial number (uppercase, stripped)

    Raises:
        ValidationError: If serial number is invalid
    """
    if not serial:
        raise ValidationError("Serial number cannot be empty")

    serial = serial.strip().upper()

    if not DEVICE_SERIAL_PATTERN.match(serial):
        raise ValidationError(
            f"Invalid serial number '{serial}'. "
            "Must start with device type prefix (FG, FM, etc.) "
            "followed by 10-20 alphanumeric characters."
        )

    return serial


def validate_package_name(name: str) -> str:
    """Validate policy package name format.

    Accepts folder-qualified names (e.g. "Corporate/Branch Policy") for
    packages nested inside a policy package folder. Spaces are allowed
    within a segment (FortiManager package/folder names commonly contain
    them) but not at the start/end of a segment.

    Args:
        name: Package name to validate

    Returns:
        Validated package name (stripped)

    Raises:
        ValidationError: If package name is invalid
    """
    if not name:
        raise ValidationError("Package name cannot be empty")

    name = name.strip()

    if not PACKAGE_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid package name '{name}'. "
            "Must be 1-35 characters per segment: alphanumeric, underscore, "
            "hyphen, or spaces (not at the start/end of a segment). "
            "Folder-nested packages may use '/' to separate up to 10 path "
            "segments (e.g. 'Corporate/Branch Policy')."
        )

    return name


def validate_policy_name(name: str) -> str:
    """Validate firewall policy name format.

    Args:
        name: Policy name to validate

    Returns:
        Validated policy name (stripped)

    Raises:
        ValidationError: If policy name is invalid
    """
    if not name:
        raise ValidationError("Policy name cannot be empty")

    name = name.strip()

    if not POLICY_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid policy name '{name}'. "
            "Must be 1-35 characters, alphanumeric, underscore, hyphen, dot, or space."
        )

    return name


#: Path segments that mean "this directory" and "the parent directory".
#: Both match the name patterns below (dots are legal in device and object
#: names), and both end up as the last segment of a URL template, so a name
#: of ".." walks the caller one level up the API tree instead of addressing
#: an object. No real FortiManager object is named "." or ".." (upstream
#: #71). Only the exact segments are refused -- a dot anywhere else in a
#: name is legitimate and stays allowed.
_TRAVERSAL_SEGMENTS = frozenset({".", ".."})


def _reject_traversal_segment(value: str, label: str) -> None:
    """Refuse a name that is only dots, before it reaches a URL template."""
    if value in _TRAVERSAL_SEGMENTS:
        raise ValidationError(
            f"Invalid {label} '{value}': a name of '.' or '..' is a path segment, not a name."
        )


def validate_object_name(name: str, object_type: str = "object") -> str:
    """Validate firewall object name format.

    Args:
        name: Object name to validate
        object_type: Type of object for error messages (e.g., "address", "service")

    Returns:
        Validated object name (stripped)

    Raises:
        ValidationError: If object name is invalid
    """
    if not name:
        raise ValidationError(f"{object_type.capitalize()} name cannot be empty")

    name = name.strip()
    _reject_traversal_segment(name, f"{object_type} name")

    if not OBJECT_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid {object_type} name '{name}'. "
            "Must be 1-79 characters, alphanumeric, underscore, hyphen, dot, or space."
        )

    return name


def validate_interface_name(name: str) -> str:
    """Validate interface name format.

    Args:
        name: Interface name to validate

    Returns:
        Validated interface name (stripped)

    Raises:
        ValidationError: If interface name is invalid
    """
    if not name:
        raise ValidationError("Interface name cannot be empty")

    name = name.strip()

    if not INTERFACE_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Invalid interface name '{name}'. "
            "Must be 1-35 characters, alphanumeric, underscore, or hyphen."
        )

    return name


def validate_ipv4_address(ip: str) -> str:
    """Validate IPv4 address format.

    Args:
        ip: IPv4 address to validate

    Returns:
        Validated IPv4 address (stripped)

    Raises:
        ValidationError: If IPv4 address is invalid
    """
    if not ip:
        raise ValidationError("IP address cannot be empty")

    ip = ip.strip()

    if not IPV4_PATTERN.match(ip):
        raise ValidationError(f"Invalid IPv4 address '{ip}'")

    return ip


def validate_ipv4_subnet(subnet: str) -> str:
    """Validate IPv4 subnet format (CIDR notation).

    Args:
        subnet: Subnet in CIDR notation (e.g., "10.0.0.0/24")

    Returns:
        Validated subnet (stripped)

    Raises:
        ValidationError: If subnet is invalid
    """
    if not subnet:
        raise ValidationError("Subnet cannot be empty")

    subnet = subnet.strip()

    # Allow space-separated format (IP netmask)
    if " " in subnet:
        parts = subnet.split()
        if len(parts) != 2:
            raise ValidationError(f"Invalid subnet format '{subnet}'")
        if not IPV4_PATTERN.match(parts[0]) or not IPV4_PATTERN.match(parts[1]):
            raise ValidationError(f"Invalid subnet '{subnet}'")
        return subnet

    # Check CIDR format
    if not IPV4_CIDR_PATTERN.match(subnet):
        raise ValidationError(
            f"Invalid subnet '{subnet}'. "
            "Use CIDR format (e.g., '10.0.0.0/24') or 'IP netmask' format."
        )

    return subnet


def validate_fqdn(fqdn: str) -> str:
    """Validate FQDN format.

    Args:
        fqdn: Fully qualified domain name to validate

    Returns:
        Validated FQDN (lowercase, stripped)

    Raises:
        ValidationError: If FQDN is invalid
    """
    if not fqdn:
        raise ValidationError("FQDN cannot be empty")

    fqdn = fqdn.strip().lower()

    if not FQDN_PATTERN.match(fqdn):
        raise ValidationError(f"Invalid FQDN '{fqdn}'")

    return fqdn


def validate_port_range(port_range: str) -> str:
    """Validate port range format.

    Args:
        port_range: Port range (e.g., "80", "8080-8090", "80 443 8080")

    Returns:
        Validated port range (stripped)

    Raises:
        ValidationError: If port range is invalid
    """
    if not port_range:
        raise ValidationError("Port range cannot be empty")

    port_range = port_range.strip()

    if not PORT_RANGE_PATTERN.match(port_range):
        raise ValidationError(
            f"Invalid port range '{port_range}'. "
            "Use formats like '80', '8080-8090', or '80 443 8080'."
        )

    # Validate individual port values (1-65535)
    for part in port_range.split():
        if "-" in part:
            start, end = part.split("-")
            if not (1 <= int(start) <= 65535) or not (1 <= int(end) <= 65535):
                raise ValidationError("Port values must be between 1 and 65535")
            if int(start) > int(end):
                raise ValidationError("Start port must be less than end port")
        else:
            if not (1 <= int(part) <= 65535):
                raise ValidationError("Port value must be between 1 and 65535")

    return port_range


def validate_policy_action(action: str) -> str:
    """Validate policy action.

    Args:
        action: Policy action to validate

    Returns:
        Validated action (lowercase)

    Raises:
        ValidationError: If action is invalid
    """
    if not action:
        raise ValidationError("Policy action cannot be empty")

    action = action.strip().lower()

    if action not in VALID_POLICY_ACTIONS:
        raise ValidationError(
            f"Invalid policy action '{action}'. "
            f"Valid actions: {', '.join(sorted(VALID_POLICY_ACTIONS))}"
        )

    return action


def validate_log_traffic_mode(mode: str) -> str:
    """Validate log traffic mode.

    Args:
        mode: Log traffic mode to validate

    Returns:
        Validated mode (lowercase)

    Raises:
        ValidationError: If mode is invalid
    """
    if not mode:
        raise ValidationError("Log traffic mode cannot be empty")

    mode = mode.strip().lower()

    if mode not in VALID_LOG_TRAFFIC_MODES:
        raise ValidationError(
            f"Invalid log traffic mode '{mode}'. "
            f"Valid modes: {', '.join(sorted(VALID_LOG_TRAFFIC_MODES))}"
        )

    return mode


def validate_status(status: str) -> str:
    """Validate enable/disable status.

    Args:
        status: Status to validate

    Returns:
        Validated status (lowercase)

    Raises:
        ValidationError: If status is invalid
    """
    if not status:
        raise ValidationError("Status cannot be empty")

    status = status.strip().lower()

    if status not in VALID_POLICY_STATUSES:
        raise ValidationError(
            f"Invalid status '{status}'. Valid values: {', '.join(sorted(VALID_POLICY_STATUSES))}"
        )

    return status


def validate_ngfw_mode(mode: str) -> str:
    """Validate NGFW mode.

    Args:
        mode: NGFW mode to validate

    Returns:
        Validated mode (lowercase with hyphen)

    Raises:
        ValidationError: If mode is invalid
    """
    if not mode:
        raise ValidationError("NGFW mode cannot be empty")

    mode = mode.strip().lower()

    if mode not in VALID_NGFW_MODES:
        raise ValidationError(
            f"Invalid NGFW mode '{mode}'. Valid modes: {', '.join(sorted(VALID_NGFW_MODES))}"
        )

    return mode


def validate_address_type(addr_type: str) -> str:
    """Validate address object type.

    Args:
        addr_type: Address type to validate

    Returns:
        Validated type (lowercase)

    Raises:
        ValidationError: If type is invalid
    """
    if not addr_type:
        raise ValidationError("Address type cannot be empty")

    addr_type = addr_type.strip().lower()

    if addr_type not in VALID_ADDRESS_TYPES:
        raise ValidationError(
            f"Invalid address type '{addr_type}'. "
            f"Valid types: {', '.join(sorted(VALID_ADDRESS_TYPES))}"
        )

    return addr_type


def validate_move_position(position: str) -> str:
    """Validate policy move position.

    Args:
        position: Move position to validate

    Returns:
        Validated position (lowercase)

    Raises:
        ValidationError: If position is invalid
    """
    if not position:
        raise ValidationError("Move position cannot be empty")

    position = position.strip().lower()

    if position not in VALID_MOVE_POSITIONS:
        raise ValidationError(
            f"Invalid move position '{position}'. "
            f"Valid positions: {', '.join(sorted(VALID_MOVE_POSITIONS))}"
        )

    return position


def validate_policy_id(policyid: int) -> int:
    """Validate policy ID.

    Args:
        policyid: Policy ID to validate

    Returns:
        Validated policy ID

    Raises:
        ValidationError: If policy ID is invalid
    """
    if policyid is None:
        raise ValidationError("Policy ID cannot be None")

    if not isinstance(policyid, int):
        raise ValidationError("Policy ID must be an integer")

    if policyid < 0:
        raise ValidationError("Policy ID must be non-negative")

    return policyid


def validate_task_id(task_id: int) -> int:
    """Validate a FortiManager task ID.

    Every tool taking one interpolates it straight into /task/task/{id}.
    The type annotation carries that in full mode, but dynamic mode passes
    ``parameters`` as ``dict[str, Any]`` and nothing enforces the shape
    there -- which is the mode the newer modules are wired into
    (upstream #71).

    ``bool`` is refused explicitly: it is a subclass of int, so True would
    otherwise sail through and address task 1.
    """
    if task_id is None:
        raise ValidationError("Task ID cannot be None")

    if isinstance(task_id, bool) or not isinstance(task_id, int):
        raise ValidationError(f"Task ID must be an integer, got {type(task_id).__name__}")

    if task_id < 0:
        raise ValidationError("Task ID must be non-negative")

    return task_id


# =============================================================================
# Security Profile Validation
# =============================================================================

# Individual security-profile fields on a firewall policy that FortiOS also
# exposes bundled into a single `firewall profile-group` object. Verified
# against the FNDN 7.6.7 `firewall/profile-group` schema
# (adomobj76-3500-objects.htm, cross-checked adomobj76-3693-objects.htm): the
# group object's attribute list carries av-profile, ips-sensor,
# webfilter-profile, dnsfilter-profile, application-list, file-filter-profile,
# ssl-ssh-profile, AND profile-protocol-options as members, so FortiOS rejects
# a policy that sets both `profile-group` and any of these eight fields.
_GROUPED_SECURITY_PROFILE_FIELDS = (
    ("av-profile", "av_profile"),
    ("ips-sensor", "ips_sensor"),
    ("webfilter-profile", "webfilter_profile"),
    ("dnsfilter-profile", "dnsfilter_profile"),
    ("application-list", "application_list"),
    ("file-filter-profile", "file_filter_profile"),
    ("ssl-ssh-profile", "ssl_ssh_profile"),
    ("profile-protocol-options", "profile_protocol_options"),
)


def validate_security_profiles(
    utm_status: bool | None,
    profile_group: str | None,
    av_profile: str | None,
    ips_sensor: str | None,
    webfilter_profile: str | None,
    dnsfilter_profile: str | None,
    application_list: str | None,
    file_filter_profile: str | None,
    ssl_ssh_profile: str | None,
    profile_protocol_options: str | None,
) -> None:
    """Validate security-profile field combinations on a firewall policy.

    FortiOS rejects a policy that sets both `profile-group` and any
    individual security-profile field the group bundles (see
    `_GROUPED_SECURITY_PROFILE_FIELDS`). This checks that combination at the
    tool boundary with a clear message instead of letting FortiManager
    reject it with an opaque error code.

    Also rejects setting any of these fields (individual or profile-group)
    while `utm_status` is explicitly False in the same call: FortiOS ignores
    security profiles when utm-status is disabled, so the combination is
    almost certainly a caller mistake rather than an intentional no-op.

    Args:
        utm_status: The utm_status value passed to this call (None means
            utm_status is not being set in this call).
        profile_group: profile_group value passed to this call.
        av_profile: av_profile value passed to this call.
        ips_sensor: ips_sensor value passed to this call.
        webfilter_profile: webfilter_profile value passed to this call.
        dnsfilter_profile: dnsfilter_profile value passed to this call.
        application_list: application_list value passed to this call.
        file_filter_profile: file_filter_profile value passed to this call.
        ssl_ssh_profile: ssl_ssh_profile value passed to this call.
        profile_protocol_options: profile_protocol_options value passed to
            this call.

    Raises:
        ValidationError: If profile_group is combined with an individual
            security-profile field, or any security-profile field is set
            together with utm_status=False.
    """
    individual_values = {
        "av_profile": av_profile,
        "ips_sensor": ips_sensor,
        "webfilter_profile": webfilter_profile,
        "dnsfilter_profile": dnsfilter_profile,
        "application_list": application_list,
        "file_filter_profile": file_filter_profile,
        "ssl_ssh_profile": ssl_ssh_profile,
        "profile_protocol_options": profile_protocol_options,
    }
    individual_set = sorted(
        field_name
        for field_name, arg_name in _GROUPED_SECURITY_PROFILE_FIELDS
        if individual_values[arg_name] is not None
    )

    if profile_group is not None and individual_set:
        raise ValidationError(
            "profile_group is mutually exclusive with individual security profile "
            f"fields. Remove profile_group or remove: {', '.join(individual_set)}."
        )

    if utm_status is False:
        active = sorted(individual_set + (["profile-group"] if profile_group is not None else []))
        if active:
            raise ValidationError(
                f"Security profile field(s) {', '.join(active)} were set together "
                "with utm_status=False. FortiOS ignores security profiles when "
                "utm-status is disabled -- set utm_status=True (or omit it) to "
                "apply them."
            )


# =============================================================================
# Path Validation
# =============================================================================


def get_allowed_output_dirs() -> list[Path]:
    """Get list of allowed output directories.

    Returns directories from FMG_ALLOWED_OUTPUT_DIRS env var.
    No default directories are permitted — file output must be
    explicitly configured via the environment variable.

    This follows the principle of secure-by-default: tools that
    only query data work without any output directory configuration.
    File output requires explicit opt-in.

    Set FMG_ALLOWED_OUTPUT_DIRS to a comma-separated list of directories:
        FMG_ALLOWED_OUTPUT_DIRS=~/Downloads,~/Reports

    Returns:
        List of allowed Path objects

    Raises:
        ValidationError: If no output directories are configured
    """
    env_dirs = os.environ.get("FMG_ALLOWED_OUTPUT_DIRS", "")

    if env_dirs:
        # Parse comma-separated list from environment
        dirs = []
        for d in env_dirs.split(","):
            d = d.strip()
            if d:
                path = Path(d).expanduser().resolve()
                if path.exists() and path.is_dir():
                    dirs.append(path)
        if dirs:
            return dirs

    # Secure by default: no output directories allowed without explicit config
    raise ValidationError(
        "No output directories configured. File output is disabled by default. "
        "Set FMG_ALLOWED_OUTPUT_DIRS environment variable to enable file output. "
        "Example: FMG_ALLOWED_OUTPUT_DIRS=~/Downloads"
    )


def validate_output_path(output_dir: str) -> Path:
    """Validate and resolve output directory path.

    Ensures the path is within allowed directories to prevent
    directory traversal attacks.

    Args:
        output_dir: Output directory path (can include ~)

    Returns:
        Resolved Path object

    Raises:
        ValidationError: If path is not within allowed directories
    """
    if not output_dir:
        raise ValidationError("Output directory cannot be empty")

    # Expand ~ and resolve to absolute path
    path = Path(output_dir).expanduser().resolve()

    # Get allowed directories
    allowed_dirs = get_allowed_output_dirs()

    # Check if path is within any allowed directory
    for allowed in allowed_dirs:
        try:
            path.relative_to(allowed)
            return path
        except ValueError:
            continue

    # Path not in allowed directories
    allowed_str = ", ".join(str(d) for d in allowed_dirs)
    raise ValidationError(
        f"Output directory '{path}' is not within allowed directories. "
        f"Allowed: {allowed_str}. "
        "Set FMG_ALLOWED_OUTPUT_DIRS environment variable to customize."
    )


def validate_filename(filename: str) -> str:
    """Validate filename for safe filesystem operations.

    Args:
        filename: Filename to validate

    Returns:
        Sanitized filename

    Raises:
        ValidationError: If filename is invalid or dangerous
    """
    if not filename:
        raise ValidationError("Filename cannot be empty")

    # Remove path separators and dangerous characters
    basename = os.path.basename(filename)

    # Check for hidden files or special names
    if basename.startswith("."):
        raise ValidationError(f"Hidden files not allowed: {basename}")

    # Check for dangerous patterns
    dangerous = [".", "..", "~", "*", "?", "|", "<", ">", ":", '"', "\\", "/"]
    for char in dangerous:
        if char in basename and char != ".":  # Allow single dot for extension
            raise ValidationError(f"Invalid character '{char}' in filename")

    # Validate with pattern: alphanumeric, underscore, hyphen, dot, space.
    # fullmatch (not match with $) so a trailing newline cannot slip through.
    if not re.fullmatch(r"[\w\-. ]+", basename):
        raise ValidationError(f"Invalid filename: {basename}")

    return basename


# =============================================================================
# Script Content Safety
# =============================================================================

# Dangerous FortiOS CLI commands and high-impact config changes that must be
# blocked. FortiOS accepts any unambiguous command-prefix abbreviation, so a
# bare "exec"/"execute" pattern is bypassable via "ex"/"exe", and "config
# system"/"config router" via "conf sys"/"conf rout". The keyword fragments
# below match every valid shortening of each token. Matching is
# case-insensitive and runs against whitespace-normalized content so attackers
# can't bypass via odd spacing/case either.
#
# Each fragment expands to the keyword and all of its accepted abbreviations:
#   _EXEC   -> ex, exe, exec, execu, execut, execute
#   _CONFIG -> conf, confi, config
#   _SYSTEM -> sys, syst, syste, system
#   _ROUTER -> rout, route, router
_EXEC = r"ex(?:e(?:c(?:u(?:te?)?)?)?)?"
_CONFIG = r"conf(?:i(?:g)?)?"
_SYSTEM = r"sys(?:t(?:e(?:m)?)?)?"
_ROUTER = r"rout(?:e(?:r)?)?"

DANGEROUS_SCRIPT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # --- Destructive / availability-impacting exec commands ---
    # Factory reset (with and without hyphen)
    (re.compile(rf"\b{_EXEC}\s+factory-?reset\b", re.IGNORECASE), "factory-reset"),
    (re.compile(rf"\b{_EXEC}\s+factoryreset\b", re.IGNORECASE), "factoryreset"),
    # Reboot
    (re.compile(rf"\b{_EXEC}\s+reboot\b", re.IGNORECASE), "reboot"),
    # Shutdown
    (re.compile(rf"\b{_EXEC}\s+shutdown\b", re.IGNORECASE), "shutdown"),
    # Format disk
    (re.compile(rf"\b{_EXEC}\s+format\b", re.IGNORECASE), "format"),
    # Erase disk (with and without hyphen)
    (re.compile(rf"\b{_EXEC}\s+erase-?disk\b", re.IGNORECASE), "erase-disk"),
    # --- High-impact config changes an attacker would use ---
    # Adding/modifying admin accounts (backdoor admin)
    (re.compile(rf"\b{_CONFIG}\s+{_SYSTEM}\s+admin\b", re.IGNORECASE), "config-system-admin"),
    # Permissive firewall rule (action accept on any policy)
    (re.compile(r"\bset\s+action\s+accept\b", re.IGNORECASE), "set-action-accept"),
    # Disabling logging (under any log config block)
    (re.compile(r"\bset\s+status\s+disable\b", re.IGNORECASE), "set-status-disable"),
    # Changing DNS resolver configuration
    (re.compile(rf"\b{_CONFIG}\s+{_SYSTEM}\s+dns\b", re.IGNORECASE), "config-system-dns"),
    # Changing static/router config (routes)
    (re.compile(rf"\b{_CONFIG}\s+{_ROUTER}\s+static\b", re.IGNORECASE), "config-router-static"),
]


def validate_script_content(content: str) -> list[str]:
    """Check script content for dangerous CLI commands and config changes.

    Scans for destructive FortiOS commands that could cause device outages or
    data loss (factory-reset, reboot, shutdown, format, erase-disk) as well as
    high-impact configuration changes an attacker would use (adding admin
    users, permissive firewall actions, disabling logging, DNS/route changes).

    Input is normalized (collapsing all runs of whitespace to a single space)
    before matching so the check cannot be trivially bypassed by extra
    spacing, tabs, or newlines between tokens.

    Args:
        content: Script content (CLI commands) to validate

    Returns:
        List of matched dangerous command names (empty if safe)
    """
    # Normalize whitespace so "config   system\tadmin" matches the same as
    # "config system admin". Patterns already use \s+ but this guards against
    # multi-line splits and unusual whitespace between tokens.
    normalized = re.sub(r"\s+", " ", content)
    matches = []
    for pattern, name in DANGEROUS_SCRIPT_PATTERNS:
        if pattern.search(normalized):
            matches.append(name)
    return matches


# =============================================================================
# Policy Permissiveness Safety
# =============================================================================


def check_policy_permissiveness(
    srcaddr: list[str] | str | None,
    dstaddr: list[str] | str | None,
    service: list[str] | str | None,
    action: str | None,
    srcaddr_negate: bool = False,
    dstaddr_negate: bool = False,
    service_negate: bool = False,
) -> str | None:
    """Check if a firewall policy is overly permissive.

    Detects policies where srcaddr=all AND dstaddr=all AND action=accept,
    which allows unrestricted traffic. Distinguishes between "fully open"
    (service=ALL) and "overly permissive" (specific services but any-to-any).

    Negation inverts a field's match set, so it changes what "broad" means:
    a negated specific list matches its complement (effectively almost
    everything), while a negated "all" matches nothing at all.

    Args:
        srcaddr: Source address list (e.g., ["all"])
        dstaddr: Destination address list (e.g., ["all"])
        service: Service list (e.g., ["ALL"])
        action: Policy action (e.g., "accept")
        srcaddr_negate: srcaddr-negate is enabled on the policy
        dstaddr_negate: dstaddr-negate is enabled on the policy
        service_negate: service-negate is enabled on the policy

    Returns:
        Warning message string if overly permissive, None if acceptable
    """
    # .strip() before comparing: PR #65 review (Christian) found a padded
    # action ("accept " with a trailing space) bypassed this check entirely
    # -- reachable from any caller that doesn't validate action against the
    # enum first (revert_firewall_policy's snapshot input, in particular).
    if action is None or action.strip().lower() != "accept":
        return None

    def _is_all(addrs: list[str] | str | None) -> bool:
        # Same review: a caller passing a bare string ("all" instead of
        # ["all"]) was iterated character-by-character ('a','l','l', none
        # of which equals "all"), silently returning False -- a scalar
        # bypassed the check completely. A list is still the contract this
        # function documents; a bare string is tolerated defensively
        # (treated as its own single-element list) rather than trusted
        # blindly, since a safety check must not be foolable by a caller
        # passing the "wrong" shape. Follow-up (08-18): a padded value
        # ("all " with a trailing space) survived the unpadded check the
        # same way the padded "accept " did above -- .strip() before
        # comparing here too.
        if not addrs:
            return False
        if isinstance(addrs, str):
            addrs = [addrs]
        return any(a.strip().lower() == "all" for a in addrs)

    src_all = _is_all(srcaddr)
    dst_all = _is_all(dstaddr)
    svc_all = service is not None and (
        any(s.strip().upper() == "ALL" for s in service)
        if not isinstance(service, str)
        else service.strip().upper() == "ALL"
    )

    # Negating "all" produces an empty match set — the policy matches no
    # traffic. Almost always a mistake, and FortiOS may reject it at install.
    negated_all = [
        field
        for field, negated, is_all in (
            ("srcaddr", srcaddr_negate, src_all),
            ("dstaddr", dstaddr_negate, dst_all),
            ("service", service_negate, svc_all),
        )
        if negated and is_all
    ]
    if negated_all:
        fields = ", ".join(negated_all)
        return (
            f"Policy negates 'all'/'ALL' on {fields}: negation inverts the "
            "field, so this policy matches no traffic at all."
        )

    # A negated specific list matches its complement, which is effectively
    # as broad as "all" for permissiveness purposes.
    src_broad = src_all or (srcaddr_negate and bool(srcaddr))
    dst_broad = dst_all or (dstaddr_negate and bool(dstaddr))
    if not (src_broad and dst_broad):
        return None

    negate_note = ""
    if srcaddr_negate or dstaddr_negate or service_negate:
        negated = [
            f
            for f, n in (
                ("srcaddr", srcaddr_negate),
                ("dstaddr", dstaddr_negate),
                ("service", service_negate),
            )
            if n
        ]
        negate_note = (
            f" Note: negation on {', '.join(negated)} makes the policy match "
            "the complement of the listed values, which is effectively full scope."
        )

    if svc_all or (service_negate and bool(service)):
        return (
            "Policy is fully open: srcaddr='all', dstaddr='all', service='ALL', "
            "action='accept'. This allows all traffic from any source to any "
            "destination on all ports." + negate_note
        )

    return (
        "Policy is overly permissive: srcaddr='all', dstaddr='all', "
        "action='accept'. This allows traffic from any source to any destination." + negate_note
    )


def check_policy_safety(
    srcaddr: list[str] | str | None,
    dstaddr: list[str] | str | None,
    service: list[str] | str | None,
    action: str | None,
    srcaddr_negate: bool = False,
    dstaddr_negate: bool = False,
    service_negate: bool = False,
) -> dict[str, Any] | None:
    """Check policy permissiveness based on the FMG_POLICY_SAFETY setting.

    Returns error dict (strict), warning dict (warn), or None (OK/disabled).
    Shared by every tool that writes a firewall-policy-shaped payload
    (create/update/revert) -- there must be exactly one copy of this gate,
    not one per tool, or a future change to the gate risks only updating
    some of the write paths.

    Enabling negation never blocks on its own (it is a legitimate feature),
    but it always attaches a warning in strict/warn mode: negation inverts a
    field's meaning, so it should be noisy rather than silent.
    """
    settings = get_settings()
    if settings.FMG_POLICY_SAFETY == "disabled":
        return None

    warning = check_policy_permissiveness(
        srcaddr,
        dstaddr,
        service,
        action,
        srcaddr_negate=srcaddr_negate,
        dstaddr_negate=dstaddr_negate,
        service_negate=service_negate,
    )
    if warning:
        if settings.FMG_POLICY_SAFETY == "strict":
            logger.warning(f"Policy blocked — {warning}")
            return {
                "status": "error",
                "message": f"Policy blocked: {warning} "
                "Set FMG_POLICY_SAFETY=warn or FMG_POLICY_SAFETY=disabled to override.",
            }

        # warn mode — return marker for caller to attach warning to success response
        logger.warning(f"Policy warning — {warning}")
        return {"_safety_warning": warning}

    negated = [
        field
        for field, flag in (
            ("srcaddr", srcaddr_negate),
            ("dstaddr", dstaddr_negate),
            ("service", service_negate),
        )
        if flag
    ]
    if negated:
        note = (
            f"Negation enabled on {', '.join(negated)}: the policy matches the "
            "complement of the listed value(s), not the value(s) themselves."
        )
        logger.warning(f"Policy warning — {note}")
        return {"_safety_warning": note}

    return None
