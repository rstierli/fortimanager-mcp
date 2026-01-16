"""Input validation and log sanitization utilities.

Security utilities for:
- Sanitizing sensitive data from log output
- Validating ADOM, device, policy, and object input parameters
- Path validation for file operations
"""

import json
import os
import re
from pathlib import Path
from typing import Any

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


# =============================================================================
# Validation Patterns
# =============================================================================

# ADOM name pattern: alphanumeric, underscore, hyphen, 1-64 chars
ADOM_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Device name pattern: alphanumeric, underscore, hyphen, dot, 1-64 chars
DEVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")

# Device serial number pattern: starts with device type prefix, alphanumeric
DEVICE_SERIAL_PATTERN = re.compile(r"^(FG|FM|FW|FA|FS|FD|FP|FC|FV)[A-Z0-9]{10,20}$")

# Object name pattern: alphanumeric, underscore, hyphen, dot, space, 1-79 chars
# FortiManager object names can be up to 79 chars and allow more characters
OBJECT_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_. -]{1,79}$")

# Package name pattern: alphanumeric, underscore, hyphen, 1-35 chars
PACKAGE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,35}$")

# Policy name pattern: alphanumeric, underscore, hyphen, dot, space, 1-35 chars
POLICY_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_. -]{1,35}$")

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

    # Check for VDOM suffix like "device[vdom]"
    if "[" in device:
        base_name = device.split("[")[0]
        vdom_part = device.split("[")[1].rstrip("]")
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
            "Must be 1-35 characters, alphanumeric, underscore, or hyphen only."
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


# =============================================================================
# Path Validation
# =============================================================================


def get_allowed_output_dirs() -> list[Path]:
    """Get list of allowed output directories.

    Returns directories from FMG_ALLOWED_OUTPUT_DIRS env var,
    or defaults to home directory subdirectories.

    Returns:
        List of allowed Path objects
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

    # Default: common subdirectories under home
    home = Path.home()
    return [
        home,
        home / "Downloads",
        home / "Documents",
        home / "Desktop",
        home / "Reports",
    ]


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

    # Validate with pattern: alphanumeric, underscore, hyphen, dot, space
    if not re.match(r"^[\w\-. ]+$", basename):
        raise ValidationError(f"Invalid filename: {basename}")

    return basename
