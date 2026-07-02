"""Custom error classes for FortiManager MCP server."""

import re


class FortiManagerMCPError(Exception):
    """Base exception for FortiManager MCP errors.

    Attributes:
        code: FortiManager API error code (if applicable)
        message: Human-readable error message
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        """Initialize FortiManager MCP error.

        Args:
            message: Error message
            code: FortiManager error code
        """
        self.code = code
        super().__init__(message)


class AuthenticationError(FortiManagerMCPError):
    """Authentication failed.

    Common causes:
    - Invalid username or password
    - Session expired
    - Account locked
    - Insufficient permissions
    """

    pass


class ConnectionError(FortiManagerMCPError):
    """Connection to FortiManager failed.

    Common causes:
    - FortiManager unreachable
    - Network connectivity issues
    - SSL/TLS certificate problems
    - Firewall blocking connection
    """

    pass


class APIError(FortiManagerMCPError):
    """FortiManager API returned an error.

    This is the general API error for issues not covered by
    more specific error types.
    """

    pass


class ValidationError(FortiManagerMCPError):
    """Input validation failed.

    Raised when input parameters don't meet format requirements
    or contain invalid values.
    """

    pass


class ResourceNotFoundError(FortiManagerMCPError):
    """Requested resource not found.

    Common cases:
    - ADOM doesn't exist
    - Device not found
    - Policy package not found
    - Object (address, service, etc.) not found
    """

    pass


class PermissionError(FortiManagerMCPError):
    """Permission denied for operation.

    The API user doesn't have sufficient privileges for the
    requested operation.
    """

    pass


class TimeoutError(FortiManagerMCPError):
    """Request timed out.

    The operation took longer than the allowed timeout period.
    """

    pass


class ADOMLockError(FortiManagerMCPError):
    """ADOM lock/unlock operation failed.

    Common causes:
    - ADOM already locked by another user
    - Lock expired during operation
    - Workspace mode disabled
    - Insufficient lock permissions
    """

    pass


class TaskError(FortiManagerMCPError):
    """Task execution or monitoring failed.

    Raised when background tasks (installation, script execution, etc.)
    fail or cannot be monitored.
    """

    pass


class PolicyError(FortiManagerMCPError):
    """Policy operation failed.

    Raised for firewall policy-related errors including:
    - Policy creation/update/deletion failures
    - Invalid policy configuration
    - Policy conflicts (duplicate names, IDs)
    - Policy move operation failures
    """

    pass


class PackageError(FortiManagerMCPError):
    """Policy package operation failed.

    Raised for policy package-related errors including:
    - Package creation/deletion failures
    - Package assignment failures
    - Installation errors
    - Invalid package configuration
    """

    pass


class ObjectError(FortiManagerMCPError):
    """Firewall object operation failed.

    Raised for object-related errors including:
    - Address/service creation failures
    - Object in use (cannot delete)
    - Duplicate object names
    - Invalid object configuration
    """

    pass


class TemplateError(FortiManagerMCPError):
    """Template operation failed.

    Raised for template-related errors including:
    - Template creation/deletion failures
    - Template assignment failures
    - Template validation errors
    - CLI template execution failures
    """

    pass


class ScriptError(FortiManagerMCPError):
    """CLI script operation failed.

    Raised for script-related errors including:
    - Script creation/deletion failures
    - Script execution failures
    - Invalid script syntax
    - Script target errors
    """

    pass


class DeviceError(FortiManagerMCPError):
    """Device management operation failed.

    Raised for device-related errors including:
    - Device add/delete failures
    - Device connection issues
    - Device sync failures
    - Invalid device configuration
    """

    pass


class InstallError(FortiManagerMCPError):
    """Installation operation failed.

    Raised when policy/config installation fails including:
    - Installation task failures
    - Preview generation failures
    - Device installation conflicts
    """

    pass


# =============================================================================
# FortiManager Error Code Mapping
# =============================================================================

# FortiManager API error codes and their corresponding exception classes.
#
# Codes marked [verified] were probed live against FMG 7.6.7 (issue #21);
# the previous table was off by several codes (e.g. -2 was treated as an
# invalid session when it actually means a duplicate object, and -3 as
# permission-denied when it means not-found), which produced misleading
# error envelopes and spurious reconnects.
ERROR_CODE_MAP: dict[int, type[FortiManagerMCPError]] = {
    -1: APIError,  # Internal error
    -2: ObjectError,  # Object already exists [verified]
    -3: ResourceNotFoundError,  # Object does not exist [verified]
    -4: ResourceNotFoundError,  # Object not found (legacy entry, unverified)
    -5: APIError,  # No such command [verified]
    -6: ValidationError,  # Invalid URL [verified]
    -7: ObjectError,  # Entry in use (legacy entry, unverified)
    -8: ValidationError,  # Invalid parameter [verified]
    -9: ValidationError,  # Command invalid for selected URL [verified]
    -10: ValidationError,  # Data invalid for selected URL [verified]
    -11: PermissionError,  # No permission / stale session [verified]
    -22: AuthenticationError,  # Login fail [verified]
    -10147: PermissionError,  # No write permission [verified]
    -20055: ADOMLockError,  # Workspace locked by another admin [verified]
}

# Human-readable messages for common error codes
ERROR_CODE_MESSAGES: dict[int, str] = {
    -1: "Internal server error occurred",
    -2: "Object already exists",
    -3: "Object does not exist",
    -4: "Requested resource not found",
    -5: "No such command",
    -6: "Invalid URL",
    -7: "Cannot delete object - it is still in use",
    -8: "Invalid parameter",
    -9: "The command is invalid for the selected URL",
    -10: "The data is invalid for the selected URL",
    -11: "No permission for the resource (or the session expired)",
    -22: "Login failed - invalid credentials",
    -10147: "No write permission (read-only admin, or ADOM not locked in workspace mode)",
    -20055: "Workspace is locked by another administrator",
}


def parse_fmg_error(code: int, message: str, url: str | None = None) -> FortiManagerMCPError:
    """Parse FortiManager error code and create appropriate exception.

    Args:
        code: FortiManager error code
        message: Error message from API
        url: API endpoint URL (for context)

    Returns:
        Appropriate FortiManagerMCPError subclass

    Example:
        >>> try:
        ...     # API call
        ... except Exception as e:
        ...     raise parse_fmg_error(-4, "Object not found", "/dvmdb/device")
    """
    error_class = ERROR_CODE_MAP.get(code, APIError)

    # Build descriptive message
    base_msg = ERROR_CODE_MESSAGES.get(code, message)
    if message and message != base_msg:
        error_msg = f"{base_msg}: {message}"
    else:
        error_msg = base_msg

    if url:
        error_msg = f"{error_msg} (endpoint: {url})"

    return error_class(error_msg, code=code)


# Regex to strip the internal "(endpoint: ...)" context that parse_fmg_error
# appends. That suffix exposes API endpoint paths / topology and must never be
# returned to the model.
_ENDPOINT_SUFFIX_RE = re.compile(r"\s*\(endpoint:[^)]*\)")

# Regex to redact any leaked FortiManager/FortiGate API path from an error
# message. These paths expose internal endpoint structure / object hierarchy.
_API_PATH_RE = re.compile(
    r"\s*(?:GET|ADD|SET|UPDATE|DELETE|EXEC|MOVE)?\s*"
    r"/(?:dvmdb|dvm|pm|sys|securityconsole|task|api)\b\S*"
)


def _scrub_message(message: str) -> str:
    """Remove endpoint suffixes and leaked API paths from an error message."""
    scrubbed = _ENDPOINT_SUFFIX_RE.sub("", message)
    scrubbed = _API_PATH_RE.sub("", scrubbed)
    return scrubbed.strip()


def client_safe_error(error: Exception) -> tuple[str, str]:
    """Convert an exception into a caller-safe (message, code) pair.

    Tool functions log the full exception server-side (with endpoint context)
    but must not echo raw API error bodies — which embed internal endpoint
    paths and object hierarchies — back to the model. This helper returns a
    sanitized, category-tagged message safe to surface to the caller.

    Args:
        error: The exception raised during an API operation.

    Returns:
        Tuple of (message, error_code) where error_code is a short, stable
        category string (e.g. "not_found", "permission_denied", "api_error").
    """
    if isinstance(error, FortiManagerMCPError):
        category = _ERROR_CATEGORY.get(type(error), "api_error")
        # Prefer the human-readable mapped message for known FMG codes; never
        # the raw API body (which carries endpoint paths).
        if error.code is not None and error.code in ERROR_CODE_MESSAGES:
            message = ERROR_CODE_MESSAGES[error.code]
        else:
            message = _scrub_message(str(error))
            if not message:
                message = _CATEGORY_MESSAGE.get(category, "FortiManager operation failed")
        return message, category

    # Input validation errors are safe to surface (they describe the bad input
    # the caller supplied, not internal topology) — but still scrub any path.
    if isinstance(error, ValueError):
        return _scrub_message(str(error)) or "Invalid input parameter.", "validation_error"

    # Other exceptions (runtime, unexpected): scrub any leaked paths but keep
    # the message so operational errors (e.g. "client not initialized") remain
    # actionable.
    message = _scrub_message(str(error))
    return message or "An internal error occurred.", "internal_error"


# Maps exception classes to short, stable category codes for client_safe_error.
_ERROR_CATEGORY: dict[type[FortiManagerMCPError], str] = {
    AuthenticationError: "authentication_error",
    ConnectionError: "connection_error",
    APIError: "api_error",
    ValidationError: "validation_error",
    ResourceNotFoundError: "not_found",
    PermissionError: "permission_denied",
    TimeoutError: "timeout",
    ADOMLockError: "adom_lock_error",
    TaskError: "task_error",
    PolicyError: "policy_error",
    PackageError: "package_error",
    ObjectError: "object_error",
    TemplateError: "template_error",
    ScriptError: "script_error",
    DeviceError: "device_error",
    InstallError: "install_error",
}

# Fallback generic messages per category when no specific message is available.
_CATEGORY_MESSAGE: dict[str, str] = {
    "authentication_error": "Authentication with FortiManager failed.",
    "connection_error": "Could not connect to FortiManager.",
    "api_error": "FortiManager returned an error.",
    "validation_error": "Invalid input parameter.",
    "not_found": "Requested resource not found.",
    "permission_denied": "Permission denied for this operation.",
    "timeout": "The operation timed out.",
    "adom_lock_error": "ADOM lock operation failed.",
    "task_error": "Task operation failed.",
    "policy_error": "Policy operation failed.",
    "package_error": "Policy package operation failed.",
    "object_error": "Firewall object operation failed.",
    "template_error": "Template operation failed.",
    "script_error": "Script operation failed.",
    "device_error": "Device management operation failed.",
    "install_error": "Installation operation failed.",
}


def is_object_in_use_error(error: Exception) -> bool:
    """Check if error indicates an object is in use.

    Useful for determining if a delete operation failed because
    the object is referenced by policies or other objects.

    Args:
        error: Exception to check

    Returns:
        True if error indicates object is in use
    """
    if isinstance(error, FortiManagerMCPError):
        if error.code == -7:
            return True
    if isinstance(error, ObjectError):
        msg = str(error).lower()
        return "in use" in msg or "referenced" in msg
    return False


def is_duplicate_error(error: Exception) -> bool:
    """Check if error indicates a duplicate entry.

    Useful for determining if a create operation failed because
    an object with the same name already exists.

    Args:
        error: Exception to check

    Returns:
        True if error indicates duplicate entry
    """
    if isinstance(error, FortiManagerMCPError):
        # -2 "Object already exists" per ERROR_CODE_MAP (verified live).
        if error.code == -2:
            return True
    if isinstance(error, ObjectError):
        msg = str(error).lower()
        return "already exists" in msg or "duplicate" in msg
    return False


def is_permission_error(error: Exception) -> bool:
    """Check if error is permission-related.

    Args:
        error: Exception to check

    Returns:
        True if error is permission-related
    """
    if isinstance(error, FortiManagerMCPError):
        # -11 no permission / stale session, -10147 no write permission,
        # per ERROR_CODE_MAP (verified live). -3 is not-found, not permission.
        if error.code in (-11, -10147):
            return True
    return isinstance(error, PermissionError)


def is_auth_error(error: Exception) -> bool:
    """Check if error is authentication-related.

    Args:
        error: Exception to check

    Returns:
        True if error is authentication-related
    """
    if isinstance(error, FortiManagerMCPError):
        # -22 login fail per ERROR_CODE_MAP (verified live). -2 is a
        # duplicate-object error, not an auth failure.
        if error.code == -22:
            return True
    return isinstance(error, AuthenticationError)
