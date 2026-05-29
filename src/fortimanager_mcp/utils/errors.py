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

# FortiManager API error codes and their corresponding exception classes
ERROR_CODE_MAP: dict[int, type[FortiManagerMCPError]] = {
    -1: APIError,  # Internal error
    -2: AuthenticationError,  # Invalid session
    -3: PermissionError,  # Permission denied
    -4: ResourceNotFoundError,  # Object not found
    -5: ValidationError,  # Invalid parameter
    -6: ObjectError,  # Entry already exists (duplicate)
    -7: ObjectError,  # Entry in use (cannot delete)
    -8: ADOMLockError,  # Workspace locked
    -9: ADOMLockError,  # Workspace has uncommitted changes
    -10: APIError,  # Version mismatch
    -11: TimeoutError,  # Task timeout
    -20: AuthenticationError,  # Invalid credentials
    -21: AuthenticationError,  # Token expired
}

# Human-readable messages for common error codes
ERROR_CODE_MESSAGES: dict[int, str] = {
    -1: "Internal server error occurred",
    -2: "Session is invalid or expired",
    -3: "Permission denied for this operation",
    -4: "Requested resource not found",
    -5: "Invalid parameter value",
    -6: "Object already exists",
    -7: "Cannot delete object - it is still in use",
    -8: "ADOM is locked by another user",
    -9: "ADOM has uncommitted changes",
    -10: "API version mismatch",
    -11: "Operation timed out",
    -20: "Invalid username or password",
    -21: "Authentication token has expired",
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
        if error.code == -6:
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
        if error.code == -3:
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
        if error.code in (-2, -20, -21):
            return True
    return isinstance(error, AuthenticationError)
