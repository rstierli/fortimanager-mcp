"""Custom error classes for FortiManager MCP server."""


class FortiManagerMCPError(Exception):
    """Base exception for FortiManager MCP errors."""

    pass


class AuthenticationError(FortiManagerMCPError):
    """Authentication failed."""

    pass


class ConnectionError(FortiManagerMCPError):
    """Connection to FortiManager failed."""

    pass


class APIError(FortiManagerMCPError):
    """FortiManager API returned an error."""

    pass


class ValidationError(FortiManagerMCPError):
    """Input validation failed."""

    pass


class ADOMLockError(FortiManagerMCPError):
    """ADOM lock/unlock operation failed."""

    pass


class TaskError(FortiManagerMCPError):
    """Task execution or monitoring failed."""

    pass
