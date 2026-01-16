"""Tests for FortiManager MCP error classes and helpers."""

import pytest

from fortimanager_mcp.utils.errors import (
    ERROR_CODE_MAP,
    ERROR_CODE_MESSAGES,
    ADOMLockError,
    APIError,
    AuthenticationError,
    ConnectionError,
    DeviceError,
    FortiManagerMCPError,
    InstallError,
    ObjectError,
    PackageError,
    PermissionError,
    PolicyError,
    ResourceNotFoundError,
    ScriptError,
    TaskError,
    TemplateError,
    TimeoutError,
    ValidationError,
    is_auth_error,
    is_duplicate_error,
    is_object_in_use_error,
    is_permission_error,
    parse_fmg_error,
)

# =============================================================================
# Base Exception Tests
# =============================================================================


class TestFortiManagerMCPError:
    """Tests for base FortiManagerMCPError class."""

    def test_basic_instantiation(self):
        """Test basic error creation."""
        error = FortiManagerMCPError("Test error")
        assert str(error) == "Test error"
        assert error.code is None

    def test_with_error_code(self):
        """Test error with code."""
        error = FortiManagerMCPError("Test error", code=-4)
        assert str(error) == "Test error"
        assert error.code == -4

    def test_inheritance(self):
        """Test that it inherits from Exception."""
        error = FortiManagerMCPError("Test")
        assert isinstance(error, Exception)


# =============================================================================
# Specific Exception Tests
# =============================================================================


class TestSpecificExceptions:
    """Tests for specific exception classes."""

    @pytest.mark.parametrize(
        "exception_class,expected_base",
        [
            (AuthenticationError, FortiManagerMCPError),
            (ConnectionError, FortiManagerMCPError),
            (APIError, FortiManagerMCPError),
            (ValidationError, FortiManagerMCPError),
            (ResourceNotFoundError, FortiManagerMCPError),
            (PermissionError, FortiManagerMCPError),
            (TimeoutError, FortiManagerMCPError),
            (ADOMLockError, FortiManagerMCPError),
            (TaskError, FortiManagerMCPError),
            (PolicyError, FortiManagerMCPError),
            (PackageError, FortiManagerMCPError),
            (ObjectError, FortiManagerMCPError),
            (TemplateError, FortiManagerMCPError),
            (ScriptError, FortiManagerMCPError),
            (DeviceError, FortiManagerMCPError),
            (InstallError, FortiManagerMCPError),
        ],
    )
    def test_inheritance(self, exception_class, expected_base):
        """Test that all exceptions inherit from base."""
        error = exception_class("Test error")
        assert isinstance(error, expected_base)
        assert isinstance(error, Exception)

    def test_authentication_error_with_code(self):
        """Test AuthenticationError with error code."""
        error = AuthenticationError("Invalid credentials", code=-20)
        assert error.code == -20
        assert "Invalid credentials" in str(error)

    def test_resource_not_found_error(self):
        """Test ResourceNotFoundError."""
        error = ResourceNotFoundError("ADOM 'test' not found", code=-4)
        assert error.code == -4

    def test_adom_lock_error(self):
        """Test ADOMLockError."""
        error = ADOMLockError("ADOM locked by admin", code=-8)
        assert error.code == -8


# =============================================================================
# Error Code Mapping Tests
# =============================================================================


class TestErrorCodeMapping:
    """Tests for error code mapping."""

    def test_error_code_map_contains_expected_codes(self):
        """Test that ERROR_CODE_MAP has expected codes."""
        expected_codes = [-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -20, -21]
        for code in expected_codes:
            assert code in ERROR_CODE_MAP

    def test_error_code_messages_match_map(self):
        """Test that all mapped codes have messages."""
        for code in ERROR_CODE_MAP:
            assert code in ERROR_CODE_MESSAGES

    @pytest.mark.parametrize(
        "code,expected_class",
        [
            (-1, APIError),
            (-2, AuthenticationError),
            (-3, PermissionError),
            (-4, ResourceNotFoundError),
            (-5, ValidationError),
            (-6, ObjectError),
            (-7, ObjectError),
            (-8, ADOMLockError),
            (-9, ADOMLockError),
            (-10, APIError),
            (-11, TimeoutError),
            (-20, AuthenticationError),
            (-21, AuthenticationError),
        ],
    )
    def test_code_to_exception_mapping(self, code, expected_class):
        """Test correct exception class for each code."""
        assert ERROR_CODE_MAP[code] == expected_class


# =============================================================================
# parse_fmg_error Tests
# =============================================================================


class TestParseFmgError:
    """Tests for parse_fmg_error function."""

    def test_known_error_code(self):
        """Test parsing known error code."""
        error = parse_fmg_error(-4, "Object not found")
        assert isinstance(error, ResourceNotFoundError)
        assert error.code == -4

    def test_unknown_error_code(self):
        """Test parsing unknown error code defaults to APIError."""
        error = parse_fmg_error(-999, "Unknown error")
        assert isinstance(error, APIError)
        assert error.code == -999

    def test_with_url_context(self):
        """Test error includes URL context."""
        error = parse_fmg_error(-4, "Not found", url="/dvmdb/device")
        assert "/dvmdb/device" in str(error)

    def test_auth_error_code(self):
        """Test authentication error code."""
        error = parse_fmg_error(-20, "Invalid credentials")
        assert isinstance(error, AuthenticationError)

    def test_permission_error_code(self):
        """Test permission error code."""
        error = parse_fmg_error(-3, "Access denied")
        assert isinstance(error, PermissionError)

    def test_lock_error_code(self):
        """Test ADOM lock error code."""
        error = parse_fmg_error(-8, "Workspace locked")
        assert isinstance(error, ADOMLockError)

    def test_message_combines_base_and_detail(self):
        """Test that message combines base message with detail."""
        error = parse_fmg_error(-4, "Device XYZ")
        # Should contain both base message and detail
        assert "not found" in str(error).lower()


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestIsObjectInUseError:
    """Tests for is_object_in_use_error function."""

    def test_with_code_minus_7(self):
        """Test detection by error code -7."""
        error = FortiManagerMCPError("Error", code=-7)
        assert is_object_in_use_error(error) is True

    def test_with_object_error_in_use_message(self):
        """Test detection by 'in use' message."""
        error = ObjectError("Object is in use by policy")
        assert is_object_in_use_error(error) is True

    def test_with_object_error_referenced_message(self):
        """Test detection by 'referenced' message."""
        error = ObjectError("Object is referenced by group")
        assert is_object_in_use_error(error) is True

    def test_with_unrelated_error(self):
        """Test returns False for unrelated error."""
        error = ValidationError("Invalid name")
        assert is_object_in_use_error(error) is False

    def test_with_non_fmg_exception(self):
        """Test returns False for non-FMG exception."""
        error = ValueError("Some error")
        assert is_object_in_use_error(error) is False


class TestIsDuplicateError:
    """Tests for is_duplicate_error function."""

    def test_with_code_minus_6(self):
        """Test detection by error code -6."""
        error = FortiManagerMCPError("Error", code=-6)
        assert is_duplicate_error(error) is True

    def test_with_already_exists_message(self):
        """Test detection by 'already exists' message."""
        error = ObjectError("Object 'test' already exists")
        assert is_duplicate_error(error) is True

    def test_with_duplicate_message(self):
        """Test detection by 'duplicate' message."""
        error = ObjectError("Duplicate entry detected")
        assert is_duplicate_error(error) is True

    def test_with_unrelated_error(self):
        """Test returns False for unrelated error."""
        error = ResourceNotFoundError("Not found")
        assert is_duplicate_error(error) is False


class TestIsPermissionError:
    """Tests for is_permission_error function."""

    def test_with_code_minus_3(self):
        """Test detection by error code -3."""
        error = FortiManagerMCPError("Error", code=-3)
        assert is_permission_error(error) is True

    def test_with_permission_error_instance(self):
        """Test detection by PermissionError type."""
        error = PermissionError("Access denied")
        assert is_permission_error(error) is True

    def test_with_unrelated_error(self):
        """Test returns False for unrelated error."""
        error = AuthenticationError("Bad password")
        assert is_permission_error(error) is False


class TestIsAuthError:
    """Tests for is_auth_error function."""

    def test_with_code_minus_2(self):
        """Test detection by error code -2."""
        error = FortiManagerMCPError("Error", code=-2)
        assert is_auth_error(error) is True

    def test_with_code_minus_20(self):
        """Test detection by error code -20."""
        error = FortiManagerMCPError("Error", code=-20)
        assert is_auth_error(error) is True

    def test_with_code_minus_21(self):
        """Test detection by error code -21."""
        error = FortiManagerMCPError("Error", code=-21)
        assert is_auth_error(error) is True

    def test_with_authentication_error_instance(self):
        """Test detection by AuthenticationError type."""
        error = AuthenticationError("Invalid session")
        assert is_auth_error(error) is True

    def test_with_unrelated_error(self):
        """Test returns False for unrelated error."""
        error = TimeoutError("Request timeout")
        assert is_auth_error(error) is False
