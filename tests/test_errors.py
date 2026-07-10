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
    client_safe_error,
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
        expected_codes = [
            -1,
            -2,
            -3,
            -4,
            -5,
            -6,
            -7,
            -8,
            -9,
            -10,
            -11,
            -22,
            -10015,
            -10147,
            -20055,
        ]
        for code in expected_codes:
            assert code in ERROR_CODE_MAP

    def test_error_code_messages_match_map(self):
        """Test that all mapped codes have messages."""
        for code in ERROR_CODE_MAP:
            assert code in ERROR_CODE_MESSAGES

    @pytest.mark.parametrize(
        "code,expected_class",
        [
            # Codes verified live against FMG 7.6.7 (issue #21).
            (-1, APIError),
            (-2, ObjectError),  # Object already exists
            (-3, ResourceNotFoundError),  # Object does not exist
            (-4, ResourceNotFoundError),
            (-5, APIError),  # No such command
            (-6, ValidationError),  # Invalid URL
            (-7, ObjectError),
            (-8, ValidationError),  # Invalid parameter
            (-9, ValidationError),  # Command invalid for selected URL
            (-10, ValidationError),  # Data invalid for selected URL
            (-11, PermissionError),  # No permission / stale session
            (-22, AuthenticationError),  # Login fail
            (-10015, ObjectError),  # Object in use ("used"), delete refused
            (-10147, PermissionError),  # No write permission
            (-20055, ADOMLockError),  # Workspace locked by another admin
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
        """Test authentication error code (-22 = login fail, verified live)."""
        error = parse_fmg_error(-22, "Login fail")
        assert isinstance(error, AuthenticationError)

    def test_permission_error_code(self):
        """Test permission error code (-11, verified live)."""
        error = parse_fmg_error(-11, "No permission for the resource")
        assert isinstance(error, PermissionError)

    def test_lock_error_code(self):
        """Test ADOM lock error code (-20055, verified live)."""
        error = parse_fmg_error(-20055, "Workspace is locked by other user")
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

    def test_with_code_minus_10015(self):
        """Test detection by error code -10015 (verified live on FMG 7.6.7)."""
        error = FortiManagerMCPError("used", code=-10015)
        assert is_object_in_use_error(error) is True

    def test_with_object_error_used_message(self):
        """Test detection by the raw FMG 'used' message."""
        error = ObjectError("used")
        assert is_object_in_use_error(error) is True

    def test_unused_message_is_not_in_use(self):
        """Test 'unused'/'caused' do not false-positive the 'used' match."""
        assert is_object_in_use_error(ObjectError("entry is unused")) is False
        assert is_object_in_use_error(ObjectError("caused a failure")) is False

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

    def test_with_code_minus_2(self):
        """Test detection by error code -2 (object already exists)."""
        error = FortiManagerMCPError("Error", code=-2)
        assert is_duplicate_error(error) is True

    def test_code_minus_6_is_not_duplicate(self):
        """-6 is 'invalid URL' per ERROR_CODE_MAP, not a duplicate."""
        error = FortiManagerMCPError("Error", code=-6)
        assert is_duplicate_error(error) is False

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

    def test_with_code_minus_11(self):
        """Test detection by error code -11 (no permission / stale session)."""
        error = FortiManagerMCPError("Error", code=-11)
        assert is_permission_error(error) is True

    def test_with_code_minus_10147(self):
        """Test detection by error code -10147 (no write permission)."""
        error = FortiManagerMCPError("Error", code=-10147)
        assert is_permission_error(error) is True

    def test_code_minus_3_is_not_permission(self):
        """-3 is 'object does not exist' per ERROR_CODE_MAP, not permission."""
        error = FortiManagerMCPError("Error", code=-3)
        assert is_permission_error(error) is False

    def test_with_permission_error_instance(self):
        """Test detection by PermissionError type."""
        error = PermissionError("Access denied")
        assert is_permission_error(error) is True

    def test_with_unrelated_error(self):
        """Test returns False for unrelated error."""
        error = AuthenticationError("Bad password")
        assert is_permission_error(error) is False


class TestClientSafeError:
    """Tests for client_safe_error sanitizer (LOW 2: no endpoint leakage)."""

    def test_strips_endpoint_suffix(self):
        """parse_fmg_error appends '(endpoint: ...)' — must not leak to caller."""
        err = parse_fmg_error(-4, "Object not found", url="GET /dvmdb/adom/root/device/FGT")
        msg, code = client_safe_error(err)
        assert "endpoint" not in msg
        assert "/dvmdb" not in msg
        assert code == "not_found"

    def test_uses_mapped_message_for_known_code(self):
        err = parse_fmg_error(-3, "raw body /pm/config/adom/root/obj/firewall/address/x")
        msg, code = client_safe_error(err)
        assert "/pm/config" not in msg
        assert code == "not_found"

    def test_scrubs_api_path_from_plain_exception(self):
        err = Exception("failure at /pm/config/adom/root/pkg/default/firewall/policy/5")
        msg, _ = client_safe_error(err)
        assert "/pm/config" not in msg

    def test_validation_error_message_preserved(self):
        """ValueError (input validation) is caller-supplied, safe to surface."""
        err = ValueError("Invalid ADOM name 'bad/name'")
        msg, code = client_safe_error(err)
        assert "Invalid ADOM name" in msg
        assert code == "validation_error"

    def test_runtime_error_message_preserved_no_path(self):
        err = RuntimeError("FortiManager client not initialized")
        msg, code = client_safe_error(err)
        assert "not initialized" in msg
        assert code == "internal_error"

    def test_in_use_delete_maps_to_object_error(self):
        """Raw FMG -10015 'used' surfaces as object_error with a clear message."""
        err = parse_fmg_error(
            -10015, "used", url="/pm/config/adom/root/obj/firewall/service/custom/x"
        )
        msg, code = client_safe_error(err)
        assert code == "object_error"
        assert "in use" in msg
        assert "/pm/config" not in msg


class TestIsAuthError:
    """Tests for is_auth_error function."""

    def test_with_code_minus_22(self):
        """Test detection by error code -22 (login fail)."""
        error = FortiManagerMCPError("Error", code=-22)
        assert is_auth_error(error) is True

    def test_code_minus_2_is_not_auth(self):
        """-2 is 'object already exists' per ERROR_CODE_MAP, not auth."""
        error = FortiManagerMCPError("Error", code=-2)
        assert is_auth_error(error) is False

    def test_with_authentication_error_instance(self):
        """Test detection by AuthenticationError type."""
        error = AuthenticationError("Invalid session")
        assert is_auth_error(error) is True

    def test_with_unrelated_error(self):
        """Test returns False for unrelated error."""
        error = TimeoutError("Request timeout")
        assert is_auth_error(error) is False
