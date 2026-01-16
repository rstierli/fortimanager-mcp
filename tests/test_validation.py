"""Tests for FortiManager MCP validation and sanitization utilities."""

from pathlib import Path

import pytest

from fortimanager_mcp.utils.validation import (
    MASK_VALUE,
    VALID_ADDRESS_TYPES,
    VALID_LOG_TRAFFIC_MODES,
    VALID_MOVE_POSITIONS,
    VALID_POLICY_ACTIONS,
    ValidationError,
    get_allowed_output_dirs,
    sanitize_for_logging,
    sanitize_json_for_logging,
    validate_address_type,
    validate_adom,
    validate_device_name,
    validate_device_serial,
    validate_filename,
    validate_fqdn,
    validate_interface_name,
    validate_ipv4_address,
    validate_ipv4_subnet,
    validate_log_traffic_mode,
    validate_move_position,
    validate_ngfw_mode,
    validate_object_name,
    validate_output_path,
    validate_package_name,
    validate_policy_action,
    validate_policy_id,
    validate_policy_name,
    validate_port_range,
    validate_status,
)

# =============================================================================
# Log Sanitization Tests
# =============================================================================


class TestSanitizeForLogging:
    """Tests for sanitize_for_logging function."""

    def test_masks_password_field(self):
        """Test that password fields are masked."""
        data = {"user": "admin", "password": "secret123"}
        result = sanitize_for_logging(data)
        assert result["user"] == "admin"
        assert result["password"] == MASK_VALUE

    def test_masks_token_field(self):
        """Test that token fields are masked."""
        data = {"api_token": "abc123xyz"}
        result = sanitize_for_logging(data)
        assert result["api_token"] == MASK_VALUE

    def test_masks_nested_sensitive_fields(self):
        """Test sanitization of nested dictionaries."""
        data = {
            "config": {
                "host": "fmg.example.com",
                "auth": {"username": "admin", "password": "secret"},
            }
        }
        result = sanitize_for_logging(data)
        assert result["config"]["host"] == "fmg.example.com"
        # "auth" key is sensitive, so entire value is masked
        assert result["config"]["auth"] == MASK_VALUE

    def test_masks_in_lists(self):
        """Test sanitization in list of dicts."""
        data = [{"user": "a", "password": "x"}, {"user": "b", "password": "y"}]
        result = sanitize_for_logging(data)
        assert result[0]["password"] == MASK_VALUE
        assert result[1]["password"] == MASK_VALUE

    def test_masks_long_hex_strings(self):
        """Test that long hex strings (likely tokens) are masked."""
        data = {"session": "abc123def456789012345"}  # >20 hex chars
        result = sanitize_for_logging(data)
        assert result["session"] == MASK_VALUE

    def test_preserves_short_hex_strings(self):
        """Test that short hex strings are preserved."""
        data = {"id": "abc123"}
        result = sanitize_for_logging(data)
        assert result["id"] == "abc123"

    def test_handles_max_depth(self):
        """Test that deep nesting is handled."""
        # Create deeply nested structure
        data = {"level": 0}
        current = data
        for i in range(15):
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        result = sanitize_for_logging(data)
        # Should not raise, should truncate at max depth
        assert "level" in result

    def test_handles_primitives(self):
        """Test handling of primitive types."""
        assert sanitize_for_logging("test") == "test"
        assert sanitize_for_logging(123) == 123
        assert sanitize_for_logging(None) is None
        assert sanitize_for_logging(True) is True

    def test_case_insensitive_field_matching(self):
        """Test that field matching is case-insensitive."""
        data = {"PASSWORD": "secret", "Api_Token": "token123"}
        result = sanitize_for_logging(data)
        assert result["PASSWORD"] == MASK_VALUE
        assert result["Api_Token"] == MASK_VALUE


class TestSanitizeJsonForLogging:
    """Tests for sanitize_json_for_logging function."""

    def test_returns_json_string(self):
        """Test that function returns JSON string."""
        data = {"user": "admin", "password": "secret"}
        result = sanitize_json_for_logging(data)
        assert isinstance(result, str)
        assert '"user": "admin"' in result
        assert MASK_VALUE in result

    def test_with_indent(self):
        """Test JSON with indentation."""
        data = {"key": "value"}
        result = sanitize_json_for_logging(data, indent=2)
        assert "\n" in result


# =============================================================================
# ADOM Validation Tests
# =============================================================================


class TestValidateAdom:
    """Tests for validate_adom function."""

    @pytest.mark.parametrize(
        "adom",
        [
            "root",
            "demo",
            "my-adom",
            "adom_test",
            "ADOM123",
            "a" * 64,  # Max length
        ],
    )
    def test_valid_adom_names(self, adom):
        """Test valid ADOM names pass validation."""
        assert validate_adom(adom) == adom

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_adom("  root  ") == "root"

    @pytest.mark.parametrize(
        "adom",
        [
            "",
            "adom.name",  # Dot not allowed
            "adom name",  # Space not allowed
            "adom@name",  # Special char
            "a" * 65,  # Too long
        ],
    )
    def test_invalid_adom_names(self, adom):
        """Test invalid ADOM names raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_adom(adom)


# =============================================================================
# Device Validation Tests
# =============================================================================


class TestValidateDeviceName:
    """Tests for validate_device_name function."""

    @pytest.mark.parametrize(
        "device",
        [
            "FGT-01",
            "firewall.local",
            "device_name",
            "FGT-Branch-01",
        ],
    )
    def test_valid_device_names(self, device):
        """Test valid device names pass validation."""
        assert validate_device_name(device) == device

    def test_device_with_vdom(self):
        """Test device name with VDOM suffix."""
        result = validate_device_name("FGT-01[root]")
        assert result == "FGT-01[root]"

    @pytest.mark.parametrize(
        "device",
        [
            "",
            "device@name",
            "device name",  # Space not allowed
        ],
    )
    def test_invalid_device_names(self, device):
        """Test invalid device names raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_device_name(device)


class TestValidateDeviceSerial:
    """Tests for validate_device_serial function."""

    @pytest.mark.parametrize(
        "serial",
        [
            "FG100FTK19001234",
            "FGT60F0000000001",
            "FMVM0000000001",
            "fg100ftk19001234",  # Lowercase converted
        ],
    )
    def test_valid_serial_numbers(self, serial):
        """Test valid serial numbers pass validation."""
        result = validate_device_serial(serial)
        assert result == serial.upper()

    @pytest.mark.parametrize(
        "serial",
        [
            "",
            "INVALID123",  # Wrong prefix
            "FG123",  # Too short
            "XX100FTK19001234",  # Invalid prefix
        ],
    )
    def test_invalid_serial_numbers(self, serial):
        """Test invalid serial numbers raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_device_serial(serial)


# =============================================================================
# Package/Policy Name Validation Tests
# =============================================================================


class TestValidatePackageName:
    """Tests for validate_package_name function."""

    @pytest.mark.parametrize(
        "name",
        [
            "default",
            "branch-policy",
            "pkg_2024",
        ],
    )
    def test_valid_package_names(self, name):
        """Test valid package names pass validation."""
        assert validate_package_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "package name",  # Space
            "pkg.test",  # Dot
            "a" * 36,  # Too long (>35)
        ],
    )
    def test_invalid_package_names(self, name):
        """Test invalid package names raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_package_name(name)


class TestValidatePolicyName:
    """Tests for validate_policy_name function."""

    @pytest.mark.parametrize(
        "name",
        [
            "Allow-Web",
            "Deny All",  # Space allowed
            "policy.rule",  # Dot allowed
            "rule_01",
        ],
    )
    def test_valid_policy_names(self, name):
        """Test valid policy names pass validation."""
        assert validate_policy_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "policy@rule",  # Invalid char
            "a" * 36,  # Too long
        ],
    )
    def test_invalid_policy_names(self, name):
        """Test invalid policy names raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_policy_name(name)


class TestValidateObjectName:
    """Tests for validate_object_name function."""

    @pytest.mark.parametrize(
        "name",
        [
            "webserver",
            "web-server-01",
            "Server Group 1",
            "addr.internal",
        ],
    )
    def test_valid_object_names(self, name):
        """Test valid object names pass validation."""
        assert validate_object_name(name) == name

    def test_custom_object_type_in_error(self):
        """Test that object type appears in error message."""
        with pytest.raises(ValidationError) as exc_info:
            validate_object_name("", object_type="address")
        assert "Address" in str(exc_info.value)


# =============================================================================
# IP/Network Validation Tests
# =============================================================================


class TestValidateIpv4Address:
    """Tests for validate_ipv4_address function."""

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "10.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
        ],
    )
    def test_valid_ipv4_addresses(self, ip):
        """Test valid IPv4 addresses pass validation."""
        assert validate_ipv4_address(ip) == ip

    @pytest.mark.parametrize(
        "ip",
        [
            "",
            "256.1.1.1",  # Octet > 255
            "192.168.1",  # Missing octet
            "192.168.1.1.1",  # Extra octet
            "not.an.ip.addr",
        ],
    )
    def test_invalid_ipv4_addresses(self, ip):
        """Test invalid IPv4 addresses raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_ipv4_address(ip)


class TestValidateIpv4Subnet:
    """Tests for validate_ipv4_subnet function."""

    @pytest.mark.parametrize(
        "subnet",
        [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "0.0.0.0/0",
        ],
    )
    def test_valid_cidr_subnets(self, subnet):
        """Test valid CIDR subnets pass validation."""
        assert validate_ipv4_subnet(subnet) == subnet

    def test_valid_space_format_subnet(self):
        """Test subnet in 'IP netmask' format."""
        result = validate_ipv4_subnet("192.168.1.0 255.255.255.0")
        assert result == "192.168.1.0 255.255.255.0"

    @pytest.mark.parametrize(
        "subnet",
        [
            "",
            "192.168.1.0/33",  # Invalid prefix
            "192.168.1.0",  # Missing prefix
            "192.168.1.0/",  # Empty prefix
        ],
    )
    def test_invalid_subnets(self, subnet):
        """Test invalid subnets raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_ipv4_subnet(subnet)


class TestValidateFqdn:
    """Tests for validate_fqdn function."""

    @pytest.mark.parametrize(
        "fqdn",
        [
            "example.com",
            "www.example.com",
            "sub.domain.example.co.uk",
            "fmg.local.lan",
        ],
    )
    def test_valid_fqdns(self, fqdn):
        """Test valid FQDNs pass validation."""
        result = validate_fqdn(fqdn)
        assert result == fqdn.lower()

    @pytest.mark.parametrize(
        "fqdn",
        [
            "",
            "example",  # No TLD
            "-example.com",  # Starts with hyphen
            "example-.com",  # Ends with hyphen
        ],
    )
    def test_invalid_fqdns(self, fqdn):
        """Test invalid FQDNs raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_fqdn(fqdn)


# =============================================================================
# Port Validation Tests
# =============================================================================


class TestValidatePortRange:
    """Tests for validate_port_range function."""

    @pytest.mark.parametrize(
        "port_range",
        [
            "80",
            "443",
            "8080-8090",
            "80 443 8080",
            "22 80-90 443",
        ],
    )
    def test_valid_port_ranges(self, port_range):
        """Test valid port ranges pass validation."""
        assert validate_port_range(port_range) == port_range

    @pytest.mark.parametrize(
        "port_range",
        [
            "",
            "0",  # Port 0 invalid
            "65536",  # Port > 65535
            "100-50",  # Start > end
            "abc",  # Non-numeric
        ],
    )
    def test_invalid_port_ranges(self, port_range):
        """Test invalid port ranges raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_port_range(port_range)


# =============================================================================
# Policy/Mode Validation Tests
# =============================================================================


class TestValidatePolicyAction:
    """Tests for validate_policy_action function."""

    @pytest.mark.parametrize("action", list(VALID_POLICY_ACTIONS))
    def test_valid_actions(self, action):
        """Test all valid policy actions pass."""
        result = validate_policy_action(action)
        assert result == action.lower()

    def test_case_insensitive(self):
        """Test action validation is case-insensitive."""
        assert validate_policy_action("ACCEPT") == "accept"
        assert validate_policy_action("Deny") == "deny"

    def test_invalid_action(self):
        """Test invalid action raises error."""
        with pytest.raises(ValidationError) as exc_info:
            validate_policy_action("invalid")
        assert "accept" in str(exc_info.value).lower()


class TestValidateLogTrafficMode:
    """Tests for validate_log_traffic_mode function."""

    @pytest.mark.parametrize("mode", list(VALID_LOG_TRAFFIC_MODES))
    def test_valid_modes(self, mode):
        """Test all valid log traffic modes pass."""
        result = validate_log_traffic_mode(mode)
        assert result == mode.lower()

    def test_invalid_mode(self):
        """Test invalid mode raises error."""
        with pytest.raises(ValidationError):
            validate_log_traffic_mode("invalid")


class TestValidateStatus:
    """Tests for validate_status function."""

    def test_enable_status(self):
        """Test enable status."""
        assert validate_status("enable") == "enable"
        assert validate_status("ENABLE") == "enable"

    def test_disable_status(self):
        """Test disable status."""
        assert validate_status("disable") == "disable"

    def test_invalid_status(self):
        """Test invalid status raises error."""
        with pytest.raises(ValidationError):
            validate_status("on")


class TestValidateNgfwMode:
    """Tests for validate_ngfw_mode function."""

    def test_profile_based(self):
        """Test profile-based mode."""
        assert validate_ngfw_mode("profile-based") == "profile-based"

    def test_policy_based(self):
        """Test policy-based mode."""
        assert validate_ngfw_mode("policy-based") == "policy-based"

    def test_invalid_mode(self):
        """Test invalid mode raises error."""
        with pytest.raises(ValidationError):
            validate_ngfw_mode("invalid")


class TestValidateAddressType:
    """Tests for validate_address_type function."""

    @pytest.mark.parametrize("addr_type", list(VALID_ADDRESS_TYPES))
    def test_valid_types(self, addr_type):
        """Test all valid address types pass."""
        result = validate_address_type(addr_type)
        assert result == addr_type.lower()

    def test_invalid_type(self):
        """Test invalid type raises error."""
        with pytest.raises(ValidationError):
            validate_address_type("invalid")


class TestValidateMovePosition:
    """Tests for validate_move_position function."""

    @pytest.mark.parametrize("position", list(VALID_MOVE_POSITIONS))
    def test_valid_positions(self, position):
        """Test all valid move positions pass."""
        result = validate_move_position(position)
        assert result == position.lower()

    def test_invalid_position(self):
        """Test invalid position raises error."""
        with pytest.raises(ValidationError):
            validate_move_position("top")


class TestValidatePolicyId:
    """Tests for validate_policy_id function."""

    @pytest.mark.parametrize("policyid", [0, 1, 100, 999999])
    def test_valid_policy_ids(self, policyid):
        """Test valid policy IDs pass validation."""
        assert validate_policy_id(policyid) == policyid

    def test_negative_policy_id(self):
        """Test negative policy ID raises error."""
        with pytest.raises(ValidationError):
            validate_policy_id(-1)

    def test_none_policy_id(self):
        """Test None policy ID raises error."""
        with pytest.raises(ValidationError):
            validate_policy_id(None)

    def test_string_policy_id(self):
        """Test string policy ID raises error."""
        with pytest.raises(ValidationError):
            validate_policy_id("123")


# =============================================================================
# Path Validation Tests
# =============================================================================


class TestGetAllowedOutputDirs:
    """Tests for get_allowed_output_dirs function."""

    def test_returns_list(self):
        """Test function returns a list."""
        result = get_allowed_output_dirs()
        assert isinstance(result, list)

    def test_includes_home_directory(self):
        """Test that home directory is included by default."""
        result = get_allowed_output_dirs()
        assert Path.home() in result

    def test_custom_dirs_from_env(self, monkeypatch, tmp_path):
        """Test custom directories from environment variable."""
        # Create temp directories
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        monkeypatch.setenv("FMG_ALLOWED_OUTPUT_DIRS", f"{dir1},{dir2}")
        result = get_allowed_output_dirs()

        assert dir1 in result
        assert dir2 in result


class TestValidateOutputPath:
    """Tests for validate_output_path function."""

    def test_valid_home_path(self):
        """Test path within home directory is valid."""
        home = Path.home()
        result = validate_output_path(str(home))
        assert result == home

    def test_valid_downloads_path(self):
        """Test Downloads path is valid."""
        downloads = Path.home() / "Downloads"
        if downloads.exists():
            result = validate_output_path(str(downloads))
            assert result == downloads

    def test_tilde_expansion(self):
        """Test that ~ is expanded."""
        result = validate_output_path("~")
        assert result == Path.home()

    def test_empty_path_raises_error(self):
        """Test empty path raises error."""
        with pytest.raises(ValidationError):
            validate_output_path("")


class TestValidateFilename:
    """Tests for validate_filename function."""

    @pytest.mark.parametrize(
        "filename",
        [
            "report.pdf",
            "backup_2024.json",
            "config-export.txt",
            "my file.csv",
        ],
    )
    def test_valid_filenames(self, filename):
        """Test valid filenames pass validation."""
        result = validate_filename(filename)
        assert result == filename

    def test_strips_path(self):
        """Test that path is stripped from filename."""
        result = validate_filename("/path/to/file.txt")
        assert result == "file.txt"

    @pytest.mark.parametrize(
        "filename",
        [
            "",
            ".hidden",  # Hidden file
            "file|name",  # Pipe
            "file<name",  # Less than
            "file>name",  # Greater than
        ],
    )
    def test_invalid_filenames(self, filename):
        """Test invalid filenames raise error."""
        with pytest.raises(ValidationError):
            validate_filename(filename)


# =============================================================================
# Interface Validation Tests
# =============================================================================


class TestValidateInterfaceName:
    """Tests for validate_interface_name function."""

    @pytest.mark.parametrize(
        "name",
        [
            "port1",
            "wan1",
            "lan-zone",
            "dmz_interface",
        ],
    )
    def test_valid_interface_names(self, name):
        """Test valid interface names pass validation."""
        assert validate_interface_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "port 1",  # Space
            "port.1",  # Dot
            "a" * 36,  # Too long
        ],
    )
    def test_invalid_interface_names(self, name):
        """Test invalid interface names raise error."""
        with pytest.raises(ValidationError):
            validate_interface_name(name)
