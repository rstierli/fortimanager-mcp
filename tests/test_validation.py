"""Tests for FortiManager MCP validation and sanitization utilities."""

from pathlib import Path

import pytest

from fortimanager_mcp.utils.validation import (
    CONFIG_TEXT_SECRET_DIRECTIVES,
    MASK_VALUE,
    VALID_ADDRESS_TYPES,
    VALID_LOG_TRAFFIC_MODES,
    VALID_MOVE_POSITIONS,
    VALID_POLICY_ACTIONS,
    ValidationError,
    coerce_device_name_list,
    get_allowed_output_dirs,
    redact_config_text_secrets,
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
    validate_security_profiles,
    validate_status,
    validate_task_id,
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


class TestRedactConfigTextSecrets:
    """Tests for redact_config_text_secrets (CLI config-text redaction)."""

    def test_redacts_known_secret_directives(self):
        text = "config vpn ipsec phase1-interface\n    set psksecret ENC AbC123==\nend\n"
        result = redact_config_text_secrets(text)
        assert "AbC123==" not in result
        assert "set psksecret ***REDACTED***" in result

    def test_redacts_multiple_directives_independently(self):
        text = (
            "    set password ENC PwdValue==\n"
            "    set community public-string\n"
            "    set private-key '-----BEGIN KEY-----'\n"
        )
        result = redact_config_text_secrets(text)
        assert "PwdValue" not in result
        assert "public-string" not in result
        assert "BEGIN KEY" not in result
        assert result.count(MASK_VALUE) == 3

    def test_does_not_touch_non_secret_lines(self):
        text = "config system global\n    set hostname myfw01\nend\n"
        assert redact_config_text_secrets(text) == text

    def test_does_not_false_match_similar_directive_names(self):
        """passwd-time is a real FortiOS field name (a timeout in minutes,
        not a secret) -- must not be caught by a "passwd" substring match."""
        text = "    set passwd-time 5\n"
        assert redact_config_text_secrets(text) == text

    def test_preserves_directive_name_and_structure(self):
        text = "    edit hq-gw\n        set psksecret ENC X==\n    next\n"
        result = redact_config_text_secrets(text)
        assert "edit hq-gw" in result
        assert "next" in result
        assert "set psksecret ***REDACTED***" in result

    def test_empty_string(self):
        assert redact_config_text_secrets("") == ""

    def test_redacts_pr65_08_18_review_directives(self):
        """PR #65 review (Christian, 08-18): 8 more format=password
        directives confirmed against the bundled 8.0.0 swagger --
        sdn-connector, api-user, user fsso, user radius, router
        key-chain/ospf -- were reachable via config-text export but
        missing from CONFIG_TEXT_SECRET_DIRECTIVES."""
        text = (
            "    set secret-key ENC AAA==\n"
            "    set client-secret ENC BBB==\n"
            "    set api-key ENC CCC==\n"
            "    set password2 ENC DDD==\n"
            "    set password3 ENC EEE==\n"
            "    set password4 ENC FFF==\n"
            "    set password5 ENC GGG==\n"
            "    set rsso-secret ENC HHH==\n"
            "    set key-string ENC III==\n"
        )
        result = redact_config_text_secrets(text)
        for raw in (
            "AAA==",
            "BBB==",
            "CCC==",
            "DDD==",
            "EEE==",
            "FFF==",
            "GGG==",
            "HHH==",
            "III==",
        ):
            assert raw not in result
        assert result.count(MASK_VALUE) == 9

    def test_redacts_multiline_quoted_value(self):
        """PR #65 review (Christian): a per-line regex only caught the
        first line of a multi-line quoted value like a PEM private key --
        the body and END line leaked raw. Live-reproduced against a real
        multi-line private-key export before fixing."""
        text = (
            "config vpn certificate local\n"
            '    edit "mycert"\n'
            '        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
            "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI\n"
            '-----END ENCRYPTED PRIVATE KEY-----"\n'
            '        set comment "prod cert"\n'
            "    next\n"
            "end\n"
        )
        result = redact_config_text_secrets(text)
        assert "MIIFHDBOBgkqhkiG9w0BBQ0w" not in result
        assert "END ENCRYPTED PRIVATE KEY" not in result
        assert "BEGIN ENCRYPTED PRIVATE KEY" not in result
        assert "set private-key ***REDACTED***" in result
        # unrelated lines survive untouched
        assert 'edit "mycert"' in result
        assert 'set comment "prod cert"' in result
        assert "next" in result
        assert "end" in result

    def test_unterminated_quote_redacts_to_end_of_text(self):
        """A truncated export (no closing quote) must fail closed -- redact
        everything after the opening line rather than guess where a close
        that isn't there would have been."""
        text = 'set private-key "-----BEGIN KEY-----\nMIIsomebody\nmore body\n'
        result = redact_config_text_secrets(text)
        assert "MIIsomebody" not in result
        assert "more body" not in result
        assert "set private-key ***REDACTED***" in result

    def test_single_line_quoted_value_unaffected(self):
        """A quoted value that opens and closes on the same line is not
        mistaken for a multi-line one -- only the matched line is touched."""
        text = 'set comment "hello world"\nset psksecret "ENC AbC=="\nset hostname fw01\n'
        result = redact_config_text_secrets(text)
        assert 'set comment "hello world"' in result
        assert "ENC AbC==" not in result
        assert "set hostname fw01" in result

    @pytest.mark.parametrize(
        "directive",
        [
            "sae-password",
            "login-passwd",
            "authpasswd",
            "priv-pwd",
            "tertiary-secret",
            "group-authentication-secret",
            "authkey",
            "enckey",
        ],
    )
    def test_redacts_previously_missing_directives(self, directive):
        """PR #65 review (Christian): these were declared secret by sibling
        field lists elsewhere in the same PR (_VAP_SECRET_FIELDS,
        _WTP_SECRET_FIELDS, _PHASE1_SECRET_FIELDS) but missing from this
        list, so they leaked raw despite the codebase already knowing they
        were sensitive."""
        text = f"    set {directive} ENC XYZ123==\n"
        result = redact_config_text_secrets(text)
        assert "XYZ123" not in result
        assert f"set {directive} ***REDACTED***" in result

    def test_tacacs_secret_directive_removed(self):
        """The old tacacs+-secret entry never matched anything real -- the
        documented TACACS+ secret fields are key/secondary-key/tertiary-key
        (confirmed against the FNDN schema, type "password")."""
        assert "tacacs+-secret" not in CONFIG_TEXT_SECRET_DIRECTIVES
        for directive in ("key", "secondary-key", "tertiary-key"):
            text = f"    set {directive} ENC realsecret==\n"
            result = redact_config_text_secrets(text)
            assert "realsecret" not in result


# =============================================================================
# Secret Directive Coverage Tests
# =============================================================================

#: Every directive redact_config_text_secrets is required to mask.
#:
#: Deliberately a second, hand-maintained copy of
#: CONFIG_TEXT_SECRET_DIRECTIVES rather than a reference to it. A test
#: parametrized over the live set cannot fail when an entry is deleted:
#: _CONFIG_TEXT_SECRET_LINE is built from that same set at import time, so
#: a surviving entry always redacts and a deleted one simply drops out of
#: the parametrization. Measured while closing upstream #68 -- deleting
#: "auth-pwd" with exactly that test in place left the suite green at 1428
#: passed, the case count sliding 37 -> 36 with nothing to notice.
#:
#: The cost is that adding a directive fails this test until the name is
#: added here too. That is the intent: both directions become a deliberate
#: edit rather than a silent one.
EXPECTED_CONFIG_TEXT_SECRET_DIRECTIVES = frozenset(
    {
        "api-key",
        "auth-pwd",
        "auth-pwd-alt",
        "authkey",
        "authpasswd",
        "certificate-password",
        "client-secret",
        "community",
        "enckey",
        "group-authentication-secret",
        "key",
        "key-string",
        "login-passwd",
        "logon-password",
        "passphrase",
        "passwd",
        "password",
        "password2",
        "password3",
        "password4",
        "password5",
        "ppk-secret",
        "preshared-key",
        "priv-pwd",
        "private-key",
        "psksecret",
        "psksecret-remote",
        "radius-secret",
        "rsso-secret",
        "sae-password",
        "secondary-key",
        "secondary-secret",
        "secret",
        "secret-key",
        "sso-password",
        "tertiary-key",
        "tertiary-secret",
    }
)


class TestConfigTextSecretDirectiveCoverage:
    """The directive set is pinned, and every pinned entry is exercised.

    Coverage here used to be per-directive and added by hand, so it drifted
    out of sync with the set it was meant to cover: 14 of the 37 entries
    could be deleted with the full suite green, each deletion returning
    that secret in clear from get_device_revision and both sides of
    diff_device_revision (upstream #68).
    """

    def test_the_directive_set_matches_the_pinned_list(self):
        """A deletion is the failure this pins. An addition fails too, on
        purpose -- the new name has to be added here, which is where it
        picks up the redaction test below."""
        dropped = EXPECTED_CONFIG_TEXT_SECRET_DIRECTIVES - CONFIG_TEXT_SECRET_DIRECTIVES
        added = CONFIG_TEXT_SECRET_DIRECTIVES - EXPECTED_CONFIG_TEXT_SECRET_DIRECTIVES
        assert not dropped, (
            f"{len(dropped)} directive(s) left CONFIG_TEXT_SECRET_DIRECTIVES: "
            f"{sorted(dropped)}. Each one now returns in clear from "
            f"get_device_revision and both sides of diff_device_revision."
        )
        assert not added, (
            f"{len(added)} directive(s) added to CONFIG_TEXT_SECRET_DIRECTIVES: "
            f"{sorted(added)}. Add them to "
            f"EXPECTED_CONFIG_TEXT_SECRET_DIRECTIVES so they get covered."
        )

    @pytest.mark.parametrize("directive", sorted(EXPECTED_CONFIG_TEXT_SECRET_DIRECTIVES))
    def test_each_pinned_directive_redacts(self, directive):
        text = f"    set {directive} ENC SECRETVALUE==\n"
        result = redact_config_text_secrets(text)
        assert "SECRETVALUE" not in result
        # The literal, not MASK_VALUE. Asserting against the imported
        # constant is self-referential: emptying MASK_VALUE keeps this test
        # green while every secret starts coming back unmasked.
        assert f"set {directive} ***REDACTED***" in result

    @pytest.mark.parametrize("directive", sorted(EXPECTED_CONFIG_TEXT_SECRET_DIRECTIVES))
    def test_each_pinned_directive_redacts_across_a_tab_separator(self, directive):
        """Every other case here puts exactly one space after the directive.

        Narrowing the matcher's separator from ``\\s+`` to a literal single
        space leaves the whole suite green while a tab-separated secret line
        goes out in clear. Measured, so the separator is pinned rather than
        assumed.
        """
        text = f"    set {directive}\tENC TabbedSecret==\n"
        result = redact_config_text_secrets(text)
        assert "TabbedSecret" not in result
        assert "***REDACTED***" in result

    @pytest.mark.parametrize("directive", sorted(EXPECTED_CONFIG_TEXT_SECRET_DIRECTIVES))
    def test_each_pinned_directive_redacts_an_unencoded_value(self, directive):
        """Not every secret in a config export is ENC-wrapped.

        The case above uses an "ENC ..." value for all 37, so a matcher
        narrowed to only that shape would pass it while leaving every
        plaintext value in clear. A community string or a WEP key is
        written bare.
        """
        text = f"    set {directive} PlainTextSecret\n"
        result = redact_config_text_secrets(text)
        assert "PlainTextSecret" not in result
        assert f"set {directive} ***REDACTED***" in result


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


class TestCoerceDeviceNameList:
    """Tests for coerce_device_name_list -- shared by every bulk-device
    tool (dvm_tools, script_tools, device_group_tools) since a bare string
    iterated character-by-character is exactly how "FGT-01" became six
    bogus single-character device names (upstream #71)."""

    def test_a_list_passes_through(self):
        assert coerce_device_name_list(["FGT-01", "FGT-02"]) == ["FGT-01", "FGT-02"]

    def test_a_bare_string_becomes_a_one_element_list(self):
        assert coerce_device_name_list("FGT-01") == ["FGT-01"]

    def test_rejects_a_dict(self):
        """list({"devices": [...]}) returns the dict's keys, not its
        values -- a caller nesting the argument one level too deep must be
        refused, not silently coerced to a list containing the dict's own
        key names."""
        with pytest.raises(ValidationError):
            coerce_device_name_list({"devices": ["FGT-01", "FGT-02"]})


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
            "Corporate/Branch-Policy",  # Folder-nested package
            "A/B/C/D/E/F/G/H/I/J",  # Max depth (10 segments)
            "package name",  # Space within a segment
            "Corporate Office/Branch Policy",  # Spaces in a folder path
            "a" + " " * 33 + "c",  # Max-length segment (35 chars) with spaces
        ],
    )
    def test_valid_package_names(self, name):
        """Test valid package names pass validation."""
        assert validate_package_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "pkg.test",  # Dot
            "a" * 36,  # Too long (>35)
            "/Branch-Policy",  # Leading slash
            "Corporate/",  # Trailing slash
            "Corporate//Branch-Policy",  # Empty segment
            "Corporate/../etc",  # Path traversal
            "A/B/C/D/E/F/G/H/I/J/K",  # Too many segments (>10)
            "Corporate /Branch",  # Trailing space in a segment
            "Corporate/ Branch",  # Leading space in a segment
            " ",  # Segment that is only a space
            "Corporate/ /Branch",  # Middle segment that is only a space
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

    def test_rejects_bool(self):
        """bool is a subclass of int, so True would otherwise pass the
        isinstance check and silently address policy ID 1 -- the same gap
        validate_task_id explicitly guards against."""
        with pytest.raises(ValidationError):
            validate_policy_id(True)


class TestValidateSecurityProfiles:
    """Tests for validate_security_profiles function (#48)."""

    def _call(self, **overrides):
        args = {
            "utm_status": None,
            "profile_group": None,
            "av_profile": None,
            "ips_sensor": None,
            "webfilter_profile": None,
            "dnsfilter_profile": None,
            "application_list": None,
            "file_filter_profile": None,
            "ssl_ssh_profile": None,
            "profile_protocol_options": None,
        }
        args.update(overrides)
        return validate_security_profiles(**args)

    def test_no_fields_set_is_valid(self):
        """Nothing supplied is always valid (nothing to check)."""
        assert self._call() is None

    def test_individual_profiles_alone_valid(self):
        """Individual profile fields with no profile_group are valid."""
        assert (
            self._call(
                utm_status=True,
                av_profile="default",
                ips_sensor="default",
                ssl_ssh_profile="certificate-inspection",
                profile_protocol_options="default",
            )
            is None
        )

    def test_profile_group_alone_valid(self):
        """profile_group with no individual profile fields is valid."""
        assert self._call(utm_status=True, profile_group="Corporate-Profiles") is None

    def test_profile_group_with_one_individual_field_rejected(self):
        """profile_group plus a single individual profile field is rejected."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            self._call(profile_group="Corporate-Profiles", av_profile="default")

    def test_profile_group_with_protocol_options_rejected(self):
        """profile_group plus profile_protocol_options is rejected.

        profile-protocol-options is a listed member of the FortiOS
        firewall/profile-group object's attribute list (FNDN 7.6.7 schema,
        adomobj76-3500-objects.htm / adomobj76-3693-objects.htm), so it is
        part of the mutual-exclusion set like every other individual
        profile field.
        """
        with pytest.raises(ValidationError, match="mutually exclusive") as exc_info:
            self._call(profile_group="Corporate-Profiles", profile_protocol_options="default")
        assert "profile-protocol-options" in str(exc_info.value)

    def test_profile_group_with_all_individual_fields_rejected(self):
        """profile_group plus every individual profile field lists them all."""
        with pytest.raises(ValidationError) as exc_info:
            self._call(
                profile_group="Corporate-Profiles",
                av_profile="default",
                ips_sensor="default",
                webfilter_profile="default",
                dnsfilter_profile="default",
                application_list="default",
                file_filter_profile="default",
                ssl_ssh_profile="certificate-inspection",
                profile_protocol_options="default",
            )
        message = str(exc_info.value)
        for field in (
            "av-profile",
            "ips-sensor",
            "webfilter-profile",
            "dnsfilter-profile",
            "application-list",
            "file-filter-profile",
            "ssl-ssh-profile",
            "profile-protocol-options",
        ):
            assert field in message

    def test_utm_disabled_with_individual_profile_rejected(self):
        """utm_status=False combined with an individual profile field is rejected."""
        with pytest.raises(ValidationError, match="utm_status=False"):
            self._call(utm_status=False, av_profile="default")

    def test_utm_disabled_with_profile_group_rejected(self):
        """utm_status=False combined with profile_group is rejected."""
        with pytest.raises(ValidationError, match="utm_status=False"):
            self._call(utm_status=False, profile_group="Corporate-Profiles")

    def test_utm_disabled_alone_is_valid(self):
        """utm_status=False with no profile fields is a legitimate disable."""
        assert self._call(utm_status=False) is None

    def test_utm_status_none_with_profiles_does_not_raise(self):
        """utm_status omitted (None) never triggers the disabled-with-profile check."""
        assert self._call(utm_status=None, av_profile="default") is None


# =============================================================================
# Path Validation Tests
# =============================================================================


class TestGetAllowedOutputDirs:
    """Tests for get_allowed_output_dirs function."""

    def test_no_env_raises_validation_error(self, monkeypatch):
        """Test that missing env var raises ValidationError (secure by default)."""
        monkeypatch.delenv("FMG_ALLOWED_OUTPUT_DIRS", raising=False)
        with pytest.raises(ValidationError, match="No output directories configured"):
            get_allowed_output_dirs()

    def test_empty_env_raises_validation_error(self, monkeypatch):
        """Test that empty env var raises ValidationError."""
        monkeypatch.setenv("FMG_ALLOWED_OUTPUT_DIRS", "")
        with pytest.raises(ValidationError, match="No output directories configured"):
            get_allowed_output_dirs()

    def test_custom_dirs_from_env(self, monkeypatch, tmp_path):
        """Test custom directories from environment variable."""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        monkeypatch.setenv("FMG_ALLOWED_OUTPUT_DIRS", f"{dir1},{dir2}")
        result = get_allowed_output_dirs()

        assert dir1 in result
        assert dir2 in result

    def test_nonexistent_dir_ignored(self, monkeypatch):
        """Test that non-existent directories are ignored."""
        monkeypatch.setenv("FMG_ALLOWED_OUTPUT_DIRS", "/nonexistent/path")
        with pytest.raises(ValidationError, match="No output directories configured"):
            get_allowed_output_dirs()


class TestValidateOutputPath:
    """Tests for validate_output_path function."""

    def test_valid_path_in_allowed_dir(self, monkeypatch):
        """Test path within allowed directory is valid."""
        monkeypatch.setenv("FMG_ALLOWED_OUTPUT_DIRS", "/tmp")
        result = validate_output_path("/tmp")
        assert result == Path("/tmp").resolve()

    def test_valid_downloads_path(self, monkeypatch):
        """Test Downloads path is valid when configured."""
        downloads = Path.home() / "Downloads"
        if downloads.exists():
            monkeypatch.setenv("FMG_ALLOWED_OUTPUT_DIRS", str(downloads))
            result = validate_output_path(str(downloads))
            assert result == downloads

    def test_tilde_expansion(self, monkeypatch):
        """Test that ~ is expanded."""
        home = str(Path.home())
        monkeypatch.setenv("FMG_ALLOWED_OUTPUT_DIRS", home)
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

    def test_rejects_trailing_newline(self):
        """A trailing newline must not slip past the pattern (fullmatch, not $)."""
        with pytest.raises(ValidationError):
            validate_filename("evil\n")


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


class TestFortiApSerialPrefixes:
    """FortiAP-U and FortiAP-S serials do not start with ``FP``.

    The prefix set accepted ``FP``, which covers the mainline FortiAP
    models, and rejected the ``PU`` and ``PS`` prefixes the FortiAP-U and
    FortiAP-S series use (upstream #56). Nothing in the current fleet
    carries one, so this never fired; the failure mode when it does is a
    valid AP registration refused for a reason the message does not
    explain, since it says the serial must start with a device type
    prefix and the serial does.
    """

    @pytest.mark.parametrize(
        "serial",
        [
            "PU321C3X17000001",  # FortiAP-U
            "PS221E3X17000001",  # FortiAP-S
            "pu321c3x17000001",  # accepted in either case, like the rest
        ],
    )
    def test_the_u_and_s_series_are_accepted(self, serial):
        assert validate_device_serial(serial) == serial.upper()

    def test_the_mainline_fortiap_prefix_still_works(self):
        """FP was already accepted and must stay that way."""
        assert validate_device_serial("FP221E3X17000001") == "FP221E3X17000001"

    @pytest.mark.parametrize(
        "serial",
        [
            "PX321C3X17000001",  # P-initial, not a real product prefix
            "PT321C3X17000001",  # ditto
            "PU12345",  # right prefix, body too short
            "PU",  # prefix alone
        ],
    )
    def test_the_prefix_set_did_not_become_a_wildcard(self, serial):
        """Adding two prefixes must not accept every P-initial string.

        The first draft of this test used ``PUU21C3X1700`` as a negative,
        which was wrong: that is ``PU`` followed by ten valid characters,
        so it is a well-formed serial and the test failed against correct
        code. Kept as a note because the mistake is easy to repeat, the
        prefix and the body run together with nothing separating them.
        """
        with pytest.raises(ValidationError):
            validate_device_serial(serial)


class TestEscapedQuoteInASecretValue:
    """An escaped quote must not close a multi-line quoted span.

    upstream #71: the span scan closed on the first double quote it saw,
    escaped or not, so a value containing \\" ended early and everything
    after it went out in clear.
    """

    def test_escaped_quote_does_not_end_the_redaction_early(self):
        text = (
            'set private-key "-----BEGIN KEY-----\n'
            'body \\" still secret\n'
            "MORE-SECRET-BODY\n"
            '-----END KEY-----"\n'
            "set hostname fw01\n"
        )
        result = redact_config_text_secrets(text)
        assert "MORE-SECRET-BODY" not in result
        assert "END KEY" not in result
        assert "still secret" not in result
        assert "set private-key ***REDACTED***" in result
        # the line after the real closing quote is untouched
        assert "set hostname fw01" in result

    def test_escaped_quote_on_the_opening_line_does_not_end_it_early(self):
        text = 'set psksecret "abc \\" def\nSTILL-SECRET\nreal-end"\nset hostname fw01\n'
        result = redact_config_text_secrets(text)
        assert "STILL-SECRET" not in result
        assert "real-end" not in result
        assert "set hostname fw01" in result

    def test_an_escaped_backslash_still_lets_the_quote_close(self):
        r"""\\" is an escaped backslash followed by a real closing quote, so
        the span ends there and the next line must survive."""
        text = 'set psksecret "abc\\\\"\nset hostname fw01\n'
        result = redact_config_text_secrets(text)
        assert "set hostname fw01" in result
        assert "abc" not in result


class TestTraversalSegmentNames:
    """A name of "." or ".." is a path segment, not a name.

    upstream #71: both matched the name patterns (dots are legal in names)
    and both land as the last segment of a URL template.
    """

    @pytest.mark.parametrize("segment", [".", ".."])
    def test_object_name_refuses_a_traversal_segment(self, segment):
        with pytest.raises(ValidationError):
            validate_object_name(segment)

    @pytest.mark.parametrize("segment", [".", ".."])
    def test_device_name_refuses_a_traversal_segment(self, segment):
        with pytest.raises(ValidationError):
            validate_device_name(segment)

    def test_device_name_refuses_it_behind_a_vdom_suffix(self):
        """The VDOM branch validates the base name separately, so it needs
        the same guard or "..[root]" walks up regardless."""
        with pytest.raises(ValidationError):
            validate_device_name("..[root]")

    @pytest.mark.parametrize("name", ["fw.01", "site.a.fw", "FGT-01", "_edge"])
    def test_a_dot_elsewhere_in_a_name_is_still_fine(self, name):
        """Only the exact segments are refused. Tightening the pattern to
        ban dots outright would reject legitimate names."""
        assert validate_device_name(name) == name
        assert validate_object_name(name) == name


class TestTaskIdValidation:
    """Every tool taking a task ID interpolates it into /task/task/{id}.

    upstream #71: full mode carries the int annotation, dynamic mode passes
    parameters as dict[str, Any] and enforces nothing.
    """

    @pytest.mark.parametrize("bad", ["../../sys/status", "1 OR 1=1", 1.5, True, None, -3, [], {}])
    def test_a_non_task_id_is_refused(self, bad):
        with pytest.raises(ValidationError):
            validate_task_id(bad)

    def test_bool_is_refused_even_though_it_is_an_int(self):
        """True would otherwise sail through isinstance(x, int) and address
        task 1."""
        with pytest.raises(ValidationError):
            validate_task_id(True)

    @pytest.mark.parametrize("good", [0, 1, 11111])
    def test_a_real_task_id_passes_through(self, good):
        assert validate_task_id(good) == good
