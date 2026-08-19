"""Tests for policy permissiveness safety validation."""

from unittest.mock import AsyncMock, patch

import pytest

from fortimanager_mcp.utils.config import get_settings
from fortimanager_mcp.utils.validation import check_policy_permissiveness

# =============================================================================
# Pure Validation Function Tests
# =============================================================================


class TestCheckPolicyPermissiveness:
    """Tests for check_policy_permissiveness()."""

    def test_fully_open_policy_detected(self):
        result = check_policy_permissiveness(["all"], ["all"], ["ALL"], "accept")
        assert result is not None
        assert "fully open" in result

    def test_any_to_any_with_specific_service(self):
        result = check_policy_permissiveness(["all"], ["all"], ["HTTP"], "accept")
        assert result is not None
        assert "overly permissive" in result

    def test_deny_action_passes(self):
        result = check_policy_permissiveness(["all"], ["all"], ["ALL"], "deny")
        assert result is None

    def test_specific_srcaddr_passes(self):
        result = check_policy_permissiveness(["LAN-Subnet"], ["all"], ["ALL"], "accept")
        assert result is None

    def test_specific_dstaddr_passes(self):
        result = check_policy_permissiveness(["all"], ["Server-Net"], ["ALL"], "accept")
        assert result is None

    def test_specific_both_passes(self):
        result = check_policy_permissiveness(["LAN-Subnet"], ["Server-Net"], ["ALL"], "accept")
        assert result is None

    def test_case_insensitive_all(self):
        result = check_policy_permissiveness(["All"], ["ALL"], ["all"], "Accept")
        assert result is not None

    def test_none_fields_pass(self):
        result = check_policy_permissiveness(None, None, None, None)
        assert result is None

    def test_none_action_passes(self):
        result = check_policy_permissiveness(["all"], ["all"], ["ALL"], None)
        assert result is None

    def test_empty_lists_pass(self):
        result = check_policy_permissiveness([], [], [], "accept")
        assert result is None

    def test_mixed_addresses_with_all(self):
        """If 'all' appears among multiple srcaddrs, still flags it."""
        result = check_policy_permissiveness(["all", "extra"], ["all"], ["HTTP"], "accept")
        assert result is not None

    def test_multiple_services_with_all(self):
        """If 'ALL' appears among multiple services, still flags as fully open."""
        result = check_policy_permissiveness(["all"], ["all"], ["HTTP", "ALL"], "accept")
        assert result is not None
        assert "fully open" in result

    def test_padded_action_does_not_bypass(self):
        """PR #65 review (Christian): 'accept ' (trailing space) failed the
        exact `!= "accept"` comparison and bypassed detection entirely."""
        result = check_policy_permissiveness(["all"], ["all"], ["ALL"], "accept ")
        assert result is not None
        assert "fully open" in result

    def test_padded_and_capitalized_action_does_not_bypass(self):
        result = check_policy_permissiveness(["all"], ["all"], ["ALL"], "  Accept  ")
        assert result is not None

    def test_scalar_string_srcaddr_does_not_bypass(self):
        """PR #65 review: a bare string ("all" instead of ["all"]) was
        iterated character by character ('a','l','l', none of which equals
        "all"), silently returning False -- a scalar bypassed the check
        entirely."""
        result = check_policy_permissiveness("all", ["all"], ["ALL"], "accept")
        assert result is not None
        assert "fully open" in result

    def test_scalar_string_dstaddr_does_not_bypass(self):
        result = check_policy_permissiveness(["all"], "all", ["ALL"], "accept")
        assert result is not None

    def test_scalar_string_service_does_not_bypass(self):
        result = check_policy_permissiveness(["all"], ["all"], "ALL", "accept")
        assert result is not None
        assert "fully open" in result

    def test_all_scalar_strings_together_does_not_bypass(self):
        """The exact combination the PR review measured live."""
        result = check_policy_permissiveness("all", "all", "ALL", "accept")
        assert result is not None
        assert "fully open" in result

    def test_scalar_non_all_string_still_passes(self):
        """A scalar string that genuinely isn't "all" must not be
        misread as broad just because it's not a list."""
        result = check_policy_permissiveness("LAN-Subnet", "Server-Net", ["HTTP"], "accept")
        assert result is None

    def test_padded_address_does_not_bypass(self):
        """PR #65 review (Christian, 08-18): the action-string fix didn't
        cover address/service values -- 'all ' (trailing space) still
        failed the exact `== "all"` comparison and bypassed detection."""
        result = check_policy_permissiveness(["all "], ["all"], ["ALL"], "accept")
        assert result is not None
        assert "fully open" in result

    def test_padded_service_does_not_bypass(self):
        result = check_policy_permissiveness(["all"], ["all"], ["ALL "], "accept")
        assert result is not None
        assert "fully open" in result


class TestCheckPolicyPermissivenessNegate:
    """Negation inverts a field's match set, changing what counts as broad."""

    def test_negated_specific_src_counts_as_broad(self):
        """Negated specific srcaddr + dstaddr=all is effectively any-to-any."""
        result = check_policy_permissiveness(
            ["LAN-Users"], ["all"], ["HTTP"], "accept", srcaddr_negate=True
        )
        assert result is not None
        assert "overly permissive" in result
        assert "srcaddr" in result

    def test_negated_specific_both_sides_flagged(self):
        result = check_policy_permissiveness(
            ["LAN-Users"],
            ["Server-Net"],
            ["ALL"],
            "accept",
            srcaddr_negate=True,
            dstaddr_negate=True,
        )
        assert result is not None
        assert "fully open" in result

    def test_negated_service_counts_as_all_ports(self):
        """Negated specific service list matches almost every port."""
        result = check_policy_permissiveness(
            ["all"], ["all"], ["HTTP"], "accept", service_negate=True
        )
        assert result is not None
        assert "fully open" in result

    def test_negated_src_with_specific_dst_passes(self):
        """Negated source scoped to a specific destination is acceptable."""
        result = check_policy_permissiveness(
            ["BASITES-LAN-USERS"],
            ["LB-VIPs"],
            ["SYSLOG"],
            "accept",
            srcaddr_negate=True,
        )
        assert result is None

    def test_negated_all_matches_nothing(self):
        """srcaddr='all' with negation matches no traffic — flagged."""
        result = check_policy_permissiveness(
            ["all"], ["Server-Net"], ["HTTP"], "accept", srcaddr_negate=True
        )
        assert result is not None
        assert "matches no traffic" in result

    def test_negated_all_service_matches_nothing(self):
        result = check_policy_permissiveness(
            ["LAN-Net"], ["Server-Net"], ["ALL"], "accept", service_negate=True
        )
        assert result is not None
        assert "matches no traffic" in result

    def test_negate_flags_default_false_keeps_behavior(self):
        """Without negate flags the original semantics are unchanged."""
        result = check_policy_permissiveness(["LAN-Subnet"], ["all"], ["ALL"], "accept")
        assert result is None

    def test_deny_with_negation_passes(self):
        """Permissiveness only applies to accept policies, negated or not."""
        result = check_policy_permissiveness(
            ["LAN-Users"], ["all"], ["ALL"], "deny", srcaddr_negate=True
        )
        assert result is None


# =============================================================================
# Tool-Level Integration Tests
# =============================================================================


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Clear settings cache so env var changes take effect."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestPolicyToolSafetyStrict:
    """Test that permissive policies are blocked in strict mode."""

    @pytest.mark.asyncio
    async def test_create_policy_blocked(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Open-Policy",
                srcintf=["any"],
                dstintf=["any"],
                srcaddr=["all"],
                dstaddr=["all"],
                service=["ALL"],
                action="accept",
            )

        assert result["status"] == "error"
        assert "blocked" in result["message"].lower()
        mock_client.return_value.create_firewall_policy.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_policy_specific_addrs_passes(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_firewall_policy = AsyncMock(
                return_value={"policyid": 1}
            )
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Web-Access",
                srcintf=["internal"],
                dstintf=["wan1"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["all"],
                service=["HTTP", "HTTPS"],
                action="accept",
            )

        assert result["status"] == "success"
        assert "warning" not in result

    @pytest.mark.asyncio
    async def test_update_policy_all_fields_blocked(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import update_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await update_firewall_policy(
                adom="root",
                package="default",
                policyid=10,
                srcaddr=["all"],
                dstaddr=["all"],
                service=["ALL"],
                action="accept",
            )

        assert result["status"] == "error"
        assert "blocked" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_update_policy_partial_fields_not_checked(self, monkeypatch):
        """Partial update with only srcaddr should not trigger safety check."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import update_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.update_firewall_policy = AsyncMock(return_value={})
            result = await update_firewall_policy(
                adom="root",
                package="default",
                policyid=10,
                srcaddr=["all"],
            )

        assert result["status"] == "success"


class TestPolicyToolSafetyWarn:
    """Test warn mode allows but adds warning."""

    @pytest.mark.asyncio
    async def test_create_policy_warns(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "warn")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_firewall_policy = AsyncMock(
                return_value={"policyid": 99}
            )
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Open-Policy",
                srcintf=["any"],
                dstintf=["any"],
                srcaddr=["all"],
                dstaddr=["all"],
                service=["ALL"],
                action="accept",
            )

        assert result["status"] == "success"
        assert "warning" in result
        assert "fully open" in result["warning"]
        # API should have been called
        mock_client.return_value.create_firewall_policy.assert_called_once()


class TestPolicyToolSafetyDisabled:
    """Test disabled mode allows everything without warnings."""

    @pytest.mark.asyncio
    async def test_create_policy_no_warning(self, monkeypatch):
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "disabled")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_firewall_policy = AsyncMock(
                return_value={"policyid": 99}
            )
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Open-Policy",
                srcintf=["any"],
                dstintf=["any"],
                srcaddr=["all"],
                dstaddr=["all"],
                service=["ALL"],
                action="accept",
            )

        assert result["status"] == "success"
        assert "warning" not in result


class TestDenyPolicyLogtraffic:
    """Test that deny policies auto-correct logtraffic from utm to all."""

    @pytest.mark.asyncio
    async def test_deny_policy_logtraffic_corrected(self, monkeypatch):
        """FMG rejects logtraffic=utm on deny policies; we auto-fix to 'all'."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_firewall_policy = AsyncMock(
                return_value={"policyid": 5}
            )
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Deny-All",
                srcintf=["any"],
                dstintf=["any"],
                srcaddr=["all"],
                dstaddr=["all"],
                service=["ALL"],
                action="deny",
            )

        assert result["status"] == "success"
        call_args = mock_client.return_value.create_firewall_policy.call_args
        policy_data = call_args[0][2]
        assert policy_data["logtraffic"] == "all"

    @pytest.mark.asyncio
    async def test_accept_policy_keeps_utm(self, monkeypatch):
        """Accept policies should keep logtraffic=utm (default)."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_firewall_policy = AsyncMock(
                return_value={"policyid": 6}
            )
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Allow-Web",
                srcintf=["internal"],
                dstintf=["wan1"],
                srcaddr=["LAN-Net"],
                dstaddr=["all"],
                service=["HTTP"],
                action="accept",
            )

        assert result["status"] == "success"
        call_args = mock_client.return_value.create_firewall_policy.call_args
        policy_data = call_args[0][2]
        assert policy_data["logtraffic"] == "utm"


class TestPolicyToolNegateSafety:
    """Negation is a footgun: it must be noisy, and broad negation must gate."""

    @pytest.mark.asyncio
    async def test_create_negated_broad_blocked_strict(self, monkeypatch):
        """Negating both src and dst on an accept policy is blocked in strict."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Double-Negate",
                srcintf=["any"],
                dstintf=["any"],
                srcaddr=["LAN-Users"],
                dstaddr=["Server-Net"],
                service=["ALL"],
                action="accept",
                srcaddr_negate=True,
                dstaddr_negate=True,
            )

        assert result["status"] == "error"
        assert "blocked" in result["message"].lower()
        mock_client.return_value.create_firewall_policy.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_negate_only_warns_but_succeeds_strict(self, monkeypatch):
        """Enabling negation on a partial update warns loudly but is not blocked."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import update_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.update_firewall_policy = AsyncMock(return_value={})
            result = await update_firewall_policy(
                adom="root",
                package="default",
                policyid=10,
                srcaddr_negate=True,
            )

        assert result["status"] == "success"
        assert "warning" in result
        assert "complement" in result["warning"]
        mock_client.return_value.update_firewall_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_negated_src_scoped_dst_warns_strict(self, monkeypatch):
        """The legitimate pattern (negated src, specific dst) passes with a warning."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.create_firewall_policy = AsyncMock(
                return_value={"policyid": 77}
            )
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Infra-Except-Users",
                srcintf=["LAN-BA"],
                dstintf=["any"],
                srcaddr=["BASITES-LAN-USERS"],
                dstaddr=["LB-VIPs"],
                service=["SYSLOG", "OTLP"],
                action="accept",
                srcaddr_negate=True,
            )

        assert result["status"] == "success"
        assert "warning" in result
        assert "complement" in result["warning"]
        payload = mock_client.return_value.create_firewall_policy.call_args[0][2]
        assert payload["srcaddr-negate"] == "enable"

    @pytest.mark.asyncio
    async def test_negated_all_blocked_strict(self, monkeypatch):
        """Negating 'all' matches no traffic — blocked in strict mode."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")

        from fortimanager_mcp.tools.policy_tools import create_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            result = await create_firewall_policy(
                adom="root",
                package="default",
                name="Negate-All",
                srcintf=["any"],
                dstintf=["any"],
                srcaddr=["all"],
                dstaddr=["Server-Net"],
                service=["HTTP"],
                action="accept",
                srcaddr_negate=True,
            )

        assert result["status"] == "error"
        assert "matches no traffic" in result["message"]
        mock_client.return_value.create_firewall_policy.assert_not_called()

    @pytest.mark.asyncio
    async def test_negate_silent_when_safety_disabled(self, monkeypatch):
        """Disabled safety mode stays silent, matching the other guards."""
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_POLICY_SAFETY", "disabled")

        from fortimanager_mcp.tools.policy_tools import update_firewall_policy

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client") as mock_client:
            mock_client.return_value = AsyncMock()
            mock_client.return_value.update_firewall_policy = AsyncMock(return_value={})
            result = await update_firewall_policy(
                adom="root",
                package="default",
                policyid=10,
                srcaddr_negate=True,
            )

        assert result["status"] == "success"
        assert "warning" not in result
