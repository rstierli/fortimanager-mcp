"""Tests for policy_tools module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import policy_tools
from fortimanager_mcp.utils.errors import PermissionError, ResourceNotFoundError
from tests.conftest import MOCK_POLICIES


class TestPolicyListTools:
    """Test policy listing tools."""

    @pytest.mark.asyncio
    async def test_list_firewall_policies_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing firewall policies."""

        # Mock count and list responses
        def mock_get(url: str, **kwargs):
            if "/policy" in url and "count" not in url:
                return (0, MOCK_POLICIES)
            return (0, {"data": 2})  # For count

        mock_fmg_instance.get.side_effect = mock_get

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.list_firewall_policies(
                adom="root",
                package="default",
            )

        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["policies"][0]["name"] == "Allow-Web"

    @pytest.mark.asyncio
    async def test_list_firewall_policies_not_connected(self) -> None:
        """Test listing policies when client not connected."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=None):
            result = await policy_tools.list_firewall_policies(
                adom="root",
                package="default",
            )

        assert result["status"] == "error"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_get_firewall_policy_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting specific policy."""
        mock_fmg_instance.get.return_value = (0, MOCK_POLICIES[0])

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.get_firewall_policy(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "success"
        assert result["policy"]["name"] == "Allow-Web"


class TestPolicyCrudTools:
    """Test policy CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_firewall_policy_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating firewall policy."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Test-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["Server-Net"],
                service=["HTTP"],
                action="accept",
            )

        assert result["status"] == "success"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_update_firewall_policy_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating firewall policy."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=1,
                name="Updated-Policy",
            )

        assert result["status"] == "success"
        assert result["policyid"] == 1

    @pytest.mark.asyncio
    async def test_delete_firewall_policy_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting firewall policy."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.delete_firewall_policy(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "success"
        assert "message" in result


class TestPolicyNegateFields:
    """Test srcaddr/dstaddr/service negation on policy create/update."""

    @pytest.mark.asyncio
    async def test_create_policy_negate_enabled(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Negate flags set to True serialize as 'enable' in the payload."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Negated-Src",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Users"],
                dstaddr=["Server-Net"],
                service=["SYSLOG"],
                action="deny",
                srcaddr_negate=True,
                dstaddr_negate=True,
                service_negate=True,
            )

        assert result["status"] == "success"
        payload = mock_fmg_instance.add.call_args.kwargs["data"]
        assert payload["srcaddr-negate"] == "enable"
        assert payload["dstaddr-negate"] == "enable"
        assert payload["service-negate"] == "enable"
        # Enabling negation is never silent.
        assert "warning" in result
        assert "complement" in result["warning"]

    @pytest.mark.asyncio
    async def test_create_policy_negate_disabled_explicit(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Negate flags set to False serialize as 'disable' in the payload."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Plain-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Users"],
                dstaddr=["Server-Net"],
                service=["SYSLOG"],
                action="accept",
                srcaddr_negate=False,
            )

        assert result["status"] == "success"
        payload = mock_fmg_instance.add.call_args.kwargs["data"]
        assert payload["srcaddr-negate"] == "disable"

    @pytest.mark.asyncio
    async def test_create_policy_negate_default_omitted(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Unset negate flags (None) are omitted from the payload entirely."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Plain-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Users"],
                dstaddr=["Server-Net"],
                service=["SYSLOG"],
                action="accept",
            )

        assert result["status"] == "success"
        payload = mock_fmg_instance.add.call_args.kwargs["data"]
        assert "srcaddr-negate" not in payload
        assert "dstaddr-negate" not in payload
        assert "service-negate" not in payload

    @pytest.mark.asyncio
    async def test_update_policy_negate_partial_only_touches_negate(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """A negate-only update sends only the negate attribute (partial update)."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                srcaddr_negate=True,
            )

        assert result["status"] == "success"
        # Enabling negation is never silent, even on a partial update.
        assert "warning" in result
        data = mock_fmg_instance.update.call_args.kwargs
        assert data["srcaddr-negate"] == "enable"
        for untouched in (
            "srcaddr",
            "dstaddr",
            "service",
            "schedule",
            "status",
            "global-label",
            "_global-label-color",
            "dstaddr-negate",
            "service-negate",
        ):
            assert untouched not in data

    @pytest.mark.asyncio
    async def test_update_policy_negate_disable(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Negate flag set to False serializes as 'disable' on update."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                srcaddr_negate=False,
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data["srcaddr-negate"] == "disable"
        # Disabling negation restores normal match semantics — no warning needed.
        assert "warning" not in result

    @pytest.mark.asyncio
    async def test_update_policy_negate_none_untouched(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Unset negate flags never appear in an unrelated update payload."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                comments="touch only comments",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert "srcaddr-negate" not in data
        assert "dstaddr-negate" not in data
        assert "service-negate" not in data


class TestPolicySecurityProfiles:
    """Test UTM/security-profile fields on policy create/update (#48)."""

    @pytest.mark.asyncio
    async def test_create_policy_individual_profiles(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Individual profile fields serialize verbatim and derive profile-type=single."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="UTM-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["all"],
                service=["HTTP", "HTTPS"],
                action="accept",
                utm_status=True,
                av_profile="default",
                ips_sensor="default",
                webfilter_profile="default",
                dnsfilter_profile="default",
                application_list="default",
                file_filter_profile="default",
                ssl_ssh_profile="certificate-inspection",
                profile_protocol_options="default",
            )

        assert result["status"] == "success"
        payload = mock_fmg_instance.add.call_args.kwargs["data"]
        assert payload["utm-status"] == "enable"
        assert payload["av-profile"] == "default"
        assert payload["ips-sensor"] == "default"
        assert payload["webfilter-profile"] == "default"
        assert payload["dnsfilter-profile"] == "default"
        assert payload["application-list"] == "default"
        assert payload["file-filter-profile"] == "default"
        assert payload["ssl-ssh-profile"] == "certificate-inspection"
        assert payload["profile-protocol-options"] == "default"
        assert payload["profile-type"] == "single"
        assert "profile-group" not in payload

    @pytest.mark.asyncio
    async def test_create_policy_profile_group(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """profile_group alone serializes with profile-type=group and no individual profiles."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="UTM-Group-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["all"],
                service=["HTTP", "HTTPS"],
                action="accept",
                utm_status=True,
                profile_group="Corporate-Profiles",
            )

        assert result["status"] == "success"
        payload = mock_fmg_instance.add.call_args.kwargs["data"]
        assert payload["utm-status"] == "enable"
        assert payload["profile-group"] == "Corporate-Profiles"
        assert payload["profile-type"] == "group"
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
            assert field not in payload

    @pytest.mark.asyncio
    async def test_create_policy_profile_group_with_protocol_options_rejected(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """profile_group + profile_protocol_options is rejected before hitting FMG.

        profile-protocol-options is a listed member of the FortiOS
        firewall/profile-group object's attribute list (FNDN 7.6.7 schema,
        adomobj76-3500-objects.htm / adomobj76-3693-objects.htm), so it is
        part of the same mutual-exclusion set as the other individual
        profile fields.
        """
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Bad-Group-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["all"],
                service=["HTTP", "HTTPS"],
                action="accept",
                utm_status=True,
                profile_group="Corporate-Profiles",
                profile_protocol_options="default",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        assert "mutually exclusive" in result["message"]
        assert "profile-protocol-options" in result["message"]

    @pytest.mark.asyncio
    async def test_create_policy_no_profile_fields_omits_profile_type(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """No profile fields supplied -> no utm-status/profile-type in payload at all."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Plain-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["all"],
                service=["HTTP"],
                action="accept",
            )

        assert result["status"] == "success"
        payload = mock_fmg_instance.add.call_args.kwargs["data"]
        for field in ("utm-status", "profile-type", "profile-group", "av-profile"):
            assert field not in payload

    @pytest.mark.asyncio
    async def test_create_policy_profile_group_mutual_exclusion_error(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """profile_group + an individual profile field is rejected before hitting FMG."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Bad-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["all"],
                service=["HTTP"],
                action="accept",
                utm_status=True,
                profile_group="Corporate-Profiles",
                av_profile="default",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        assert "mutually exclusive" in result["message"]
        assert "av-profile" in result["message"]

    @pytest.mark.asyncio
    async def test_create_policy_utm_disabled_with_profile_error(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Setting a profile field while utm_status=False is rejected, not silently dropped."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_firewall_policy(
                adom="root",
                package="default",
                name="Bad-Policy",
                srcintf=["port1"],
                dstintf=["port2"],
                srcaddr=["LAN-Subnet"],
                dstaddr=["all"],
                service=["HTTP"],
                action="accept",
                utm_status=False,
                av_profile="default",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        assert "utm_status=False" in result["message"]
        assert "av-profile" in result["message"]

    @pytest.mark.asyncio
    async def test_update_policy_profile_group_partial(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """A profile_group-only update sends only profile-group/profile-type/utm-status."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                utm_status=True,
                profile_group="Corporate-Profiles",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data["utm-status"] == "enable"
        assert data["profile-group"] == "Corporate-Profiles"
        assert data["profile-type"] == "group"
        for untouched in ("srcaddr", "dstaddr", "service", "av-profile", "ips-sensor"):
            assert untouched not in data

    @pytest.mark.asyncio
    async def test_update_policy_individual_profile_partial(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """A single individual-profile update derives profile-type=single."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                av_profile="default",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data["av-profile"] == "default"
        assert data["profile-type"] == "single"
        assert "profile-group" not in data
        assert "utm-status" not in data

    @pytest.mark.asyncio
    async def test_update_policy_protocol_options_partial_flips_to_single(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Sending profile_protocol_options alone on update derives profile-type=single.

        Regression test: _build_security_profile_fields()'s profile-type
        derivation previously omitted profile_protocol_options from the
        tuple it checks, so this call silently no-op'd on profile-type
        instead of correctly flipping a group-mode policy to single mode.
        """
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                profile_protocol_options="default",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data["profile-protocol-options"] == "default"
        assert data["profile-type"] == "single"
        assert "profile-group" not in data

    @pytest.mark.asyncio
    async def test_update_policy_profile_group_mutual_exclusion_error(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """profile_group + an individual profile field is rejected on update too."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                profile_group="Corporate-Profiles",
                webfilter_profile="default",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        assert "mutually exclusive" in result["message"]
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_policy_profile_group_protocol_options_mutual_exclusion_error(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """profile_group + profile_protocol_options is rejected on update too."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                profile_group="Corporate-Profiles",
                profile_protocol_options="default",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        assert "mutually exclusive" in result["message"]
        assert "profile-protocol-options" in result["message"]
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_policy_utm_disabled_with_profile_error(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Disabling utm_status while touching a profile field is rejected on update too."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_firewall_policy(
                adom="root",
                package="default",
                policyid=42,
                utm_status=False,
                ips_sensor="default",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        mock_fmg_instance.update.assert_not_called()


class TestPackageTools:
    """Test package management tools."""

    @pytest.mark.asyncio
    async def test_create_package_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating policy package."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_package(
                adom="root",
                name="test-package",
            )

        assert result["status"] == "success"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_delete_package_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting policy package."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.delete_package(
                adom="root",
                package="test-package",
            )

        assert result["status"] == "success"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_clone_package_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test cloning policy package."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.clone_package(
                adom="root",
                package="default",
                new_name="default-copy",
            )

        assert result["status"] == "success"
        assert "message" in result


class TestGetPolicyServices:
    """Tests for the get_policy_services tool."""

    def _make_mock_client(
        self,
        policy: dict | None = None,
        services: dict | None = None,
        service_groups: dict | None = None,
        policy_error: Exception | None = None,
        service_errors: dict | None = None,
    ) -> MagicMock:
        """Create a mock client with configurable responses.

        Args:
            policy: Policy data returned by get_firewall_policy.
            services: Mapping of service name -> service data.
            service_groups: Mapping of group name -> group data.
            policy_error: Exception to raise from get_firewall_policy.
            service_errors: Mapping of service name -> Exception for get_service.
        """
        client = MagicMock()
        services = services or {}
        service_groups = service_groups or {}
        service_errors = service_errors or {}

        if policy_error:
            client.get_firewall_policy = AsyncMock(side_effect=policy_error)
        else:
            client.get_firewall_policy = AsyncMock(return_value=policy or {})

        async def mock_get_service(adom: str, name: str):
            if name in service_errors:
                raise service_errors[name]
            if name in services:
                return services[name]
            raise ResourceNotFoundError(f"Object not found: {name}", code=-3)

        async def mock_get_service_group(adom: str, name: str):
            if name in service_groups:
                return service_groups[name]
            raise ResourceNotFoundError(f"Object not found: {name}", code=-3)

        client.get_service = mock_get_service
        client.get_service_group = mock_get_service_group
        return client

    @pytest.mark.asyncio
    async def test_single_service_resolution(self) -> None:
        """Test resolving a single TCP service."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 1,
                "name": "Allow-Web",
                "service": ["HTTP"],
            },
            services={
                "HTTP": {
                    "name": "HTTP",
                    "protocol": 15,
                    "tcp-portrange": "80",
                },
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=1
            )

        assert result["status"] == "success"
        assert result["policy_id"] == 1
        assert result["policy_name"] == "Allow-Web"
        assert result["service_names"] == ["HTTP"]
        assert len(result["services"]) == 1
        assert result["services"][0]["name"] == "HTTP"
        assert result["services"][0]["category"] == "TCP/UDP/SCTP"
        assert result["services"][0]["ports"]["tcp-portrange"] == "80"

    @pytest.mark.asyncio
    async def test_service_group_expansion(self) -> None:
        """Test resolving a service group into its members."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 5,
                "name": "Allow-WebGroup",
                "service": ["Web-Services"],
            },
            services={
                "HTTP": {
                    "name": "HTTP",
                    "protocol": 15,
                    "tcp-portrange": "80",
                },
                "HTTPS": {
                    "name": "HTTPS",
                    "protocol": 15,
                    "tcp-portrange": "443",
                },
            },
            service_groups={
                "Web-Services": {
                    "name": "Web-Services",
                    "member": ["HTTP", "HTTPS"],
                },
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=5
            )

        assert result["status"] == "success"
        assert len(result["services"]) == 1
        svc = result["services"][0]
        assert svc["type"] == "group"
        assert svc["name"] == "Web-Services"
        assert len(svc["members"]) == 2
        member_names = [m["name"] for m in svc["members"]]
        assert "HTTP" in member_names
        assert "HTTPS" in member_names

    @pytest.mark.asyncio
    async def test_all_service_handling(self) -> None:
        """Test that 'ALL' service is handled specially without resolution."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 2,
                "name": "Deny-All",
                "service": ["ALL"],
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=2
            )

        assert result["status"] == "success"
        assert result["service_names"] == ["ALL"]
        assert len(result["services"]) == 1
        assert result["services"][0]["category"] == "wildcard"
        assert result["services"][0]["name"] == "ALL"

    @pytest.mark.asyncio
    async def test_missing_unknown_service(self) -> None:
        """Test handling of a service that doesn't exist."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 3,
                "name": "Test-Policy",
                "service": ["NonExistent-Service"],
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=3
            )

        assert result["status"] == "success"
        assert len(result["services"]) == 1
        assert result["services"][0]["type"] == "unknown"
        assert "not found" in result["services"][0]["error"]

    @pytest.mark.asyncio
    async def test_resolve_false_passthrough(self) -> None:
        """Test that resolve=False returns only service names."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 1,
                "name": "Allow-Web",
                "service": ["HTTP", "HTTPS", "DNS"],
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=1, resolve=False
            )

        assert result["status"] == "success"
        assert result["service_names"] == ["HTTP", "HTTPS", "DNS"]
        assert "services" not in result

    @pytest.mark.asyncio
    async def test_invalid_policy_id(self) -> None:
        """Test error when policy doesn't exist."""
        mock_client = self._make_mock_client(
            policy_error=Exception("Object not found"),
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=9999
            )

        assert result["status"] == "error"
        assert "Object not found" in result["message"]

    @pytest.mark.asyncio
    async def test_empty_service_list(self) -> None:
        """Test policy with no services configured."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 4,
                "name": "Empty-Services",
                "service": [],
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=4
            )

        assert result["status"] == "success"
        assert result["service_names"] == []
        assert result["services"] == []

    @pytest.mark.asyncio
    async def test_multiple_services_mixed_types(self) -> None:
        """Test resolving multiple services with different protocols."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 10,
                "name": "Mixed-Services",
                "service": ["HTTP", "PING", "Custom-App"],
            },
            services={
                "HTTP": {
                    "name": "HTTP",
                    "protocol": 15,
                    "tcp-portrange": "80",
                },
                "PING": {
                    "name": "PING",
                    "protocol": "ICMP",
                    "icmptype": 8,
                },
                "Custom-App": {
                    "name": "Custom-App",
                    "protocol": 15,
                    "tcp-portrange": "8080-8090",
                    "udp-portrange": "9000",
                },
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=10
            )

        assert result["status"] == "success"
        assert len(result["services"]) == 3

        by_name = {s["name"]: s for s in result["services"]}
        assert by_name["HTTP"]["category"] == "TCP/UDP/SCTP"
        assert by_name["PING"]["category"] == "ICMP"
        assert by_name["PING"]["icmp_type"] == 8
        assert by_name["Custom-App"]["ports"]["tcp-portrange"] == "8080-8090"
        assert by_name["Custom-App"]["ports"]["udp-portrange"] == "9000"

    @pytest.mark.asyncio
    async def test_client_not_initialized(self) -> None:
        """Test error when FMG client is not initialized."""
        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=None,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=1
            )

        assert result["status"] == "error"
        assert "not initialized" in result["message"]

    @pytest.mark.asyncio
    async def test_all_service_as_string(self) -> None:
        """Test that 'ALL' service works when returned as a string (not list)."""
        mock_client = self._make_mock_client(
            policy={
                "policyid": 2,
                "name": "Deny-All",
                "service": "ALL",
            },
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=2
            )

        assert result["status"] == "success"
        assert result["services"][0]["category"] == "wildcard"


class TestResolveServiceSafety:
    """Guard rails on service resolution: circular groups terminate and real
    errors are surfaced rather than mislabeled as not-found."""

    def _client_with_groups(self, groups: dict[str, list[str]]) -> MagicMock:
        client = MagicMock()

        async def mock_get_service(adom: str, name: str):
            raise ResourceNotFoundError(f"Object not found: {name}", code=-3)

        async def mock_get_service_group(adom: str, name: str):
            if name in groups:
                return {"name": name, "member": groups[name]}
            raise ResourceNotFoundError(f"Object not found: {name}", code=-3)

        client.get_service = mock_get_service
        client.get_service_group = mock_get_service_group
        return client

    @pytest.mark.asyncio
    async def test_circular_group_reference_terminates(self) -> None:
        """A group cycle (A -> B -> A) resolves with a circular-reference marker
        instead of recursing forever."""
        client = self._client_with_groups({"GroupA": ["GroupB"], "GroupB": ["GroupA"]})

        result = await policy_tools._resolve_single_service(client, "root", "GroupA")

        assert result["type"] == "group"
        inner = result["members"][0]
        assert inner["name"] == "GroupB"
        assert inner["members"][0]["name"] == "GroupA"
        assert "Circular group reference" in inner["members"][0]["error"]

    @pytest.mark.asyncio
    async def test_self_referencing_group_terminates(self) -> None:
        client = self._client_with_groups({"GroupA": ["GroupA"]})

        result = await policy_tools._resolve_single_service(client, "root", "GroupA")

        assert result["type"] == "group"
        assert "Circular group reference" in result["members"][0]["error"]

    @pytest.mark.asyncio
    async def test_permission_error_propagates_not_swallowed(self) -> None:
        """A permission failure on lookup must surface as a tool error, not be
        reported as 'service not found'."""
        mock_client = MagicMock()
        mock_client.get_firewall_policy = AsyncMock(
            return_value={"policyid": 7, "name": "P", "service": ["HTTP"]}
        )
        mock_client.get_service = AsyncMock(
            side_effect=PermissionError("No permission for the resource", code=-11)
        )

        with patch(
            "fortimanager_mcp.tools.policy_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await policy_tools.get_policy_services(
                adom="root", package="default", policy_id=7
            )

        assert result["status"] == "error"


class TestServiceProtocolParsing:
    """_extract_service_details must classify by the integer protocol enum FMG
    actually returns (verified live on FMG 7.6.7: TCP/UDP/SCTP=5, ICMP=1,
    ICMP6=6, IP=2), while staying backward-compatible with the string aliases
    and the legacy 15 some paths/versions produce."""

    def test_tcp_udp_integer_5(self) -> None:
        d = policy_tools._extract_service_details(
            {"name": "all_tcp", "protocol": 5, "tcp-portrange": ["1-65535"]}
        )
        assert d["category"] == "TCP/UDP/SCTP"
        assert d["ports"]["tcp-portrange"] == ["1-65535"]

    def test_tcp_udp_legacy_15(self) -> None:
        d = policy_tools._extract_service_details(
            {"name": "custom", "protocol": 15, "tcp-portrange": "8080"}
        )
        assert d["category"] == "TCP/UDP/SCTP"

    def test_tcp_udp_string_alias(self) -> None:
        """Some endpoints surface the string alias instead of the integer."""
        d = policy_tools._extract_service_details(
            {"name": "web", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"}
        )
        assert d["category"] == "TCP/UDP/SCTP"
        assert d["ports"]["tcp-portrange"] == "80"

    def test_icmp_integer_1(self) -> None:
        d = policy_tools._extract_service_details(
            {"name": "ping", "protocol": 1, "icmptype": 8, "icmpcode": 0}
        )
        assert d["category"] == "ICMP"
        assert d["icmp_type"] == 8
        assert d["icmp_code"] == 0

    def test_icmp_string_alias(self) -> None:
        d = policy_tools._extract_service_details(
            {"name": "ping", "protocol": "ICMP", "icmptype": 8}
        )
        assert d["category"] == "ICMP"
        assert d["icmp_type"] == 8

    def test_icmp6_integer_6(self) -> None:
        d = policy_tools._extract_service_details({"name": "ping6", "protocol": 6, "icmptype": 128})
        assert d["category"] == "ICMP6"
        assert d["icmp_type"] == 128

    def test_ip_integer_2(self) -> None:
        d = policy_tools._extract_service_details(
            {"name": "GRE", "protocol": 2, "protocol-number": 47}
        )
        assert d["category"] == "IP"
        assert d["protocol_number"] == 47


MOCK_LOCAL_IN_POLICIES = [
    {
        "policyid": 1,
        "intf": ["port1"],
        "srcaddr": ["Admin-Subnet"],
        "dstaddr": ["all"],
        "service": ["HTTPS"],
        "action": "accept",
        "status": "enable",
    },
    {
        "policyid": 2,
        "intf": ["any"],
        "srcaddr": ["all"],
        "dstaddr": ["all"],
        "service": ["ALL"],
        "action": "deny",
        "status": "enable",
    },
]


class TestLocalInPolicyTools:
    """Test IPv4 local-in-policy CRUD tools."""

    @pytest.mark.asyncio
    async def test_list_local_in_policies_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing local-in policies."""

        def mock_get(url: str, **kwargs):
            if "local-in-policy" in url and kwargs.get("option") == ["count"]:
                return (0, 2)
            return (0, MOCK_LOCAL_IN_POLICIES)

        mock_fmg_instance.get.side_effect = mock_get

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.list_local_in_policies(
                adom="root",
                package="default",
            )

        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["total"] == 2
        assert result["policies"][0]["policyid"] == 1

    @pytest.mark.asyncio
    async def test_list_local_in_policies_not_connected(self) -> None:
        """Test listing local-in policies when client not connected."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=None):
            result = await policy_tools.list_local_in_policies(
                adom="root",
                package="default",
            )

        assert result["status"] == "error"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_get_local_in_policy_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific local-in policy."""
        mock_fmg_instance.get.return_value = (0, MOCK_LOCAL_IN_POLICIES[0])

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.get_local_in_policy(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "success"
        assert result["policy"]["policyid"] == 1

    @pytest.mark.asyncio
    async def test_create_local_in_policy_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test creating a local-in policy, including the default-deny action."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_local_in_policy(
                adom="root",
                package="default",
                intf=["port1"],
                srcaddr=["Admin-Subnet"],
                dstaddr=["all"],
                service=["SSH"],
            )

        assert result["status"] == "success"
        assert "message" in result

        # Verify the field-name translation and the default-closed action.
        _, kwargs = mock_fmg_instance.add.call_args
        payload = kwargs["data"][0] if isinstance(kwargs["data"], list) else kwargs["data"]
        assert payload["action"] == "deny"
        assert payload["intf"] == ["port1"]
        assert payload["schedule"] == ["always"]

    @pytest.mark.asyncio
    async def test_create_local_in_policy_negate_and_ha_mgmt(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Negate flags and the IPv4-only ha_mgmt_intf_only field serialize to enable/disable."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_local_in_policy(
                adom="root",
                package="default",
                intf=["port1"],
                srcaddr=["Admin-Subnet"],
                dstaddr=["FGT-mgmt-ip"],
                service=["SSH"],
                action="accept",
                srcaddr_negate=True,
                ha_mgmt_intf_only=True,
                virtual_patch=False,
            )

        assert result["status"] == "success"

        _, kwargs = mock_fmg_instance.add.call_args
        payload = kwargs["data"][0] if isinstance(kwargs["data"], list) else kwargs["data"]
        assert payload["srcaddr-negate"] == "enable"
        assert payload["ha-mgmt-intf-only"] == "enable"
        assert payload["virtual-patch"] == "disable"

    @pytest.mark.asyncio
    async def test_create_local_in_policy_blocked_when_overly_permissive(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """srcaddr=all + dstaddr=all + action=accept is refused under strict policy safety,
        same as create_firewall_policy -- this is management-plane access, so it should
        be at least as guarded."""
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_local_in_policy(
                adom="root",
                package="default",
                intf=["any"],
                srcaddr=["all"],
                dstaddr=["all"],
                service=["ALL"],
                action="accept",
            )

        assert result["status"] == "error"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_update_local_in_policy_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating a local-in policy."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_local_in_policy(
                adom="root",
                package="default",
                policyid=1,
                status="disable",
            )

        assert result["status"] == "success"
        assert result["policyid"] == 1

    @pytest.mark.asyncio
    async def test_update_local_in_policy_no_params(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating with no fields returns an error."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_local_in_policy(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "error"
        assert "No update parameters" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_local_in_policy_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting a local-in policy."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.delete_local_in_policy(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "success"
        assert "message" in result


class TestLocalInPolicy6Tools:
    """Test IPv6 local-in-policy6 CRUD tools."""

    @pytest.mark.asyncio
    async def test_list_local_in_policies6_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing local-in-policy6 entries."""

        def mock_get(url: str, **kwargs):
            if "local-in-policy6" in url and kwargs.get("option") == ["count"]:
                return (0, 1)
            return (0, [MOCK_LOCAL_IN_POLICIES[0]])

        mock_fmg_instance.get.side_effect = mock_get

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.list_local_in_policies6(
                adom="root",
                package="default",
            )

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_get_local_in_policy6_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific local-in-policy6 entry."""
        mock_fmg_instance.get.return_value = (0, MOCK_LOCAL_IN_POLICIES[0])

        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.get_local_in_policy6(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "success"
        assert result["policy"]["policyid"] == 1

    @pytest.mark.asyncio
    async def test_create_local_in_policy6_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test creating a local-in-policy6 entry, including the default-deny action."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.create_local_in_policy6(
                adom="root",
                package="default",
                intf=["port1"],
                srcaddr=["Admin-Subnet-v6"],
                dstaddr=["all"],
                service=["SSH"],
            )

        assert result["status"] == "success"

        _, kwargs = mock_fmg_instance.add.call_args
        payload = kwargs["data"][0] if isinstance(kwargs["data"], list) else kwargs["data"]
        assert payload["action"] == "deny"
        assert "ha-mgmt-intf-only" not in payload

    def test_create_local_in_policy6_has_no_ha_mgmt_intf_only_param(self) -> None:
        """local-in-policy6 has no ha-mgmt-intf-only field on the appliance (IPv4-only) --
        confirm the tool signature doesn't expose one."""
        import inspect

        sig = inspect.signature(policy_tools.create_local_in_policy6)
        assert "ha_mgmt_intf_only" not in sig.parameters

    @pytest.mark.asyncio
    async def test_update_local_in_policy6_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating a local-in-policy6 entry."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_local_in_policy6(
                adom="root",
                package="default",
                policyid=1,
                status="disable",
            )

        assert result["status"] == "success"
        assert result["policyid"] == 1

    @pytest.mark.asyncio
    async def test_update_local_in_policy6_no_params(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating with no fields returns an error."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.update_local_in_policy6(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "error"
        assert "No update parameters" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_local_in_policy6_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting a local-in-policy6 entry."""
        with patch("fortimanager_mcp.tools.policy_tools.get_fmg_client", return_value=mock_client):
            result = await policy_tools.delete_local_in_policy6(
                adom="root",
                package="default",
                policyid=1,
            )

        assert result["status"] == "success"
        assert "message" in result
