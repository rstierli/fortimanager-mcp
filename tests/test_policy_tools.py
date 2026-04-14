"""Tests for policy_tools module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import policy_tools
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
                srcaddr=["all"],
                dstaddr=["all"],
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
            raise Exception(f"Object not found: {name}")

        async def mock_get_service_group(adom: str, name: str):
            if name in service_groups:
                return service_groups[name]
            raise Exception(f"Object not found: {name}")

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
