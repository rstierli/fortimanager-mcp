"""Tests for object_tools module."""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.tools import object_tools
from tests.conftest import MOCK_ADDRESSES


class TestAddressTools:
    """Test address object tools."""

    @pytest.mark.asyncio
    async def test_list_addresses_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test listing addresses."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.list_addresses(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_list_addresses_not_connected(self) -> None:
        """Test listing addresses when client not connected."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=None):
            result = await object_tools.list_addresses(adom="root")

        assert result["status"] == "error"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_get_address_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting specific address."""
        mock_fmg_instance.get.return_value = (0, MOCK_ADDRESSES[1])

        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.get_address(adom="root", name="webserver")

        assert result["status"] == "success"
        assert result["address"]["name"] == "webserver"

    @pytest.mark.asyncio
    async def test_create_address_subnet_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating subnet address."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.create_address_subnet(
                adom="root",
                name="test-subnet",
                subnet="10.0.0.0/24",
            )

        assert result["status"] == "success"
        assert result["name"] == "test-subnet"

    @pytest.mark.asyncio
    async def test_create_address_host_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating host address."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.create_address_host(
                adom="root",
                name="test-host",
                ip="192.168.1.100",
            )

        assert result["status"] == "success"
        assert result["name"] == "test-host"

    @pytest.mark.asyncio
    async def test_create_address_fqdn_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating FQDN address."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.create_address_fqdn(
                adom="root",
                name="test-fqdn",
                fqdn="www.example.com",
            )

        assert result["status"] == "success"
        assert result["name"] == "test-fqdn"

    @pytest.mark.asyncio
    async def test_delete_address_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting address."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.delete_address(adom="root", name="test-addr")

        assert result["status"] == "success"
        assert "message" in result


class TestAddressGroupTools:
    """Test address group tools."""

    @pytest.mark.asyncio
    async def test_list_address_groups_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing address groups."""
        mock_fmg_instance.get.return_value = (0, [{"name": "grp1"}, {"name": "grp2"}])

        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.list_address_groups(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_create_address_group_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating address group."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.create_address_group(
                adom="root",
                name="test-group",
                members=["webserver", "all"],
            )

        assert result["status"] == "success"
        assert result["name"] == "test-group"


class TestServiceTools:
    """Test service object tools."""

    @pytest.mark.asyncio
    async def test_list_services_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing services."""
        mock_fmg_instance.get.return_value = (0, [{"name": "HTTP"}, {"name": "HTTPS"}])

        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.list_services(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_create_service_tcp_udp_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating TCP/UDP service."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.create_service_tcp_udp(
                adom="root",
                name="custom-http",
                tcp_portrange="8080",
            )

        assert result["status"] == "success"
        assert result["name"] == "custom-http"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stored_protocol", [15, 5])
    async def test_create_service_tcp_udp_uses_detected_protocol(self, stored_protocol) -> None:
        """The TCP/UDP/SCTP protocol enum is version-dependent (verified live:
        FMG 7.6.6 uses 5, 7.6.7/8.0 use 15), so the tool must send whatever the
        ADOM's own predefined services use, discovered at runtime, not a
        hardcoded guess."""
        from unittest.mock import AsyncMock

        object_tools._TCP_UDP_PROTOCOL_CACHE.clear()
        client = MagicMock()
        client.get_service = AsyncMock(
            return_value={
                "name": "ALL_TCP",
                "protocol": stored_protocol,
                "tcp-portrange": ["1-65535"],
            }
        )
        client.create_service = AsyncMock(return_value={})

        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=client):
            result = await object_tools.create_service_tcp_udp(
                adom="root",
                name="custom-web",
                tcp_portrange="8080",
            )

        assert result["status"] == "success"
        _adom, service = client.create_service.await_args.args
        assert service["protocol"] == stored_protocol

    @pytest.mark.asyncio
    async def test_tcp_udp_protocol_detects_via_list_scan(self) -> None:
        """When the named probes miss, detection scans the service list and
        skips non-port-based entries (e.g. ICMP) to find the code."""
        from unittest.mock import AsyncMock

        object_tools._TCP_UDP_PROTOCOL_CACHE.clear()
        client = MagicMock()
        client.get_service = AsyncMock(side_effect=Exception("not found"))
        client.list_services = AsyncMock(
            return_value=[
                {"name": "some-icmp", "protocol": 1, "icmptype": 8},
                {"name": "some-tcp", "protocol": 5, "tcp-portrange": ["1234"]},
            ]
        )

        proto = await object_tools._tcp_udp_protocol(client, "adom-scan")
        assert proto == 5

    @pytest.mark.asyncio
    async def test_tcp_udp_protocol_falls_back_when_undetectable(self) -> None:
        """If nothing port-based can be read, fall back to the current-build
        value rather than failing the create."""
        from unittest.mock import AsyncMock

        object_tools._TCP_UDP_PROTOCOL_CACHE.clear()
        client = MagicMock()
        client.get_service = AsyncMock(side_effect=Exception("not found"))
        client.list_services = AsyncMock(return_value=[])

        proto = await object_tools._tcp_udp_protocol(client, "adom-empty")
        assert proto == object_tools._TCP_UDP_PROTOCOL_FALLBACK

    @pytest.mark.asyncio
    async def test_create_service_icmp_sends_integer_protocol(self) -> None:
        """ICMP services must be created with the integer enum FMG stores
        (protocol=1, verified live), not the string "ICMP"."""
        from unittest.mock import AsyncMock

        client = MagicMock()
        client.create_service = AsyncMock(return_value={})

        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=client):
            result = await object_tools.create_service_icmp(
                adom="root",
                name="custom-ping",
                icmp_type=8,
            )

        assert result["status"] == "success"
        _adom, service = client.create_service.await_args.args
        assert service["protocol"] == 1
        assert service["icmptype"] == 8


class TestInputValidationRejection:
    """HIGH 1: malformed identifiers must be rejected before any API call."""

    @pytest.mark.asyncio
    async def test_get_address_rejects_path_injection_name(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A name with path separators must not reach the client."""
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.get_address(adom="root", name="../../sys/status")

        assert result["status"] == "error"
        # Client GET must not have been called with the malformed name
        mock_fmg_instance.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_address_rejects_bad_adom(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.delete_address(adom="root/../other", name="addr")

        assert result["status"] == "error"
        mock_fmg_instance.delete.assert_not_called()


class TestSearchTools:
    """Test object search tools."""

    @pytest.mark.asyncio
    async def test_search_objects_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test searching objects."""
        # Mock responses for each object type
        mock_fmg_instance.get.return_value = (0, [{"name": "web-server"}])

        with patch("fortimanager_mcp.tools.object_tools.get_fmg_client", return_value=mock_client):
            result = await object_tools.search_objects(adom="root", search_term="web")

        assert result["status"] == "success"
        # Should have results from at least addresses search
        assert "addresses" in result
