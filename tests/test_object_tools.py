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
