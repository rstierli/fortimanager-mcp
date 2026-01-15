"""Tests for FortiManager API client."""

from unittest.mock import MagicMock

import pytest

from fortimanager_mcp.api.client import FortiManagerClient, parse_fmg_error
from fortimanager_mcp.utils.errors import APIError, ConnectionError


class TestClientInitialization:
    """Test client initialization."""

    def test_init_with_api_token(self) -> None:
        """Test initialization with API token."""
        client = FortiManagerClient(
            host="test-fmg.example.com",
            api_token="test-token",
        )
        assert client.host == "test-fmg.example.com"
        assert client.api_token == "test-token"
        assert not client.is_connected

    def test_init_with_credentials(self) -> None:
        """Test initialization with username/password."""
        client = FortiManagerClient(
            host="https://test-fmg.example.com/",
            username="admin",
            password="password",
        )
        # Should strip protocol and trailing slash
        assert client.host == "test-fmg.example.com"
        assert client.username == "admin"
        assert client.password == "password"

    def test_init_default_values(self) -> None:
        """Test default configuration values."""
        client = FortiManagerClient(host="test-fmg.example.com")
        assert client.verify_ssl is True
        assert client.timeout == 30
        assert client.max_retries == 3


class TestClientConnection:
    """Test client connection methods."""

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, mock_client: FortiManagerClient) -> None:
        """Test connecting when already connected logs warning."""
        # Client is already connected via fixture
        assert mock_client.is_connected
        # Calling connect again should not raise
        await mock_client.connect()
        assert mock_client.is_connected

    @pytest.mark.asyncio
    async def test_disconnect(self, mock_client: FortiManagerClient) -> None:
        """Test disconnection."""
        assert mock_client.is_connected
        await mock_client.disconnect()
        assert not mock_client.is_connected

    @pytest.mark.asyncio
    async def test_ensure_connected_raises_when_disconnected(
        self, mock_client_disconnected: FortiManagerClient
    ) -> None:
        """Test that operations fail when disconnected."""
        with pytest.raises(ConnectionError):
            mock_client_disconnected._ensure_connected()


class TestClientOperations:
    """Test client API operations."""

    @pytest.mark.asyncio
    async def test_get_system_status(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test getting system status."""
        result = await mock_client.get_system_status()
        assert result["Version"] == "v7.6.5"
        assert result["Hostname"] == "FMG-TEST"

    @pytest.mark.asyncio
    async def test_list_adoms(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing ADOMs."""
        result = await mock_client.list_adoms()
        assert len(result) == 2
        assert result[0]["name"] == "root"
        assert result[1]["name"] == "demo"

    @pytest.mark.asyncio
    async def test_list_devices(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing devices."""
        result = await mock_client.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"

    @pytest.mark.asyncio
    async def test_list_packages(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing packages."""
        result = await mock_client.list_packages(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "default"

    @pytest.mark.asyncio
    async def test_install_package_returns_task(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test package installation returns task ID."""
        result = await mock_client.install_package(
            adom="root",
            pkg="default",
            scope=[{"name": "FGT-01", "vdom": "root"}],
        )
        assert "task" in result
        assert result["task"] == 123


class TestErrorHandling:
    """Test error handling."""

    def test_parse_fmg_error_known_code(self) -> None:
        """Test parsing known error codes."""
        error = parse_fmg_error(-3, "Not found", "GET /test")
        assert isinstance(error, APIError)
        assert "Object not found" in str(error)

    def test_parse_fmg_error_unknown_code(self) -> None:
        """Test parsing unknown error codes."""
        error = parse_fmg_error(-999, "Unknown error", "GET /test")
        assert isinstance(error, APIError)
        assert "-999" in str(error)

    @pytest.mark.asyncio
    async def test_handle_error_response(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test handling error responses from API."""
        mock_fmg_instance.get.return_value = (-3, {"status": {"message": "Not found"}})

        with pytest.raises(APIError) as exc_info:
            await mock_client.get("/test/url")

        assert "Object not found" in str(exc_info.value)
