"""Tests for system_tools module."""

import pytest
from unittest.mock import MagicMock, patch

from fortimanager_mcp.api.client import FortiManagerClient
from tests.conftest import MOCK_SYSTEM_STATUS, MOCK_ADOMS, MOCK_DEVICES, MOCK_PACKAGES


@pytest.fixture
def mock_client_configured(
    mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
) -> FortiManagerClient:
    """Configure mock client with standard responses."""

    def mock_get(url: str, **kwargs):
        if url == "/sys/status":
            return (0, MOCK_SYSTEM_STATUS)
        elif url == "/dvmdb/adom":
            return (0, MOCK_ADOMS)
        elif "/dvmdb/adom/" in url and "/device" in url:
            return (0, MOCK_DEVICES)
        elif url.startswith("/dvmdb/adom/") and "/device" not in url:
            return (0, MOCK_ADOMS[0])
        elif "/pm/pkg/adom" in url:
            return (0, MOCK_PACKAGES)
        return (0, {})

    def mock_execute(url: str, **kwargs):
        return (0, {"task": 123})

    mock_fmg_instance.get.side_effect = mock_get
    mock_fmg_instance.execute.side_effect = mock_execute
    return mock_client


class TestSystemStatus:
    """Test system status tools."""

    @pytest.mark.asyncio
    async def test_get_system_status_success(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        """Test successful system status retrieval."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.get_system_status()

        assert result["status"] == "success"
        assert "data" in result
        assert result["data"]["Version"] == "v7.6.5"

    @pytest.mark.asyncio
    async def test_get_system_status_not_connected(self) -> None:
        """Test system status when client not connected."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=None):
            result = await system_tools.get_system_status()

        assert result["status"] == "error"
        assert "message" in result


class TestAdomTools:
    """Test ADOM management tools."""

    @pytest.mark.asyncio
    async def test_list_adoms_success(self, mock_client_configured: FortiManagerClient) -> None:
        """Test listing ADOMs."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.list_adoms()

        assert result["status"] == "success"
        assert result["count"] == 2


class TestDeviceTools:
    """Test device listing tools."""

    @pytest.mark.asyncio
    async def test_list_devices_success(self, mock_client_configured: FortiManagerClient) -> None:
        """Test listing devices."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.list_devices(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2


class TestPackageTools:
    """Test package management tools."""

    @pytest.mark.asyncio
    async def test_list_packages_success(self, mock_client_configured: FortiManagerClient) -> None:
        """Test listing packages."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.list_packages(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_install_package_returns_task(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        """Test package installation returns task ID."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.install_package(
                adom="root",
                package="default",
                devices=[{"name": "FGT-01", "vdom": "root"}],
            )

        assert result["status"] == "success"
        assert "task_id" in result


class TestWorkspaceTools:
    """Test workspace/ADOM locking tools."""

    @pytest.mark.asyncio
    async def test_lock_adom_success(self, mock_client_configured: FortiManagerClient) -> None:
        """Test ADOM locking."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.lock_adom(adom="root")

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_unlock_adom_success(self, mock_client_configured: FortiManagerClient) -> None:
        """Test ADOM unlocking."""
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.unlock_adom(adom="root")

        assert result["status"] == "success"
