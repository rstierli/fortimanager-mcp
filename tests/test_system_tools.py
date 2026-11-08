"""Tests for system_tools module."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils.config import get_settings
from tests.conftest import MOCK_ADOMS, MOCK_DEVICES, MOCK_PACKAGES, MOCK_SYSTEM_STATUS


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
        self, mock_client_configured: FortiManagerClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test package installation returns task ID (gate disabled here;
        the preview-before-install gate has its own tests in test_fmg_safety)."""
        from fortimanager_mcp.tools import system_tools
        from fortimanager_mcp.utils.config import get_settings

        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_INSTALL_SAFETY", "disabled")
        get_settings.cache_clear()
        try:
            with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
                result = await system_tools.install_package(
                    adom="root",
                    package="default",
                    devices=[{"name": "FGT-01", "vdom": "root"}],
                )
        finally:
            get_settings.cache_clear()

        assert result["status"] == "success"
        assert "task_id" in result


class TestInstallDeviceSettings:
    """install_device_settings forwards an optional revision comment.

    The preview gate it shares with install_package is covered in
    test_install_preview.py; it is switched off here.
    """

    @pytest.fixture(autouse=True)
    def _no_gate(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_INSTALL_SAFETY", "disabled")
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_comment_is_sent(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.install_device_settings(
                adom="root",
                devices=[{"name": "FGT-01", "vdom": "root"}],
                dev_rev_comments="  quick install from MCP  ",
            )

        assert result["status"] == "success"
        assert result["task_id"] == 123
        url, kwargs = (
            mock_fmg_instance.execute.call_args.args[0],
            mock_fmg_instance.execute.call_args.kwargs,
        )
        assert url == "/securityconsole/install/device"
        assert kwargs["dev_rev_comments"] == "quick install from MCP"

    @pytest.mark.asyncio
    async def test_no_comment_omits_field(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.install_device_settings(
                adom="root", devices=[{"name": "FGT-01", "vdom": "root"}]
            )

        assert result["status"] == "success"
        assert "dev_rev_comments" not in mock_fmg_instance.execute.call_args.kwargs

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "comment",
        ["", "   ", "line1\nline2", "x" * 128, "é" * 64],
    )
    async def test_bad_comment_refused_before_install(
        self,
        comment: str,
        mock_client_configured: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.install_device_settings(
                adom="root",
                devices=[{"name": "FGT-01", "vdom": "root"}],
                dev_rev_comments=comment,
            )

        assert result["status"] == "error"
        assert "dev_rev_comments" in result["message"]
        mock_fmg_instance.execute.assert_not_called()

    def test_comment_at_byte_limit_accepted(self) -> None:
        from fortimanager_mcp.tools import system_tools

        assert system_tools._validate_rev_comment("x" * 127) == "x" * 127


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


class TestTaskIdGuards:
    """get_task and wait_for_task interpolate task_id into /task/task/{id}.

    upstream #71 named delete_task, but these two reach the same URL through
    the client and have the same dynamic-mode gap: the int annotation is
    enforced in full mode only.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["../../sys/status", 1.5, True, None, -3])
    async def test_get_task_refuses_a_bad_id(
        self, bad: object, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.get_task(bad)

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        mock_fmg_instance.get.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["../../sys/status", 1.5, True, None, -3])
    async def test_wait_for_task_refuses_a_bad_id(
        self, bad: object, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        from fortimanager_mcp.tools import system_tools

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await system_tools.wait_for_task(bad, timeout=1, poll_interval=1)

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        mock_fmg_instance.get.assert_not_called()
