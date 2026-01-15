"""Tests for policy_tools module."""

from unittest.mock import MagicMock, patch

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
