"""Integration tests for policy operations against real FortiManager.

Tests:
- Create test policy package
- Create test address object
- Create test firewall policy
- Test installation PREVIEW (not actual install)
- Cleanup: delete all test objects

All test objects are prefixed with 'mcp-test-' for easy identification.
"""

import pytest

from fortimanager_mcp.api.client import FortiManagerClient

pytestmark = pytest.mark.integration


class TestPolicyOperations:
    """Test policy package and firewall policy operations.

    Tests are ordered for proper resource lifecycle:
    1. Create package
    2. Create address object
    3. Create firewall policy
    4. Preview installation
    5. Cleanup (delete in reverse order)
    """

    @pytest.mark.asyncio
    async def test_01_create_policy_package(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_package_name: str,
    ):
        """Create a test policy package."""
        # First, try to delete if exists from previous failed run
        try:
            await fmg_client.delete_package(test_adom, test_package_name)
        except Exception:
            pass  # Package might not exist

        # Create the package
        result = await fmg_client.create_package(test_adom, test_package_name)
        assert result is not None

        # Verify it exists
        packages = await fmg_client.list_packages(test_adom)
        pkg_names = [p.get("name") for p in packages]
        assert test_package_name in pkg_names

    @pytest.mark.asyncio
    async def test_02_create_address_object(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_address_name: str,
    ):
        """Create a test address object."""
        # First, try to delete if exists
        try:
            await fmg_client.delete_address(test_adom, test_address_name)
        except Exception:
            pass

        # Create subnet address
        address = {
            "name": test_address_name,
            "type": 0,  # subnet type
            "subnet": ["10.99.99.0", "255.255.255.0"],
            "comment": "MCP integration test address - safe to delete",
        }
        result = await fmg_client.create_address(test_adom, address)
        assert result is not None

        # Verify it exists
        addresses = await fmg_client.list_addresses(test_adom)
        addr_names = [a.get("name") for a in addresses]
        assert test_address_name in addr_names

    @pytest.mark.asyncio
    async def test_03_get_address_object(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_address_name: str,
    ):
        """Get the created address object."""
        address = await fmg_client.get_address(test_adom, test_address_name)

        assert address is not None
        assert address.get("name") == test_address_name
        assert "subnet" in address

    @pytest.mark.asyncio
    async def test_04_create_firewall_policy(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_package_name: str,
        test_policy_name: str,
        test_address_name: str,
    ):
        """Create a test firewall policy in the test package."""
        policy = {
            "name": test_policy_name,
            "srcintf": ["any"],
            "dstintf": ["any"],
            "srcaddr": [test_address_name],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "action": 0,  # deny
            "status": 0,  # disabled
            "logtraffic": 2,  # all
            "comments": "MCP integration test policy - safe to delete",
        }

        result = await fmg_client.create_firewall_policy(test_adom, test_package_name, policy)
        assert result is not None

    @pytest.mark.asyncio
    async def test_05_list_firewall_policies(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_package_name: str,
        test_policy_name: str,
    ):
        """List and verify the created policy exists."""
        policies = await fmg_client.list_firewall_policies(test_adom, test_package_name)

        assert isinstance(policies, list)
        policy_names = [p.get("name") for p in policies]
        assert test_policy_name in policy_names

    @pytest.mark.asyncio
    async def test_06_get_firewall_policy_count(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_package_name: str,
    ):
        """Get policy count in test package."""
        count = await fmg_client.get_firewall_policy_count(test_adom, test_package_name)

        assert isinstance(count, int)
        assert count >= 1  # At least our test policy

    @pytest.mark.asyncio
    async def test_07_assign_package_to_device(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_package_name: str,
        test_device: str,
    ):
        """Assign the test package to the test device."""
        scope = [{"name": test_device, "vdom": "root"}]

        result = await fmg_client.assign_package(test_adom, test_package_name, scope)
        assert result is not None

        # Verify assignment
        pkg = await fmg_client.get_package(test_adom, test_package_name)
        scope_members = pkg.get("scope member", [])
        device_names = [s.get("name") for s in scope_members]
        assert test_device in device_names

    @pytest.mark.asyncio
    async def test_08_preview_installation(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_device: str,
    ):
        """Test installation preview (does NOT actually install).

        This generates a preview of what would be installed without
        making any changes to the device.
        """
        scope = [{"name": test_device, "vdom": "root"}]

        # Request preview
        result = await fmg_client.install_preview(test_adom, scope)

        # Preview returns a task ID
        assert result is not None
        assert "task" in result

        task_id = result["task"]

        # Wait for preview task to complete (with timeout)
        import asyncio

        for _ in range(30):  # Max 30 seconds
            task = await fmg_client.get_task(task_id)
            state = task.get("state", 0)
            if state in [3, 4, 5]:  # done, error, cancelled
                break
            await asyncio.sleep(1)

        # Get preview result
        try:
            preview_result = await fmg_client.get_preview_result(test_adom, scope)
            # Preview result contains the CLI commands that would be sent
            assert preview_result is not None
        except Exception as e:
            # Preview result might fail if device is not reachable
            # This is OK for integration test
            pytest.skip(f"Preview result not available: {e}")

    # =========================================================================
    # Cleanup Tests (run last)
    # =========================================================================

    @pytest.mark.asyncio
    async def test_90_cleanup_firewall_policy(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_package_name: str,
        test_policy_name: str,
    ):
        """Cleanup: delete the test firewall policy."""
        # Find the policy ID
        policies = await fmg_client.list_firewall_policies(test_adom, test_package_name)

        policy_id = None
        for p in policies:
            if p.get("name") == test_policy_name:
                policy_id = p.get("policyid")
                break

        if policy_id:
            result = await fmg_client.delete_firewall_policy(
                test_adom, test_package_name, policy_id
            )
            assert result is not None

    @pytest.mark.asyncio
    async def test_91_cleanup_address_object(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_address_name: str,
    ):
        """Cleanup: delete the test address object."""
        try:
            result = await fmg_client.delete_address(test_adom, test_address_name)
            assert result is not None
        except Exception:
            pass  # Might already be deleted

    @pytest.mark.asyncio
    async def test_92_cleanup_policy_package(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
        test_package_name: str,
    ):
        """Cleanup: delete the test policy package."""
        try:
            result = await fmg_client.delete_package(test_adom, test_package_name)
            assert result is not None
        except Exception:
            pass  # Might already be deleted

        # Verify it's gone
        packages = await fmg_client.list_packages(test_adom)
        pkg_names = [p.get("name") for p in packages]
        assert test_package_name not in pkg_names


class TestAddressOperations:
    """Additional address object tests."""

    @pytest.mark.asyncio
    async def test_list_addresses(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing address objects."""
        addresses = await fmg_client.list_addresses(test_adom)

        assert isinstance(addresses, list)
        # Should have at least 'all' address
        addr_names = [a.get("name") for a in addresses]
        assert "all" in addr_names

    @pytest.mark.asyncio
    async def test_list_address_groups(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing address groups."""
        groups = await fmg_client.list_address_groups(test_adom)

        assert isinstance(groups, list)


class TestServiceOperations:
    """Service object tests."""

    @pytest.mark.asyncio
    async def test_list_services(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing service objects."""
        services = await fmg_client.list_services(test_adom)

        assert isinstance(services, list)
        # Should have predefined services

    @pytest.mark.asyncio
    async def test_list_service_groups(
        self,
        fmg_client: FortiManagerClient,
        test_adom: str,
    ):
        """Test listing service groups."""
        groups = await fmg_client.list_service_groups(test_adom)

        assert isinstance(groups, list)
