"""Integration tests for system operations against real FortiManager.

Tests:
- System status
- ADOM listing and verification
- Device listing in test ADOM
"""

import pytest

from fortimanager_mcp.api.client import FortiManagerClient

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_get_system_status(fmg_client: FortiManagerClient):
    """Test getting FortiManager system status."""
    status = await fmg_client.get_system_status()

    assert status is not None
    assert "Version" in status
    assert "Hostname" in status
    assert "Serial Number" in status

    # Verify we're connected to a FortiManager
    assert "Platform Type" in status
    platform = status.get("Platform Type", "")
    assert "FMG" in platform or "FortiManager" in platform.replace("-", "")


@pytest.mark.asyncio
async def test_list_adoms(fmg_client: FortiManagerClient):
    """Test listing all ADOMs."""
    adoms = await fmg_client.list_adoms()

    assert isinstance(adoms, list)
    assert len(adoms) > 0

    # Root ADOM should always exist
    adom_names = [a.get("name") for a in adoms]
    assert "root" in adom_names


@pytest.mark.asyncio
async def test_verify_test_adom_exists(
    fmg_client: FortiManagerClient,
    test_adom: str,
):
    """Verify the test ADOM (mcp-dev-test) exists."""
    adoms = await fmg_client.list_adoms()
    adom_names = [a.get("name") for a in adoms]

    assert test_adom in adom_names, (
        f"Test ADOM '{test_adom}' not found. "
        f"Available ADOMs: {adom_names}. "
        f"Please create the test ADOM first."
    )


@pytest.mark.asyncio
async def test_get_test_adom(
    fmg_client: FortiManagerClient,
    test_adom: str,
):
    """Test getting specific test ADOM details."""
    adom = await fmg_client.get_adom(test_adom)

    assert adom is not None
    assert adom.get("name") == test_adom


@pytest.mark.asyncio
async def test_list_devices_in_test_adom(
    fmg_client: FortiManagerClient,
    test_adom: str,
):
    """Test listing devices in test ADOM."""
    devices = await fmg_client.list_devices(test_adom)

    assert isinstance(devices, list)
    # List might be empty if no devices configured yet


@pytest.mark.asyncio
async def test_verify_test_device_exists(
    fmg_client: FortiManagerClient,
    test_adom: str,
    test_device: str,
):
    """Verify the test device (FGT-MCP-TEST-01) exists."""
    devices = await fmg_client.list_devices(test_adom)
    device_names = [d.get("name") for d in devices]

    assert test_device in device_names, (
        f"Test device '{test_device}' not found in ADOM '{test_adom}'. "
        f"Available devices: {device_names}. "
        f"Please create the test device first."
    )


@pytest.mark.asyncio
async def test_get_device_status(
    fmg_client: FortiManagerClient,
    test_adom: str,
    test_device: str,
):
    """Test getting device status for test device."""
    status = await fmg_client.get_device_status(test_adom, test_device)

    assert isinstance(status, list)
    if status:
        device = status[0]
        assert device.get("name") == test_device
        # Status fields should be present
        assert "conn_status" in device or "conf_status" in device


@pytest.mark.asyncio
async def test_list_tasks(fmg_client: FortiManagerClient):
    """Test listing tasks."""
    tasks = await fmg_client.list_tasks()

    assert isinstance(tasks, list)
    # Tasks list might be empty, but the call should succeed


@pytest.mark.asyncio
async def test_list_packages_in_test_adom(
    fmg_client: FortiManagerClient,
    test_adom: str,
):
    """Test listing policy packages in test ADOM."""
    packages = await fmg_client.list_packages(test_adom)

    assert isinstance(packages, list)
    # Should have at least default package or empty list


@pytest.mark.asyncio
async def test_list_device_groups(
    fmg_client: FortiManagerClient,
    test_adom: str,
):
    """Test listing device groups in test ADOM."""
    groups = await fmg_client.list_device_groups(test_adom)

    assert isinstance(groups, list)
    # Groups might be empty


@pytest.mark.asyncio
async def test_get_ha_status(fmg_client: FortiManagerClient):
    """Test getting HA status."""
    try:
        status = await fmg_client.get_ha_status()
        assert status is not None
    except Exception:
        # HA might not be configured, which is OK
        pytest.skip("HA not configured on this FortiManager")
