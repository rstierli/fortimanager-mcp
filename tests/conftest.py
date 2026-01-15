"""Pytest fixtures for FortiManager MCP tests.

Provides mocked client fixtures for testing tools without a real FortiManager.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any, Generator

from fortimanager_mcp.api.client import FortiManagerClient


# =============================================================================
# Mock Response Data
# =============================================================================


MOCK_SYSTEM_STATUS = {
    "Admin Domain Configuration": "Enabled",
    "BIOS version": "04000002",
    "Branch Point": "2620",
    "Build": "2620",
    "Current Time": "Tue Jan 14 10:00:00 UTC 2026",
    "Daylight Time Saving": "No",
    "FIPS Mode": "Disabled",
    "HA Mode": "Stand Alone",
    "Hostname": "FMG-TEST",
    "Platform Full Name": "FortiManager-VM64",
    "Platform Type": "FMG-VM64",
    "Release Version Information": "GA",
    "Serial Number": "FMG-VMTM00000000",
    "Time Zone": "UTC",
    "Version": "v7.6.5",
}

MOCK_ADOMS = [
    {
        "name": "root",
        "oid": 3,
        "state": 1,
        "flags": 0,
        "version": 700,
    },
    {
        "name": "demo",
        "oid": 100,
        "state": 1,
        "flags": 0,
        "version": 700,
    },
]

MOCK_DEVICES = [
    {
        "name": "FGT-01",
        "ip": "192.168.1.1",
        "sn": "FGT60F0000000001",
        "conn_status": 1,
        "conf_status": 1,
        "os_ver": "7.4.4",
        "platform_str": "FortiGate-60F",
    },
    {
        "name": "FGT-02",
        "ip": "192.168.1.2",
        "sn": "FGT60F0000000002",
        "conn_status": 1,
        "conf_status": 1,
        "os_ver": "7.4.4",
        "platform_str": "FortiGate-60F",
    },
]

MOCK_PACKAGES = [
    {
        "name": "default",
        "oid": 10,
        "type": "pkg",
        "scope member": [],
    },
    {
        "name": "branch-policy",
        "oid": 20,
        "type": "pkg",
        "scope member": [{"name": "FGT-01", "vdom": "root"}],
    },
]

MOCK_POLICIES = [
    {
        "policyid": 1,
        "name": "Allow-Web",
        "srcintf": ["port1"],
        "dstintf": ["port2"],
        "srcaddr": ["all"],
        "dstaddr": ["all"],
        "service": ["HTTP", "HTTPS"],
        "action": 1,
        "status": 1,
    },
    {
        "policyid": 2,
        "name": "Deny-All",
        "srcintf": ["any"],
        "dstintf": ["any"],
        "srcaddr": ["all"],
        "dstaddr": ["all"],
        "service": ["ALL"],
        "action": 0,
        "status": 1,
    },
]

MOCK_ADDRESSES = [
    {
        "name": "all",
        "type": 0,
        "subnet": ["0.0.0.0", "0.0.0.0"],
    },
    {
        "name": "webserver",
        "type": 0,
        "subnet": ["192.168.10.10", "255.255.255.255"],
    },
]

MOCK_SCRIPTS = [
    {
        "name": "backup-config",
        "type": "cli",
        "target": "remote_device",
        "content": "execute backup config ftp",
        "desc": "Backup device configuration",
    },
]

MOCK_TASKS = [
    {
        "id": 1,
        "adom": "root",
        "state": 4,
        "percent": 100,
        "title": "Install Package",
        "src": "securityconsole",
    },
]


# =============================================================================
# Client Fixtures
# =============================================================================


@pytest.fixture
def mock_fmg_instance() -> MagicMock:
    """Create a mock pyfmg FortiManager instance."""
    fmg = MagicMock()
    fmg.login.return_value = (0, {"status": {"code": 0, "message": "OK"}})
    fmg.logout.return_value = (0, {"status": {"code": 0, "message": "OK"}})
    return fmg


@pytest.fixture
def mock_client(mock_fmg_instance: MagicMock) -> FortiManagerClient:
    """Create a FortiManagerClient with mocked pyfmg backend."""
    client = FortiManagerClient(
        host="test-fmg.example.com",
        username="admin",
        password="password",
        verify_ssl=False,
    )
    client._fmg = mock_fmg_instance
    client._connected = True
    return client


@pytest.fixture
def mock_client_disconnected() -> FortiManagerClient:
    """Create a disconnected FortiManagerClient."""
    return FortiManagerClient(
        host="test-fmg.example.com",
        username="admin",
        password="password",
    )


# =============================================================================
# Response Configuration Fixtures
# =============================================================================


@pytest.fixture
def configure_mock_responses(mock_fmg_instance: MagicMock) -> None:
    """Configure standard mock responses for common API calls."""

    def mock_get(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock GET responses based on URL."""
        if url == "/sys/status":
            return (0, MOCK_SYSTEM_STATUS)
        elif "/dvmdb/adom" in url and "/device" in url:
            return (0, MOCK_DEVICES)
        elif url == "/dvmdb/adom":
            return (0, MOCK_ADOMS)
        elif "/pm/pkg/adom" in url:
            if "/firewall/policy" in url:
                return (0, MOCK_POLICIES)
            return (0, MOCK_PACKAGES)
        elif "/obj/firewall/address" in url:
            return (0, MOCK_ADDRESSES)
        elif "/script" in url:
            return (0, MOCK_SCRIPTS)
        elif "/task/task" in url:
            return (0, MOCK_TASKS)
        return (0, {})

    def mock_execute(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock EXEC responses."""
        return (0, {"task": 123})

    def mock_add(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock ADD responses."""
        return (0, {"status": {"code": 0, "message": "OK"}})

    def mock_update(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock UPDATE responses."""
        return (0, {"status": {"code": 0, "message": "OK"}})

    def mock_delete(url: str, **kwargs: Any) -> tuple[int, Any]:
        """Mock DELETE responses."""
        return (0, {"status": {"code": 0, "message": "OK"}})

    mock_fmg_instance.get.side_effect = mock_get
    mock_fmg_instance.execute.side_effect = mock_execute
    mock_fmg_instance.add.side_effect = mock_add
    mock_fmg_instance.update.side_effect = mock_update
    mock_fmg_instance.delete.side_effect = mock_delete


# =============================================================================
# Server/Tool Fixtures
# =============================================================================


@pytest.fixture
def mock_get_fmg_client(mock_client: FortiManagerClient) -> Generator[MagicMock, None, None]:
    """Patch get_fmg_client to return mocked client."""
    with patch("fortimanager_mcp.server.get_fmg_client", return_value=mock_client) as mock:
        yield mock


@pytest.fixture
def mock_get_fmg_client_none() -> Generator[MagicMock, None, None]:
    """Patch get_fmg_client to return None (disconnected)."""
    with patch("fortimanager_mcp.server.get_fmg_client", return_value=None) as mock:
        yield mock


# =============================================================================
# Async Fixtures
# =============================================================================


@pytest.fixture
async def async_mock_client(
    mock_client: FortiManagerClient, configure_mock_responses: None
) -> FortiManagerClient:
    """Async fixture that provides a fully configured mock client."""
    return mock_client
