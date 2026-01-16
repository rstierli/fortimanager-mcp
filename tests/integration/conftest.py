"""Pytest fixtures for FortiManager MCP integration tests.

Requires environment variables for connection to real FortiManager.
"""

import os
from collections.abc import AsyncGenerator

import pytest
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from fortimanager_mcp.api.client import FortiManagerClient  # noqa: E402

# =============================================================================
# Skip Decorators
# =============================================================================


def requires_fmg_connection(func):
    """Decorator to skip test if FortiManager connection not available."""
    return pytest.mark.skipif(
        not os.getenv("FORTIMANAGER_HOST"),
        reason="FORTIMANAGER_HOST not set",
    )(func)


def requires_test_adom(func):
    """Decorator to skip test if test ADOM not configured."""
    return pytest.mark.skipif(
        not os.getenv("TEST_ADOM"),
        reason="TEST_ADOM not set",
    )(func)


def requires_test_device(func):
    """Decorator to skip test if test device not configured."""
    return pytest.mark.skipif(
        not os.getenv("TEST_DEVICE"),
        reason="TEST_DEVICE not set",
    )(func)


# =============================================================================
# Connection Fixtures
# =============================================================================


@pytest.fixture
def fmg_host() -> str:
    """Get FortiManager host from environment."""
    host = os.getenv("FORTIMANAGER_HOST")
    if not host:
        pytest.skip("FORTIMANAGER_HOST not set")
    return host


@pytest.fixture
def fmg_credentials() -> dict:
    """Get FortiManager credentials from environment."""
    return {
        "api_token": os.getenv("FORTIMANAGER_API_TOKEN"),
        "username": os.getenv("FORTIMANAGER_USERNAME"),
        "password": os.getenv("FORTIMANAGER_PASSWORD"),
    }


@pytest.fixture
async def fmg_client(
    fmg_host: str,
    fmg_credentials: dict,
) -> AsyncGenerator[FortiManagerClient, None]:
    """Create and connect FortiManager client.

    Yields connected client and disconnects on cleanup.
    """
    client = FortiManagerClient(
        host=fmg_host,
        api_token=fmg_credentials["api_token"],
        username=fmg_credentials["username"],
        password=fmg_credentials["password"],
        verify_ssl=os.getenv("FORTIMANAGER_VERIFY_SSL", "false").lower() == "true",
        timeout=30,
    )
    await client.connect()
    yield client
    await client.disconnect()


# =============================================================================
# Test Environment Fixtures
# =============================================================================


@pytest.fixture
def test_adom() -> str:
    """Get test ADOM from environment.

    Default: mcp-dev-test
    """
    return os.getenv("TEST_ADOM", "mcp-dev-test")


@pytest.fixture
def test_device() -> str:
    """Get test device name from environment.

    Default: FGT-MCP-TEST-01
    """
    return os.getenv("TEST_DEVICE", "FGT-MCP-TEST-01")


# =============================================================================
# Test Object Name Prefixes
# =============================================================================


@pytest.fixture
def test_prefix() -> str:
    """Prefix for test objects to easily identify and clean up.

    All test objects should be named with this prefix.
    """
    return "mcp-test-"


# =============================================================================
# Test Resource Names
# =============================================================================


@pytest.fixture
def test_package_name(test_prefix: str) -> str:
    """Name for test policy package."""
    return f"{test_prefix}pkg-integration"


@pytest.fixture
def test_address_name(test_prefix: str) -> str:
    """Name for test address object."""
    return f"{test_prefix}addr-integration"


@pytest.fixture
def test_policy_name(test_prefix: str) -> str:
    """Name for test firewall policy."""
    return f"{test_prefix}policy-integration"


@pytest.fixture
def test_script_name(test_prefix: str) -> str:
    """Name for test CLI script."""
    return f"{test_prefix}script-integration"


@pytest.fixture
def test_cli_template_group_name(test_prefix: str) -> str:
    """Name for test CLI template group."""
    return f"{test_prefix}cli-tmpl-group"
