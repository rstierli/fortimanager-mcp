"""Main MCP server implementation for FortiManager.

Uses FastMCP pattern for tool registration.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from mcp.server.fastmcp import FastMCP

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils.config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global client instance
_fmg_client: FortiManagerClient | None = None


def get_fmg_client() -> FortiManagerClient | None:
    """Get the global FortiManager client instance."""
    return _fmg_client


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[None]:
    """Manage server lifecycle - connect/disconnect FortiManager client."""
    global _fmg_client

    logger.info("FortiManager MCP Server starting...")

    # Check if host is configured
    if not settings.fortimanager_host:
        logger.warning(
            "FORTIMANAGER_HOST not configured. "
            "Set environment variables or .env file to connect."
        )
        _fmg_client = None
        yield
        return

    # Initialize and connect client
    try:
        _fmg_client = FortiManagerClient.from_settings(settings)
        await _fmg_client.connect()
        logger.info("FortiManager client connected successfully")
    except Exception as e:
        logger.error(f"Failed to connect to FortiManager: {e}")
        _fmg_client = None

    yield

    # Cleanup on shutdown
    if _fmg_client:
        await _fmg_client.disconnect()
        logger.info("FortiManager client disconnected")


# Create FastMCP server with lifespan
mcp = FastMCP(
    "fortimanager-mcp",
    dependencies=["pyfmg", "pydantic-settings"],
    lifespan=lifespan,
)


def main() -> None:
    """Main entry point for the FortiManager MCP server."""
    # Import tools to register them with the server
    from fortimanager_mcp.tools import system_tools  # noqa: F401
    from fortimanager_mcp.tools import dvm_tools  # noqa: F401
    from fortimanager_mcp.tools import policy_tools  # noqa: F401
    from fortimanager_mcp.tools import object_tools  # noqa: F401
    from fortimanager_mcp.tools import script_tools  # noqa: F401
    from fortimanager_mcp.tools import template_tools  # noqa: F401
    from fortimanager_mcp.tools import sdwan_tools  # noqa: F401

    logger.info("Starting FortiManager MCP Server...")
    mcp.run()


if __name__ == "__main__":
    main()
