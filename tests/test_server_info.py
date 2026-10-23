"""The server must report its own version in the MCP initialize handshake.

``MCPServer`` defaults ``version`` to an empty string, so without passing it
every client saw ``serverInfo.version == ""`` and could not tell which release
it was talking to.
"""

from mcp.client import Client

import fortimanager_mcp.server as server
from fortimanager_mcp import __version__


async def test_initialize_reports_package_version() -> None:
    async with Client(server.mcp) as client:
        assert client.server_info is not None
        assert client.server_info.name == "fortimanager-mcp"
        assert client.server_info.version == __version__
