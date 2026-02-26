"""Main MCP server implementation for FortiManager.

Uses FastMCP pattern for tool registration.
Supports two modes:
- full: All 101 tools loaded (default)
- dynamic: Only discovery tools loaded (~90% context reduction)
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils.config import get_settings

# Get settings
settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT,
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
    if not settings.FORTIMANAGER_HOST:
        logger.warning(
            "FORTIMANAGER_HOST not configured. Set environment variables or .env file to connect."
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


# Health check tool (always available)
@mcp.tool()
async def health_check() -> str:
    """Check FortiManager MCP server health and connection status."""
    mode = settings.FMG_TOOL_MODE
    if mode == "full":
        tool_info = "All 101 tools loaded"
    else:
        tool_info = "Discovery tools + dynamic execution"
    return f"FortiManager MCP Server is healthy (mode: {mode}, {tool_info})"


# Dynamic mode: lightweight discovery tools
def register_dynamic_tools(mcp_server: FastMCP) -> None:
    """Register discovery tools for dynamic mode only."""

    @mcp_server.tool()
    async def find_fortimanager_tool(operation: str) -> dict[str, Any]:
        """Discover FortiManager tools by operation name/keywords.

        Args:
            operation: Search term or operation description

        Returns:
            Matching tools with usage instructions
        """
        op = operation.lower().strip()

        # Define available tools and their categories (101 tools total)
        tool_catalog = {
            "system": [
                ("get_system_status", "Get FortiManager system status and version info"),
                ("get_ha_status", "Get High Availability cluster status"),
                ("list_adoms", "List all Administrative Domains"),
                ("get_adom", "Get specific ADOM details"),
                ("list_devices", "List devices in an ADOM"),
                ("get_device", "Get specific device information"),
                ("list_device_groups", "List device groups in an ADOM"),
                ("list_tasks", "List background tasks"),
                ("get_task", "Get task details by ID"),
                ("wait_for_task", "Wait for a task to complete"),
                ("list_packages", "List policy packages in an ADOM"),
                ("get_package", "Get policy package details"),
                ("install_package", "Install policy package to devices"),
                ("install_device_settings", "Install device settings only"),
                ("lock_adom", "Lock ADOM for editing (workspace mode)"),
                ("unlock_adom", "Unlock ADOM"),
                ("commit_adom", "Commit ADOM changes"),
            ],
            "device": [
                ("list_device_vdoms", "List VDOMs for a device"),
                ("get_device_status", "Get device connection and sync status"),
                ("search_devices", "Search devices with filters"),
                ("add_device", "Add a new device to FortiManager"),
                ("add_model_device", "Add offline model device"),
                ("delete_device", "Remove a device from FortiManager"),
                ("add_devices_bulk", "Add multiple devices at once"),
                ("delete_devices_bulk", "Remove multiple devices at once"),
                ("update_device", "Update device metadata"),
                ("reload_device_list", "Refresh device list cache"),
                ("get_device_realtime_status", "Get live device status"),
                ("get_device_interfaces", "Get device interface information"),
            ],
            "policy": [
                ("create_package", "Create a new policy package"),
                ("delete_package", "Delete a policy package"),
                ("clone_package", "Clone an existing package"),
                ("assign_package", "Assign package to devices"),
                ("list_firewall_policies", "List policies in a package"),
                ("get_firewall_policy", "Get policy details"),
                ("create_firewall_policy", "Create a new firewall policy"),
                ("update_firewall_policy", "Update an existing policy"),
                ("delete_firewall_policy", "Delete a firewall policy"),
                ("delete_firewall_policies_bulk", "Bulk delete policies"),
                ("move_firewall_policy", "Reorder policy position"),
                ("search_firewall_policies", "Search policies with filters"),
                ("preview_install", "Preview installation changes"),
                ("get_preview_result", "Get preview results"),
            ],
            "object": [
                ("list_addresses", "List firewall address objects"),
                ("get_address", "Get address object details"),
                ("create_address_subnet", "Create subnet address"),
                ("create_address_host", "Create host address"),
                ("create_address_fqdn", "Create FQDN address"),
                ("create_address_range", "Create IP range address"),
                ("update_address", "Update address object"),
                ("delete_address", "Delete address object"),
                ("list_address_groups", "List address groups"),
                ("get_address_group", "Get address group details"),
                ("create_address_group", "Create address group"),
                ("update_address_group", "Update address group"),
                ("delete_address_group", "Delete address group"),
                ("list_services", "List service objects"),
                ("get_service", "Get service details"),
                ("create_service_tcp_udp", "Create TCP/UDP service"),
                ("create_service_icmp", "Create ICMP service"),
                ("update_service", "Update service object"),
                ("delete_service", "Delete service object"),
                ("list_service_groups", "List service groups"),
                ("get_service_group", "Get service group details"),
                ("create_service_group", "Create service group"),
                ("delete_service_group", "Delete service group"),
                ("search_objects", "Search all object types"),
            ],
            "script": [
                ("list_scripts", "List CLI scripts in ADOM"),
                ("get_script", "Get script content and details"),
                ("create_script", "Create a new CLI script"),
                ("update_script", "Update existing script"),
                ("delete_script", "Delete a script"),
                ("execute_script_on_device", "Run script on single device"),
                ("execute_script_on_devices", "Run script on multiple devices"),
                ("execute_script_on_device_group", "Run script on device group"),
                ("execute_script_on_package", "Run script on package/ADOM DB"),
                ("get_script_log_latest", "Get latest execution log"),
                ("get_script_log_summary", "Get execution history"),
                ("get_script_log_output", "Get specific log output"),
            ],
            "template": [
                ("list_templates", "List provisioning templates"),
                ("get_template", "Get template details"),
                ("list_system_templates", "List system templates (devprof)"),
                ("get_system_template", "Get system template details"),
                ("assign_system_template", "Assign template to device"),
                ("assign_system_template_bulk", "Bulk assign system template"),
                ("unassign_system_template", "Remove template assignment"),
                ("list_cli_template_groups", "List CLI template groups"),
                ("get_cli_template_group", "Get CLI template group"),
                ("create_cli_template_group", "Create CLI template group"),
                ("delete_cli_template_group", "Delete CLI template group"),
                ("list_template_groups", "List template groups"),
                ("get_template_group", "Get template group"),
                ("assign_template_group", "Assign template group"),
                ("validate_template", "Validate template against device"),
            ],
            "sdwan": [
                ("list_sdwan_templates", "List SD-WAN templates"),
                ("get_sdwan_template", "Get SD-WAN template details"),
                ("create_sdwan_template", "Create SD-WAN template"),
                ("delete_sdwan_template", "Delete SD-WAN template"),
                ("assign_sdwan_template", "Assign template to device"),
                ("assign_sdwan_template_bulk", "Bulk assign SD-WAN template"),
                ("unassign_sdwan_template", "Remove template assignment"),
            ],
        }

        # Search for matching tools
        matches = []
        keywords = op.split()

        for category, tools in tool_catalog.items():
            # Check if searching by category
            if op in category or category in op:
                matches.extend([(name, desc, category) for name, desc in tools])
                continue

            # Search by keywords in tool names and descriptions
            for name, desc in tools:
                if any(kw in name.lower() or kw in desc.lower() for kw in keywords):
                    matches.append((name, desc, category))

        if not matches:
            return {
                "found": False,
                "message": f"No tools found for '{operation}'",
                "hint": "Try broader terms like: policy, device, script, template, sdwan, object, system",
                "categories": list(tool_catalog.keys()),
            }

        return {
            "found": True,
            "count": len(matches),
            "tools": [
                {"name": name, "description": desc, "category": cat}
                for name, desc, cat in matches[:20]  # Limit to 20 results
            ],
            "usage": "Use execute_fortimanager_tool(tool_name, parameters) to run a tool",
        }

    @mcp_server.tool()
    async def list_fortimanager_categories() -> dict[str, Any]:
        """List all FortiManager tool categories and their tool counts.

        Returns:
            Categories with descriptions and tool counts
        """
        return {
            "total_tools": 101,
            "categories": {
                "system": {
                    "count": 17,
                    "description": "System status, ADOM management, tasks, packages",
                },
                "device": {
                    "count": 12,
                    "description": "Device management, VDOMs, bulk operations",
                },
                "policy": {
                    "count": 14,
                    "description": "Firewall policies, packages, installation",
                },
                "object": {
                    "count": 24,
                    "description": "Addresses, services, groups, object search",
                },
                "script": {
                    "count": 12,
                    "description": "CLI scripts, execution, logs",
                },
                "template": {
                    "count": 15,
                    "description": "Provisioning templates, system templates, CLI template groups",
                },
                "sdwan": {
                    "count": 7,
                    "description": "SD-WAN templates, assignment",
                },
            },
            "usage": "Use find_fortimanager_tool(category) to see tools in a category",
        }

    @mcp_server.tool()
    async def execute_fortimanager_tool(
        tool_name: str, parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a FortiManager tool by name with parameters.

        Args:
            tool_name: Name of the tool to execute (e.g., 'list_devices')
            parameters: Dictionary of parameters for the tool

        Returns:
            Tool execution result
        """
        # Import tools module dynamically
        try:
            from fortimanager_mcp import tools

            # Reject private/internal names
            if tool_name.startswith("_"):
                return {
                    "error": f"Tool '{tool_name}' not found",
                    "hint": "Use find_fortimanager_tool() to discover available tools",
                }

            # Find the tool function
            tool_func = None
            for module_name in [
                "system_tools",
                "dvm_tools",
                "policy_tools",
                "object_tools",
                "script_tools",
                "template_tools",
                "sdwan_tools",
            ]:
                module = getattr(tools, module_name, None)
                if module and hasattr(module, tool_name):
                    candidate = getattr(module, tool_name)
                    if not callable(candidate):
                        continue
                    tool_func = candidate
                    break

            if not tool_func:
                return {
                    "error": f"Tool '{tool_name}' not found",
                    "hint": "Use find_fortimanager_tool() to discover available tools",
                }

            # Execute the tool
            params = parameters or {}
            result = await tool_func(**params)
            return {"success": True, "result": result}

        except Exception as e:
            return {
                "error": str(e),
                "tool": tool_name,
            }


# Conditional tool loading based on FMG_TOOL_MODE
if settings.FMG_TOOL_MODE == "dynamic":
    # Dynamic mode: register discovery tools only
    logger.info("Loading in DYNAMIC mode - discovery tools only (~90% context reduction)")
    register_dynamic_tools(mcp)

else:
    # Full mode: Load all tools (default behavior)
    logger.info("Loading in FULL mode - all 101 tools")

    # Import all tool modules (registers them with the server)
    from fortimanager_mcp.tools import (  # noqa: E402, F401
        dvm_tools,
        object_tools,
        policy_tools,
        script_tools,
        sdwan_tools,
        system_tools,
        template_tools,
    )


def main() -> None:
    """Entry point for the MCP server."""
    import sys

    # Determine server mode from settings
    server_mode = settings.MCP_SERVER_MODE

    if server_mode == "auto":
        # Auto-detect: stdio if no TTY, http otherwise
        if not sys.stdin.isatty():
            server_mode = "stdio"
        else:
            server_mode = "http"

    logger.info(f"Starting FortiManager MCP Server in {server_mode} mode...")
    logger.info(f"Tool mode: {settings.FMG_TOOL_MODE}")

    if server_mode == "stdio":
        # Claude Desktop / stdio mode
        mcp.run()
    else:
        # HTTP mode for Docker/web
        logger.info(
            f"Starting MCP server in HTTP mode on {settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}"
        )
        run_http()


def run_http() -> None:
    """Run MCP server in HTTP mode with Starlette wrapper and optional auth."""
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    import uvicorn
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from starlette.types import ASGIApp, Receive, Scope, Send

    # Health check endpoint
    async def health_endpoint(request: Request) -> JSONResponse:
        """HTTP health check endpoint for Docker health checks."""
        is_connected = _fmg_client is not None
        return JSONResponse(
            {
                "status": "healthy",
                "service": "fortimanager-mcp",
                "fortimanager_connected": is_connected,
            },
            status_code=200,
        )

    # Auth middleware
    class AuthMiddleware:
        """ASGI middleware that enforces Bearer token auth when MCP_AUTH_TOKEN is set."""

        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] not in ("http", "websocket"):
                await self.app(scope, receive, send)
                return

            # Allow health endpoint without auth
            path = scope.get("path", "")
            if path == "/health":
                await self.app(scope, receive, send)
                return

            # Skip auth if no token configured (backwards compatible)
            token = settings.MCP_AUTH_TOKEN
            if not token:
                await self.app(scope, receive, send)
                return

            # Check Authorization header
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode()

            if auth_header != f"Bearer {token}":
                response = JSONResponse(
                    {"error": "Unauthorized", "detail": "Invalid or missing Bearer token"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

            await self.app(scope, receive, send)

    # Lifespan context manager
    @asynccontextmanager
    async def app_lifespan(app: Starlette) -> AsyncIterator[None]:
        """Ensure MCP session manager and FortiManager client start."""
        async with mcp.session_manager.run():
            global _fmg_client

            if settings.FORTIMANAGER_HOST:
                logger.info("Initializing FortiManager connection")
                _fmg_client = FortiManagerClient.from_settings(settings)
                try:
                    await _fmg_client.connect()
                    logger.info("FortiManager connection established")
                except Exception as e:
                    logger.warning(f"FortiManager connection failed: {e}. Server will still start.")
                    _fmg_client = None
            else:
                logger.warning(
                    "FORTIMANAGER_HOST not configured. Set environment variables or .env file to connect."
                )
                _fmg_client = None

            try:
                yield
            finally:
                logger.info("Closing FortiManager connection")
                if _fmg_client:
                    await _fmg_client.disconnect()

    # Create Starlette app with health route, MCP mount, and auth middleware
    app = Starlette(
        routes=[
            Route("/health", health_endpoint, methods=["GET"]),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        lifespan=app_lifespan,
        middleware=[Middleware(AuthMiddleware)],
    )

    uvicorn.run(
        app,
        host=settings.MCP_SERVER_HOST,
        port=settings.MCP_SERVER_PORT,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main()
