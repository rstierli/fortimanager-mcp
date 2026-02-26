# FortiManager MCP Server

[![CI](https://github.com/rstierli/fortimanager-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rstierli/fortimanager-mcp/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0--beta-green)](CHANGELOG.md)
[![FortiManager](https://img.shields.io/badge/FortiManager-7.0%20%7C%207.2%20%7C%207.4%20%7C%207.6-red)](README.md)

A Model Context Protocol (MCP) server for FortiManager JSON-RPC API. This server enables AI assistants like Claude to interact with FortiManager for centralized firewall policy management, device provisioning, and network configuration.

> **Note**: This is an independent open-source project and is not affiliated with, endorsed by, or supported by Fortinet, Inc. FortiManager is a trademark of Fortinet, Inc.

## Overview

This MCP server provides a comprehensive interface to FortiManager's capabilities, allowing AI assistants to:

- Create and manage firewall policies and policy packages
- Configure firewall objects (addresses, services, VIPs)
- Add, provision, and manage FortiGate devices
- Execute CLI scripts on managed devices
- Configure provisioning and SD-WAN templates
- Monitor tasks and installations
- Manage ADOMs and workspace locking

## Features

| Category | Capabilities |
|----------|-------------|
| **Policy Management** | Create/update/delete firewall policies, manage policy packages, clone packages |
| **Object Management** | Addresses, address groups, services, service groups, search objects |
| **Device Management** | Add/delete devices, bulk operations, device status, VDOM management |
| **Script Execution** | Create/run CLI scripts, execute on devices/groups, view execution logs |
| **Templates** | System templates, CLI template groups, template assignment and validation |
| **SD-WAN** | SD-WAN templates, rule configuration, template assignment |
| **System** | System status, ADOM management, task monitoring, workspace locking |

## Requirements

- **Python**: 3.12 or higher
- **FortiManager**: 7.x with JSON-RPC API access enabled
- **Authentication**: API token (recommended) or username/password
- **Network**: HTTPS access to FortiManager management interface

## Installation

### Using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/rstierli/fortimanager-mcp.git
cd fortimanager-mcp

# Create and activate virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv sync
```

### Using pip

```bash
# Clone the repository
git clone https://github.com/rstierli/fortimanager-mcp.git
cd fortimanager-mcp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .
```

### Using Docker

Pre-built images are available on GitHub Container Registry:

```bash
docker pull ghcr.io/rstierli/fortimanager-mcp:latest
```

Quick start with Docker Compose:

```yaml
# docker-compose.yml
services:
  fortimanager-mcp:
    image: ghcr.io/rstierli/fortimanager-mcp:latest
    container_name: fortimanager-mcp
    restart: unless-stopped
    ports:
      - "8000:8000"
    env_file:
      - .env
    environment:
      - MCP_SERVER_MODE=http
      - MCP_SERVER_HOST=0.0.0.0
      - MCP_SERVER_PORT=8000
      - FORTIMANAGER_HOST=your-fmg-hostname
      - FORTIMANAGER_VERIFY_SSL=false
      - DEFAULT_ADOM=root
      - FMG_TOOL_MODE=full
      - LOG_LEVEL=INFO
```

Create a `.env` file for secrets (not tracked in git):

```bash
# .env
FORTIMANAGER_API_TOKEN=your-api-token
MCP_AUTH_TOKEN=your-secret-bearer-token  # optional, enables HTTP auth
```

```bash
chmod 600 .env
docker compose up -d
```

Verify the server is running:

```bash
curl http://localhost:8000/health
# {"status": "healthy", "service": "fortimanager-mcp", "fortimanager_connected": true}
```

## Configuration

### Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` with your FortiManager settings:

```bash
# FortiManager Connection (Required)
FORTIMANAGER_HOST=192.168.1.100

# Authentication Option 1: API Token (Recommended)
FORTIMANAGER_API_TOKEN=your-api-token-here

# Authentication Option 2: Username/Password
# FORTIMANAGER_USERNAME=admin
# FORTIMANAGER_PASSWORD=your-password

# SSL Verification (set to false for self-signed certificates)
FORTIMANAGER_VERIFY_SSL=false

# Request Settings
FORTIMANAGER_TIMEOUT=30
FORTIMANAGER_MAX_RETRIES=3

# Logging
LOG_LEVEL=INFO  # DEBUG for troubleshooting

# Tool Loading Mode (important for context window optimization)
FMG_TOOL_MODE=full  # or "dynamic" for ~90% context reduction

# Default ADOM (optional - defaults to "root")
DEFAULT_ADOM=root

# HTTP Authentication (optional, recommended for Docker/HTTP deployments)
# MCP_AUTH_TOKEN=your-secret-token

# MCP Server Settings (for HTTP/Docker mode)
# MCP_SERVER_MODE=http     # "http" for Docker, "stdio" for Claude Desktop, "auto" to detect
# MCP_SERVER_HOST=0.0.0.0  # Bind address (0.0.0.0 for Docker)
# MCP_SERVER_PORT=8000      # Server port

# Allowed Host headers for reverse proxy deployments (optional)
# Required when running behind a reverse proxy (e.g., Traefik, nginx).
# The MCP SDK rejects non-localhost Host headers by default for DNS rebinding protection.
# MCP_ALLOWED_HOSTS=["mcp.example.com"]
```

### Tool Loading Modes

FortiManager MCP supports two tool loading modes to optimize context window usage:

| Mode | Tools Loaded | Context Usage | Best For |
|------|-------------|---------------|----------|
| `full` (default) | All 101 tools | ~100% | Large context windows, full functionality |
| `dynamic` | 4 discovery tools | ~10% | Smaller context windows, on-demand loading |

**Full Mode** (default): All 101 tools are loaded at startup. Best when you have sufficient context window and need immediate access to all FortiManager operations.

**Dynamic Mode**: Only lightweight discovery tools are loaded:
- `find_fortimanager_tool(operation)` - Search for tools by keyword
- `list_fortimanager_categories()` - List tool categories
- `execute_fortimanager_tool(name, params)` - Execute any tool by name
- `health_check()` - Server health status

To enable dynamic mode:
```bash
FMG_TOOL_MODE=dynamic
```

### Default ADOM

The `DEFAULT_ADOM` environment variable sets the default Administrative Domain (ADOM) for all FortiManager operations. When a tool is called without specifying an ADOM, this value is used.

```bash
DEFAULT_ADOM=root  # default value
```

This is particularly useful when:
- Your FortiManager only uses a single ADOM
- Most of your work is within one specific ADOM
- You want to avoid repeatedly specifying the ADOM in each tool call

If not set, defaults to `root` (the global ADOM).

### Generating an API Token

1. Log into FortiManager web interface
2. Go to **System Settings** > **Admin** > **Administrators**
3. Edit your admin user or create a new one
4. Under **JSON API Access**, click **Regenerate** or **New API Key**
5. Copy the generated token

## Running the Server

### Standalone Mode

```bash
# Using the installed command
fortimanager-mcp

# Or using Python module
python -m fortimanager_mcp
```

### Claude Desktop Integration

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "fortimanager": {
      "command": "/path/to/fortimanager-mcp/.venv/bin/fortimanager-mcp",
      "env": {
        "FORTIMANAGER_HOST": "your-fmg-hostname",
        "FORTIMANAGER_API_TOKEN": "your-api-token",
        "FORTIMANAGER_VERIFY_SSL": "false",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Note**: Use the full path to the `fortimanager-mcp` executable in your virtual environment.

### Claude Code Integration

Add to `~/.claude/mcp_servers.json`:

```json
{
  "mcpServers": {
    "fortimanager": {
      "command": "/path/to/fortimanager-mcp/.venv/bin/fortimanager-mcp",
      "env": {
        "FORTIMANAGER_HOST": "your-fmg-hostname",
        "FORTIMANAGER_API_TOKEN": "your-api-token",
        "FORTIMANAGER_VERIFY_SSL": "false",
        "DEFAULT_ADOM": "root",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Docker Mode

```bash
# Start the server
docker compose up -d

# View logs
docker compose logs -f

# Stop the server
docker compose down
```

### HTTP Mode (Remote Access)

When running in HTTP mode (Docker or standalone with `MCP_SERVER_MODE=http`), MCP clients connect via the Streamable HTTP transport:

**Claude Code** (`~/.claude/mcp_servers.json`):

```json
{
  "mcpServers": {
    "fortimanager": {
      "type": "streamable-http",
      "url": "https://your-mcp-host.example.com/mcp",
      "headers": {
        "Authorization": "Bearer your-mcp-auth-token"
      }
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "fortimanager": {
      "type": "streamable-http",
      "url": "https://your-mcp-host.example.com/mcp",
      "headers": {
        "Authorization": "Bearer your-mcp-auth-token"
      }
    }
  }
}
```

### Production Deployment (Reverse Proxy)

For production deployments behind a TLS-terminating reverse proxy:

```
MCP Client → HTTPS → Reverse Proxy (Traefik/nginx) → HTTP → MCP Container → FortiManager
```

**Key considerations:**

1. **MCP_ALLOWED_HOSTS** — The MCP SDK validates Host headers to prevent DNS rebinding attacks. Behind a reverse proxy, the Host header is your external hostname (not `localhost`). You must configure allowed hosts:

   ```bash
   MCP_ALLOWED_HOSTS=["mcp.example.com"]
   ```

2. **MCP_AUTH_TOKEN** — Always set a Bearer token for HTTP deployments:

   ```bash
   MCP_AUTH_TOKEN=$(openssl rand -hex 32)
   ```

3. **Secrets management** — Keep API tokens and auth tokens in an `env_file` (`.env`), not inline in `docker-compose.yml`.

**Example with Traefik:**

```yaml
services:
  fortimanager-mcp:
    image: ghcr.io/rstierli/fortimanager-mcp:latest
    container_name: fortimanager-mcp
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    env_file:
      - .env
    environment:
      - MCP_SERVER_MODE=http
      - MCP_SERVER_HOST=0.0.0.0
      - MCP_SERVER_PORT=8000
      - FORTIMANAGER_HOST=your-fmg-hostname
      - FORTIMANAGER_VERIFY_SSL=false
      - MCP_ALLOWED_HOSTS=["mcp.example.com"]
      - DEFAULT_ADOM=root
      - FMG_TOOL_MODE=full
      - LOG_LEVEL=INFO
    networks:
      - frontend
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.fmg-mcp-secure.entrypoints=https"
      - "traefik.http.routers.fmg-mcp-secure.rule=Host(`mcp.example.com`)"
      - "traefik.http.routers.fmg-mcp-secure.tls=true"
      - "traefik.http.services.fmg-mcp.loadbalancer.server.port=8000"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  frontend:
    external: true
```

## Available Tools (101 tools)

### System Tools (17 tools)

| Tool | Description |
|------|-------------|
| `get_system_status` | Get FortiManager system status and version info |
| `get_ha_status` | Get High Availability cluster status |
| `list_adoms` | List all Administrative Domains |
| `get_adom` | Get specific ADOM details |
| `list_devices` | List devices in an ADOM |
| `get_device` | Get specific device information |
| `list_device_groups` | List device groups in an ADOM |
| `list_tasks` | List background tasks |
| `get_task` | Get task details by ID |
| `wait_for_task` | Wait for a task to complete |
| `list_packages` | List policy packages in an ADOM |
| `get_package` | Get policy package details |
| `install_package` | Install policy package to devices |
| `install_device_settings` | Install device settings only |
| `lock_adom` | Lock ADOM for editing (workspace mode) |
| `unlock_adom` | Unlock ADOM |
| `commit_adom` | Commit ADOM changes |

### Device Management Tools (12 tools)

| Tool | Description |
|------|-------------|
| `list_device_vdoms` | List VDOMs for a device |
| `get_device_status` | Get device connection and sync status |
| `search_devices` | Search devices with filters |
| `add_device` | Add a new device to FortiManager |
| `add_model_device` | Add offline model device |
| `delete_device` | Remove a device from FortiManager |
| `add_devices_bulk` | Add multiple devices at once |
| `delete_devices_bulk` | Remove multiple devices at once |
| `update_device` | Update device metadata |
| `reload_device_list` | Refresh device list cache |
| `get_device_realtime_status` | Get live device status |
| `get_device_interfaces` | Get device interface information |

### Policy Tools (14 tools)

| Tool | Description |
|------|-------------|
| `create_package` | Create a new policy package |
| `delete_package` | Delete a policy package |
| `clone_package` | Clone an existing package |
| `assign_package` | Assign package to devices |
| `list_firewall_policies` | List policies in a package |
| `get_firewall_policy` | Get policy details |
| `create_firewall_policy` | Create a new firewall policy |
| `update_firewall_policy` | Update an existing policy |
| `delete_firewall_policy` | Delete a firewall policy |
| `delete_firewall_policies_bulk` | Bulk delete policies |
| `move_firewall_policy` | Reorder policy position |
| `search_firewall_policies` | Search policies with filters |
| `preview_install` | Preview installation changes |
| `get_preview_result` | Get preview results |

### Object Tools (24 tools)

| Tool | Description |
|------|-------------|
| `list_addresses` | List firewall address objects |
| `get_address` | Get address object details |
| `create_address_subnet` | Create subnet address |
| `create_address_host` | Create host address |
| `create_address_fqdn` | Create FQDN address |
| `create_address_range` | Create IP range address |
| `update_address` | Update address object |
| `delete_address` | Delete address object |
| `list_address_groups` | List address groups |
| `get_address_group` | Get address group details |
| `create_address_group` | Create address group |
| `update_address_group` | Update address group |
| `delete_address_group` | Delete address group |
| `list_services` | List service objects |
| `get_service` | Get service details |
| `create_service_tcp_udp` | Create TCP/UDP service |
| `create_service_icmp` | Create ICMP service |
| `update_service` | Update service object |
| `delete_service` | Delete service object |
| `list_service_groups` | List service groups |
| `get_service_group` | Get service group details |
| `create_service_group` | Create service group |
| `delete_service_group` | Delete service group |
| `search_objects` | Search all object types |

### Script Tools (12 tools)

| Tool | Description |
|------|-------------|
| `list_scripts` | List CLI scripts in ADOM |
| `get_script` | Get script content and details |
| `create_script` | Create a new CLI script |
| `update_script` | Update existing script |
| `delete_script` | Delete a script |
| `execute_script_on_device` | Run script on single device |
| `execute_script_on_devices` | Run script on multiple devices |
| `execute_script_on_device_group` | Run script on device group |
| `execute_script_on_package` | Run script on package/ADOM DB |
| `get_script_log_latest` | Get latest execution log |
| `get_script_log_summary` | Get execution history |
| `get_script_log_output` | Get specific log output |

### Template Tools (15 tools)

| Tool | Description |
|------|-------------|
| `list_templates` | List provisioning templates |
| `get_template` | Get template details |
| `list_system_templates` | List system templates (devprof) |
| `get_system_template` | Get system template details |
| `assign_system_template` | Assign template to device |
| `assign_system_template_bulk` | Bulk assign system template |
| `unassign_system_template` | Remove template assignment |
| `list_cli_template_groups` | List CLI template groups |
| `get_cli_template_group` | Get CLI template group |
| `create_cli_template_group` | Create CLI template group |
| `delete_cli_template_group` | Delete CLI template group |
| `list_template_groups` | List template groups |
| `get_template_group` | Get template group |
| `assign_template_group` | Assign template group |
| `validate_template` | Validate template against device |

### SD-WAN Tools (7 tools)

| Tool | Description |
|------|-------------|
| `list_sdwan_templates` | List SD-WAN templates |
| `get_sdwan_template` | Get SD-WAN template details |
| `create_sdwan_template` | Create SD-WAN template |
| `delete_sdwan_template` | Delete SD-WAN template |
| `assign_sdwan_template` | Assign template to device |
| `assign_sdwan_template_bulk` | Bulk assign SD-WAN template |
| `unassign_sdwan_template` | Remove template assignment |

## Usage Examples

### Policy Management

```
"List all firewall policies in the 'default' package"
"Create a new policy to allow HTTP traffic from internal to wan1"
"Move policy 10 before policy 5 in the default package"
"Install the branch-policy package to FGT-01"
```

### Object Management

```
"Create an address object for the web server at 192.168.10.10"
"List all address groups in the root ADOM"
"Create a service for TCP port 8443"
"Search for all objects containing 'web' in the name"
```

### Device Management

```
"List all devices in the root ADOM"
"Add a new FortiGate device at 10.0.0.1"
"Get the connection status for FGT-01"
"Show the VDOMs configured on FGT-01"
```

### Script Execution

```
"List all CLI scripts in the root ADOM"
"Create a backup script that runs 'execute backup config ftp'"
"Execute the backup script on FGT-01"
"Show the latest script execution log for FGT-01"
```

### Template Management

```
"List all system templates in the ADOM"
"Assign the 'Branch-Template' to FGT-01"
"Show available SD-WAN templates"
"Validate the template against device FGT-01"
```

### System Operations

```
"What is the FortiManager system status?"
"Lock the root ADOM for editing"
"Show all running tasks"
"Wait for task 123 to complete"
```

## Architecture

```
fortimanager-mcp/
├── src/fortimanager_mcp/
│   ├── api/
│   │   └── client.py          # FortiManager API client (JSON-RPC)
│   ├── tools/
│   │   ├── system_tools.py    # System, ADOM, task management
│   │   ├── dvm_tools.py       # Device management tools
│   │   ├── policy_tools.py    # Policy and package tools
│   │   ├── object_tools.py    # Address, service objects
│   │   ├── script_tools.py    # CLI script tools
│   │   ├── template_tools.py  # Provisioning templates
│   │   └── sdwan_tools.py     # SD-WAN templates
│   ├── utils/
│   │   ├── config.py          # Configuration management
│   │   └── errors.py          # Error handling
│   └── server.py              # MCP server implementation
├── tests/                     # Test suite (190+ tests)
├── docs/                      # API documentation
├── .env.example               # Example configuration
├── pyproject.toml             # Project configuration
├── Dockerfile                 # Container image definition
└── docker-compose.yml         # Container orchestration
```

## API Reference

The server communicates with FortiManager using the JSON-RPC API over HTTPS. All requests are sent to the `/jsonrpc` endpoint.

### Supported FortiManager Versions

- FortiManager 7.0.x
- FortiManager 7.2.x
- FortiManager 7.4.x
- FortiManager 7.6.x (primary development target)

### Authentication Methods

1. **API Token** (Recommended)
   - More secure, no session management
   - Tokens can be revoked without changing passwords
   - Works with FortiManager 7.0+

2. **Username/Password**
   - Traditional session-based authentication
   - Session automatically managed by the client

## Troubleshooting

### Enable Debug Logging

Set `LOG_LEVEL=DEBUG` in your environment to see detailed API requests and responses:

```bash
LOG_LEVEL=DEBUG fortimanager-mcp
```

### Common Issues

**Connection Failed**
- Verify FortiManager hostname/IP is correct
- Check network connectivity and firewall rules
- Ensure HTTPS port (443) is accessible

**Authentication Failed**
- Verify API token or credentials are correct
- Check if the admin account has API access enabled
- Ensure the account has sufficient permissions

**SSL Certificate Errors**
- Set `FORTIMANAGER_VERIFY_SSL=false` for self-signed certificates
- For production, use valid SSL certificates

**ADOM Locked**
- Another user may have the ADOM locked
- Use `unlock_adom` to release the lock (requires permissions)
- Check workspace mode settings in FortiManager

### Viewing Logs

**Claude Desktop MCP Server Logs**:
- macOS: `~/Library/Logs/Claude/mcp-server-fortimanager.log`
- Windows: `%APPDATA%\Claude\logs\mcp-server-fortimanager.log`

## Development

### Running Tests

The project includes 190+ tests covering all tool modules, error handling, and validation logic.

```bash
# Install dev dependencies
uv sync --all-extras

# Run all unit tests
pytest

# Run with coverage report
pytest --cov=src/fortimanager_mcp --cov-report=html

# Run specific test file
pytest tests/test_policy_tools.py -v

# Run tests with verbose output
pytest -v
```

### Integration Tests

Integration tests require a real FortiManager instance and are not run in CI.

```bash
# Set up environment
export FORTIMANAGER_HOST=your-fmg-host
export FORTIMANAGER_API_TOKEN=your-token
export FORTIMANAGER_VERIFY_SSL=false

# Run integration tests (requires live FMG)
pytest tests/integration/ -v
```

**Note**: Integration tests are verified against FortiManager 7.6.2. Some features may behave differently on older versions.

### CI Workflow

The project uses GitHub Actions for continuous integration:

- **Linting**: ruff check on all source files
- **Type checking**: mypy with strict mode
- **Unit tests**: pytest with coverage reporting
- **Python versions**: 3.12+

All CI checks must pass before merging pull requests.

### Code Quality

```bash
# Linting
ruff check src/

# Type checking
mypy src/

# Formatting
ruff format src/
```

## Security Considerations

### HTTP Authentication

When running in HTTP mode (Docker), you can secure the MCP endpoint with Bearer token authentication:

```bash
# Set in .env or environment
MCP_AUTH_TOKEN=your-secret-token
```

When configured, all HTTP requests (except `/health`) must include the `Authorization: Bearer <token>` header. If not set, the server runs without authentication (backwards compatible).

### Environment File Permissions

Protect your `.env` files containing API tokens:

```bash
chmod 600 .env .env.*
```

### Dynamic Tool Dispatch Security

In dynamic mode, the tool dispatcher validates tool names:
- Rejects private/internal functions (underscore-prefixed names)
- Validates that resolved attributes are callable
- Error responses never include request parameters (prevents credential leakage)

### General Security

- **API Tokens**: Store tokens securely, never commit to version control
- **SSL Verification**: Enable SSL verification in production environments
- **Least Privilege**: Use FortiManager accounts with minimal required permissions
- **Network Security**: Restrict access to FortiManager management interface
- **Workspace Locking**: Use ADOM locking to prevent concurrent modifications
- **Credential Sanitization**: Device credentials are automatically stripped from API responses

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to submit bug reports, feature requests, and pull requests.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Anthropic](https://anthropic.com) for the [Model Context Protocol](https://modelcontextprotocol.io)
- [Fortinet](https://fortinet.com) for FortiManager
- [pyfmg](https://github.com/ftntcorecse/pyfmg) library for FortiManager/FortiAnalyzer API
- [jmpijll/fortimanager-mcp](https://github.com/jmpijll/fortimanager-mcp) - Architectural inspiration

## Related Projects

- [fortianalyzer-mcp](https://github.com/rstierli/fortianalyzer-mcp) - MCP server for FortiAnalyzer with 70+ tools
- [pyfmg](https://github.com/ftntcorecse/pyfmg) - FortiManager/FortiAnalyzer Python library

## Author

Roland Stierli
