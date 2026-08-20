# FortiManager MCP Server

[![CI](https://github.com/rstierli/fortimanager-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/rstierli/fortimanager-mcp/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.11.0-green)](CHANGELOG.md)
[![FortiManager](https://img.shields.io/badge/FortiManager-7.0%20%7C%207.2%20%7C%207.4%20%7C%207.6-red)](README.md)

A Model Context Protocol (MCP) server for FortiManager JSON-RPC API. This server enables AI assistants like Claude to interact with FortiManager for centralized firewall policy management, device provisioning, and network configuration.

> **Note**: This is an independent open-source project and is not affiliated with, endorsed by, or supported by Fortinet, Inc. FortiManager is a trademark of Fortinet, Inc.

> **Disclaimer:** This MCP server can create, modify, and delete configurations on FortiManager. Misuse or misconfiguration can impact production networks. Use at your own risk. Always test in a non-production environment first and ensure appropriate ADOM permissions are configured.

## Overview

This MCP server provides a comprehensive interface to FortiManager's capabilities, allowing AI assistants to:

- Create and manage firewall policies and policy packages, including security-profile (UTM) inspection
- Configure firewall objects (addresses, services, VIPs)
- Add, provision, and manage FortiGate devices
- Configure device-DB interfaces, DHCP scopes, and wireless (VAPs, FortiAP/WTP profiles, managed APs)
- Execute CLI scripts on managed devices
- Configure provisioning and SD-WAN templates
- Monitor tasks and installations
- Manage ADOMs and workspace locking

## Features

| Category | Capabilities |
|----------|-------------|
| **Policy Management** | Create/update/delete firewall policies, manage policy packages, clone packages, security-profile (UTM) inspection fields |
| **Object Management** | Addresses, address groups, services, service groups, search objects |
| **Device Management** | Add/delete devices, bulk operations, device status, VDOM management |
| **Device Configuration** | Interfaces/VLAN subinterfaces, DHCP scopes, wireless VAPs/SSIDs, FortiAP (WTP) profiles and managed AP registration -- all via the device DB, credential fields stripped from every read |
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
      # Keep TLS verification on; import the FortiManager CA for self-signed
      # certs. FORTIMANAGER_VERIFY_SSL=false disables MITM protection.
      - FORTIMANAGER_VERIFY_SSL=true
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

# SSL Verification — keep this TRUE. For self-signed FortiManager certs,
# import the FortiManager CA into your trust store instead of disabling it
# (see docs/SETUP_GUIDE.md "Trusting the FortiManager CA"). Setting this to
# false disables TLS verification and exposes the connection to MITM attacks.
FORTIMANAGER_VERIFY_SSL=true

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

# Allowed Host headers for HTTP/Docker deployments (optional)
# Set to the value clients use in their connection URL — NOT the client's IP.
# The MCP SDK rejects non-localhost Host headers by default for DNS rebinding protection.
# Examples: ["mcp.example.com"], ["10.1.5.62:8000"], or wildcard ["10.1.5.62:*"]
# MCP_ALLOWED_HOSTS=["mcp.example.com"]

# Streamable HTTP transport mode (optional - stateful by default)
# Set true behind a load balancer / multiple replicas, or a proxy that does not
# preserve the Mcp-Session-Id header, so each request is handled independently.
# MCP_STATELESS_HTTP=true

# HTTP request bounds (optional - bounded by default)
# MCP_MAX_REQUEST_BYTES=10485760     # Max request body; oversize gets 413. 0 disables.
# MCP_MAX_CONCURRENT_REQUESTS=64     # Max in-flight requests; excess gets 503. 0 disables.

# Reversible data masking (optional - off by default, issue #34)
# Masks IOC-bearing VALUES in tool outputs (IPs, subnets, serials, FQDNs,
# admin usernames). Names (object/ADOM/package/VDOM/device) route calls
# and are never masked. Masked values are read-only context: a token sent
# back as a tool argument is refused, so create and modify with real
# values. Requires 32/48/64 hex chars; enabling without a key aborts
# startup. Shares token compatibility with the FortiAnalyzer sibling when
# both use the same key, which also means one shared blast radius.
# MASKING_ENABLED=false
# FMG_MASKING_KEY=

# Safety Guardrails (optional - strict by default)
# FMG_SCRIPT_SAFETY=strict    # Block dangerous CLI commands in scripts (factory-reset, reboot, etc.)
# FMG_POLICY_SAFETY=strict    # Block overly permissive policies (srcaddr=all + dstaddr=all + accept)
```

### Tool Loading Modes

FortiManager MCP supports two tool loading modes to optimize context window usage:

| Mode | Tools Loaded | Context Usage | Best For |
|------|-------------|---------------|----------|
| `full` (default) | All 230 tools | ~100% | Large context windows, full functionality |
| `dynamic` | 4 discovery tools | ~10% | Smaller context windows, on-demand loading |

**Full Mode** (default): All 230 tools are loaded at startup. Best when you have sufficient context window and need immediate access to all FortiManager operations.

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

### Default Device

The `DEFAULT_DEVICE` environment variable sets a fallback managed device for
device-scoped tools (e.g. `get_device_client_location`,
`get_device_interface_config`, `get_device_sdwan_monitor`). When such a tool is
called without a `device`, this value is used.

```bash
DEFAULT_DEVICE=myfw01   # unset by default
```

It is unset by default because there is no universal device name. Setting it is
recommended for single-FortiGate deployments (and when driving the tools from an
LLM, which may omit `device` if it treats it as an implied default) — the tool
then resolves to `DEFAULT_DEVICE` instead of erroring. If neither a `device`
argument nor `DEFAULT_DEVICE` is provided, the tool returns a clear
`device_required` error.

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
        "FORTIMANAGER_VERIFY_SSL": "true",
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
        "FORTIMANAGER_VERIFY_SSL": "true",
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

1. **MCP_ALLOWED_HOSTS** — The MCP SDK validates the Host header to prevent DNS rebinding attacks. By default only `localhost` and `127.0.0.1` are accepted. Set this to the value clients put in their connection URL (NOT the client's IP):

   ```bash
   # Reverse-proxy hostname (Traefik/nginx):
   MCP_ALLOWED_HOSTS=["mcp.example.com"]
   # Direct Docker exposure on IP+port:
   MCP_ALLOWED_HOSTS=["10.1.5.62:8000"]
   # Port wildcard (any port on the host):
   MCP_ALLOWED_HOSTS=["10.1.5.62:*"]
   ```

2. **MCP_AUTH_TOKEN** — Always set a Bearer token for HTTP deployments:

   ```bash
   MCP_AUTH_TOKEN=$(openssl rand -hex 32)
   ```

3. **Secrets management** — Keep API tokens and auth tokens in an `env_file` (`.env`), not inline in `docker-compose.yml`.

4. **MCP_STATELESS_HTTP** — When the server runs behind a load balancer or as multiple replicas (or behind a proxy that does not preserve the `Mcp-Session-Id` header), enable stateless mode so each request is self-contained and no sticky sessions are required:

   ```bash
   MCP_STATELESS_HTTP=true
   ```

   Leave it unset (stateful, the default) for single-instance deployments. Stateless mode disables server-initiated streaming that relies on a persistent session.

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
      # Keep TLS verification on; import the FortiManager CA for self-signed
      # certs. FORTIMANAGER_VERIFY_SSL=false disables MITM protection.
      - FORTIMANAGER_VERIFY_SSL=true
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

## Available Tools (230 tools)

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

### Device Management Tools (14 tools)

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
| `get_device_interface_config` | Read device-DB interface config objects, filterable by VLAN id / interface name (maps a client IP to its VLAN/interface/port) |
| `get_device_client_location` | Asset Identity Center: locate a client (by ip/mac/hostname) via the live detected-device inventory — resolves the FortiAP/FortiSwitch, port and VLAN it is connected through |

### Device Configuration Tools (19 tools)

Typed device-DB configuration (issues #45, #52): everything is staged in FortiManager's
device database and pushed with `preview_install` + `install_device_settings`;
nothing talks to the FortiGate directly.

| Tool | Description |
|------|-------------|
| `create_device_interface` | Create a VLAN subinterface (parent, vlanid, ip, allowaccess, role, alias) |
| `update_device_interface` | Update device-DB interface fields |
| `delete_device_interface` | Delete a device-DB interface |
| `list_device_dhcp_servers` | List DHCP server scopes in the device DB |
| `create_device_dhcp_server` | Create a DHCP scope (interface, range, netmask, gateway, DNS) |
| `update_device_dhcp_server` | Update a DHCP scope by id |
| `delete_device_dhcp_server` | Delete a DHCP scope by id |
| `list_device_vaps` | List wireless VAPs (SSIDs), passphrases stripped |
| `create_device_vap` | Create a wireless VAP/SSID with security mode and VLAN mapping |
| `delete_device_vap` | Delete a wireless VAP |
| `assign_vap_to_wtp_profile` | Add a VAP to FortiAP profile radios so the SSID broadcasts |
| `list_device_wtp_profiles` | List FortiAP (WTP) profiles in the device DB |
| `get_device_wtp_profile` | Get a FortiAP (WTP) profile, radios included |
| `update_device_wtp_profile_radio` | Update one radio's `channel`/`channel-bonding`, other fields untouched |
| `list_device_wtps` | List managed FortiAPs (`wireless-controller wtp`) in the device DB |
| `get_device_wtp` | Get a managed FortiAP by wtp-id (serial number) |
| `create_device_wtp` | Register a managed FortiAP (wtp-id, wtp-profile, authorization state) |
| `update_device_wtp` | Update a managed FortiAP's profile/name/admin/location/comment |
| `delete_device_wtp` | Delete a managed FortiAP registration |

### Policy Tools (25 tools)

`create_firewall_policy` and `update_firewall_policy` accept security-profile
(UTM) fields -- `utm_status`, `av_profile`, `ips_sensor`, `webfilter_profile`,
`dnsfilter_profile`, `application_list`, `file_filter_profile`,
`ssl_ssh_profile`, `profile_protocol_options`, `profile_group` -- so a policy
can actually apply inspection, not just route traffic. `profile_group` is
mutually exclusive with the individual profile fields it bundles; see
"Security Profile Field Validation" under Safety Guardrails below.

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
| `get_policy_services` | Get policy services with optional group resolution |
| `preview_install` | Preview installation changes |
| `get_preview_result` | Get preview results |
| `create_local_in_policy` | Create a new IPv4 local-in policy |
| `create_local_in_policy6` | Create a new IPv6 local-in policy |
| `delete_local_in_policy` | Delete an IPv4 local-in policy |
| `delete_local_in_policy6` | Delete an IPv6 local-in policy |
| `get_local_in_policy` | Get detailed information about a specific IPv4 local-in policy |
| `get_local_in_policy6` | Get detailed information about a specific IPv6 local-in policy |
| `list_local_in_policies` | List IPv4 local-in policies in a policy package |
| `list_local_in_policies6` | List IPv6 local-in policies in a policy package |
| `update_local_in_policy` | Update an existing IPv4 local-in policy |
| `update_local_in_policy6` | Update an existing IPv6 local-in policy |

### Object Tools (25 tools)

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
| `update_service_group` | Update service group members and comment |
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

### SD-WAN Tools (10 tools)

| Tool | Description |
|------|-------------|
| `list_sdwan_templates` | List SD-WAN templates |
| `get_sdwan_template` | Get SD-WAN template details |
| `create_sdwan_template` | Create SD-WAN template |
| `delete_sdwan_template` | Delete SD-WAN template |
| `assign_sdwan_template` | Assign template to device |
| `assign_sdwan_template_bulk` | Bulk assign SD-WAN template |
| `unassign_sdwan_template` | Remove template assignment |
| `get_device_sdwan` | Read a device's SD-WAN config (members/zones/health-checks/rules) from the device DB — for SD-WAN configured locally, not via a template |
| `get_device_sdwan_monitor` | Live SD-WAN Monitor via the device proxy — per-member link/bandwidth (`virtual-wan/members`) + per-member SLA health (`virtual-wan/health-check`) |
| `resolve_datasource` | Generic config-DB introspection: resolve the objects a config attribute is allowed to reference (`option: datasrc`) |

### Security Profile Tools (20 tools)

| Tool | Description |
|------|-------------|
| `create_antivirus_profile` | Create an antivirus profile |
| `create_application_list` | Create an application-control list |
| `create_dnsfilter_profile` | Create a DNS filter profile |
| `create_webfilter_profile` | Create a web filter profile |
| `delete_antivirus_profile` | Delete an antivirus profile |
| `delete_application_list` | Delete an application-control list |
| `delete_dnsfilter_profile` | Delete a DNS filter profile |
| `delete_webfilter_profile` | Delete a web filter profile |
| `get_antivirus_profile` | Get detailed information about an antivirus profile |
| `get_application_list` | Get detailed information about an application-control list |
| `get_dnsfilter_profile` | Get detailed information about a DNS filter profile |
| `get_webfilter_profile` | Get detailed information about a web filter profile |
| `list_antivirus_profiles` | List antivirus profiles in an ADOM |
| `list_application_lists` | List application-control lists in an ADOM |
| `list_dnsfilter_profiles` | List DNS filter profiles in an ADOM |
| `list_webfilter_profiles` | List web filter profiles in an ADOM |
| `update_antivirus_profile` | Update an existing antivirus profile |
| `update_application_list` | Update an existing application-control list |
| `update_dnsfilter_profile` | Update an existing DNS filter profile |
| `update_webfilter_profile` | Update an existing web filter profile |

### Security Profile (Advanced) Tools (23 tools)

| Tool | Description |
|------|-------------|
| `add_ips_sensor_signature_override` | Add a signature filter/override entry to an IPS sensor |
| `create_dlp_profile` | Create a DLP (Data Loss Prevention) profile |
| `create_ips_sensor` | Create an IPS sensor |
| `create_ssl_ssh_profile` | Create an SSL/SSH inspection profile |
| `create_waf_profile` | Create a WAF (Web Application Firewall) profile |
| `delete_dlp_profile` | Delete a DLP profile |
| `delete_ips_sensor` | Delete an IPS sensor |
| `delete_ssl_ssh_profile` | Delete an SSL/SSH inspection profile |
| `delete_waf_profile` | Delete a WAF profile |
| `get_dlp_profile` | Get detailed information about a DLP profile |
| `get_ips_sensor` | Get detailed information about an IPS sensor |
| `get_ssl_ssh_profile` | Get detailed information about an SSL/SSH inspection profile |
| `get_waf_profile` | Get detailed information about a WAF profile |
| `list_dlp_profiles` | List DLP (Data Loss Prevention) profiles in an ADOM |
| `list_ips_sensor_signature_overrides` | List the signature-filter/override entries of an IPS sensor |
| `list_ips_sensors` | List IPS sensors in an ADOM |
| `list_ssl_ssh_profiles` | List SSL/SSH inspection profiles in an ADOM |
| `list_waf_profiles` | List WAF (Web Application Firewall) profiles in an ADOM |
| `remove_ips_sensor_signature_override` | Remove a signature filter/override entry from an IPS sensor |
| `update_dlp_profile` | Update a DLP profile's top-level settings |
| `update_ips_sensor` | Update an IPS sensor's top-level settings |
| `update_ssl_ssh_profile` | Update an SSL/SSH inspection profile |
| `update_waf_profile` | Update a WAF profile's top-level settings |

### VPN Tools (14 tools)

| Tool | Description |
|------|-------------|
| `create_device_ipsec_phase1_interface` | Create an IPsec phase1-interface (remote gateway / IKE SA) in a device's device DB |
| `create_device_ipsec_phase2_interface` | Create an IPsec phase2-interface (tunnel/traffic selector) in a device's device DB |
| `delete_device_ipsec_phase1_interface` | Delete an IPsec phase1-interface from a device's device DB |
| `delete_device_ipsec_phase2_interface` | Delete an IPsec phase2-interface from a device's device DB |
| `get_device_ipsec_phase1_interface` | Get one IPsec phase1-interface (remote gateway) from a device's device DB |
| `get_device_ipsec_phase2_interface` | Get one IPsec phase2-interface (tunnel/selector) from a device's device DB |
| `get_device_sslvpn_settings` | Get the SSL-VPN (Agentless VPN) settings object from a device's device DB |
| `get_device_sslvpn_web_portal` | Get an SSL-VPN web portal from a device's device DB |
| `list_device_ipsec_phase1_interfaces` | List IPsec phase1-interface (remote gateway) definitions in a device's device DB |
| `list_device_ipsec_phase2_interfaces` | List IPsec phase2-interface (tunnel/selector) definitions in a device's device DB |
| `update_device_ipsec_phase1_interface` | Update fields on a device-DB IPsec phase1-interface, unspecified fields unchanged |
| `update_device_ipsec_phase2_interface` | Update fields on a device-DB IPsec phase2-interface, unspecified fields unchanged |
| `update_device_sslvpn_settings` | Update the SSL-VPN (Agentless VPN) settings object in a device's device DB |
| `update_device_sslvpn_web_portal` | Update an SSL-VPN web portal in a device's device DB |

### Revision History Tools (11 tools)

| Tool | Description |
|------|-------------|
| `diff_adom_revision` | Diff a past ADOM DB revision against the CURRENT live ADOM |
| `diff_device_revision` | Diff a past device DB revision against the CURRENT device DB |
| `diff_policy_package` | Diff a policy package's objects at a past ADOM revision against its CURRENT live state |
| `get_adom_revision` | Get one ADOM DB revision's metadata |
| `get_device_revision` | Check out one device DB revision's stored configuration text |
| `list_adom_revisions` | List the ADOM DB revision history for an ADOM |
| `list_device_revisions` | List the device DB revision history for a managed device |
| `list_policy_revisions` | List the change log for a policy package's firewall policies |
| `revert_adom_revision` | Revert the live ADOM DB to a past revision |
| `revert_device_revision` | Revert a device's device DB to a past revision |
| `revert_firewall_policy` | Restore a firewall policy to a past change-log snapshot |

### FortiManager Operations Tools (9 tools)

| Tool | Description |
|------|-------------|
| `add_packet_capture` | Add a new FortiManager packet capture definition |
| `delete_task` | Delete a task record from FortiManager's task list |
| `get_fmg_license` | Get the FortiManager license/contract status |
| `get_packet_capture_status` | Get the running/packet-count status of packet captures |
| `list_packet_captures` | List existing FortiManager packet capture definitions |
| `start_packet_capture` | Start a packet capture from an existing definition |
| `stop_packet_capture` | Stop a running packet capture |
| `trigger_fmg_backup` | Trigger a FortiManager system backup to a remote server |
| `trigger_fmg_restore` | Restore the FortiManager system from a backup on a remote server |

### Device Group Tools (8 tools)

| Tool | Description |
|------|-------------|
| `add_device_to_group` | Add a single device to a device group |
| `add_devices_to_group_bulk` | Add multiple devices to a device group in one call |
| `add_group_to_group` | Nest a device group inside another device group |
| `create_device_group` | Create a device group in FortiManager's device manager database |
| `delete_device_group` | Delete a device group from FortiManager |
| `remove_device_from_group` | Remove a single device from a device group |
| `remove_devices_from_group_bulk` | Remove multiple devices from a device group in one call |
| `remove_group_from_group` | Remove a nested group from its parent device group |

### Firmware Tools (5 tools)

| Tool | Description |
|------|-------------|
| `get_firmware_upgrade_path` | Preview the multi-step firmware upgrade path to a target version |
| `get_firmware_upgrade_report` | Get the firmware upgrade report for a device under a named profile |
| `list_available_firmware` | List firmware versions available for a platform |
| `list_firmware_images` | List firmware image files stored on the FortiManager's local disk |
| `upgrade_device_firmware` | Trigger a firmware upgrade on a managed device |

### Object Usage Tools (2 tools)

| Tool | Description |
|------|-------------|
| `find_duplicate_objects` | Find objects with identical content configured under different names |
| `find_object_usage` | Find everywhere an ADOM object is referenced (where-used) |

### Policy Lookup Tools (1 tool)

| Tool | Description |
|------|-------------|
| `policy_lookup` | Simulate a firewall policy lookup for a traffic 5-tuple against a managed device |

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
- For self-signed FortiManager certs, import the FortiManager CA certificate
  into your trust store and keep `FORTIMANAGER_VERIFY_SSL=true`
  (see [SETUP_GUIDE.md](docs/SETUP_GUIDE.md) → "Trusting the FortiManager CA")
- For production, use valid SSL certificates signed by a trusted CA
- Last resort only: `FORTIMANAGER_VERIFY_SSL=false` disables TLS verification
  and exposes the connection to man-in-the-middle attacks — avoid in production

**ADOM Locked**
- Another user may have the ADOM locked
- Use `unlock_adom` to release the lock (requires permissions)
- Check workspace mode settings in FortiManager

### MCP Transport Issues

**`Invalid Host header` (HTTP/Docker mode)**

Symptom — server logs show:

```
mcp.server.transport_security - WARNING - Invalid Host header: 10.x.y.z:8000
INFO:     ... "POST /mcp HTTP/1.1" 421 Misdirected Request
```

Cause: the MCP SDK validates the Host header for DNS rebinding protection. By default only `localhost` and `127.0.0.1` are accepted. The header value is whatever the **client** puts in its connection URL — not the client's IP.

Fix: add the URL value (with port, if used) to `MCP_ALLOWED_HOSTS`:

```bash
# If the client connects to http://10.1.5.62:8000/mcp:
MCP_ALLOWED_HOSTS=["10.1.5.62:8000"]
# Or use a port wildcard to allow any port on that host:
MCP_ALLOWED_HOSTS=["10.1.5.62:*"]
# For a reverse-proxy hostname:
MCP_ALLOWED_HOSTS=["mcp.example.com"]
```

**`PermissionError: pyvenv.cfg` (macOS stdio mode)**

Symptom — Claude Desktop MCP logs show:

```
Fatal Python error: init_import_site: Failed to import the site module
PermissionError: [Errno 1] Operation not permitted: '.../.venv/pyvenv.cfg'
```

Cause: macOS TCC (Transparency, Consent, Control) blocks Claude Desktop from launching executables from inside `~/Documents`, `~/Desktop`, or `~/Downloads`.

Fix (preferred): move the project out of those folders, recreate the venv, and update Claude Desktop's MCP config to the new path:

```bash
mv ~/Documents/mcp ~/mcp
cd ~/mcp/fortimanager-mcp
rm -rf .venv && uv sync
# Then update the "command" path in claude_desktop_config.json
```

Fix (alternative): grant Claude Desktop **Full Disk Access** — System Settings → Privacy & Security → Full Disk Access → add Claude. Broader permission; only use if relocation isn't feasible.

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
# Keep verification on; import the FortiManager CA for self-signed certs.
export FORTIMANAGER_VERIFY_SSL=true

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

### Safety Guardrails

The MCP server includes built-in safety checks to prevent accidental damage to managed infrastructure. Both are **enabled by default**.

#### Script Content Safety (`FMG_SCRIPT_SAFETY`)

Blocks dangerous CLI commands in `create_script` and `update_script`:

| Blocked Command | Risk |
|----------------|------|
| `execute factory-reset` | Wipes device configuration |
| `execute reboot` | Causes device outage |
| `execute shutdown` | Powers off device |
| `execute format` | Formats device disk |
| `execute erase-disk` | Erases device disk |

Handles FortiOS abbreviations (`exec` for `execute`) and case variations.

```bash
FMG_SCRIPT_SAFETY=strict    # Default: block dangerous commands
FMG_SCRIPT_SAFETY=disabled  # Allow all commands (use with extreme caution)
```

#### Policy Permissiveness Safety (`FMG_POLICY_SAFETY`)

Blocks overly permissive firewall policies in `create_firewall_policy` and `update_firewall_policy`. Detects policies where `srcaddr=all` + `dstaddr=all` + `action=accept`, which allows unrestricted traffic.

```bash
FMG_POLICY_SAFETY=strict    # Default: block overly permissive policies
FMG_POLICY_SAFETY=warn      # Allow but include warning in response
FMG_POLICY_SAFETY=disabled  # Allow all policies
```

#### Restore Safety (`FMG_RESTORE_SAFETY`)

Blocks `trigger_fmg_restore` (replaces FortiManager's entire configuration and interrupts the service) unless the caller also passes `confirm=True`.

```bash
FMG_RESTORE_SAFETY=strict    # Default: refuse without confirm=True
FMG_RESTORE_SAFETY=disabled  # Allow unconditionally
```

#### Revert Safety (`FMG_REVERT_SAFETY`)

Blocks `revert_adom_revision` (restores the entire live ADOM DB in one call) and `revert_device_revision` (rewrites a device's entire stored config from a revision) unless the caller also passes `confirm=True`.

```bash
FMG_REVERT_SAFETY=strict    # Default: refuse without confirm=True
FMG_REVERT_SAFETY=disabled  # Allow unconditionally
```

#### Firmware Upgrade Safety (`FMG_FIRMWARE_SAFETY`)

Blocks `upgrade_device_firmware` (reboots the real managed device) unless the caller also passes `confirm=True`.

```bash
FMG_FIRMWARE_SAFETY=strict    # Default: refuse without confirm=True
FMG_FIRMWARE_SAFETY=disabled  # Allow unconditionally
```

#### Security Profile Field Validation

`create_firewall_policy` and `update_firewall_policy` validate security-profile
(UTM) field combinations before sending the payload to FortiManager, so an
invalid combination fails with a clear message instead of an opaque FMG error
code. This check always runs (no environment toggle):

- `profile_group` is mutually exclusive with `av_profile`, `ips_sensor`,
  `webfilter_profile`, `dnsfilter_profile`, `application_list`,
  `file_filter_profile`, `ssl_ssh_profile`, and `profile_protocol_options` --
  FortiOS rejects a policy that sets both a security-profile group and any
  individual profile it bundles. `profile_protocol_options` is itself a
  member of the `firewall profile-group` object, so it is part of this
  exclusion set too.
- Setting any of the fields above together with `utm_status=False` in the
  same call is rejected -- FortiOS ignores security profiles when
  `utm-status` is disabled, so the combination is almost certainly a mistake.

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
