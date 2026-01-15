# FortiManager MCP Server - Setup Guide

This guide explains how to set up and use the FortiManager MCP server with Claude Desktop, Claude Code, and other MCP clients.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [MCP Client Setup](#mcp-client-setup)
5. [Docker Deployment](#docker-deployment)
6. [Testing without Claude](#testing-without-claude)
7. [Available Tools](#available-tools)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Python 3.12+** installed
- **FortiManager** instance (7.0.x, 7.2.x, 7.4.x, 7.6.x supported)
- **FortiManager API credentials** (API token recommended, or username/password)
- **Claude Desktop** or **Claude Code** (optional - can run standalone)

### FortiManager API Token Setup

1. Log in to FortiManager GUI as admin
2. Navigate to **System Settings** → **Admin** → **Administrators**
3. Edit your admin user or create a new API user
4. Enable **JSON API Access**
5. Generate an **API Key** (recommended over password auth)
6. Copy the API key - you'll need it for configuration

---

## Installation

### Option 1: Using uv (Recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package manager:

```bash
# Install uv (macOS/Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/rstierli/fortimanager-mcp.git
cd fortimanager-mcp

uv venv
source .venv/bin/activate
uv sync --all-extras
```

### Option 2: Using pip

```bash
git clone https://github.com/rstierli/fortimanager-mcp.git
cd fortimanager-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Configuration

The MCP server is configured via environment variables:

### Required Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `FORTIMANAGER_HOST` | FortiManager hostname/IP | `fmg.example.com` |
| `FORTIMANAGER_API_TOKEN` | API token (recommended) | `your-api-token` |

### Optional Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `FORTIMANAGER_USERNAME` | Username (if not using token) | - |
| `FORTIMANAGER_PASSWORD` | Password (if not using token) | - |
| `FORTIMANAGER_VERIFY_SSL` | Verify SSL certificates | `true` |
| `FORTIMANAGER_TIMEOUT` | Request timeout (seconds) | `30` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `FMG_TOOL_MODE` | Tool loading mode (`full`/`dynamic`) | `full` |

### Example .env File

```bash
# FortiManager Connection
FORTIMANAGER_HOST=your-fmg-hostname
FORTIMANAGER_API_TOKEN=your-api-token-here
FORTIMANAGER_VERIFY_SSL=false

# Logging
LOG_LEVEL=INFO

# Tool mode: "full" (all 101 tools) or "dynamic" (discovery only)
FMG_TOOL_MODE=full
```

---

## MCP Client Setup

MCP (Model Context Protocol) is supported by multiple AI platforms. Choose your preferred client:

### Claude Desktop

Edit `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "fortimanager": {
      "command": "/path/to/fortimanager-mcp/.venv/bin/fortimanager-mcp",
      "env": {
        "FORTIMANAGER_HOST": "your-fmg-hostname",
        "FORTIMANAGER_API_TOKEN": "your-api-token-here",
        "FORTIMANAGER_VERIFY_SSL": "false",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

Restart Claude Desktop after saving.

### Claude Code (CLI)

```bash
# Install Claude Code
npm install -g @anthropic-ai/claude-code

# Add the MCP server
claude mcp add fortimanager -s user \
  -e FORTIMANAGER_HOST=your-fmg-hostname \
  -e FORTIMANAGER_API_TOKEN=your-api-token \
  -e FORTIMANAGER_VERIFY_SSL=false \
  -- /path/to/fortimanager-mcp/.venv/bin/fortimanager-mcp

# Verify connection
claude mcp list
```

### Perplexity (Mac App)

1. Install the **PerplexityXPC** helper app (required for local MCP)
2. Open Perplexity Settings → MCP Connectors
3. Add a new local MCP server:

```json
{
  "fortimanager": {
    "type": "stdio",
    "command": "/path/to/fortimanager-mcp/.venv/bin/fortimanager-mcp",
    "env": {
      "FORTIMANAGER_HOST": "your-fmg-hostname",
      "FORTIMANAGER_API_TOKEN": "your-api-token",
      "FORTIMANAGER_VERIFY_SSL": "false"
    }
  }
}
```

### Other MCP-Compatible Clients

MCP is now widely supported across AI platforms:

| Client | MCP Support | Notes |
|--------|-------------|-------|
| **Claude Desktop** | ✓ Native | Full support via config file |
| **Claude Code** | ✓ Native | CLI-based, `claude mcp add` |
| **Perplexity** | ✓ Native | Mac app with PerplexityXPC |
| **ChatGPT** | ✓ | Via plugins/actions |
| **Google Gemini** | ✓ | Via extensions |
| **VS Code Copilot** | ✓ | Via MCP extension |
| **Cursor** | ✓ | Native MCP support |

For other clients, use the standard stdio MCP configuration format shown above.

---

## Docker Deployment

Docker allows you to run the MCP server without installing Python dependencies locally.

### Quick Start with Docker Compose

1. Create a `.env` file:
```bash
FORTIMANAGER_HOST=your-fmg-hostname
FORTIMANAGER_API_TOKEN=your-api-token
FORTIMANAGER_VERIFY_SSL=false
LOG_LEVEL=INFO
```

2. Run the container:
```bash
docker-compose up -d
```

3. Check logs:
```bash
docker-compose logs -f
```

### Docker Build & Run (Manual)

```bash
# Build the image
docker build -t fortimanager-mcp .

# Run the container
docker run -d \
  --name fortimanager-mcp \
  -e FORTIMANAGER_HOST=your-fmg-hostname \
  -e FORTIMANAGER_API_TOKEN=your-api-token \
  -e FORTIMANAGER_VERIFY_SSL=false \
  -p 8000:8000 \
  fortimanager-mcp
```

---

## Testing without Claude

You can test the MCP server and FortiManager connection without Claude Desktop.

### Option 1: Direct Python Testing

```bash
cd fortimanager-mcp
source .venv/bin/activate

# Set environment variables
export FORTIMANAGER_HOST="your-fmg-hostname"
export FORTIMANAGER_API_TOKEN="your-api-token"
export FORTIMANAGER_VERIFY_SSL="false"

# Test connection and basic operations
python3 -c "
import asyncio
from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils.config import Settings

async def test():
    settings = Settings()
    client = FortiManagerClient.from_settings(settings)
    await client.connect()

    # Test: Get system status
    status = await client.get_system_status()
    print('System Status:', status)

    # Test: List ADOMs
    adoms = await client.list_adoms()
    print('ADOMs:', [a['name'] for a in adoms])

    # Test: List devices in root ADOM
    devices = await client.list_devices('root')
    print('Devices:', [d['name'] for d in devices])

    await client.disconnect()

asyncio.run(test())
"
```

### Option 2: Run Unit Tests

```bash
cd fortimanager-mcp
source .venv/bin/activate

# Run unit tests (no real FMG needed - uses mocks)
pytest tests/ -v

# Run with coverage
pytest --cov=src/fortimanager_mcp --cov-report=html
```

### Option 3: Interactive Python Shell

```bash
cd fortimanager-mcp
source .venv/bin/activate
export FORTIMANAGER_HOST="your-fmg-hostname"
export FORTIMANAGER_API_TOKEN="your-api-token"
export FORTIMANAGER_VERIFY_SSL="false"

python3
```

```python
import asyncio
from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils.config import Settings

settings = Settings()
client = FortiManagerClient.from_settings(settings)

# Connect
asyncio.run(client.connect())

# Try operations
asyncio.run(client.get_system_status())
asyncio.run(client.list_adoms())
asyncio.run(client.list_firewall_policies('your-adom', 'your-package'))

# Disconnect
asyncio.run(client.disconnect())
```

---

## Available Tools

The MCP server provides **101 tools** across 7 categories:

| Category | Tools | Description |
|----------|-------|-------------|
| System | 17 | Status, ADOMs, devices, tasks, packages, workspace |
| Device Management | 12 | Add/delete devices, VDOMs, groups, status |
| Policy | 14 | Firewall policies, packages, install, preview |
| Objects | 24 | Addresses, services, groups, search |
| Scripts | 12 | CLI scripts, execution, logs |
| Templates | 15 | Provisioning, system templates, groups |
| SD-WAN | 7 | SD-WAN templates, assignment |

### Key Policy Tools

- `list_firewall_policies` - List policies in a package
- `create_firewall_policy` - Create new policy
- `update_firewall_policy` - Modify existing policy
- `move_firewall_policy` - Reorder policy (before/after)
- `delete_firewall_policy` - Remove policy
- `install_package` - Deploy changes to FortiGate

---

## Troubleshooting

### Connection Issues

1. **Verify FortiManager is reachable**:
```bash
curl -k https://your-fmg-hostname/jsonrpc
```

2. **Check API token permissions**: Ensure JSON API Access is enabled

3. **SSL Errors**: Set `FORTIMANAGER_VERIFY_SSL=false` for self-signed certs

### Authentication Errors

- API Token must have JSON API access enabled in FortiManager
- If using username/password, ensure the user has API permissions

### Server Won't Start

1. Check Python version: `python3 --version` (needs 3.12+)
2. Verify virtual environment is activated: `which python`
3. Check environment variables are set correctly

---

## Support

For issues or questions:
- Open an issue on [GitHub](https://github.com/rstierli/fortimanager-mcp/issues)
- Review test files in `tests/` for usage examples
- Check FortiManager API documentation (FNDN) from Fortinet Developer Network
