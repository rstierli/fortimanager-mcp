#!/bin/sh
# NCP LocalMCP entrypoint. SSE on :8001 /mcp/sse for aviz-shared-network.
set -eu

export LOCAL_MCP_MODE="${LOCAL_MCP_MODE:-true}"
export MCP_SERVER_MODE="${MCP_SERVER_MODE:-http}"
export MCP_SERVER_HOST="${MCP_SERVER_HOST:-0.0.0.0}"
export MCP_SERVER_PORT="${MCP_SERVER_PORT:-${MCP_PORT:-8001}}"
export MCP_PORT="${MCP_PORT:-${MCP_SERVER_PORT}}"

echo "LocalMCP: starting fortimanager-mcp on ${MCP_SERVER_HOST}:${MCP_SERVER_PORT} (sse /mcp/sse)"
exec python -m fortimanager_mcp
