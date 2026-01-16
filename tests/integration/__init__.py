"""Integration tests for FortiManager MCP server.

These tests require a real FortiManager instance.

Environment Variables:
- FORTIMANAGER_HOST: FortiManager hostname/IP
- FORTIMANAGER_USERNAME / FORTIMANAGER_PASSWORD (or FORTIMANAGER_API_TOKEN)
- TEST_ADOM: Test ADOM name (default: mcp-dev-test)
- TEST_DEVICE: Test device name (default: FGT-MCP-TEST-01)

Run with: pytest tests/integration -v -m integration
"""
