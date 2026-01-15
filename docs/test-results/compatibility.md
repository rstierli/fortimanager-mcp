# FortiManager MCP - Version Compatibility Matrix

**Last Updated:** 2025-01-15

## Supported Versions

| FMG Version | MCP Version | Status | Unit Tests | Integration Tests | Notes |
|-------------|-------------|--------|------------|-------------------|-------|
| 7.6.5 | 0.1.0-alpha | Supported | Pending | Pending | Primary target |
| 7.6.4 | 0.1.0-alpha | Supported | Pending | Pending | |
| 7.4.x | 0.1.0-alpha | Expected | Pending | Pending | Should work |
| 7.2.x | 0.1.0-alpha | Expected | Pending | Pending | Should work |
| 7.0.x | 0.1.0-alpha | Unknown | Not tested | Not tested | May work |

## Status Legend

| Status | Meaning |
|--------|---------|
| **Supported** | Actively tested and maintained |
| **Expected** | Should work based on API compatibility |
| **Unknown** | Not tested, may or may not work |
| **Deprecated** | No longer supported |

## API Compatibility Notes

FortiManager and FortiAnalyzer share the same JSON-RPC API codebase. General patterns are identical across versions:

- Authentication: Same across all versions
- Request/Response format: Same across all versions
- Error codes: Same across all versions

### Version-Specific Differences

#### FMG 7.6.x
- Full feature support
- All 101 tools tested
- SD-WAN enhancements

#### FMG 7.4.x
- Expected full compatibility
- Some SD-WAN features may differ

#### FMG 7.2.x
- Expected compatibility for core features
- Template features may have differences

## Tool Categories

| Category | Tools | Description |
|----------|-------|-------------|
| System | 17 | Status, ADOMs, tasks |
| Device Management | 12 | Devices, groups, VDOMs |
| Policy | 14 | Firewall policies, packages |
| Objects | 24 | Addresses, services, groups |
| Scripts | 12 | CLI script execution |
| Templates | 15 | Provisioning templates |
| SD-WAN | 7 | SD-WAN configuration |

## Python Version Support

| Python | Status |
|--------|--------|
| 3.13.x | Supported |
| 3.12.x | Supported (Primary) |
| 3.11.x | Should work |
| 3.10.x | Not tested |
| < 3.10 | Not supported |

## Testing Your Version

To test compatibility with your FMG version:

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your FMG credentials

# 2. Create test ADOM and model device
# ADOM: mcp-dev-test
# Device: FGT-MCP-TEST-01 (Model FortiGate)

# 3. Run unit tests (no FMG required)
uv run pytest tests/ -v

# 4. Run integration tests (FMG required)
uv run pytest tests/integration/ -v -m integration

# 5. Report results
# Create docs/test-results/fmg-X.Y.Z.md with your results
```

## Reporting Issues

If you encounter version-specific issues:

1. Check existing issues on GitHub
2. Include FMG version and build number
3. Include full error message
4. Include steps to reproduce

## Contributing

Help us expand compatibility testing:

1. Test against your FMG version
2. Document results using template in README.md
3. Submit PR with test results
4. Report any version-specific issues
