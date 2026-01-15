# Test Results Documentation

This directory contains test results from unit tests and integration tests against real FortiManager instances.

## Purpose

- Track which FMG versions have been tested
- Document known issues per version
- Provide compatibility matrix for users
- Record integration test coverage

## Structure

```
test-results/
├── README.md                 # This file
├── compatibility.md          # Version compatibility matrix
├── fmg-7.6.5.md             # Test results for FMG 7.6.5
├── fmg-7.6.4.md             # Test results for FMG 7.6.4
├── fmg-7.4.x.md             # Test results for FMG 7.4.x
└── fmg-7.2.x.md             # Test results for FMG 7.2.x
```

## Test Categories

### Unit Tests
- Run without real FMG connection
- Test code logic, parsing, error handling
- Command: `pytest tests/ -m "not integration"`

### Integration Tests
- Require real FMG connection
- Test actual API calls and responses
- Command: `pytest tests/integration/ -m integration`

## How to Run Tests

```bash
# All unit tests
uv run pytest tests/ -v --tb=short

# Integration tests (requires .env with FMG credentials)
uv run pytest tests/integration/ -v -m integration

# Generate coverage report
uv run pytest tests/ --cov=src/fortimanager_mcp --cov-report=html
```

## Test ADOM Setup

For safe integration testing, create a dedicated test environment:

1. **Create Test ADOM**: `mcp-dev-test`
2. **Create Model Device**: `FGT-MCP-TEST-01`
   - Model devices behave like real devices
   - Safe for policy testing without affecting production

## Contributing Test Results

When testing against a new FMG version:

1. Create a new file: `fmg-X.Y.Z.md`
2. Use the template below
3. Run full test suite
4. Document any failures or issues
5. Submit PR with results

## Template for Version Results

```markdown
# FortiManager X.Y.Z Test Results

**Test Date:** YYYY-MM-DD
**Tester:** Name
**MCP Version:** X.Y.Z

## Environment
- FMG Version: X.Y.Z
- FMG Build: XXXX
- Test ADOM: mcp-dev-test
- Test Device: FGT-MCP-TEST-01 (Model)
- Python Version: 3.12.x

## Unit Test Results
- Total: XX tests
- Passed: XX
- Failed: XX
- Skipped: XX

## Integration Test Results

| Category | Tests | Passed | Failed | Notes |
|----------|-------|--------|--------|-------|
| System | X | X | X | |
| Device Mgmt | X | X | X | |
| Policy | X | X | X | |
| Objects | X | X | X | |
| Templates | X | X | X | |
| Scripts | X | X | X | |
| SD-WAN | X | X | X | |

## Known Issues
- Issue 1: Description
- Issue 2: Description

## Notes
Additional observations or recommendations.
```
