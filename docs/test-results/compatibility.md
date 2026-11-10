# FortiManager MCP - Version Compatibility Matrix

**Last Updated:** 2026-11-10

## Supported Versions

| FMG Version | Status | Tested | Notes |
|-------------|--------|--------|-------|
| 8.0.2 | Supported | Every release since 1.12.1 | Primary development target |
| 8.0.0, 8.0.1 | Expected | No | The install preview is task-based (see below). The 8.0.0 FNDN reference is bundled in `docs/fndn/8.0.0`. |
| 7.6.7 | Supported | Releases up to 1.12.0 | |
| 7.6.0 - 7.6.6 | Expected | No | The install preview is task-based (see below) |
| 7.4.x | Expected | No | Built against the bundled 7.4.8 FNDN reference |
| 7.2.x | Expected | No | Built against the bundled 7.2.11 FNDN reference |
| 7.0.x | Expected | No | No reference bundled |

"Tested" means the release gate: unit tests plus the live integration suite (`pytest tests/`), `tests/integration/test_real_fmg.py`, the Docker image smoke tests and a secret leak sweep, all against a lab FortiManager with managed FortiGates.

## Status Legend

| Status | Meaning |
|--------|---------|
| **Supported** | Tested live and maintained |
| **Expected** | Should work based on the API reference, not tested live |
| **Unknown** | Not tested, may or may not work |
| **Deprecated** | No longer supported |

## Version-Specific Differences

The server detects the FortiManager version once per connection (`/sys/status`) and adapts where the API differs:

| Feature | Behaviour |
|---------|-----------|
| CLI scripts | 7.6 and later use `/pm/config/adom/{adom}/obj/fmg/script`; earlier versions use `/dvmdb/adom/{adom}/script`. 8.0.2 no longer serves the `/dvmdb` path. |
| Install preview | 7.6.7+ and 8.0.2+ run the staged preview (`preview_taskid`) and return the diff in one call. Earlier versions, including 8.0.0 and 8.0.1, start a preview task: run `wait_for_task`, then `get_preview_result`. |
| FortiManager backup | 7.0.11+, 7.2.5+ and 7.4.2+ refuse an unencrypted backup: `trigger_fmg_backup` needs `passwd`. |

Several endpoints are not in the bundled FNDN references and were verified on FortiManager 8.0.2 only. They include firmware templates (`/pm/fwmprof`), BGP template neighbor groups, metadata-variable writes, `add_model_device` with `meta_variables`, and the tools added in 1.13.0. Their docstrings say so. On 7.x they are expected to work, but they are untested there.

## Python Version Support

| Python | Status |
|--------|--------|
| 3.13.x | Supported (CI) |
| 3.12.x | Supported (CI, primary) |
| < 3.12 | Not supported (`requires-python = ">=3.12"`) |

## Testing Your Version

To test compatibility with your FMG version:

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your FMG credentials

# 2. Create test ADOM and model device
# ADOM: mcp-dev-test
# Device: FGT-MCP-TEST-01 (Model FortiGate)

# 3. Run unit and live integration tests (FMG required for the live part)
uv run pytest tests/ -v

# 4. Run the read-only live check script
uv run python tests/integration/test_real_fmg.py

# 5. Report results
# Open an issue or PR with your FMG version, build and the test output
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
2. Share the results in an issue or PR
3. Report any version-specific issues
