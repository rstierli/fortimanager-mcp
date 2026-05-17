# Changelog

All notable changes to FortiManager MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.2-beta] - 2026-05-17

### Fixed
- **Script `target` field mapping for FMG 7.6+ endpoint** ([#3](https://github.com/rstierli/fortimanager-mcp/issues/3)): the new `/pm/config/.../obj/fmg/script` endpoint stores `target` as an integer, but the client was passing the documented strings (`device_database`, `adom_database`, `remote_device`). FMG silently coerced unknown values to `0`, causing scripts intended for remote devices or ADOM database to land on the wrong target. The client now maps strings ↔ ints transparently. Verified live against FMG 7.6.6.
- **`list_scripts` target filter mapping** ([#7](https://github.com/rstierli/fortimanager-mcp/issues/7)): the same string-vs-int mismatch broke filter expressions like `["target", "==", "remote_device"]` on FMG 7.6+. Filter walker now handles both the binary triplet form and the multi-value `in`/`!in` flat-list form (`["target", "in", v1, v2, ...]`). Operator-aware: only documented FMG comparison operators trigger value mapping.

### Changed
- Cleared mypy strict-mode baseline: 75 errors → 0. Seven real type bugs fixed (filter signatures, `_get_client` return annotations across tool modules, list element type, pydantic-settings false positive). The 68 pyfmg SDK passthrough errors are silenced via a documented per-module override; all other strict checks remain active.
- Bumped GitHub Actions to Node 24 majors ahead of the June 2, 2026 forced cutover.

## [1.2.1-beta] - 2026-04-23

### Fixed
- Consolidated duplicate `parse_fmg_error` — removed simple version from client.py, now uses the comprehensive version from errors.py

### Added
- Usage disclaimer in README

## [1.2.0-beta] - 2026-04-23

### Added
- **`get_policy_services` tool** — Retrieve services configured on a firewall policy with optional group resolution. Enables automated policy hardening workflows by comparing actual traffic (from FortiAnalyzer) against configured services.

### Security
- **Script content safety** (`FMG_SCRIPT_SAFETY`) — Blocks dangerous CLI commands (`execute factory-reset`, `reboot`, `shutdown`, `format`, `erase-disk`) in `create_script` and `update_script`. Enabled by default (`strict`), set to `disabled` to override.
- **Policy permissiveness safety** (`FMG_POLICY_SAFETY`) — Blocks overly permissive firewall policies (srcaddr=all + dstaddr=all + action=accept) in `create_firewall_policy` and `update_firewall_policy`. Modes: `strict` (default, blocks), `warn` (allows with warning), `disabled`.
- Both safety guardrails are **strict by default** — require explicit env var override to disable.
- 40 new tests covering all safety validation and tool integration.

## [0.1.0-beta] - 2026-01-17

### Added
- **Unit tests expanded** - 213 tests covering errors, validation, and tool modules
- **Version-aware script endpoints** - Automatically selects correct API endpoint based on FMG version (7.6+ uses `/pm/config`, 7.0-7.4 uses `/dvmdb`)

### Fixed
- Import sorting in test files (ruff compliance)
- E402 linting errors for post-dotenv imports

### Technical
- All CI checks passing
- Integration tests verified against FMG 7.6.2

## [0.1.0-alpha] - 2025-01-15

### Added
- Initial release with 101 MCP tools
- **System Tools** (17 tools)
  - `get_system_status`, `get_ha_status`
  - `list_adoms`, `get_adom`
  - `list_devices`, `get_device`, `search_devices`
  - `list_tasks`, `get_task`, `get_task_line`
  - `list_packages`, `get_package`
  - Workspace operations: `lock_adom`, `unlock_adom`, `commit_changes`
- **Device Management Tools** (12 tools)
  - `list_device_vdoms`, `list_device_groups`
  - `add_device`, `delete_device`
  - `add_device_list`, `delete_device_list`
  - `update_device`, `reload_device_list`
  - `get_device_status`
- **Policy Tools** (14 tools)
  - `list_firewall_policies`, `get_firewall_policy`, `get_firewall_policy_count`
  - `create_firewall_policy`, `update_firewall_policy`, `delete_firewall_policy`
  - `delete_firewall_policies`, `move_firewall_policy`
  - `install_package`, `get_install_preview`, `check_install_status`
  - `get_policy_package`, `clone_policy_package`
- **Object Tools** (24 tools)
  - Address objects: `list_addresses`, `get_address`, `create_address`, `update_address`, `delete_address`
  - Address groups: `list_address_groups`, `get_address_group`, `create_address_group`, `update_address_group`, `delete_address_group`
  - Services: `list_services`, `get_service`, `create_service`, `update_service`, `delete_service`
  - Service groups: `list_service_groups`, `get_service_group`, `create_service_group`, `delete_service_group`
  - Search: `search_objects`
- **Script Tools** (12 tools)
  - `list_scripts`, `get_script`, `create_script`, `update_script`, `delete_script`
  - `run_script`, `run_script_on_device`, `run_script_on_devices`
  - `get_script_log`, `get_script_logs`
- **Template Tools** (15 tools)
  - Provisioning templates, system templates (devprof)
  - Template groups, CLI template groups
  - Assignment and validation operations
- **SD-WAN Tools** (7 tools)
  - `list_sdwan_templates`, `get_sdwan_template`
  - `create_sdwan_template`, `delete_sdwan_template`
  - `assign_sdwan_template`, `assign_sdwan_template_bulk`, `unassign_sdwan_template`

### Features
- Support for FortiManager 7.0.x, 7.2.x, 7.4.x, 7.6.x
- API Token authentication (recommended) and username/password support
- Full mode (all 101 tools) and Dynamic mode (discovery tools only)
- Docker deployment support
- Claude Desktop integration via stdio transport
- Comprehensive debug logging (configurable)

### Technical
- Built on FastMCP framework
- Uses upstream pyfmg library (`p4r4n0y1ng/pyfmg`)
- Async/await throughout for efficient resource utilization
- Type hints with Pydantic validation
- Comprehensive error handling with FortiManager-specific error codes
- 45 unit tests with mock fixtures

### Fixed
- **Move operation** - Now uses correct MOVE method and endpoint (`/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{id}`)
- **pyfmg parameter handling** - Pass move params as dict in args, not kwargs (kwargs get nested in `data` key)

## [0.0.1] - 2025-01-11

### Added
- Initial project structure (based on fortianalyzer-mcp template)
- Basic API client implementation
- Core tool modules
- GitHub Actions CI workflow
