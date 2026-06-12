# Changelog

All notable changes to FortiManager MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-06-11

Fail closed: the streamable-HTTP transport now refuses to start without `MCP_AUTH_TOKEN` unless the operator explicitly opts out with `MCP_ALLOW_NO_AUTH=true`. Forward-port of [fortianalyzer-mcp#25](https://github.com/rstierli/fortianalyzer-mcp/pull/25); completes bundle B of [#11](https://github.com/rstierli/fortimanager-mcp/issues/11). 428 unit tests pass.

### Changed
- **The HTTP transport now fails closed when `MCP_AUTH_TOKEN` is unset.** The streamable-HTTP server fronts the full tool surface (including device add/delete, policy install, and script execution on managed devices), so it previously could serve everything unauthenticated if the token was simply forgotten. `run_http()` now refuses to start without a token and exits with a message that names the fix, unless the operator explicitly opts out with `MCP_ALLOW_NO_AUTH=true` (logged at CRITICAL; intended only for a trusted, isolated bind such as 127.0.0.1 behind a gateway). **Upgrade note:** a deployment that ran on a `0.0.0.0` bind without a token must now set either `MCP_AUTH_TOKEN` or `MCP_ALLOW_NO_AUTH=true` to keep starting.

### Added
- `MCP_ALLOW_NO_AUTH` setting (default `false`) — the explicit opt-out for running HTTP without a token. 4 tests cover token-set start, no-token fail-closed, empty-token fail-closed, and the explicit opt-out.

## [1.4.1] - 2026-06-12

Three bugs found and fixed by live verification against a lab FortiManager 7.6.7 (v7.6.7-build3737). 388 unit tests pass.

### Fixed
- **Script target enum was swapped on the FMG 7.6+ endpoint** — every `execute_script_on_package` call failed with `-8 Invalid parameter`. `_SCRIPT_TARGET_MAP` had `adom_database=1 / remote_device=2`; verified by execution (a create+get round-trip cannot detect a swap because the mapping is symmetric): a `target=2` script executes against a policy package and spawns a task, a `target=1` script accepts a device-scoped execute. Correct map: `device_database=0, remote_device=1, adom_database=2`. Scripts created through the MCP with `target="adom_database"` were actually stored as remote-device scripts and vice versa.
- **`add_model_device` omitted the `mr` field** — every model-device add failed with `Unsupported device/ADOM version`. FMG expects the major version in `os_ver` (`"7.0"`) and the minor in a separate `mr` integer. The tool now splits `os_version` "X.Y" into `os_ver="X.0"` + `mr=Y` (verified live: device lands as FortiOS 7.6).
- **FMG error-code table corrected to live-verified semantics.** The previous table mislabeled most codes: `-2` is "Object already exists" (was: invalid session — a duplicate create triggered a spurious re-login + retry), `-3` is "Object does not exist" (was: permission denied), `-8` is "Invalid parameter" (was: ADOM locked), `-10` is "data invalid for selected URL" (was: version mismatch), and `-11` is "no permission / **stale session**" (was: task timeout, retried twice with the same dead session). Newly mapped: `-22` login fail, `-10147` no write permission, `-20055` workspace locked by another admin. Consequences: `_RECONNECTABLE_ERROR_CODES` is now `{-11}` — the reconnect-once path (#14/#16) now actually triggers on the code the FMG emits for a stale session — and `_TRANSIENT_ERROR_CODES` is `{-1}`.

## [1.4.0] - 2026-06-10

Hardening pass: ports the FortiAnalyzer MCP's resilience and observability patterns (PRs [fortianalyzer-mcp#17](https://github.com/rstierli/fortianalyzer-mcp/pull/17), [#18](https://github.com/rstierli/fortianalyzer-mcp/pull/18), [#22](https://github.com/rstierli/fortianalyzer-mcp/issues/22) by Christian Dassy / [@inxbit](https://github.com/inxbit)) over to FortiManager. Tracked in #11. 424 unit tests pass.

### Added
- **Shared error envelope + secret redactor** ([#12](https://github.com/rstierli/fortimanager-mcp/pull/12)). New `utils/responses.py` provides `error_response(error, message, operation, ...)` — one structured envelope used by every tool error path with stable machine code, redacted + length-bounded human text, optional `adom`/`package`/`device`/`task_id` fields included only when supplied. `redact()` scrubs `key=value` / `key: value` pairs whose key matches `SENSITIVE_FIELDS` (excluding the generic words `key`/`auth`/`pass` to avoid mangling policy names) and masks long hex token-like runs. Tool wiring to use the envelope ships in a follow-up.
- **`FORTIMANAGER_VERIFY_SSL=false` connect-time warning** ([#13](https://github.com/rstierli/fortimanager-mcp/pull/13)). When SSL verification is disabled, a single `logger.warning` at connect time names the host, mentions the env var by name, and nudges toward importing the FortiManager CA into the system trust store. Default remains `True` (v1.3.0 stability); anyone hitting this warning has explicitly opted into insecure.
- **`async ensure_connected()` + serialized reconnect-once foundation** ([#14](https://github.com/rstierli/fortimanager-mcp/pull/14)). Tools call `await client.ensure_connected()` before requests so idle-closed sessions are transparently revived instead of surfacing raw "Not connected" errors. `_force_reconnect()` is serialized via `asyncio.Lock` + generation counter so concurrent dropped-session callers only re-log in **once**; the rest observe the bumped generation and bail out.
- **Bounded transient-retry wrapper wired through every API method** ([#16](https://github.com/rstierli/fortimanager-mcp/pull/16)). New `_execute_resilient()` runs each request with reconnect-once on session error (auth, codes `-2`/`-20`/`-21`, raw "Not connected" when previously connected) and bounded transient retry on `OSError` or codes `-1`/`-11` with exponential backoff (`0.5s`, `1.0s`). Annotates raised exceptions with `.retries_attempted` so `error_response()` surfaces `retry_count`. Every typed wrapper (101 tools) picks up the resilience without per-method changes.

### Changed
- **Server lifecycle ownership consolidated** ([#15](https://github.com/rstierli/fortimanager-mcp/pull/15)). Dropped the top-level `lifespan()` and the `lifespan=lifespan` kwarg on `mcp = FastMCP(...)`. With `FastMCP`'s `stateless_http=True` shape that lifespan was running per request/session, connect-then-disconnect cycling the global `_fmg_client` around every call and dropping the session under concurrent requests. Lifecycle ownership now lives in exactly two paths: `run_http()` → `app_lifespan` (HTTP mode, already existed and was already correct) and a new `run_stdio()` → `stdio_main` (stdio mode). HTTP user-visible behavior is unchanged; the per-request lifespan that was running redundantly alongside `app_lifespan` is now gone.
- **Transient FMG errors are silently retried before surfacing.** Callers see slightly longer wait on a transient failure (up to ~1.5s of backoff) in exchange for the failure not happening at all most of the time. Validation, permission, not-found, and ADOM-locked errors remain surfaced immediately — these aren't transient and retrying them would be wrong.

## [1.3.0] - 2026-05-29

First stable release — graduated from beta.

### Security
- **Input validation enforced at tool boundaries** ([#10](https://github.com/rstierli/fortimanager-mcp/issues/10)): identifier parameters (`adom`, `device`, object/policy/package/template/script names) are now validated before being interpolated into API request paths, closing a path-injection vector. Object and policy name patterns permit parentheses and colons (e.g. cloned `addr (1)`, `grp:prod`); path separators, shell metacharacters, and quotes are rejected.
- **Stored scripts re-validated in the execute path** ([#10](https://github.com/rstierli/fortimanager-mcp/issues/10)): `execute_script_on_device/devices/group/package` now re-check the resolved script body against the safety denylist (previously only `create_script`/`update_script` were checked, so a script created with safety disabled or pre-existing on the FMG could execute unguarded). The denylist is broadened beyond destructive exec commands to cover backdoor-admin creation (`config system admin`), permissive firewall actions (`set action accept`), disabling logging (`set status disable`), and DNS/route changes — with whitespace normalization to prevent spacing/case bypass.
- **API error bodies sanitized** ([#10](https://github.com/rstierli/fortimanager-mcp/issues/10)): tool errors now return a generic message plus an error code instead of the raw FortiManager error text, preventing internal endpoint paths from leaking to the caller. Full detail is still logged server-side.
- **Pinned `pyfmg` dependency** ([#10](https://github.com/rstierli/fortimanager-mcp/issues/10)) to a specific commit instead of a floating fork reference.

### Changed
- **Stability promotion:** no functional changes beyond the security hardening above. TLS guidance now recommends importing the FortiManager CA certificate; `FORTIMANAGER_VERIFY_SSL=false` is documented only as a warned last resort, and shipped example configs default to verification enabled.

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
