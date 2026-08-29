# Changelog

All notable changes to FortiManager MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **The model-device echo strips credentials too (#60, closes #53).** #51 covered the four read paths and the two `add_device` echoes, but `add_model_device` echoed the FortiManager-returned object unstripped, so the same stored admin password came back on a path the earlier fix had not enumerated. It now routes through the same shared helper as the rest, and the test asserts membership of the set of credential-returning tools rather than naming them one at a time, so a new device-creating tool cannot quietly reopen this.

### Added

- **Reversible data masking (FPE), ported from the FortiAnalyzer layer (#39, closes #34).** With `MASKING_ENABLED=true` and a key, IOC-bearing values (device and management IPs, subnets, IP ranges, serials, FQDNs, admin usernames) are replaced by reversible, deterministic tokens, so a model can still correlate a value across calls without holding the value. Tokens are also refused as inputs, at any depth and inside free text, before the tool body runs. Off by default, and enabling it without a valid key aborts startup rather than running unmasked. Object, ADOM and package names are deliberately never masked, because they route follow-up calls.
- **The ten highest-priority missing tool groups (#65).** Security-profile object CRUD (AV, web filter, DNS filter, application control, IPS sensor including signature overrides, SSL/SSH inspection, DLP, WAF), which closes the gap where firewall policies could reference a profile by name that nothing in this server could create; IPsec phase1/phase2-interface CRUD and SSL-VPN settings plus web portal; device-group create/delete, member add/remove and nesting; revision history (list, get, diff, revert) for device DB, ADOM DB and firewall-policy history; firmware upgrade path, catalog, trigger and report; an object-usage graph for where-used and duplicate detection; FortiManager appliance operations (backup/restore, packet capture, license, task cleanup); and local-in policy CRUD for management-plane access control in both address families.
- **`firewall.sniffer` and `firewall.on-demand-sniffer` device-DB tools (#77).** Two separate FortiOS cmdb tables that happen to share a word, confirmed against the 7.6.7 Configuration API spec: the first is ID-keyed and runs continuously while `status=enable`, the second is name-keyed and bounded by `max_packet_count`, which exists only on that table. Neither is FortiManager's own local diagnostic sniffer, which the existing appliance packet-capture tools still target. Both stage into the device DB only; nothing reaches the device until `install_device_settings`.
- **A 6 GHz radio is guarded against a VAP whose security mode cannot work there (#62, follow-up to #47).** The guard keys off the **band, not the radio index**, because the index does not determine the band: the schema offers the 6 GHz bands on every index, so an index-keyed guard would refuse a legal WPA2 SSID on an AP whose radio 3 happens to be 5 GHz. The refuse tier holds only what the review attested, that 6 GHz is WPA3-only and anything else is rejected at install time. It is deliberately narrower than first offered: writing the full table of what a 6 GHz radio accepts would mean writing down what could not be measured here, so the remainder warns rather than refuses.

### Fixed

- **Two tools existed but dynamic mode could neither discover nor dispatch them (#61, closes #58).** `get_policy_services` and `update_service_group` were missing from the hand-written catalog and the per-module dispatch allowlist, which is how they survived several releases unreachable. The fix that matters is the test: it parses the `@mcp.tool()`-decorated functions out of the tool modules and both literals out of `server.py` and asserts they agree, so the class is closed rather than the two instances.
- **FortiAP-U and FortiAP-S serial prefixes are accepted (#63, closes #56 part 2).** The validator recognised only the base prefix, so two shipping hardware families were refused by name.
- **wtp-profile radio writes were rejected outright, and a wide 6 GHz channel was silently written wrong (#64).** The read-modify-write echo carried back read-only bookkeeping keys the API injects on GET, which made FortiManager reject the whole request on **every** radio rather than in a specific case. Separately, FortiOS stores a wide 6 GHz channel as the full list of its member 20 MHz sub-channels, while the device-DB write accepts a single-element list without complaint, so pinning a wide channel by its label produced a silent misconfiguration rather than a loud failure. A single wide-channel label is now expanded to the correct member list above 20 MHz bonding, an explicit member list passes through, and a label that lines up with no valid member set is rejected.
- **The policy safety gate normalizes inside itself, and what it is fed is pinned (#73, works #69).** Normalization living outside the gate meant a caller reaching the gate by another route got an unnormalized action.
- **Nine of the ten backlog findings from the #65 review (#74, works #71).** Global-ADOM object paths, unvalidated `task_id` on `delete_task`, a quote-span scan that closed on an escaped quote, a bulk device string iterated one character at a time, a protocol allowlist too narrow for the lookup it served, and an unredacted preview result. The tenth, a hand-rolled error envelope, was refused on measurement: converting the one site named would have made it inconsistent with 260 neighbours rather than consistent with 10, which is a contract change belonging in its own issue.
- **A partial update is gated against the policy it will produce, not the fields it carries (#75, works #71).** `update_local_in_policy` left the gate ungated when `action` was omitted, so an update that omitted the field could widen a policy without being screened. The gate now reads through to the resulting policy, and an unreadable action is a sentinel that fails closed rather than a value that reads as permissive.
- **A request size is no longer reported as an outcome count (#81, closes #78).** Bulk group tools returned the number of members **asked for** as though it were the number acted on, so a partial or total failure still reported full success. The counts now come from the appliance response.
- **Five more review-backlog issues, three of them wider than filed (#87, closes #82, #83, #84, #85, #86).** Security-profile CRUD (AV, web filter, DNS filter, app control, IPS, SSL/SSH, DLP, WAF) addressed the Global ADOM as `adom/global` where FMG expects `global`, and the bug lived in four shared constants, not the list tools the issue named, so create/get/update/delete were affected on all eight profile types too (#82). `capture_id` reached the wire with no validation: a bool, a negative, or a float all passed (#83). `policy_lookup` accepted ICMPv6 together with an IPv4-only address, an unanswerable combination now refused rather than silently answering the wrong half of it (#84). A PEM certificate split across list elements in a redacted preview leaked every line after the first (#85). `dvm_tools.add_devices_bulk` had no shape check on `devices`, so a single dict or a bare string reached the payload builder and failed with an opaque internal error instead of a clear one (#86).
- **A stock appliance's certificate cannot pass the verification the old warning recommended enabling (#90, closes #89).** The certificate is self-signed with no SAN, so trusting it and turning verification on fails with an IP-address mismatch regardless — the warning was pointing operators at a step that cannot succeed. It now names the real prerequisite (a certificate whose SAN matches the connection address), and a new `FORTIMANAGER_CA_BUNDLE` setting lets an estate that has done that work verify against a specific CA instead of choosing between "off" and "everything fails."

### Changed

- **The server is ported to the mcp 2.0 `MCPServer` API and the `<2` pin is lifted (#92).** mcp 2.0 removed `mcp.server.fastmcp`, the API this server was built on, so the old `mcp>=1.28.1,<2` pin was holding CI green rather than describing a supported range. The floor is now `mcp>=2.0.0`, and it is a hard import requirement rather than a preference: the 2.0.0 wheel ships `mcp/server/mcpserver` and drops `fastmcp`, the 1.28.1 wheel is the exact reverse, so an install below the floor cannot start at all rather than degrading quietly. **Upgrading an existing deployment therefore needs its dependencies reinstalled, not only its source synced.** The migration is largely a rename, with one part that fails silently: `MCPServer` accepts neither `stateless_http` nor `transport_security`, both having moved to `streamable_http_app()`, so dropping them from the constructor without adding them to the transport would have left the HTTP deployment stateful and unbound by `MCP_ALLOWED_HOSTS` with nothing reporting it. Both are now passed at the transport and pinned by tests that record the call `run_http` makes, because `MCPServer.settings` has no `stateless_http` field to assert against. Masking is unaffected: it runs before the `CallToolResult` conversion 2.x introduced, so the new return shape never reaches redaction.
- **CI type-checks `src/`, and the mypy range is pinned below 2.0 (#91).** The lint job ran ruff only, so a type regression passed all five green checks, which is how the two `no-any-return` errors in #87 reached main and had to be corrected by hand afterwards. The pin is the load-bearing half. Measured at that merge commit, mypy 1.10.0 and 1.20.2 both report those two errors while 2.1.0 and 2.3.1 report none, and this repo commits no lockfile, so an unpinned step would resolve the newest release and track a checker that has stopped reporting the very class it was added for. The declared range is `mypy>=1.14,<2`, currently resolving to 1.20.2; the floor matches the one the FortiAnalyzer companion merged in rstierli/fortianalyzer-mcp#132 rather than anything this tree needs, since this tree is clean on 1.10.0 too. One source change came with it: of the two casts `a505445` added, the `_validate_int_id` one is required on mypy 1.x and redundant on 2.x, where `warn_redundant_casts` flags it, so that function now returns through an annotated local satisfying both generations. The `validate_device_dict_list` cast is untouched and still required on 1.x.
- **`update_device_wtp` and `delete_device_wtp` are documented as able to strand a profile (#67, closes #57).** Registering an AP in the `wtp` table is what keeps FortiManager from pruning an otherwise-unreferenced wtp-profile on install, so removing or repointing the registration can orphan the profile it referenced. Behaviour is unchanged; the hazard is now stated where a caller reads it.
- **Three behaviours are pinned that had no test holding them (#66, #72, #79).** That a radio update writes only the target radio key and leaves its siblings untouched (#66, closes #59); the secret-directive set itself rather than only its current members, so adding a directive without adding its guard is a failing test (#72, works #68); and the three radio-path coverage gaps the #66 sweep surfaced (#79, works #76).

## [1.11.0] - 2026-08-12

Security fix release: device credentials were leaking in cleartext from four read paths -- upgrade promptly. Also ships device-level configuration tools (interfaces/VLAN, DHCP, wireless VAP), wtp-profile radio config and managed-AP tools, and security-profile (UTM) fields on firewall policy tools.

### Security

- **Device credentials stripped from every read path, not just the write echoes (#51, Christian Dassy).** `add_device` and `add_devices_bulk` had always stripped `adm_pass`/`adm_passwd` from the FMG-echoed object, but no read path did -- `list_devices`, `get_device`, `search_devices`, and `get_device_status` were returning the stored admin password of every managed device to the caller, independent of `MASKING_ENABLED`. A single recursive helper in `utils/responses` now applies at all four read paths (recursing because `get_device(include_details=True)` can carry a credential inside a nested VDOM sub-object), with a depth bound that fails closed rather than publishing an unchecked subtree. Both credential spellings now have one shared definition instead of two independent literals, and a test asserts every device-returning tool goes through the helper so a new tool can't quietly skip it.

### Added

- **WTP-profile radio config and managed-AP (`wtp`) tools (issue #52, PR #54): eight typed tools for the device DB.** `list_device_wtp_profiles`, `get_device_wtp_profile` and `update_device_wtp_profile_radio` cover reading a FortiAP profile and surgically updating one radio's `channel`/`channel-bonding`, carrying every other field on that radio through unchanged (the same read-modify-write discipline `assign_vap_to_wtp_profile` uses, since FortiManager replaces a nested radio object rather than merging into it). `channel` is sent as the list FortiOS stores it as (a single-element list pins one channel); `channel_bonding` is checked against the confirmed `20MHz`/`40MHz`/`80MHz`/`160MHz` set. `list_device_wtps`, `get_device_wtp`, `create_device_wtp`, `update_device_wtp` and `delete_device_wtp` cover `wireless-controller wtp`, the table that maps a physical AP's serial number (`wtp-id`) to a profile and an authorization state (`discovered`/`enable`/`disable`) — registering an AP here is what keeps FortiManager from pruning an otherwise-unreferenced wtp-profile on install. Everything writes to FortiManager's device database only and is pushed with the existing `preview_install` + `install_device_settings` flow; no direct-to-device CLI. Both wtp-profile and wtp reads strip credential-shaped fields (`login-passwd` and four sibling `type=password` fields, one nested per radio) confirmed live against the FMG sandbox to leak as encrypted blobs otherwise, the same class of gap #51 fixed for device records. 28 new unit tests (749 total).

- **Security-profile (UTM) fields on `create_firewall_policy` / `update_firewall_policy` (issue #48, PR #55).** Previously the two tools exposed only `nat` and `logtraffic`, so a policy could be created but no inspection could actually be applied to it. Ten new optional parameters: `utm_status`, `av_profile`, `ips_sensor`, `webfilter_profile`, `dnsfilter_profile`, `application_list`, `file_filter_profile`, `ssl_ssh_profile`, `profile_protocol_options`, `profile_group` -- all reference existing profile objects by name, so no new object CRUD was needed. `None` omits a field from the payload entirely, matching every other optional field on these tools.

  `profile_group` is validated as mutually exclusive with the eight individual profile fields it bundles (`av_profile`, `ips_sensor`, `webfilter_profile`, `dnsfilter_profile`, `application_list`, `file_filter_profile`, `ssl_ssh_profile`, `profile_protocol_options`) -- FortiOS rejects setting both, so this is now caught at the tool boundary with a clear message instead of an opaque FortiManager error code. Verified directly against the FNDN 7.6.7 `firewall/profile-group` schema (`adomobj76-3500-objects.htm`, cross-checked `adomobj76-3693-objects.htm`): all eight fields, including `profile_protocol_options`, are listed as members of the group object's attribute list. (An earlier draft of this change incorrectly excluded `profile_protocol_options` from the exclusion set based on a misreading of that same schema; corrected before merge.) Setting any profile field together with `utm_status=False` in the same call is also rejected, since FortiOS ignores security profiles when utm-status is disabled.

  `profile-type` (FortiOS's own single-vs-group switch) is not a tool argument -- it's derived automatically (`"group"` when `profile_group` is set, `"single"` when any individual profile field is set, `profile_protocol_options` included) so a caller doesn't also need to know to set it for FortiOS to honor `profile_group`. Note that a partial `update_firewall_policy` call which sends any individual profile field on a currently-group-mode policy flips `profile-type` to `"single"` -- the stored `profile-group` value becomes dormant, not deleted. 22 unit tests (725 total) assert exact payloads for both the profile-group and individual-profiles paths, the mutual-exclusion and utm-disabled validation errors, and the profile-type derivation, on create and update.

- **Device-level configuration tools (issue #45, PR #47, Christian Dassy): eleven typed tools for the device DB.** Interfaces: `create_device_interface` (VLAN subinterface with parent, vlanid, ip, allowaccess, role, alias, vdom), `update_device_interface`, `delete_device_interface`; reads stay on the existing `get_device_interface_config`. DHCP: `list_device_dhcp_servers`, `create_device_dhcp_server` (interface, lease range, netmask, gateway, up to three DNS servers or the device's system DNS), `update_device_dhcp_server`, `delete_device_dhcp_server`. Wireless: `list_device_vaps`, `create_device_vap` (SSID, security mode, credential, VLAN mapping), `delete_device_vap`, and `assign_vap_to_wtp_profile`, which appends the VAP to the selected FortiAP profile radios and switches them to manual VAP selection so the SSID actually broadcasts. Everything writes to FortiManager's device database only and is pushed with the existing `preview_install` + `install_device_settings` flow; no direct-to-device CLI. Field names follow the FortiOS cmdb tables the device DB mirrors.

  The VAP credential is routed by security mode, since FortiManager keeps the WPA3-SAE password in its own field: `sae-password` for `wpa3-sae` and `wpa3-sae-transition` (with `pmf` enabled, which SAE requires), `passphrase` for the personal modes, and both for transition mode, which runs a WPA2 leg alongside SAE. Sending `passphrase` for SAE is rejected by the appliance with "vap sae password must be not empty". Modes needing credentials these tools do not set (enterprise, WEP) are refused up front rather than creating an unusable SSID. Both credential fields are stripped from every response, list and the FMG create echo alike. Field names confirmed against the `wireless-controller vap` schema on 7.6.7 and 8.0.0. 33 new unit tests (645 total), including dynamic-mode resolution of the new module.

### Added

- **Reversible data masking (FPE), opt-in and off by default** ([#34](https://github.com/rstierli/fortimanager-mcp/issues/34)). `MASKING_ENABLED=true` plus a 32/48/64 hex-character `FMG_MASKING_KEY` masks the identifier-bearing *values* in tool outputs (addresses, subnets, MACs, device serials, FQDNs, admin usernames) with format-preserving encryption, so a model can still correlate a value across calls without seeing it. Enabling the flag without a valid key aborts startup rather than running unmasked. The ciphers are shared with the FortiAnalyzer sibling under `faz-mcp-fpe:v1`, so one key produces matching tokens on both, which also means one blast radius: rotate them together.

  **Names are never masked.** Object, ADOM, package, VDOM, device, template and script names are routing keys; masking one would not hide an identifier, it would break every follow-up call that used it.

  **Masked values are read-only context.** A token supplied as a tool argument is refused rather than restored. FortiManager arguments become estate configuration, and the v1 token format carries no integrity tag, so a stale, rotated or foreign token would decrypt to a plausible wrong address and be written with nothing to catch it. An authenticated envelope that would make restoration safe is the subject of the joint protocol v2 RFC.

  **Fail-closed by construction.** A value the ciphers cannot represent becomes an irreversible keyed placeholder, never the raw value, and is never logged. A carrier key holding a container is walked rather than returned. If masking a whole result fails, the tool returns an error envelope and the raw result is withheld. Secrets are replaced by a fixed constant instead of a token, since a token is reversible by design, and that constant is itself refused on the way back in.

  Deliberately out of scope for this version, each with a reason rather than an oversight: free text, script bodies, install previews and task detail, and names that embed an address.

  Carrier coverage was set by static derivation over every tool module plus read-only sweeps of live FortiManager 7.6.7 and 8.0.0, then corrected three times by review against a live FortiGate device DB: the SD-WAN source and gateway fields, the interface IPv4 and IPv6 address, relay and VRRP fields, MAC-type address objects, wildcard FQDNs, service IP ranges, the proxy envelope's device serial, and the interface address fields that carry a netmask alongside the address. `adm_pass` and its siblings are redacted rather than tokenised.

## [1.10.0] - 2026-08-09

Minor release: new device-config read tools and an SD-WAN reader, a service-group update tool, address/service negation on policies, HTTP transport hardening, and error-handling fixes.

### Added

- **`get_device_sdwan`** reads a device's SD-WAN configuration from the FMG object DB (#40).
- **`get_device_interface_config`, `get_device_client_location`, `get_device_sdwan_monitor`, `resolve_datasource`** for reading device-level interface and config state and resolving datasource paths (#43).
- **`update_service_group`** updates a service group's members and comment, mirroring `update_address_group`; a supplied member list replaces the existing set (#42).
- **Address and service negation on `create_firewall_policy` / `update_firewall_policy`.** New `srcaddr_negate` / `dstaddr_negate` / `service_negate` parameters set the matching FMG fields. They default to off, so an unset value never negates and a partial update never clobbers the stored negate state. The permissiveness guard treats a negated `all` as matching no traffic and a negated specific list as broad (#41).

### Changed

- **The HTTP transport bounds request body size and in-flight request count** (#37). `MCP_MAX_REQUEST_BYTES` (default 10 MiB) rejects an oversize body with 413 before it is buffered; `MCP_MAX_CONCURRENT_REQUESTS` (default 64) caps concurrency through uvicorn and returns 503 past the ceiling. Set either to 0 to disable. Auth still runs first, and `/health` is unaffected.
- **Policy package-name validation accepts folder-nested names** such as `folder/pkg` (up to ten segments), while still rejecting path traversal, empty segments, and URL/JSON-RPC metacharacters (#36).

### Fixed

- **Stored scripts execute again under strict safety: the type screener now understands FMG's integer type codes.** `create_script` validates the caller's string name ("cli"), but FortiManager stores and returns `type` as an integer, so the execute-path readback handed the allowlist "1" and every CLI script created through the MCP was refused at execution time as "not a recognized screenable type". The screener now normalizes stored codes to their names before the check, using the mapping FortiManager's own schema reports (`get /dvmdb/script` with `option=syntax`, verified identical on 7.6.7 and 8.0.0): cli=1, tcl=2, cligrp=3, tclgrp=4, jinja=5. Create and execute now agree on both representations, Tcl codes are refused under their real name instead of a bare digit, and codes outside the schema keep failing closed. (#44)
- **FMG error `-10015` ("object in use") is classified as `object_error`** instead of a generic API error, so a delete blocked by a dependency returns a clear, categorised message (#35).

### Security

- **Pinned `mcp` to the 1.x line and raised dependency security floors** so the server keeps importing and pulls patched transitive versions (#38).

## [1.9.2] - 2026-07-04

### Tests

- **Pinned the two invariants the v1.9.1 lock-handoff and protocol-detection fixes rely on.** New tests assert that cancelling a call still queued on the request lock cannot release the in-flight holder's lock (verified by mutation: moving the acquire inside the try/finally fails the test), that the TCP/UDP protocol cache is keyed per ADOM and serves repeat lookups without re-probing, and that the fallback constant is never cached so a temporarily unreachable ADOM recovers to its real code. Also covered: orphaned-worker exception retrieval, error propagation with lock release on a plain failing call, connect()'s non-dict probe response detail, the parser's `TCP/UDP/SCTP` string alias, and the operator warning on detection fallback. The per-ADOM cache is now cleared by an autouse fixture (before and after each test), removing a latent test-order dependence. 506 unit tests pass.

## [1.9.1] - 2026-07-03

Follow-ups to v1.9.0, verified against live FortiManager appliances (7.6.6, 7.6.7, 8.0.0). 496 unit tests pass.

### Fixed (live-FMG follow-ups)

- **`create_service_tcp_udp` now detects the version-specific `protocol` enum instead of hardcoding it.** `firewall service custom` stores `protocol` as an integer enum whose TCP/UDP/SCTP code changed between FMG builds: verified live, 7.6.6 (build 3654) uses `5` while 7.6.7 (build 3737) and 8.0.0 use `15`, and each version rejects the other's value with `prop[protocol]: option empty or invalid`. A hardcoded constant broke service creation on one version or the other, so the tool now discovers the code per ADOM from a predefined port-based service the appliance ships (its own code is by definition the one that ADOM accepts) and caches it, falling back to `15` only if none can be read.
- **Service parsing handles the real integer enum.** `_extract_service_details` previously only recognized `15` for TCP/UDP and the string `"ICMP"`, so an ICMP service (stored as integer `1`) lost its type and a `5`-encoded TCP service (7.6.6) read back as category "IP". It now classifies across every observed representation: TCP/UDP/SCTP `5` and `15`, ICMP `1`, ICMP6 `6`, IP `2`, and their string aliases.
- **`create_service_icmp` sends the integer protocol code.** Now sends `protocol: 1` instead of the string `"ICMP"`. The string was accepted (FMG coerces the alias, storing 1), so this is a consistency change matching the integer approach used elsewhere rather than a behavior fix.
- **API-token connections verify reachability at connect time.** pyfmg's apikey "login" makes no network call, so a bad token or an unreachable FMG went undetected and `/health` reported `fortimanager_connected: true` against a dead FMG. Token-mode `connect()` now probes `/sys/status` once and fails closed if it errors or returns a non-zero code. Session (username/password) auth already round-trips in login and is unchanged.
- **A cancelled FMG call no longer lets a second call run on the shared pyfmg session concurrently.** pyfmg's `requests.Session` is not thread-safe and a worker thread cannot be interrupted, so when an outer `asyncio.wait_for` cancels a call, `_run_fmg_call` now hands lock ownership to the in-flight worker: the cancelled caller returns immediately (preserving the timeout bound) and the worker's completion callback releases the lock, so any follow-up call queues until the session is idle. Closes the concurrency window raised in the v1.9.0 review.

### Documented

- **The preview-before-install gate's package binding is enforced by the gate, not the preview API.** FortiManager's `/securityconsole/install/preview` is device-scoped (`adom` + `scope`, no `pkg` parameter), so a preview reflects whatever is pending for those devices. `install_gate` makes this explicit: the package binding comes from the record key `(adom, package, scope)` plus the package revision fingerprint, so an install is only authorized by a preview recorded for that same package with unchanged content.

## [1.9.0] - 2026-07-03

Correctness and hardening batch from a full code review + security audit. 473 unit tests pass.

### Fixed
- **Every FortiManager API call no longer blocks the event loop.** pyfmg is a synchronous requests-based library; login/logout/get/add/set/update/delete/execute/move now run via `asyncio.to_thread` under a serializing lock (the shared pyfmg session is not thread-safe). Concurrent MCP sessions, `/health`, and retry backoffs stay responsive during slow FMG round-trips, and `wait_for_task`'s documented `POLL_CALL_TIMEOUT` bound is actually enforceable.
- **Dynamic mode (`FMG_TOOL_MODE=dynamic`) could never execute any tool.** `execute_fortimanager_tool` looked tool modules up as package attributes, but dynamic mode never imports them, so every call returned "Tool not found". The owning module is now imported on first use.
- **`move()` / `move_firewall_policy` gets the same reconnect-once + transient-retry resilience as every other verb** — it previously bypassed `_execute_resilient`, so a routine policy reorder on an idle-dropped session hard-failed with a raw -11.
- **`MCP_ALLOWED_HOSTS` accepts the comma-separated form its own description promised.** Previously only a JSON array parsed; `host1,host2` crashed settings load (and therefore server startup) with a `SettingsError`. Both forms now work.
- **`is_permission_error` / `is_auth_error` / `is_duplicate_error` matched FMG error codes contradicting the verified `ERROR_CODE_MAP`** (-3 is not-found, not permission; -2 is duplicate, not auth; -6 is invalid URL, not duplicate). Corrected to -11/-10147, -22, and -2 respectively; tests updated to match.
- **Service resolution in `get_policy_services` no longer recurses forever on a circular service-group reference**, and permission/connection failures during lookup now surface as tool errors instead of being mislabeled "service not found".
- **`/health` reports the client's actual connection state** instead of merely whether the client object exists.
- **`add_device` sanitizes the FMG-echoed device object**, so a response echoing the submitted config can no longer leak `adm_pass` back to the caller.
- **`search_devices` rejects invalid `connection_status` values** instead of silently treating any non-"up" string (including typos) as "down".
- **`validate_filename` rejects a trailing newline** (`$`-anchored match replaced with `fullmatch`).

### Security
- **Script-safety patterns now cover FortiOS command-prefix abbreviations** (`ex`/`exe`/`execu…` for `execute`, `conf sys`/`conf rout` for the config stanzas), which previously bypassed the strict-mode denylist. Script types are now **allowlisted** under `FMG_SCRIPT_SAFETY=strict` at create, update, and execute time: only the documented content-screenable types (`cli`, `cligrp`, `jinja`) pass; Tcl types (`tcl`, `tclgrp`) are refused because their commands can be assembled at runtime, and unrecognized types are refused because FortiManager stores the `type` field without any server-side validation (verified live: arbitrary type strings are accepted with code 0), so a Tcl payload could otherwise be filed under an invented type. A stored script whose type cannot be read fails closed at execute time. The screen remains defense-in-depth; a least-privilege FMG API account is the primary control.
- **All GitHub Actions pinned to full commit SHAs** (previously mutable `@vN` tags); Docker publish now emits provenance attestations (`mode=max`) and an SBOM; the `uv` builder image is version-pinned instead of `:latest`.
- **Input validation wired into object tools**: IPv4/subnet/FQDN validation on address creation, position validation on policy move, device-name validation on bulk device add (parity with the single-device and bulk-delete paths).

### Changed
- CI's pip-audit step documents that the git-pinned pyfmg dependency is out of its scope (VCS direct references are skipped); SECURITY.md gained a "Dependency auditing" section describing how pyfmg is tracked.

## [1.8.0] - 2026-07-01

Opt-in stateless Streamable HTTP transport for multi-replica / load-balanced deployments. 438 unit tests pass.

### Added
- **`MCP_STATELESS_HTTP` setting (default `false`).** Runs the Streamable HTTP transport's session manager in stateless mode so the server can sit behind a load balancer / run as multiple replicas when the fronting proxy does not preserve the `Mcp-Session-Id` header. Default `false` preserves the current session-persistent behavior — no change for existing single-instance deployments. Wired through to `FastMCP(stateless_http=...)`; the process-global FortiManager client lifecycle (owned by `run_http`'s `app_lifespan` / `run_stdio`) is unaffected in either mode. Tradeoff: stateless mode keeps no per-session state across requests, so server-initiated streaming that relies on a persistent session is unavailable — enable only when fronting the server with a load balancer/proxy that cannot pin sessions.

## [1.7.1] - 2026-06-14

Preview-gate revision fingerprinting — closes the TOCTOU window between preview and install ([#25](https://github.com/rstierli/fortimanager-mcp/issues/25)). 434 unit tests pass.

### Fixed
- **A package edited between preview and install no longer deploys unreviewed changes under the old preview's authorization.** `preview_install` now captures the package's revision counter (the package object's `obj ver` field — verified live against FMG 7.6.7: increments on policy add, modify, and delete) at preview time; `install_package` compares it at install time. On mismatch the install is refused with a new `preview_stale` error naming both revisions, and the stale record is expired so the next attempt cleanly reports "no preview on record". The revision is read *before* the preview is submitted, so a change racing the preview task itself fails toward re-preview, never toward a stale pass. When `obj ver` is unavailable at preview time (older builds, transient fetch failure) the record carries no revision and the gate degrades to v1.7.0 behavior (TTL + single-use); a recorded revision that cannot be re-verified at install time refuses in `strict` mode. Live-verified end-to-end: hidden policy edit between preview and install → `preview_stale` (revision 8 → 9); fresh preview → install passes.

## [1.7.0] - 2026-06-12

FMG-specific safety additions (bundle D of [#11](https://github.com/rstierli/fortimanager-mcp/issues/11)): preview-before-install gate, ADOM workspace-lock tracking with shutdown release, and per-item bulk delete reporting. 421 unit tests pass.

### Added
- **Preview-before-install gate** (`utils/install_gate.py` + `FMG_INSTALL_SAFETY`). By default (`strict`) `install_package` refuses a real install unless a `preview_install` for the same ADOM + package + device set is on record and its FMG task finished successfully (verified live via `get_task` at install time). Previews expire after 30 minutes and are single-use — each authorizes exactly one install, because the package may change in between. `warn` installs but returns a warning; `disabled` restores previous behavior. Same setting shape as `FMG_SCRIPT_SAFETY` / `FMG_POLICY_SAFETY`. `install_package(preview=True)` is itself a dry run and bypasses the gate. **Upgrade note:** agents that installed without previewing must now run `preview_install` + `wait_for_task` first, or the operator sets `FMG_INSTALL_SAFETY=warn`/`disabled`.
- **ADOM workspace-lock tracking + shutdown release** (`utils/adom_locks.py`). `lock_adom`/`unlock_adom` now track which ADOMs this server locked; at server shutdown (both lifecycle owners) any still-held lock is released best-effort — shielded, bounded by 5s per unlock — before the client disconnects, so an agent that errored out between lock and unlock doesn't leave the ADOM blocking other admins. Deliberately **no** auto-unlock on individual tool failure: the agent may be mid-workflow (lock → change → retry → commit → unlock) and yanking the lock would discard the workspace session it is still using.

### Changed
- **`delete_firewall_policies_bulk` reports per-item results.** Previously one filtered DELETE reported `len(policyids)` as deleted no matter how many IDs actually matched, and one bad ID failed the whole call opaquely. Now each policy is deleted individually and the response carries `status: success|partial|error`, `deleted` (IDs), and `failed` (`{policyid, message, error_code}` per item).

## [1.6.0] - 2026-06-12

Async-task contract (bundle C of [#11](https://github.com/rstierli/fortimanager-mcp/issues/11)): anti-exhaustion guards for the FMG task lifecycle — bounded concurrent task spawns, deadline-bounded status polls, and a shared poll-recovery budget. Adapted from the FortiAnalyzer MCP's logsearch guards ([fortianalyzer-mcp#18](https://github.com/rstierli/fortianalyzer-mcp/pull/18)). 400 unit tests pass.

### Added
- **Shared in-flight task budget** (`utils/task_guard.py`). The seven task-spawning tools (`install_package`, `install_device_settings`, `preview_install`, `execute_script_on_device/devices/device_group/package`) now share one in-process budget of `TASK_CONCURRENCY_LIMIT = 5` concurrent FMG tasks, so a caller cannot slam the FMG with 20 parallel installs. The slot is reserved *before* the submit is awaited (racing spawns cannot overshoot), bound to the returned task id, and released when `wait_for_task` observes a terminal state — or reclaimed after `TASK_SLOT_TTL` (30 min) for callers that never poll. When the budget is full the tool fails fast with a structured `task_slots_exhausted` envelope naming the in-flight kinds, rather than queueing the MCP request.
- **Deadline-bounded task polling in `wait_for_task`.** Each `get_task` poll is bounded by `asyncio.wait_for` (`POLL_CALL_TIMEOUT = 30s`), the overall wait is clamped to `MAX_TASK_WAIT_TIMEOUT = 3600s`, and `poll_interval` is clamped to `[1, 60]` so a 0 interval cannot hot-loop. Wedged polls re-poll on a shared budget of `MAX_TASK_POLL_FAILURES = 3` (the FMG analog of FAZ's `MAX_SEARCH_REISSUES`), then surface a structured `task_poll_failed` envelope. Persistent API errors still surface immediately — `get_task` already retries transients internally, so re-polling those here would be wrong.

### Notes (FMG adaptations of the FAZ pattern)
- **No automatic cleanup-cancel of FMG tasks.** FAZ cancels an orphaned logsearch (read-only, single-use tid). An FMG task is a config-mutating install or script run: auto-cancelling one mid-flight because the *poll* was aborted risks a half-applied install, which is worse than letting the task finish unobserved. Exhaustion protection comes from the slot TTL instead.
- The `assign_*` bulk operations named in #11 turn out to be synchronous (no task id in their responses), so they need no guard. The guard is one `spawn_guarded(...)` wrapper per call site if other spawn sites (e.g. dvm `create_task`-flag tools, `validate_template`) should be added later.

## [1.5.0] - 2026-06-12

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
