---
name: fmg-sdwan-overlay-troubleshoot
description: Troubleshoot a SD-WAN overlay or inter-LAN traffic failure on FortiGates managed by FortiManager, using the fortimanager MCP tools. Use it whenever tunnels or SLAs are up but traffic does not pass, BGP does not come up, pings fail between branches or to the datacenter, or after re-running the SD-WAN Overlay Template, even if the user does not mention BGP. Panne overlay SD-WAN, VPN up mais pas de trafic, BGP en Connect.
---

# SD-WAN overlay failure

Work through the layers in order and stop at the first one that fails. A tunnel that is up and a green SLA do not prove routing works: the probe can target a different loopback from BGP.

Read first, and write nothing unless asked. Keep calls small with `fields` on policies, `sections` on diffs, `summary_only=True` on `get_device_bgp` and `since_hours` on `list_tasks`, because full responses are expensive.

## 1. Locate the failure
Note the traffic direction, source IP, destination IP and what changed recently. Check `list_tasks(since_hours=24)` and `get_package_install_status`.

A ping from a FortiGate CLI leaves from an interface IP, sometimes a stale one, so ask for the source.

## 2. BGP
Run `get_device_bgp_status` on the hub and on each branch.

| Finding | Lead |
|---|---|
| Branch in `Connect`, hub lists no neighbor | The hub refuses the session: go to step 3 |
| `Established`, branch lacks the other branches' LANs | `route-reflector-client` is off, or `execute router clear bgp all soft out` was not run after enabling it |
| `Established`, hub lacks a LAN | Branch redistribution, or a wrongly addressed LAN: step 4 |
| Same prefix via two branches | Duplicate LAN: step 4 |

The hub lists dynamic peers only once they connect, so an empty list does not mean BGP is unconfigured. Direct branch-to-branch sessions in `Connect` do not stop traffic: ignore them if the session to the hub is `Established`.

## 3. Policies
Run `policy_lookup` for each real direction.

- BGP on the hub: TCP/179 from the branch loopback to the hub loopback, with `srcintf` on the tunnel. FortiOS needs a policy to reach a loopback, so check it is in `dstintf`.
- `error_unknown_route`: no route, back to step 2.
- `error_unknown_source_route`: the device has no route to the source.
- Compare what runs with the package using `check_device_policy_sync`.

## 4. Addressing and variables
After a template re-run, read the real IPs with `get_device_interfaces`, then `list_metadata_variables(device=...)`.

A variable such as `branch_id` can exist in several scopes (`global`, `root`) with different values. LANs, loopbacks and router IDs depend on it: if it is wrong, fix the variable rather than the IPs, or the next install overwrites them. `get_cli_template` shows how a variable is used.

To see what changed: `diff_device_revision(device, revision, sections=["router bgp", "system interface", "system dhcp server"])`.

## 5. Conclude
For anything no dedicated tool covers, read the FortiOS API with `query_device_api`, for example `/api/v2/monitor/router/ipv4` or `/api/v2/monitor/firewall/session` with `source`.

If traffic is still blocked, ask for a `diagnose debug flow` trace on the device concerned.

Before fixing: show the cause and its evidence, propose the change, run `preview_install`, show the output and wait for approval before installing. Point out anything in the preview beyond the fix, such as a password or another pending policy. Then recheck with `get_device_bgp_status` and `policy_lookup`, and ask for a real ping: a simulation does not replace traffic.
