---
name: fmg-template-rerun-check
description: Check what changed after re-running or editing a FortiManager SD-WAN Overlay Template or provisioning template, before or after installing, using the fortimanager MCP tools. Use it whenever someone re-ran an overlay template, regenerated templates, changed template variables, or plans an install after such a change. Relance du template overlay, vérifier après relance, avant d'installer le template.
---

# Check after a template re-run

A re-run can change much more than the option that was edited: addressing, BGP design, policies and interfaces. Compare with the state before, ideally before installing.

## 1. Variables
Run `list_metadata_variables`, and look at each variable the templates use, such as a branch id. A device can hold one mapping per scope (`global`, `root`). Report any device whose scopes disagree, and any id used twice. `list_cli_templates` shows which variables each template reads, and `get_cli_template` how it uses them.

## 2. What the devices would receive
Run `preview_install(package=None)` on all the devices of the overlay. Check for changes to LAN addresses, DHCP scopes, loopbacks, `router-id`, phase1 `exchange-ip-addr4`, BGP neighbors and neighbor ranges, and admin passwords. Explain any change the user did not ask for.

If it was already installed, use `list_device_revisions` and `diff_device_revision` with `sections` set to `["system interface", "router bgp", "vpn ipsec phase1-interface", "system sdwan", "router static"]`.

## 3. Coherence

| Check | Tool | Risk |
|---|---|---|
| Hub loopbacks allowed by policy | `policy_lookup` for TCP/179 towards the BGP loopback | Tunnels up with BGP stuck in `Connect` |
| Address objects match the LANs | `get_address` against `get_device_interfaces` | Rules apply to the wrong site |
| Route reflection on the hub | `get_bgp_template`, `get_device_bgp` with `summary_only=True` | Branches lose each other's routes |
| Steering rules kept | `get_device_sdwan` | A custom rule disappeared |
| Packages | `get_package_install_status` | A hub or branch package needs installing too |

A value set by hand on a device or in generated templates can be lost on the next re-run: list those so the user can reapply them.

## 4. After installing
Run `get_device_bgp_status` on the hub and each branch, and `policy_lookup` for branch to hub and branch to branch. A new route-reflector setting needs `execute router clear bgp all soft out` on the hub. Finish with a real ping.

## Report
List what changed and was expected, what changed and was not, and what must be fixed before installing.
