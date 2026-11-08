---
name: fmg-firewall-policy-audit
description: Audit a FortiManager policy package or explain why one flow is allowed or blocked, using the fortimanager MCP tools. Use it whenever someone asks to analyze, review, clean up or harden firewall policies, looks for shadowed, unused, too broad or duplicate rules, or asks which rule matches a flow, even without the word audit. Analyser les policies, règles masquées, nettoyage, pourquoi ce flux est bloqué.
---

# Firewall policy audit

There are two modes. Use **Explain a flow** for one flow, and **Audit a package** for a whole package. Both are read-only: report and propose, and change nothing unless asked.

Rule order decides everything, so sort policies by `obj seq`, not by `policyid`.

## Explain a flow
1. Run `policy_lookup` on the device with the real source, destination, port and `srcintf`.
2. Name the policy that matched and what it applies, then read it with `get_firewall_policy`.
3. `error_unknown_route` or `error_unknown_source_route` means routing, not policy: say so and check routes.

## Audit a package
Collect the data:
- `list_firewall_policies` with `fields`: `policyid`, `name`, `srcintf`, `dstintf`, `srcaddr`, `dstaddr`, `service`, `action`, `status`, `nat`, `utm-status`, `logtraffic`, `profile-group`, `comments`, `_policy_block`. It also returns `scope member`.
- `list_policy_block_policies` for each entry with `_policy_block`, since a package shows a block as one empty entry.
- `get_address_group`, `get_address` and `get_policy_services` to resolve objects. Comparing names is not enough: `10.0.0.0/8` covers a subnet with another name.
- `get_profile_group` for groups in use, and `get_package` for `ngfw-mode`.
- `check_device_policy_sync` per device, whose `not_targeted` shows which policies each device gets.

Then check, in this order:

| Check | Finding |
|---|---|
| Shadowing | An earlier enabled rule covers source, destination, interfaces, service and schedule of a later one, so the later one never matches |
| Intent vs result | A deny or an inspection rule that is shadowed protects nothing. Report these first |
| Too broad | `all` destinations, service `ALL`, or a whole private range where one subnet is enough |
| Inspection | `utm-status` off, or a profile that does not do what the name suggests. `certificate-inspection` does not decrypt content |
| Duplicates and leftovers | Copies, disabled rules, comments such as "temporary" or "quick fix" |
| Scope | A rule for one site installed on every device |
| Logging | Rules or the implicit deny that log nothing |

Keep these traps in mind:
- In profile mode (`ngfw-mode` 0), an application list does not decide which rule matches. A rule named after an application with service `HTTPS` matches all HTTPS, so moving a shadowed one up can block far more than intended.
- Hit counters read 0 until FortiManager collects them. If every rule shows 0, including the main internet rule, they prove nothing: never call a rule unused from that alone.
- Interfaces can differ per device through mappings.

## Report
Lead with how many rules have no effect and the most serious finding. Sort findings by risk, with the rule, the problem, the evidence and the fix, and warn when a fix changes what traffic passes. End with what could not be verified.
