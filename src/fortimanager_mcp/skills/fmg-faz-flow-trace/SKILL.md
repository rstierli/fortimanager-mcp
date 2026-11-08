---
name: fmg-faz-flow-trace
description: Trace a traffic flow from a source IP to a destination IP across FortiGates, combining the fortimanager and fortianalyzer MCP servers, and build a table of devices, serials, interfaces, IPsec tunnels, firewall rules and logs. Use it whenever someone asks where a flow goes, which rule or tunnel it uses, whether it passed through the hub or an ADVPN shortcut, or asks for a flow table between two IPs, even without naming a device. Tracer un flux, tableau de flux, par où passe ce trafic.
---

# Flow trace

Work from two IPs, with no device name needed. FortiManager shows where the flow should go and what runs now. FortiAnalyzer shows what really happened. Report both, because they can differ. Read-only.

If only one server is connected, do its part and say what is missing.

## 1. Collect the inputs
Source IP, destination IP, and port or service if known. Ask for the date or time range only when the flow is not running now. Use the ADOM of the devices.

Unless the user already said, ask at the start whether they want the result in Markdown or HTML. Answer in the language the user writes in, and write the report in it too, so a demo in English gets an English report.

## 2. Find the end devices
`list_devices` with `fields` `name`, `sn`, `ha_mode`, `ha_group_name`. Then, for each device, `query_device_api` on `/api/v2/monitor/router/lookup` with `{"destination": "<ip>"}`. A connected route, shown on a LAN interface, marks the device that owns the IP.

For a cluster (`ha_mode` not 0), read `/api/v2/monitor/system/ha-peer`: the entry with `primary: true` is the active member and holds live state. Logs can sit under either serial, so search both.

## 3. Follow the path, hop by hop
Start on the source's device and repeat until you reach the destination's device.

- Next hop: `router/lookup` gives the interface and gateway for the destination.
- Active flow: `/api/v2/monitor/firewall/session` with `{"ip_version": "ipv4", "source": "<ip>", "count": 20}` gives the real `srcintf`, `dstintf`, `policyid`, `dport`, bytes and packets. Filter with `source` or `destination`: `filter` and port or policy parameters are ignored, so check each row yourself.
- Tunnel: `/api/v2/monitor/vpn/ipsec` gives the tunnel, its peer `rgwy` and, for a shortcut, a name such as `HUB1-VPN1_0` with `parent`.
- Rule: `policyid` in the session or `policyname` in the logs. For a flow that is not running, simulate with `policy_lookup`, using the real `srcintf`. It can answer `error_unknown_source_route` on a tunnel when the route back uses a shortcut: try the shortcut's name before calling it a routing fault.

Session tables name the parent tunnel, even on a shortcut, so read the current route as well. When a flow between two branches shows a session on the hub with fewer packets than on the branches, it started through the hub and moved to an ADVPN shortcut. If a shortcut already exists, a flow can use it from its first packet, and only earlier traffic such as a ping shows on the hub. Compare packet counts rather than assuming either path.

## 4. Read the logs
Run `search_log_file` on each serial of the path, with `filter` such as `srcip==A and dstip==B`, and `date==2026-11-06 and time>=15:00:00` for a period. It takes no time range, and its `time-range` parameter is ignored, so filter on `date` and `time`. Use `fields=["*"]` once to see what is there, then keep `date`, `time`, `srcintf`, `dstintf`, `policyid`, `policyname`, `service`, `action`, `sentbyte`, `rcvdbyte`, `vpntype`.

Prefer `search_log_file` when `query_logs` returns nothing while `get_log_stats` shows the device logging, which happens on a FortiManager with the FortiAnalyzer feature.

Keep these in mind:
- A running session only logs when it ends, unless the policy logs at start. A live SSH shows in the session table and not yet in logs, so older entries may be another session of the same flow.
- One session can log several rows with the same `sessionid`: `pass` at the start, `accept` along the way, then `close` or `timeout`. Take the totals from the last row, since an earlier one undercounts. `deny` means a rule dropped it, and `ip-conn` means the device could not reach the host, which often means a wrong IP or a host that is off.
- A hub that a flow left for an ADVPN shortcut sees no end of session, so it logs nothing until its session ages out, about one hour later for TCP. It then logs `timeout` with a `duration` near 3600 and only the first packets' bytes, while the branches logged `close` with a much shorter duration. That pattern probably means the flow moved to a shortcut, not a failed session. A missing hub log does not prove the flow avoided the hub: check the hub's session table too.
- A rule without traffic logging leaves nothing to find, so no logs do not prove no traffic.

## 5. Locate the end hosts
For each end of the flow, run `get_device_client_location` with the IP on the device that owns it, to add the FortiSwitch, port and VLAN. If it finds nothing, follow the `fmg-host-location` steps with the MAC from the session's `srcmac` or `dstmac`, or say the host is not behind a switch.

## 6. Report
One table per flow, one row per device in path order:

| Hop | FortiGate | Hostname | Serial | In | Out | IPsec tunnel | Rule | Action | Bytes sent/received | Last seen |

Always show each FortiGate's full hostname and full serial number, in tables and in text, and never shorten a serial: an engineer needs them to find the device, and a partial serial cannot be searched. The FortiManager name can differ from the hostname. Read the hostname from `/api/v2/monitor/system/status`, or for a cluster from `ha-peer`, which gives each member's hostname and serial. For a cluster, name the active member and show both members.

Add one table for the end hosts:

| Side | Host | IP | MAC | FortiSwitch | Switch serial | Port | VLAN |

State the source of each row: live session, logs or simulation. Then give the path in one line, say whether it used the hub or a shortcut with the evidence, and list any gap between simulation and logs, and any device you could not read.

## 7. Deliver
- **Markdown:** give the report in the conversation.
- **HTML:** fill `references/report-template.html` next to this skill, in the report's language, escaping values. Replace every `{{PLACEHOLDER}}`, and add ` warn` to `{{VERDICT_CLASS}}` if the flow failed or something could not be read, otherwise leave it empty. Save it in the user's Downloads folder as `flow-<source>-to-<destination>-<YYYYMMDD-HHMM>.html`, using the full serial numbers as in the report. On macOS, open it with `open -a "Google Chrome" <file>`, or `open <file>` if Chrome is missing. Give the path, and keep a short summary in the conversation. If the template is not available, write one self-contained page with the same sections. The file holds addresses and serial numbers, so say so before anyone shares it.
