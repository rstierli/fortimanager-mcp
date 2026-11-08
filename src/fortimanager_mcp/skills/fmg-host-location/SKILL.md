---
name: fmg-host-location
description: Find where a host connects behind a managed FortiGate, on which FortiSwitch, port and VLAN or FortiAP, from its IP, MAC or hostname, using the fortimanager MCP tools. Use it whenever someone asks where a host is plugged, which switch port or VLAN it uses, or whether it sits behind a FortiSwitch. Sur quel port de FortiSwitch est ce host, localiser une IP, trouver un poste.
---

# Host location

A FortiSwitch port table lists MACs or host names, not IPs. The link between IP and port is on the FortiGate, in its device inventory, so start there. Read-only.

## 1. Find the FortiGate
If the device is unknown, run `query_device_api` on `/api/v2/monitor/router/lookup` with `{"destination": "<ip>"}` on each device from `list_devices`. The device with a connected route on a LAN interface owns the IP.

## 2. Locate the host
Run `get_device_client_location` with `ip`, or with `mac` or `hostname`. It returns the hostname, MAC, VLAN, switch or FortiAP, port, serial and last seen time.

No match with the IP does not mean the host is absent:
- Find its MAC in `/api/v2/monitor/network/arp`, or in `srcmac` and `dstmac` of `/api/v2/monitor/firewall/session`, then search with `mac`.
- `/api/v2/monitor/switch-controller/detected-device` lists MAC, switch and port, without IPs.
- Still nothing: on a device with no managed switch, the host is on a FortiGate interface. Say so, with the interface from the route.

## 3. Check the port
Run `/api/v2/monitor/switch-controller/managed-switch/status`, and find the switch and port. It gives port status, speed, VLAN and the switch serial.

A MAC on a port with `fortilink_port` true or a value in `isl_peer_device_name` was only seen through an uplink or a link between switches. The host is further along, so follow that peer switch instead of reporting this port.

An old `last_seen`, or a MAC with no IP, can be stale: give the time.

## Report
| Host | IP | MAC | FortiGate | Hostname | Serial | FortiSwitch | Switch serial | Port | VLAN | Last seen |

Show full serial numbers. For a cluster, name the active member, whose `ha-peer` entry has `primary: true`.
