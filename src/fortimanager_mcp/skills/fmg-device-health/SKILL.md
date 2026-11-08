---
name: fmg-device-health
description: Check why a FortiGate looks down, unreachable or unmanaged from FortiManager, or review its general health, using the fortimanager MCP tools. Use it whenever a device is offline in FortiManager, proxy calls fail, a device stopped syncing, or someone asks for the state of a device, firmware or license. Équipement down, FortiGate injoignable, device offline, état d'un FortiGate.
---

# Device health

Separate three questions: does FortiManager reach the device, is the device healthy, and do the two agree. Read-only.

## 1. Connection
`list_devices` with `fields` such as `name`, `ip`, `conn_status`, `conf_status`, `db_status`, `os_ver`, `mr`, then `get_device` for one device. `conn_status` 1 means connected.

Confirm with a live read: `get_device_realtime_status`. If it answers, the management channel works, whatever an older status says. If `get_device_status` fails too, the problem is between FortiManager and the device: check the path used by FGFM (TCP/541), which on an overlay can depend on a VIP on the hub. Check the same read on a sibling device: if all fail, suspect FortiManager or the hub.

## 2. Device state
- Interfaces: `get_device_interfaces`, which includes VLANs.
- Overlay: `get_device_sdwan_monitor`, and `diagnose_ipsec_tunnel` for a tunnel that is down.
- Routing: `get_device_bgp_status`.
- Anything else: `query_device_api`, for example `/api/v2/monitor/system/resource/usage` or `/api/v2/monitor/router/ipv4`. Sessions come from `/api/v2/monitor/firewall/session` with `ip_version` and `source`.

Report what you read, not what you assume: a healthy link and a green SLA say nothing about a host behind the device. The ARP table at `/api/v2/monitor/network/arp` shows whether a host answers at all.

## 3. FortiManager view
- Sync: `get_package_install_status`, and `list_device_revisions` for recent changes.
- Firmware: `list_firmware_images`, and `get_firmware_upgrade_report` when an upgrade is planned. Flag devices on a different version from their peers.
- FortiManager itself: `get_system_status`, `get_fmg_license`, `get_ha_status`.

## Report
State the layer that fails, or that all layers are healthy, with the evidence for each. Name what could not be read rather than treating it as healthy.
