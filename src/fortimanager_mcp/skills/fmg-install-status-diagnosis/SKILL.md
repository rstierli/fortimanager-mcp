---
name: fmg-install-status-diagnosis
description: Explain why a FortiManager policy package or device shows conflict, out of sync or modified, and whether installing is safe, using the fortimanager MCP tools. Use it whenever someone sees those statuses, asks what differs between FortiManager and a FortiGate, or asks if an install would overwrite something. Statut conflict, out of sync, modified, désynchronisé, est-ce que je peux installer.
---

# Install status diagnosis

The goal is two answers: what differs, and which side should win. Read-only: do not install.

## 1. Read the status
Run `get_package_install_status`.

| Status | Meaning |
|---|---|
| `installed` | The device runs the package |
| `modified` | The package changed since the last install |
| `out of sync` | FortiManager and the device disagree |
| `conflict` | FortiManager will not call the package installed. It does not prove a local edit: it was seen with a pending package and no device change since the last install, so find the difference below |

## 2. Find the difference
Run `check_device_policy_sync` for each device. It compares three things:
- `package_vs_revision`: the package against what the device last had.
- `package_vs_device_db`: the package against FortiManager's working copy.
- `device_db_vs_revision`: changes staged in FortiManager and not installed.

This compares stored values, so a field can differ without any change to push: if a difference is absent from the preview in step 4, an install will not touch it. The package only covers policies. If it reports `in_sync` while the status stays bad, the cause is elsewhere: compare device settings with `list_device_revisions` and `diff_device_revision` using `sections`.

## 3. Find out who changed what
- `list_device_revisions`: "Auto update from device" or "Autoretrieve" means a change arrived from the device. Read it with `diff_device_revision` before blaming anyone: it is often only a FortiGuard internet-service update and reordered lines.
- `list_tasks(since_hours=24)`: an entry means the change went through FortiManager. A device change with no task was made on the FortiGate directly.
- Ask the user before calling a local change a mistake: it can be a deliberate fix.

## 4. See what an install would do
`preview_install` stages and renders without touching the device. Run it with the package, and with `package=None` for device settings. Read every line and report:
- what goes beyond the expected change, such as a password or a pending policy;
- what an install would overwrite on the device, and what it would delete;
- that devices in a shared template must usually be installed together when values move between them;
- lines that come back in every preview, which the device is not keeping: check the value with `query_device_api`.

Before accepting an object deletion, check that nothing uses it: `query_device_api` with `with_meta` returns `q_ref`, its reference count.

## Report
Give the difference per device, its origin, and a recommendation: install, retrieve the device config first, or fix a value and preview again. Installing overwrites a local change, and retrieving overwrites a pending one, so leave that choice to the user.
