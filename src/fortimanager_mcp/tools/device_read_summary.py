"""Pure summaries for routes, policy counters, IPsec status, and package diff.

These keep chat payloads small. They do not call FortiManager.
"""

from typing import Any

_COMPARE_FIELDS = (
    "name",
    "status",
    "action",
    "srcintf",
    "dstintf",
    "srcaddr",
    "dstaddr",
    "service",
)

_STATUS = {0: "disable", 1: "enable", "0": "disable", "1": "enable"}
_ACTION = {0: "deny", 1: "accept", "0": "deny", "1": "accept"}


def _names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, dict):
        name = value.get("name") or value.get("q_origin_key")
        return [str(name)] if name else []
    if isinstance(value, list):
        names: list[str] = []
        for item in value:
            names.extend(_names(item))
        return names
    return [str(value)]


def _token(value: Any, mapping: dict[Any, str]) -> str | None:
    if value is None or value == "":
        return None
    if value in mapping:
        return mapping[value]
    text = str(value).strip().lower()
    return mapping.get(text, text)


def summarize_routes(results: Any) -> list[dict[str, Any]]:
    """Live IPv4 routes from the FortiGate router monitor."""
    if not isinstance(results, list):
        return []
    rows = []
    for route in results:
        if not isinstance(route, dict):
            continue
        rows.append(
            {
                "type": route.get("type"),
                "destination": route.get("ip_mask"),
                "gateway": route.get("gateway"),
                "interface": route.get("interface"),
                "distance": route.get("distance"),
                "metric": route.get("metric"),
            }
        )
    rows.sort(key=lambda item: (item.get("destination") != "0.0.0.0/0", str(item.get("destination") or "")))
    return rows


def summarize_static_routes(results: Any) -> list[dict[str, Any]]:
    """Configured static routes from the firewall configuration."""
    if not isinstance(results, list):
        return []
    rows = []
    for route in results:
        if not isinstance(route, dict):
            continue
        rows.append(
            {
                "destination": route.get("dst"),
                "gateway": route.get("gateway"),
                "interface": route.get("device"),
                "distance": route.get("distance"),
                "status": _token(route.get("status"), _STATUS),
            }
        )
    return rows


def summarize_hit_counters(results: Any) -> list[dict[str, Any]]:
    """Current per-policy packet and byte counters.

    policyid 0 is the implicit rule counter when the firewall includes it.
    These numbers are since the firewall last cleared them, not a 30-day history.
    """
    if not isinstance(results, list):
        return []
    rows = []
    for item in results:
        if not isinstance(item, dict):
            continue
        policyid = item.get("policyid")
        rows.append(
            {
                "policyid": policyid,
                "packets": item.get("packets"),
                "bytes": item.get("bytes"),
                "active_sessions": item.get("active_sessions"),
                "implicit": policyid == 0,
            }
        )
    rows.sort(key=lambda item: (item.get("policyid") is None, item.get("policyid") or 0))
    return rows


def summarize_ipsec_tunnels(results: Any) -> list[dict[str, Any]]:
    """Live IPsec tunnel state. A tunnel is up when any phase-2 is up."""
    if not isinstance(results, list):
        return []
    rows = []
    for tunnel in results:
        if not isinstance(tunnel, dict):
            continue
        phases = []
        for phase in tunnel.get("proxyid") or []:
            if not isinstance(phase, dict):
                continue
            phases.append(
                {
                    "name": phase.get("p2name") or phase.get("name"),
                    "status": _token(phase.get("status"), {}) or "unknown",
                }
            )
        if any(phase["status"] == "up" for phase in phases):
            status = "up"
        elif phases:
            status = "down"
        else:
            status = "unknown"
        rows.append(
            {
                "name": tunnel.get("name"),
                "remote_gateway": tunnel.get("rgwy"),
                "status": status,
                "phase2": phases,
            }
        )
    rows.sort(key=lambda item: (item.get("status") != "down", str(item.get("name") or "")))
    return rows


def _as_rows(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _policy_view(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "policyid": policy.get("policyid"),
        "name": policy.get("name"),
        "status": _token(policy.get("status"), _STATUS),
        "action": _token(policy.get("action"), _ACTION),
        "srcintf": _names(policy.get("srcintf")),
        "dstintf": _names(policy.get("dstintf")),
        "srcaddr": _names(policy.get("srcaddr")),
        "dstaddr": _names(policy.get("dstaddr")),
        "service": _names(policy.get("service")),
    }


def compare_policies(package_rows: Any, device_rows: Any) -> dict[str, Any]:
    """Compare a FortiManager package with the policy on the firewall.

    Integers from the package (status 0, action 0) match the firewall words
    disable and deny. Interface and address objects match by name.
    """
    package = [_policy_view(row) for row in _as_rows(package_rows) if isinstance(row, dict)]
    device = [_policy_view(row) for row in _as_rows(device_rows) if isinstance(row, dict)]
    package_by_id = {row["policyid"]: row for row in package if row.get("policyid") is not None}
    device_by_id = {row["policyid"]: row for row in device if row.get("policyid") is not None}

    only_in_package = [package_by_id[key] for key in package_by_id if key not in device_by_id]
    only_on_device = [device_by_id[key] for key in device_by_id if key not in package_by_id]
    different = []
    for key in package_by_id:
        if key not in device_by_id:
            continue
        left = package_by_id[key]
        right = device_by_id[key]
        fields = {}
        for field in _COMPARE_FIELDS:
            if left.get(field) != right.get(field):
                fields[field] = {"package": left.get(field), "device": right.get(field)}
        if fields:
            different.append({"policyid": key, "name": left.get("name") or right.get("name"), "fields": fields})

    return {
        "package_count": len(package_by_id),
        "device_count": len(device_by_id),
        "match": not only_in_package and not only_on_device and not different,
        "only_in_package": only_in_package,
        "only_on_device": only_on_device,
        "different": different,
    }
