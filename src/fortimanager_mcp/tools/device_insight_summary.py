"""Pure helpers for the firewall topology view and health alerts.

FortiManager 7.6 has no alert list unless FortiAnalyzer features are on, and
no topology call. These helpers build both from live FortiGate data that
FortiManager proxies. They do not call FortiManager.
"""

import re
from datetime import datetime, timezone
from typing import Any

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
_EVENT_SEVERITY = {
    "emergency": "high",
    "alert": "high",
    "critical": "high",
    "error": "medium",
    "warning": "low",
}
_CONN_STATUS = {0: "unknown", 1: "up", 2: "down"}
_CONF_STATUS = {0: "unknown", 1: "in_sync", 2: "out_of_sync"}


def _first_line(text: Any, limit: int = 80) -> str | None:
    if not isinstance(text, str) or not text.strip():
        return None
    line = text.strip().splitlines()[0].strip()
    return line[:limit]


def _neighbor_ip(neighbor: dict[str, Any]) -> str | None:
    for item in neighbor.get("addresses") or []:
        if isinstance(item, dict) and item.get("address"):
            return str(item["address"])
    return None


def interface_index_map(cmdb_interfaces: Any) -> dict[int, str]:
    """Map the FortiGate interface index (devindex) to its name.

    LLDP neighbors report the local port as this index, not as a name.
    """
    mapping: dict[int, str] = {}
    for item in cmdb_interfaces or []:
        if not isinstance(item, dict):
            continue
        index = item.get("devindex")
        name = item.get("name")
        if isinstance(index, int) and name:
            mapping[index] = str(name)
    return mapping


def _interfaces_by_name(monitor_interfaces: Any) -> dict[str, dict[str, Any]]:
    if isinstance(monitor_interfaces, dict):
        items = list(monitor_interfaces.values())
    elif isinstance(monitor_interfaces, list):
        items = monitor_interfaces
    else:
        items = []
    return {str(item.get("name")): item for item in items if isinstance(item, dict) and item.get("name")}


def _ip_with_mask(iface: dict[str, Any]) -> str | None:
    ip = iface.get("ip")
    if not ip or ip == "0.0.0.0":
        return None
    mask = iface.get("mask")
    return f"{ip}/{mask}" if mask not in (None, "", 0) else str(ip)


def summarize_neighbors(
    neighbors: Any,
    index_map: dict[int, str],
    monitor_interfaces: Any,
) -> list[dict[str, Any]]:
    """One row per LLDP neighbor, with the local port shown by name."""
    interfaces = _interfaces_by_name(monitor_interfaces)
    rows = []
    for item in neighbors or []:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        local = index_map.get(port) if isinstance(port, int) else None
        iface = interfaces.get(local or "", {})
        rows.append(
            {
                "local_port": local or (f"index {port}" if port is not None else None),
                "local_alias": iface.get("alias") or None,
                "local_ip": _ip_with_mask(iface) if iface else None,
                "neighbor": item.get("system_name") or item.get("chassis_id"),
                "neighbor_port": item.get("port_id"),
                "neighbor_port_description": item.get("port_desc"),
                "neighbor_ip": _neighbor_ip(item),
                "neighbor_platform": _first_line(item.get("system_desc")),
            }
        )
    rows.sort(key=lambda row: str(row.get("local_port") or ""))
    return rows


def _label(text: Any) -> str:
    cleaned = re.sub(r'["\[\]{}()<>|]', " ", str(text or "")).strip()
    return re.sub(r"\s+", " ", cleaned) or "unknown"


def topology_mermaid(
    device: str,
    management_ip: str | None,
    links: list[dict[str, Any]],
    gateways: list[dict[str, Any]],
    vpn_peers: list[dict[str, Any]],
) -> str:
    """A Mermaid diagram with the firewall in the middle."""
    title = _label(device) + (f" {management_ip}" if management_ip else "")
    lines = ["graph LR", f'  fw["{title}"]']
    node_ids: dict[str, str] = {}

    def node(key: str, text: str) -> str:
        if key not in node_ids:
            node_ids[key] = f"n{len(node_ids) + 1}"
            lines.append(f'  {node_ids[key]}["{_label(text)}"]')
        return node_ids[key]

    for link in links:
        name = link.get("neighbor") or "unknown neighbor"
        text = name + (f" {link['neighbor_ip']}" if link.get("neighbor_ip") else "")
        target = node(f"nbr:{name}", text)
        edge = _label(f"{link.get('local_port')} to {link.get('neighbor_port') or '?'}")
        lines.append(f'  fw ---|"{edge}"| {target}')
    for gateway in gateways:
        target = node(f"gw:{gateway.get('gateway')}", f"gateway {gateway.get('gateway')}")
        edge = _label(f"{gateway.get('destination')} via {gateway.get('interface')}")
        lines.append(f'  fw -.->|"{edge}"| {target}')
    for peer in vpn_peers:
        target = node(f"vpn:{peer.get('name')}", f"{peer.get('name')} {peer.get('remote_gateway') or ''}")
        edge = _label(f"IPsec {peer.get('status')}")
        lines.append(f'  fw ==>|"{edge}"| {target}')
    return "\n".join(lines)


def static_gateways(routes: Any) -> list[dict[str, Any]]:
    """Distinct static next hops from the live route table, default route first."""
    seen = set()
    rows = []
    for route in routes or []:
        if not isinstance(route, dict) or route.get("type") != "static":
            continue
        gateway = route.get("gateway")
        if not gateway or gateway == "0.0.0.0":
            continue
        key = (route.get("ip_mask"), gateway, route.get("interface"))
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "destination": route.get("ip_mask"),
                "gateway": gateway,
                "interface": route.get("interface"),
            }
        )
    rows.sort(key=lambda row: (row.get("destination") != "0.0.0.0/0", str(row.get("destination") or "")))
    return rows


def _version_tuple(text: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(text or ""))
    return tuple(int(part) for part in match.groups()) if match else None


def latest_patch(installed: tuple[int, int, int], catalog: Any) -> str | None:
    """Newest GA build on the same major.minor branch, if newer than installed."""
    best = None
    best_text = None
    for entry in (catalog or {}).get("version_list", []) if isinstance(catalog, dict) else []:
        for item in entry.get("versions") or []:
            if not isinstance(item, dict) or item.get("type") not in (None, "GA"):
                continue
            version = _version_tuple(item.get("version"))
            if not version or version[:2] != installed[:2]:
                continue
            if best is None or version > best:
                best = version
                best_text = item.get("version")
    if best and best > installed:
        return best_text
    return None


def _date(epoch: Any) -> str | None:
    if not isinstance(epoch, (int, float)) or epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def _finding(severity: str, category: str, title: str, detail: str) -> dict[str, Any]:
    return {"severity": severity, "category": category, "title": title, "detail": detail}


def evaluate_alerts(
    device_record: dict[str, Any] | None = None,
    performance: dict[str, Any] | None = None,
    monitor_interfaces: Any = None,
    tunnels: list[dict[str, Any]] | None = None,
    system_events: Any = None,
    threat_counts: dict[str, int] | None = None,
    licenses: Any = None,
    newer_patch: str | None = None,
    installed_version: str | None = None,
    cpu_threshold: float = 80,
    memory_threshold: float = 85,
) -> list[dict[str, Any]]:
    """Health findings computed from live data. These are not Fortinet alerts."""
    findings: list[dict[str, Any]] = []

    record = device_record or {}
    conn = _CONN_STATUS.get(record.get("conn_status"))
    if conn == "down":
        findings.append(
            _finding("high", "connectivity", "Firewall is disconnected from FortiManager",
                     "FortiManager reports the management connection as down.")
        )
    conf = _CONF_STATUS.get(record.get("conf_status"))
    if conf == "out_of_sync":
        findings.append(
            _finding("medium", "sync", "Firewall configuration is out of sync",
                     "The firewall configuration differs from FortiManager's copy.")
        )

    perf = performance or {}
    cpu = (perf.get("cpu") or {}).get("utilization_percent")
    if isinstance(cpu, (int, float)) and cpu >= cpu_threshold:
        findings.append(
            _finding("high", "performance", f"CPU at {cpu}%", f"CPU is at or above {cpu_threshold}%.")
        )
    memory = (perf.get("memory") or {}).get("used_percent")
    if isinstance(memory, (int, float)) and memory >= memory_threshold:
        findings.append(
            _finding("high", "performance", f"Memory at {memory}%",
                     f"Memory use is at or above {memory_threshold}%.")
        )

    for name, iface in sorted(_interfaces_by_name(monitor_interfaces).items()):
        address = _ip_with_mask(iface)
        if address and not iface.get("link"):
            findings.append(
                _finding("low", "interface", f"Interface {name} is down",
                         f"{name} has address {address} configured but no link.")
            )

    for tunnel in tunnels or []:
        if tunnel.get("status") == "down":
            findings.append(
                _finding("medium", "vpn", f"IPsec tunnel {tunnel.get('name')} is down",
                         f"No phase-2 is up to remote gateway {tunnel.get('remote_gateway')}.")
            )

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for event in system_events or []:
        if not isinstance(event, dict):
            continue
        severity = _EVENT_SEVERITY.get(str(event.get("level") or "").lower())
        if not severity:
            continue
        desc = event.get("logdesc") or event.get("msg") or "event"
        key = (severity, str(desc))
        entry = grouped.setdefault(key, {"count": 0, "level": event.get("level"), "latest": None})
        entry["count"] += 1
        if entry["latest"] is None:
            entry["latest"] = f"{event.get('date')} {event.get('time')}"
    for (severity, desc), entry in grouped.items():
        findings.append(
            _finding(severity, "event", f"{entry['level']} event: {desc}",
                     f"{entry['count']} in the recent system log, latest {entry['latest']}.")
        )

    for kind, count in sorted((threat_counts or {}).items()):
        if count:
            findings.append(
                _finding("medium", "threat", f"{count} recent {kind} detections",
                         f"The firewall recorded {kind} detections in its recent log.")
            )

    expired: dict[str, list[str]] = {}
    if isinstance(licenses, dict):
        for name, item in licenses.items():
            if isinstance(item, dict) and item.get("status") == "expired":
                expired.setdefault(_date(item.get("expires")) or "unknown date", []).append(name)
    for when, names in sorted(expired.items()):
        findings.append(
            _finding("medium", "license", f"{len(names)} FortiGuard services expired",
                     f"Expired {when}: {', '.join(sorted(names))}.")
        )

    if newer_patch:
        findings.append(
            _finding("low", "firmware", f"Newer FortiOS patch {newer_patch} available",
                     f"Installed {installed_version}; {newer_patch} is the newest build on the same branch.")
        )

    findings.sort(key=lambda item: (_SEVERITY_ORDER.get(item["severity"], 9), item["category"], item["title"]))
    return findings


def alert_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return counts
