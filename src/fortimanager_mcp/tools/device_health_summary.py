"""Pure summaries of live FortiGate monitor and log payloads.

FortiManager's device-status call does not include CPU, memory, interface
counters, or logs. Those come from the FortiGate monitor and log APIs, which
FortiManager proxies. These helpers keep the chat payload small.
"""

from typing import Any

_LOG_PATHS = {
    "traffic": "/api/v2/log/disk/traffic/forward",
    "system": "/api/v2/log/disk/event/system",
    "ips": "/api/v2/log/disk/ips",
    "virus": "/api/v2/log/disk/virus",
    "webfilter": "/api/v2/log/disk/webfilter",
    "app-ctrl": "/api/v2/log/disk/app-ctrl",
}

_TRAFFIC_FIELDS = (
    "date",
    "time",
    "srcip",
    "srcport",
    "dstip",
    "dstport",
    "srcintf",
    "dstintf",
    "action",
    "policyid",
    "service",
    "app",
    "sentbyte",
    "rcvdbyte",
    "duration",
)
_SYSTEM_FIELDS = ("date", "time", "level", "logdesc", "action", "msg")
_THREAT_FIELDS = (
    "date",
    "time",
    "level",
    "subtype",
    "srcip",
    "dstip",
    "action",
    "service",
    "msg",
    "attack",
    "virus",
    "app",
    "url",
    "hostname",
)

_COUNTER_FIELDS = (
    "name",
    "alias",
    "ip",
    "link",
    "speed",
    "duplex",
    "tx_packets",
    "rx_packets",
    "tx_bytes",
    "rx_bytes",
    "tx_errors",
    "rx_errors",
)


def log_resource(log_type: str, rows: int) -> str:
    """FortiGate disk-log URL for a supported log type."""
    path = _LOG_PATHS.get(log_type)
    if not path:
        raise ValueError(
            f"log_type must be one of: {', '.join(sorted(_LOG_PATHS))}"
        )
    return f"{path}?rows={clamp_rows(rows)}"


def clamp_rows(rows: int) -> int:
    try:
        count = int(rows)
    except (TypeError, ValueError):
        count = 20
    return max(1, min(count, 50))


def unwrap_proxy(result: Any) -> tuple[Any, dict[str, Any] | None]:
    """Return FortiGate ``results``, or an error dict when the proxy failed."""
    item = result[0] if isinstance(result, list) and result else result
    if not isinstance(item, dict):
        return None, {"status": "error", "message": "Unexpected FortiManager proxy response"}
    fmg = item.get("status") or {}
    code = fmg.get("code") if isinstance(fmg, dict) else None
    if code not in (0, None):
        return None, {
            "status": "error",
            "message": (fmg.get("message") if isinstance(fmg, dict) else None)
            or "FortiManager proxy failed",
            "error_code": code,
        }
    response = item.get("response") or {}
    if not isinstance(response, dict):
        return None, {"status": "error", "message": "Unexpected FortiGate response"}
    if response.get("status") == "error":
        return None, {
            "status": "error",
            "message": "FortiGate API returned an error",
            "error_code": code,
        }
    return response.get("results"), None


def _mb(value: Any) -> float | None:
    if not isinstance(value, (int, float)):
        return None
    return round(value / (1024 * 1024), 1)


def _as_block(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        value = value[0] if value else {}
    return value if isinstance(value, dict) else {}


def _sample(block: Any) -> dict[str, Any]:
    block = _as_block(block)
    if not block:
        return {}
    window = (block.get("historical") or {}).get("1-min") or {}
    return {
        "current": block.get("current"),
        "one_min_average": window.get("average"),
        "one_min_max": window.get("max"),
    }


def summarize_performance(
    performance: Any,
    usage: Any,
    ui_state: Any,
) -> dict[str, Any]:
    """CPU, memory, sessions, and uptime from three FortiGate monitor calls."""
    cpu = (performance or {}).get("cpu") if isinstance(performance, dict) else {}
    mem = (performance or {}).get("mem") if isinstance(performance, dict) else {}
    cpu = cpu if isinstance(cpu, dict) else {}
    mem = mem if isinstance(mem, dict) else {}
    idle = cpu.get("idle")
    total = mem.get("total")
    used = mem.get("used")
    cores = cpu.get("cores")
    usage = usage if isinstance(usage, dict) else {}
    ui_state = ui_state if isinstance(ui_state, dict) else {}

    uptime_seconds = None
    reboot = ui_state.get("utc_last_reboot")
    now = ui_state.get("snapshot_utc_time")
    if isinstance(reboot, (int, float)) and isinstance(now, (int, float)) and now >= reboot:
        uptime_seconds = int((now - reboot) / 1000)

    return {
        "cpu": {
            "utilization_percent": None if not isinstance(idle, (int, float)) else round(100 - idle, 1),
            "user_percent": cpu.get("user"),
            "system_percent": cpu.get("system"),
            "iowait_percent": cpu.get("iowait"),
            "idle_percent": idle,
            "core_count": len(cores) if isinstance(cores, list) else None,
        },
        "memory": {
            "used_percent": (
                round(100 * used / total, 1)
                if isinstance(used, (int, float)) and isinstance(total, (int, float)) and total
                else None
            ),
            "used_mb": _mb(used),
            "total_mb": _mb(total),
            "free_mb": _mb(mem.get("free")),
        },
        "sessions": _sample(usage.get("session")),
        "setup_rate": _sample(usage.get("setuprate")),
        "disk": _sample(usage.get("disk")),
        "uptime_seconds": uptime_seconds,
        "uptime": _format_uptime(uptime_seconds),
    }


def _format_uptime(seconds: int | None) -> str | None:
    if seconds is None:
        return None
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    return f"{days}d {hours}h {minutes}m"


def summarize_interface_counters(results: Any) -> list[dict[str, Any]]:
    """Compact per-interface packet and byte counters."""
    if isinstance(results, dict):
        items = list(results.values())
    elif isinstance(results, list):
        items = results
    else:
        return []
    rows = []
    for iface in items:
        if not isinstance(iface, dict):
            continue
        row = {key: iface.get(key) for key in _COUNTER_FIELDS}
        row["link"] = "up" if iface.get("link") else "down"
        rows.append(row)
    rows.sort(key=lambda item: (item.get("link") != "up", str(item.get("name") or "")))
    return rows


def summarize_logs(log_type: str, results: Any) -> list[dict[str, Any]]:
    """Keep the columns a chat answer needs from a FortiGate log page."""
    if log_type == "traffic":
        fields = _TRAFFIC_FIELDS
    elif log_type == "system":
        fields = _SYSTEM_FIELDS
    else:
        fields = _THREAT_FIELDS
    if not isinstance(results, list):
        return []
    rows = []
    for item in results:
        if not isinstance(item, dict):
            continue
        rows.append({key: item.get(key) for key in fields if item.get(key) not in (None, "")})
    return rows
