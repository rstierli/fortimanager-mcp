"""Summaries for the live FortiGate health tools."""

from fortimanager_mcp.tools.device_health_summary import (
    log_resource,
    summarize_interface_counters,
    summarize_logs,
    summarize_performance,
    unwrap_proxy,
)


def test_performance_summary_uses_idle_and_reboot_clock():
    summary = summarize_performance(
        performance={
            "cpu": {"user": 1, "system": 2, "idle": 97, "iowait": 0, "cores": [{}, {}]},
            "mem": {"total": 200 * 1024 * 1024, "used": 50 * 1024 * 1024, "free": 150 * 1024 * 1024},
        },
        usage={"session": [{"current": 23, "historical": {"1-min": {"average": 24, "max": 29, "values": [1]}}}]},
        ui_state={"utc_last_reboot": 1_000_000, "snapshot_utc_time": 1_000_000 + 90_000},
    )
    assert summary["cpu"]["utilization_percent"] == 3
    assert summary["cpu"]["core_count"] == 2
    assert summary["memory"]["used_mb"] == 50
    assert summary["memory"]["used_percent"] == 25
    assert summary["sessions"]["current"] == 23
    assert "values" not in summary["sessions"]
    assert summary["uptime_seconds"] == 90
    assert summary["uptime"] == "0d 0h 1m"


def test_interface_counters_mark_link_and_keep_bytes():
    rows = summarize_interface_counters(
        {"wan1": {"name": "wan1", "link": True, "tx_bytes": 10, "rx_bytes": 4, "tx_errors": 0}}
    )
    assert rows[0]["link"] == "up"
    assert rows[0]["tx_bytes"] == 10


def test_logs_drop_empty_fields_and_reject_unknown_type():
    rows = summarize_logs("traffic", [{"srcip": "10.0.0.1", "dstip": "1.1.1.1", "msg": ""}])
    assert rows == [{"srcip": "10.0.0.1", "dstip": "1.1.1.1"}]
    try:
        log_resource("syslog", 20)
    except ValueError as exc:
        assert "traffic" in str(exc)
    else:
        raise AssertionError("syslog is not a FortiGate log type")


def test_proxy_error_is_not_treated_as_data():
    results, err = unwrap_proxy([{"status": {"code": -6, "message": "Invalid url"}, "response": {}}])
    assert results is None
    assert err["status"] == "error"
