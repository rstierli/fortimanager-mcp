"""Topology view and health alerts built from live FortiGate payloads."""

from fortimanager_mcp.tools.device_insight_summary import (
    alert_counts,
    evaluate_alerts,
    interface_index_map,
    latest_patch,
    static_gateways,
    summarize_neighbors,
    topology_mermaid,
)

_CMDB = [
    {"name": "wan1", "devindex": 5},
    {"name": "port1", "devindex": 9},
    {"name": "port7", "devindex": 15},
]
_MONITOR = {
    "wan1": {"name": "wan1", "link": True, "ip": "172.17.0.25", "mask": 30, "alias": ""},
    "port1": {"name": "port1", "link": True, "ip": "172.17.0.21", "mask": 30, "alias": "(Towards Spine-2)"},
    "dmz": {"name": "dmz", "link": False, "ip": "10.10.10.1", "mask": 24},
    "port6": {"name": "port6", "link": False, "ip": "0.0.0.0", "mask": 0},
}


def test_neighbor_port_index_becomes_interface_name():
    rows = summarize_neighbors(
        [
            {
                "port": 9,
                "system_name": "Spine1",
                "port_id": "Gi1/0/2",
                "addresses": [{"type": "ipv4", "address": "172.17.0.22"}],
                "system_desc": "Cisco IOS Software\nmore",
            },
            {"port": 99, "system_name": "Unknown"},
        ],
        interface_index_map(_CMDB),
        _MONITOR,
    )
    by_neighbor = {row["neighbor"]: row for row in rows}
    assert by_neighbor["Spine1"]["local_port"] == "port1"
    assert by_neighbor["Spine1"]["local_ip"] == "172.17.0.21/30"
    assert by_neighbor["Spine1"]["neighbor_ip"] == "172.17.0.22"
    assert by_neighbor["Spine1"]["neighbor_platform"] == "Cisco IOS Software"
    assert by_neighbor["Unknown"]["local_port"] == "index 99"


def test_static_gateways_skip_connected_and_duplicates():
    rows = static_gateways(
        [
            {"type": "connect", "ip_mask": "172.17.0.24/30", "gateway": "0.0.0.0", "interface": "wan1"},
            {"type": "static", "ip_mask": "10.0.0.0/8", "gateway": "172.17.0.22", "interface": "port1"},
            {"type": "static", "ip_mask": "0.0.0.0/0", "gateway": "172.17.0.26", "interface": "wan1"},
            {"type": "static", "ip_mask": "0.0.0.0/0", "gateway": "172.17.0.26", "interface": "wan1"},
        ]
    )
    assert [row["destination"] for row in rows] == ["0.0.0.0/0", "10.0.0.0/8"]


def test_mermaid_has_no_characters_that_break_labels():
    diagram = topology_mermaid(
        "fgt-lab-29",
        "10.20.11.29",
        [{"local_port": "port1", "neighbor": 'Spine "1" (core)', "neighbor_port": "Gi1/0/2", "neighbor_ip": None}],
        [{"destination": "0.0.0.0/0", "gateway": "172.17.0.26", "interface": "wan1"}],
        [{"name": "SJC-MUM-IPSEC", "remote_gateway": "203.0.113.10", "status": "down"}],
    )
    assert diagram.startswith("graph LR")
    assert '"Spine 1 core"' in diagram
    assert "IPsec down" in diagram


def test_latest_patch_stays_on_the_installed_branch():
    catalog = {
        "version_list": [
            {
                "versions": [
                    {"version": "7.0.12-b0523", "type": "GA"},
                    {"version": "7.0.19-b0696", "type": "GA"},
                    {"version": "7.2.13-b1762", "type": "GA"},
                ]
            }
        ]
    }
    assert latest_patch((7, 0, 12), catalog) == "7.0.19-b0696"
    assert latest_patch((7, 0, 19), catalog) is None


def test_alerts_flag_lab_conditions_and_sort_by_severity():
    findings = evaluate_alerts(
        device_record={"conn_status": 1, "conf_status": 1},
        performance={"cpu": {"utilization_percent": 91.0}, "memory": {"used_percent": 45.5}},
        monitor_interfaces=_MONITOR,
        tunnels=[{"name": "SJC-MUM-IPSEC", "remote_gateway": "203.0.113.10", "status": "down"}],
        system_events=[
            {"level": "notice", "logdesc": "Dynamic address updated"},
            {"level": "critical", "logdesc": "Power supply failure", "date": "2026-10-30", "time": "01:00:00"},
        ],
        threat_counts={"IPS": 0, "antivirus": 3},
        licenses={
            "antivirus": {"status": "expired", "expires": 1682294400},
            "ips": {"status": "expired", "expires": 1682294400},
            "sms": {"status": "no_license"},
        },
        newer_patch="7.0.19-b0696",
        installed_version="7.0.12",
    )
    titles = [item["title"] for item in findings]
    assert findings[0]["severity"] == "high"
    assert "CPU at 91.0%" in titles
    assert "critical event: Power supply failure" in titles
    assert "IPsec tunnel SJC-MUM-IPSEC is down" in titles
    assert "Interface dmz is down" in titles
    assert "Interface port6 is down" not in titles
    assert "3 recent antivirus detections" in titles
    assert not any("IPS detections" in title for title in titles)
    license_alert = next(item for item in findings if item["category"] == "license")
    assert "2023-04-24" in license_alert["detail"]
    assert "sms" not in license_alert["detail"]
    assert alert_counts(findings)["high"] == 2


def test_healthy_device_has_no_alerts():
    findings = evaluate_alerts(
        device_record={"conn_status": 1, "conf_status": 1},
        performance={"cpu": {"utilization_percent": 2.0}, "memory": {"used_percent": 40.0}},
        system_events=[{"level": "notice", "logdesc": "ok"}],
    )
    assert findings == []
