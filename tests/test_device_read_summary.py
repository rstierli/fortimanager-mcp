"""Summaries for routes, policy counters, IPsec status, and package compare."""

from fortimanager_mcp.tools.device_read_summary import (
    compare_policies,
    summarize_hit_counters,
    summarize_ipsec_tunnels,
    summarize_routes,
    summarize_static_routes,
)


def test_routes_keep_destination_gateway_and_interface():
    rows = summarize_routes(
        [
            {"type": "connect", "ip_mask": "172.17.0.0/24", "gateway": "0.0.0.0", "interface": "port1", "distance": 0, "metric": 0},
            {"type": "static", "ip_mask": "0.0.0.0/0", "gateway": "172.17.0.26", "interface": "wan1", "distance": 10, "metric": 0},
        ]
    )
    assert rows[0]["destination"] == "0.0.0.0/0"
    assert rows[0]["gateway"] == "172.17.0.26"
    assert rows[0]["interface"] == "wan1"


def test_static_routes_use_the_device_field_as_interface():
    rows = summarize_static_routes(
        [{"dst": "10.0.0.0 255.0.0.0", "gateway": "172.17.0.26", "device": "wan1", "status": "enable", "distance": 10}]
    )
    assert rows[0]["interface"] == "wan1"
    assert rows[0]["status"] == "enable"


def test_hit_counters_mark_policy_zero_as_implicit():
    rows = summarize_hit_counters(
        [{"policyid": 0, "packets": 10, "bytes": 100, "active_sessions": 0, "asic_bytes": 1}]
    )
    assert rows[0]["implicit"] is True
    assert rows[0]["packets"] == 10
    assert "asic_bytes" not in rows[0]


def test_ipsec_tunnel_is_down_when_every_phase2_is_down():
    rows = summarize_ipsec_tunnels(
        [
            {"name": "SJC-MUM-IPSEC", "rgwy": "203.0.113.10", "proxyid": [{"p2name": "SJC-MUM-IPSEC", "status": "down"}]},
            {"name": "UP-TUN", "rgwy": "203.0.113.11", "proxyid": [{"p2name": "p2", "status": "up"}]},
        ]
    )
    by_name = {row["name"]: row["status"] for row in rows}
    assert by_name["SJC-MUM-IPSEC"] == "down"
    assert by_name["UP-TUN"] == "up"


def test_compare_treats_package_integers_as_disable_and_deny():
    compared = compare_policies(
        package_rows=[
            {
                "policyid": 1,
                "name": "sandbox-test",
                "status": 0,
                "action": 0,
                "srcintf": ["port1"],
                "dstintf": ["wan1"],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["ALL"],
            }
        ],
        device_rows=[
            {
                "policyid": 1,
                "name": "sandbox-test",
                "status": "disable",
                "action": "deny",
                "srcintf": [{"name": "port1"}],
                "dstintf": [{"name": "wan1"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "service": [{"name": "ALL"}],
            },
            {
                "policyid": 3,
                "name": "only-on-firewall",
                "status": "enable",
                "action": "accept",
                "srcintf": [{"name": "port1"}],
                "dstintf": [{"name": "wan1"}],
                "srcaddr": ["all"],
                "dstaddr": ["all"],
                "service": ["ALL"],
            },
        ],
    )
    assert compared["match"] is False
    assert compared["different"] == []
    assert compared["only_on_device"][0]["policyid"] == 3
    assert compared["only_in_package"] == []
