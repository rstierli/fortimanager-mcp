"""Tests for sdwan_tools module (device-DB SD-WAN config read + summary)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import sdwan_tools

# A trimmed but representative system/sdwan object as the device DB returns it.
MOCK_DEVICE_SDWAN = {
    "status": "enable",
    "load-balance-mode": "source-ip-based",
    "zone": [{"name": "virtual-wan-link"}, {"name": "BBI-zone"}],
    "members": [
        {
            "seq-num": 1,
            "interface": "mystier_v_BBI",
            "gateway": "82.197.160.1",
            "zone": "BBI-zone",
            "weight": 70,
            "priority": 0,
            "status": "enable",
        },
        {
            "seq-num": 2,
            "interface": "mystier_v_BBI2",
            "gateway": "46.127.181.1",
            "zone": "BBI-zone",
            "weight": 30,
            "priority": 0,
            "status": "enable",
        },
    ],
    "health-check": [
        {"name": "olay_inet", "server": "1.1.1.1", "members": [1, 2]},
    ],
    "service": [
        {"id": 1, "name": "ZZZ_catch_all", "mode": "sla", "dst": ["all"]},
    ],
}


@pytest.fixture
def mock_client_configured(
    mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
) -> FortiManagerClient:
    """Mock client whose device-DB sdwan GET returns MOCK_DEVICE_SDWAN."""

    def mock_get(url: str, **kwargs):
        if url.endswith("/system/sdwan"):
            return (0, MOCK_DEVICE_SDWAN)
        return (0, {})

    mock_fmg_instance.get.side_effect = mock_get
    return mock_client


class TestGetDeviceSdwan:
    @pytest.mark.asyncio
    async def test_success_returns_raw_and_summary(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await sdwan_tools.get_device_sdwan(device="myfw01")

        assert result["device"] == "myfw01"
        assert result["vdom"] == "root"
        assert result["sdwan"] == MOCK_DEVICE_SDWAN

        summary = result["summary"]
        assert summary["status"] == "enable"
        assert summary["load_balance_mode"] == "source-ip-based"
        assert summary["member_count"] == 2
        assert [m["interface"] for m in summary["members"]] == [
            "mystier_v_BBI",
            "mystier_v_BBI2",
        ]
        assert summary["zones"] == ["virtual-wan-link", "BBI-zone"]
        assert summary["health_checks"][0]["name"] == "olay_inet"
        assert summary["service_rule_count"] == 1

    @pytest.mark.asyncio
    async def test_hits_device_db_path_not_template(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client_configured):
            await sdwan_tools.get_device_sdwan(device="myfw01", vdom="root")

        called_url = mock_fmg_instance.get.call_args[0][0]
        assert called_url == "/pm/config/device/myfw01/vdom/root/system/sdwan"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=None):
            result = await sdwan_tools.get_device_sdwan(device="myfw01")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_device_name_is_rejected(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await sdwan_tools.get_device_sdwan(device="bad name; drop")
        assert "error" in result


class TestSummarizeSdwanRobustness:
    def test_empty_object(self) -> None:
        summary = sdwan_tools._summarize_sdwan({})
        assert summary["member_count"] == 0
        assert summary["members"] == []
        assert summary["zones"] == []
        assert summary["service_rule_count"] == 0

    def test_off_shape_fields_do_not_crash(self) -> None:
        # members as a single dict, zone as a bare string, service missing
        summary = sdwan_tools._summarize_sdwan(
            {"members": {"seq-num": 9, "interface": "wan1"}, "zone": "not-a-list"}
        )
        assert summary["member_count"] == 1
        assert summary["members"][0]["interface"] == "wan1"
        assert summary["zones"] == []


# A trimmed ADOM object-level system/sdwan object (neutral values only).
# Proxy-response envelopes as virtual-wan/members and health-check return them.
MOCK_SDWAN_MEMBERS = [
    {
        "response": {
            "results": [
                {
                    "interface": "wan1",
                    "seq_num": 1,
                    "link": "up",
                    "tx_bandwidth": 1000,
                    "rx_bandwidth": 2000,
                    "tx_bytes": 111,
                    "rx_bytes": 222,
                },
                {
                    "interface": "wan2",
                    "seq_num": 2,
                    "link": "down",
                    "tx_bandwidth": 0,
                    "rx_bandwidth": 0,
                    "tx_bytes": 0,
                    "rx_bytes": 0,
                },
            ],
            "status": "success",
        },
        "status": {"code": 0, "message": "OK"},
        "target": "FGT-HQ",
    }
]

MOCK_SDWAN_HEALTH = [
    {
        "response": {
            "results": {
                "HC_PING": {
                    "wan1": {
                        "status": "up",
                        "latency": 8.5,
                        "jitter": 1.2,
                        "packet_loss": 0.0,
                        "sla_targets_met": [1],
                    },
                    "wan2": {
                        "status": "down",
                        "latency": 0.0,
                        "jitter": 0.0,
                        "packet_loss": 100.0,
                        "sla_targets_met": [],
                    },
                }
            },
            "status": "success",
        },
        "status": {"code": 0},
        "target": "FGT-HQ",
    }
]

MOCK_DATASRC = {
    "data": [
        {"name": "Google-Other", "id": 1},
        {"name": "Microsoft-Office365", "id": 2},
    ]
}


def _monitor_client() -> AsyncMock:
    """An async client whose proxy_call returns the canned monitor envelopes."""

    def proxy(action: str, resource: str, target: list) -> list:
        if "members" in resource:
            return MOCK_SDWAN_MEMBERS
        if "health-check" in resource:
            return MOCK_SDWAN_HEALTH
        return []

    client = AsyncMock()
    client.proxy_call = AsyncMock(side_effect=proxy)
    return client


@pytest.fixture
def mock_client_adom(
    mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
) -> FortiManagerClient:
    """Mock client for datasource (option=datasrc) GETs."""

    def mock_get(url: str, **kwargs):
        if kwargs.get("option") == "datasrc":
            return (0, MOCK_DATASRC)
        return (0, {})

    mock_fmg_instance.get.side_effect = mock_get
    return mock_client


class TestGetDeviceSdwanMonitor:
    @pytest.mark.asyncio
    async def test_success_returns_raw_and_summary(self) -> None:
        client = _monitor_client()
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_sdwan_monitor(adom="root", device="FGT-HQ")

        assert result["device"] == "FGT-HQ"
        assert result["members"] == MOCK_SDWAN_MEMBERS
        assert result["health_check"] == MOCK_SDWAN_HEALTH

        summary = result["summary"]
        assert summary["member_count"] == 2
        assert summary["members_up"] == 1  # wan1 up, wan2 down
        assert [m["interface"] for m in summary["members"]] == ["wan1", "wan2"]
        assert summary["health_checks"] == ["HC_PING"]
        assert summary["sla_entry_count"] == 2
        wan1_sla = next(s for s in summary["sla"] if s["interface"] == "wan1")
        assert wan1_sla["status"] == "up"
        assert wan1_sla["sla_targets_met"] == [1]

    @pytest.mark.asyncio
    async def test_hits_both_monitor_endpoints(self) -> None:
        client = _monitor_client()
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            await sdwan_tools.get_device_sdwan_monitor(adom="root", device="FGT-HQ")

        resources = [c.kwargs["resource"] for c in client.proxy_call.call_args_list]
        assert "/api/v2/monitor/virtual-wan/members" in resources
        assert "/api/v2/monitor/virtual-wan/health-check" in resources

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=None):
            result = await sdwan_tools.get_device_sdwan_monitor(adom="root", device="FGT-HQ")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_device_name_is_rejected(self) -> None:
        client = _monitor_client()
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_sdwan_monitor(
                adom="root", device="bad name; drop"
            )
        assert "error" in result


MOCK_BGP_NEIGHBORS = [
    {
        "neighbor_ip": "172.16.255.252",
        "local_ip": "172.16.0.3",
        "remote_as": 65000,
        "admin_status": True,
        "state": "Established",
        "type": "ipv4",
    },
    {
        "neighbor_ip": "172.16.255.251",
        "local_ip": "0.0.0.0",
        "remote_as": 65000,
        "admin_status": True,
        "state": "Connect",
        "type": "ipv4",
    },
]
MOCK_BGP_PATHS = [
    {
        "nlri_prefix": "10.0.96.0",
        "nlri_prefix_len": 21,
        "learned_from": "0.0.0.0",
        "next_hop": "0.0.0.0",
        "is_best": True,
    },
    {
        "nlri_prefix": "10.1.0.0",
        "nlri_prefix_len": 24,
        "learned_from": "172.16.255.252",
        "next_hop": "172.16.255.252",
        "is_best": True,
    },
]
MOCK_ROUTES = [
    {"type": "connect", "ip_mask": "10.0.96.0/21", "interface": "port3", "distance": 0},
    {
        "type": "bgp",
        "ip_mask": "10.1.0.0/24",
        "gateway": "172.16.255.252",
        "interface": "HUB1-VPN1",
        "distance": 200,
        "metric": 0,
    },
]


def _proxied(results: object) -> list[dict]:
    return [{"response": {"results": results}, "status": {"code": 0, "message": "OK"}}]


def _bgp_client(fail: frozenset[str] = frozenset()) -> AsyncMock:
    """Client whose proxy answers the BGP monitor endpoints."""
    answers = {
        "/api/v2/monitor/router/bgp/neighbors": MOCK_BGP_NEIGHBORS,
        "/api/v2/monitor/router/bgp/paths": MOCK_BGP_PATHS,
        "/api/v2/monitor/router/ipv4": MOCK_ROUTES,
    }

    async def proxy(action: str, resource: str, target: list[str]) -> list[dict]:
        if resource in fail:
            return [{"status": {"code": -1, "message": "device unreachable"}}]
        return _proxied(answers[resource])

    client = AsyncMock()
    client.proxy_call = AsyncMock(side_effect=proxy)
    return client


class TestGetDeviceBgpStatus:
    @pytest.mark.asyncio
    async def test_reports_peers_paths_and_routes(self) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=_bgp_client()):
            result = await sdwan_tools.get_device_bgp_status(adom="root", device="branch1")

        summary = result["summary"]
        assert result["unverified"] == []
        assert summary["neighbor_count"] == 2
        assert summary["established_count"] == 1
        assert summary["local_path_count"] == 1
        assert summary["learned_path_count"] == 1
        assert summary["learned_paths"][0]["prefix"] == "10.1.0.0/24"
        assert [r["prefix"] for r in summary["bgp_routes"]] == ["10.1.0.0/24"]

    @pytest.mark.asyncio
    async def test_targets_the_device(self) -> None:
        client = _bgp_client()
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            await sdwan_tools.get_device_bgp_status(adom="root", device="branch1")

        targets = {tuple(c.kwargs["target"]) for c in client.proxy_call.call_args_list}
        assert targets == {("/adom/root/device/branch1",)}

    @pytest.mark.asyncio
    async def test_unreadable_source_is_listed(self) -> None:
        client = _bgp_client(frozenset({"/api/v2/monitor/router/ipv4"}))
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp_status(adom="root", device="branch1")

        assert result["summary"]["established_count"] == 1
        assert result["summary"]["bgp_route_count"] == 0
        assert result["unverified"] == ["routing table: device unreachable"]

    @pytest.mark.asyncio
    async def test_all_sources_unreadable_is_an_error(self) -> None:
        client = _bgp_client(
            frozenset(
                {
                    "/api/v2/monitor/router/bgp/neighbors",
                    "/api/v2/monitor/router/bgp/paths",
                    "/api/v2/monitor/router/ipv4",
                }
            )
        )
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp_status(adom="root", device="branch1")

        assert result["error_code"] == "device_proxy_error"
        assert "summary" not in result

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=None):
            result = await sdwan_tools.get_device_bgp_status(adom="root", device="branch1")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_device_name_is_rejected(self) -> None:
        client = _bgp_client()
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp_status(adom="root", device="bad name; drop")
        assert "error" in result
        client.proxy_call.assert_not_called()


class TestSummarizeSdwanMonitorRobustness:
    def test_empty_or_none(self) -> None:
        summary = sdwan_tools._summarize_sdwan_monitor(None, None)
        assert summary["member_count"] == 0
        assert summary["members_up"] == 0
        assert summary["sla"] == []
        assert summary["health_checks"] == []

    def test_off_shape_envelopes_do_not_crash(self) -> None:
        # members results not a list; health results not a dict
        summary = sdwan_tools._summarize_sdwan_monitor(
            [{"response": {"results": "nope"}}], {"weird": 1}
        )
        assert summary["member_count"] == 0
        assert summary["sla_entry_count"] == 0


class TestResolveDatasource:
    @pytest.mark.asyncio
    async def test_success_passes_option_and_attr(
        self, mock_client_adom: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client_adom):
            result = await sdwan_tools.resolve_datasource(
                url="pm/config/adom/root/obj/system/sdwan",
                attr="service/internet-service-name",  # nested attr path (has a slash)
            )

        assert result["datasource"] == MOCK_DATASRC
        assert result["url"] == "pm/config/adom/root/obj/system/sdwan"
        assert result["attr"] == "service/internet-service-name"
        kwargs = mock_fmg_instance.get.call_args.kwargs
        assert kwargs["option"] == "datasrc"
        assert kwargs["attr"] == "service/internet-service-name"

    @pytest.mark.asyncio
    async def test_leading_slash_url_accepted(self, mock_client_adom: FortiManagerClient) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client_adom):
            result = await sdwan_tools.resolve_datasource(
                url="/pm/config/adom/root/obj/system/sdwan",
                attr="service",
            )
        assert "error" not in result

    @pytest.mark.asyncio
    async def test_non_config_url_is_rejected(self, mock_client_adom: FortiManagerClient) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client_adom):
            result = await sdwan_tools.resolve_datasource(
                url="/sys/status",
                attr="service",
            )
        assert result["error_code"] == "invalid_url"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=None):
            result = await sdwan_tools.resolve_datasource(
                url="pm/config/adom/root/obj/system/sdwan", attr="service"
            )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_attr_is_rejected(self, mock_client_adom: FortiManagerClient) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client_adom):
            result = await sdwan_tools.resolve_datasource(
                url="pm/config/adom/root/obj/system/sdwan", attr="bad;attr"
            )
        assert "error" in result


# ---------------------------------------------------------------------------
# Template bodies, BGP and static routes (overlay documentation reads)
# ---------------------------------------------------------------------------

#: Invented value; asserted absent from every result below.
SECRET = "not-a-real-password"

MOCK_SDWAN_WITH_SECRET = {
    "status": "enable",
    "members": [{"seq-num": 1, "interface": "port1", "zone": "WAN1"}],
    "health-check": [
        {"name": "http_probe", "server": "192.0.2.10", "protocol": "http", "password": SECRET}
    ],
}

MOCK_BGP = {
    "as": 65000,
    "router-id": "172.16.255.253",
    "ibgp-multipath": "enable",
    "neighbor": [{"ip": "192.0.2.1", "remote-as": 65000, "password": SECRET}],
    "neighbor-group": [
        {
            "name": "EDGE",
            "remote-as": 65000,
            "interface": "HUB1-Lo",
            "update-source": "HUB1-Lo",
            "route-reflector-client": "enable",
            "password": SECRET,
        }
    ],
    "neighbor-range": [
        {"id": 1, "prefix": ["172.16.0.0", "255.255.0.0"], "neighbor-group": "EDGE"}
    ],
    "network": [{"id": 1, "prefix": ["10.1.0.0", "255.255.255.0"]}],
}

MOCK_STATIC = [
    {"seq-num": 1, "dst": ["0.0.0.0", "0.0.0.0"], "sdwan-zone": ["WAN1"], "status": "enable"},
    {"seq-num": 2, "dst": ["10.0.0.0", "255.0.0.0"], "blackhole": "enable", "distance": 254},
]


def _client_returning(mock_client: FortiManagerClient, mock_fmg_instance: MagicMock, payload):
    mock_fmg_instance.get.side_effect = lambda url, **kwargs: (0, payload)
    return mock_client


class TestGetSdwanTemplateConfig:
    @pytest.mark.asyncio
    async def test_reads_the_template_body_not_the_metadata(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_SDWAN_WITH_SECRET)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_sdwan_template_config(adom="production", name="tpl")

        called_url = mock_fmg_instance.get.call_args[0][0]
        assert called_url == "/pm/config/adom/production/wanprof/tpl/system/sdwan"
        assert result["summary"]["member_count"] == 1
        assert result["summary"]["health_checks"][0]["name"] == "http_probe"

    @pytest.mark.asyncio
    async def test_probe_password_is_stripped(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_SDWAN_WITH_SECRET)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_sdwan_template_config(adom="production", name="tpl")
        assert SECRET not in repr(result)

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(sdwan_tools, "get_fmg_client", return_value=None):
            result = await sdwan_tools.get_sdwan_template_config(adom="root", name="tpl")
        assert "error" in result


class TestDeviceSdwanStripsProbePassword:
    """The device-DB read shares the schema, so it carried the same leak."""

    @pytest.mark.asyncio
    async def test_probe_password_is_stripped(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_SDWAN_WITH_SECRET)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_sdwan(device="myfw01")
        assert SECRET not in repr(result)
        assert result["sdwan"]["health-check"][0]["name"] == "http_probe"


class TestGetBgpTemplate:
    @pytest.mark.asyncio
    async def test_reads_the_template_body(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_BGP)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_bgp_template(adom="production", name="sites_HUB1_BGP")

        called_url = mock_fmg_instance.get.call_args_list[0][0][0]
        assert (
            called_url == "/pm/config/adom/production/template/router_bgp/sites_HUB1_BGP/router/bgp"
        )
        assert result["summary"]["as"] == 65000
        assert result["summary"]["neighbor_groups"][0]["route_reflector_client"] == "enable"

    @pytest.mark.asyncio
    async def test_route_reflector_client_is_read_by_name(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """A full read omits the field; only a read naming it returns it."""
        base = "/pm/config/adom/production/template/router_bgp/sites_HUB1_BGP/router/bgp"

        def mock_get(url: str, **kwargs: object) -> tuple[int, object]:
            if url == base:
                return (0, {"as": "65000", "neighbor-group": [{"name": "EDGE"}]})
            assert url == f"{base}/neighbor-group"
            assert kwargs["fields"] == ["name", "route-reflector-client"]
            return (0, [{"name": "EDGE", "route-reflector-client": 1}])

        mock_fmg_instance.get.side_effect = mock_get
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client):
            result = await sdwan_tools.get_bgp_template(adom="production", name="sites_HUB1_BGP")

        assert result["summary"]["neighbor_groups"][0]["route_reflector_client"] == 1

    @pytest.mark.asyncio
    async def test_failed_flag_read_keeps_the_template(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        base = "/pm/config/adom/production/template/router_bgp/sites_HUB1_BGP/router/bgp"

        def mock_get(url: str, **kwargs: object) -> tuple[int, object]:
            if url == base:
                return (0, {"as": "65000", "neighbor-group": [{"name": "EDGE"}]})
            return (-11, {"status": {"code": -11, "message": "No permission"}})

        mock_fmg_instance.get.side_effect = mock_get
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client):
            result = await sdwan_tools.get_bgp_template(adom="production", name="sites_HUB1_BGP")

        assert result["summary"]["as"] == "65000"
        assert result["summary"]["neighbor_groups"][0]["route_reflector_client"] is None

    @pytest.mark.asyncio
    async def test_neighbor_passwords_are_stripped(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_BGP)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_bgp_template(adom="production", name="tpl")
        assert SECRET not in repr(result)


class TestGetDeviceBgp:
    @pytest.mark.asyncio
    async def test_success_returns_raw_and_summary(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_BGP)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp(device="hub01")

        called_url = mock_fmg_instance.get.call_args[0][0]
        assert called_url == "/pm/config/device/hub01/vdom/root/router/bgp"
        summary = result["summary"]
        assert summary["router_id"] == "172.16.255.253"
        assert summary["neighbor_count"] == 1
        assert summary["neighbor_ranges"][0]["neighbor_group"] == "EDGE"
        assert summary["network_count"] == 1

    @pytest.mark.asyncio
    async def test_neighbor_and_group_passwords_are_stripped(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_BGP)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp(device="hub01")
        assert SECRET not in repr(result)

    @pytest.mark.asyncio
    async def test_summary_only_leaves_out_the_raw_object(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_BGP)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp(device="hub01", summary_only=True)

        assert "bgp" not in result
        assert result["summary"]["as"] == 65000

    @pytest.mark.asyncio
    async def test_invalid_device_name_is_rejected(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_BGP)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp(device="bad name; drop")
        assert "error" in result

    def test_summary_tolerates_empty_and_off_shape(self) -> None:
        assert sdwan_tools._summarize_bgp({})["neighbor_count"] == 0
        summary = sdwan_tools._summarize_bgp({"neighbor": {"ip": "192.0.2.9"}, "network": "x"})
        assert summary["neighbors"][0]["ip"] == "192.0.2.9"
        assert summary["networks"] == []


class TestGetDeviceStaticRoutes:
    @pytest.mark.asyncio
    async def test_success_returns_raw_and_summary(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        client = _client_returning(mock_client, mock_fmg_instance, MOCK_STATIC)
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_static_routes(device="branch1")

        called_url = mock_fmg_instance.get.call_args[0][0]
        assert called_url == "/pm/config/device/branch1/vdom/root/router/static"
        assert result["route_count"] == 2
        assert result["summary"][0]["sdwan_zone"] == ["WAN1"]
        assert result["summary"][1]["blackhole"] == "enable"


# --- diagnose_ipsec_tunnel ---------------------------------------------------
# Documentation addresses only (RFC 5737); shapes follow the live 7.4.12 proxy
# responses for system/interface, vpn/ipsec and virtual-wan/*.

_SPOKE_GW = {
    "name": "HUB1-VPN2",
    "type": 0,
    "interface": ["port2"],
    "remote-gw": "203.0.113.1",
    "network-id": 2,
    "auto-negotiate": 1,
}
_HUB_GWS = [
    {"name": "VPN1", "type": 1, "interface": ["port1"], "network-id": 1},
    {"name": "VPN2", "type": 1, "interface": ["port2"], "network-id": 2},
]


def _envelope(results: object) -> list[dict]:
    return [{"response": {"results": results}, "status": {"code": 0, "message": "OK"}}]


def _live(
    *,
    link: bool = True,
    ip: str = "192.0.2.10",
    tunnel_up: bool = True,
    hc_status: str = "up",
    sla_met: list | None = None,
    tunnel_listed: bool = True,
) -> dict[str, object]:
    sla = [1] if sla_met is None else sla_met
    vpn = (
        [
            {
                "name": "HUB1-VPN2",
                "rgwy": "203.0.113.1",
                "proxyid": [{"p2name": "HUB1-VPN2", "status": "up" if tunnel_up else "down"}],
            }
        ]
        if tunnel_listed
        else []
    )
    return {
        "system/interface": {"port2": {"name": "port2", "link": link, "ip": ip}},
        "vpn/ipsec": vpn,
        "virtual-wan/members": [
            {"interface": "port2", "link": "up" if link else "down", "state_changed": 1792534744},
            {"interface": "HUB1-VPN2", "link": "up" if tunnel_up else "down"},
        ],
        "virtual-wan/health-check": {
            "HUB1_HC": {
                "HUB1-VPN2": (
                    {"status": hc_status, "latency": 1.5, "packet_loss": 0, "sla_targets_met": sla}
                    if hc_status == "up"
                    else {"status": hc_status}
                )
            }
        },
    }


def _diag_client(
    spoke: dict[str, object],
    hub: dict[str, object] | None = None,
    admin_status: int = 1,
    failing: tuple[str, ...] = (),
) -> AsyncMock:
    async def proxy(action: str, resource: str, target: list[str], data=None):
        live = hub if hub is not None and "datacenter" in target[0] else spoke
        key = resource.removeprefix("/api/v2/monitor/")
        if key in failing:
            raise RuntimeError("proxy timeout")
        return _envelope(live[key])

    client = AsyncMock()
    client.get_device_ipsec_phase1_interface = AsyncMock(return_value=_SPOKE_GW)
    client.get_device_interface_config = AsyncMock(
        return_value=[{"name": "port2", "status": admin_status}]
    )
    client.list_device_ipsec_phase1_interfaces = AsyncMock(return_value=_HUB_GWS)
    client.proxy_call = AsyncMock(side_effect=proxy)
    return client


async def _diagnose(client: AsyncMock, **kwargs: object) -> dict:
    with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
        return await sdwan_tools.diagnose_ipsec_tunnel(
            device="branch2", tunnel="HUB1-VPN2", adom="production", **kwargs
        )


class TestDiagnoseIpsecTunnel:
    @pytest.mark.asyncio
    async def test_underlay_link_down_wins_over_tunnel_state(self) -> None:
        result = await _diagnose(_diag_client(_live(link=False, tunnel_up=False, hc_status="down")))

        assert result["verdict"] == "underlay_link_down"
        assert "port2" in result["explanation"]
        assert "2026-10-20T22:19:04" in result["explanation"]
        assert result["evidence"]["underlay"]["link"] is False
        assert result["evidence"]["gateway"]["remote_gw"] == "203.0.113.1"
        assert result["unverified"] == []

    @pytest.mark.asyncio
    async def test_admin_down_reported_before_link(self) -> None:
        result = await _diagnose(_diag_client(_live(link=False), admin_status=0))
        assert result["verdict"] == "underlay_admin_down"

    @pytest.mark.asyncio
    async def test_underlay_without_address(self) -> None:
        result = await _diagnose(_diag_client(_live(ip="0.0.0.0", tunnel_up=False)))
        assert result["verdict"] == "underlay_no_address"

    @pytest.mark.asyncio
    async def test_tunnel_down_on_healthy_underlay(self) -> None:
        result = await _diagnose(_diag_client(_live(tunnel_up=False, hc_status="down")))

        assert result["verdict"] == "tunnel_down"
        assert any("203.0.113.1" in step for step in result["next_steps"])
        assert any("ike" in step for step in result["next_steps"])

    @pytest.mark.asyncio
    async def test_unlisted_tunnel_counts_as_down(self) -> None:
        result = await _diagnose(_diag_client(_live(tunnel_listed=False)))
        assert result["verdict"] == "tunnel_down"
        assert result["evidence"]["tunnel"]["up"] is False

    @pytest.mark.asyncio
    async def test_health_check_down_on_established_tunnel(self) -> None:
        result = await _diagnose(_diag_client(_live(hc_status="down")))
        assert result["verdict"] == "health_check_down"
        assert "HUB1_HC" in result["explanation"]

    @pytest.mark.asyncio
    async def test_sla_not_met(self) -> None:
        result = await _diagnose(_diag_client(_live(sla_met=[])))
        assert result["verdict"] == "sla_not_met"

    @pytest.mark.asyncio
    async def test_healthy(self) -> None:
        result = await _diagnose(_diag_client(_live()))
        assert result["verdict"] == "healthy"
        assert result["next_steps"] == []

    @pytest.mark.asyncio
    async def test_hub_matched_on_network_id(self) -> None:
        hub_live = {
            "system/interface": {"port2": {"link": True, "ip": "203.0.113.1"}},
            "vpn/ipsec": [
                {
                    "name": "VPN2_0",
                    "parent": "VPN2",
                    "rgwy": "192.0.2.10",
                    "proxyid": [{"p2name": "VPN2", "status": "up"}],
                },
                {"name": "VPN1_0", "parent": "VPN1", "rgwy": "192.0.2.10", "proxyid": []},
            ],
        }
        result = await _diagnose(_diag_client(_live(), hub=hub_live), hub_device="datacenter")

        hub = result["evidence"]["hub"]
        assert hub["tunnel"] == "VPN2"
        assert hub["underlay"] == "port2"
        assert hub["underlay_link"] is True
        assert hub["instances"] == 1
        assert hub["instances_up"] == 1
        assert hub["spoke_instance"]["name"] == "VPN2_0"

    @pytest.mark.asyncio
    async def test_hub_underlay_down(self) -> None:
        hub_live = {
            "system/interface": {"port2": {"link": False, "ip": "203.0.113.1"}},
            "vpn/ipsec": [],
        }
        result = await _diagnose(
            _diag_client(_live(tunnel_up=False), hub=hub_live), hub_device="datacenter"
        )
        assert result["verdict"] == "hub_underlay_link_down"

    @pytest.mark.asyncio
    async def test_unreadable_source_is_reported_not_fatal(self) -> None:
        result = await _diagnose(_diag_client(_live(link=False), failing=("vpn/ipsec",)))

        assert result["verdict"] == "underlay_link_down"
        assert any(u.startswith("tunnel status") for u in result["unverified"])

    @pytest.mark.asyncio
    async def test_nothing_live_is_undetermined(self) -> None:
        everything = (
            "system/interface",
            "vpn/ipsec",
            "virtual-wan/members",
            "virtual-wan/health-check",
        )
        result = await _diagnose(_diag_client(_live(), failing=everything))

        assert result["verdict"] == "undetermined"
        assert len(result["unverified"]) == 4

    @pytest.mark.asyncio
    async def test_unknown_tunnel(self) -> None:
        client = _diag_client(_live())
        client.get_device_ipsec_phase1_interface = AsyncMock(return_value={})
        result = await _diagnose(client)
        assert result["error_code"] == "not_found"
        client.proxy_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_bad_tunnel_name_rejected(self) -> None:
        client = _diag_client(_live())
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.diagnose_ipsec_tunnel(device="branch2", tunnel="x; drop")
        assert "error" in result
        client.proxy_call.assert_not_called()
