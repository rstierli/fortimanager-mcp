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
