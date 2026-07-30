"""Tests for sdwan_tools module (device-DB SD-WAN config read + summary)."""

from unittest.mock import MagicMock, patch

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
