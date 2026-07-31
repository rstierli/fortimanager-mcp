"""Tests for dvm_tools device-DB interface config read + summary.

Uses only neutral/example values (RFC 5737 documentation IPs, generic
interface names) since this is a public repository.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import dvm_tools

# A trimmed but representative device-DB interface list.
MOCK_INTERFACES = [
    {
        "name": "port1",
        "alias": "wan",
        "vlanid": 0,
        "ip": ["192.0.2.1", "255.255.255.0"],
        "type": "physical",
        "vdom": "root",
        "status": "up",
        "role": "wan",
        "description": "uplink",
    },
    {
        "name": "vlan10",
        "alias": "users",
        "vlanid": 10,
        "ip": ["198.51.100.1", "255.255.255.0"],
        "type": "vlan",
        "interface": "internal",
        "vdom": "root",
        "status": "up",
        "role": "lan",
        "description": "user segment",
    },
]


@pytest.fixture
def mock_client_configured(
    mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
) -> FortiManagerClient:
    """Mock client whose device-DB interface GET returns MOCK_INTERFACES."""

    def mock_get(url: str, **kwargs):
        if url.endswith("/system/interface"):
            return (0, MOCK_INTERFACES)
        return (0, {})

    mock_fmg_instance.get.side_effect = mock_get
    return mock_client


class TestGetDeviceInterfaceConfig:
    @pytest.mark.asyncio
    async def test_success_returns_raw_and_summary(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await dvm_tools.get_device_interface_config(device="FGT-01")

        assert result["device"] == "FGT-01"
        assert result["interfaces"] == MOCK_INTERFACES
        assert result["interface_count"] == 2

        summary = result["summary"]
        assert [i["name"] for i in summary] == ["port1", "vlan10"]
        assert summary[1]["vlanid"] == 10
        assert summary[1]["interface"] == "internal"
        assert summary[0]["ip"] == ["192.0.2.1", "255.255.255.0"]

    @pytest.mark.asyncio
    async def test_hits_device_db_config_path(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            await dvm_tools.get_device_interface_config(device="FGT-01")

        called_url = mock_fmg_instance.get.call_args[0][0]
        assert called_url == "/pm/config/device/FGT-01/global/system/interface"
        # No filter when neither name nor vlanids is provided.
        assert "filter" not in mock_fmg_instance.get.call_args.kwargs

    @pytest.mark.asyncio
    async def test_filter_by_name(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            await dvm_tools.get_device_interface_config(device="FGT-01", name="port1")

        assert mock_fmg_instance.get.call_args.kwargs["filter"] == ["name", "==", "port1"]

    @pytest.mark.asyncio
    async def test_filter_by_vlanids(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            await dvm_tools.get_device_interface_config(device="FGT-01", vlanids=[10, 20])

        assert mock_fmg_instance.get.call_args.kwargs["filter"] == ["vlanid", "in", 10, 20]

    @pytest.mark.asyncio
    async def test_filter_by_name_and_vlanids_is_compound(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            await dvm_tools.get_device_interface_config(
                device="FGT-01", name="vlan10", vlanids=[10]
            )

        assert mock_fmg_instance.get.call_args.kwargs["filter"] == [
            ["name", "==", "vlan10"],
            "&&",
            ["vlanid", "in", 10],
        ]

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=None):
            result = await dvm_tools.get_device_interface_config(device="FGT-01")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_device_name_is_rejected(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await dvm_tools.get_device_interface_config(device="bad name; drop")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_interface_name_is_rejected(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await dvm_tools.get_device_interface_config(device="FGT-01", name="bad;name")
        assert "error" in result


class TestSummarizeInterfacesRobustness:
    def test_list_input(self) -> None:
        summary = dvm_tools._summarize_interfaces(MOCK_INTERFACES)
        assert len(summary) == 2

    def test_dict_wrapped_data_list(self) -> None:
        summary = dvm_tools._summarize_interfaces({"data": MOCK_INTERFACES})
        assert [i["name"] for i in summary] == ["port1", "vlan10"]

    def test_single_dict_becomes_one_item(self) -> None:
        summary = dvm_tools._summarize_interfaces({"name": "wan1", "vlanid": 5})
        assert len(summary) == 1
        assert summary[0]["name"] == "wan1"
        assert summary[0]["alias"] is None

    def test_off_shape_input_does_not_crash(self) -> None:
        assert dvm_tools._summarize_interfaces(None) == []
        assert dvm_tools._summarize_interfaces("not-a-list") == []
        # Non-dict members in a list are skipped.
        assert dvm_tools._summarize_interfaces([MOCK_INTERFACES[0], "junk", 5]) == [
            {
                "name": "port1",
                "alias": "wan",
                "vlanid": 0,
                "ip": ["192.0.2.1", "255.255.255.0"],
                "type": "physical",
                "interface": None,
                "vdom": "root",
                "status": "up",
                "role": "wan",
                "description": "uplink",
            }
        ]


# --- get_device_client_location (Asset Identity Center) ---------------------

# Detected-device inventory as /api/v2/monitor/user/device/query returns it,
# wrapped in the FMG proxy envelope. Neutral/example values only.
MOCK_DETECTED = [
    {
        "response": {
            "results": [
                {
                    "ipv4_address": "198.51.100.32",
                    "mac": "00:11:22:33:44:55",
                    "hardware_vendor": "ExampleCorp",
                    "os_name": "ExampleOS",
                    "hardware_type": "Media Player",
                    "hostname": "living-room-tv",
                    "is_online": True,
                    "detected_interface": "vlan_kids",
                    "fortiap_id": "FP-EXAMPLE-001",
                    "fortiap_ssid": "kids-wifi",
                    "fortiap_name": "ap-livingroom",
                    "fortiswitch_id": "sw-example",
                    "fortiswitch_port_name": "port22",
                    "fortiswitch_vlan_id": 15,
                    "dhcp_lease_status": "leased",
                    "total_vuln_count": 0,
                    "last_seen": 1,
                },
                {
                    "ipv4_address": "198.51.100.40",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "hostname": "office-laptop",
                    "is_online": False,
                    "detected_interface": "vlan_users",
                    "fortiswitch_id": "sw-example",
                    "fortiswitch_port_name": "port5",
                    "fortiswitch_vlan_id": 10,
                },
            ],
            "status": "success",
        },
        "status": {"code": 0, "message": "OK"},
        "target": "FGT-HQ",
    }
]


def _detected_client() -> AsyncMock:
    client = AsyncMock()
    client.proxy_call = AsyncMock(return_value=MOCK_DETECTED)
    return client


class TestGetDeviceClientLocation:
    @pytest.mark.asyncio
    async def test_locate_by_ip(self) -> None:
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.get_device_client_location(
                adom="root", device="FGT-HQ", ip="198.51.100.32"
            )

        assert result["match_count"] == 1
        loc = result["clients"][0]
        assert loc["hostname"] == "living-room-tv"
        assert loc["fortiap_id"] == "FP-EXAMPLE-001"
        assert loc["fortiap_ssid"] == "kids-wifi"
        assert loc["fortiswitch_port"] == "port22"
        assert loc["vlan_id"] == 15
        assert loc["is_online"] is True
        # hits the detected-device monitor endpoint
        assert client.proxy_call.call_args.kwargs["resource"] == "/api/v2/monitor/user/device/query"

    @pytest.mark.asyncio
    async def test_locate_by_mac_case_insensitive(self) -> None:
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.get_device_client_location(
                adom="root", device="FGT-HQ", mac="AA:BB:CC:DD:EE:FF"
            )
        assert result["match_count"] == 1
        assert result["clients"][0]["hostname"] == "office-laptop"

    @pytest.mark.asyncio
    async def test_locate_by_hostname_substring(self) -> None:
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.get_device_client_location(
                adom="root", device="FGT-HQ", hostname="LIVING-ROOM"
            )
        assert result["match_count"] == 1
        assert result["clients"][0]["ip"] == "198.51.100.32"

    @pytest.mark.asyncio
    async def test_no_filter_returns_full_inventory(self) -> None:
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.get_device_client_location(adom="root", device="FGT-HQ")
        assert result["query"] is None
        assert result["match_count"] == 2

    @pytest.mark.asyncio
    async def test_unknown_ip_matches_nothing(self) -> None:
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.get_device_client_location(
                adom="root", device="FGT-HQ", ip="203.0.113.99"
            )
        assert result["match_count"] == 0
        assert result["clients"] == []

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=None):
            result = await dvm_tools.get_device_client_location(adom="root", device="FGT-HQ")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_device_name_is_rejected(self) -> None:
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.get_device_client_location(
                adom="root", device="bad name; drop"
            )
        assert "error" in result


class TestClientLocationHelpers:
    def test_summarize_maps_key_fields(self) -> None:
        summary = dvm_tools._summarize_detected_client(MOCK_DETECTED[0]["response"]["results"][0])
        assert summary["ip"] == "198.51.100.32"
        assert summary["fortiap_id"] == "FP-EXAMPLE-001"
        assert summary["vlan_id"] == 15

    def test_proxy_results_off_shape_returns_none(self) -> None:
        assert dvm_tools._proxy_results({"no": "envelope"}) is None
        assert dvm_tools._proxy_results([]) is None


# --- DEFAULT_DEVICE fallback -------------------------------------------------


class TestDefaultDeviceFallback:
    def test_get_default_device_reads_env(self, monkeypatch) -> None:
        from fortimanager_mcp.utils.config import get_default_device

        monkeypatch.setenv("DEFAULT_DEVICE", "myfw01")
        assert get_default_device() == "myfw01"
        monkeypatch.delenv("DEFAULT_DEVICE", raising=False)
        assert get_default_device() == ""

    @pytest.mark.asyncio
    async def test_client_location_defaults_device_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("DEFAULT_DEVICE", "FGT-HQ")
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            # device omitted entirely — the model's exact failure mode
            result = await dvm_tools.get_device_client_location(ip="198.51.100.32")
        assert result["device"] == "FGT-HQ"
        assert result["match_count"] == 1
        # and the proxy was still scoped to the resolved device
        assert "/device/FGT-HQ" in client.proxy_call.call_args.kwargs["target"][0]

    @pytest.mark.asyncio
    async def test_client_location_missing_device_without_default_errors(self, monkeypatch) -> None:
        monkeypatch.delenv("DEFAULT_DEVICE", raising=False)
        client = _detected_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.get_device_client_location(ip="198.51.100.32")
        assert result["error_code"] == "device_required"
        assert client.proxy_call.await_count == 0  # never reached the appliance

    @pytest.mark.asyncio
    async def test_interface_config_defaults_device_from_env(
        self, monkeypatch, mock_client_configured: FortiManagerClient
    ) -> None:
        monkeypatch.setenv("DEFAULT_DEVICE", "FGT-01")
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await dvm_tools.get_device_interface_config()
        assert result["device"] == "FGT-01"
        assert result["interface_count"] == 2
