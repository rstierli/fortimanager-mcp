"""Tests for device-DB configuration tools (issue #45).

Uses only neutral/example values (RFC 5737 documentation IPs, generic
interface names) since this is a public repository.
"""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import device_config_tools


class TestCreateDeviceInterface:
    @pytest.mark.asyncio
    async def test_creates_vlan_subinterface_in_device_db(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "vlan15"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_interface(
                device="FGT-01",
                name="vlan15",
                parent="internal",
                vlanid=15,
                ip="192.0.2.254/24",
                allowaccess=["ping", "https"],
                role="lan",
                alias="users",
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.add.call_args
        assert args[0] == "/pm/config/device/FGT-01/global/system/interface"
        data = kwargs["data"]
        assert data["name"] == "vlan15"
        assert data["type"] == "vlan"
        assert data["interface"] == "internal"
        assert data["vlanid"] == 15
        assert data["ip"] == ["192.0.2.254", "255.255.255.0"]
        assert data["mode"] == "static"
        assert data["allowaccess"] == ["ping", "https"]
        assert data["role"] == "lan"
        assert data["alias"] == "users"
        assert data["vdom"] == "root"

    @pytest.mark.asyncio
    async def test_rejects_out_of_range_vlanid(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_interface(
                device="FGT-01", name="vlan5000", parent="internal", vlanid=5000
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()


class TestUpdateDeviceInterface:
    @pytest.mark.asyncio
    async def test_updates_only_provided_fields(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"name": "vlan15"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_interface(
                device="FGT-01", name="vlan15", ip="198.51.100.1/24", alias="printers"
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == "/pm/config/device/FGT-01/global/system/interface/vlan15"
        data = kwargs["data"]
        assert data == {
            "ip": ["198.51.100.1", "255.255.255.0"],
            "mode": "static",
            "alias": "printers",
        }

    @pytest.mark.asyncio
    async def test_no_fields_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_interface(
                device="FGT-01", name="vlan15"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()


class TestDeleteDeviceInterface:
    @pytest.mark.asyncio
    async def test_deletes_by_name(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.delete.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.delete_device_interface(
                device="FGT-01", name="vlan15"
            )

        assert result.get("success") is True
        args, _ = mock_fmg_instance.delete.call_args
        assert args[0] == "/pm/config/device/FGT-01/global/system/interface/vlan15"


MOCK_DHCP_SERVERS = [
    {
        "id": 1,
        "interface": ["vlan15"],
        "ip-range": [{"id": 1, "start-ip": "192.0.2.32", "end-ip": "192.0.2.200"}],
        "netmask": "255.255.255.0",
        "default-gateway": "192.0.2.254",
        "dns-service": 0,
        "status": 1,
    },
]


class TestListDeviceDhcpServers:
    @pytest.mark.asyncio
    async def test_lists_vdom_scoped_servers(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, MOCK_DHCP_SERVERS)

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.list_device_dhcp_servers(device="FGT-01")

        assert result["count"] == 1
        assert result["dhcp_servers"] == MOCK_DHCP_SERVERS
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/system/dhcp/server"


class TestCreateDeviceDhcpServer:
    @pytest.mark.asyncio
    async def test_creates_scope_with_range_and_gateway(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"id": 2})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_dhcp_server(
                device="FGT-01",
                interface="vlan15",
                start_ip="192.0.2.32",
                end_ip="192.0.2.200",
                netmask="255.255.255.0",
                default_gateway="192.0.2.254",
                dns_servers=["192.0.2.253", "198.51.100.53"],
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.add.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/system/dhcp/server"
        data = kwargs["data"]
        assert data["interface"] == "vlan15"
        assert data["ip-range"] == [{"id": 1, "start-ip": "192.0.2.32", "end-ip": "192.0.2.200"}]
        assert data["netmask"] == "255.255.255.0"
        assert data["default-gateway"] == "192.0.2.254"
        assert data["dns-service"] == "specify"
        assert data["dns-server1"] == "192.0.2.253"
        assert data["dns-server2"] == "198.51.100.53"

    @pytest.mark.asyncio
    async def test_defaults_dns_to_system_dns(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"id": 2})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_dhcp_server(
                device="FGT-01",
                interface="vlan15",
                start_ip="192.0.2.32",
                end_ip="192.0.2.200",
                netmask="255.255.255.0",
            )

        assert result.get("success") is True
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["dns-service"] == "default"
        assert "dns-server1" not in data

    @pytest.mark.asyncio
    async def test_rejects_more_than_three_dns_servers(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_dhcp_server(
                device="FGT-01",
                interface="vlan15",
                start_ip="192.0.2.32",
                end_ip="192.0.2.200",
                netmask="255.255.255.0",
                dns_servers=["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_bad_ip(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_dhcp_server(
                device="FGT-01",
                interface="vlan15",
                start_ip="not-an-ip",
                end_ip="192.0.2.200",
                netmask="255.255.255.0",
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()


class TestUpdateDeviceDhcpServer:
    @pytest.mark.asyncio
    async def test_updates_by_id(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"id": 1})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_dhcp_server(
                device="FGT-01",
                dhcp_server_id=1,
                start_ip="192.0.2.50",
                end_ip="192.0.2.99",
                lease_time=7200,
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/system/dhcp/server/1"
        data = kwargs["data"]
        assert data["ip-range"] == [{"id": 1, "start-ip": "192.0.2.50", "end-ip": "192.0.2.99"}]
        assert data["lease-time"] == 7200

    @pytest.mark.asyncio
    async def test_range_requires_both_ends(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_dhcp_server(
                device="FGT-01", dhcp_server_id=1, start_ip="192.0.2.50"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()


class TestDeleteDeviceDhcpServer:
    @pytest.mark.asyncio
    async def test_deletes_by_id(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.delete.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.delete_device_dhcp_server(
                device="FGT-01", dhcp_server_id=1
            )

        assert result.get("success") is True
        args, _ = mock_fmg_instance.delete.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/system/dhcp/server/1"


class TestListDeviceVaps:
    @pytest.mark.asyncio
    async def test_lists_vaps(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "TEST", "ssid": "TEST", "security": "wpa2-only-personal"}],
        )

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.list_device_vaps(device="FGT-01")

        assert result["count"] == 1
        assert result["vaps"][0]["ssid"] == "TEST"
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/wireless-controller/vap"


class TestCreateDeviceVap:
    @pytest.mark.asyncio
    async def test_creates_ssid_with_vlan_mapping(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "TEST"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01",
                name="TEST",
                ssid="TEST",
                security="wpa2-only-personal",
                passphrase="s3cretpass",
                vlanid=15,
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.add.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/wireless-controller/vap"
        data = kwargs["data"]
        assert data["name"] == "TEST"
        assert data["ssid"] == "TEST"
        assert data["security"] == "wpa2-only-personal"
        assert data["passphrase"] == "s3cretpass"
        assert data["vlanid"] == 15

    @pytest.mark.asyncio
    async def test_result_never_echoes_the_passphrase(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        # FMG echoes the created object back, secret included
        mock_fmg_instance.add.return_value = (
            0,
            {"name": "TEST", "passphrase": "s3cretpass"},
        )

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01",
                name="TEST",
                ssid="TEST",
                security="wpa2-only-personal",
                passphrase="s3cretpass",
            )

        assert result.get("success") is True
        assert "s3cretpass" not in repr(result)

    @pytest.mark.asyncio
    async def test_rejects_short_passphrase(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01",
                name="TEST",
                ssid="TEST",
                security="wpa2-only-personal",
                passphrase="short",
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()


class TestDeleteDeviceVap:
    @pytest.mark.asyncio
    async def test_deletes_by_name(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.delete.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.delete_device_vap(device="FGT-01", name="TEST")

        assert result.get("success") is True
        args, _ = mock_fmg_instance.delete.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/wireless-controller/vap/TEST"


class TestAssignVapToWtpProfile:
    @pytest.mark.asyncio
    async def test_appends_vap_to_selected_radios(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            {
                "name": "AP-profile",
                "radio-1": {"vap-all": "tunnel", "vaps": ["corp"]},
                "radio-2": {"vap-all": "tunnel"},
            },
        )
        mock_fmg_instance.update.return_value = (0, {"name": "AP-profile"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.assign_vap_to_wtp_profile(
                device="FGT-01", profile="AP-profile", vap="TEST"
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == (
            "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp-profile/AP-profile"
        )
        data = kwargs["data"]
        assert data["radio-1"] == {"vap-all": "manual", "vaps": ["corp", "TEST"]}
        assert data["radio-2"] == {"vap-all": "manual", "vaps": ["TEST"]}

    @pytest.mark.asyncio
    async def test_already_assigned_is_a_noop(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            {
                "name": "AP-profile",
                "radio-1": {"vap-all": "manual", "vaps": ["TEST"]},
                "radio-2": {"vap-all": "manual", "vaps": ["TEST"]},
            },
        )

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.assign_vap_to_wtp_profile(
                device="FGT-01", profile="AP-profile", vap="TEST"
            )

        assert result.get("success") is True
        assert "already" in result["message"]
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_single_radio_selection(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            {"name": "AP-profile", "radio-1": {"vap-all": "tunnel"}, "radio-2": {}},
        )
        mock_fmg_instance.update.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.assign_vap_to_wtp_profile(
                device="FGT-01", profile="AP-profile", vap="TEST", radios=[2]
            )

        assert result.get("success") is True
        data = mock_fmg_instance.update.call_args.kwargs["data"]
        assert "radio-1" not in data
        assert data["radio-2"] == {"vap-all": "manual", "vaps": ["TEST"]}

    @pytest.mark.asyncio
    async def test_rejects_unknown_radio(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.assign_vap_to_wtp_profile(
                device="FGT-01", profile="AP-profile", vap="TEST", radios=[9]
            )

        assert "error" in result
        mock_fmg_instance.get.assert_not_called()


class TestDynamicModeResolution:
    """The new module must be reachable through the dynamic-mode allowlist."""

    @pytest.mark.asyncio
    async def test_execute_resolves_device_config_tool(self) -> None:
        from fortimanager_mcp import server

        class _Collector:
            def __init__(self) -> None:
                self.fns: dict = {}

            def tool(self):
                def decorator(fn):
                    self.fns[fn.__name__] = fn
                    return fn

                return decorator

        collector = _Collector()
        server.register_dynamic_tools(collector)

        result = await collector.fns["execute_fortimanager_tool"]("list_device_dhcp_servers")
        assert "not found" not in str(result.get("error", ""))

    @pytest.mark.asyncio
    async def test_discovery_finds_device_config_category(self) -> None:
        from fortimanager_mcp import server

        class _Collector:
            def __init__(self) -> None:
                self.fns: dict = {}

            def tool(self):
                def decorator(fn):
                    self.fns[fn.__name__] = fn
                    return fn

                return decorator

        collector = _Collector()
        server.register_dynamic_tools(collector)

        result = await collector.fns["find_fortimanager_tool"]("vap")
        assert result["found"] is True
        assert any(t["name"] == "create_device_vap" for t in result["tools"])
        assert any(t["category"] == "device_config" for t in result["tools"])
