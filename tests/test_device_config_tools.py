"""Tests for device-DB configuration tools (issue #45).

Uses only neutral/example values (RFC 5737 documentation IPs, generic
interface names) since this is a public repository.
"""

import inspect
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

    @pytest.mark.asyncio
    async def test_sae_sends_sae_password_not_passphrase(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        # FMG keeps the SAE credential in its own field; sending `passphrase`
        # for wpa3-sae is rejected with "vap sae password must be not empty".
        mock_fmg_instance.add.return_value = (0, {"name": "TEST"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01",
                name="TEST",
                ssid="TEST",
                security="wpa3-sae",
                passphrase="s3cretpass",
            )

        assert result.get("success") is True
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["sae-password"] == "s3cretpass"
        assert "passphrase" not in data

    @pytest.mark.asyncio
    async def test_sae_enables_pmf(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "TEST"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            await device_config_tools.create_device_vap(
                device="FGT-01",
                name="TEST",
                ssid="TEST",
                security="wpa3-sae",
                passphrase="s3cretpass",
            )

        assert mock_fmg_instance.add.call_args.kwargs["data"]["pmf"] == "enable"

    @pytest.mark.asyncio
    async def test_sae_transition_sends_both_credentials(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        # Transition mode runs a WPA2 leg alongside SAE, so both fields apply.
        mock_fmg_instance.add.return_value = (0, {"name": "TEST"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            await device_config_tools.create_device_vap(
                device="FGT-01",
                name="TEST",
                ssid="TEST",
                security="wpa3-sae-transition",
                passphrase="s3cretpass",
            )

        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["sae-password"] == "s3cretpass"
        assert data["passphrase"] == "s3cretpass"

    @pytest.mark.asyncio
    async def test_sae_rejects_missing_password(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01", name="TEST", ssid="TEST", security="wpa3-sae"
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_result_never_echoes_the_sae_password(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (
            0,
            {"name": "TEST", "sae-password": "s3cretpass"},
        )

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01",
                name="TEST",
                ssid="TEST",
                security="wpa3-sae",
                passphrase="s3cretpass",
            )

        assert result.get("success") is True
        assert "s3cretpass" not in repr(result)

    @pytest.mark.asyncio
    async def test_list_strips_the_sae_password(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "TEST", "ssid": "TEST", "sae-password": "s3cretpass"}],
        )

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.list_device_vaps(device="FGT-01")

        assert "s3cretpass" not in repr(result)

    @pytest.mark.asyncio
    async def test_enterprise_refused_before_any_call(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        # Enterprise modes need a radius server or user group, which this tool
        # does not wire up; creating the VAP anyway leaves an unusable SSID.
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01", name="TEST", ssid="TEST", security="wpa2-only-enterprise"
            )

        assert "error" in result
        assert "radius" in result["error"].lower()
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_wep_refused_without_claiming_it_needs_radius(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        # wep64/wep128 are in the security enum but take a `key`, not radius.
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01", name="TEST", ssid="TEST", security="wep128"
            )

        assert "error" in result
        assert "radius" not in result["error"].lower()
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_open_needs_no_credential(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "TEST"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01", name="TEST", ssid="TEST", security="open"
            )

        assert result.get("success") is True
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert "passphrase" not in data
        assert "sae-password" not in data


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
        # The radios carry the settings a real profile has. The first
        # version of this mock had only vap-all and vaps, so the
        # exact-equality asserts below passed whether or not the tool
        # preserved anything else: it could not catch the write dropping
        # band, channel and power.
        mock_fmg_instance.get.return_value = (
            0,
            {
                "name": "AP-profile",
                "radio-1": {
                    "vap-all": "tunnel",
                    "vaps": ["corp"],
                    "band": "802.11ax-5G",
                    "channel": ["36", "40"],
                    "power-level": 70,
                },
                "radio-2": {"vap-all": "tunnel", "band": "802.11ax-2G", "channel-bonding": "20MHz"},
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
        assert data["radio-1"] == {
            "vap-all": "manual",
            "vaps": ["corp", "TEST"],
            "band": "802.11ax-5G",
            "channel": ["36", "40"],
            "power-level": 70,
        }
        assert data["radio-2"] == {
            "vap-all": "manual",
            "vaps": ["TEST"],
            "band": "802.11ax-2G",
            "channel-bonding": "20MHz",
        }

    @pytest.mark.asyncio
    async def test_radio_settings_are_not_reset_by_the_write(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Assigning an SSID must not disturb how the radio transmits.

        This is a read-modify-write, and FortiManager replaces a nested
        object rather than merging into it, so writing back only the two
        keys the tool touches would reset band, channel and power to
        defaults, and the next install_device_settings would push that to
        a live AP. Its own test because the consequence is physical
        rather than a wrong value in a response.
        """
        radio = {
            "vap-all": "tunnel",
            "vaps": [],
            "band": "802.11ax-5G",
            "channel": ["149"],
            "power-level": 30,
            "mode": "ap",
        }
        mock_fmg_instance.get.return_value = (0, {"name": "AP-profile", "radio-1": dict(radio)})
        mock_fmg_instance.update.return_value = (0, {"name": "AP-profile"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            await device_config_tools.assign_vap_to_wtp_profile(
                device="FGT-01", profile="AP-profile", vap="TEST", radios=[1]
            )

        written = mock_fmg_instance.update.call_args.kwargs["data"]["radio-1"]
        for key in ("band", "channel", "power-level", "mode"):
            assert written[key] == radio[key], f"{key} was dropped by the write"

    @pytest.mark.asyncio
    async def test_an_empty_read_does_not_invent_radios(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """An empty read is a read that told us nothing, not a bare profile.

        Continuing would build radio objects from scratch and write them,
        so a typo in the profile name would create configuration instead
        of failing.
        """
        mock_fmg_instance.get.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.assign_vap_to_wtp_profile(
                device="FGT-01", profile="typo-profile", vap="TEST"
            )

        assert result.get("error_code") == "not_found"
        assert result.get("success") is not True
        mock_fmg_instance.update.assert_not_called()

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


MOCK_WTP_PROFILES = [
    {
        "name": "AP-profile",
        "radio-1": {"vap-all": "manual", "vaps": ["corp"], "band": "802.11ax-5G"},
        "radio-3": {"vap-all": "manual", "band": "802.11ax-6G", "channel-bonding": "160MHz"},
    }
]


class TestListDeviceWtpProfiles:
    @pytest.mark.asyncio
    async def test_lists_profiles(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, MOCK_WTP_PROFILES)

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.list_device_wtp_profiles(device="FGT-01")

        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp-profile"
        assert result["count"] == 1
        assert result["profiles"] == MOCK_WTP_PROFILES


class TestGetDeviceWtpProfile:
    @pytest.mark.asyncio
    async def test_returns_the_stored_profile(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, MOCK_WTP_PROFILES[0])

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.get_device_wtp_profile(
                device="FGT-01", profile="AP-profile"
            )

        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == (
            "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp-profile/AP-profile"
        )
        assert result["profile"] == MOCK_WTP_PROFILES[0]

    @pytest.mark.asyncio
    async def test_empty_read_is_not_found(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.get_device_wtp_profile(
                device="FGT-01", profile="typo-profile"
            )

        assert result.get("error_code") == "not_found"


class TestUpdateDeviceWtpProfileRadio:
    @pytest.mark.asyncio
    async def test_pins_a_single_channel(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            {
                "name": "AP-profile",
                "radio-3": {
                    "vap-all": "manual",
                    "vaps": ["corp-6g"],
                    "band": "802.11ax-6G",
                    "channel-bonding": "160MHz",
                    "power-level": 50,
                },
            },
        )
        mock_fmg_instance.update.return_value = (0, {"name": "AP-profile"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp_profile_radio(
                device="FGT-01", profile="AP-profile", radio=3, channel=[15]
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == (
            "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp-profile/AP-profile"
        )
        data = kwargs["data"]
        # channel-bonding, vaps, band, power-level: everything not touched
        # must survive the write untouched, per assign_vap_to_wtp_profile's
        # read-modify-write discipline.
        assert data["radio-3"] == {
            "vap-all": "manual",
            "vaps": ["corp-6g"],
            "band": "802.11ax-6G",
            "channel-bonding": "160MHz",
            "power-level": 50,
            "channel": ["15"],
        }

    @pytest.mark.asyncio
    async def test_updates_channel_bonding_only(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            {"name": "AP-profile", "radio-1": {"vap-all": "manual", "channel": ["36"]}},
        )
        mock_fmg_instance.update.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp_profile_radio(
                device="FGT-01", profile="AP-profile", radio=1, channel_bonding="80MHz"
            )

        assert result.get("success") is True
        data = mock_fmg_instance.update.call_args.kwargs["data"]
        assert data["radio-1"] == {
            "vap-all": "manual",
            "channel": ["36"],
            "channel-bonding": "80MHz",
        }

    @pytest.mark.asyncio
    async def test_rejects_unknown_radio(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp_profile_radio(
                device="FGT-01", profile="AP-profile", radio=9, channel=[15]
            )

        assert "error" in result
        mock_fmg_instance.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_unknown_channel_bonding(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp_profile_radio(
                device="FGT-01", profile="AP-profile", radio=1, channel_bonding="320MHz"
            )

        assert "error" in result
        mock_fmg_instance.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_fields_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp_profile_radio(
                device="FGT-01", profile="AP-profile", radio=1
            )

        assert "error" in result
        mock_fmg_instance.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_an_empty_read_does_not_invent_radios(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp_profile_radio(
                device="FGT-01", profile="typo-profile", radio=1, channel=[36]
            )

        assert result.get("error_code") == "not_found"
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_radio_on_profile_is_not_found(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {"name": "AP-profile", "radio-1": {}})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp_profile_radio(
                device="FGT-01", profile="AP-profile", radio=2, channel=[36]
            )

        assert result.get("error_code") == "not_found"
        mock_fmg_instance.update.assert_not_called()


MOCK_WTPS = [
    {
        "wtp-id": "FP231FTF24000123",
        "name": "ap-hallway",
        "wtp-profile": "AP-profile-5g6g",
        "admin": "enable",
    },
]


class TestListDeviceWtps:
    @pytest.mark.asyncio
    async def test_lists_wtps(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, MOCK_WTPS)

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.list_device_wtps(device="FGT-01")

        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp"
        assert result["count"] == 1
        assert result["wtps"] == MOCK_WTPS


class TestGetDeviceWtp:
    @pytest.mark.asyncio
    async def test_returns_the_stored_wtp(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, MOCK_WTPS[0])

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.get_device_wtp(
                device="FGT-01", wtp_id="FP231FTF24000123"
            )

        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == (
            "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp/FP231FTF24000123"
        )
        assert result["wtp"] == MOCK_WTPS[0]

    @pytest.mark.asyncio
    async def test_empty_read_is_not_found(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.get_device_wtp(
                device="FGT-01", wtp_id="FP231FTF24000123"
            )

        assert result.get("error_code") == "not_found"

    @pytest.mark.asyncio
    async def test_rejects_a_non_serial_wtp_id(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.get_device_wtp(
                device="FGT-01", wtp_id="not-a-serial"
            )

        assert "error" in result
        mock_fmg_instance.get.assert_not_called()


class TestCreateDeviceWtp:
    @pytest.mark.asyncio
    async def test_registers_a_managed_ap(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"wtp-id": "FP231FTF24000123"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_wtp(
                device="FGT-01",
                wtp_id="fp231ftf24000123",
                wtp_profile="AP-profile-5g6g",
                name="ap-hallway",
                location="hallway",
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.add.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp"
        data = kwargs["data"]
        assert data == {
            "wtp-id": "FP231FTF24000123",
            "wtp-profile": "AP-profile-5g6g",
            "admin": "discovered",
            "name": "ap-hallway",
            "location": "hallway",
        }

    @pytest.mark.asyncio
    async def test_rejects_unknown_admin_state(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_wtp(
                device="FGT-01",
                wtp_id="FP231FTF24000123",
                wtp_profile="AP-profile",
                admin="authorized",
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()


class TestUpdateDeviceWtp:
    @pytest.mark.asyncio
    async def test_updates_only_provided_fields(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"wtp-id": "FP231FTF24000123"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp(
                device="FGT-01", wtp_id="FP231FTF24000123", admin="enable"
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == (
            "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp/FP231FTF24000123"
        )
        assert kwargs["data"] == {"admin": "enable"}

    @pytest.mark.asyncio
    async def test_no_fields_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.update_device_wtp(
                device="FGT-01", wtp_id="FP231FTF24000123"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()


class TestDeleteDeviceWtp:
    @pytest.mark.asyncio
    async def test_deletes_by_wtp_id(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.delete.return_value = (0, {})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.delete_device_wtp(
                device="FGT-01", wtp_id="FP231FTF24000123"
            )

        assert result.get("success") is True
        args, _ = mock_fmg_instance.delete.call_args
        assert args[0] == (
            "/pm/config/device/FGT-01/vdom/root/wireless-controller/wtp/FP231FTF24000123"
        )


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

    @pytest.mark.asyncio
    async def test_execute_resolves_wtp_tool(self) -> None:
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

        result = await collector.fns["execute_fortimanager_tool"]("update_device_wtp_profile_radio")
        assert "not found" not in str(result.get("error", ""))

    @pytest.mark.asyncio
    async def test_discovery_finds_wtp_tools(self) -> None:
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

        result = await collector.fns["find_fortimanager_tool"]("wtp")
        assert result["found"] is True
        names = {t["name"] for t in result["tools"]}
        assert "list_device_wtps" in names
        assert "update_device_wtp_profile_radio" in names


class TestVdomIsValidatedOnEveryWritePath:
    """The vdom reaches a URL path segment, so it has to be validated.

    `device`, `name` and `interface` were validated from the start; `vdom`
    was the one caller-supplied value that went straight into
    `/pm/config/device/{device}/vdom/{vdom}/...` unchecked, on tools that
    write. The sibling SD-WAN reader already validated it
    (sdwan_tools.py), so this is the module agreeing with the rest of the
    repo rather than a new rule.
    """

    #: Minimal valid arguments per vdom-taking tool. Discovered by
    #: signature below, so a new tool that forgets to validate vdom fails
    #: this class rather than shipping: it either appears here or the
    #: coverage test names it as unlisted.
    TOOL_ARGS = {
        "create_device_interface": {"name": "vlan15", "parent": "internal", "vlanid": 15},
        "create_device_dhcp_server": {
            "interface": "vlan15",
            "start_ip": "192.0.2.10",
            "end_ip": "192.0.2.50",
            "netmask": "255.255.255.0",
        },
        "update_device_dhcp_server": {"dhcp_server_id": 1, "netmask": "255.255.255.0"},
        "delete_device_dhcp_server": {"dhcp_server_id": 1},
        "list_device_dhcp_servers": {},
        "create_device_vap": {"name": "TEST", "ssid": "corp", "security": "open"},
        "delete_device_vap": {"name": "TEST"},
        "list_device_vaps": {},
        "assign_vap_to_wtp_profile": {"profile": "AP-profile", "vap": "TEST"},
        "list_device_wtp_profiles": {},
        "get_device_wtp_profile": {"profile": "AP-profile"},
        "update_device_wtp_profile_radio": {"profile": "AP-profile", "radio": 1, "channel": [36]},
        "list_device_wtps": {},
        "get_device_wtp": {"wtp_id": "FP231FTF24000123"},
        "create_device_wtp": {"wtp_id": "FP231FTF24000123", "wtp_profile": "AP-profile"},
        "update_device_wtp": {"wtp_id": "FP231FTF24000123", "name": "ap-1"},
        "delete_device_wtp": {"wtp_id": "FP231FTF24000123"},
    }

    def test_every_vdom_taking_tool_is_listed(self) -> None:
        """The list above must not drift behind the module."""
        import inspect

        found = {
            n
            for n in dir(device_config_tools)
            if not n.startswith("_")
            and inspect.iscoroutinefunction(getattr(device_config_tools, n))
            and "vdom" in inspect.signature(getattr(device_config_tools, n)).parameters
        }
        assert found == set(self.TOOL_ARGS), (
            "a vdom-taking tool is not covered by the refusal test below; "
            f"unlisted: {sorted(found - set(self.TOOL_ARGS))}"
        )

    @pytest.mark.parametrize("tool_name", sorted(TOOL_ARGS))
    @pytest.mark.parametrize(
        "bad_vdom",
        ["root/global/system/admin", "../../sys/status", "root/../global", "a" * 100],
    )
    @pytest.mark.asyncio
    async def test_a_path_bearing_vdom_is_refused_before_any_call(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        tool_name: str,
        bad_vdom: str,
    ) -> None:
        tool = getattr(device_config_tools, tool_name)

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await tool(device="FGT-01", vdom=bad_vdom, **self.TOOL_ARGS[tool_name])

        assert "error" in result, f"{tool_name} accepted vdom={bad_vdom!r}"
        assert result.get("success") is not True
        for call in ("add", "set", "update", "delete", "get"):
            getattr(mock_fmg_instance, call).assert_not_called()

    @pytest.mark.asyncio
    async def test_an_ordinary_vdom_still_works(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Negative control: the guard must not refuse a normal vdom."""
        mock_fmg_instance.add.return_value = (0, {"id": 1})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_dhcp_server(
                device="FGT-01",
                interface="vlan15",
                start_ip="192.0.2.10",
                end_ip="192.0.2.50",
                netmask="255.255.255.0",
                vdom="root",
            )

        assert result.get("success") is True


class TestCredentialSanitizerRecurses:
    """A sanitizer that depends on the shape it is handed is one response
    format away from leaking."""

    def test_a_nested_credential_is_stripped(self) -> None:
        nested = {"data": {"name": "TEST", "passphrase": "s3cretpass"}}

        out = device_config_tools._sanitize_vap_result(nested)

        assert "s3cretpass" not in repr(out)
        assert out["data"]["name"] == "TEST"

    def test_a_credential_inside_a_list_of_dicts_is_stripped(self) -> None:
        nested = {"results": [{"name": "A", "sae-password": "s3cretpass"}]}

        out = device_config_tools._sanitize_vap_result(nested)

        assert "s3cretpass" not in repr(out)
        assert out["results"][0]["name"] == "A"

    def test_the_flat_shape_still_works(self) -> None:
        """Negative control: today's actual echo shape."""
        out = device_config_tools._sanitize_vap_result(
            {"name": "TEST", "passphrase": "s3cretpass", "ssid": "corp"}
        )

        assert out == {"name": "TEST", "ssid": "corp"}


#: A wtp-profile record shaped like the live read confirmed on the
#: mcp-dev-test sandbox (FGT-MCP-TEST-01): login-passwd-change enabled with
#: an ENC-blob login-passwd, plus the sibling credential fields found via
#: the same schema dump, including one nested under a radio sub-object.
#: Values here are invented; no credential from any estate appears.
SECRET_ENC_BLOB = ["ENC", "not-a-real-enc-blob"]

WTP_PROFILE_WITH_CREDENTIALS = {
    "name": "AP-profile",
    "login-passwd-change": 1,
    "login-passwd": SECRET_ENC_BLOB,
    "apcfg-auto-cert-est-http-password": SECRET_ENC_BLOB,
    "apcfg-auto-cert-scep-password": SECRET_ENC_BLOB,
    "apcfg-mesh-passwd": SECRET_ENC_BLOB,
    "wan-port-auth-password": SECRET_ENC_BLOB,
    "radio-1": {
        "band": "802.11ax-5G",
        "sam-private-key-password": SECRET_ENC_BLOB,
    },
}

WTP_WITH_CREDENTIAL = {
    "wtp-id": "FP231FTF24000123",
    "name": "ap-hallway",
    "wtp-profile": "AP-profile",
    "override-login-passwd-change": 1,
    "login-passwd-change": 1,
    "login-passwd": SECRET_ENC_BLOB,
}


class TestNoWtpReadPathReturnsTheCredential:
    """The review that found this: both wireless-controller.wtp-profile and
    wireless-controller.wtp can carry login-passwd (the FortiAP admin
    password) whenever login-passwd-change is enabled. Confirmed live
    against the mcp-dev-test sandbox (FGT-MCP-TEST-01): FMG echoes it back
    as an ENC-prefixed blob on every read, the same shape adm_pass had
    before the dvmdb-device fix. The sibling fields here were found
    alongside it via the same schema dump.
    """

    @pytest.mark.asyncio
    async def test_list_device_wtp_profiles(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [dict(WTP_PROFILE_WITH_CREDENTIALS)])

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.list_device_wtp_profiles(device="FGT-01")

        assert "not-a-real-enc-blob" not in repr(result)
        assert result["profiles"][0]["name"] == "AP-profile"
        assert result["profiles"][0]["radio-1"]["band"] == "802.11ax-5G"

    @pytest.mark.asyncio
    async def test_get_device_wtp_profile(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, dict(WTP_PROFILE_WITH_CREDENTIALS))

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.get_device_wtp_profile(
                device="FGT-01", profile="AP-profile"
            )

        assert "not-a-real-enc-blob" not in repr(result)
        assert result["profile"]["name"] == "AP-profile"
        # login-passwd-change (the enable/disable flag) is not a credential
        # and must survive -- only the password value itself is stripped.
        assert result["profile"]["login-passwd-change"] == 1

    @pytest.mark.asyncio
    async def test_list_device_wtps(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [dict(WTP_WITH_CREDENTIAL)])

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.list_device_wtps(device="FGT-01")

        assert "not-a-real-enc-blob" not in repr(result)
        assert result["wtps"][0]["wtp-id"] == "FP231FTF24000123"

    @pytest.mark.asyncio
    async def test_get_device_wtp(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, dict(WTP_WITH_CREDENTIAL))

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.get_device_wtp(
                device="FGT-01", wtp_id="FP231FTF24000123"
            )

        assert "not-a-real-enc-blob" not in repr(result)
        assert result["wtp"]["name"] == "ap-hallway"


class TestWtpCredentialSanitizerRecurses:
    """Same shape hazard as the VAP sanitizer: wtp-profile nests
    sam-private-key-password inside radio-1..radio-4, not at the top level.
    """

    def test_a_credential_nested_under_a_radio_is_stripped(self) -> None:
        nested = {
            "name": "AP-profile",
            "radio-1": {"band": "802.11ax-5G", "sam-private-key-password": SECRET_ENC_BLOB},
        }

        out = device_config_tools._sanitize_wtp_profile_result(nested)

        assert "not-a-real-enc-blob" not in repr(out)
        assert out["radio-1"]["band"] == "802.11ax-5G"

    def test_a_credential_inside_a_list_of_dicts_is_stripped(self) -> None:
        nested = {"results": [{"wtp-id": "FP1", "login-passwd": SECRET_ENC_BLOB}]}

        out = device_config_tools._sanitize_wtp_result(nested)

        assert "not-a-real-enc-blob" not in repr(out)
        assert out["results"][0]["wtp-id"] == "FP1"


class TestTheWtpStripCannotBeForgotten:
    """A future wtp/wtp-profile-returning tool must not silently miss the
    strip. Same discipline as PR #51's dvmdb-device equivalent."""

    def test_every_wtp_returning_tool_calls_a_sanitizer(self) -> None:
        expected = {
            "list_device_wtp_profiles": "_sanitize_wtp_profile_result",
            "get_device_wtp_profile": "_sanitize_wtp_profile_result",
            "list_device_wtps": "_sanitize_wtp_result",
            "get_device_wtp": "_sanitize_wtp_result",
        }

        for tool_name, helper_name in expected.items():
            source = inspect.getsource(getattr(device_config_tools, tool_name))
            assert helper_name in source, (
                f"device_config_tools.{tool_name} returns wtp/wtp-profile records "
                f"without calling {helper_name}"
            )


class TestOweMode:
    """`owe` is advertised in the docstring and was reachable but untested.

    Deleting its branch let it fall through to the reject path, and all 33
    tests still passed, so nothing proved the mode worked at all.
    """

    @pytest.mark.asyncio
    async def test_owe_needs_no_credential_and_enables_pmf(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "OPEN-SECURE"})

        with patch.object(device_config_tools, "get_fmg_client", return_value=mock_client):
            result = await device_config_tools.create_device_vap(
                device="FGT-01", name="OPEN-SECURE", ssid="guest", security="owe"
            )

        assert result.get("success") is True
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["security"] == "owe"
        assert data["pmf"] == "enable"
        assert "passphrase" not in data
        assert "sae-password" not in data
