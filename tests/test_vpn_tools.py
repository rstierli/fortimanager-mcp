"""Tests for VPN device-DB configuration tools (IPsec + SSL-VPN).

Uses only neutral/example values (RFC 5737 documentation IPs, generic
interface names) since this is a public repository.
"""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import vpn_tools

# =============================================================================
# IPsec phase1-interface
# =============================================================================


class TestListDeviceIpsecPhase1Interfaces:
    @pytest.mark.asyncio
    async def test_lists_and_strips_secrets(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            [
                {
                    "name": "hq-gw",
                    "interface": "wan1",
                    "remote-gw": "198.51.100.1",
                    "psksecret": "ENC abcdef==",
                }
            ],
        )

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.list_device_ipsec_phase1_interfaces(device="FGT-01")

        assert result["count"] == 1
        assert "psksecret" not in result["interfaces"][0]
        assert result["interfaces"][0]["name"] == "hq-gw"
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase1-interface"

    @pytest.mark.asyncio
    async def test_disconnected_client_returns_error(
        self, mock_client_disconnected: FortiManagerClient
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=None):
            result = await vpn_tools.list_device_ipsec_phase1_interfaces(device="FGT-01")

        assert "error" in result


class TestGetDeviceIpsecPhase1Interface:
    @pytest.mark.asyncio
    async def test_gets_single_interface_secret_stripped(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            {
                "name": "hq-gw",
                "interface": "wan1",
                "psksecret": "ENC abcdef==",
                "psksecret-remote": "ENC ghijkl==",
            },
        )

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.get_device_ipsec_phase1_interface(
                device="FGT-01", name="hq-gw"
            )

        assert result["phase1_interface"]["name"] == "hq-gw"
        assert "psksecret" not in result["phase1_interface"]
        assert "psksecret-remote" not in result["phase1_interface"]
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase1-interface/hq-gw"

    @pytest.mark.asyncio
    async def test_not_found_returns_not_found_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.get_device_ipsec_phase1_interface(
                device="FGT-01", name="missing-gw"
            )

        assert result.get("error_code") == "not_found"


class TestCreateDeviceIpsecPhase1Interface:
    @pytest.mark.asyncio
    async def test_creates_static_gateway_with_psk(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "hq-gw", "psksecret": "ENC abcdef=="})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01",
                name="hq-gw",
                interface="wan1",
                remote_gw="198.51.100.1",
                psksecret="correct-horse-battery",
                ike_version="2",
                proposal=["aes256-sha256"],
                dhgrp=["14", "21"],
                nattraversal="enable",
                dpd="on-idle",
                keylife=28800,
                comments="site-to-site to branch",
            )

        assert result.get("success") is True
        assert "psksecret" not in result["result"]
        args, kwargs = mock_fmg_instance.add.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase1-interface"
        data = kwargs["data"]
        assert data["name"] == "hq-gw"
        assert data["interface"] == "wan1"
        assert data["type"] == "static"
        assert data["remote-gw"] == "198.51.100.1"
        assert data["psksecret"] == "correct-horse-battery"
        assert data["ike-version"] == "2"
        assert data["proposal"] == ["aes256-sha256"]
        assert data["dhgrp"] == ["14", "21"]
        assert data["nattraversal"] == "enable"
        assert data["dpd"] == "on-idle"
        assert data["keylife"] == 28800
        assert data["comments"] == "site-to-site to branch"

    @pytest.mark.asyncio
    async def test_static_type_requires_remote_gw(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01", name="hq-gw", interface="wan1"
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_dynamic_type_does_not_require_remote_gw(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "dialup-gw"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01", name="dialup-gw", interface="wan1", type="dynamic"
            )

        assert result.get("success") is True
        _, kwargs = mock_fmg_instance.add.call_args
        assert "remote-gw" not in kwargs["data"]

    @pytest.mark.asyncio
    async def test_rejects_invalid_type(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01",
                name="hq-gw",
                interface="wan1",
                type="satellite-uplink",
                remote_gw="198.51.100.1",
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_too_short_psksecret(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01",
                name="hq-gw",
                interface="wan1",
                remote_gw="198.51.100.1",
                psksecret="abc",
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_static_type_defaults_peertype_to_any(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """FMG 7.6.7 live-verified: a static PSK gateway with no peertype is
        rejected with "peer invalid value" -- default to "any" so callers
        don't hit that error without knowing to pass peertype explicitly.
        """
        mock_fmg_instance.add.return_value = (0, {"name": "hq-gw"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01",
                name="hq-gw",
                interface="wan1",
                remote_gw="198.51.100.1",
                psksecret="correct-horse-battery",
            )

        assert result.get("success") is True
        _, kwargs = mock_fmg_instance.add.call_args
        assert kwargs["data"]["peertype"] == "any"

    @pytest.mark.asyncio
    async def test_explicit_peertype_overrides_static_default(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "hq-gw"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01",
                name="hq-gw",
                interface="wan1",
                remote_gw="198.51.100.1",
                psksecret="correct-horse-battery",
                peertype="dialup",
            )

        assert result.get("success") is True
        _, kwargs = mock_fmg_instance.add.call_args
        assert kwargs["data"]["peertype"] == "dialup"

    @pytest.mark.asyncio
    async def test_dynamic_type_does_not_default_peertype(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "dialup-gw"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase1_interface(
                device="FGT-01", name="dialup-gw", interface="wan1", type="dynamic"
            )

        assert result.get("success") is True
        _, kwargs = mock_fmg_instance.add.call_args
        assert "peertype" not in kwargs["data"]


class TestUpdateDeviceIpsecPhase1Interface:
    @pytest.mark.asyncio
    async def test_updates_only_provided_fields(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"name": "hq-gw"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_ipsec_phase1_interface(
                device="FGT-01", name="hq-gw", remote_gw="203.0.113.5", comments="rehomed"
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase1-interface/hq-gw"
        assert kwargs["data"] == {"remote-gw": "203.0.113.5", "comments": "rehomed"}

    @pytest.mark.asyncio
    async def test_no_fields_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_ipsec_phase1_interface(
                device="FGT-01", name="hq-gw"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_invalid_ike_version(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_ipsec_phase1_interface(
                device="FGT-01", name="hq-gw", ike_version="3"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()


class TestDeleteDeviceIpsecPhase1Interface:
    @pytest.mark.asyncio
    async def test_deletes_by_name(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.delete.return_value = (0, {})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.delete_device_ipsec_phase1_interface(
                device="FGT-01", name="hq-gw"
            )

        assert result.get("success") is True
        args, _ = mock_fmg_instance.delete.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase1-interface/hq-gw"


# =============================================================================
# IPsec phase2-interface
# =============================================================================


class TestListDeviceIpsecPhase2Interfaces:
    @pytest.mark.asyncio
    async def test_lists_vdom_scoped_interfaces(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "hq-tunnel", "phase1name": "hq-gw"}],
        )

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.list_device_ipsec_phase2_interfaces(device="FGT-01")

        assert result["count"] == 1
        assert result["interfaces"][0]["name"] == "hq-tunnel"
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase2-interface"


class TestGetDeviceIpsecPhase2Interface:
    @pytest.mark.asyncio
    async def test_not_found_returns_not_found_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.get_device_ipsec_phase2_interface(
                device="FGT-01", name="missing-tunnel"
            )

        assert result.get("error_code") == "not_found"


class TestCreateDeviceIpsecPhase2Interface:
    @pytest.mark.asyncio
    async def test_creates_tunnel_with_subnets(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "hq-tunnel"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase2_interface(
                device="FGT-01",
                name="hq-tunnel",
                phase1name="hq-gw",
                src_subnet="192.0.2.0/24",
                dst_subnet="198.51.100.0/24",
                proposal=["aes256-sha256"],
                dhgrp=["14"],
                pfs="enable",
                replay="enable",
                keepalive="disable",
                auto_negotiate="enable",
                keylifeseconds=3600,
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.add.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase2-interface"
        data = kwargs["data"]
        assert data["name"] == "hq-tunnel"
        assert data["phase1name"] == "hq-gw"
        assert data["src-subnet"] == ["192.0.2.0", "255.255.255.0"]
        assert data["dst-subnet"] == ["198.51.100.0", "255.255.255.0"]
        assert data["proposal"] == ["aes256-sha256"]
        assert data["dhgrp"] == ["14"]
        assert data["pfs"] == "enable"
        assert data["replay"] == "enable"
        assert data["keepalive"] == "disable"
        assert data["auto-negotiate"] == "enable"
        assert data["keylifeseconds"] == 3600

    @pytest.mark.asyncio
    async def test_accepts_space_separated_subnet_form(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {"name": "hq-tunnel"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase2_interface(
                device="FGT-01",
                name="hq-tunnel",
                phase1name="hq-gw",
                src_subnet="192.0.2.0 255.255.255.0",
            )

        assert result.get("success") is True
        _, kwargs = mock_fmg_instance.add.call_args
        assert kwargs["data"]["src-subnet"] == ["192.0.2.0", "255.255.255.0"]

    @pytest.mark.asyncio
    async def test_rejects_keylifeseconds_out_of_range(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase2_interface(
                device="FGT-01",
                name="hq-tunnel",
                phase1name="hq-gw",
                keylifeseconds=10,
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_invalid_pfs_value(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.create_device_ipsec_phase2_interface(
                device="FGT-01", name="hq-tunnel", phase1name="hq-gw", pfs="maybe"
            )

        assert "error" in result
        mock_fmg_instance.add.assert_not_called()


class TestUpdateDeviceIpsecPhase2Interface:
    @pytest.mark.asyncio
    async def test_updates_only_provided_fields(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"name": "hq-tunnel"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_ipsec_phase2_interface(
                device="FGT-01", name="hq-tunnel", dst_subnet="203.0.113.0/24"
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase2-interface/hq-tunnel"
        assert kwargs["data"] == {"dst-subnet": ["203.0.113.0", "255.255.255.0"]}

    @pytest.mark.asyncio
    async def test_no_fields_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_ipsec_phase2_interface(
                device="FGT-01", name="hq-tunnel"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()


class TestDeleteDeviceIpsecPhase2Interface:
    @pytest.mark.asyncio
    async def test_deletes_by_name(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.delete.return_value = (0, {})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.delete_device_ipsec_phase2_interface(
                device="FGT-01", name="hq-tunnel"
            )

        assert result.get("success") is True
        args, _ = mock_fmg_instance.delete.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ipsec/phase2-interface/hq-tunnel"


# =============================================================================
# SSL-VPN settings
# =============================================================================


class TestGetDeviceSslvpnSettings:
    @pytest.mark.asyncio
    async def test_gets_settings_object(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {"status": "enable", "port": 10443})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.get_device_sslvpn_settings(device="FGT-01")

        assert result["settings"]["port"] == 10443
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ssl/settings"

    @pytest.mark.asyncio
    async def test_empty_object_returns_empty_settings(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.get_device_sslvpn_settings(device="FGT-01")

        assert result["settings"] == {}


class TestUpdateDeviceSslvpnSettings:
    @pytest.mark.asyncio
    async def test_updates_only_provided_fields(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"status": "enable"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_sslvpn_settings(
                device="FGT-01",
                status="enable",
                port=10443,
                source_interface=["wan1"],
                default_portal="full-access",
                idle_timeout=300,
                auth_timeout=28800,
                dns_server1="198.51.100.53",
                reqclientcert="disable",
                https_redirect="enable",
                ssl_min_proto_ver="tls1-2",
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ssl/settings"
        data = kwargs["data"]
        assert data["status"] == "enable"
        assert data["port"] == 10443
        assert data["source-interface"] == ["wan1"]
        assert data["default-portal"] == "full-access"
        assert data["idle-timeout"] == 300
        assert data["auth-timeout"] == 28800
        assert data["dns-server1"] == "198.51.100.53"
        assert data["reqclientcert"] == "disable"
        assert data["https-redirect"] == "enable"
        assert data["ssl-min-proto-ver"] == "tls1-2"

    @pytest.mark.asyncio
    async def test_no_fields_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_sslvpn_settings(device="FGT-01")

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_out_of_range_port(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_sslvpn_settings(device="FGT-01", port=70000)

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_invalid_tls_version(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_sslvpn_settings(
                device="FGT-01", ssl_min_proto_ver="ssl3"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()


# =============================================================================
# SSL-VPN web portal
# =============================================================================


class TestGetDeviceSslvpnWebPortal:
    @pytest.mark.asyncio
    async def test_gets_portal(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {"name": "full-access", "tunnel-mode": "enable"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.get_device_sslvpn_web_portal(
                device="FGT-01", name="full-access"
            )

        assert result["portal"]["name"] == "full-access"
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ssl/web/portal/full-access"

    @pytest.mark.asyncio
    async def test_not_found_returns_not_found_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.get_device_sslvpn_web_portal(
                device="FGT-01", name="missing-portal"
            )

        assert result.get("error_code") == "not_found"


class TestUpdateDeviceSslvpnWebPortal:
    @pytest.mark.asyncio
    async def test_updates_only_provided_fields(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"name": "full-access"})

        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_sslvpn_web_portal(
                device="FGT-01",
                name="full-access",
                tunnel_mode="enable",
                split_tunneling="disable",
                ip_pools=["SSLVPN-pool"],
                web_mode="enable",
                dns_server1="198.51.100.53",
            )

        assert result.get("success") is True
        args, kwargs = mock_fmg_instance.update.call_args
        assert args[0] == "/pm/config/device/FGT-01/vdom/root/vpn/ssl/web/portal/full-access"
        data = kwargs["data"]
        assert data["tunnel-mode"] == "enable"
        assert data["split-tunneling"] == "disable"
        assert data["ip-pools"] == ["SSLVPN-pool"]
        assert data["web-mode"] == "enable"
        assert data["dns-server1"] == "198.51.100.53"

    @pytest.mark.asyncio
    async def test_no_fields_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_sslvpn_web_portal(
                device="FGT-01", name="full-access"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_rejects_invalid_tunnel_mode(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(vpn_tools, "get_fmg_client", return_value=mock_client):
            result = await vpn_tools.update_device_sslvpn_web_portal(
                device="FGT-01", name="full-access", tunnel_mode="maybe"
            )

        assert "error" in result
        mock_fmg_instance.update.assert_not_called()
