"""Tests for security_profile_advanced_tools module."""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.tools import security_profile_advanced_tools as spat


class TestIpsSensorTools:
    """Test IPS sensor tools."""

    @pytest.mark.asyncio
    async def test_list_ips_sensors_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing IPS sensors."""
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "default"}, {"name": "Custom-IPS"}],
        )

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.list_ips_sensors(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        url = mock_fmg_instance.get.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/ips/sensor"

    @pytest.mark.asyncio
    async def test_list_ips_sensors_not_connected(self) -> None:
        """Test listing IPS sensors when client is not connected."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=None,
        ):
            result = await spat.list_ips_sensors(adom="root")

        assert result["status"] == "error"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_get_ips_sensor_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific IPS sensor."""
        mock_fmg_instance.get.return_value = (0, {"name": "Custom-IPS", "entries": []})

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.get_ips_sensor(adom="root", name="Custom-IPS")

        assert result["status"] == "success"
        assert result["sensor"]["name"] == "Custom-IPS"

    @pytest.mark.asyncio
    async def test_create_ips_sensor_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating an IPS sensor and the payload sent to FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_ips_sensor(
                adom="root",
                name="Custom-IPS",
                scan_botnet_connections="block",
                comment="baseline",
            )

        assert result["status"] == "success"
        assert result["name"] == "Custom-IPS"
        url = mock_fmg_instance.add.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/ips/sensor"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["name"] == "Custom-IPS"
        assert data["scan-botnet-connections"] == "block"
        assert data["comment"] == "baseline"

    @pytest.mark.asyncio
    async def test_create_ips_sensor_invalid_botnet_mode(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test invalid scan_botnet_connections is rejected before any API call."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_ips_sensor(
                adom="root",
                name="Custom-IPS",
                scan_botnet_connections="quarantine",
            )

        assert result["status"] == "error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_ips_sensor_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating an IPS sensor's top-level settings."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.update_ips_sensor(
                adom="root",
                name="Custom-IPS",
                extended_log="enable",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data == {"extended-log": "enable"}

    @pytest.mark.asyncio
    async def test_update_ips_sensor_no_params(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test update with no parameters returns an error without calling FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.update_ips_sensor(adom="root", name="Custom-IPS")

        assert result["status"] == "error"
        assert "No update parameters" in result["message"]
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_ips_sensor_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting an IPS sensor."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.delete_ips_sensor(adom="root", name="Custom-IPS")

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/ips/sensor/Custom-IPS"

    @pytest.mark.asyncio
    async def test_list_ips_sensor_signature_overrides_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing a sensor's signature-override entries."""
        mock_fmg_instance.get.return_value = (0, [{"id": 1, "rule": ["trojan.generic"]}])

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.list_ips_sensor_signature_overrides(
                adom="root", sensor="Custom-IPS"
            )

        assert result["status"] == "success"
        assert result["count"] == 1
        url = mock_fmg_instance.get.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/ips/sensor/Custom-IPS/entries"

    @pytest.mark.asyncio
    async def test_add_ips_sensor_signature_override_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test adding a signature override and the exact payload sent to FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.add_ips_sensor_signature_override(
                adom="root",
                sensor="Custom-IPS",
                rule=["trojan.generic"],
                action="block",
                log="enable",
            )

        assert result["status"] == "success"
        assert result["sensor"] == "Custom-IPS"
        url = mock_fmg_instance.add.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/ips/sensor/Custom-IPS/entries"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["rule"] == ["trojan.generic"]
        assert data["action"] == "block"
        assert data["log"] == "enable"
        assert data["status"] == "enable"  # default
        assert "id" not in data

    @pytest.mark.asyncio
    async def test_add_ips_sensor_signature_override_with_explicit_id(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test an explicit entry_id is passed through as the entry's id."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.add_ips_sensor_signature_override(
                adom="root",
                sensor="Custom-IPS",
                entry_id=42,
                severity=["critical"],
                default_action="block",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["id"] == 42
        assert data["severity"] == ["critical"]
        assert data["default-action"] == "block"

    @pytest.mark.asyncio
    async def test_add_ips_sensor_signature_override_invalid_action(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test an invalid action enum is rejected before any API call."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.add_ips_sensor_signature_override(
                adom="root",
                sensor="Custom-IPS",
                action="quarantine",
            )

        assert result["status"] == "error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_ips_sensor_signature_override_invalid_entry_id(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test an out-of-range entry_id is rejected before any API call."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.add_ips_sensor_signature_override(
                adom="root",
                sensor="Custom-IPS",
                entry_id=-1,
            )

        assert result["status"] == "error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_remove_ips_sensor_signature_override_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test removing a signature override by entry id."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.remove_ips_sensor_signature_override(
                adom="root",
                sensor="Custom-IPS",
                entry_id=42,
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/ips/sensor/Custom-IPS/entries/42"

    @pytest.mark.asyncio
    async def test_remove_ips_sensor_signature_override_invalid_entry_id(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test an out-of-range entry_id is rejected before any API call."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.remove_ips_sensor_signature_override(
                adom="root",
                sensor="Custom-IPS",
                entry_id=4294967296,
            )

        assert result["status"] == "error"
        mock_fmg_instance.delete.assert_not_called()


class TestSslSshProfileTools:
    """Test SSL/SSH inspection profile tools."""

    @pytest.mark.asyncio
    async def test_list_ssl_ssh_profiles_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing SSL/SSH profiles."""
        mock_fmg_instance.get.return_value = (0, [{"name": "certificate-inspection"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.list_ssl_ssh_profiles(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_get_ssl_ssh_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific SSL/SSH profile."""
        mock_fmg_instance.get.return_value = (0, {"name": "Custom-Deep"})

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.get_ssl_ssh_profile(adom="root", name="Custom-Deep")

        assert result["status"] == "success"
        assert result["profile"]["name"] == "Custom-Deep"

    @pytest.mark.asyncio
    async def test_create_ssl_ssh_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating an SSL/SSH profile builds the nested ssl/https objects."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_ssl_ssh_profile(
                adom="root",
                name="Custom-Deep",
                ssl_inspection="deep-inspection",
                https_inspection="deep-inspection",
                server_cert_mode="re-sign",
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.add.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/firewall/ssl-ssh-profile"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["name"] == "Custom-Deep"
        assert data["ssl"] == {"inspect-all": "deep-inspection"}
        assert data["https"] == {"status": "deep-inspection"}
        assert data["server-cert-mode"] == "re-sign"

    @pytest.mark.asyncio
    async def test_create_ssl_ssh_profile_invalid_inspection_level(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test an invalid inspection level is rejected before any API call."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_ssl_ssh_profile(
                adom="root",
                name="Custom-Deep",
                ssl_inspection="full-inspection",
            )

        assert result["status"] == "error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_ssl_ssh_profile_only_specified_fields(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test update only sends the fields that were explicitly passed."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.update_ssl_ssh_profile(
                adom="root",
                name="Custom-Deep",
                comment="reviewed",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data == {"comment": "reviewed"}

    @pytest.mark.asyncio
    async def test_update_ssl_ssh_profile_no_params(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test update with no parameters returns an error without calling FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.update_ssl_ssh_profile(adom="root", name="Custom-Deep")

        assert result["status"] == "error"
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_ssl_ssh_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting an SSL/SSH profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.delete_ssl_ssh_profile(adom="root", name="Custom-Deep")

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/firewall/ssl-ssh-profile/Custom-Deep"


class TestDlpProfileTools:
    """Test DLP profile tools."""

    @pytest.mark.asyncio
    async def test_list_dlp_profiles_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing DLP profiles."""
        mock_fmg_instance.get.return_value = (0, [{"name": "Custom-DLP"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.list_dlp_profiles(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_get_dlp_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific DLP profile."""
        mock_fmg_instance.get.return_value = (0, {"name": "Custom-DLP"})

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.get_dlp_profile(adom="root", name="Custom-DLP")

        assert result["status"] == "success"
        assert result["profile"]["name"] == "Custom-DLP"

    @pytest.mark.asyncio
    async def test_create_dlp_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating a DLP profile and the payload sent to FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_dlp_profile(
                adom="root",
                name="Custom-DLP",
                feature_set="flow",
                dlp_log="enable",
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.add.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/dlp/profile"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["name"] == "Custom-DLP"
        assert data["feature-set"] == "flow"
        assert data["dlp-log"] == "enable"

    @pytest.mark.asyncio
    async def test_create_dlp_profile_invalid_feature_set(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test an invalid feature_set is rejected before any API call."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_dlp_profile(
                adom="root",
                name="Custom-DLP",
                feature_set="hybrid",
            )

        assert result["status"] == "error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_dlp_profile_no_params(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test update with no parameters returns an error without calling FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.update_dlp_profile(adom="root", name="Custom-DLP")

        assert result["status"] == "error"
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_dlp_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting a DLP profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.delete_dlp_profile(adom="root", name="Custom-DLP")

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/dlp/profile/Custom-DLP"


class TestWafProfileTools:
    """Test WAF profile tools."""

    @pytest.mark.asyncio
    async def test_list_waf_profiles_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing WAF profiles."""
        mock_fmg_instance.get.return_value = (0, [{"name": "Custom-WAF"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.list_waf_profiles(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_get_waf_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific WAF profile."""
        mock_fmg_instance.get.return_value = (0, {"name": "Custom-WAF"})

        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.get_waf_profile(adom="root", name="Custom-WAF")

        assert result["status"] == "success"
        assert result["profile"]["name"] == "Custom-WAF"

    @pytest.mark.asyncio
    async def test_create_waf_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating a WAF profile and the payload sent to FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_waf_profile(
                adom="root",
                name="Custom-WAF",
                extended_log="enable",
                comment="baseline",
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.add.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/waf/profile"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data["name"] == "Custom-WAF"
        assert data["extended-log"] == "enable"
        assert data["comment"] == "baseline"

    @pytest.mark.asyncio
    async def test_create_waf_profile_invalid_status_value(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test an invalid enable/disable value is rejected before any API call."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.create_waf_profile(
                adom="root",
                name="Custom-WAF",
                external="maybe",
            )

        assert result["status"] == "error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_waf_profile_no_params(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test update with no parameters returns an error without calling FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.update_waf_profile(adom="root", name="Custom-WAF")

        assert result["status"] == "error"
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_waf_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting a WAF profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_advanced_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await spat.delete_waf_profile(adom="root", name="Custom-WAF")

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/waf/profile/Custom-WAF"
