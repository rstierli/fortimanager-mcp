"""Tests for security_profile_tools module."""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.tools import security_profile_tools


class TestAntivirusProfileTools:
    """Test antivirus profile tools."""

    @pytest.mark.asyncio
    async def test_list_antivirus_profiles_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing antivirus profiles."""
        mock_fmg_instance.get.return_value = (0, [{"name": "default"}, {"name": "strict-av"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.list_antivirus_profiles(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        url = mock_fmg_instance.get.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/antivirus/profile"

    @pytest.mark.asyncio
    async def test_list_antivirus_profiles_not_connected(self) -> None:
        """Test listing antivirus profiles when client not connected."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=None,
        ):
            result = await security_profile_tools.list_antivirus_profiles(adom="root")

        assert result["status"] == "error"
        assert "message" in result

    @pytest.mark.asyncio
    async def test_list_antivirus_profiles_with_name_filter(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test that a name filter is forwarded to the FMG GET call."""
        mock_fmg_instance.get.return_value = (0, [{"name": "strict-av"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.list_antivirus_profiles(
                adom="root", name_filter="strict"
            )

        assert result["status"] == "success"
        kwargs = mock_fmg_instance.get.call_args.kwargs
        assert kwargs["filter"] == [["name", "contain", "strict"]]

    @pytest.mark.asyncio
    async def test_get_antivirus_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific antivirus profile."""
        mock_fmg_instance.get.return_value = (0, {"name": "default", "feature-set": "flow"})

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.get_antivirus_profile(adom="root", name="default")

        assert result["status"] == "success"
        assert result["profile"]["name"] == "default"
        url = mock_fmg_instance.get.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/antivirus/profile/default"

    @pytest.mark.asyncio
    async def test_create_antivirus_profile_success(
        self,
        mock_client: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test creating an antivirus profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.create_antivirus_profile(
                adom="root",
                name="strict-av",
                feature_set="flow",
                av_virus_log="enable",
            )

        assert result["status"] == "success"
        assert result["name"] == "strict-av"

    @pytest.mark.asyncio
    async def test_create_antivirus_profile_field_mapping(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Optional args must map to the hyphenated FMG field names."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            await security_profile_tools.create_antivirus_profile(
                adom="root",
                name="strict-av",
                comment="test",
                feature_set="flow",
                scan_mode="legacy",
                av_virus_log="enable",
            )

        url = mock_fmg_instance.add.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/antivirus/profile"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data == {
            "name": "strict-av",
            "comment": "test",
            "feature-set": "flow",
            "scan-mode": "legacy",
            "av-virus-log": "enable",
        }

    @pytest.mark.asyncio
    async def test_create_antivirus_profile_minimal(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Optional fields are omitted from the payload when not provided."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.create_antivirus_profile(
                adom="root", name="bare-av"
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data == {"name": "bare-av"}

    @pytest.mark.asyncio
    async def test_update_antivirus_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating an antivirus profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.update_antivirus_profile(
                adom="root",
                name="default",
                av_virus_log="disable",
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.update.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/antivirus/profile/default"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data == {"av-virus-log": "disable"}

    @pytest.mark.asyncio
    async def test_update_antivirus_profile_no_params(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Update with no parameters returns an error without calling FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.update_antivirus_profile(
                adom="root", name="default"
            )

        assert result["status"] == "error"
        assert "No update parameters" in result["message"]
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_antivirus_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting an antivirus profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.delete_antivirus_profile(
                adom="root", name="strict-av"
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/antivirus/profile/strict-av"


class TestWebfilterProfileTools:
    """Test web filter profile tools."""

    @pytest.mark.asyncio
    async def test_list_webfilter_profiles_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing web filter profiles."""
        mock_fmg_instance.get.return_value = (0, [{"name": "default"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.list_webfilter_profiles(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        url = mock_fmg_instance.get.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/webfilter/profile"

    @pytest.mark.asyncio
    async def test_get_webfilter_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific web filter profile."""
        mock_fmg_instance.get.return_value = (0, {"name": "default"})

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.get_webfilter_profile(adom="root", name="default")

        assert result["status"] == "success"
        assert result["profile"]["name"] == "default"

    @pytest.mark.asyncio
    async def test_create_webfilter_profile_field_mapping(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Optional args must map to the hyphenated FMG field names."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.create_webfilter_profile(
                adom="root",
                name="strict-web",
                feature_set="flow",
                log_all_url="enable",
                web_content_log="enable",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data == {
            "name": "strict-web",
            "feature-set": "flow",
            "log-all-url": "enable",
            "web-content-log": "enable",
        }

    @pytest.mark.asyncio
    async def test_update_webfilter_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating a web filter profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.update_webfilter_profile(
                adom="root",
                name="default",
                comment="reviewed",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data == {"comment": "reviewed"}

    @pytest.mark.asyncio
    async def test_delete_webfilter_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting a web filter profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.delete_webfilter_profile(
                adom="root", name="strict-web"
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/webfilter/profile/strict-web"


class TestDnsfilterProfileTools:
    """Test DNS filter profile tools."""

    @pytest.mark.asyncio
    async def test_list_dnsfilter_profiles_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing DNS filter profiles."""
        mock_fmg_instance.get.return_value = (0, [{"name": "default"}, {"name": "strict-dns"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.list_dnsfilter_profiles(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 2
        url = mock_fmg_instance.get.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/dnsfilter/profile"

    @pytest.mark.asyncio
    async def test_get_dnsfilter_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific DNS filter profile."""
        mock_fmg_instance.get.return_value = (0, {"name": "default"})

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.get_dnsfilter_profile(adom="root", name="default")

        assert result["status"] == "success"
        assert result["profile"]["name"] == "default"

    @pytest.mark.asyncio
    async def test_create_dnsfilter_profile_field_mapping(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Optional args must map to the hyphenated FMG field names."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.create_dnsfilter_profile(
                adom="root",
                name="strict-dns",
                block_action="block",
                block_botnet="enable",
                safe_search="enable",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data == {
            "name": "strict-dns",
            "block-action": "block",
            "block-botnet": "enable",
            "safe-search": "enable",
        }

    @pytest.mark.asyncio
    async def test_update_dnsfilter_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating a DNS filter profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.update_dnsfilter_profile(
                adom="root",
                name="default",
                block_botnet="enable",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data == {"block-botnet": "enable"}

    @pytest.mark.asyncio
    async def test_update_dnsfilter_profile_no_params(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Update with no parameters returns an error without calling FMG."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.update_dnsfilter_profile(
                adom="root", name="default"
            )

        assert result["status"] == "error"
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_dnsfilter_profile_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting a DNS filter profile."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.delete_dnsfilter_profile(
                adom="root", name="strict-dns"
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/dnsfilter/profile/strict-dns"


class TestApplicationListTools:
    """Test application-control list tools."""

    @pytest.mark.asyncio
    async def test_list_application_lists_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test listing application-control lists."""
        mock_fmg_instance.get.return_value = (0, [{"name": "default"}])

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.list_application_lists(adom="root")

        assert result["status"] == "success"
        assert result["count"] == 1
        url = mock_fmg_instance.get.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/application/list"

    @pytest.mark.asyncio
    async def test_get_application_list_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test getting a specific application-control list."""
        mock_fmg_instance.get.return_value = (0, {"name": "default"})

        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.get_application_list(adom="root", name="default")

        assert result["status"] == "success"
        assert result["list"]["name"] == "default"

    @pytest.mark.asyncio
    async def test_create_application_list_field_mapping(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Optional args must map to the hyphenated FMG field names."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.create_application_list(
                adom="root",
                name="strict-appctrl",
                deep_app_inspection="enable",
                unknown_application_action="block",
                other_application_action="block",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert data == {
            "name": "strict-appctrl",
            "deep-app-inspection": "enable",
            "unknown-application-action": "block",
            "other-application-action": "block",
        }

    @pytest.mark.asyncio
    async def test_update_application_list_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test updating an application-control list."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.update_application_list(
                adom="root",
                name="default",
                unknown_application_action="block",
            )

        assert result["status"] == "success"
        data = mock_fmg_instance.update.call_args.kwargs
        assert data == {"unknown-application-action": "block"}

    @pytest.mark.asyncio
    async def test_delete_application_list_success(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
        configure_mock_responses: None,
    ) -> None:
        """Test deleting an application-control list."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.delete_application_list(
                adom="root", name="strict-appctrl"
            )

        assert result["status"] == "success"
        url = mock_fmg_instance.delete.call_args.args[0]
        assert url == "/pm/config/adom/root/obj/application/list/strict-appctrl"


class TestInputValidationRejection:
    """Malformed identifiers must be rejected before any API call."""

    @pytest.mark.asyncio
    async def test_get_antivirus_profile_rejects_path_injection_name(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A name with path separators must not reach the client."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.get_antivirus_profile(
                adom="root", name="../../sys/status"
            )

        assert result["status"] == "error"
        mock_fmg_instance.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_webfilter_profile_rejects_bad_adom(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A malformed ADOM name must not reach the client."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.delete_webfilter_profile(
                adom="root/../other", name="profile"
            )

        assert result["status"] == "error"
        mock_fmg_instance.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_dnsfilter_profile_rejects_empty_name(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """An empty profile name must not reach the client."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.create_dnsfilter_profile(adom="root", name="")

        assert result["status"] == "error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_application_list_rejects_path_injection_name(
        self,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A name with path separators must not reach the client."""
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            result = await security_profile_tools.update_application_list(
                adom="root", name="../etc/passwd", comment="x"
            )

        assert result["status"] == "error"
        mock_fmg_instance.update.assert_not_called()


class TestGlobalAdomUrlShape:
    """The Global ADOM has its own branch of the tree, not an ADOM named
    "global".

    ``object_usage_tools._obj_path`` records the live evidence:
    ``/pm/config/global/obj/firewall/address`` returns objects while
    ``/pm/config/adom/global/obj/firewall/address`` is refused with
    "Invalid url". PR #74 fixed that shape there; these four profile URL
    templates hardcode ``adom/{adom}`` and never got the branch (#82).

    The live evidence is for ``firewall/address``. These paths share the
    same URL grammar but were not themselves exercised against an
    appliance, so this is the grammar inferred, not the endpoint measured.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("tool", "tail"),
        [
            ("list_antivirus_profiles", "antivirus/profile"),
            ("list_webfilter_profiles", "webfilter/profile"),
            ("list_dnsfilter_profiles", "dnsfilter/profile"),
            ("list_application_lists", "application/list"),
        ],
    )
    async def test_global_uses_its_own_branch(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock, tool: str, tail: str
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            await getattr(security_profile_tools, tool)(adom="global")

        url = mock_fmg_instance.get.call_args.args[0]
        assert url == f"/pm/config/global/obj/{tail}"
        assert "adom/global" not in url

    @pytest.mark.asyncio
    async def test_global_is_matched_case_insensitively(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        """_obj_path lowercases before comparing, so this must too."""
        mock_fmg_instance.get.return_value = (0, [])
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            await security_profile_tools.list_antivirus_profiles(adom="Global")
        assert mock_fmg_instance.get.call_args.args[0] == "/pm/config/global/obj/antivirus/profile"

    @pytest.mark.asyncio
    async def test_an_ordinary_adom_is_unchanged(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        """The regression guard: every non-Global ADOM keeps the shape it
        has always had."""
        mock_fmg_instance.get.return_value = (0, [])
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            await security_profile_tools.list_antivirus_profiles(adom="root")
        assert (
            mock_fmg_instance.get.call_args.args[0] == "/pm/config/adom/root/obj/antivirus/profile"
        )

    @pytest.mark.asyncio
    async def test_the_single_object_paths_branch_too(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        """The finding is in the shared constant, so every tool built on it
        is affected, not just the list tools the issue names."""
        mock_fmg_instance.get.return_value = (0, {"name": "default"})
        with patch(
            "fortimanager_mcp.tools.security_profile_tools.get_fmg_client",
            return_value=mock_client,
        ):
            await security_profile_tools.get_antivirus_profile(adom="global", name="default")
        assert (
            mock_fmg_instance.get.call_args.args[0]
            == "/pm/config/global/obj/antivirus/profile/default"
        )
