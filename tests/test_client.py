"""Tests for FortiManager API client."""

from typing import Any
from unittest.mock import MagicMock

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils.errors import (
    APIError,
    ConnectionError,
    FortiManagerMCPError,
    PermissionError,
    parse_fmg_error,
)


class TestClientInitialization:
    """Test client initialization."""

    def test_init_with_api_token(self) -> None:
        """Test initialization with API token."""
        client = FortiManagerClient(
            host="test-fmg.example.com",
            api_token="test-token",
        )
        assert client.host == "test-fmg.example.com"
        assert client.api_token == "test-token"
        assert not client.is_connected

    def test_init_with_credentials(self) -> None:
        """Test initialization with username/password."""
        client = FortiManagerClient(
            host="https://test-fmg.example.com/",
            username="admin",
            password="password",
        )
        # Should strip protocol and trailing slash
        assert client.host == "test-fmg.example.com"
        assert client.username == "admin"
        assert client.password == "password"

    def test_init_default_values(self) -> None:
        """Test default configuration values."""
        client = FortiManagerClient(host="test-fmg.example.com")
        assert client.verify_ssl is True
        assert client.timeout == 30
        assert client.max_retries == 3


class TestClientConnection:
    """Test client connection methods."""

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, mock_client: FortiManagerClient) -> None:
        """Test connecting when already connected logs warning."""
        # Client is already connected via fixture
        assert mock_client.is_connected
        # Calling connect again should not raise
        await mock_client.connect()
        assert mock_client.is_connected

    @pytest.mark.asyncio
    async def test_disconnect(self, mock_client: FortiManagerClient) -> None:
        """Test disconnection."""
        assert mock_client.is_connected
        await mock_client.disconnect()
        assert not mock_client.is_connected

    @pytest.mark.asyncio
    async def test_ensure_connected_raises_when_disconnected(
        self, mock_client_disconnected: FortiManagerClient
    ) -> None:
        """Test that operations fail when disconnected."""
        with pytest.raises(ConnectionError):
            mock_client_disconnected._ensure_connected()


class TestClientOperations:
    """Test client API operations."""

    @pytest.mark.asyncio
    async def test_get_system_status(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test getting system status."""
        result = await mock_client.get_system_status()
        assert result["Version"] == "v7.6.5"
        assert result["Hostname"] == "FMG-TEST"

    @pytest.mark.asyncio
    async def test_list_adoms(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing ADOMs."""
        result = await mock_client.list_adoms()
        assert len(result) == 2
        assert result[0]["name"] == "root"
        assert result[1]["name"] == "demo"

    @pytest.mark.asyncio
    async def test_list_devices(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing devices."""
        result = await mock_client.list_devices(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "FGT-01"

    @pytest.mark.asyncio
    async def test_list_packages(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test listing packages."""
        result = await mock_client.list_packages(adom="root")
        assert len(result) == 2
        assert result[0]["name"] == "default"

    @pytest.mark.asyncio
    async def test_install_package_returns_task(
        self,
        mock_client: FortiManagerClient,
        configure_mock_responses: None,
    ) -> None:
        """Test package installation returns task ID."""
        result = await mock_client.install_package(
            adom="root",
            pkg="default",
            scope=[{"name": "FGT-01", "vdom": "root"}],
        )
        assert "task" in result
        assert result["task"] == 123


class TestErrorHandling:
    """Test error handling."""

    def test_parse_fmg_error_known_code(self) -> None:
        """Test parsing known error codes."""
        error = parse_fmg_error(-3, "Not found", "GET /test")
        assert isinstance(error, PermissionError)
        assert "Permission denied" in str(error)

    def test_parse_fmg_error_unknown_code(self) -> None:
        """Test parsing unknown error codes."""
        error = parse_fmg_error(-999, "Unknown error", "GET /test")
        assert isinstance(error, APIError)
        assert "Unknown error" in str(error)

    @pytest.mark.asyncio
    async def test_handle_error_response(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Test handling error responses from API."""
        mock_fmg_instance.get.return_value = (-3, {"status": {"message": "Not found"}})

        with pytest.raises(FortiManagerMCPError) as exc_info:
            await mock_client.get("/test/url")

        assert "Permission denied" in str(exc_info.value)


class TestScriptTargetMapping:
    """Regression tests for GitHub issue #3.

    The FMG 7.6+ /pm/config/.../script endpoint expects an integer `target`
    and silently coerces unknown values (including legacy strings) to 0
    (device_database). The client must map strings -> ints when talking to
    the new endpoint, and leave strings untouched on the legacy /dvmdb
    endpoint. Responses go the other way to keep the public surface
    string-typed.
    """

    @pytest.mark.asyncio
    async def test_create_script_maps_target_on_new_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.6+: target string must be converted to integer."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, {"Version": "v7.6.5"})
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={
                "name": "reboot-fgt",
                "content": "execute reboot",
                "type": "cli",
                "target": "remote_device",
            },
        )

        mock_fmg_instance.add.assert_called_once()
        call_args = mock_fmg_instance.add.call_args
        url = call_args.args[0]
        body = call_args.kwargs["data"]
        assert url == "/pm/config/adom/root/obj/fmg/script"
        assert body["target"] == 2, "remote_device must map to 2 on FMG 7.6+"
        assert isinstance(body["target"], int)

    @pytest.mark.asyncio
    async def test_create_script_maps_all_known_targets(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Each documented target string maps to the expected integer."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        expected = {
            "device_database": 0,
            "adom_database": 1,
            "remote_device": 2,
        }

        for target_str, target_int in expected.items():
            mock_fmg_instance.add.reset_mock()
            await mock_client.create_script(
                adom="root",
                script={"name": f"s-{target_str}", "content": "noop", "target": target_str},
            )
            body = mock_fmg_instance.add.call_args.kwargs["data"]
            assert body["target"] == target_int, (
                f"{target_str} should map to {target_int}, got {body['target']!r}"
            )

    @pytest.mark.asyncio
    async def test_create_script_passes_target_through_on_legacy_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.0-7.4: legacy endpoint accepts strings, must not be remapped."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={
                "name": "reboot-fgt",
                "content": "execute reboot",
                "type": "cli",
                "target": "remote_device",
            },
        )

        call_args = mock_fmg_instance.add.call_args
        url = call_args.args[0]
        body = call_args.kwargs["data"]
        assert url == "/dvmdb/adom/root/script"
        assert body["target"] == "remote_device"
        assert isinstance(body["target"], str)

    @pytest.mark.asyncio
    async def test_create_script_unknown_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Unknown target strings are not silently rewritten to 0."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={"name": "weird", "content": "noop", "target": "not_a_real_target"},
        )

        body = mock_fmg_instance.add.call_args.kwargs["data"]
        assert body["target"] == "not_a_real_target"

    @pytest.mark.asyncio
    async def test_create_script_integer_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A caller passing an int already (advanced use) is left alone."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={"name": "preformatted", "content": "noop", "target": 2},
        )

        body = mock_fmg_instance.add.call_args.kwargs["data"]
        assert body["target"] == 2

    @pytest.mark.asyncio
    async def test_create_script_no_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Scripts without a target field are unaffected."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.add.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.create_script(
            adom="root",
            script={"name": "no-target", "content": "noop"},
        )

        body = mock_fmg_instance.add.call_args.kwargs["data"]
        assert "target" not in body

    @pytest.mark.asyncio
    async def test_update_script_maps_target_on_new_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """update_script must also apply the mapping on FMG 7.6+."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.update.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.update_script(
            adom="root",
            name="existing",
            data={"target": "adom_database", "desc": "updated"},
        )

        call_args = mock_fmg_instance.update.call_args
        url = call_args.args[0]
        body = call_args.kwargs["data"]
        assert url == "/pm/config/adom/root/obj/fmg/script/existing"
        assert body["target"] == 1
        assert body["desc"] == "updated"

    @pytest.mark.asyncio
    async def test_update_script_passes_target_through_on_legacy_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """update_script leaves string targets alone on FMG 7.0-7.4."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.update.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        await mock_client.update_script(
            adom="root",
            name="existing",
            data={"target": "remote_device"},
        )

        body = mock_fmg_instance.update.call_args.kwargs["data"]
        assert body["target"] == "remote_device"

    @pytest.mark.asyncio
    async def test_list_scripts_reverse_maps_int_target(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Responses from FMG 7.6+ contain int targets; callers see strings."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (
            0,
            [
                {"name": "s1", "target": 0},
                {"name": "s2", "target": 1},
                {"name": "s3", "target": 2},
            ],
        )

        scripts = await mock_client.list_scripts(adom="root")
        targets = {s["name"]: s["target"] for s in scripts}
        assert targets == {
            "s1": "device_database",
            "s2": "adom_database",
            "s3": "remote_device",
        }

    @pytest.mark.asyncio
    async def test_list_scripts_leaves_string_targets_alone(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Legacy responses already contain string targets; pass them through."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "s1", "target": "device_database"}],
        )

        scripts = await mock_client.list_scripts(adom="root")
        assert scripts[0]["target"] == "device_database"

    @pytest.mark.asyncio
    async def test_get_script_reverse_maps_int_target(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """get_script reverses the mapping on FMG 7.6+ for the single result."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, {"name": "s1", "target": 2})

        script = await mock_client.get_script(adom="root", name="s1")
        assert script["target"] == "remote_device"

    def test_uses_new_script_endpoint_predicate(self) -> None:
        """The version predicate matches the script endpoint branch exactly."""
        client = FortiManagerClient(host="test.example.com", api_token="t")
        cases: list[tuple[Any, bool]] = [
            (None, False),
            ((7, 0, 0), False),
            ((7, 4, 5), False),
            ((7, 5, 99), False),
            ((7, 6, 0), True),
            ((7, 6, 5), True),
            ((8, 0, 0), True),
        ]
        for version, expected in cases:
            client._fmg_version = version
            assert client._uses_new_script_endpoint() is expected, (
                f"version {version} should yield {expected}"
            )

    @pytest.mark.asyncio
    async def test_list_scripts_maps_all_target_filter_values(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.6+: each documented target string maps to int in filter."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        expected = {"device_database": 0, "adom_database": 1, "remote_device": 2}
        for target_str, target_int in expected.items():
            mock_fmg_instance.get.reset_mock()
            await mock_client.list_scripts(
                adom="root",
                filter=[["target", "==", target_str]],
            )
            params = mock_fmg_instance.get.call_args.kwargs
            assert params["filter"] == [["target", "==", target_int]], (
                f"filter target=={target_str} should send int {target_int}, "
                f"got {params['filter']!r}"
            )

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_passes_through_on_legacy_endpoint(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """FMG 7.0-7.4: legacy endpoint stores strings; filter unchanged."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "==", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "==", "remote_device"]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_with_compound_conditions(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Target mapping must coexist with other conditions in the filter."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[
                ["type", "==", "cli"],
                ["target", "==", "remote_device"],
            ],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [
            ["type", "==", "cli"],
            ["target", "==", 2],
        ]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_unknown_value_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Unknown target values are left for FMG to reject explicitly."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "==", "not_a_real_target"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "==", "not_a_real_target"]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_non_eq_operator_mapped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Non-`==` operators (e.g. `!=`) on target are still mapped."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "!=", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "!=", 2]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_int_value_unchanged(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """A caller passing an int already (advanced use) is left alone."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "==", 2]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "==", 2]]

    @pytest.mark.asyncio
    async def test_list_scripts_no_filter_unchanged(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Calling without a filter must not forward one."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(adom="root")

        params = mock_fmg_instance.get.call_args.kwargs
        assert "filter" not in params

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_mapped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """`["target", "in", v1, v2, ...]` maps each known string value."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "in", "device_database", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "in", 0, 2]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_not_in_operator_mapped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """`["target", "!in", ...]` is treated the same as `in`."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "!in", "remote_device", "adom_database"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "!in", 2, 1]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_mixed_values(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Unknown values inside `in` are left untouched; known ones mapped."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "in", "device_database", "not_a_real_target", 2]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "in", 0, "not_a_real_target", 2]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_legacy_passthrough(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """Legacy /dvmdb endpoint stores strings — `in` filter unchanged."""
        mock_client._fmg_version = (7, 4, 0)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "in", "device_database", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "in", "device_database", "remote_device"]]

    @pytest.mark.asyncio
    async def test_list_scripts_target_filter_in_operator_inside_compound(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """`in` filter on target coexists with other compound conditions."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        await mock_client.list_scripts(
            adom="root",
            filter=[
                ["type", "==", "cli"],
                ["target", "in", "remote_device", "adom_database"],
            ],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [
            ["type", "==", "cli"],
            ["target", "in", 2, 1],
        ]

    @pytest.mark.asyncio
    async def test_list_scripts_unknown_operator_on_target_passes_through(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
    ) -> None:
        """3-element list with an unrecognized operator is left alone."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        # "weird_op" is not a known FMG comparison operator
        await mock_client.list_scripts(
            adom="root",
            filter=[["target", "weird_op", "remote_device"]],
        )

        params = mock_fmg_instance.get.call_args.kwargs
        assert params["filter"] == [["target", "weird_op", "remote_device"]]
