"""Tests for object_usage_tools module (where-used + duplicate detection)."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import object_usage_tools


def _noop_sleep_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace asyncio.sleep in the module with an instant no-op for fast tests."""

    async def _fake_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(object_usage_tools.asyncio, "sleep", _fake_sleep)


class TestObjectTypePath:
    """Test the object_type -> CMDB path fragment helper."""

    def test_known_types_resolve(self) -> None:
        assert object_usage_tools._object_type_path("address") == "firewall/address"
        assert object_usage_tools._object_type_path("address_group") == "firewall/addrgrp"
        assert object_usage_tools._object_type_path("service") == "firewall/service/custom"
        assert object_usage_tools._object_type_path("service_group") == "firewall/service/group"

    def test_unknown_type_raises_validation_error(self) -> None:
        with pytest.raises(object_usage_tools.ValidationError):
            object_usage_tools._object_type_path("bogus")


class TestWhereUsedObjRef:
    """Test the "obj" reference built for /cache/search/where/used/start."""

    def test_regular_adom_uses_adom_prefix(self) -> None:
        assert (
            object_usage_tools._where_used_obj_ref("root", "address")
            == "adom/root/obj/firewall/address"
        )

    def test_global_adom_uses_global_prefix(self) -> None:
        assert (
            object_usage_tools._where_used_obj_ref("global", "address")
            == "global/obj/firewall/address"
        )
        # Case-insensitive: FMG ADOM names are commonly typed "Global" too.
        assert (
            object_usage_tools._where_used_obj_ref("Global", "service_group")
            == "global/obj/firewall/service/group"
        )


class TestFindObjectUsage:
    """Test the where-used three-step async lookup."""

    @pytest.mark.asyncio
    async def test_success(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _noop_sleep_patch(monkeypatch)

        def _execute(url: str, *args: Any, **kwargs: Any) -> tuple[int, Any]:
            if url == "/cache/search/where/used/start":
                assert kwargs["mkey"] == "WebServer"
                assert kwargs["obj"] == "adom/root/obj/firewall/address"
                return (0, {"token": "tok123"})
            if url == "/cache/search/where/used/get/summary":
                # token must be a flat sibling of 'url', not nested under 'data'
                assert args == ({"token": "tok123"},)
                return (0, {"percent": 100})
            if url == "/cache/search/where/used/get/detail":
                assert args == ({"token": "tok123"},)
                return (
                    0,
                    {
                        "percent": 100,
                        "total_num": 1,
                        "where_used": [
                            {
                                "root": {"name": "root", "oid": 3},
                                "data": [
                                    {
                                        "attr": "dstaddr",
                                        "mapping_name": "firewall policy",
                                        "mattr": "policyid",
                                        "mkey": "4",
                                        "pkg": {"name": "default", "oid": 10},
                                    }
                                ],
                            }
                        ],
                    },
                )
            raise AssertionError(f"unexpected exec url: {url}")

        mock_fmg_instance.execute.side_effect = _execute

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_object_usage("root", "WebServer")

        assert result["status"] == "success"
        assert result["object_name"] == "WebServer"
        assert result["object_type"] == "address"
        assert result["total_matches"] == 1
        assert len(result["used_in"]) == 1
        assert result["used_in"][0]["data"][0]["mapping_name"] == "firewall policy"

    @pytest.mark.asyncio
    async def test_global_adom_builds_global_obj_ref(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _noop_sleep_patch(monkeypatch)

        def _execute(url: str, *args: Any, **kwargs: Any) -> tuple[int, Any]:
            if url == "/cache/search/where/used/start":
                assert kwargs["obj"] == "global/obj/firewall/address"
                return (0, {"token": "tok"})
            if url == "/cache/search/where/used/get/summary":
                assert args == ({"token": "tok"},)
                return (0, {"percent": 100})
            if url == "/cache/search/where/used/get/detail":
                assert args == ({"token": "tok"},)
                return (0, {"percent": 100, "total_num": 0, "where_used": []})
            raise AssertionError(f"unexpected exec url: {url}")

        mock_fmg_instance.execute.side_effect = _execute

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_object_usage("global", "g_host_001")

        assert result["status"] == "success"
        assert result["total_matches"] == 0

    @pytest.mark.asyncio
    async def test_polls_until_complete(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _noop_sleep_patch(monkeypatch)
        percents = iter([0, 50, 100])

        def _execute(url: str, *args: Any, **kwargs: Any) -> tuple[int, Any]:
            if url == "/cache/search/where/used/start":
                return (0, {"token": "tok"})
            if url == "/cache/search/where/used/get/summary":
                return (0, {"percent": next(percents)})
            if url == "/cache/search/where/used/get/detail":
                return (0, {"percent": 100, "total_num": 0, "where_used": []})
            raise AssertionError(f"unexpected exec url: {url}")

        mock_fmg_instance.execute.side_effect = _execute

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_object_usage("root", "WebServer")

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_timeout_returns_error(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
    ) -> None:
        # Deliberately does NOT patch time.monotonic: object_usage_tools.time
        # is the real `time` module (not a namespaced copy), and asyncio's
        # own event-loop clock reads from it too, so globally monkeypatching
        # it corrupts the loop's internal scheduling and can hang the test
        # runner. Real asyncio.sleep is left in place too, for the same
        # reason -- only a tiny real timeout/poll_interval is used instead,
        # matching the wait_for_task tests in test_task_guard.py.
        def _execute(url: str, *args: Any, **kwargs: Any) -> tuple[int, Any]:
            if url == "/cache/search/where/used/start":
                return (0, {"token": "tok"})
            if url == "/cache/search/where/used/get/summary":
                return (0, {"percent": 40})
            raise AssertionError(f"unexpected exec url: {url}")

        mock_fmg_instance.execute.side_effect = _execute

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_object_usage(
                "root", "WebServer", timeout=1, poll_interval=1
            )

        assert result["status"] == "error"
        assert result["error_code"] == "timeout"

    @pytest.mark.asyncio
    async def test_missing_token_is_an_error(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {})

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_object_usage("root", "WebServer")

        assert result["status"] == "error"
        assert result["error_code"] == "api_error"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch("fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=None):
            result = await object_usage_tools.find_object_usage("root", "WebServer")

        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_invalid_object_type(self) -> None:
        result = await object_usage_tools.find_object_usage(
            "root", "WebServer", object_type="not-a-type"
        )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_invalid_adom(self) -> None:
        result = await object_usage_tools.find_object_usage("bad adom!", "WebServer")

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"


class TestFindDuplicateObjects:
    """Test the "find duplicates" scan."""

    @pytest.mark.asyncio
    async def test_success_with_duplicates(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
    ) -> None:
        def _get(url: str, **kwargs: Any) -> tuple[int, Any]:
            assert url == "/pm/config/adom/root/obj/firewall/address"
            assert kwargs["option"] == ["find duplicates"]
            assert kwargs["load assigned"] == 0
            assert kwargs["loadsub"] == 0
            assert "fields" not in kwargs
            return (
                0,
                [
                    {
                        "name": "gmail.com",
                        "type": "fqdn",
                        "subnet": ["0.0.0.0", "0.0.0.0"],
                        "duplicate entries": ["login.microsoft.com", "wildcard.google.com"],
                    },
                    {
                        "name": "host_001_001",
                        "type": "ipmask",
                        "subnet": ["10.0.0.1", "255.255.255.255"],
                    },
                ],
            )

        mock_fmg_instance.get.side_effect = _get

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_duplicate_objects("root")

        assert result["status"] == "success"
        assert result["object_type"] == "address"
        assert len(result["objects"]) == 2
        assert result["duplicate_count"] == 1

    @pytest.mark.asyncio
    async def test_no_duplicates(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "unique-host", "subnet": ["10.0.0.1", "255.255.255.255"]}],
        )

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_duplicate_objects("root")

        assert result["status"] == "success"
        assert result["duplicate_count"] == 0

    @pytest.mark.asyncio
    async def test_fields_are_forwarded(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
    ) -> None:
        captured: dict[str, Any] = {}

        def _get(url: str, **kwargs: Any) -> tuple[int, Any]:
            captured.update(kwargs)
            return (0, [])

        mock_fmg_instance.get.side_effect = _get

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            result = await object_usage_tools.find_duplicate_objects(
                "root", fields=["name", "subnet"]
            )

        assert result["status"] == "success"
        assert captured["fields"] == ["name", "subnet"]

    @pytest.mark.asyncio
    async def test_other_object_types_use_correct_url(
        self,
        mock_client: Any,
        mock_fmg_instance: MagicMock,
    ) -> None:
        captured_urls: list[str] = []

        def _get(url: str, **kwargs: Any) -> tuple[int, Any]:
            captured_urls.append(url)
            return (0, [])

        mock_fmg_instance.get.side_effect = _get

        with patch(
            "fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=mock_client
        ):
            await object_usage_tools.find_duplicate_objects("root", object_type="address_group")
            await object_usage_tools.find_duplicate_objects("root", object_type="service")
            await object_usage_tools.find_duplicate_objects("root", object_type="service_group")

        assert captured_urls == [
            "/pm/config/adom/root/obj/firewall/addrgrp",
            "/pm/config/adom/root/obj/firewall/service/custom",
            "/pm/config/adom/root/obj/firewall/service/group",
        ]

    @pytest.mark.asyncio
    async def test_invalid_object_type(self) -> None:
        result = await object_usage_tools.find_duplicate_objects("root", object_type="not-a-type")

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_invalid_adom(self) -> None:
        result = await object_usage_tools.find_duplicate_objects("bad adom!")

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch("fortimanager_mcp.tools.object_usage_tools.get_fmg_client", return_value=None):
            result = await object_usage_tools.find_duplicate_objects("root")

        assert result["status"] == "error"


class TestGlobalAdomObjectPath:
    """The Global ADOM has its own branch of the object tree.

    Live-verified against a lab FortiManager while closing upstream #71:
    /pm/config/global/obj/firewall/address returns objects, while
    /pm/config/adom/global/obj/firewall/address is refused with
    "Invalid url". find_duplicate_objects built the second form, so it
    could never have worked against Global.
    """

    def test_global_adom_does_not_go_through_the_adom_branch(self) -> None:
        assert object_usage_tools._obj_path("global", "address") == "global/obj/firewall/address"

    def test_global_is_matched_case_insensitively(self) -> None:
        assert object_usage_tools._obj_path("Global", "address").startswith("global/obj/")

    def test_a_named_adom_still_goes_through_the_adom_branch(self) -> None:
        assert object_usage_tools._obj_path("demo", "address") == "adom/demo/obj/firewall/address"

    def test_both_callers_agree_on_every_adom(self) -> None:
        """The two builders disagreeing is the bug itself, so pin that they
        cannot drift apart again."""
        for adom in ("global", "Global", "demo", "root"):
            assert object_usage_tools._where_used_obj_ref(adom, "address") == (
                object_usage_tools._obj_path(adom, "address")
            )

    @pytest.mark.asyncio
    async def test_find_duplicate_objects_uses_the_global_branch(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(object_usage_tools, "get_fmg_client", return_value=mock_client):
            result = await object_usage_tools.find_duplicate_objects("global", "address")

        assert result["status"] == "success"
        assert mock_fmg_instance.get.call_args.args[0] == "/pm/config/global/obj/firewall/address"
