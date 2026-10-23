"""Partial-match filters reach FortiManager as ``like``, not ``contain``.

On FortiManager 7.6.7, ``["name", "contain", term]`` compares a scalar string
field whole, so every "partial match" parameter below silently returned only
exact names, or nothing.
"""

import ast
import inspect
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.tools import (
    dvm_tools,
    object_tools,
    policy_tools,
    script_tools,
    security_profile_advanced_tools,
    security_profile_tools,
)
from fortimanager_mcp.utils.validation import and_filters, substring_filter

TOOLS_DIR = Path(object_tools.__file__).parent


class TestSubstringFilter:
    def test_wraps_term_in_wildcards(self) -> None:
        assert substring_filter("name", "Veeam") == ["name", "like", "%Veeam%"]

    @pytest.mark.parametrize(
        ("term", "pattern"),
        [
            ("TCP_8", "%TCP\\_8%"),
            ("50%", "%50\\%%"),
            ("a\\b", "%a\\\\b%"),
            # The backslash is escaped first, so an escape it introduces is
            # not itself doubled.
            ("\\_", "%\\\\\\_%"),
        ],
    )
    def test_escapes_like_metacharacters(self, term: str, pattern: str) -> None:
        assert substring_filter("name", term) == ["name", "like", pattern]


class TestAndFilters:
    """A bare list of conditions is an OR on FortiManager; "&&" is the AND."""

    def test_empty_is_none(self) -> None:
        assert and_filters([]) is None

    def test_single_condition_is_unchanged(self) -> None:
        assert and_filters([["name", "==", "a"]]) == [["name", "==", "a"]]

    def test_conditions_are_joined_with_and(self) -> None:
        a, b, c = ["a", "==", 1], ["b", "==", 2], ["c", "==", 3]
        assert and_filters([a, b, c]) == [a, "&&", b, "&&", c]


Call = Callable[[], Awaitable[dict[str, Any]]]

# Every tool whose name filter is documented as a partial match, called with
# the filter set. A new partial-match parameter belongs here.
NAME_FILTER_TOOLS: list[tuple[ModuleType, Callable[[], Awaitable[dict[str, Any]]]]] = [
    (object_tools, lambda: object_tools.list_addresses(adom="root", name_filter="Veeam")),
    (object_tools, lambda: object_tools.list_address_groups(adom="root", name_filter="Veeam")),
    (object_tools, lambda: object_tools.list_services(adom="root", name_filter="Veeam")),
    (object_tools, lambda: object_tools.list_service_groups(adom="root", name_filter="Veeam")),
    (
        policy_tools,
        lambda: policy_tools.search_firewall_policies(
            adom="root", package="default", name_filter="Veeam"
        ),
    ),
    (dvm_tools, lambda: dvm_tools.search_devices(adom="root", name_filter="Veeam")),
    (
        security_profile_tools,
        lambda: security_profile_tools.list_antivirus_profiles(adom="root", name_filter="Veeam"),
    ),
    (
        security_profile_tools,
        lambda: security_profile_tools.list_webfilter_profiles(adom="root", name_filter="Veeam"),
    ),
    (
        security_profile_tools,
        lambda: security_profile_tools.list_dnsfilter_profiles(adom="root", name_filter="Veeam"),
    ),
    (
        security_profile_tools,
        lambda: security_profile_tools.list_application_lists(adom="root", name_filter="Veeam"),
    ),
    (
        security_profile_advanced_tools,
        lambda: security_profile_advanced_tools.list_ips_sensors(adom="root", name_filter="Veeam"),
    ),
    (
        security_profile_advanced_tools,
        lambda: security_profile_advanced_tools.list_ssl_ssh_profiles(
            adom="root", name_filter="Veeam"
        ),
    ),
    (
        security_profile_advanced_tools,
        lambda: security_profile_advanced_tools.list_dlp_profiles(adom="root", name_filter="Veeam"),
    ),
    (
        security_profile_advanced_tools,
        lambda: security_profile_advanced_tools.list_waf_profiles(adom="root", name_filter="Veeam"),
    ),
]


def _sent_filters(mock_fmg_instance: MagicMock) -> list[Any]:
    calls = mock_fmg_instance.get.call_args_list
    assert calls, "the tool never reached the FMG GET"
    return [call.kwargs.get("filter") for call in calls]


class TestToolsSendLike:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("module", "call"),
        NAME_FILTER_TOOLS,
        ids=[inspect.getsource(c).split("(")[0].split(".")[-1] for _, c in NAME_FILTER_TOOLS],
    )
    async def test_name_filter_is_like(
        self,
        module: ModuleType,
        call: Call,
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(module, "get_fmg_client", return_value=mock_client):
            result = await call()

        assert result["status"] == "success", result
        for sent in _sent_filters(mock_fmg_instance):
            assert ["name", "like", "%Veeam%"] in sent

    @pytest.mark.asyncio
    async def test_search_objects_sends_like_to_all_four_types(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(object_tools, "get_fmg_client", return_value=mock_client):
            result = await object_tools.search_objects(adom="root", search_term="RAS-VPN")

        assert result["status"] == "success"
        sent = _sent_filters(mock_fmg_instance)
        assert sent == [[["name", "like", "%RAS-VPN%"]]] * 4

    @pytest.mark.asyncio
    async def test_search_devices_platform_filter_is_like(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            await dvm_tools.search_devices(adom="root", platform_filter="1100E")

        assert _sent_filters(mock_fmg_instance) == [[["platform_str", "like", "%1100E%"]]]


class TestCombinedFiltersAreAnded:
    """Two narrowing parameters must intersect, not union."""

    @pytest.mark.asyncio
    async def test_list_addresses_name_and_type(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(object_tools, "get_fmg_client", return_value=mock_client):
            await object_tools.list_addresses(adom="root", name_filter="oob", type_filter="fqdn")

        assert _sent_filters(mock_fmg_instance) == [
            [["name", "like", "%oob%"], "&&", ["type", "==", "fqdn"]]
        ]

    @pytest.mark.asyncio
    async def test_search_devices_name_and_status(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            await dvm_tools.search_devices(
                adom="root", name_filter="Office", connection_status="down"
            )

        assert _sent_filters(mock_fmg_instance) == [
            [["name", "like", "%Office%"], "&&", ["conn_status", "==", 2]]
        ]

    @pytest.mark.asyncio
    async def test_search_firewall_policies_name_and_action(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(policy_tools, "get_fmg_client", return_value=mock_client):
            await policy_tools.search_firewall_policies(
                adom="root", package="default", name_filter="VPN", action_filter="deny"
            )

        assert _sent_filters(mock_fmg_instance) == [
            [["name", "like", "%VPN%"], "&&", ["action", "==", "deny"]]
        ]

    @pytest.mark.asyncio
    async def test_list_scripts_type_and_target(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        """The legacy /dvmdb script endpoint (before 7.6) takes the target string as-is."""
        mock_client._fmg_version = (7, 4, 8)
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
            result = await script_tools.list_scripts(
                adom="root", script_type="cli", target="remote_device"
            )

        assert "error" not in result, result
        assert _sent_filters(mock_fmg_instance) == [
            [["type", "==", "cli"], "&&", ["target", "==", "remote_device"]]
        ]

    @pytest.mark.asyncio
    async def test_list_scripts_target_is_still_mapped_inside_the_join(
        self, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        """FMG 7.6+ stores target as an int; the mapping must reach into the "&&" form."""
        mock_client._fmg_version = (7, 6, 5)
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
            await script_tools.list_scripts(adom="root", script_type="cli", target="remote_device")

        assert _sent_filters(mock_fmg_instance) == [
            [["type", "==", "cli"], "&&", ["target", "==", 1]]
        ]


class TestSearchDevicesOsVersion:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("7", [["os_ver", "==", 7]]),
            ("7.4", [["os_ver", "==", 7], "&&", ["mr", "==", 4]]),
            (
                "v7.4.12",
                [["os_ver", "==", 7], "&&", ["mr", "==", 4], "&&", ["patch", "==", 12]],
            ),
            (" 7.6 ", [["os_ver", "==", 7], "&&", ["mr", "==", 6]]),
        ],
    )
    async def test_version_splits_into_integer_fields(
        self,
        version: str,
        expected: list[Any],
        mock_client: MagicMock,
        mock_fmg_instance: MagicMock,
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.search_devices(adom="root", os_version_filter=version)

        assert result["status"] == "success"
        assert _sent_filters(mock_fmg_instance) == [expected]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("version", ["7.x", "7.4.12.1", "", "seven", "7..4"])
    async def test_malformed_version_is_refused(
        self, version: str, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.search_devices(adom="root", os_version_filter=version or " ")

        assert result["status"] == "error"
        mock_fmg_instance.get.assert_not_called()

    @pytest.mark.asyncio
    # Superscript two, and Arabic-Indic seven and four.
    @pytest.mark.parametrize("version", ["²", "7.²", "٧.٤"])
    async def test_non_ascii_digits_are_refused_by_the_validator(
        self, version: str, mock_client: MagicMock, mock_fmg_instance: MagicMock
    ) -> None:
        """``str.isdigit`` accepts these, so they reached ``int()`` or were read as 7.4."""
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.search_devices(adom="root", os_version_filter=version)

        assert result["status"] == "error"
        assert "Invalid os_version_filter" in result["message"]
        mock_fmg_instance.get.assert_not_called()


def _scalar_contain_sites() -> list[str]:
    """Every ``[<scalar field>, "contain", ...]`` literal left in the tool modules.

    ``contain`` stays legitimate on multi-value fields (a policy's srcaddr,
    dstaddr, service), where it means list membership.
    """
    multi_value = {"srcaddr", "dstaddr", "service"}
    found = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.List)
                and len(node.elts) == 3
                and isinstance(node.elts[1], ast.Constant)
                and node.elts[1].value == "contain"
                and isinstance(node.elts[0], ast.Constant)
                and node.elts[0].value not in multi_value
            ):
                found.append(f"{path.name}:{node.lineno} {node.elts[0].value}")
    return found


def test_no_scalar_field_is_filtered_with_contain() -> None:
    assert _scalar_contain_sites() == []
