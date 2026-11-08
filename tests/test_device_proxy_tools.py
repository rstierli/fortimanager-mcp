"""Tests for device_proxy_tools module."""

import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from fortimanager_mcp.tools import device_proxy_tools
from fortimanager_mcp.utils.validation import MASK_VALUE


def _envelope(results: Any, **response: Any) -> list[dict[str, Any]]:
    return [
        {
            "response": {
                "http_method": "GET",
                "http_status": 200,
                "status": "success",
                "version": "v7.4.12",
                "build": 2902,
                "results": results,
                **response,
            },
            "status": {"code": 0, "message": "OK"},
            "target": "branch1",
        }
    ]


def _client(answer: Any) -> AsyncMock:
    client = AsyncMock()
    client.proxy_call = AsyncMock(return_value=answer)
    return client


async def _query(client: AsyncMock | None, path: str, **kwargs: Any) -> dict[str, Any]:
    with patch.object(device_proxy_tools, "get_fmg_client", return_value=client):
        kwargs.setdefault("device", "branch1")
        kwargs.setdefault("adom", "demo")
        return await device_proxy_tools.query_device_api(path, **kwargs)


class TestQueryDeviceApi:
    @pytest.mark.asyncio
    async def test_sends_a_get_to_the_device(self) -> None:
        client = _client(_envelope([{"name": "wan1"}]))
        result = await _query(client, "/api/v2/monitor/system/status")

        client.proxy_call.assert_awaited_once_with(
            action="get",
            resource="/api/v2/monitor/system/status",
            target=["/adom/demo/device/branch1"],
        )
        assert result["results"] == [{"name": "wan1"}]
        assert result["http_status"] == 200
        assert result["version"] == "v7.4.12"

    @pytest.mark.asyncio
    async def test_encodes_params_and_vdom(self) -> None:
        client = _client(_envelope([]))
        await _query(
            client,
            "/api/v2/cmdb/firewall/address",
            vdom="root",
            params={"count": 5, "filter": "name==a b", "with_meta": True},
        )

        resource = client.proxy_call.await_args.kwargs["resource"]
        assert resource == (
            "/api/v2/cmdb/firewall/address?count=5&filter=name%3D%3Da+b&with_meta=true&vdom=root"
        )

    @pytest.mark.asyncio
    async def test_session_filters_are_forwarded(self) -> None:
        client = _client(_envelope({"details": []}))
        await _query(
            client,
            "/api/v2/monitor/firewall/session",
            params={"ip_version": "ipv4", "source": "10.1.0.101", "summary": True},
        )

        resource = client.proxy_call.await_args.kwargs["resource"]
        assert resource.endswith("?ip_version=ipv4&source=10.1.0.101&summary=true")

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        result = await _query(None, "/api/v2/monitor/system/status")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_device_required(self) -> None:
        with (
            patch.object(device_proxy_tools, "get_fmg_client", return_value=_client([])),
            patch.object(device_proxy_tools, "get_default_device", return_value=""),
        ):
            result = await device_proxy_tools.query_device_api("/api/v2/monitor/system/status")
        assert result["error_code"] == "device_required"

    @pytest.mark.asyncio
    async def test_proxy_error_is_reported(self) -> None:
        client = _client([{"status": {"code": -1, "message": "device unreachable"}}])
        result = await _query(client, "/api/v2/monitor/system/status")
        assert result == {"error": "device unreachable", "error_code": "device_proxy_error"}

    @pytest.mark.asyncio
    async def test_proxy_error_message_is_scrubbed(self) -> None:
        """The message is the device's text: no API path, no secret, one line."""
        message = (
            "branch1(228) error: GET /api/v2/cmdb/system/admin failed\n"
            "password=hunter2 token: 0123456789abcdef0123456789abcdef\n"
        )
        client = _client([{"status": {"code": -1, "message": message}}])
        result = await _query(client, "/api/v2/monitor/system/status")

        assert result["error_code"] == "device_proxy_error"
        assert "/api/" not in result["error"]
        assert "hunter2" not in result["error"]
        assert "0123456789abcdef0123456789abcdef" not in result["error"]
        assert "\n" not in result["error"]
        assert result["error"].startswith("branch1(228) error:")

    @pytest.mark.asyncio
    async def test_proxy_error_keeps_the_device_http_status(self) -> None:
        """Measured on 8.0.2: an unknown endpoint is code -6 "Invalid url", HTTP 404."""
        client = _client(
            [
                {
                    "status": {"code": -6, "message": "Invalid url"},
                    "response": {"http_status": 404, "status": "error"},
                }
            ]
        )
        result = await _query(client, "/api/v2/monitor/router/bgp/neighbors")
        assert result == {
            "error": "Invalid url",
            "error_code": "device_proxy_error",
            "http_status": 404,
        }

    @pytest.mark.asyncio
    async def test_device_http_error_is_reported(self) -> None:
        client = _client(_envelope(None, status="error", http_status=404))
        result = await _query(client, "/api/v2/monitor/router/no-such")
        assert result["error_code"] == "device_api_error"
        assert result["http_status"] == 404

    @pytest.mark.asyncio
    async def test_vdom_is_validated(self) -> None:
        client = _client(_envelope([]))
        result = await _query(client, "/api/v2/monitor/system/status", vdom="../x")
        assert result["error_code"] == "validation_error"
        client.proxy_call.assert_not_awaited()


SKILLS_DIR = Path(device_proxy_tools.__file__).resolve().parent.parent / "skills"


def _skill_paths() -> list[str]:
    paths: set[str] = set()
    for skill in SKILLS_DIR.glob("*/SKILL.md"):
        paths.update(re.findall(r"/api/v2/(?:monitor|cmdb)/[A-Za-z0-9_./-]+", skill.read_text()))
    return sorted(p.rstrip(".") for p in paths)


class TestAllowlist:
    def test_the_skills_name_paths(self) -> None:
        """Guard for the test below: it must have something to check."""
        assert len(_skill_paths()) >= 5

    @pytest.mark.parametrize("path", _skill_paths())
    def test_every_path_a_skill_calls_is_allowed(self, path: str) -> None:
        assert device_proxy_tools._validate_path(path) == path

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/monitor/switch-controller/managed-switch/status",
            "/api/v2/monitor/switch-controller/detected-device",
            "/api/v2/monitor/router/bgp/neighbors",
            "/api/v2/monitor/router/lookup",
            "/api/v2/monitor/system/interface",
            "/api/v2/monitor/vpn/ipsec",
            "/api/v2/monitor/firewall/policy",
            "/api/v2/monitor/wifi/client",
            "/api/v2/monitor/system/ha-peer",
            "/api/v2/cmdb/firewall/address/srv-web",
            "/api/v2/cmdb/vpn.ipsec/phase1-interface",
            "/api/v2/cmdb/system.snmp/community",
            "/api/v2/cmdb/router/static",
        ],
    )
    def test_diagnostic_paths_are_allowed(self, path: str) -> None:
        assert device_proxy_tools._validate_path(path) == path

    def test_matching_ignores_case_and_sends_the_path_as_given(self) -> None:
        path = "/api/v2/Monitor/System/Status"
        assert device_proxy_tools._validate_path(path) == path

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/cmdb/system/admin",
            "/api/v2/cmdb/system/api-user",
            "/api/v2/cmdb/user/local",
            "/api/v2/monitor/system/config-revision/file",
            "/api/v2/monitor/system/com-log/dump",
            "/api/v2/monitor/system/config/backup",
            "/api/v2/monitor/system/ha-peerx",
            "/api/v2/cmdb/system/ha-monitor",
            "/api/v2/monitor/log/device/state",
        ],
    )
    def test_everything_else_is_refused_with_the_list(self, path: str) -> None:
        with pytest.raises(device_proxy_tools.ValidationError) as caught:
            device_proxy_tools._validate_path(path)
        message = str(caught.value)
        assert "refused" in message or "monitor/router" in message

    def test_a_refusal_names_the_allowed_prefixes(self) -> None:
        with pytest.raises(device_proxy_tools.ValidationError) as caught:
            device_proxy_tools._validate_path("/api/v2/cmdb/system/admin")
        message = str(caught.value)
        for prefix in device_proxy_tools._ALLOWED_PREFIXES:
            assert prefix in message

    @pytest.mark.parametrize("segment", ["backup", "Download", "DUMP", "file", "raw"])
    def test_a_file_segment_is_refused_even_under_an_allowed_prefix(self, segment: str) -> None:
        with pytest.raises(device_proxy_tools.ValidationError):
            device_proxy_tools._validate_path(f"/api/v2/monitor/router/{segment}")

    def test_no_allowed_prefix_is_a_file_export(self) -> None:
        for prefix in device_proxy_tools._ALLOWED_PREFIXES:
            assert not device_proxy_tools._FILE_SEGMENTS.intersection(prefix.split("/"))
            assert prefix == prefix.lower()


class TestRefusals:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/monitor/system/config/backup",
            "/api/v2/monitor/system/debug/download",
            "/api/v2/monitor/../cmdb/system/admin",
            "/api/v2/cmdb/system/admin",
            "/api/v2/monitor/system/status?plain-text-password=1",
            "/api/v2/monitor/system%2Fstatus",
            "/api/v2/log/disk/event",
            "/logincheck",
            "api/v2/monitor/system/status",
            "/api/v2/monitor",
        ],
    )
    async def test_path_is_refused_before_any_call(self, path: str) -> None:
        client = _client([])
        result = await _query(client, path)

        assert "error" in result
        client.proxy_call.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "params",
        [{"plain-text-password": 1}, {"action": "move"}, {"count": [1, 2]}],
    )
    async def test_param_is_refused_before_any_call(self, params: dict[str, Any]) -> None:
        client = _client([])
        result = await _query(client, "/api/v2/cmdb/firewall/address", params=params)

        assert "error" in result
        client.proxy_call.assert_not_awaited()


class TestRedaction:
    @pytest.mark.asyncio
    async def test_secret_fields_are_masked_at_any_depth(self) -> None:
        client = _client(
            _envelope(
                [
                    {
                        "name": "admin",
                        "password": "x",
                        "psksecret": "y",
                        "peers": [{"auth_token": "z", "private-key": "k", "keylife": 86400}],
                    }
                ]
            )
        )
        result = await _query(client, "/api/v2/cmdb/vpn.ipsec/phase1-interface")

        entry = result["results"][0]
        assert entry["name"] == "admin"
        assert entry["password"] == MASK_VALUE
        assert entry["psksecret"] == MASK_VALUE
        assert entry["peers"][0]["auth_token"] == MASK_VALUE
        assert entry["peers"][0]["private-key"] == MASK_VALUE
        assert entry["peers"][0]["keylife"] == 86400

    @pytest.mark.asyncio
    async def test_secret_values_are_masked_under_any_field_name(self) -> None:
        pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
        client = _client(_envelope({"new-field": "ENC abc", "blob": pem, "comment": "ENCORE"}))
        result = await _query(client, "/api/v2/cmdb/system/global")

        assert result["results"] == {
            "new-field": MASK_VALUE,
            "blob": MASK_VALUE,
            "comment": "ENCORE",
        }

    @pytest.mark.asyncio
    async def test_config_text_is_redacted(self) -> None:
        text = 'config system admin\n    set password ENC abc\n    set name "a"\nend'
        client = _client(_envelope({"config": text}))
        result = await _query(client, "/api/v2/monitor/system/status")

        assert "ENC abc" not in result["results"]["config"]
        assert 'set name "a"' in result["results"]["config"]


class TestSnmpCommunities:
    """A community string is the entry's ``name``: a field-name match misses it."""

    @pytest.mark.asyncio
    async def test_the_community_table_has_its_names_masked(self) -> None:
        client = _client(
            _envelope(
                [
                    {
                        "id": 1,
                        "q_origin_key": 1,
                        "name": "s3cret-community",
                        "status": "enable",
                        "hosts": [{"id": 1, "ip": "192.0.2.10 255.255.255.255"}],
                    }
                ]
            )
        )
        result = await _query(client, "/api/v2/cmdb/system.snmp/community")

        entry = result["results"][0]
        assert entry["name"] == MASK_VALUE
        assert entry["status"] == "enable"
        assert entry["hosts"] == [{"id": 1, "ip": "192.0.2.10 255.255.255.255"}]
        assert "s3cret-community" not in str(result)

    @pytest.mark.asyncio
    async def test_a_single_community_read_is_masked_too(self) -> None:
        client = _client(_envelope({"id": 1, "name": "s3cret-community"}))
        result = await _query(client, "/api/v2/cmdb/system.snmp/community/1")
        assert result["results"]["name"] == MASK_VALUE

    @pytest.mark.asyncio
    async def test_a_nested_switch_community_is_masked(self) -> None:
        client = _client(
            _envelope(
                [
                    {
                        "switch-id": "S108EP0000000001",
                        "name": "sw1",
                        "snmp-community": [{"id": 1, "name": "s3cret-community"}],
                    }
                ]
            )
        )
        result = await _query(client, "/api/v2/cmdb/switch-controller/managed-switch")

        entry = result["results"][0]
        assert entry["name"] == "sw1"
        assert entry["snmp-community"][0]["name"] == MASK_VALUE
        assert "s3cret-community" not in str(result)

    @pytest.mark.asyncio
    async def test_other_tables_keep_their_names(self) -> None:
        client = _client(_envelope([{"name": "srv-web", "subnet": "192.0.2.10 255.255.255.255"}]))
        result = await _query(client, "/api/v2/cmdb/firewall/address")
        assert result["results"][0]["name"] == "srv-web"


class TestPathIsAscii:
    """Case-insensitive matching must not fold non-ASCII letters (L12).

    Under ``re.I`` alone ``[A-Za-z]`` also matches the Kelvin sign, the
    dotless i and the long s, which case-fold onto k, i and s.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/monitor/networK/arp",
            "/api/v2/monitor/lıcense/status",
            "/api/v2/cmdb/ſystem/interface",
        ],
    )
    def test_a_non_ascii_letter_is_refused(self, path: str) -> None:
        with pytest.raises(device_proxy_tools.ValidationError):
            device_proxy_tools._validate_path(path)


class TestManagedSwitchMonitor:
    """Only the documented read below managed-switch is allowed (L13).

    Some GETs below ``monitor/switch-controller/managed-switch`` act on the
    switch, such as cable-status, which runs a cable diagnostic on a port.
    """

    def test_status_is_allowed(self) -> None:
        path = "/api/v2/monitor/switch-controller/managed-switch/status"
        assert device_proxy_tools._validate_path(path) == path

    @pytest.mark.parametrize(
        "child", ["cable-status", "port-stats-reset", "restart", "poe-reset", "faceplate-xml"]
    )
    def test_other_children_are_refused(self, child: str) -> None:
        with pytest.raises(device_proxy_tools.ValidationError):
            device_proxy_tools._validate_path(
                f"/api/v2/monitor/switch-controller/managed-switch/{child}"
            )


class TestCommunityTables:
    """Any table that can hold an SNMP community is redacted as one (M10)."""

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/cmdb/system.snmp/community",
            "/api/v2/cmdb/system.snmp/community/1",
            "/api/v2/cmdb/system.snmp/user",
            "/api/v2/cmdb/system.snmp/sysinfo",
            "/api/v2/cmdb/System.SNMP/Community",
            "/api/v2/cmdb/switch-controller/snmp-community",
            "/api/v2/cmdb/switch-controller/managed-switch/S108EP0000000001/snmp-community",
            "/api/v2/cmdb/switch-controller/managed-switch/S108EP0000000001/snmp-community/1",
            "/api/v2/cmdb/wireless-controller/snmp/community",
            "/api/v2/cmdb/wireless-controller/snmp/community/1",
        ],
    )
    def test_the_path_is_a_community_table(self, path: str) -> None:
        assert device_proxy_tools._is_community_table(path)

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/cmdb/firewall/address",
            "/api/v2/cmdb/switch-controller/managed-switch",
            "/api/v2/cmdb/wireless-controller/wtp-profile",
        ],
    )
    def test_other_paths_are_not(self, path: str) -> None:
        assert not device_proxy_tools._is_community_table(path)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/cmdb/switch-controller/managed-switch/S108EP0000000001/snmp-community",
            "/api/v2/cmdb/wireless-controller/snmp/community",
        ],
    )
    async def test_a_child_community_table_has_its_names_masked(self, path: str) -> None:
        client = _client(_envelope([{"id": 1, "q_origin_key": 1, "name": "s3cret-community"}]))
        result = await _query(client, path)

        assert result["results"][0]["name"] == MASK_VALUE
        assert result["results"][0]["id"] == 1
        assert "s3cret-community" not in str(result)

    def test_bare_entries_are_masked(self) -> None:
        """A community entry that is not a dict, or a list of them, still masks."""
        redacted = device_proxy_tools._redact(
            ["s3cret-a", ["s3cret-b", {"name": "s3cret-c", "mkey": "s3cret-c"}], 7],
            community=True,
        )
        assert "s3cret" not in str(redacted)
        assert redacted[2] == 7

    def test_a_string_key_copy_of_the_name_is_masked(self) -> None:
        redacted = device_proxy_tools._redact(
            {"name": "s3cret", "q_origin_key": "s3cret", "mkey": "s3cret"}, community=True
        )
        assert redacted == {"name": MASK_VALUE, "q_origin_key": MASK_VALUE, "mkey": MASK_VALUE}


class TestQueryOracles:
    """Selectors that would reveal what the redaction or the masking hides (M9)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["filter", "key", "pattern", "sort"])
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/cmdb/system.snmp/community",
            "/api/v2/cmdb/switch-controller/managed-switch/sw1/snmp-community",
            "/api/v2/cmdb/wireless-controller/snmp/community",
        ],
    )
    async def test_selectors_are_refused_on_community_tables(self, path: str, name: str) -> None:
        client = _client(_envelope([]))
        result = await _query(client, path, params={name: "name"})

        assert result["error_code"] == "validation_error"
        client.proxy_call.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "params",
        [
            {"filter": "password=@a"},
            {"filter": "name==a,psksecret=@x"},
            {"filter": " Passwd ==x"},
            {"filter": "community==public"},
            {"filter": "ppp.password=@a"},
            {"key": "password", "pattern": "a"},
            {"key": "private-key"},
            {"sort": "psksecret"},
            {"sort": "name,-password"},
        ],
    )
    async def test_a_selector_on_a_secret_field_is_refused(self, params: dict[str, Any]) -> None:
        client = _client(_envelope([]))
        result = await _query(client, "/api/v2/cmdb/system/interface", params=params)

        assert result["error_code"] == "validation_error"
        client.proxy_call.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["name", "=@x", "name~x", "name==a,b", "a b==c", ""])
    async def test_an_unreadable_filter_is_refused(self, value: str) -> None:
        """Fail closed: a clause whose field cannot be read cannot be checked."""
        client = _client(_envelope([]))
        result = await _query(client, "/api/v2/cmdb/firewall/address", params={"filter": value})

        assert result["error_code"] == "validation_error"
        client.proxy_call.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "params",
        [
            {"filter": "name==srv-web"},
            {"filter": "name=@web,comment!@test"},
            {"filter": "q_ref>=1"},
            {"key": "name", "pattern": "srv"},
            {"sort": "name"},
        ],
    )
    async def test_ordinary_selectors_are_forwarded(self, params: dict[str, Any]) -> None:
        client = _client(_envelope([]))
        result = await _query(client, "/api/v2/cmdb/firewall/address", params=params)

        assert "error" not in result
        client.proxy_call.assert_awaited_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "params",
        [{"filter": "name==srv-web"}, {"key": "name", "pattern": "a"}, {"sort": "ip"}],
    )
    async def test_selectors_are_refused_when_masking_is_on(self, params: dict[str, Any]) -> None:
        client = _client(_envelope([]))
        with patch.object(device_proxy_tools, "_masking_enabled", return_value=True):
            result = await _query(client, "/api/v2/cmdb/firewall/address", params=params)

        assert result["error_code"] == "validation_error"
        assert "masking" in result["error"].lower()
        client.proxy_call.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_an_exact_address_lookup_still_works_when_masking_is_on(self) -> None:
        client = _client(_envelope([]))
        with patch.object(device_proxy_tools, "_masking_enabled", return_value=True):
            result = await _query(
                client,
                "/api/v2/monitor/firewall/session",
                params={"ip_version": "ipv4", "source": "10.1.0.101", "count": 5},
            )

        assert "error" not in result
        client.proxy_call.assert_awaited_once()
