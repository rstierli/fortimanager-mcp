"""Tests for device_proxy_tools module."""

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
        kwargs.setdefault("adom", "production")
        return await device_proxy_tools.query_device_api(path, **kwargs)


class TestQueryDeviceApi:
    @pytest.mark.asyncio
    async def test_sends_a_get_to_the_device(self) -> None:
        client = _client(_envelope([{"name": "wan1"}]))
        result = await _query(client, "/api/v2/monitor/system/status")

        client.proxy_call.assert_awaited_once_with(
            action="get",
            resource="/api/v2/monitor/system/status",
            target=["/adom/production/device/branch1"],
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
    async def test_device_http_error_is_reported(self) -> None:
        client = _client(_envelope(None, status="error", http_status=404))
        result = await _query(client, "/api/v2/monitor/no/such")
        assert result["error_code"] == "device_api_error"
        assert result["http_status"] == 404


class TestRefusals:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v2/monitor/system/config/backup",
            "/api/v2/monitor/system/debug/download",
            "/api/v2/monitor/../cmdb/system/admin",
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
        result = await _query(client, "/api/v2/cmdb/system/admin", params=params)

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
        result = await _query(client, "/api/v2/cmdb/system/admin")

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
