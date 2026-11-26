"""The JSON-RPC params the client hands to FortiManager, as pyFMG builds them.

A MagicMock in place of pyFMG cannot show where a key lands: pyFMG's
``common_datagram_params`` decides that. For any verb but get and clone it
puts the keyword arguments under ``data``, unless one of them is itself
called ``data``, which then replaces all the others. These tests run a real
pyFMG ``FortiManager`` with only ``_post_request`` replaced, and read the
``params`` it would have sent (#139 item 16).
"""

from typing import Any

import pytest
from pyFMG.fortimgr import FortiManager

from fortimanager_mcp.api.client import FortiManagerClient


@pytest.fixture
def sent(mock_client: FortiManagerClient) -> list[tuple[str, list[dict[str, Any]]]]:
    """(method, params) of every request the client makes."""
    calls: list[tuple[str, list[dict[str, Any]]]] = []
    fmg = FortiManager("fmg.example.com", "admin", "not-a-password")

    def record(method: str, params: list[dict[str, Any]], *args: Any, **kwargs: Any) -> Any:
        calls.append((method, params))
        return 0, [{"response": {}}]

    fmg._post_request = record  # type: ignore[method-assign]
    mock_client._fmg = fmg
    return calls


TARGET = ["/adom/root/device/FGT-1"]


class TestProxyCall:
    @pytest.mark.asyncio
    async def test_a_body_is_sent_beside_action_resource_and_target(
        self, mock_client: FortiManagerClient, sent: list[tuple[str, list[dict[str, Any]]]]
    ) -> None:
        """pyFMG replaced the whole payload with ``data``, so the FortiGate
        body was all that went out. The body goes under ``payload``, the
        key the sys/proxy/json schema gives it."""
        await mock_client.proxy_call(
            "post", "/api/v2/cmdb/firewall/address", TARGET, data={"name": "a1"}
        )

        assert sent == [
            (
                "exec",
                [
                    {
                        "url": "/sys/proxy/json",
                        "data": {
                            "action": "post",
                            "resource": "/api/v2/cmdb/firewall/address",
                            "target": TARGET,
                            "payload": {"name": "a1"},
                        },
                    }
                ],
            )
        ]

    @pytest.mark.asyncio
    async def test_a_call_without_a_body_is_unchanged(
        self, mock_client: FortiManagerClient, sent: list[tuple[str, list[dict[str, Any]]]]
    ) -> None:
        await mock_client.proxy_call("get", "/api/v2/monitor/system/status", TARGET)

        assert sent == [
            (
                "exec",
                [
                    {
                        "url": "/sys/proxy/json",
                        "data": {
                            "action": "get",
                            "resource": "/api/v2/monitor/system/status",
                            "target": TARGET,
                        },
                    }
                ],
            )
        ]


class TestDeleteFirewallPolicies:
    @pytest.mark.asyncio
    async def test_filter_and_confirm_are_sent_beside_the_url(
        self, mock_client: FortiManagerClient, sent: list[tuple[str, list[dict[str, Any]]]]
    ) -> None:
        """They went out nested under ``data``, where a delete does not read
        a filter."""
        await mock_client.delete_firewall_policies("root", "default", [3, 5])

        assert sent == [
            (
                "delete",
                [
                    {
                        "url": "/pm/config/adom/root/pkg/default/firewall/policy",
                        "confirm": 1,
                        "filter": ["policyid", "in", 3, 5],
                    }
                ],
            )
        ]
