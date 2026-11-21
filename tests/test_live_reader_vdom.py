"""The tools that read live state through the device proxy can name a VDOM.

A proxied read that names no VDOM is answered by the device for a VDOM of
its own choice, so on a device with several VDOMs these tools could only
ever report on that one. Each takes an optional ``vdom`` now and sends it as
``query_device_api`` does. Without it the request is what it always was.
"""

from types import ModuleType
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from fortimanager_mcp.tools import dvm_tools, sdwan_tools
from fortimanager_mcp.utils.device_proxy import in_vdom

MONITOR = "/api/v2/monitor"


@pytest.mark.parametrize(
    ("resource", "vdom", "sent"),
    [
        ("/api/v2/monitor/vpn/ipsec", "customerA", "/api/v2/monitor/vpn/ipsec?vdom=customerA"),
        (
            "/api/v2/monitor/x?include_vlan=true",
            "root",
            "/api/v2/monitor/x?include_vlan=true&vdom=root",
        ),
        ("/api/v2/monitor/vpn/ipsec", "lab 2", "/api/v2/monitor/vpn/ipsec?vdom=lab+2"),
        ("/api/v2/monitor/vpn/ipsec", None, "/api/v2/monitor/vpn/ipsec"),
        ("/api/v2/monitor/vpn/ipsec", "", "/api/v2/monitor/vpn/ipsec"),
    ],
    ids=["named", "behind a query", "encoded", "none", "empty"],
)
def test_in_vdom(resource: str, vdom: str | None, sent: str) -> None:
    assert in_vdom(resource, vdom) == sent


#: (module, tool, the resources it reads, the same with ``vdom="customerA"``).
READERS = [
    pytest.param(
        sdwan_tools,
        "get_device_sdwan_monitor",
        [f"{MONITOR}/virtual-wan/members", f"{MONITOR}/virtual-wan/health-check"],
        [
            f"{MONITOR}/virtual-wan/members?vdom=customerA",
            f"{MONITOR}/virtual-wan/health-check?vdom=customerA",
        ],
        id="get_device_sdwan_monitor",
    ),
    pytest.param(
        sdwan_tools,
        "get_device_bgp_status",
        [
            f"{MONITOR}/router/bgp/neighbors",
            f"{MONITOR}/router/bgp/paths",
            f"{MONITOR}/router/ipv4",
        ],
        [
            f"{MONITOR}/router/bgp/neighbors?vdom=customerA",
            f"{MONITOR}/router/bgp/paths?vdom=customerA",
            f"{MONITOR}/router/ipv4?vdom=customerA",
        ],
        id="get_device_bgp_status",
    ),
    pytest.param(
        dvm_tools,
        "get_device_realtime_status",
        [f"{MONITOR}/system/status"],
        [f"{MONITOR}/system/status?vdom=customerA"],
        id="get_device_realtime_status",
    ),
    pytest.param(
        dvm_tools,
        "get_device_interfaces",
        [f"{MONITOR}/system/interface?include_vlan=true"],
        [f"{MONITOR}/system/interface?include_vlan=true&vdom=customerA"],
        id="get_device_interfaces",
    ),
    pytest.param(
        dvm_tools,
        "get_device_client_location",
        [f"{MONITOR}/user/device/query"],
        [f"{MONITOR}/user/device/query?vdom=customerA"],
        id="get_device_client_location",
    ),
]


async def _read(module: ModuleType, tool: str, **kwargs: Any) -> tuple[dict[str, Any], list[str]]:
    """Call the tool on a device that answers every read; the result and the resources read."""
    client = AsyncMock()
    client.proxy_call = AsyncMock(
        return_value=[{"response": {"results": []}, "status": {"code": 0, "message": "OK"}}]
    )
    with patch.object(module, "get_fmg_client", return_value=client):
        result = await getattr(module, tool)(adom="demo", device="branch1", **kwargs)
    return result, [call.kwargs["resource"] for call in client.proxy_call.call_args_list]


@pytest.mark.parametrize(("module", "tool", "plain", "in_vdom"), READERS)
class TestLiveReaderVdom:
    async def test_a_named_vdom_goes_out_on_every_read(
        self, module: ModuleType, tool: str, plain: list[str], in_vdom: list[str]
    ) -> None:
        result, resources = await _read(module, tool, vdom="customerA")
        assert "error_code" not in result, result
        assert resources == in_vdom

    async def test_without_a_vdom_the_request_is_as_before(
        self, module: ModuleType, tool: str, plain: list[str], in_vdom: list[str]
    ) -> None:
        result, resources = await _read(module, tool)
        assert "error_code" not in result, result
        assert resources == plain

    @pytest.mark.parametrize("vdom", ["root&scope=global", "../x"])
    async def test_a_bad_vdom_is_refused_before_any_read(
        self, module: ModuleType, tool: str, plain: list[str], in_vdom: list[str], vdom: str
    ) -> None:
        result, resources = await _read(module, tool, vdom=vdom)
        assert result["error_code"] == "validation_error", result
        assert resources == []
