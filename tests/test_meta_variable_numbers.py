"""A number sent as a meta-variable value reaches the tool on both MCP routes.

``add_model_device(meta_variables=)`` and ``check_device_variables(expected=)``
say a value is a string or a number, and their validator turns a number into
the string FortiManager stores. The declared type was ``dict[str, str]``, so
the argument model both routes validate with (the SDK's ``Tool.run`` and the
dynamic dispatcher) refused a JSON number before the tool ran.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from fortimanager_mcp import server  # full mode registers every tool
from fortimanager_mcp.tools import dvm_tools
from fortimanager_mcp.utils.errors import ResourceNotFoundError

VARIABLES = [{"name": "branch_id", "value": "0", "type": "string", "dynamic_mapping": None}]
SERIAL = "FGVM020000123456"

CHECK = {"adom": "demo", "device": "branch2"}
ADD = {"adom": "demo", "name": "branch1", "serial_number": SERIAL}


class _ToolCollector:
    def __init__(self) -> None:
        self.fns: dict[str, Any] = {}

    def tool(self) -> Any:
        def decorator(fn: Any) -> Any:
            self.fns[fn.__name__] = fn
            return fn

        return decorator


async def _full_mode(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call the tool the way a full-mode MCP client does."""
    try:
        answer = await server.mcp.call_tool(tool, arguments)
    except ToolError as refusal:
        return {"refused": str(refusal)}
    return answer.structured_content


async def _dynamic_mode(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call the tool through the dynamic-mode dispatcher."""
    collector = _ToolCollector()
    server.register_dynamic_tools(collector)  # type: ignore[arg-type]
    answer = await collector.fns["execute_fortimanager_tool"](tool, arguments)
    return answer["result"] if answer.get("success") else {"refused": answer["error"]}


ROUTES = pytest.mark.parametrize("route", [_full_mode, _dynamic_mode])


@pytest.fixture
def client() -> Any:
    fake = MagicMock()
    fake.get_metadata_variables = AsyncMock(return_value=VARIABLES)
    fake.get_device = AsyncMock(side_effect=ResourceNotFoundError("nope", code=-3))
    fake.list_devices = AsyncMock(return_value=[])
    fake.get = AsyncMock(return_value={})
    fake.add_device = AsyncMock(return_value={})
    with patch.object(dvm_tools, "get_fmg_client", return_value=fake):
        yield fake


@ROUTES
@pytest.mark.parametrize(("value", "stored"), [(2, "2"), (1.5, "1.5"), ("2", "2")])
async def test_check_device_variables_takes_a_number(
    client: Any, route: Any, value: Any, stored: str
) -> None:
    result = await route("check_device_variables", {**CHECK, "expected": {"branch_id": value}})
    assert result["status"] == "success", result
    assert result["not_mapped"] == [{"name": "branch_id", "expected": stored, "default": "0"}]


@ROUTES
@pytest.mark.parametrize(("value", "stored"), [(2, "2"), (1.5, "1.5"), ("2", "2")])
async def test_add_model_device_takes_a_number(
    client: Any, route: Any, value: Any, stored: str
) -> None:
    result = await route("add_model_device", {**ADD, "meta_variables": {"branch_id": value}})
    assert result["status"] == "success", result
    sent = client.add_device.call_args.kwargs["device"]["meta variables"]
    assert sent == {"branch_id": stored}


@ROUTES
@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("check_device_variables", {**CHECK, "expected": {"enabled": True}}),
        ("add_model_device", {**ADD, "meta_variables": {"enabled": True}}),
    ],
)
async def test_a_boolean_is_refused_and_not_read_as_one(
    client: Any, route: Any, tool: str, arguments: dict[str, Any]
) -> None:
    """Lax validation of ``str | int | float`` alone turns ``true`` into ``1``,
    which would be stored as the variable's value."""
    result = await route(tool, arguments)
    assert "boolean" in result["refused"], result
    client.add_device.assert_not_awaited()
    client.get_metadata_variables.assert_not_awaited()


@pytest.mark.parametrize(
    ("tool", "param"),
    [("check_device_variables", "expected"), ("add_model_device", "meta_variables")],
)
def test_the_schema_offers_a_number(tool: str, param: str) -> None:
    schema = server.mcp._tool_manager.get_tool(tool).parameters["properties"][param]
    objects = [o for o in (schema, *schema.get("anyOf", [])) if o.get("type") == "object"]
    offered = {o.get("type") for o in objects[0]["additionalProperties"]["anyOf"]}
    assert offered == {"string", "integer", "number"}
