"""Integer id parameters refuse a JSON boolean on every MCP route.

Both routes validate arguments with pydantic in lax mode (the SDK's
``Tool.run`` and the dynamic dispatcher's ``func_metadata``), which turns
``true`` into ``1`` before the tool runs. A tool's own ``isinstance(x, bool)``
check then never sees the boolean, and ``delete_firewall_policy(policyid=true)``
deletes policy 1. The ``Id`` annotation refuses it at the argument model.
"""

import re
from typing import Annotated, Any

import pytest
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from fortimanager_mcp import server  # full mode registers every tool

#: Parameter names that select an object by number.
_ID_NAME = re.compile(r"(^|_)(ids?|policyids?|taskid|revision)$|id$")


def _id_parameters() -> list[tuple[str, str, bool]]:
    """(tool, parameter, is_list) for every integer id parameter registered."""
    found = []
    for tool in server.mcp._tool_manager.list_tools():
        for name, schema in tool.parameters.get("properties", {}).items():
            if not _ID_NAME.search(name):
                continue
            options = [schema, *schema.get("anyOf", [])]
            if any(o.get("type") == "integer" for o in options):
                found.append((tool.name, name, False))
            elif any(
                o.get("type") == "array" and o.get("items", {}).get("type") == "integer"
                for o in options
            ):
                found.append((tool.name, name, True))
    return found


ID_PARAMETERS = _id_parameters()


def _validate(tool_name: str, param: str, value: Any) -> Any:
    """Validate one argument the way the tool's argument model does.

    The field is taken from the argument model both MCP routes validate
    with, annotation and metadata included.
    """
    tool = server.mcp._tool_manager.get_tool(tool_name)
    field = tool.fn_metadata.arg_model.model_fields[param]
    annotation = (
        Annotated[field.annotation, *field.metadata] if field.metadata else field.annotation
    )
    return TypeAdapter(annotation).validate_python(value)


def test_the_walk_finds_the_known_id_parameters() -> None:
    names = {(tool, param) for tool, param, _ in ID_PARAMETERS}
    assert {
        ("delete_firewall_policy", "policyid"),
        ("delete_firewall_policies_bulk", "policyids"),
        ("move_firewall_policy", "target_policyid"),
        ("revert_adom_revision", "revision"),
        ("delete_task", "task_id"),
    } <= names
    assert len(names) >= 35


@pytest.mark.parametrize(("tool", "param", "is_list"), ID_PARAMETERS)
def test_a_boolean_id_is_refused(tool: str, param: str, is_list: bool) -> None:
    with pytest.raises(PydanticValidationError):
        _validate(tool, param, [True] if is_list else True)


@pytest.mark.parametrize(("tool", "param", "is_list"), ID_PARAMETERS)
def test_an_integer_id_and_its_digits_are_accepted(tool: str, param: str, is_list: bool) -> None:
    for value in (7, "7"):
        assert _validate(tool, param, [value] if is_list else value) == ([7] if is_list else 7)
