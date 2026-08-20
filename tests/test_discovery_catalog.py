"""Every registered tool must be reachable from dynamic mode.

Dynamic mode does not import the tool modules; it answers
``find_fortimanager_tool`` from a hand-written catalog and dispatches
through a hand-written per-module allowlist. Both are literals, so a tool
added to a module and not to those two lists exists in full mode and is
invisible and unreachable in dynamic mode.

That is not hypothetical: ``get_policy_services`` and
``update_service_group`` shipped that way and stayed missing across
several releases, found only when a tool-count claim in a later PR did
not add up (upstream #58).

The lists live inside nested functions in ``server.py``, so they cannot
be imported. Reading them out of the source is deliberate: the
alternative is exporting internals for a test, and this file is the same
shape as the credential-strip meta-test, which reads source for the same
reason.
"""

import ast
import pathlib

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "fortimanager_mcp"

#: The two containers in ``server.py`` a tool has to appear in.
CATALOG_NAME = "tool_catalog"
DISPATCH_NAME = "_TOOL_MODULES"


def _decorated_tool_names() -> set[str]:
    """Every function carrying an ``@mcp.tool()`` decorator."""
    names: set[str] = set()
    for path in sorted((SRC / "tools").glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr == "tool":
                    names.add(node.name)
    return names


def _strings_under(assigned_name: str) -> set[str]:
    """Every string constant inside the named assignment in server.py."""
    tree = ast.parse((SRC / "server.py").read_text(), filename="server.py")
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if assigned_name not in targets:
            continue
        for inner in ast.walk(node.value):
            if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                found.add(inner.value)
    return found


def test_every_tool_is_listed_in_the_discovery_catalog() -> None:
    missing = _decorated_tool_names() - _strings_under(CATALOG_NAME)
    assert not missing, (
        f"{len(missing)} tool(s) exist but dynamic mode cannot discover them: {sorted(missing)}"
    )


def test_every_tool_is_reachable_through_the_dispatch_allowlist() -> None:
    """Discoverable but not dispatchable is the worse half of the bug."""
    missing = _decorated_tool_names() - _strings_under(DISPATCH_NAME)
    assert not missing, (
        f"{len(missing)} tool(s) are listed but cannot be executed in dynamic mode: {sorted(missing)}"
    )


def test_the_catalog_does_not_advertise_tools_that_do_not_exist() -> None:
    """The other direction: a renamed or removed tool left in the catalog
    is discoverable and then fails at dispatch with 'Tool not found'."""
    catalog_tools = _strings_under(CATALOG_NAME) & _strings_under(DISPATCH_NAME)
    phantom = catalog_tools - _decorated_tool_names()
    assert not phantom, f"catalog advertises tool(s) that no module defines: {sorted(phantom)}"
