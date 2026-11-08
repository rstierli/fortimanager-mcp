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


# ---------------------------------------------------------------------------
# Module ownership: the dispatch allowlist must name the module that really
# defines each tool. execute_fortimanager_tool imports the module it finds the
# name under and reads the attribute, so a tool listed under the wrong module
# is discoverable, allowlisted, and still answers "Tool not found" in dynamic
# mode. list_policy_blocks and list_policy_block_policies shipped that way,
# listed under system_tools while policy_tools defines them.
# ---------------------------------------------------------------------------


def _decorated_tools_by_module() -> dict[str, set[str]]:
    """Module stem -> every ``@mcp.tool()`` function it defines."""
    out: dict[str, set[str]] = {}
    for path in sorted((SRC / "tools").glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
            and any(
                isinstance(t := (d.func if isinstance(d, ast.Call) else d), ast.Attribute)
                and t.attr == "tool"
                for d in node.decorator_list
            )
        }
        if names:
            out[path.stem] = names
    return out


def _dict_literal(assigned_name: str) -> ast.Dict:
    tree = ast.parse((SRC / "server.py").read_text(), filename="server.py")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == assigned_name for t in node.targets)
            and isinstance(node.value, ast.Dict)
        ):
            return node.value
    raise AssertionError(f"{assigned_name} not found in server.py")


def _dispatch_by_module() -> dict[str, set[str]]:
    """``_TOOL_MODULES`` as module -> tool names."""
    node = _dict_literal(DISPATCH_NAME)
    out: dict[str, set[str]] = {}
    for key, value in zip(node.keys, node.values, strict=True):
        assert isinstance(key, ast.Constant) and isinstance(value, ast.Set)
        out[key.value] = {e.value for e in value.elts if isinstance(e, ast.Constant)}
    return out


def _catalog_by_category() -> dict[str, list[str]]:
    """``tool_catalog`` as category -> tool names, in listing order."""
    node = _dict_literal(CATALOG_NAME)
    out: dict[str, list[str]] = {}
    for key, value in zip(node.keys, node.values, strict=True):
        assert isinstance(key, ast.Constant) and isinstance(value, ast.List)
        out[key.value] = [
            e.elts[0].value
            for e in value.elts
            if isinstance(e, ast.Tuple) and isinstance(e.elts[0], ast.Constant)
        ]
    return out


def _category_labels() -> tuple[int, dict[str, int]]:
    """``total_tools`` and per-category ``count`` from list_fortimanager_categories."""
    tree = ast.parse((SRC / "server.py").read_text(), filename="server.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "list_fortimanager_categories":
            ret = next(n for n in ast.walk(node) if isinstance(n, ast.Return))
            assert isinstance(ret.value, ast.Dict)
            fields = {
                k.value: v
                for k, v in zip(ret.value.keys, ret.value.values, strict=True)
                if isinstance(k, ast.Constant)
            }
            total = fields["total_tools"]
            cats = fields["categories"]
            assert isinstance(total, ast.Constant) and isinstance(cats, ast.Dict)
            counts: dict[str, int] = {}
            for ck, cv in zip(cats.keys, cats.values, strict=True):
                assert isinstance(ck, ast.Constant) and isinstance(cv, ast.Dict)
                for k, v in zip(cv.keys, cv.values, strict=True):
                    if isinstance(k, ast.Constant) and k.value == "count":
                        assert isinstance(v, ast.Constant)
                        counts[ck.value] = v.value
            return total.value, counts
    raise AssertionError("list_fortimanager_categories not found")


def test_every_dispatch_entry_names_the_module_that_defines_the_tool() -> None:
    defined = _decorated_tools_by_module()
    wrong = {
        f"{tool} (listed under {module}, defined in "
        f"{[m for m, names in defined.items() if tool in names] or 'no module'})"
        for module, tools in _dispatch_by_module().items()
        for tool in tools
        if tool not in defined.get(module, set())
    }
    assert not wrong, f"dynamic mode would answer 'Tool not found' for: {sorted(wrong)}"


def test_every_dispatch_entry_resolves_to_a_callable_at_runtime() -> None:
    """The same lookup execute_fortimanager_tool does, for every tool."""
    import importlib

    unresolved = [
        f"{module}.{tool}"
        for module, tools in _dispatch_by_module().items()
        for tool in sorted(tools)
        if not callable(
            getattr(importlib.import_module(f"fortimanager_mcp.tools.{module}"), tool, None)
        )
    ]
    assert not unresolved, f"allowlisted but not resolvable: {unresolved}"


def test_no_tool_is_allowlisted_under_two_modules() -> None:
    seen: dict[str, str] = {}
    duplicated = []
    for module, tools in _dispatch_by_module().items():
        for tool in tools:
            if tool in seen:
                duplicated.append(f"{tool} ({seen[tool]}, {module})")
            seen[tool] = module
    assert not duplicated, f"first match wins, so the second listing is dead: {duplicated}"


#: Categories whose module is not ``<category>_tools``.
_CATEGORY_MODULE_EXCEPTIONS = {"device": "dvm_tools"}


def test_each_catalog_category_lists_exactly_its_module() -> None:
    """Category ``x`` is module ``x_tools`` (``device`` is ``dvm_tools``): the
    same tools, no more, no fewer.

    Keeps the dynamic-mode categories in step with the full-mode modules and
    the per-module tables in README and docs/SETUP_GUIDE.md.
    """
    defined = _decorated_tools_by_module()
    catalog = _catalog_by_category()

    def module_of(category: str) -> str:
        return _CATEGORY_MODULE_EXCEPTIONS.get(category, f"{category}_tools")

    assert {module_of(c) for c in catalog} == set(defined), "category set != module set"
    mismatched = {
        category: {
            "missing": sorted(defined[module_of(category)] - set(tools)),
            "foreign": sorted(set(tools) - defined[module_of(category)]),
        }
        for category, tools in catalog.items()
        if set(tools) != defined[module_of(category)]
    }
    assert not mismatched, mismatched


def test_category_labels_match_the_catalog() -> None:
    total, counts = _category_labels()
    catalog = _catalog_by_category()
    assert counts == {c: len(t) for c, t in catalog.items()}
    assert total == len(_decorated_tool_names())


def test_tool_count_claims_in_server_match_the_modules() -> None:
    """health_check, the module docstring and the full-mode log line state the count."""
    import re

    count = len(_decorated_tool_names())
    text = (SRC / "server.py").read_text()
    claims = re.findall(r"\b[Aa]ll (\d+) tools\b", text)
    assert claims, "no 'all N tools' claim found in server.py"
    assert set(claims) == {str(count)}, (
        f"server.py claims {sorted(set(claims))}, modules have {count}"
    )
    assert f"({count} tools total)" in text


def test_full_mode_imports_every_tool_module() -> None:
    """A module missing from the full-mode import list never registers its tools."""
    tree = ast.parse((SRC / "server.py").read_text(), filename="server.py")
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "fortimanager_mcp.tools"
        for alias in node.names
    }
    assert imported == set(_decorated_tools_by_module())


# ---------------------------------------------------------------------------
# Documentation counts. README and docs/SETUP_GUIDE.md state the tool count
# and a per-category table by hand; both drifted on every release that added
# tools (#112 fixed SETUP_GUIDE at 232 after it had sat at an older count).
# ---------------------------------------------------------------------------

REPO = SRC.parents[1]


def _readme_tool_sections() -> tuple[int, list[tuple[str, int, list[str]]]]:
    import re

    text = (REPO / "README.md").read_text()
    start = text.index("## Available Tools")
    end = text.index("\n## ", start + 1)
    section = text[start:end]
    header = re.match(r"## Available Tools \((\d+) tools\)", section)
    assert header, "README 'Available Tools (N tools)' header not found"
    sections = [
        (m.group(1), int(m.group(2)), re.findall(r"^\| `([a-z0-9_]+)` \|", m.group(3), re.M))
        for m in re.finditer(
            r"^### (.*?) \((\d+) tools?\)\n(.*?)(?=^### |\Z)", section, re.M | re.S
        )
    ]
    return int(header.group(1)), sections


def test_readme_lists_every_tool_once_with_matching_counts() -> None:
    total, sections = _readme_tool_sections()
    listed = [tool for _, _, tools in sections for tool in tools]
    defined = _decorated_tool_names()

    assert total == len(defined)
    assert sorted(set(listed)) == sorted(defined), {
        "missing": sorted(defined - set(listed)),
        "phantom": sorted(set(listed) - defined),
    }
    assert len(listed) == len(set(listed)), "a tool is listed in two README sections"
    wrong = {
        name: (claimed, len(tools)) for name, claimed, tools in sections if claimed != len(tools)
    }
    assert not wrong, f"README section header count != rows: {wrong}"


def test_readme_sections_follow_the_modules() -> None:
    """One README section per tool module, as in SETUP_GUIDE and dynamic mode."""
    by_tool = {
        tool: module for module, tools in _decorated_tools_by_module().items() for tool in tools
    }
    _, sections = _readme_tool_sections()
    mixed = {
        name: sorted({by_tool[t] for t in tools})
        for name, _, tools in sections
        if len({by_tool[t] for t in tools}) != 1
    }
    assert not mixed, f"README sections spanning several modules: {mixed}"
    assert len(sections) == len(_decorated_tools_by_module())


def test_setup_guide_counts_match_the_modules() -> None:
    import re

    text = (REPO / "docs" / "SETUP_GUIDE.md").read_text()
    section = text[text.index("## Available Tools") :]
    section = section[: section.index("\n### ")]
    total = re.search(r"\*\*(\d+) tools\*\* across (\d+) categories", section)
    assert total, "SETUP_GUIDE tool-count sentence not found"
    rows = [int(n) for n in re.findall(r"^\| [^|]+ \| (\d+) \|", section, re.M)]
    modules = _decorated_tools_by_module()

    assert int(total.group(1)) == len(_decorated_tool_names())
    assert int(total.group(2)) == len(modules) == len(rows)
    assert sorted(rows) == sorted(len(tools) for tools in modules.values())
    assert sum(rows) == len(_decorated_tool_names())
    assert f"(all {len(_decorated_tool_names())} tools)" in text
