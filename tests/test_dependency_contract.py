"""The dependency floors that keep the server importable.

mcp 2.0 removed ``mcp.server.fastmcp`` and replaced it with
``mcp.server.mcpserver``. The server is now built on the 2.x API, so the
floor is load-bearing in the other direction: 1.x lacks the module this
server imports, and the removed ``<2`` ceiling must stay removed.
"""

import tomllib
from pathlib import Path

import mcp

_PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


def _requirement(prefix: str) -> str:
    data = tomllib.loads(_PYPROJECT.read_text())
    for entry in data["project"]["dependencies"]:
        if entry.startswith(prefix):
            return entry
    raise AssertionError(f"{prefix} is not declared in pyproject dependencies")


def test_mcpserver_is_importable() -> None:
    """The smoke test that mcp 1.x fails."""
    from mcp.server.mcpserver import MCPServer

    assert MCPServer is not None


def test_installed_mcp_is_2x() -> None:
    assert mcp.__name__ == "mcp"
    from importlib.metadata import version

    assert version("mcp").startswith("2."), "mcp 1.x lacks mcp.server.mcpserver"


def test_mcp_floor_is_2x_and_unceilinged() -> None:
    """Guards the floor itself: dropping back to 1.x stops the import.

    2.0.0 is also above the ``>=1.28.1`` security floor the old pin
    carried for PYSEC-2026-3483, so nothing regresses by lifting it.
    """
    requirement = _requirement("mcp")
    assert "<2" not in requirement
    assert requirement == "mcp>=2.0.0"


def test_security_floors_are_declared() -> None:
    """Holding mcp at 1.x holds its transitive deps back onto known CVEs.

    pydantic-settings 2.14.2 fixes GHSA-4xgf-cpjx-pc3j and starlette
    1.3.1 fixes PYSEC-2026-249, so both floors have to be stated here
    rather than inherited.
    """
    assert _requirement("pydantic-settings") == "pydantic-settings>=2.14.2"
    assert _requirement("starlette") == "starlette>=1.3.1"
