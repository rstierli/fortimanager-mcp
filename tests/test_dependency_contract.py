"""The dependency floors that keep the server importable.

mcp 2.0 removed ``mcp.server.fastmcp``, which is the API this whole
server is built on. With a floating ``mcp>=1.0.0`` the resolver picks
2.x on any fresh install and the server stops importing entirely, so the
pin is load-bearing rather than housekeeping.
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


def test_fastmcp_is_importable() -> None:
    """The smoke test that mcp 2.x fails."""
    from mcp.server.fastmcp import FastMCP

    assert FastMCP is not None


def test_installed_mcp_is_1x() -> None:
    assert mcp.__name__ == "mcp"
    from importlib.metadata import version

    assert version("mcp").startswith("1."), "mcp 2.x removed mcp.server.fastmcp"


def test_mcp_pin_excludes_2x() -> None:
    """Guards the pin itself: loosening it reintroduces the breakage."""
    assert "<2" in _requirement("mcp")


def test_security_floors_are_declared() -> None:
    """Holding mcp at 1.x holds its transitive deps back onto known CVEs.

    pydantic-settings 2.14.2 fixes GHSA-4xgf-cpjx-pc3j and starlette
    1.3.1 fixes PYSEC-2026-249, so both floors have to be stated here
    rather than inherited.
    """
    assert _requirement("pydantic-settings") == "pydantic-settings>=2.14.2"
    assert _requirement("starlette") == "starlette>=1.3.1"
