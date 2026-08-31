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
    """Nothing upstream raises these to the patched releases.

    Measured against mcp 2.1.1: mcp does not depend on
    pydantic-settings at all, and the tightest starlette constraint in
    the tree is ``sse-starlette`` 3.4.8's ``>=0.49.1`` (mcp itself asks
    ``>=0.27``, or ``>=0.48.0`` on 3.14+). pydantic-settings 2.14.2
    fixes GHSA-4xgf-cpjx-pc3j and starlette 1.3.1 fixes PYSEC-2026-249.
    """
    assert _requirement("pydantic-settings") == "pydantic-settings>=2.14.2"
    assert _requirement("starlette") == "starlette>=1.3.1"


def test_httpx_is_not_declared() -> None:
    """mcp 2.x depends on ``httpx2``, never ``httpx`` (#95).

    Nothing in ``src/`` or ``tests/`` imports ``httpx``, and nothing else
    in the tree pulls it: starlette wants it only under a ``full`` extra
    this project does not install. It is dead weight rather than a
    security floor, unlike the two guarded above.
    """
    data = tomllib.loads(_PYPROJECT.read_text())
    # Match the name exactly. A bare ``startswith("httpx")`` would also fire
    # on a future ``httpx2`` floor, and this project does declare transitive
    # floors directly (see the two guarded above), so that door stays open.
    declared = [
        e
        for e in data["project"]["dependencies"]
        if e == "httpx"
        or e.startswith(("httpx>", "httpx=", "httpx<", "httpx!", "httpx~", "httpx["))
    ]
    assert declared == [], f"httpx is declared but unused: {declared}"


def test_noise_suppression_names_the_client_that_ships() -> None:
    """The suppression must name ``httpx2``, the client mcp 2.x actually uses (#95).

    Under mcp 1.x this named ``httpx``; 2.x logs under ``httpx2``
    (``httpx2/_client.py``), so the old name silenced a logger this tree
    no longer has.
    """
    source = (
        Path(__file__).parent.parent / "src" / "fortimanager_mcp" / "utils" / "config.py"
    ).read_text()
    assert 'getLogger("httpx2")' in source
    assert 'getLogger("httpx")' not in source
