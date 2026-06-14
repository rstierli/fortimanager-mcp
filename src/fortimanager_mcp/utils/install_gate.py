"""Preview-before-install gate for policy package installation.

FortiManager can preview an installation (``preview_install``) before pushing
it to devices, but nothing forces a caller to look before leaping: an agent
can ``install_package`` straight to production devices with no dry run. This
module records successful preview submissions so ``install_package`` can
require one (bundle D of
`#11 <https://github.com/rstierli/fortimanager-mcp/issues/11>`_).

Behavior is governed by ``FMG_INSTALL_SAFETY`` (same shape as
``FMG_SCRIPT_SAFETY`` / ``FMG_POLICY_SAFETY``):

- ``strict`` (default): refuse to install without a verified preview for the
  same ADOM + package + device set.
- ``warn``: install proceeds, but the response carries a warning.
- ``disabled``: previous behavior, no gate.

A recorded preview is only honored when its FMG task finished successfully
(verified live via ``get_task`` at install time), is younger than
``PREVIEW_VALIDITY_TTL``, matches the exact device scope, and the package's
revision counter is unchanged since the preview (issue
`#25 <https://github.com/rstierli/fortimanager-mcp/issues/25>`_ — without the
revision check, a package edited *between* preview and install would deploy
unreviewed changes under the old preview's authorization). It is consumed by
the install that uses it: the next install needs a fresh preview.

The revision counter is the package object's ``obj ver`` field (verified live
against FMG 7.6.7: increments on policy add, modify, and delete). When the
field is unavailable at preview time the record carries no revision and the
gate degrades to v1.7.0 behavior (TTL + single-use only).

This is ephemeral process state and assumes the server runs as a single
process (uvicorn with no workers), like the global client itself.
"""

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

# A preview older than this no longer authorizes an install. Long enough to
# run preview -> wait_for_task -> get_preview_result -> review -> install by
# hand; short enough that yesterday's preview cannot bless today's install.
PREVIEW_VALIDITY_TTL = 1800.0

# (adom, package, scope_key) ->
#     {"task_id": int, "recorded_at": float, "revision": int | None}
_PREVIEWS: dict[tuple[str, str, str], dict[str, Any]] = {}


def _scope_key(devices: list[dict[str, str]]) -> str:
    """Canonical, order-insensitive key for a device scope."""
    return ",".join(sorted(f"{d.get('name', '')}/{d.get('vdom', 'root')}" for d in devices))


async def package_revision(client: Any, adom: str, package: str) -> int | None:
    """Fetch the package's revision counter (``obj ver``), or None.

    Returns None when the fetch fails or the field is absent (older builds);
    callers decide what that means — preview-time None degrades the gate to
    TTL + single-use, install-time None (with a recorded revision) refuses.
    """
    try:
        pkg = await client.get_package(adom, package)
    except Exception as e:
        logger.warning(f"Could not fetch revision of package '{package}': {e}")
        return None
    rev = pkg.get("obj ver") if isinstance(pkg, dict) else None
    return rev if isinstance(rev, int) else None


def record_preview(
    adom: str,
    package: str,
    devices: list[dict[str, str]],
    task_id: int,
    revision: int | None = None,
) -> None:
    """Record a successfully submitted preview task for this install target.

    ``revision`` is the package's ``obj ver`` captured at preview time; None
    disables the revision comparison for this record.
    """
    key = (adom, package, _scope_key(devices))
    _PREVIEWS[key] = {
        "task_id": task_id,
        "recorded_at": asyncio.get_event_loop().time(),
        "revision": revision,
    }


def find_preview(adom: str, package: str, devices: list[dict[str, str]]) -> int | None:
    """Return the recorded preview task id for this target, or None.

    Expired records are dropped on lookup.
    """
    key = (adom, package, _scope_key(devices))
    entry = _PREVIEWS.get(key)
    if entry is None:
        return None
    age = asyncio.get_event_loop().time() - entry["recorded_at"]
    if age > PREVIEW_VALIDITY_TTL:
        del _PREVIEWS[key]
        return None
    task_id: int = entry["task_id"]
    return task_id


def recorded_revision(adom: str, package: str, devices: list[dict[str, str]]) -> int | None:
    """The package revision captured when this target's preview was recorded.

    None when no record exists or the record carries no revision (preview-time
    fetch failed, or the build exposes no ``obj ver``). Does not TTL-check —
    call ``find_preview`` first.
    """
    entry = _PREVIEWS.get((adom, package, _scope_key(devices)))
    if entry is None:
        return None
    revision: int | None = entry.get("revision")
    return revision


def consume_preview(adom: str, package: str, devices: list[dict[str, str]]) -> None:
    """Drop the recorded preview after an install used it (single-use)."""
    _PREVIEWS.pop((adom, package, _scope_key(devices)), None)


def task_state(task: dict[str, Any]) -> str:
    """Normalize an FMG task object's state to a lowercase string."""
    state = task.get("state")
    if isinstance(state, str):
        return state.lower()
    if isinstance(state, int):
        state_map = {0: "pending", 1: "running", 4: "done", 5: "error", 3: "cancelled"}
        return state_map.get(state, "unknown")
    return "unknown"


def _reset() -> None:
    """Drop all recorded previews (test isolation only)."""
    _PREVIEWS.clear()
