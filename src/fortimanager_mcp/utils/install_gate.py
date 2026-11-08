"""Preview-before-install gate for policy package and device-settings installs.

FortiManager can preview an installation (``preview_install``) before pushing
it to devices, but nothing forces a caller to look before leaping: an agent
can ``install_package`` straight to production devices with no dry run. This
module records successful preview submissions so ``install_package`` and
``install_device_settings`` can require one (bundle D of
`#11 <https://github.com/rstierli/fortimanager-mcp/issues/11>`_).

Behavior is governed by ``FMG_INSTALL_SAFETY`` (same shape as
``FMG_SCRIPT_SAFETY`` / ``FMG_POLICY_SAFETY``):

- ``strict`` (default): refuse to install without a verified preview for the
  same ADOM + target + device set.
- ``warn``: install proceeds, but the response carries a warning.
- ``disabled``: previous behavior, no gate.

The target is the package name, or :data:`DEVICE_SETTINGS_TARGET` for a
device-settings install (``preview_install(package=None)`` authorizes
``install_device_settings``). The two never authorize each other.

Scope note: FortiManager's ``/securityconsole/install/preview`` is
*device*-scoped -- it takes ``adom`` + ``scope`` (devices) but no ``pkg``
parameter. On builds with the staged preview (FMG 7.6.7+ / 8.0.2+, see
``install_preview``) the render is tied to a staging install of the named
package; on older builds it reflects whatever is pending for those devices,
not one named package in isolation. The package binding here is therefore
enforced by this gate either way: the record is keyed by
``(adom, target, scope)`` and additionally carries a fingerprint
(:func:`preview_fingerprint`), so an install is only authorized by a preview
recorded for that same target whose content has not changed since.

A recorded preview is only honored when its FMG task finished successfully
(verified live via ``get_task`` at install time), is younger than
``PREVIEW_VALIDITY_TTL``, matches the exact device scope, and the fingerprint
is unchanged since the preview (issue
`#25 <https://github.com/rstierli/fortimanager-mcp/issues/25>`_ — without the
check, a package edited *between* preview and install would deploy
unreviewed changes under the old preview's authorization). An install takes
the record out of the registry before its first await (:func:`take_preview`)
and puts it back only if the gate refuses, and installs of one target run
one at a time (:func:`install_lock`), so one preview authorizes exactly one
install even when calls race. A preview attempt drops the target's record
when it starts, so a failed re-preview leaves nothing behind that authorizes.

This is ephemeral process state and assumes the server runs as a single
process (uvicorn with no workers), like the global client itself.
"""

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

logger = logging.getLogger(__name__)

# A preview older than this no longer authorizes an install. Long enough to
# run preview_install, review its result and install by hand; short enough
# that yesterday's preview cannot bless today's install.
PREVIEW_VALIDITY_TTL = 1800.0

#: The gate target of a device-settings install (``install_device_settings``,
#: ``preview_install(package=None)``). ``<`` and ``>`` are outside the
#: package-name pattern, so no real package can be keyed the same way.
DEVICE_SETTINGS_TARGET = "<device-settings>"

#: What the gate compares between preview and install: one FMG change
#: counter per component (see :func:`preview_fingerprint`).
Fingerprint = dict[str, int]

_Key = tuple[str, str, str]

# (adom, target, scope_key) ->
#     {"task_id": int, "recorded_at": float, "fingerprint": Fingerprint | None}
_PREVIEWS: dict[_Key, dict[str, Any]] = {}

# Bumped whenever a target's record is replaced or dropped, so a record an
# install took out is only put back if nothing happened to it meanwhile.
_GENERATIONS: dict[_Key, int] = {}

# Per-target install locks, with the number of calls holding or awaiting
# each; an entry is dropped when its last user leaves.
_INSTALL_LOCKS: dict[_Key, tuple[asyncio.Lock, int]] = {}


def _target(package: str | None) -> str:
    return DEVICE_SETTINGS_TARGET if package is None else package


def _scope_key(devices: list[dict[str, str]]) -> str:
    """Canonical, order-insensitive key for a device scope.

    Only ``name`` and ``vdom`` count, stripped: they are what names an
    install target, and nothing else in an entry widens or narrows the key.
    A missing vdom keys as ``""``, not ``"root"``: ``{"name": "FGT1"}`` is a
    different install target from FGT1/root, so a preview of one must not
    authorize the other. JSON-encoded so a separator inside a name cannot
    make two scopes collide.
    """
    pairs = sorted(
        [str(d.get("name") or "").strip(), str(d.get("vdom") or "").strip()] for d in devices
    )
    return json.dumps(pairs, separators=(",", ":"))


def _key(adom: str, package: str | None, devices: list[dict[str, str]]) -> _Key:
    return (adom, _target(package), _scope_key(devices))


def _bump(key: _Key) -> None:
    _GENERATIONS[key] = _GENERATIONS.get(key, 0) + 1


async def package_revision(client: Any, adom: str, package: str) -> int | None:
    """Fetch the package's revision counter (``obj ver``), or None.

    Returns None when the fetch fails or the field is absent (older builds).
    """
    try:
        pkg = await client.get_package(adom, package)
    except Exception as e:
        logger.warning(f"Could not fetch revision of package '{package}': {e}")
        return None
    rev = pkg.get("obj ver") if isinstance(pkg, dict) else None
    return rev if isinstance(rev, int) else None


async def preview_fingerprint(client: Any, adom: str, package: str | None) -> Fingerprint | None:
    """The state a preview describes, as FMG change counters, or None.

    Captured before a preview is submitted and again at install time; any
    difference means the preview no longer describes what would be pushed.
    Each component is one counter, named by what it covers:

    - ``package``: the policy package's ``obj ver``. It moves on policy
      add, modify and delete inside the package (measured on 7.6.7), and
      verified on 8.0.2: edits to objects the package references bump obj
      ver (an address used by a policy); an object nothing in the package
      uses does not, and needs not. Device-level settings are not covered.

    A device-settings target (``package=None``) has no component, so its
    fingerprint is None. None means "nothing to compare": recorded at
    preview time, the gate falls back to TTL + single use for that record;
    returned at install time for a record that has one, the gate refuses.
    A component added here must be readable on every build the gate runs
    on, or the install-time read fails closed.
    """
    if package is None:
        return None
    revision = await package_revision(client, adom, package)
    if revision is None:
        return None
    return {"package": revision}


def record_preview(
    adom: str,
    package: str | None,
    devices: list[dict[str, str]],
    task_id: int,
    fingerprint: Fingerprint | None = None,
) -> None:
    """Record a successfully submitted preview task for this install target.

    ``package=None`` is the device-settings target. ``fingerprint`` is
    :func:`preview_fingerprint` captured at preview time; None disables
    the fingerprint comparison for this record.
    """
    key = _key(adom, package, devices)
    _PREVIEWS[key] = {
        "task_id": task_id,
        "recorded_at": time.monotonic(),
        "fingerprint": fingerprint,
    }
    _bump(key)


def _fresh(key: _Key) -> dict[str, Any] | None:
    """The record under ``key``, dropping it first if it has expired."""
    entry = _PREVIEWS.get(key)
    if entry is None:
        return None
    if time.monotonic() - entry["recorded_at"] > PREVIEW_VALIDITY_TTL:
        del _PREVIEWS[key]
        _bump(key)
        return None
    return entry


def find_preview(adom: str, package: str | None, devices: list[dict[str, str]]) -> int | None:
    """Return the recorded preview task id for this target, or None.

    Expired records are dropped on lookup.
    """
    entry = _fresh(_key(adom, package, devices))
    if entry is None:
        return None
    task_id: int = entry["task_id"]
    return task_id


def recorded_fingerprint(
    adom: str, package: str | None, devices: list[dict[str, str]]
) -> Fingerprint | None:
    """The fingerprint captured when this target's preview was recorded.

    None when no record exists or the record carries none. Does not
    TTL-check -- call ``find_preview`` first.
    """
    entry = _PREVIEWS.get(_key(adom, package, devices))
    if entry is None:
        return None
    fingerprint: Fingerprint | None = entry.get("fingerprint")
    return fingerprint


def consume_preview(adom: str, package: str | None, devices: list[dict[str, str]]) -> None:
    """Drop this target's preview record (a new preview attempt starts)."""
    key = _key(adom, package, devices)
    _PREVIEWS.pop(key, None)
    _bump(key)


class TakenPreview:
    """A preview record an install took out of the registry.

    ``entry`` is the record, or None if there was none or it had expired.
    """

    def __init__(self, key: _Key, entry: dict[str, Any] | None):
        self.key = key
        self.entry = entry
        self.generation = _GENERATIONS.get(key, 0)

    @property
    def task_id(self) -> int | None:
        return None if self.entry is None else int(self.entry["task_id"])

    @property
    def fingerprint(self) -> Fingerprint | None:
        return None if self.entry is None else self.entry.get("fingerprint")

    def restore(self) -> None:
        """Put the record back after the gate refused the install.

        Skipped when the registry moved on meanwhile (a new preview was
        recorded, or a preview attempt dropped the record): a restore never
        undoes a newer state.
        """
        if self.entry is None or _GENERATIONS.get(self.key, 0) != self.generation:
            return
        _PREVIEWS.setdefault(self.key, self.entry)


def take_preview(adom: str, package: str | None, devices: list[dict[str, str]]) -> TakenPreview:
    """Remove this target's preview record and hand it to the install.

    Synchronous on purpose: lookup and removal happen with no await in
    between, so two installs racing for one preview cannot both get it.
    """
    key = _key(adom, package, devices)
    entry = _fresh(key)
    if entry is not None:
        del _PREVIEWS[key]
        _bump(key)
    return TakenPreview(key, entry)


@contextlib.asynccontextmanager
async def install_lock(
    adom: str, package: str | None, devices: list[dict[str, str]]
) -> AsyncIterator[None]:
    """Serialize installs of one target (ADOM + package or device settings + scope).

    Held from the gate check until the install is submitted, so two calls
    for the same target never overlap, whatever ``FMG_INSTALL_SAFETY`` says.
    """
    key = _key(adom, package, devices)
    lock, users = _INSTALL_LOCKS.get(key, (asyncio.Lock(), 0))
    _INSTALL_LOCKS[key] = (lock, users + 1)
    try:
        async with lock:
            yield
    finally:
        lock, users = _INSTALL_LOCKS[key]
        if users <= 1:
            del _INSTALL_LOCKS[key]
        else:
            _INSTALL_LOCKS[key] = (lock, users - 1)


#: ``/task/task`` ``state`` values. FNDN ``STATE_OPTIONS`` macro of the task
#: syntax; the same 0-10 enum in the 7.2.11, 7.4.8, 7.6.5, 7.6.7 and 8.0.0
#: references.
TASK_STATES: dict[int, str] = {
    0: "pending",
    1: "running",
    2: "cancelling",
    3: "cancelled",
    4: "done",
    5: "error",
    6: "aborting",
    7: "aborted",
    8: "warning",
    9: "to_continue",
    10: "unknown",
}

#: States in which a task has ended. ``warning`` is an end state too: an
#: install with nothing to push ends there (verified live, FMG 8.0.2).
#: ``to_continue`` is not: the task waits to be resumed.
TERMINAL_TASK_STATES = frozenset({"done", "warning", "error", "cancelled", "aborted"})


def task_state(task: dict[str, Any]) -> str:
    """Normalize an FMG task object's state to a lowercase string.

    Numeric states decode through :data:`TASK_STATES`; anything else
    (missing, or a number outside the enum) is ``"unknown"``.
    """
    state = task.get("state")
    if isinstance(state, str):
        return state.lower()
    if isinstance(state, int) and not isinstance(state, bool):
        return TASK_STATES.get(state, "unknown")
    return "unknown"


def _reset() -> None:
    """Drop all recorded previews and install locks (test isolation only)."""
    _PREVIEWS.clear()
    _GENERATIONS.clear()
    _INSTALL_LOCKS.clear()
