"""Anti-exhaustion guard for FortiManager async-task spawning tools.

FortiManager runs installs, install previews, and script executions as
server-side background tasks: the spawning call returns a task id immediately
and the work continues on the FMG. Spawning is therefore cheap for the caller
but expensive for the FMG, so the tools that create tasks share one in-process
budget of concurrent in-flight tasks. Ported from the FortiAnalyzer MCP's
logsearch anti-exhaustion guards
(`fortianalyzer-mcp#18 <https://github.com/rstierli/fortianalyzer-mcp/pull/18>`_),
adapted to the FMG task lifecycle (bundle C of
`#11 <https://github.com/rstierli/fortimanager-mcp/issues/11>`_):

- A FAZ logsearch holds its concurrency slot only for the guarded call's own
  lifetime. An FMG task keeps running server-side *after* the spawning tool
  returns, so a slot here is held until ``wait_for_task`` observes a terminal
  state (``mark_task_done``) or the slot's TTL expires — the TTL covers
  callers that never poll, so they cannot permanently exhaust the budget.
- A plain ``asyncio.Semaphore`` cannot express "release on observed completion
  or TTL, whichever first", so the budget is a small registry with the same
  acquire/release contract instead.
- When the budget is full, ``spawn_guarded`` fails fast with
  :class:`TaskSlotsExhausted` rather than queueing: blocking an MCP request
  for minutes while installs drain is worse than a clear, retryable error.

This is ephemeral process state and assumes the server runs as a single
process (uvicorn with no workers), like the global client itself.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

# Max concurrent in-flight FMG tasks spawned through this server (installs,
# previews, script executions). Conservative: FMG serializes much of this
# work internally per device/ADOM, so more parallel tasks mostly means more
# queueing and lock contention on the FMG, not more throughput.
TASK_CONCURRENCY_LIMIT = 5

# A slot whose task was never observed terminal is reclaimed after this many
# seconds. Generous on purpose: a multi-device install can legitimately run
# for many minutes, and reclaiming a slot early only weakens the guard (the
# FMG task itself is unaffected either way).
TASK_SLOT_TTL = 1800.0

# Hard upper bound on wait_for_task's wall-clock budget. A caller passing a
# huge timeout must not be able to park a request (and its connection) for
# hours; anything longer-running should re-poll with get_task/wait_for_task.
MAX_TASK_WAIT_TIMEOUT = 3600

# Deadline for a single get_task status poll. The client's own transport
# timeout applies per HTTP attempt; this bounds the whole poll call (including
# the client's internal transient retries) so one wedged poll cannot eat the
# entire wait budget.
POLL_CALL_TIMEOUT = 30.0

# Shared recovery budget for deadline-bounded polls that time out within one
# wait_for_task call (the FMG analog of FAZ's MAX_SEARCH_REISSUES). Persistent
# API errors are NOT retried here — get_task already retries transients
# internally, so an exception surfacing means retries were exhausted or the
# error is real (not found, permission) and re-polling would be wrong.
MAX_TASK_POLL_FAILURES = 3


class TaskSlotsExhausted(RuntimeError):
    """Raised when no async-task slot is available for a new spawn."""


# slot handle -> {"kind": str, "task_id": int | None, "expires_at": float}
_SLOTS: dict[object, dict[str, Any]] = {}


def _evict_expired(now: float) -> None:
    """Reclaim slots whose TTL passed without an observed terminal state."""
    for handle, slot in list(_SLOTS.items()):
        if slot["expires_at"] <= now:
            logger.warning(
                "Task slot for %s (task %s) expired after %.0fs without an observed "
                "terminal state; reclaiming the slot. The FMG task itself is unaffected.",
                slot["kind"],
                slot["task_id"],
                TASK_SLOT_TTL,
            )
            del _SLOTS[handle]


def in_flight() -> int:
    """Number of currently held task slots (after evicting expired ones)."""
    _evict_expired(asyncio.get_event_loop().time())
    return len(_SLOTS)


async def spawn_guarded(
    kind: str, submit: Callable[[], Awaitable[dict[str, Any]]]
) -> dict[str, Any]:
    """Run a task-spawning API call under the shared in-flight budget.

    Reserves a slot *before* awaiting ``submit`` (so concurrent spawns cannot
    overshoot the limit), binds the returned task id to the slot on success,
    and releases the slot if the submit fails or spawns no task. The slot is
    later released by ``mark_task_done`` (via ``wait_for_task``) or by TTL.

    Raises:
        TaskSlotsExhausted: when ``TASK_CONCURRENCY_LIMIT`` slots are held.
    """
    now = asyncio.get_event_loop().time()
    _evict_expired(now)
    if len(_SLOTS) >= TASK_CONCURRENCY_LIMIT:
        kinds = ", ".join(sorted({s["kind"] for s in _SLOTS.values()}))
        raise TaskSlotsExhausted(
            f"Refusing to start {kind}: {len(_SLOTS)} FMG tasks are already in flight "
            f"({kinds}); limit is {TASK_CONCURRENCY_LIMIT}. Wait for running tasks to "
            f"complete (wait_for_task) and retry."
        )

    handle = object()
    _SLOTS[handle] = {"kind": kind, "task_id": None, "expires_at": now + TASK_SLOT_TTL}
    try:
        result = await submit()
    except BaseException:
        # Submit failed (or was cancelled): nothing is running on the FMG
        # under this slot, release it immediately.
        _SLOTS.pop(handle, None)
        raise

    task_id = result.get("task", result.get("taskid")) if isinstance(result, dict) else None
    if task_id is None:
        # No task spawned (synchronous result): nothing to hold a slot for.
        _SLOTS.pop(handle, None)
    else:
        _SLOTS[handle]["task_id"] = task_id
    return result


def mark_task_done(task_id: int) -> None:
    """Release the slot bound to ``task_id`` (no-op when none is held).

    Called by ``wait_for_task`` when it observes a terminal task state. Safe
    to call for tasks that were not spawned through ``spawn_guarded`` (e.g. a
    task id from a previous server process).
    """
    for handle, slot in list(_SLOTS.items()):
        if slot["task_id"] == task_id:
            del _SLOTS[handle]
            return


def _reset() -> None:
    """Drop all held slots (test isolation only)."""
    _SLOTS.clear()
