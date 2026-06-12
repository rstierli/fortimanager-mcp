"""ADOM workspace-lock tracking and shutdown release.

In workspace mode an ADOM must be locked before changes and unlocked after.
The lock/unlock calls are separate MCP tools, so an agent that errors out (or
a conversation that simply ends) between ``lock_adom`` and ``unlock_adom``
leaves the ADOM locked, blocking other administrators until the FMG session
times out. This module tracks which ADOMs were locked through this server and
releases any still-held locks at server shutdown, before the client logs out
(bundle D of `#11 <https://github.com/rstierli/fortimanager-mcp/issues/11>`_).

Deliberately NOT done here: auto-unlocking when an individual tool call
fails. The agent may be mid-workflow (lock -> change -> retry the failed
change -> commit -> unlock), and yanking the lock out from under it would
discard the workspace session it is still using. Only at shutdown — when no
further tool call can possibly come — is releasing the lock always right.

This is ephemeral process state and assumes the server runs as a single
process (uvicorn with no workers), like the global client itself.
"""

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Per-unlock budget during shutdown: best-effort, must not stall the shutdown.
UNLOCK_TIMEOUT = 5.0

_HELD_LOCKS: set[str] = set()


def record_lock(adom: str) -> None:
    """Track an ADOM locked through this server."""
    _HELD_LOCKS.add(adom)


def record_unlock(adom: str) -> None:
    """Stop tracking an ADOM after it was unlocked."""
    _HELD_LOCKS.discard(adom)


def held_locks() -> list[str]:
    """ADOMs currently recorded as locked through this server."""
    return sorted(_HELD_LOCKS)


async def release_held_locks(client: Any) -> None:
    """Best-effort unlock of every ADOM still recorded as locked.

    Called at server shutdown, before the client disconnects. Each unlock is
    shielded (dispatched even while shutdown itself is being cancelled) and
    bounded by ``UNLOCK_TIMEOUT`` so a wedged FMG cannot stall the shutdown.
    Failures are logged and swallowed — the FMG releases session-bound locks
    when the session ends, so this is an explicit, observable release of what
    would otherwise be reclaimed implicitly.
    """
    for adom in held_locks():
        try:
            await asyncio.shield(asyncio.wait_for(client.unlock_adom(adom), timeout=UNLOCK_TIMEOUT))
            record_unlock(adom)
            logger.warning(
                "ADOM '%s' was still locked at shutdown; released the workspace lock.", adom
            )
        except Exception:  # noqa: BLE001 - cleanup must not block shutdown
            logger.warning(
                "ADOM '%s' was still locked at shutdown and could not be unlocked; "
                "the FMG will release it when the session ends.",
                adom,
            )


def _reset() -> None:
    """Drop all tracked locks (test isolation only)."""
    _HELD_LOCKS.clear()
