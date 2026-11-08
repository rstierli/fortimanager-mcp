"""Run a complete FortiManager install preview: stage, render, fetch, release.

FortiManager has no single "preview this package" call. The GUI's Install
Preview is four JSON-RPC steps, and the API only produces a preview of the
package asked about when all four run in order (FNDN 8.0
``securityconsole.json``; live-verified against FMG 8.0.2-build0198):

1. ``/securityconsole/install/package`` (or ``/install/device`` for device
   settings) with ``flags=["preview"]`` -- "generate preview cache only".
   Copies the package into the device DB and opens an install-wizard
   session on the target devices. This is where a package that cannot be
   installed fails (e.g. a normalized interface with no mapping for the
   device), so its task lines are returned on failure.
2. ``/securityconsole/install/preview`` with ``preview_taskid`` = step 1's
   task -- renders the CLI the install would push.
3. ``/securityconsole/preview/result`` with the same ``preview_taskid``.
4. ``/securityconsole/package/cancel/install`` -- discards the staged copy
   and releases the wizard session. Skipping it leaves the devices held:
   every later install or preview of them queues "Blocked by
   preview/install wizard" until the session is cancelled.

Before this module, ``preview_install`` ran step 2 alone. Without a staging
task, ``preview_taskid`` defaults to "the last install task", so the result
described whatever install ran last, not the named package -- and
``install_package(preview=True)`` ran step 1 alone, leaving the wizard
session open. Step 4 runs in a ``finally`` here so neither can recur.
"""

import asyncio
import json
import logging
import re
from typing import Any

from fortimanager_mcp.utils.install_gate import task_state
from fortimanager_mcp.utils.task_guard import mark_task_done, spawn_guarded
from fortimanager_mcp.utils.validation import redact_config_text_secrets

logger = logging.getLogger(__name__)

#: Default and maximum wall-clock budget for one preview, all steps together.
DEFAULT_PREVIEW_TIMEOUT = 300
MAX_PREVIEW_TIMEOUT = 900

_POLL_INTERVAL = 2.0


class PreviewFailed(Exception):
    """A preview step did not finish successfully.

    Carries the step name and the FMG task lines, which hold the reason
    (``"Compiling dynamic interface ... fail: invalid value"``) a caller
    needs to fix the package.
    """

    def __init__(self, step: str, message: str, task_id: int | None, lines: list[dict[str, Any]]):
        super().__init__(message)
        self.step = step
        self.task_id = task_id
        self.lines = lines


def summarize_task_lines(lines: Any) -> list[dict[str, Any]]:
    """Reduce FMG task lines to what explains an outcome: name, state, detail, history."""
    out: list[dict[str, Any]] = []
    for line in lines if isinstance(lines, list) else []:
        if not isinstance(line, dict):
            continue
        history = [
            h.get("detail")
            for h in line.get("history") or []
            if isinstance(h, dict) and h.get("detail")
        ]
        out.append(
            {
                "name": line.get("name"),
                "state": task_state(line),
                "detail": line.get("detail"),
                "history": history,
            }
        )
    return out


class NothingToInstall(Exception):
    """FortiManager ended the staging task because no device has changes."""

    def __init__(self, task_id: int):
        super().__init__(f"task {task_id} found no changes to install")
        self.task_id = task_id


async def wait_task_terminal(client: Any, task_id: int, deadline: float) -> dict[str, Any]:
    """Poll a task until it is terminal; raise TimeoutError past ``deadline``.

    ``deadline`` is an event-loop time. Releases the task's in-flight slot
    once the task ends.
    """
    loop = asyncio.get_event_loop()
    while True:
        task: dict[str, Any] = await client.get_task(task_id)
        if task_state(task) in ("done", "error", "cancelled", "warning", "aborted"):
            mark_task_done(task_id)
            return task
        if loop.time() >= deadline:
            raise TimeoutError(f"task {task_id} still {task_state(task)} at the deadline")
        await asyncio.sleep(_POLL_INTERVAL)


async def _run_step(client: Any, step: str, kind: str, submit: Any, deadline: float) -> int:
    """Submit one task-spawning step, wait for it, return its task id or raise."""
    result = await spawn_guarded(kind, submit)
    task_id = result.get("task") if isinstance(result, dict) else None
    if task_id is None:
        raise PreviewFailed(step, f"{step} returned no task id: {result}", None, [])
    try:
        task = await wait_task_terminal(client, task_id, deadline)
        problem = (
            None
            if task_state(task) == "done"
            else f"{step} task {task_id} ended in state '{task_state(task)}'"
        )
    except TimeoutError as e:
        # A task stuck pending usually says why in its lines, e.g. "Blocked
        # by preview/install wizard" when another session holds the device.
        problem = str(e)
    if problem is None:
        return int(task_id)
    try:
        lines = summarize_task_lines(await client.get_task_line(task_id))
    except Exception as e:  # the failure itself matters more than its detail
        logger.warning(f"Could not read lines of failed task {task_id}: {e}")
        lines = []
    if lines and all("no changes" in str(line.get("detail")).lower() for line in lines):
        # Measured on FMG 8.0.2: an install with nothing to push ends in
        # state 8 with the single line "no installing devices/no changes on
        # device". A partial warning names other reasons and stays a failure.
        raise NothingToInstall(int(task_id))
    raise PreviewFailed(step, problem, task_id, lines)


def parse_preview_message(result: Any) -> list[dict[str, Any]] | None:
    """Decode preview/result's per-device envelope, or None if it is not one.

    FMG 8.0 returns ``{"message": "<JSON text>"}`` where the text is a list
    of ``{"name", "oid", "result"}``. The CLI inside ``result`` is therefore
    escaped twice over; redacting the outer string would never match a
    ``set psksecret`` line, because its newlines are still ``\\n`` escapes.
    """
    message = result.get("message") if isinstance(result, dict) else None
    if not isinstance(message, str):
        return None
    try:
        decoded = json.loads(message)
    except ValueError:
        return None
    if not isinstance(decoded, list) or not all(isinstance(d, dict) for d in decoded):
        return None
    return decoded


def redact_preview(value: Any) -> Any:
    """Run the CLI-text redactor over every string in a preview result.

    An install preview is the pending device config rendered as FortiOS CLI,
    so it carries "set psksecret ...", "set password ..." and the rest in
    clear, exactly like the revision content get_device_revision already
    redacts. get_preview_result returned it raw (upstream #71).

    Walks the structure instead of reaching for a known key: the endpoint's
    envelope is not pinned anywhere in this repo, and redacting only the key
    we happen to expect would leak the moment FortiManager nests it
    differently. redact_config_text_secrets only rewrites lines that match
    "set <secret-directive>", so running it over an unrelated string is a
    no-op rather than damage.

    Not measured against a preview that actually contains a credential --
    that needs a pending change carrying one, which is why the finding was
    filed unmeasured. The redactor itself is pinned by its own tests.
    """
    if isinstance(value, str):
        return redact_config_text_secrets(value)
    if isinstance(value, dict):
        return {k: redact_preview(v) for k, v in value.items()}
    if isinstance(value, list):
        return _redact_preview_list(value)
    return value


def _redact_preview_list(value: list[Any]) -> list[Any]:
    """Redact a list, treating each run of strings as one block of CLI.

    redact_config_text_secrets handles a quoted value spanning several
    lines by consuming continuation lines until the quote closes. That
    tracking lives inside one string, so redacting each element on its own
    matched only the line carrying the directive and let every later line
    of the same secret through verbatim (upstream #85).

    Joining a run and redacting it as one text gives those lines the same
    treatment they get when the preview arrives as a single string. The
    result is SHORTER than the input when a secret spanned elements,
    because the redactor drops the continuation lines rather than keeping
    them partially: that is the same fail-closed trade the single-string
    path already makes, and the lines it drops carry only secret content.

    Only CONTIGUOUS runs are joined. A non-string element belongs to a
    different part of the envelope, so an unterminated quote must not
    reach across it and eat the far side.
    """
    out: list[Any] = []
    run: list[str] = []

    def flush() -> None:
        if not run:
            return
        redacted = redact_config_text_secrets("\n".join(run))
        out.extend(redacted.split("\n") if redacted else [])
        run.clear()

    for item in value:
        if isinstance(item, str):
            run.append(item)
            continue
        flush()
        out.append(redact_preview(item))
    flush()
    return out


#: FMG prefixes each device's CLI with "=== Preview result ===", or returns
#: only "=== No preview result ===" when the install would push nothing.
_PREVIEW_BANNER = re.compile(r"^=== .* ===$", re.MULTILINE)


def _device_previews(decoded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-device preview CLI, redacted, with a has_changes flag."""
    devices = []
    for entry in decoded:
        cli = entry.get("result")
        cli = redact_config_text_secrets(cli) if isinstance(cli, str) else cli
        body = _PREVIEW_BANNER.sub("", cli).strip() if isinstance(cli, str) else ""
        devices.append(
            {
                "name": entry.get("name"),
                "has_changes": bool(body),
                "preview": cli,
            }
        )
    return devices


async def run_install_preview(
    client: Any,
    adom: str,
    package: str | None,
    devices: list[dict[str, str]],
    timeout: int = DEFAULT_PREVIEW_TIMEOUT,
) -> dict[str, Any]:
    """Stage, render, fetch and release one install preview.

    ``package=None`` previews pending device settings (install/device)
    instead of a policy package. Returns the staging and preview task ids
    and the per-device preview; raises :class:`PreviewFailed` when a step
    does not finish. The staged copy is always cancelled, success or not.
    """
    timeout = max(30, min(int(timeout), MAX_PREVIEW_TIMEOUT))
    deadline = asyncio.get_event_loop().time() + timeout

    if package is None:

        async def stage() -> dict[str, Any]:
            result: dict[str, Any] = await client.install_device(
                adom=adom, scope=devices, flags=["preview"]
            )
            return result

    else:

        async def stage() -> dict[str, Any]:
            result: dict[str, Any] = await client.install_package(
                adom=adom, pkg=package, scope=devices, flags=["preview"]
            )
            return result

    staging_task: int | None = None
    try:
        staging_task = await _run_step(client, "stage", "preview_install", stage, deadline)
        preview_task = await _run_step(
            client,
            "render",
            "preview_install",
            lambda: client.install_preview(
                adom=adom, scope=devices, flags=["none"], preview_taskid=staging_task
            ),
            deadline,
        )
        raw = await client.get_preview_result(adom, devices, preview_taskid=staging_task)
    except NothingToInstall as e:
        return {
            "staging_task_id": e.task_id,
            "preview_task_id": e.task_id,
            "devices": [{"name": d["name"], "has_changes": False, "preview": ""} for d in devices],
        }
    except PreviewFailed as e:
        if e.step == "stage" and e.task_id is not None:
            staging_task = e.task_id
        raise
    finally:
        if staging_task is not None:
            try:
                await client.cancel_install(adom, preview_taskid=staging_task)
            except Exception as e:
                # Not fatal to the preview, but the devices stay held by the
                # wizard session until it is cancelled -- say so loudly.
                logger.error(
                    f"Could not release staged preview task {staging_task} in ADOM "
                    f"'{adom}'; installs to {devices} may queue until it is cancelled: {e}"
                )

    decoded = parse_preview_message(raw)
    response: dict[str, Any] = {
        "staging_task_id": staging_task,
        "preview_task_id": preview_task,
    }
    if decoded is None:
        # An envelope this module does not know: hand it back through the
        # structural redactor rather than guessing at its shape.
        response["raw"] = redact_preview(raw)
    else:
        response["devices"] = _device_previews(decoded)
    return response
