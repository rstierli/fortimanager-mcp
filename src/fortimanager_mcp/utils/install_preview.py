"""Run a complete FortiManager install preview: stage, render, fetch, release.

FortiManager has no single "preview this package" call. The GUI's Install
Preview is four JSON-RPC steps (How-To guide, "How to trigger an install
preview for a single device?"; live-verified against FMG 8.0.2):

1. ``/securityconsole/install/package`` (or ``/install/device`` for device
   settings) with ``flags=["preview"]`` -- "generate preview cache only".
   Copies the package into the device DB and opens an install-wizard
   session on the target devices. This is where a package that cannot be
   installed fails (e.g. a normalized interface with no mapping for the
   device), so its task lines are returned on failure.
2. ``/securityconsole/install/preview`` with ``preview_taskid`` = step 1's
   task -- renders the CLI the install would push.
3. ``/securityconsole/preview/result`` with the same ``preview_taskid``.
4. ``/securityconsole/package/cancel/install`` with the same
   ``preview_taskid`` -- discards the staged copy and releases the wizard
   session. Left open, it held the devices in the original 8.0.2 run of
   this flow: later installs queued "Blocked by preview/install wizard".
   (A second stage by the same API admin was not blocked in a later run,
   so the hold seems to bite other sessions and real installs.)

Which builds get this flow
--------------------------
``preview_taskid`` is what ties steps 2-4 to step 1. The FNDN references
bundled here list it on all three commands (and on ``abort``) in 7.6.7
only; the 7.2.11, 7.4.8, 7.6.5 and 8.0.0 references do not have it, and the
How-To guide's step 4 sends ``cancel/install`` with ``adom`` alone. Without
the id, that cancel is ADOM-wide as far as the documentation goes: it could
discard another administrator's install wizard in the same ADOM. So the
staged flow runs only where the id is documented or measured
(:func:`staged_preview_supported`: 7.6.7+ on 7.6, 8.0.2+ on 8.0, anything
newer than 8.0). Elsewhere preview_install keeps the pre-1.13 behaviour:
the render step alone, a task id to wait for, then get_preview_result, with
a warning that the result shows what is pending for the devices rather
than one named package.

What 8.0.2 showed live: ``preview/result`` honours ``preview_taskid`` (a
real staging id returns that preview, an unknown id "No preview result"),
and so does ``cancel/install``: after a cancel naming another id, this
preview's result was still there; after a cancel naming its own id it was
gone. ``cancel/install`` answers OK to anything (an unknown id, a
non-numeric one, an unknown attribute), so its reply proves nothing; and a
second administrator's GUI wizard could not be tested from one API
account. An ADOM-wide cancel (``adom`` alone) was deliberately not tried
on the shared lab.

Release on every path
---------------------
The release (step 4) runs whenever a staging task was submitted: success,
failed step, "nothing to install", timeout, or the tool call being
cancelled. A release that fails is reported to the caller in a
``warning`` (or ``release_warning`` on an error) naming the staging task,
because the devices may stay held until someone cancels it. A cancelled
tool call (client gone, server stopping) cannot return anything: the
release is then sent from its own task, shielded from that cancellation,
and its outcome is logged. Once the server is stopping
(``FortiManagerClient.prepare_shutdown``), every request is capped at what
is left of the shutdown budget and refused after it, so a release sent
then cannot stretch the stop, but may not go out: a release that was not
sent is logged as an error with the call that releases the session by
hand. A tool call cancelled before the stop begins (stdio closes its
session first; an HTTP client can drop its request) sends the release as
one ordinary request, bounded by FORTIMANAGER_TIMEOUT. A preview
waiting on a long ``timeout`` does not hold the stop either: its polls
fail the same way, which ends the wait and triggers the release.

Before this module, ``preview_install`` ran step 2 alone. Without a staging
task, ``preview_taskid`` defaults to "the last install task", so the result
described whatever install ran last, not the named package -- and
``install_package(preview=True)`` ran step 1 alone, leaving the wizard
session open.
"""

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.install_gate import (
    TERMINAL_TASK_STATES,
    consume_preview,
    preview_fingerprint,
    record_preview,
    task_state,
)
from fortimanager_mcp.utils.responses import error_response, redact
from fortimanager_mcp.utils.task_guard import mark_task_done, spawn_guarded
from fortimanager_mcp.utils.validation import (
    CONFIG_TEXT_SECRET_DIRECTIVES,
    MASK_VALUE,
    redact_config_text_secrets,
)

logger = logging.getLogger(__name__)

#: Default, minimum and maximum wall-clock budget for one preview, all
#: steps together.
DEFAULT_PREVIEW_TIMEOUT = 300
MIN_PREVIEW_TIMEOUT = 30
MAX_PREVIEW_TIMEOUT = 900

_POLL_INTERVAL = 2.0

#: First patch release of each train whose preview endpoints take
#: ``preview_taskid``: 7.6.7 per the FNDN reference, 8.0.2 measured live
#: (the 8.0.0 reference does not have it; 8.0.1 is unverified, so it is
#: treated like 8.0.0). Trains newer than 8.0 are assumed to keep it: a
#: parameter present in both a 7.6 and an 8.0 patch is not one a later
#: release would drop.
_STAGED_PREVIEW_MIN_PATCH = {(7, 6): 7, (8, 0): 2}


def staged_preview_supported(version: tuple[int, int, int]) -> bool:
    """Whether this FMG build can run the staged preview with a scoped release."""
    major, minor, patch = version
    if (major, minor) in _STAGED_PREVIEW_MIN_PATCH:
        return patch >= _STAGED_PREVIEW_MIN_PATCH[(major, minor)]
    return (major, minor) > (8, 0)


class PreviewFailed(Exception):
    """A preview step did not finish successfully.

    Carries the step name and the FMG task lines, which hold the reason
    (``"Compiling dynamic interface ... fail: invalid value"``) a caller
    needs to fix the package. ``release_warning`` is set when the staged
    copy could not be released afterwards.
    """

    def __init__(self, step: str, message: str, task_id: int | None, lines: list[dict[str, Any]]):
        super().__init__(message)
        self.step = step
        self.task_id = task_id
        self.lines = lines
        self.release_warning: str | None = None


#: A secret directive quoted inside a line of text ("failed at: set
#: psksecret ENC ..."). redact_config_text_secrets only matches a directive
#: at the start of a line; in a task message or a broken JSON envelope it
#: can sit anywhere, after any non-word character. The rest of the line is
#: masked, and a value that opens a double quote is masked up to the
#: closing quote, across lines, or to the end of the text if it never
#: closes (a PEM key quoted mid-line otherwise leaked its body lines).
_INLINE_SECRET_DIRECTIVE = re.compile(
    r"(?P<prefix>(?<!\w)set\s+(?:"
    + "|".join(re.escape(d) for d in sorted(CONFIG_TEXT_SECRET_DIRECTIVES, key=len, reverse=True))
    + r')[ \t]+)(?:"(?:\\[\s\S]?|[^"\\])*(?:"|\Z))?[^\n]*'
)
_INLINE_ENC_VALUE = re.compile(r'(?P<prefix>(?<!\w)set\s+\S+\s+)"?ENC\s[^\n]*')


def _redact_inline_cli(text: str) -> str:
    """CLI secrets at the start of a line and anywhere inside one."""
    text = redact_config_text_secrets(text)
    text = _INLINE_SECRET_DIRECTIVE.sub(lambda m: m.group("prefix") + MASK_VALUE, text)
    return _INLINE_ENC_VALUE.sub(lambda m: m.group("prefix") + MASK_VALUE, text)


def redact_task_text(text: str) -> str:
    """Redact FortiManager's free text about a task: CLI form and key=value form.

    Task-line detail and history describe the object a step failed on and
    can quote it as CLI (``set psksecret ENC ...``), which the key=value
    redactor does not see, as well as ``password=...`` pairs, which the CLI
    redactor does not.
    """
    return redact(_redact_inline_cli(text))


def summarize_task_lines(lines: Any) -> list[dict[str, Any]]:
    """Reduce FMG task lines to what explains an outcome: name, state, detail, history.

    The detail and history are FortiManager's own text about the object a
    step failed on and can quote the offending value, so they go through
    :func:`redact_task_text` here, before any caller returns them.
    """
    out: list[dict[str, Any]] = []
    for line in lines if isinstance(lines, list) else []:
        if not isinstance(line, dict):
            continue
        history = [
            redact_task_text(str(h.get("detail")))
            for h in line.get("history") or []
            if isinstance(h, dict) and h.get("detail")
        ]
        out.append(
            {
                "name": line.get("name"),
                "state": task_state(line),
                "detail": redact_task_text(d) if isinstance(d := line.get("detail"), str) else d,
                "history": history,
            }
        )
    return out


class NothingToInstall(Exception):
    """FortiManager ended the staging task because it found nothing to install."""

    def __init__(self, task_id: int, lines: list[dict[str, Any]]):
        super().__init__(f"task {task_id} found nothing to install")
        self.task_id = task_id
        self.lines = lines


#: Task-line details that mean "nothing to install" rather than a failure.
#: Measured on FMG 8.0.2: "No installing devices" (e.g. the package is not
#: assigned to the device) and "no changes on device".
_NOTHING_TO_INSTALL = ("no changes", "no installing devices")


async def wait_task_terminal(client: Any, task_id: int, deadline: float) -> dict[str, Any]:
    """Poll a task until it is terminal; raise TimeoutError past ``deadline``.

    ``deadline`` is an event-loop time. Releases the task's in-flight slot
    once the task ends.
    """
    loop = asyncio.get_running_loop()
    while True:
        task: dict[str, Any] = await client.get_task(task_id)
        if task_state(task) in TERMINAL_TASK_STATES:
            mark_task_done(task_id)
            return task
        if loop.time() >= deadline:
            raise TimeoutError(f"task {task_id} still {task_state(task)} at the deadline")
        await asyncio.sleep(_POLL_INTERVAL)


async def _submit_step(
    step: str, kind: str, submit: Callable[[], Awaitable[dict[str, Any]]]
) -> int:
    """Submit one task-spawning step and return its task id, or raise."""
    result = await spawn_guarded(kind, submit)
    task_id = result.get("task") if isinstance(result, dict) else None
    if task_id is None:
        raise PreviewFailed(step, f"{step} returned no task id: {result}", None, [])
    return int(task_id)


async def _await_step(client: Any, step: str, task_id: int, deadline: float) -> None:
    """Wait for a submitted step to finish; raise unless it ended ``done``."""
    try:
        task = await wait_task_terminal(client, task_id, deadline)
        state = task_state(task)
        problem = None if state == "done" else f"{step} task {task_id} ended in state '{state}'"
    except TimeoutError as e:
        # A task stuck pending usually says why in its lines, e.g. "Blocked
        # by preview/install wizard" when another session holds the device.
        problem = str(e)
    if problem is None:
        return
    try:
        lines = summarize_task_lines(await client.get_task_line(task_id))
    except Exception as e:  # the failure itself matters more than its detail
        logger.warning(f"Could not read lines of failed task {task_id}: {e}")
        lines = []
    if (
        step == "stage"
        and lines
        and all(
            any(marker in str(line.get("detail")).lower() for marker in _NOTHING_TO_INSTALL)
            for line in lines
        )
    ):
        # An install with nothing to push ends in state 8 (warning) with
        # only such lines. A warning naming any other reason stays a failure.
        raise NothingToInstall(task_id, lines)
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


#: How many times a JSON string nested in a JSON string is decoded.
_MAX_JSON_STRING_DEPTH = 3

_JSON_ESCAPE = re.compile(r'\\(["\\/nrt])')
_JSON_UNESCAPED = {"n": "\n", "r": "\r", "t": "\t"}


def _decode_json(text: str) -> Any:
    """``text`` decoded if it is JSON, else ``text`` itself.

    A JSON string literal is decoded again while its content is JSON too, up
    to _MAX_JSON_STRING_DEPTH levels, so a double-encoded envelope ends as
    the object or array inside it. The result is an object, an array, a
    decoded string, or ``text`` itself when nothing decoded.
    """
    value: Any = text
    for _ in range(_MAX_JSON_STRING_DEPTH):
        stripped = value.strip()
        if not stripped or stripped[0] not in '[{"':
            break
        try:
            value = json.loads(stripped)
        except ValueError:
            break
        if not isinstance(value, str):
            break
    return value if value != text else text


def _redact_preview_text(text: str) -> str:
    """Redact one preview string that is not a JSON object or array.

    Text that starts like JSON but did not decode (a truncated envelope, or
    a nested encoding) still has its CLI escaped, once per level:
    ``\\n`` for line breaks, so no line starts with ``set``, and ``\\"`` for
    quotes, so a quoted multi-line value is never seen to open. Those
    escapes are read back first and the directive is matched anywhere in a
    line (after ``"result": "``, say). Returned unchanged when that finds no
    secret, so harmless text keeps its escapes.
    """
    if text.lstrip()[:1] not in ("[", "{", '"'):
        return redact_config_text_secrets(text)
    unescaped = text
    for _ in range(_MAX_JSON_STRING_DEPTH):
        unescaped = _JSON_ESCAPE.sub(
            lambda m: _JSON_UNESCAPED.get(m.group(1), m.group(1)), unescaped
        )
    redacted = _redact_inline_cli(unescaped)
    return text if redacted == unescaped else redacted


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

    A string holding a JSON object or array is decoded and walked like the
    rest, and comes back decoded: FMG 8.0 wraps the per-device CLI in a JSON
    text, where every newline is still a ``\\n`` escape and no line starts
    with ``set``, so redacting the encoded text matched nothing. A string
    that looks like JSON but does not parse (e.g. a truncated envelope) is
    redacted with those escapes read back, for the same reason (see
    _redact_preview_text). A JSON-encoded string, single or nested, is
    decoded and redacted; it is returned as it came when it held no secret.

    Not measured against a preview that actually contains a credential --
    that needs a pending change carrying one, which is why the finding was
    filed unmeasured. The redactor itself is pinned by its own tests.
    """
    if isinstance(value, str):
        decoded = _decode_json(value)
        if isinstance(decoded, dict | list):
            return redact_preview(decoded)
        if decoded is value:
            return _redact_preview_text(value)
        # A JSON-encoded string: comes back decoded only if it held a secret.
        redacted = _redact_preview_text(decoded)
        return value if redacted == decoded else redacted
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
    reach across it and eat the far side. A string holding JSON is such an
    element too: it is decoded and walked on its own.
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
        if isinstance(item, str) and _decode_json(item) is item:
            run.append(item)
            continue
        flush()
        out.append(redact_preview(item))
    flush()
    return out


#: FMG prefixes each device's CLI with "=== Preview result ===", or returns
#: only "=== No preview result ===" when the install would push nothing.
_PREVIEW_BANNER = re.compile(r"^=== .* ===$", re.MULTILINE)


def _strings(value: Any) -> Iterator[str]:
    """Every string in a decoded JSON value, depth first."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _device_previews(decoded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-device preview CLI, redacted, with a has_changes flag.

    ``result`` is a string on the builds measured; whatever else it turns
    out to be (a list of lines, a nested object) goes through the same
    structural redactor rather than back to the caller raw.
    """
    devices = []
    for entry in decoded:
        cli = redact_preview(entry.get("result"))
        text = cli if isinstance(cli, str) else "\n".join(_strings(cli))
        body = _PREVIEW_BANNER.sub("", text).strip()
        devices.append(
            {
                "name": entry.get("name"),
                "has_changes": bool(body),
                "preview": cli,
            }
        )
    return devices


#: Releases running on their own because the tool call that started them was
#: cancelled. Holding them here keeps them from being garbage-collected.
_BACKGROUND_RELEASES: set["asyncio.Task[Any]"] = set()


def release_warning_text(
    adom: str, task_id: int, devices: list[dict[str, str]], reason: str
) -> str:
    """What a caller needs to know when a staged preview was not released."""
    names = ", ".join(str(d.get("name")) for d in devices)
    return (
        f"The staged preview (task {task_id}) in ADOM '{adom}' could not be released: "
        f"{reason}. FortiManager may hold {names} in an install-wizard session until it "
        "is cancelled, and installs to them can queue behind it ('Blocked by "
        "preview/install wizard'). Release it with exec "
        f'/securityconsole/package/cancel/install {{"adom": "{adom}", '
        f'"preview_taskid": {task_id}}}, or have a FortiManager administrator cancel the '
        "pending install."
    )


def _log_background_release(
    adom: str, task_id: int, devices: list[dict[str, str]], release: "asyncio.Task[Any]"
) -> None:
    """Log how a release that outlived its tool call ended."""
    if release.cancelled():
        logger.error(release_warning_text(adom, task_id, devices, "the release was cancelled"))
        return
    exc = release.exception()
    if exc is None:
        logger.info(f"Released staged preview task {task_id} in ADOM '{adom}'")
        return
    reason = client_safe_error(exc)[0] if isinstance(exc, Exception) else repr(exc)
    logger.error(release_warning_text(adom, task_id, devices, reason))


async def release_staged_preview(
    client: Any, adom: str, task_id: int, devices: list[dict[str, str]]
) -> str | None:
    """Cancel a staged preview; return a warning for the caller if that failed.

    The cancel runs in its own task shielded from the caller's cancellation:
    a tool call cancelled mid-preview (client disconnect, server stop) still
    sends it, and its outcome is logged since no caller is left to tell.
    """
    release = asyncio.ensure_future(client.cancel_install(adom, preview_taskid=task_id))
    _BACKGROUND_RELEASES.add(release)
    release.add_done_callback(_BACKGROUND_RELEASES.discard)
    try:
        await asyncio.shield(release)
    except asyncio.CancelledError:
        release.add_done_callback(
            lambda done: _log_background_release(adom, task_id, devices, done)
        )
        raise
    except Exception as e:
        warning = release_warning_text(adom, task_id, devices, client_safe_error(e)[0])
        logger.error(f"{warning} ({e})")
        return warning
    return None


class _Staging:
    """The staging task id, known as soon as the stage step is submitted."""

    task_id: int | None = None


async def run_install_preview(
    client: Any,
    adom: str,
    package: str | None,
    devices: list[dict[str, str]],
    timeout: int = DEFAULT_PREVIEW_TIMEOUT,
) -> dict[str, Any]:
    """Stage, render, fetch and release one install preview.

    ``package=None`` previews pending device settings (install/device)
    instead of a policy package. Returns the staging and preview task ids,
    the per-device preview and, when the release failed, ``warning``;
    raises :class:`PreviewFailed` when a step does not finish. The staged
    copy is released on every path once the stage step was submitted.

    Only for builds where :func:`staged_preview_supported` is true: the
    release relies on ``preview_taskid`` to cancel this session only.
    """
    timeout = max(MIN_PREVIEW_TIMEOUT, min(int(timeout), MAX_PREVIEW_TIMEOUT))
    deadline = asyncio.get_running_loop().time() + timeout
    staging = _Staging()
    try:
        response = await _stage_render_fetch(client, adom, package, devices, deadline, staging)
    except BaseException as e:
        if staging.task_id is not None:
            warning = await release_staged_preview(client, adom, staging.task_id, devices)
            if isinstance(e, PreviewFailed):
                e.release_warning = warning
        raise
    if staging.task_id is not None:
        warning = await release_staged_preview(client, adom, staging.task_id, devices)
        if warning:
            response["warning"] = warning
    return response


async def _stage_render_fetch(
    client: Any,
    adom: str,
    package: str | None,
    devices: list[dict[str, str]],
    deadline: float,
    staging: _Staging,
) -> dict[str, Any]:
    """Steps 1-3; records the staging task id in ``staging`` once submitted."""
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

    staging.task_id = staging_task = await _submit_step("stage", "preview_install", stage)
    try:
        await _await_step(client, "stage", staging_task, deadline)
    except NothingToInstall as e:
        return {
            "staging_task_id": e.task_id,
            "preview_task_id": e.task_id,
            "nothing_to_install": True,
            "task_lines": e.lines,
            "devices": [{"name": d["name"], "has_changes": False, "preview": ""} for d in devices],
        }
    preview_task = await _submit_step(
        "render",
        "preview_install",
        lambda: client.install_preview(
            adom=adom, scope=devices, flags=["none"], preview_taskid=staging_task
        ),
    )
    await _await_step(client, "render", preview_task, deadline)
    raw = await client.get_preview_result(adom, devices, preview_taskid=staging_task)

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


def _legacy_preview_warning(version: tuple[int, int, int]) -> str:
    return (
        f"FortiManager {'.'.join(map(str, version))} does not document preview_taskid on "
        "the install preview endpoints (FNDN lists it from 7.6.7; 8.0.2 measured), so the "
        "staged preview is not used: releasing it would take an ADOM-wide cancel/install "
        "that can also discard another administrator's install wizard. This preview runs "
        "the render step alone, as before 1.13.0: its result shows what is pending for "
        "these devices, which is not necessarily the named package alone."
    )


async def preview_install_response(
    client: Any,
    adom: str,
    package: str | None,
    devices: list[dict[str, str]],
    timeout: int,
    operation: str,
) -> dict[str, Any]:
    """Run an install preview and build the tool response; record it for the gate.

    Shared by ``preview_install`` and ``install_package(preview=True)``.
    ``adom``, ``package`` and ``devices`` must already be validated.
    Raises ``TaskSlotsExhausted`` and API errors for the tool to report.
    """
    # A new attempt supersedes any earlier preview of this target, whether
    # or not it succeeds: a failed re-preview must not leave the older one
    # authorizing the install.
    consume_preview(adom, package, devices)
    # Capture the fingerprint BEFORE submitting the preview (#25): if the
    # package changes between this read and the preview's own read, the
    # recorded fingerprint is older and the install gate fails safe (forces
    # a re-preview) instead of passing a stale one. None (fetch failed /
    # field absent / device settings) degrades the gate to TTL + single-use.
    fingerprint = await preview_fingerprint(client, adom, package)
    version = await client._detect_version()

    if not staged_preview_supported(version):
        result = await spawn_guarded(
            "preview_install",
            lambda: client.install_preview(adom=adom, scope=devices, flags=["json"]),
        )
        task_id = result.get("task") if isinstance(result, dict) else None
        if task_id is not None:
            # The gate verifies at install time that this task finished.
            record_preview(adom, package, devices, task_id, fingerprint=fingerprint)
        return {
            "status": "success",
            "staged": False,
            "task_id": task_id,
            "package": package,
            "message": (
                f"Preview started, task ID: {task_id}. Run wait_for_task({task_id}), "
                "then get_preview_result for the same devices."
            ),
            "warning": _legacy_preview_warning(version),
        }

    try:
        result = await run_install_preview(client, adom, package, devices, timeout)
    except PreviewFailed as e:
        extra: dict[str, Any] = {}
        if e.release_warning:
            extra["release_warning"] = e.release_warning
        return error_response(
            error="preview_failed",
            message=e,
            operation=operation,
            adom=adom,
            package=package,
            step=e.step,
            task_id=e.task_id,
            task_lines=e.lines,
            **extra,
        )

    # Record for the preview-before-install gate: install_package (or
    # install_device_settings, for package=None) verifies this task
    # finished -- and the fingerprint is unchanged -- before installing the
    # same target. After "nothing to install" this is the staging task,
    # which ended in state warning, so the gate refuses.
    record_preview(adom, package, devices, result["preview_task_id"], fingerprint=fingerprint)
    response: dict[str, Any] = {
        "status": "success",
        "staged": True,
        "task_id": result["preview_task_id"],
        "staging_task_id": result["staging_task_id"],
        "package": package,
    }
    if result.get("nothing_to_install"):
        details = sorted({str(line.get("detail")) for line in result["task_lines"]})
        response["devices"] = result["devices"]
        response["task_lines"] = result["task_lines"]
        response["message"] = f"FortiManager found nothing to install: {'; '.join(details)}"
    elif "devices" in result:
        response["devices"] = result["devices"]
        changed = [d["name"] for d in result["devices"] if d["has_changes"]]
        response["message"] = (
            f"Install would change {', '.join(map(str, changed))}"
            if changed
            else "Install would push no changes"
        )
    else:
        response["preview"] = result["raw"]
        response["message"] = "Preview finished (unrecognized result envelope, returned raw)"
    if result.get("warning"):
        response["warning"] = result["warning"]
    return response
