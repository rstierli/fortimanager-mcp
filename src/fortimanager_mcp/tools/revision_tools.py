"""Revision-history tools for FortiManager: list, diff, and revert.

Covers three separate revision systems FortiManager keeps, each with its own
RPC surface:

- Device DB revisions (``/deployment/*``) -- a per-device history FortiManager
  keeps of that device's staged configuration. Revert only rewrites
  FortiManager's own device DB copy; the live FortiGate is untouched until a
  separate ``install_device_settings`` push.
- ADOM DB revisions (``/dvmdb/adom/{adom}/revision*``) -- ADOM-wide snapshots
  (all shared objects and packages together). Revert clones the target
  revision, which both restores the live ADOM DB and records the clone as a
  new revision -- there is no separate revert call.
- Firewall policy/object change history (``/pm/config/adom/{adom}/_objrev/
  pkg/{pkg}/firewall/policy``) -- a per-package change log. There is no
  revert call either; the documented mechanism is to capture a past change's
  snapshot and ``update`` the live policy with it.

``/deployment/*`` (device DB revisions) is published, non-deprecated API --
see ``docs/fndn/{7.6.7,8.0.0}/json_api_reference/swagger/dmserver.json`` (the
"Deployment Manager" daemon) -- not the similarly-named but internal-only,
uniformly-deprecated ``/dmworker/*`` daemon. ``/dvmdb/*/revision*`` (ADOM DB
revisions) is likewise published, in ``dvmdb.json``. ``/cache/diff/*`` and
``/pm/config/*/_objrev/*`` genuinely do not appear anywhere in the public
swagger or HTML reference (only in ``html-internal/``), so those two stay
grounded solely in the bundled How-To guide. Every RPC shape here matches the
How-To guide, sections 007 ("Device revisions"), 008 ("Policy Package
Revision" / "Firewall Policy Revision"), and 013 ("ADOM Revision") -- see
``docs/guides/FortiManager API - How-To Guide/howto_jsonrpc_api-main/``.

Device DB revision calls (``get_device_revisions``/``list_device_revisions``
and ``get_device_revision``/``diff_device_revision``) require the target
device to actually have device-DB revision history -- i.e. it has been
installed to or retrieved from at least once. Live-verified 2026-08-14
against fmg-prod-01 (FMG 7.6.7-build3737): both calls succeed against a
device with real history, but fail with a generic "Internal server error:
runtime error 0: invalid value" against a freshly added / never-installed
model device with zero revisions on record -- that is FMG's own handling of
an empty revision table, not an indicator that the API is deprecated or
removed.

Diffing is read-only everywhere. Reverting is a device-DB or ADOM-DB/package
write, never a live-device write -- see each tool's docstring for the exact
push step still required afterward.
"""

import asyncio
import difflib
import json
import logging
import time
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    ValidationError,
    check_policy_safety,
    redact_config_text_secrets,
    validate_adom,
    validate_device_name,
    validate_package_name,
    validate_policy_id,
)

logger = logging.getLogger(__name__)

#: Hard ceiling on how long a cache-diff poll loop (diff_adom_revision,
#: diff_policy_package) is allowed to run, regardless of the caller's
#: `timeout` argument -- mirrors system_tools.wait_for_task's MAX_TASK_WAIT_TIMEOUT
#: bound so a huge timeout cannot park a request indefinitely.
_MAX_DIFF_WAIT_TIMEOUT = 300


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


def _validate_revision(revision: int, *, allow_latest: bool = False) -> int:
    """Validate a device/ADOM revision number.

    Args:
        revision: Revision number to validate
        allow_latest: If True, also accept -1 (FortiManager's "give me the
            latest revision" sentinel -- used only by device DB checkout)

    Returns:
        Validated revision number

    Raises:
        ValidationError: If revision is not a valid revision number
    """
    if not isinstance(revision, int):
        raise ValidationError(f"revision must be an integer, got {revision!r}")
    if allow_latest and revision == -1:
        return revision
    if revision < 1:
        suffix = " (or -1 for the latest revision)" if allow_latest else ""
        raise ValidationError(f"revision must be a positive integer{suffix}, got {revision}")
    return revision


def _prepare_policy_snapshot(config: str | dict[str, Any]) -> dict[str, Any]:
    """Turn a list_policy_revisions "config" entry into a writable payload.

    ``config`` arrives from FortiManager as a JSON-encoded string (see the
    How-To guide's change-log examples), so a string is decoded here as a
    convenience -- an already-decoded dict is accepted unchanged. ``oid`` is
    always stripped: the guide warns that including it makes FortiManager
    reject the write with "The data is invalid for selected url".

    Raises:
        ValidationError: If config is not a JSON object, or has no policyid
    """
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except json.JSONDecodeError as e:
            raise ValidationError(f"config is not valid JSON: {e}") from e
    if not isinstance(config, dict):
        raise ValidationError(
            "config must be a JSON object (dict), or a JSON-encoded string of one"
        )
    snapshot = {k: v for k, v in config.items() if k != "oid"}
    if "policyid" not in snapshot:
        raise ValidationError("config must include 'policyid' (which policy this snapshot reverts)")
    return snapshot


def _snapshot_action_for_safety_check(action: Any) -> str | None:
    """Normalize a policy snapshot's raw ``action`` field for the gate.

    A real change-log snapshot encodes action as FMG's internal integer,
    not the string a caller sends when creating/updating a policy --
    live-verified against fmg-prod-01 (a real accept policy on myfw01
    returned action=1; a test policy created with action="deny" and read
    back returned action=0). Fed straight into check_policy_safety, which
    calls ``.lower()`` on it, this crashed with 'int' object has no
    attribute 'lower' (PR #65 review, Christian) -- the gate had never
    been exercised against a real snapshot's actual shape.

    Only whether action is "accept" matters to the permissiveness check,
    so any int other than 1 normalizes to "deny" as a safe placeholder --
    which specific non-accept action it really was (ipsec, ssl-vpn, ...)
    doesn't change the gate's answer.
    """
    if isinstance(action, str):
        return action
    if isinstance(action, int):
        return "accept" if action == 1 else "deny"
    return None


def _snapshot_negate_for_safety_check(value: Any) -> bool:
    """Normalize a policy snapshot's raw ``*-negate`` field for the gate.

    Same live-verified encoding gap as action above: a real snapshot's
    negate fields are FMG's internal 0/1 integers (confirmed via
    srcaddr-negate on a test policy created with srcaddr_negate=True),
    not the "enable"/"disable" string a caller sends when writing a new
    policy. An int was previously compared with `== "enable"`, which is
    always False -- negation on a reverted policy was invisible to the
    gate regardless of its real value.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if isinstance(value, str):
        return value == "enable"
    return False


async def _run_cache_diff(
    client: FortiManagerClient,
    *,
    dst: str,
    src: str,
    timeout: int,
    poll_interval: int,
    pkg: str | None = None,
) -> dict[str, Any]:
    """Run one full cache/diff/start -> poll summary -> end cycle.

    Mirrors system_tools.wait_for_task's bounded-poll shape: the whole wait
    is deadline-bound, poll_interval is floored/capped, and the diff job is
    always closed with cache_diff_end -- including on timeout or error -- so
    a failed poll does not leak a server-side cache entry.

    Returns:
        The diff job's summary payload (``{"percent": 100, "obj": {...},
        ["pkg": {...}]}``) once ``percent`` reaches 100.

    Raises:
        RuntimeError: cache_diff_start did not return a token
        TimeoutError: the diff did not reach 100% within `timeout` seconds
    """
    timeout = min(max(1, timeout), _MAX_DIFF_WAIT_TIMEOUT)
    poll_interval = max(1, min(poll_interval, 30))

    start = await client.cache_diff_start(dst=dst, src=src)
    token = start.get("token") if isinstance(start, dict) else None
    if not token:
        raise RuntimeError(f"cache_diff_start did not return a token (dst={dst}, src={src})")

    try:
        loop_start = asyncio.get_event_loop().time()
        while True:
            summary = await client.cache_diff_get_summary(token, pkg=pkg)
            percent = summary.get("percent") if isinstance(summary, dict) else None
            if percent == 100:
                return summary
            if asyncio.get_event_loop().time() - loop_start > timeout:
                raise TimeoutError(
                    f"cache diff of {src} against {dst} did not complete within "
                    f"{timeout}s (last percent: {percent})"
                )
            await asyncio.sleep(poll_interval)
    finally:
        try:
            await client.cache_diff_end(token)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup, never masks the real error
            logger.warning(f"cache_diff_end failed for dst={dst} src={src}: {exc}")


# =============================================================================
# Device DB Revisions
# =============================================================================


@mcp.tool()
async def list_device_revisions(device: str) -> dict[str, Any]:
    """List the device DB revision history for a managed device.

    Every install, auto-update, retrieve, or revert creates a new device DB
    revision. ``base_ver`` is the revision FortiManager currently considers
    in sync with the real device configuration.

    Note:
        Requires the device to have at least one device DB revision on
        record (i.e. it has been installed to or retrieved from at least
        once). A freshly added device that has never gone through either
        will make FortiManager return a generic internal-server error here
        rather than an empty list -- that is FMG's own handling of an empty
        revision table, not a sign this tool or the underlying API is broken.

    Args:
        device: Managed device name

    Returns:
        dict: status, device, base_ver, count, revisions (each entry has
        revision, comments, instime/instusr, modtime/modusr, status, tag)

    Example:
        >>> result = await list_device_revisions("hub2")
        >>> for rev in result["revisions"]:
        ...     print(rev["revision"], rev["comments"])
    """
    try:
        device = validate_device_name(device)
        client = _get_client()
        data = await client.get_device_revisions(device=device)
        revisions = data.get("revinfo", []) if isinstance(data, dict) else []
        return {
            "status": "success",
            "device": device,
            "base_ver": data.get("base_ver") if isinstance(data, dict) else None,
            "count": len(revisions),
            "revisions": revisions,
        }
    except Exception as e:
        logger.error(f"Failed to list device revisions for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_device_revision(device: str, revision: int = -1) -> dict[str, Any]:
    """Check out one device DB revision's stored configuration text.

    Note:
        Requires the device to have at least one device DB revision on
        record -- see the note on list_device_revisions.

    Args:
        device: Managed device name
        revision: Revision number (see list_device_revisions), or -1
            (default) for the latest revision

    Returns:
        dict: status, device, revision, content (device DB config text with
        known secret-bearing directives redacted -- see
        redact_config_text_secrets. Structured dict-field masking elsewhere
        in this codebase can't see inside this multi-line CLI text, so this
        applies a separate directive-name-based redaction.)

    Example:
        >>> result = await get_device_revision("hub2", revision=8)
        >>> print(result["content"])
    """
    try:
        device = validate_device_name(device)
        revision = _validate_revision(revision, allow_latest=True)
        client = _get_client()
        data = await client.get_device_revision_content(device=device, revision=revision)
        raw_content = data.get("content") if isinstance(data, dict) else None
        return {
            "status": "success",
            "device": device,
            "revision": data.get("revision", revision) if isinstance(data, dict) else revision,
            "content": redact_config_text_secrets(raw_content) if raw_content else raw_content,
        }
    except Exception as e:
        logger.error(f"Failed to check out revision {revision} for device {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def diff_device_revision(device: str, revision: int) -> dict[str, Any]:
    """Diff a past device DB revision against the CURRENT device DB.

    FortiManager has no native diff endpoint for device DB revisions (unlike
    ADOM DB revisions -- see diff_adom_revision). This instead fetches both
    the past revision's config text (checkout) and the current device DB
    export, then computes a client-side unified line diff. Read-only.

    Note:
        The checkout half of this requires the device to have at least one
        device DB revision on record -- see the note on
        list_device_revisions.

    Args:
        device: Managed device name
        revision: Revision number to compare against current (see
            list_device_revisions)

    Returns:
        dict: status, device, revision, changed (bool), diff (unified diff
        text, empty string if unchanged; both sides are redacted of known
        secret-bearing directives before diffing -- see
        redact_config_text_secrets -- so a line whose only change is its
        secret value will not show as changed)

    Example:
        >>> result = await diff_device_revision("hub2", revision=7)
        >>> if result["changed"]:
        ...     print(result["diff"])
    """
    try:
        device = validate_device_name(device)
        revision = _validate_revision(revision)
        client = _get_client()
        past = await client.get_device_revision_content(device=device, revision=revision)
        current = await client.get_device_current_config(device=device)
        past_content = past.get("content") or "" if isinstance(past, dict) else ""
        current_content = current.get("content") or "" if isinstance(current, dict) else ""
        # Redact before diffing, not after: the diff must never surface a raw
        # secret value even transiently. Since both sides are redacted with
        # the same directive-name-preserving placeholder, a line whose only
        # change is its secret VALUE will no longer show as changed -- an
        # accepted tradeoff (never leak the value) over a false negative on
        # secret-only changes (the directive name itself still diffs if it
        # was added/removed/reordered).
        past_content = redact_config_text_secrets(past_content)
        current_content = redact_config_text_secrets(current_content)
        diff_lines = list(
            difflib.unified_diff(
                past_content.splitlines(keepends=True),
                current_content.splitlines(keepends=True),
                fromfile=f"revision {revision}",
                tofile="current",
            )
        )
        return {
            "status": "success",
            "device": device,
            "revision": revision,
            "changed": bool(diff_lines),
            "diff": "".join(diff_lines),
        }
    except Exception as e:
        logger.error(f"Failed to diff device {device} revision {revision} against current: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def revert_device_revision(device: str, revision: int) -> dict[str, Any]:
    """Revert a device's device DB to a past revision.

    This rewrites FortiManager's stored device DB copy for `device` only --
    the live FortiGate is not touched. Push the reverted device DB to the
    device the same way any other device DB change is pushed: preview_install
    then install_device_settings.

    Note:
        Requires the device to have at least one device DB revision on
        record -- see the note on list_device_revisions. Not live-tested
        (reverting a device's config is a real, consequential write); the
        request shape matches the FNDN-documented, non-deprecated
        ``/deployment/revert`` command exactly (see client.py), which the
        sibling get/checkout calls confirm works correctly on this FMG
        generation for devices that have revision history.

    Args:
        device: Managed device name
        revision: Revision number to revert to (see list_device_revisions)

    Returns:
        dict: status, device, revision, message
    """
    try:
        device = validate_device_name(device)
        revision = _validate_revision(revision)
        client = _get_client()
        await client.revert_device_revision(device=device, revision=revision)
        return {
            "status": "success",
            "device": device,
            "revision": revision,
            "message": f"Device DB of '{device}' reverted to revision {revision}. "
            "This is a device-DB-only change -- push it to the device with "
            "preview_install + install_device_settings.",
        }
    except Exception as e:
        logger.error(f"Failed to revert device {device} to revision {revision}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# ADOM DB Revisions
# =============================================================================


@mcp.tool()
async def list_adom_revisions(
    adom: str,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List the ADOM DB revision history for an ADOM.

    Args:
        adom: ADOM name
        fields: Specific fields to return (optional, returns all if omitted)

    Returns:
        dict: status, adom, count, revisions (each entry has version,
        name, desc, created_by, created_time, locked)

    Example:
        >>> result = await list_adom_revisions("demo")
        >>> for rev in result["revisions"]:
        ...     print(rev["version"], rev["desc"])
    """
    try:
        adom = validate_adom(adom)
        client = _get_client()
        revisions = await client.list_adom_revisions(adom, fields=fields)
        return {
            "status": "success",
            "adom": adom,
            "count": len(revisions),
            "revisions": revisions,
        }
    except Exception as e:
        logger.error(f"Failed to list ADOM revisions for {adom}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def get_adom_revision(adom: str, revision: int) -> dict[str, Any]:
    """Get one ADOM DB revision's metadata.

    Args:
        adom: ADOM name
        revision: Revision number (the `version` field from
            list_adom_revisions)

    Returns:
        dict: status, adom, revision (name, desc, created_by, created_time,
        locked, version)
    """
    try:
        adom = validate_adom(adom)
        revision = _validate_revision(revision)
        client = _get_client()
        data = await client.get_adom_revision(adom, revision)
        return {"status": "success", "adom": adom, "revision": data}
    except Exception as e:
        logger.error(f"Failed to get ADOM {adom} revision {revision}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def diff_adom_revision(
    adom: str,
    revision: int,
    timeout: int = 60,
    poll_interval: int = 2,
) -> dict[str, Any]:
    """Diff a past ADOM DB revision against the CURRENT live ADOM.

    Starts a FortiManager cache-diff job (the revision as source, the live
    ADOM as destination), polls it to completion, and returns the summary.
    Read-only -- nothing is written to the ADOM.

    Args:
        adom: ADOM name
        revision: Revision number to compare against current (see
            list_adom_revisions)
        timeout: Maximum wait for the diff job in seconds (default 60,
            capped at 300)
        poll_interval: Seconds between poll attempts (default 2, capped at 30)

    Returns:
        dict: status, adom, revision, obj (object-level change summary,
        keyed by category), pkg (per-package change summary)
    """
    try:
        adom = validate_adom(adom)
        revision = _validate_revision(revision)
        client = _get_client()
        summary = await _run_cache_diff(
            client,
            dst=f"adom/{adom}",
            src=f"adom/{adom}/revision/{revision}",
            timeout=timeout,
            poll_interval=poll_interval,
        )
        return {
            "status": "success",
            "adom": adom,
            "revision": revision,
            "obj": summary.get("obj"),
            "pkg": summary.get("pkg"),
        }
    except Exception as e:
        logger.error(f"Failed to diff ADOM {adom} revision {revision} against current: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def revert_adom_revision(
    adom: str,
    revision: int,
    name: str | None = None,
    desc: str | None = None,
    locked: bool = False,
) -> dict[str, Any]:
    """Revert the live ADOM DB to a past revision.

    FortiManager has no dedicated revert-ADOM-revision call. The documented
    mechanism (How-To 013, "How to revert an ADOM Revision?") is to `clone`
    the target past revision: this both restores the live ADOM DB to that
    historical state and records the clone itself as a brand-new revision.
    This writes to the ADOM DB (a pure ADOM object, not a device) -- push any
    restored policy/object changes to devices separately with preview_install
    + install_package/install_device_settings as needed.

    Args:
        adom: ADOM name
        revision: Revision number to revert to (the `version` field from
            list_adom_revisions)
        name: Name for the newly-created revision (default:
            "Restored-rev_{revision}")
        desc: Description for the newly-created revision (default:
            "Revert of ADOM Revision #{revision}")
        locked: Protect the newly-created revision from deletion (default
            False)

    Returns:
        dict: status, adom, reverted_from, new_revision, message
    """
    try:
        adom = validate_adom(adom)
        revision = _validate_revision(revision)
        client = _get_client()
        data: dict[str, Any] = {
            "created_time": int(time.time()),
            "desc": desc or f"Revert of ADOM Revision #{revision}",
            "locked": 1 if locked else 0,
            "name": name or f"Restored-rev_{revision}",
        }
        result = await client.clone_adom_revision(adom, revision, data)
        new_version = result.get("version") if isinstance(result, dict) else None
        return {
            "status": "success",
            "adom": adom,
            "reverted_from": revision,
            "new_revision": new_version,
            "message": f"ADOM '{adom}' reverted to revision {revision}, recorded as new "
            f"revision {new_version}.",
        }
    except Exception as e:
        logger.error(f"Failed to revert ADOM {adom} to revision {revision}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


# =============================================================================
# Firewall Policy / Object Revisions (package-level, ADOM)
# =============================================================================


@mcp.tool()
async def list_policy_revisions(
    adom: str,
    package: str,
    policyid: int | None = None,
) -> dict[str, Any]:
    """List the change log for a policy package's firewall policies.

    Args:
        adom: ADOM name
        package: Policy package name
        policyid: Limit to one policy's change history (optional; all
            policies in the package if omitted)

    Returns:
        dict: status, adom, package, policyid, count, changes -- each entry
        has act (1=created, 2=deleted, 3=modified), key (the policyid),
        config (a JSON-encoded policy snapshot at that change -- pass
        straight to revert_firewall_policy), timestamp, user

    Example:
        >>> result = await list_policy_revisions("demo", "ppkg_001", policyid=14)
        >>> first_change = result["changes"][0]
        >>> await revert_firewall_policy("demo", "ppkg_001", first_change["config"])
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        if policyid is not None:
            policyid = validate_policy_id(policyid)
        client = _get_client()
        changes = await client.list_policy_revisions(adom, package, policyid=policyid)
        return {
            "status": "success",
            "adom": adom,
            "package": package,
            "policyid": policyid,
            "count": len(changes),
            "changes": changes,
        }
    except Exception as e:
        logger.error(f"Failed to list policy revisions for {adom}/{package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def diff_policy_package(
    adom: str,
    package: str,
    revision: int,
    timeout: int = 60,
    poll_interval: int = 2,
) -> dict[str, Any]:
    """Diff a policy package's objects at a past ADOM revision against its
    CURRENT live state.

    Package-level changes are tracked as part of the ADOM DB revision
    history, not separately, so this reuses the same cache-diff job as
    diff_adom_revision, scoped to one package's summary view. Read-only.

    Args:
        adom: ADOM name
        package: Policy package name
        revision: ADOM revision number to compare against current (see
            list_adom_revisions)
        timeout: Maximum wait for the diff job in seconds (default 60,
            capped at 300)
        poll_interval: Seconds between poll attempts (default 2, capped at 30)

    Returns:
        dict: status, adom, package, revision, summary (change summary for
        this package only, keyed by category -- e.g. 181 = firewall policy)
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        revision = _validate_revision(revision)
        client = _get_client()
        summary = await _run_cache_diff(
            client,
            dst=f"adom/{adom}",
            src=f"adom/{adom}/revision/{revision}",
            timeout=timeout,
            poll_interval=poll_interval,
            pkg=package,
        )
        return {
            "status": "success",
            "adom": adom,
            "package": package,
            "revision": revision,
            "summary": summary.get("obj"),
        }
    except Exception as e:
        logger.error(
            f"Failed to diff package {package} in ADOM {adom} at revision {revision} "
            f"against current: {e}"
        )
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


@mcp.tool()
async def revert_firewall_policy(
    adom: str,
    package: str,
    config: str | dict[str, Any],
    revision_note: str | None = None,
) -> dict[str, Any]:
    """Restore a firewall policy to a past change-log snapshot.

    FortiManager has no dedicated revert-firewall-policy endpoint. The
    documented mechanism (How-To 008, "How to revert a firewall policy from
    a past changes?") is to capture a past change's `config` snapshot from
    list_policy_revisions and `update` the live policy with it -- this tool
    does exactly that. This writes a policy OBJECT inside the ADOM's policy
    package; it does not touch any device. Push the reverted policy to
    devices the same way any other policy edit is pushed: preview_install
    then install_package.

    Args:
        adom: ADOM name
        package: Policy package name
        config: A snapshot from list_policy_revisions' "config" field --
            either the JSON string as returned, or the already-decoded dict.
            Must include "policyid". Any "oid" key is stripped automatically
            (FortiManager rejects the write if it is present).
        revision_note: Optional note recorded against this change

    Returns:
        dict: status, adom, package, policyid, message

    Example:
        >>> revisions = await list_policy_revisions("demo", "ppkg_001", policyid=14)
        >>> await revert_firewall_policy(
        ...     "demo", "ppkg_001", revisions["changes"][0]["config"],
        ...     revision_note="Revert from create time",
        ... )
    """
    try:
        adom = validate_adom(adom)
        package = validate_package_name(package)
        snapshot = _prepare_policy_snapshot(config)
        policyid = validate_policy_id(snapshot["policyid"])

        # A revert writes an arbitrary caller-supplied policy payload, same
        # as create/update -- it must go through the same permissiveness
        # gate or it's an unguarded general-purpose policy-write path.
        safety_warning = None
        safety_result = check_policy_safety(
            snapshot.get("srcaddr"),
            snapshot.get("dstaddr"),
            snapshot.get("service"),
            _snapshot_action_for_safety_check(snapshot.get("action")),
            srcaddr_negate=_snapshot_negate_for_safety_check(snapshot.get("srcaddr-negate")),
            dstaddr_negate=_snapshot_negate_for_safety_check(snapshot.get("dstaddr-negate")),
            service_negate=_snapshot_negate_for_safety_check(snapshot.get("service-negate")),
        )
        if safety_result:
            if safety_result.get("status") == "error":
                return safety_result
            safety_warning = safety_result.get("_safety_warning")

        client = _get_client()
        await client.revert_firewall_policy_snapshot(
            adom, package, snapshot, revision_note=revision_note
        )
        result = {
            "status": "success",
            "adom": adom,
            "package": package,
            "policyid": policyid,
            "message": f"Policy {policyid} in package '{package}' reverted to the supplied "
            "snapshot. Push to devices with preview_install + install_package.",
        }
        if safety_warning:
            result["safety_warning"] = safety_warning
        return result
    except Exception as e:
        logger.error(f"Failed to revert firewall policy in {adom}/{package}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
