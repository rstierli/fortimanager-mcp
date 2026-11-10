"""Policy-package sync checks: does a device run the package FortiManager has for it?

FortiManager flags a device's package as "out of sync" without saying what
differs. These tools answer that from data FortiManager already holds:

- ``get_package_install_status`` -- the per-device status the GUI shows
  (``/pm/config/adom/{adom}/_package/status``): which package is assigned
  to which device/VDOM, and whether it is installed, modified or out of
  sync.
- ``check_device_policy_sync`` -- a firewall-policy comparison between the
  package assigned to a device and either or both of:

  * the device's latest device DB **revision** -- the configuration last
    retrieved from or installed to the device, i.e. what it actually runs
    (CLI text, parsed here);
  * the **device DB** itself (``/pm/config/device/{dev}/vdom/{vdom}/
    firewall/policy``) -- FortiManager's current working copy, which also
    holds changes staged in FortiManager but not yet installed.

  With both, the device DB is also compared with the revision: a
  difference there is something staged in FortiManager and not installed.
  Policies are matched by UUID, which FortiManager carries from the
  package to the device, and fall back to policy id.

Both are read-only. Neither stages, previews nor installs anything: use
``preview_install`` to see the exact CLI an install would push.

Package policies are read with ``verbose`` so enums come back as the same
names FortiOS writes in its config (``action: "accept"`` rather than
``1``), which is what makes a field comparison against config text
possible. Live-verified against FMG 8.0.2-build0198 with FortiOS 7.4.12
devices.
"""

import logging
import re
import shlex
from typing import Any

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.responses import error_response
from fortimanager_mcp.utils.validation import (
    Id,
    ValidationError,
    validate_adom,
    validate_device_name,
    validate_object_name,
    validate_package_name,
)

logger = logging.getLogger(__name__)

#: Policy fields compared between package and device. Chosen for what
#: decides which traffic a policy matches and what it does with it; hit
#: counters, labels, comments and internal bookkeeping are left out.
_COMPARED_FIELDS = (
    "name",
    "action",
    "status",
    "srcintf",
    "dstintf",
    "srcaddr",
    "dstaddr",
    "srcaddr6",
    "dstaddr6",
    "service",
    "schedule",
    "internet-service",
    "internet-service-name",
    "users",
    "groups",
    "nat",
    "ippool",
    "poolname",
    "utm-status",
    "profile-type",
    "profile-group",
    "av-profile",
    "webfilter-profile",
    "dnsfilter-profile",
    "application-list",
    "ips-sensor",
    "ssl-ssh-profile",
    "logtraffic",
)

#: FortiOS omits a field from its config when it holds the default, while a
#: package read returns every field. An absent device field is read as this.
_FORTIOS_DEFAULTS: dict[str, list[str]] = {
    "action": ["deny"],
    "status": ["enable"],
    "nat": ["disable"],
    "ippool": ["disable"],
    "internet-service": ["disable"],
    "utm-status": ["disable"],
    "profile-type": ["single"],
    "logtraffic": ["utm"],
    "ssl-ssh-profile": ["no-inspection"],
}

_SINGLE_PROFILE_FIELDS = (
    "av-profile",
    "webfilter-profile",
    "dnsfilter-profile",
    "application-list",
    "ips-sensor",
)

#: Fields whose names are per-device mapped in a package (normalized
#: interfaces, dynamic address objects): a difference there may be a
#: mapping, not drift.
_MAPPED_FIELDS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6")


def _get_client() -> FortiManagerClient:
    """Get the FortiManager client instance."""
    client = get_fmg_client()
    if not client:
        raise RuntimeError("FortiManager client not initialized")
    return client


# =============================================================================
# Device config text -> firewall policy table
# =============================================================================


def _logical_lines(text: str) -> list[str]:
    """Split config text into lines, joining a quoted value that spans lines.

    A ``set comments "..."`` value may contain newlines; read line by line,
    its continuation lines would be taken for directives of their own.
    """
    out: list[str] = []
    pending: str | None = None
    for raw in text.splitlines():
        line = raw if pending is None else pending + "\n" + raw
        if _open_quote(line):
            pending = line
            continue
        pending = None
        out.append(line.strip())
    if pending is not None:
        out.append(pending.strip())
    return out


def _open_quote(line: str) -> bool:
    """True when ``line`` ends inside a double-quoted string."""
    inside = False
    escaped = False
    for ch in line:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            inside = not inside
    return inside


def _split_values(rest: str) -> list[str]:
    """Tokenize the value part of a ``set`` line (quoted, space-separated)."""
    try:
        return shlex.split(rest, posix=True)
    except ValueError:
        return rest.split()


def parse_firewall_policies(config: str, vdom: str = "root") -> list[dict[str, Any]]:
    """Extract ``config firewall policy`` from FortiOS config text, in order.

    Handles both layouts: a single-VDOM device has the table at the top
    level; a multi-VDOM device has it under ``config vdom`` / ``edit
    <vdom>``. Only directives directly under each ``edit`` are kept --
    nested ``config`` blocks inside a policy are skipped.

    Returns:
        [{"policyid": <int>, "<field>": [<str>, ...], ...}] in config order.
    """
    targets = (["firewall policy"], ["vdom", vdom, "firewall policy"])
    stack: list[str] = []
    policies: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in _logical_lines(config):
        if not line or line.startswith("#"):
            continue
        keyword, _, rest = line.partition(" ")
        if keyword == "config":
            stack.append(rest.strip())
        elif keyword == "edit":
            key = _split_values(rest)
            name = key[0] if key else rest.strip()
            stack.append(name)
            if stack[:-1] in targets:
                try:
                    current = {"policyid": int(name)}
                except ValueError:
                    current = None
                if current is not None:
                    policies.append(current)
        elif keyword in ("next", "end"):
            if stack:
                popped_policy = stack[:-1] in targets and keyword == "next"
                stack.pop()
                if popped_policy:
                    current = None
        elif keyword in ("set", "unset") and current is not None and stack[:-1] in targets:
            field, _, values = rest.partition(" ")
            if keyword == "set":
                current[field] = _split_values(values)
            else:
                current.pop(field, None)
    return policies


# =============================================================================
# Package side
# =============================================================================


def _as_list(value: Any) -> list[str]:
    """Normalize a package or device field value to a sorted list of strings."""
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return sorted(str(v) for v in value if v is not None and v != "")
    return [str(value)]


def _targets_device(
    scope: Any, device: str, vdom: str, group_members: dict[str, list[dict[str, Any]]]
) -> bool:
    """Does an install-on scope include device/vdom? No scope means everyone."""
    if not scope:
        return True
    seen: set[str] = set()
    todo = list(scope) if isinstance(scope, list) else [scope]
    while todo:
        member = todo.pop()
        if not isinstance(member, dict):
            continue
        name = member.get("name")
        if "vdom" in member:
            if name == device and member.get("vdom") in (vdom, None, ""):
                return True
        elif isinstance(name, str) and name not in seen:
            seen.add(name)
            if name in group_members:
                todo.extend(group_members[name])
            elif name == device:
                return True
    return False


async def _group_members(client: FortiManagerClient, adom: str) -> dict[str, list[dict[str, Any]]]:
    """Device-group name -> its direct members (devices carry a vdom, groups don't)."""
    groups = await client.get(
        f"/dvmdb/adom/{adom}/group", fields=["name"], option=["object member"]
    )
    out: dict[str, list[dict[str, Any]]] = {}
    for group in groups if isinstance(groups, list) else [groups] if groups else []:
        if isinstance(group, dict) and isinstance(group.get("name"), str):
            out[group["name"]] = group.get("object member") or []
    return out


async def _package_policies(
    client: FortiManagerClient, adom: str, package: str
) -> list[dict[str, Any]]:
    """The package's firewall policies in order, policy blocks expanded in place."""
    url = f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy"
    entries = await client.get_verbose(url, option=["scope member"])
    policies: list[dict[str, Any]] = []
    for entry in entries if isinstance(entries, list) else [entries] if entries else []:
        block = entry.get("_policy_block") if isinstance(entry, dict) else None
        if not block:
            policies.append(entry)
            continue
        # The block name comes from FortiManager, not the caller, but it is
        # still interpolated into a URL: hold it to the same rule as any
        # object name before it gets there.
        block = validate_object_name(str(block), "policy block")
        members = await client.get_verbose(
            f"/pm/config/adom/{adom}/pblock/{block}/firewall/policy", option=["scope member"]
        )
        for member in members if isinstance(members, list) else [members] if members else []:
            if isinstance(member, dict):
                # A block member is only installed where the block's own entry is.
                member = {**member, "_policy_block": block}
                if entry.get("scope member") and not member.get("scope member"):
                    member["scope member"] = entry["scope member"]
                policies.append(member)
    return policies


_VARIABLE = re.compile(r"\$\(([A-Za-z0-9_.-]+)\)")


def _in_scope(scope: Any, device: str, vdom: str) -> bool:
    """Does a dynamic_mapping ``_scope`` name this device/VDOM ("global" counts)?"""
    return any(
        isinstance(m, dict) and m.get("name") == device and m.get("vdom") in (vdom, "global")
        for m in (scope if isinstance(scope, list) else [])
    )


def _rows(result: Any) -> list[dict[str, Any]]:
    rows = result if isinstance(result, list) else [result] if result else []
    return [r for r in rows if isinstance(r, dict)]


async def _interface_map(
    client: FortiManagerClient,
    adom: str,
    device: str,
    vdom: str,
    policies: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Resolve the package's normalized interfaces to this device's interfaces.

    A package names normalized interfaces; the device has real ones. The
    mapping is, in FortiManager's order of precedence: a per-device
    ``dynamic_mapping``, else a ``platform_mapping`` entry for the device's
    model (``intf-zone``), else the default mapping (``defmap-intf``).
    ``$(variable)`` references in the last two are resolved through the
    device's metadata variables. Live example: the normalized ``port3``
    has 68 platform entries, none for FortiGate-VM64-KVM, so on those
    devices it falls through to its default ``$(vl_lan)``, which is
    ``port3`` on branch1 and ``vl_lan`` on branch3. Names without a mapping
    are returned as they are.
    """
    names = sorted(
        {n for p in policies for f in ("srcintf", "dstintf") for n in _as_list(p.get(f))}
    )
    if not names:
        return {}
    interfaces = _rows(
        await client.get(
            f"/pm/config/adom/{adom}/obj/dynamic/interface",
            loadsub=1,
            filter=["name", "in", *names],
        )
    )
    platform: str | None = None
    if any(intf.get("platform_mapping") for intf in interfaces):
        record = await client.get(f"/dvmdb/adom/{adom}/device/{device}", fields=["platform_str"])
        if isinstance(record, dict) and isinstance(record.get("platform_str"), str):
            platform = record["platform_str"]

    mapping: dict[str, list[str]] = {}
    templates: dict[str, str] = {}
    for intf in interfaces:
        name = intf.get("name")
        if not isinstance(name, str):
            continue
        for dm in intf.get("dynamic_mapping") or []:
            if isinstance(dm, dict) and _in_scope(dm.get("_scope"), device, vdom):
                mapping[name] = _as_list(dm.get("local-intf"))
                break
        else:
            for pm in intf.get("platform_mapping") or []:
                if isinstance(pm, dict) and platform is not None and pm.get("name") == platform:
                    zone = _as_list(pm.get("intf-zone"))
                    if zone:
                        templates[name] = zone[0]
                    break
            else:
                default = intf.get("defmap-intf")
                if intf.get("default-mapping") in (1, "enable") and isinstance(default, str):
                    templates[name] = default

    variables = sorted({v for t in templates.values() for v in _VARIABLE.findall(t)})
    values: dict[str, str] = {}
    if variables:
        for var in _rows(
            await client.get(
                f"/pm/config/adom/{adom}/obj/fmg/variable",
                loadsub=1,
                filter=["name", "in", *variables],
            )
        ):
            value = var.get("value")
            for dm in var.get("dynamic_mapping") or []:
                if isinstance(dm, dict) and _in_scope(dm.get("_scope"), device, vdom):
                    value = dm.get("value")
                    break
            if isinstance(var.get("name"), str) and isinstance(value, str):
                values[var["name"]] = value
    for name, template in templates.items():
        resolved = _VARIABLE.sub(lambda m: values.get(m.group(1), m.group(0)), template)
        mapping[name] = [resolved]
    return mapping


def _map_interfaces(
    policies: list[dict[str, Any]], mapping: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Package policies with srcintf/dstintf translated to device interface names."""
    if not mapping:
        return policies
    out = []
    for policy in policies:
        mapped = dict(policy)
        for field in ("srcintf", "dstintf"):
            names = _as_list(policy.get(field))
            if names:
                mapped[field] = [m for n in names for m in mapping.get(n, [n])]
        out.append(mapped)
    return out


# =============================================================================
# Comparison
# =============================================================================


def _relevant_fields(pkg_policy: dict[str, Any]) -> list[str]:
    """Compared fields that matter for this policy's configuration."""
    utm = _as_list(pkg_policy.get("utm-status")) or _FORTIOS_DEFAULTS["utm-status"]
    ptype = _as_list(pkg_policy.get("profile-type")) or _FORTIOS_DEFAULTS["profile-type"]
    fields = []
    for field in _COMPARED_FIELDS:
        if utm == ["disable"] and (field in _SINGLE_PROFILE_FIELDS or field == "profile-group"):
            continue
        if ptype == ["group"] and field in _SINGLE_PROFILE_FIELDS:
            continue
        if ptype != ["group"] and field == "profile-group":
            continue
        fields.append(field)
    return fields


def _field_diffs(
    expected: dict[str, Any], actual: dict[str, Any], labels: tuple[str, str]
) -> dict[str, Any]:
    diffs: dict[str, Any] = {}
    for field in _relevant_fields(expected):
        default = _FORTIOS_DEFAULTS.get(field, [])
        # FortiOS omits a field holding its default; FortiManager may return
        # it empty. Either way the effective value is the default.
        want = _as_list(expected.get(field)) or default
        have = _as_list(actual.get(field)) or default
        if want != have:
            diffs[field] = {labels[0]: want, labels[1]: have}
    return diffs


def _label(policy: dict[str, Any]) -> dict[str, Any]:
    name = policy.get("name")
    label: dict[str, Any] = {"policyid": policy.get("policyid")}
    if name:
        label["name"] = name[0] if isinstance(name, list) and len(name) == 1 else name
    if policy.get("_policy_block"):
        label["policy_block"] = policy["_policy_block"]
    return label


def _uuid(policy: dict[str, Any]) -> str | None:
    value = policy.get("uuid")
    if isinstance(value, list):
        value = value[0] if value else None
    return value if isinstance(value, str) and value else None


def compare_policies(
    expected: list[dict[str, Any]],
    actual: list[dict[str, Any]],
    labels: tuple[str, str] = ("package", "device"),
) -> dict[str, Any]:
    """Match two policy tables (UUID, then policy id) and diff them.

    ``labels`` name the two sides in the result: ``only_in_<label>`` lists
    and the per-field values under ``differences``.
    """
    want_label, have_label = labels
    by_uuid = {u: p for p in actual if (u := _uuid(p))}
    by_id = {p["policyid"]: p for p in actual}
    matched: set[int] = set()
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    only_expected: list[dict[str, Any]] = []
    for want in expected:
        uuid = _uuid(want)
        have = by_uuid.get(uuid) if uuid else None
        if have is None:
            candidate = by_id.get(want.get("policyid"))
            # A same-id policy with a different UUID is another policy.
            if candidate is not None and (not uuid or not _uuid(candidate)):
                have = candidate
        if have is None or id(have) in matched:
            only_expected.append(_label(want))
            continue
        matched.add(id(have))
        pairs.append((want, have))

    modified = []
    for want, have in pairs:
        diffs = _field_diffs(want, have, labels)
        if diffs:
            entry = _label(want)
            if have["policyid"] != want.get("policyid"):
                entry[f"{have_label}_policyid"] = have["policyid"]
            entry["differences"] = diffs
            if any(f in _MAPPED_FIELDS for f in diffs):
                entry["note"] = (
                    "interfaces are compared after FortiManager's interface mapping "
                    "(per-device, per-platform, then default); address objects are "
                    "compared by name, not by their per-device values"
                )
            modified.append(entry)

    only_actual = [_label(p) for p in actual if id(p) not in matched]

    # Order matters on a firewall: the first matching policy wins. Compare
    # the sequence of the policies both sides have.
    want_order = [have["policyid"] for _, have in pairs]
    have_order = [p["policyid"] for p in actual if id(p) in matched]
    order_matches = want_order == have_order
    result: dict[str, Any] = {
        "in_sync": not only_expected and not only_actual and not modified and order_matches,
        "summary": {
            f"{want_label}_policies": len(expected),
            f"{have_label}_policies": len(actual),
            "matched": len(pairs),
            f"only_in_{want_label}": len(only_expected),
            f"only_in_{have_label}": len(only_actual),
            "modified": len(modified),
        },
        f"only_in_{want_label}": only_expected,
        f"only_in_{have_label}": only_actual,
        "modified": modified,
        "order_matches": order_matches,
    }
    if not order_matches:
        result[f"{want_label}_order"] = want_order
        result[f"{have_label}_order"] = have_order
    return result


# =============================================================================
# Tools
# =============================================================================


@mcp.tool()
async def get_package_install_status(adom: str, device: str | None = None) -> dict[str, Any]:
    """Show which policy package is assigned to each device and whether it is installed.

    The same status the GUI shows per device in Policy & Objects: a package
    is "installed" when the device runs it, "modified" when the package
    changed since the last install, and "out of sync" when the device and
    FortiManager disagree. Use check_device_policy_sync to see which
    policies differ.

    Args:
        adom: ADOM name
        device: Only this device (optional)

    Returns:
        dict: status, count, packages: [{"device", "vdom", "package",
        "install_status"}]
    """
    try:
        adom = validate_adom(adom)
        if device is not None:
            device = validate_device_name(device)
        client = _get_client()
        rows = await client.get_package_status(adom)
        packages = [
            {
                "device": row.get("dev"),
                "vdom": row.get("vdom"),
                "package": row.get("pkg"),
                "install_status": row.get("status"),
            }
            for row in rows
            if isinstance(row, dict) and (device is None or row.get("dev") == device)
        ]
        return {"status": "success", "count": len(packages), "packages": packages}
    except Exception as e:
        logger.error(f"Failed to get package install status: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}


_SOURCES = ("revision", "device_db", "both")


async def _revision_policies(
    client: FortiManagerClient, device: str, vdom: str, revision: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Firewall policies of one device DB revision, plus that revision's metadata."""
    content = await client.get_device_revision_content(device=device, revision=revision)
    config = content.get("content") if isinstance(content, dict) else None
    if not isinstance(config, str):
        raise ValidationError(
            f"Device DB revision {revision} of {device} returned no configuration"
        )
    used = content.get("revision", revision)
    info: dict[str, Any] = {"number": used}
    try:
        history = await client.get_device_revisions(device)
        for rev in history.get("revinfo") or [] if isinstance(history, dict) else []:
            if rev.get("revision") == used:
                info.update(
                    time=rev.get("instime"), comment=rev.get("comments"), by=rev.get("instusr")
                )
                break
    except Exception as e:  # metadata only; the comparison stands without it
        logger.warning(f"Could not read revision history of {device}: {e}")
    return parse_firewall_policies(config, vdom), info


async def _device_db_policies(
    client: FortiManagerClient, device: str, vdom: str
) -> list[dict[str, Any]]:
    """The device DB's firewall policy table, enums as FortiOS names."""
    result = await client.get_verbose(f"/pm/config/device/{device}/vdom/{vdom}/firewall/policy")
    rows = result if isinstance(result, list) else [result] if result else []
    return [r for r in rows if isinstance(r, dict) and "policyid" in r]


@mcp.tool()
async def check_device_policy_sync(
    adom: str,
    device: str,
    vdom: str = "root",
    package: str | None = None,
    source: str = "both",
    revision: Id = -1,
) -> dict[str, Any]:
    """Compare a device's firewall policies with its assigned policy package.

    Reports, policy by policy, what differs between the package FortiManager
    has assigned to the device and what the device has. Read-only.

    Two views of "what the device has", chosen with ``source``:

    - ``revision``: the latest device DB revision -- the configuration last
      retrieved from or installed to the device, i.e. what it runs.
    - ``device_db``: FortiManager's current device DB, which also holds
      changes staged in FortiManager but not installed yet.
    - ``both`` (default): both comparisons, plus device DB vs revision --
      a difference there is staged in FortiManager and not installed.

    Only policies the package installs on this device count: install-on
    targets (devices and nested device groups) are resolved, and policy
    blocks are expanded in place. Policies only on the device side can be
    global header/footer policies or edits made on the device.

    Args:
        adom: ADOM name
        device: Managed device name
        vdom: VDOM (default "root")
        package: Package to compare with (default: the one assigned to the
            device/VDOM)
        source: "revision", "device_db" or "both" (default)
        revision: Device DB revision to use (default -1, the latest; see
            list_device_revisions). Ignored for source="device_db".

    Returns:
        dict: status, in_sync (all comparisons run), package,
        install_status, revision (number, time, comment), interface_mapping
        (normalized interfaces this device names differently), comparisons:
        {"package_vs_revision", "package_vs_device_db",
        "device_db_vs_revision"} as requested -- each with in_sync,
        summary, only_in_<side> lists, modified (field -> value per side)
        and order_matches -- and not_targeted (package policies scoped to
        other devices).

    Example:
        >>> result = await check_device_policy_sync("demo", "branch1")
        >>> for p in result["comparisons"]["package_vs_revision"]["modified"]:
        ...     print(p["policyid"], p["differences"])
    """
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
        vdom = validate_object_name(vdom, "VDOM")
        if source not in _SOURCES:
            raise ValidationError(f"source must be one of {', '.join(_SOURCES)}, got {source!r}")
        if isinstance(revision, bool) or not isinstance(revision, int):
            raise ValidationError(f"revision must be an integer, got {revision!r}")
        if revision != -1 and revision < 1:
            raise ValidationError(f"revision must be positive or -1 (latest), got {revision}")
        client = _get_client()

        status_rows = await client.get_package_status(adom)
        row = next(
            (
                r
                for r in status_rows
                if isinstance(r, dict) and r.get("dev") == device and r.get("vdom") == vdom
            ),
            None,
        )
        if package is None:
            if row is None or not row.get("pkg"):
                return error_response(
                    error="no_package_assigned",
                    message=f"No policy package is assigned to {device} (vdom {vdom}) in ADOM "
                    f"'{adom}'; pass package= to compare with one explicitly",
                    operation="check_device_policy_sync",
                    adom=adom,
                    device=device,
                )
            package = str(row["pkg"])
        package = validate_package_name(package)

        all_package_policies = await _package_policies(client, adom, package)
        groups = await _group_members(client, adom)
        targeted, not_targeted = [], []
        for policy in all_package_policies:
            if _targets_device(policy.get("scope member"), device, vdom, groups):
                targeted.append(policy)
            else:
                not_targeted.append(_label(policy))

        # Compare on the device's interface names, not the package's
        # normalized ones, or every per-device mapping reads as drift.
        intf_map = await _interface_map(client, adom, device, vdom, targeted)
        expected = _map_interfaces(targeted, intf_map)

        response: dict[str, Any] = {
            "status": "success",
            "adom": adom,
            "device": device,
            "vdom": vdom,
            "package": package,
            "install_status": row.get("status") if row and row.get("pkg") == package else None,
            "source": source,
        }
        comparisons: dict[str, Any] = {}
        rev_policies: list[dict[str, Any]] | None = None
        db_policies: list[dict[str, Any]] | None = None
        if source in ("revision", "both"):
            rev_policies, response["revision"] = await _revision_policies(
                client, device, vdom, revision
            )
            comparisons["package_vs_revision"] = compare_policies(
                expected, rev_policies, ("package", "revision")
            )
        if source in ("device_db", "both"):
            db_policies = await _device_db_policies(client, device, vdom)
            comparisons["package_vs_device_db"] = compare_policies(
                expected, db_policies, ("package", "device_db")
            )
        if rev_policies is not None and db_policies is not None:
            comparisons["device_db_vs_revision"] = compare_policies(
                db_policies, rev_policies, ("device_db", "revision")
            )

        response["in_sync"] = all(c["in_sync"] for c in comparisons.values())
        renamed = {n: m for n, m in intf_map.items() if m != [n]}
        if renamed:
            response["interface_mapping"] = renamed
        response["comparisons"] = comparisons
        response["not_targeted"] = not_targeted
        return response
    except Exception as e:
        logger.error(f"Failed to check policy sync for {device}: {e}")
        msg, code = client_safe_error(e)
        return {"status": "error", "message": msg, "error_code": code}
