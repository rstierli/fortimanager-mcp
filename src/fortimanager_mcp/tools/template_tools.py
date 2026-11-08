"""Provisioning template management tools for FortiManager MCP.

Provides tools for managing provisioning templates including:
- System templates (devprof) - device configuration templates
- CLI template groups - CLI command templates
- Template groups - combined template packages

Based on FNDN FortiManager 7.6.5 API specifications.
"""

import logging
import re
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    CONFIG_TEXT_SECRET_DIRECTIVES,
    MASK_VALUE,
    validate_adom,
    validate_device_name,
    validate_object_name,
)

logger = logging.getLogger(__name__)

#: ``type`` of a CLI template (``obj/cli/template``).
_CLI_TEMPLATE_TYPES: dict[Any, str] = {0: "cli", 1: "jinja"}

# -----------------------------------------------------------------------------
# CLI template script redaction
#
# A template body is FortiOS CLI, so the "set <secret-directive> <value>"
# rule that redact_config_text_secrets applies to device config exports
# applies here too. A template differs from an export in three ways, which
# is why it gets its own pass instead of the shared one:
#
# - Jinja (type 1) can hold a secret outside any "set" line, in a variable
#   assignment ("{% set psk = '...' %}", "{% set psk %}...{% endset %}") or a
#   dict/keyword literal ('{"password": "..."}').
# - A "set" line can follow a Jinja tag on the same line
#   ("{% if hub %}set psksecret ...{% endif %}").
# - The value is often a variable reference ("{{ psk }}", "$(psk)"), which is
#   not a secret and is the useful part to see: it says where the value comes
#   from. Only a bare reference is kept; anything with a filter, literal or
#   expression in it is masked.
#
# Single quotes are tracked as well as double quotes, since a template author
# may write either; a multi-line quoted value is dropped up to its closing
# quote, as redact_config_text_secrets does.
# -----------------------------------------------------------------------------

#: A variable name containing one of these is treated as holding a secret.
_SECRET_NAME_HINTS = (
    "pass",
    "pwd",
    "psk",
    "secret",
    "key",
    "token",
    "community",
    "credential",
)
_SECRET_NAME = rf"[\w.]*(?:{'|'.join(_SECRET_NAME_HINTS)})[\w.]*"

_JINJA_BLOCK_SET = re.compile(
    r"(?P<open>\{%-?\s*set\s+(?P<name>[\w.]+)\s*-?%\})(?P<body>.*?)"
    r"(?P<close>\{%-?\s*endset\s*-?%\})",
    re.DOTALL,
)
_JINJA_INLINE_SET = re.compile(
    r"(?P<head>\{%-?\s*set\s+(?P<name>[\w.]+(?:\s*,\s*[\w.]+)*)\s*=\s*)"
    r"(?P<value>.*?)(?P<tail>\s*-?%\})",
    re.DOTALL,
)
_JINJA_TAG = re.compile(r"\{%.*?%\}|\{\{.*?\}\}", re.DOTALL)
_JINJA_SECRET_LITERAL = re.compile(
    rf"(?P<key>(?P<q>[\"']?)(?i:{_SECRET_NAME})(?P=q)\s*(?:==|!=|[:=])\s*)"
    r"(?P<lq>[\"'])(?:\\.|(?!(?P=lq)).)*(?P=lq)",
    re.DOTALL,
)
_SET_LINE = re.compile(
    r"(?P<lead>^|%\}|\}\})(?P<prefix>\s*set\s+(?P<directive>\S+)\s+)(?P<rest>.*)$"
)
_ENC_VALUE = re.compile(r"^[\"']?ENC\s")
_VARIABLE_REFERENCE = re.compile(
    r"^(?P<q>[\"']?)(?:\{\{-?\s*[A-Za-z_][\w.]*\s*-?\}\}|\$\([A-Za-z_]\w*\))(?P=q)$"
)


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SECRET_NAME_HINTS)


def _closes_quote(text: str, quote: str) -> bool:
    """True if ``text`` holds ``quote`` not escaped by a backslash."""
    escaped = False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return True
    return False


def _redact_jinja(text: str) -> str:
    """Mask secret-named Jinja assignments and secret-keyed string literals."""

    def block(m: re.Match[str]) -> str:
        if not _is_secret_name(m.group("name")):
            return m.group(0)
        return f"{m.group('open')}{MASK_VALUE}{m.group('close')}"

    def inline(m: re.Match[str]) -> str:
        if not _is_secret_name(m.group("name")):
            return m.group(0)
        return f"{m.group('head')}{MASK_VALUE}{m.group('tail')}"

    def literal(m: re.Match[str]) -> str:
        return f"{m.group('key')}{m.group('lq')}{MASK_VALUE}{m.group('lq')}"

    text = _JINJA_BLOCK_SET.sub(block, text)
    text = _JINJA_INLINE_SET.sub(inline, text)
    return _JINJA_TAG.sub(lambda m: _JINJA_SECRET_LITERAL.sub(literal, m.group(0)), text)


def redact_cli_template_script(script: str) -> str:
    """Mask secrets in a CLI template body (FortiOS CLI or Jinja).

    Keeps the directive or variable name visible, so the result still shows
    that a template sets a password and, for a bare ``{{ var }}`` or
    ``$(var)`` reference, which variable it comes from.
    """
    lines = _redact_jinja(script).split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        match = _SET_LINE.search(line)
        if not match:
            out.append(line)
            continue
        rest = match.group("rest")
        cut = rest.find("{%")
        value, tail = (rest[:cut], rest[cut:]) if cut > 0 else (rest, "")
        value = value.rstrip()
        secret = match.group("directive") in CONFIG_TEXT_SECRET_DIRECTIVES or bool(
            _ENC_VALUE.match(value)
        )
        if not secret or _VARIABLE_REFERENCE.match(value) or value == MASK_VALUE:
            out.append(line)
            continue
        out.append(line[: match.start("rest")] + MASK_VALUE + (f" {tail}" if tail else ""))
        quote = value[:1]
        if quote in ("'", '"') and not _closes_quote(value[1:], quote):
            # Unterminated quote: the value continues on the next lines up to
            # the closing one (or the end of the script). Drop them all.
            while i < len(lines) and not _closes_quote(lines[i], quote):
                i += 1
            i += 1
    return "\n".join(out)


# =============================================================================
# Provisioning Templates (General)
# =============================================================================


@mcp.tool()
async def list_templates(
    adom: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List all provisioning templates in an ADOM.

    Returns all template types: IPsec, BGP, system, etc.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        limit: Maximum number of templates to return

    Returns:
        List of templates with name, type, and settings
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        templates = await client.list_templates(adom=adom)
        templates = templates[:limit] if templates else []

        return {
            "adom": adom,
            "count": len(templates),
            "templates": templates,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a specific provisioning template.

    Args:
        adom: ADOM name
        name: Template name

    Returns:
        Template details including settings and scope
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "template")
        template = await client.get_template(adom=adom, name=name)
        return {"template": template}
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# System Templates (devprof)
# =============================================================================


@mcp.tool()
async def list_system_templates(
    adom: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List system templates (device profiles) in an ADOM.

    System templates configure device settings like DNS, NTP, logging, etc.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        limit: Maximum number to return

    Returns:
        List of system templates with name, type, and assigned devices
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        templates = await client.list_system_templates(adom=adom)
        templates = templates[:limit] if templates else []

        return {
            "adom": adom,
            "count": len(templates),
            "templates": templates,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_system_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a specific system template.

    Args:
        adom: ADOM name
        name: System template name

    Returns:
        System template details including widgets and assigned devices
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "template")
        template = await client.get_system_template(adom=adom, name=name)
        return {"template": template}
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def assign_system_template(
    adom: str,
    template: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Assign a system template to a device.

    Args:
        adom: ADOM name
        template: System template name
        device: Device name to assign
        vdom: VDOM name (default: root)

    Returns:
        Assignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template = validate_object_name(template, "template")
        device = validate_device_name(device)
        scope = [{"name": device, "vdom": vdom}]
        result = await client.assign_system_template(adom=adom, template=template, scope=scope)
        return {
            "success": True,
            "message": f"System template '{template}' assigned to device '{device}'",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def assign_system_template_bulk(
    adom: str,
    template: str,
    devices: list[dict[str, str]],
) -> dict[str, Any]:
    """Assign a system template to multiple devices.

    Args:
        adom: ADOM name
        template: System template name
        devices: List of devices [{"name": "dev1", "vdom": "root"}, ...]

    Returns:
        dict: Assignment result with keys:
            - success: True
            - requested_count: Number of devices in the request. NOT a
              count of assignments actually made: FortiManager reports no
              per-device result for this scope-member ADD, and the client
              raises on any non-zero code, so everything reaching this
              line is a code 0 that says nothing about individual devices
              (same shape as #78's device-group bulk tools).
            - result: Raw client result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template = validate_object_name(template, "template")
        result = await client.assign_system_template(adom=adom, template=template, scope=devices)
        return {
            "success": True,
            "requested_count": len(devices),
            "message": (
                f"Requested assignment of system template '{template}' to "
                f"{len(devices)} device(s). FortiManager does not report "
                "per-device results, so this does not confirm the assignments "
                "were made."
            ),
            "result": result,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def unassign_system_template(
    adom: str,
    template: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Unassign a system template from a device.

    Args:
        adom: ADOM name
        template: System template name
        device: Device name to unassign
        vdom: VDOM name (default: root)

    Returns:
        Unassignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template = validate_object_name(template, "template")
        device = validate_device_name(device)
        scope = [{"name": device, "vdom": vdom}]
        result = await client.unassign_system_template(adom=adom, template=template, scope=scope)
        return {
            "success": True,
            "message": f"System template '{template}' unassigned from device '{device}'",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# CLI Template Groups
# =============================================================================


@mcp.tool()
async def list_cli_templates(
    adom: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List CLI templates in an ADOM, without their scripts.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        limit: Maximum number to return

    Returns:
        dict: adom, count, cli_templates (name, type, description, variables)
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        templates = await client.list_cli_templates(adom=adom)
        templates = [
            {
                "name": t.get("name"),
                "type": _CLI_TEMPLATE_TYPES.get(t.get("type"), t.get("type")),
                "description": t.get("description"),
                "variables": t.get("variables"),
            }
            for t in templates[:limit]
        ]
        return {"adom": adom, "count": len(templates), "cli_templates": templates}
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_cli_template(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Read a CLI template, with its script.

    ``get_cli_template_group`` lists a group's members only; this returns what
    a member pushes. Secrets in the script are redacted, so the result shows
    that a template sets a password, not the value: ``set <secret>`` values
    and ENC blobs (also after a Jinja tag on the same line), secret-named
    Jinja ``{% set %}`` assignments, and secret-keyed string literals inside
    Jinja tags. A bare variable reference (``set psksecret {{ psk }}``,
    ``$(psk)``) is kept, since it names where the value comes from.

    Args:
        adom: ADOM name
        name: CLI template name (see list_cli_templates)

    Returns:
        dict: cli_template with name, type, description, variables, script
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "CLI template")
        template = await client.get_cli_template(adom=adom, name=name)
        script = template.get("script")
        return {
            "cli_template": {
                "name": template.get("name"),
                "type": _CLI_TEMPLATE_TYPES.get(template.get("type"), template.get("type")),
                "description": template.get("description"),
                "variables": template.get("variables"),
                "script": redact_cli_template_script(script) if isinstance(script, str) else script,
            }
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def list_cli_template_groups(
    adom: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List CLI template groups in an ADOM.

    CLI template groups contain CLI commands to be executed on devices.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        limit: Maximum number to return

    Returns:
        List of CLI template groups
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        groups = await client.list_cli_template_groups(adom=adom)
        groups = groups[:limit] if groups else []

        return {
            "adom": adom,
            "count": len(groups),
            "cli_template_groups": groups,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_cli_template_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a CLI template group.

    Args:
        adom: ADOM name
        name: CLI template group name

    Returns:
        CLI template group details
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "CLI template group")
        group = await client.get_cli_template_group(adom=adom, name=name)
        return {"cli_template_group": group}
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def create_cli_template_group(
    adom: str,
    name: str,
    description: str | None = None,
) -> dict[str, Any]:
    """Create a new CLI template group.

    Args:
        adom: ADOM name
        name: CLI template group name
        description: Optional description

    Returns:
        Created CLI template group
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "CLI template group")
        group_data: dict[str, Any] = {"name": name}
        if description:
            group_data["description"] = description

        result = await client.create_cli_template_group(adom=adom, group=group_data)
        return {
            "success": True,
            "message": f"CLI template group '{name}' created",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def delete_cli_template_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Delete a CLI template group.

    Args:
        adom: ADOM name
        name: CLI template group name

    Returns:
        Deletion result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "CLI template group")
        result = await client.delete_cli_template_group(adom=adom, name=name)
        return {
            "success": True,
            "message": f"CLI template group '{name}' deleted",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# Template Groups (Combined Templates)
# =============================================================================


@mcp.tool()
async def list_template_groups(
    adom: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List template groups in an ADOM.

    Template groups combine multiple templates (system, CLI, SD-WAN, etc.)
    into a single package for device assignment.

    Args:
        adom: ADOM name (default: from DEFAULT_ADOM env var, or "root")
        limit: Maximum number to return

    Returns:
        List of template groups
    """
    adom = adom or get_default_adom()
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        groups = await client.list_template_groups(adom=adom)
        groups = groups[:limit] if groups else []

        return {
            "adom": adom,
            "count": len(groups),
            "template_groups": groups,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def get_template_group(
    adom: str,
    name: str,
) -> dict[str, Any]:
    """Get details of a template group.

    Args:
        adom: ADOM name
        name: Template group name

    Returns:
        Template group details including member templates
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        name = validate_object_name(name, "template group")
        group = await client.get_template_group(adom=adom, name=name)
        return {"template_group": group}
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


@mcp.tool()
async def assign_template_group(
    adom: str,
    template_group: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Assign a template group to a device.

    Args:
        adom: ADOM name
        template_group: Template group name
        device: Device name
        vdom: VDOM name (default: root)

    Returns:
        Assignment result
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template_group = validate_object_name(template_group, "template group")
        device = validate_device_name(device)
        scope = [{"name": device, "vdom": vdom}]
        result = await client.assign_template_group(
            adom=adom, template_group=template_group, scope=scope
        )
        return {
            "success": True,
            "message": f"Template group '{template_group}' assigned to device '{device}'",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}


# =============================================================================
# Template Validation
# =============================================================================


@mcp.tool()
async def validate_template(
    adom: str,
    template_group: str,
    device: str,
    vdom: str = "root",
) -> dict[str, Any]:
    """Validate a template group for a device.

    Checks that all metadata variables are resolved for the device.

    Args:
        adom: ADOM name
        template_group: Template group name
        device: Target device name
        vdom: VDOM name (default: root)

    Returns:
        Task ID for monitoring validation progress
    """
    client = get_fmg_client()
    if not client:
        return {"error": "FortiManager client not connected"}

    try:
        adom = validate_adom(adom)
        template_group = validate_object_name(template_group, "template group")
        device = validate_device_name(device)
        # FortiManager API path for template-group (tmplgrp). Both adom and
        # template_group are validated above. The "tmpl" substring trips
        # bandit's hardcoded-tmp-directory heuristic — this is a URL fragment,
        # not a temp directory.
        pkg = f"adom/{adom}/tmplgrp/{template_group}"  # nosec B108
        scope = [{"name": device, "vdom": vdom}]
        result = await client.validate_template(adom=adom, pkg=pkg, scope=scope)
        return {
            "success": True,
            "message": f"Template validation started for '{template_group}' on '{device}'",
            "task_id": result.get("task"),
            "result": result,
        }
    except Exception as e:
        logger.error(f"Template tool operation failed: {e}")
        msg, code = client_safe_error(e)
        return {"error": msg, "error_code": code}
