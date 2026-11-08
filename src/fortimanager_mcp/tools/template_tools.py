"""Provisioning template management tools for FortiManager MCP.

Provides tools for managing provisioning templates including:
- System templates (devprof) - device configuration templates
- CLI template groups - CLI command templates
- Template groups - combined template packages

Based on FNDN FortiManager 7.6.5 API specifications.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from fortimanager_mcp.server import get_fmg_client, mcp
from fortimanager_mcp.utils.config import get_default_adom
from fortimanager_mcp.utils.errors import client_safe_error
from fortimanager_mcp.utils.validation import (
    CONFIG_TEXT_SECRET_DIRECTIVES,
    MASK_VALUE,
    redact_snmp_community_names,
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
# applies here too. A Jinja template (type 1) differs from an export in that
# the secret need not be written on the "set" line: it can sit in a
# "{% set %}", a loop list, a macro body or a dict literal and reach the
# "set" line through a variable. Matching each such construct with its own
# pattern was tried first and leaked whenever a template used a form the
# pattern did not expect ("{%+", a tuple target, a "%}" inside a string, two
# "set" statements on one line). So the body is tokenized instead, the way
# Jinja's lexer splits it, and the redactor fails closed on what it finds:
#
# - In template text, every "set <secret-directive>" is masked up to the end
#   of the line, or to the closing quote of a quoted value (across lines),
#   whatever precedes it on the line.
# - A value that is only a bare reference ("{{ psk }}", "$(psk)") is kept:
#   it says where the value comes from and is not itself a secret.
# - If a secret value is anything more than a bare reference, or reads a
#   variable the template itself mentions in another tag, the template could
#   be computing the secret from its own constants. Then every string and
#   number literal in every tag, and the body of every "{% set %}",
#   "{% macro %}", "{% call %}" and "{% block %}", is masked. The model loses
#   the template's literal constants but never sees a secret.
# - Independently of that, a "{% set %}" of a secret-looking name and a
#   secret-keyed literal ('{"password": "..."}', psk='...') are masked.
#
# Single quotes are tracked as well as double quotes, since a template author
# may write either. A tag that never closes masks the rest of the script.
# -----------------------------------------------------------------------------

#: A variable name containing one of these is treated as holding a secret.
_SECRET_NAME_HINTS = (
    "pass",
    "passwd",
    "pw",
    "pwd",
    "psk",
    "secret",
    "key",
    "token",
    "community",
    "credential",
)
_SECRET_NAME = rf"[\w.]*(?:{'|'.join(_SECRET_NAME_HINTS)})[\w.]*"
_JINJA_SECRET_LITERAL = re.compile(
    rf"(?P<key>(?P<q>[\"']?)(?i:{_SECRET_NAME})(?P=q)\s*(?:==|!=|[:=])\s*)"
    r"(?P<lq>[\"'])(?:\\.|(?!(?P=lq)).)*(?P=lq)",
    re.DOTALL,
)

#: A Jinja tag opener, with optional whitespace control; group 1 is the kind.
_TAG_OPEN = re.compile(r"\{([{%#])[-+]?")
_TAG_CLOSE = {"{": "}}", "%": "%}", "#": "#}"}
#: A FortiOS "set <directive>" anywhere in template text. The value follows
#: the blanks after the directive, or starts in the next token when a tag
#: follows the directive directly.
_SET_DIRECTIVE = re.compile(r"(?<![\w-])set[ \t]+(?P<directive>[\w+.-]+)(?:[ \t]+|\Z)", re.I)
#: Text right after a tag that starts a new "set" ends an unquoted value.
_SET_START = re.compile(r"[ \t]*set[ \t]", re.I)
_ENC_VALUE = re.compile(r"^[\"']?ENC\s")
_METAVAR_REFERENCE = re.compile(r"\s*\$\([A-Za-z_]\w*\)\s*\Z")
_BARE_EXPRESSION = re.compile(
    r"\{\{[-+]?\s*(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*[-+]?\}\}\Z"
)
_STATEMENT = re.compile(r"\{%[-+]?\s*(?P<keyword>\w*)")
_STATEMENT_TAIL = re.compile(r"\s*[-+]?%\}\Z")
_NUMBER = re.compile(r"\d[\w.]*")
_WORD_BEFORE_NUMBER = re.compile(r"[\w.]")
#: Statements whose body is captured rather than rendered in place.
_CAPTURING = frozenset({"set", "macro", "call", "block"})


@dataclass
class _Tag:
    kind: str  # "{", "%" or "#"
    text: str
    #: Index of the "=" of an inline "{% set %}" of a secret-looking name.
    secret_assign: int = -1


@dataclass
class _Text:
    text: str
    #: 0 rendered in place, 1 inside a capturing block, 2 inside a
    #: "{% set %}" block of a secret-looking name.
    capture: int


@dataclass
class _Value:
    """The value of a secret "set" directive: text pieces and the tags between them."""

    quote: str
    items: list[str | _Tag] = field(default_factory=list)
    closed: bool = False


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SECRET_NAME_HINTS)


def _is_secret_directive(directive: str, value: str) -> bool:
    return directive.lower() in CONFIG_TEXT_SECRET_DIRECTIVES or bool(_ENC_VALUE.match(value))


def _tag_end(script: str, i: int, kind: str) -> int:
    """Index just past the tag closer, skipping quoted strings; -1 if none."""
    close = _TAG_CLOSE[kind]
    quote = ""
    while i < len(script):
        char = script[i]
        if quote:
            if char == "\\":
                i += 1
            elif char == quote:
                quote = ""
        elif char in "'\"" and kind != "#":
            quote = char
        elif script.startswith(close, i):
            return i + len(close)
        i += 1
    return -1


def _tokenize(script: str) -> list[tuple[str, str]]:
    """Split a template into ("text", s), (kind, tag) and ("unterminated", rest).

    A quoted string inside a ``{{ }}`` or ``{% %}`` tag is skipped, as
    Jinja's lexer does, so a ``%}`` inside it does not end the tag.
    """
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(script):
        match = _TAG_OPEN.search(script, pos)
        if match is None:
            tokens.append(("text", script[pos:]))
            break
        if match.start() > pos:
            tokens.append(("text", script[pos : match.start()]))
        end = _tag_end(script, match.end(), match.group(1))
        if end < 0:
            tokens.append(("unterminated", script[match.start() :]))
            break
        tokens.append((match.group(1), script[match.start() : end]))
        pos = end
    return tokens


def _literal_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) of every string and number literal in a tag."""
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        char = text[i]
        if char in "'\"":
            j = i + 1
            while j < len(text) and text[j] != char:
                j += 2 if text[j] == "\\" else 1
            spans.append((i, min(j + 1, len(text))))
            i = j + 1
        elif char.isdigit() and not (i and _WORD_BEFORE_NUMBER.match(text[i - 1])):
            number = _NUMBER.match(text, i)
            end = number.end() if number else i + 1
            spans.append((i, end))
            i = end
        else:
            i += 1
    return spans


def _blank_literals(text: str) -> str:
    """``text`` with every literal replaced by spaces, so only code is left."""
    for start, end in _literal_spans(text):
        text = text[:start] + " " * (end - start) + text[end:]
    return text


def _top_level_assign(blank: str, start: int, end: int) -> int:
    """Index of the assignment "=" outside brackets, or -1."""
    depth = 0
    for i in range(start, end):
        char = blank[i]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif (
            char == "="
            and depth == 0
            and blank[i - 1] not in "=!<>"
            and blank[i + 1 : i + 2] != "="
        ):
            return i
    return -1


def _track_statement(tag: _Tag, stack: list[tuple[str, bool]]) -> None:
    """Follow capturing blocks and flag inline sets of secret-looking names."""
    match = _STATEMENT.match(tag.text)
    keyword = match.group("keyword") if match else ""
    if match and keyword == "set":
        blank = _blank_literals(tag.text)
        tail = _STATEMENT_TAIL.search(tag.text)
        end = tail.start() if tail else len(tag.text)
        assign = _top_level_assign(blank, match.end(), end)
        target = blank[match.end() : assign if assign >= 0 else end].split("|")[0]
        if assign < 0:
            stack.append(("set", _is_secret_name(target)))
        elif _is_secret_name(target):
            tag.secret_assign = assign
    elif keyword in _CAPTURING:
        stack.append((keyword, False))
    elif keyword.startswith("end") and stack and stack[-1][0] == keyword[3:]:
        stack.pop()


def _closing_quote(text: str, i: int, quote: str) -> int:
    """Index of the first ``quote`` at or after ``i`` not escaped by a backslash."""
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i
        i += 1
    return -1


def _scan_text(
    text: str,
    capture: int,
    parts: list[_Text | _Tag | _Value],
    values: list[_Value],
    value: _Value | None,
) -> _Value | None:
    """Split template text into plain text and secret values; return the open value."""
    if value is not None and not value.quote and _SET_START.match(text):
        value = None
    i = 0
    while True:
        if value is not None:
            end = _closing_quote(text, i, value.quote) if value.quote else text.find("\n", i)
            value.items.append(text[i:] if end < 0 else text[i:end])
            if end < 0:
                return value
            value.closed = bool(value.quote)
            i = end + 1 if value.quote else end
            value = None
        match = _SET_DIRECTIVE.search(text, i)
        if match is None:
            if i < len(text):
                parts.append(_Text(text[i:], capture))
            return None
        parts.append(_Text(text[i : match.end()], capture))
        i = match.end()
        if not _is_secret_directive(match.group("directive"), text[i:]):
            continue
        quote = text[i : i + 1] if text[i : i + 1] in ("'", '"') else ""
        value = _Value(quote)
        i += len(quote)
        parts.append(value)
        values.append(value)


def _parse(script: str) -> tuple[list[_Text | _Tag | _Value], list[_Value]]:
    parts: list[_Text | _Tag | _Value] = []
    values: list[_Value] = []
    stack: list[tuple[str, bool]] = []
    value: _Value | None = None
    for kind, token in _tokenize(script):
        if kind == "text":
            capture = 2 if any(secret for _, secret in stack) else int(bool(stack))
            value = _scan_text(token, capture, parts, values, value)
        elif kind == "unterminated":
            parts.append(_Text(MASK_VALUE, 0))
        else:
            tag = _Tag(kind, token)
            if kind == "%":
                _track_statement(tag, stack)
            (value.items if value is not None else parts).append(tag)
    return parts, values


def _literals_reach_a_secret(parts: list[_Text | _Tag | _Value], values: list[_Value]) -> bool:
    """Whether a secret value could be built from the template's own literals.

    True when a secret value holds a tag that is not a bare ``{{ name }}``,
    or reads a name that any other tag mentions (and so may assign).
    """
    names: set[str] = set()
    bare: list[_Tag] = []
    for value in values:
        for item in value.items:
            if not isinstance(item, _Tag) or item.kind == "#":
                continue
            match = _BARE_EXPRESSION.match(item.text)
            if match is None:
                return True
            names.add(match.group("name").split(".")[0])
            bare.append(item)
    if not names:
        return False
    mention = re.compile(r"(?<!\w)(?:" + "|".join(map(re.escape, names)) + r")(?!\w)")
    tags = [p for p in parts if isinstance(p, _Tag)] + [
        item for value in values for item in value.items if isinstance(item, _Tag)
    ]
    return any(
        tag.kind != "#"
        and not any(tag is b for b in bare)
        and mention.search(_blank_literals(tag.text))
        for tag in tags
    )


def _holds_secret_directive(literal: str) -> bool:
    return any(
        _is_secret_directive(m.group("directive"), literal[1:-1][m.end() :])
        for m in _SET_DIRECTIVE.finditer(literal[1:-1])
    )


def _render_tag(tag: _Tag, mask_all: bool) -> str:
    text = tag.text
    if tag.kind == "#":
        return text[:2] + redact_cli_template_script(text[2:-2]) + text[-2:]
    if tag.secret_assign >= 0:
        rest = text[tag.secret_assign + 1 :]
        start = len(text) - len(rest.lstrip())
        tail = _STATEMENT_TAIL.search(text)
        return text[:start] + MASK_VALUE + text[tail.start() if tail else len(text) :]
    out: list[str] = []
    last = 0
    for start, end in _literal_spans(text):
        literal = text[start:end]
        quoted = literal[0] in "'\""
        if not (mask_all or (quoted and _holds_secret_directive(literal))):
            continue
        out.append(text[last:start])
        out.append(f"{literal[0]}{MASK_VALUE}{literal[0]}" if quoted else MASK_VALUE)
        last = end
    text = "".join(out) + text[last:]
    return _JINJA_SECRET_LITERAL.sub(
        lambda m: f"{m.group('key')}{m.group('lq')}{MASK_VALUE}{m.group('lq')}", text
    )


def _render_value(value: _Value, mask_all: bool) -> str:
    if value.quote and not any(isinstance(item, _Tag) for item in value.items):
        body = "".join(str(item) for item in value.items)
        if body and not _METAVAR_REFERENCE.match(body):
            return MASK_VALUE
        return value.quote + body + (value.quote if value.closed else "")
    pieces = [
        _render_tag(item, mask_all)
        if isinstance(item, _Tag)
        else item
        if not item.strip() or _METAVAR_REFERENCE.match(item)
        else MASK_VALUE
        for item in value.items
    ]
    return value.quote + "".join(pieces) + (value.quote if value.closed else "")


def redact_cli_template_script(script: str) -> str:
    """Mask secrets in a CLI template body (FortiOS CLI or Jinja).

    Keeps the directive or variable name visible, so the result still shows
    that a template sets a password and, for a bare ``{{ var }}`` or
    ``$(var)`` reference, which variable it comes from. See the comment
    block above for what is masked when.
    """
    parts, values = _parse(script)
    mask_all = _literals_reach_a_secret(parts, values)
    out: list[str] = []
    for part in parts:
        if isinstance(part, _Value):
            out.append(_render_value(part, mask_all))
        elif isinstance(part, _Tag):
            out.append(_render_tag(part, mask_all))
        elif part.text.strip() and (part.capture == 2 or (part.capture == 1 and mask_all)):
            out.append(MASK_VALUE)
        else:
            out.append(part.text)
    # What only block context shows: an SNMP community's ``set name`` is its
    # community string.
    return redact_snmp_community_names("".join(out))


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
