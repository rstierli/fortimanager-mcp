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
    is_snmp_community_block,
    validate_adom,
    validate_device_name,
    validate_object_name,
)

logger = logging.getLogger(__name__)

#: ``type`` of a CLI template (``obj/cli/template``); FNDN: "cli" 0, "jinja" 1.
_CLI_TEMPLATE_TYPES: dict[Any, str] = {0: "cli", 1: "jinja"}

# -----------------------------------------------------------------------------
# CLI template script redaction
#
# A template body is FortiOS CLI, so the "set <secret-directive> <value>"
# rule that redact_config_text_secrets applies to device config exports
# applies here too. A Jinja template (type 1) differs from an export in two
# ways: the secret need not be written on the "set" line (it can sit in a
# "{% set %}", a loop list, a macro body or a dict literal and reach the
# "set" line through a variable), and whitespace control ("-%}", "{%-") or
# trim_blocks can carry a value on over any number of lines. Two rounds of
# matching one construct at a time each leaked on a form the patterns did
# not expect, so the redactor fails closed by design instead:
#
# - The body is tokenized the way Jinja's lexer splits it (quoted strings
#   and bracket nesting inside a tag are skipped, so a "%}" or "}}" there
#   does not end it). A plain CLI template (type 0) is not tokenized: braces
#   are text there.
# - A secret value is precise only if it is one quoted string closed on its
#   line, or a bare "{{ name }}" / "$(name)" alone, and no left-trimming tag
#   follows to pull the next line in. A literal is masked, a reference kept:
#   it says where the value comes from and is not itself a secret.
# - Any other value is opaque. Everything after the directive (text and
#   tags) is masked up to the start of the next line that begins with a
#   FortiOS CLI keyword outside a tag, or a line holding only statement or
#   comment tags that close back to the depth the directive started at.
#   After such a tag line, a line that is neither CLI, blank nor more tags
#   is masked again, since trim_blocks may join it to the value.
# - A directive the template spells with a tag ("set {{ f }}", "set
#   pass{{ x }}", "set $(f)") is treated as a secret one, as is a secret
#   directive name right after a tag.
# - In SNMP community blocks (config/end are tracked) "set name" is a secret
#   directive: the name is the community string.
# - If a secret value holds a tag that is not a bare reference, reads a name
#   the template mentions elsewhere (another tag, or a "#"/"%" line that a
#   line-statement setup would run), or a tag spells a secret directive,
#   the template could compute the secret from its own constants. Then every
#   literal in every tag, the body of every "{% set %}", "{% macro %}" and
#   "{% block %}" and every "#"/"%" line is masked. A "{% call %}" body and
#   a "{% set %}" block of a secret-looking name are always masked.
# - A "{% set %}" of a secret-looking name and a secret-keyed literal
#   ('{"password": "..."}', psk='...') are masked in any case. A comment is
#   redacted as a template of its own, with every literal masked if it
#   holds a tag. A tag that never closes masks the rest of the script.
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
# The lookbehind pins a name to its first character: without it, a long
# identifier is retried from every position inside it (quadratic).
_SECRET_NAME = rf"(?<![\w.])[\w.]*?(?:{'|'.join(_SECRET_NAME_HINTS)})[\w.]*"
_JINJA_SECRET_LITERAL = re.compile(
    rf"(?P<key>(?P<q>[\"']?)(?i:{_SECRET_NAME})(?P=q)\s*(?:==|!=|[:=])\s*)"
    r"(?P<lq>[\"'])(?:\\.|(?!(?P=lq)).)*(?P=lq)",
    re.DOTALL,
)

#: A Jinja tag opener, with optional whitespace control; group 1 is the kind.
_TAG_OPEN = re.compile(r"\{([{%#])[-+]?")
_TAG_CLOSE = {"{": "}}", "%": "%}", "#": "#}"}
_TAG_KINDS = frozenset("{%#")
#: A tag that strips the whitespace (newlines included) before it.
_TRIM_OPEN = re.compile(r"\{[{%#]-")

#: FortiOS CLI keywords that start a line of their own.
_CLI_KEYWORDS = (
    "set",
    "unset",
    "config",
    "edit",
    "next",
    "end",
    "append",
    "select",
    "unselect",
    "purge",
    "execute",
    "delete",
    "rename",
    "clone",
    "show",
    "get",
)
_CLI_LINE = re.compile(r"[^\S\n]*(?:" + "|".join(_CLI_KEYWORDS) + r")(?![\w-])", re.I)
_CONFIG_LINE = re.compile(r"[^\S\n]*config(?![\w-])(?P<path>.*)", re.I)
_END_LINE = re.compile(r"[^\S\n]*end(?![\w-])", re.I)
_SET_WORD = re.compile(r"(?<![\w-])set(?![\w-])", re.I)
_DIRECTIVE = re.compile(r"(?P<q>[\"']?)(?P<directive>[\w+.-]+)(?P=q)")
_LEADING_DIRECTIVE = re.compile(r"[^\S\n]*" + _DIRECTIVE.pattern)
_BLANKS = re.compile(r"[^\S\n]*")
_NEWLINES = re.compile(r"(\n+)")
_ENC_VALUE = re.compile(r"[\"']?ENC(?:\s|\Z)")

#: Precise values: one closed quoted string, or a bare reference alone.
_QUOTED_ALONE = re.compile(r"(?P<q>[\"'])(?:\\.|(?!(?P=q))[^\\])*(?P=q)(?P<tail>[^\S\n]*)")
_METAVAR_ALONE = re.compile(r"(?P<q>[\"']?)[^\S\n]*\$\([A-Za-z_]\w*\)[^\S\n]*(?P=q)[^\S\n]*")
_QUOTE_OPEN = re.compile(r"(?P<q>[\"']?)[^\S\n]*")
#: A bare reference; no right trim, which would pull the next line in.
_BARE_REFERENCE = re.compile(r"\{\{[-+]?\s*(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\+?\}\}\Z")

_STATEMENT = re.compile(r"\{%[-+]?\s*(?P<keyword>\w*)")
_STATEMENT_TAIL = re.compile(r"\s*[-+]?%\}\Z")
_LITERAL = re.compile(r"'(?:\\.|[^'\\])*'?|\"(?:\\.|[^\"\\])*\"?|(?<![\w.])\d[\w.]*", re.DOTALL)
_WORD = re.compile(r"\w+")
#: Statements whose body is captured rather than rendered in place.
_CAPTURING = frozenset({"set", "macro", "call", "block"})
#: Statements that open a block closed by "end<keyword>".
_BLOCK_OPENERS = _CAPTURING | {"if", "for", "filter", "with", "autoescape", "raw", "trans"}

_Token = tuple[str, str]


@dataclass
class _Tag:
    kind: str  # "{", "%" or "#"
    text: str
    #: (start, end) of every string and number literal.
    spans: list[tuple[int, int]] = field(default_factory=list)
    #: ``text`` with every literal blanked out, so only code is left.
    blank: str = ""
    #: Index of the "=" of an inline "{% set %}" of a secret-looking name.
    secret_assign: int = -1
    #: The tag's code spells a secret "set" directive (CLI text that a brace
    #: made look like Jinja): the whole tag is masked.
    code_directive: bool = False


@dataclass
class _Text:
    text: str
    #: 0 rendered in place, 1 inside a capturing block, 2 always masked
    #: (a "{% call %}" body, a "{% set %}" block of a secret-looking name).
    capture: int = 0
    #: On a line starting with "#" or "%": a comment, or a line statement.
    line_statement: bool = False


@dataclass
class _Value:
    """What follows a secret "set" directive: text pieces and tags."""

    items: list[str | _Tag] = field(default_factory=list)
    #: "keep" (a bare reference), "mask" (one quoted literal) or "" (opaque).
    precise: str = ""
    #: Blanks after the closing quote of a "mask" value.
    tail: str = ""
    #: Statement depth the directive started at.
    depth: int = 0
    #: Opening quote of an opaque value still waiting for its close.
    quote: str = ""


def _is_plain_cli_type(template_type: Any) -> bool:
    """Whether a CLI template ``type`` says plain FortiOS CLI rather than Jinja.

    Only an explicit "cli" (0) counts. A missing or unrecognised type is
    read as Jinja, whose redaction is the stricter of the two.
    """
    if isinstance(template_type, bool):
        return False
    if isinstance(template_type, int):
        return template_type == 0
    return isinstance(template_type, str) and template_type.strip().lower() in ("0", "cli")


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SECRET_NAME_HINTS)


def _is_secret_directive(directive: str, community: bool, text: str = "", value: int = 0) -> bool:
    """A secret directive by name, or one whose value (``text[value:]``) is an ENC blob."""
    name = directive.lower().replace("_", "-")
    return (
        name in CONFIG_TEXT_SECRET_DIRECTIVES
        or (community and name == "name")
        or bool(_ENC_VALUE.match(text, value))
    )


def _skip_blanks(text: str, i: int) -> int:
    """Index of the first non-blank at or after ``i`` on the line."""
    match = _BLANKS.match(text, i)
    return match.end() if match else i


def _secret_value_start(text: str, after_tag: bool, tag_follows: bool, community: bool) -> int:
    """Where the value of the first secret directive in ``text`` starts, or -1.

    ``text`` is one line, or the part of one between tags. A directive that
    is not a plain word (a tag or metavariable supplies it, or is glued to
    it) is taken to be a secret one. ``after_tag``: ``text`` directly follows
    a tag, which may have written the "set". ``tag_follows``: a tag follows
    ``text`` directly, so what ends ``text`` continues there.
    """
    if after_tag:
        match = _LEADING_DIRECTIVE.match(text)
        if match and _is_secret_directive(match.group("directive"), community):
            end = match.end()
            if end == len(text) or not text[end].isspace():
                return end
            return _skip_blanks(text, end)
    for match in _SET_WORD.finditer(text):
        start = _skip_blanks(text, match.end())
        if start == len(text):
            if tag_follows:
                return start
            continue
        if start == match.end() and text[start] not in "\"'":
            continue  # "set," / "set:" in prose
        directive = _DIRECTIVE.match(text, start)
        if directive is None:
            return start  # "set $(field)", "set (..."
        end = directive.end()
        name = directive.group("directive")
        if end == len(text):
            if tag_follows or _is_secret_directive(name, community):
                return end
            continue
        if not text[end].isspace():
            return end  # glued: "set pass$(x)"
        value = _skip_blanks(text, end)
        if _is_secret_directive(name, community, text, value):
            return value
    return -1


def _holds_directive(content: str) -> bool:
    """Whether a string literal spells a secret directive, or one left open."""
    return any(_secret_value_start(line, False, True, False) >= 0 for line in content.split("\n"))


def _tag_end(script: str, i: int, kind: str) -> int:
    """Index just past the tag closer, or -1 if none.

    As in Jinja's lexer, quoted strings are skipped and the closer only
    counts outside brackets, so ``{{ f({'a': {'b': 1}}) }}`` is one tag.
    """
    if kind == "#":
        end = script.find("#}", i)
        return end + 2 if end >= 0 else -1
    close = _TAG_CLOSE[kind]
    quote = ""
    depth = 0
    n = len(script)
    while i < n:
        char = script[i]
        if quote:
            if char == "\\":
                i += 1
            elif char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif depth == 0 and char == close[0] and script.startswith(close, i):
            return i + 2
        elif char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        i += 1
    return -1


def _tokenize(script: str, plain: bool) -> list[_Token]:
    """Split a template into text, "nl", tag ("{", "%", "#") and "unterminated" tokens.

    Text tokens never hold a newline; each run of newlines is one "nl"
    token (no rule depends on an empty line). A plain CLI template is text
    and newlines only.
    """
    tokens: list[_Token] = []

    def add_text(text: str) -> None:
        for k, piece in enumerate(_NEWLINES.split(text)):
            if piece:
                tokens.append(("nl" if k % 2 else "text", piece))

    if plain:
        add_text(script)
        return tokens
    pos = 0
    while pos < len(script):
        match = _TAG_OPEN.search(script, pos)
        if match is None:
            add_text(script[pos:])
            break
        if match.start() > pos:
            add_text(script[pos : match.start()])
        end = _tag_end(script, match.end(), match.group(1))
        if end < 0:
            tokens.append(("unterminated", script[match.start() :]))
            break
        tokens.append((match.group(1), script[match.start() : end]))
        pos = end
    return tokens


def _lines(tokens: list[_Token]) -> list[list[_Token]]:
    """Group tokens into lines, each ending with its "nl" token (the last may not)."""
    lines: list[list[_Token]] = []
    line: list[_Token] = []
    for token in tokens:
        line.append(token)
        if token[0] == "nl":
            lines.append(line)
            line = []
    if line:
        lines.append(line)
    return lines


def _significant(line: list[_Token]) -> _Token | None:
    """The first token of a line that is not blank."""
    for token in line:
        if token[0] != "nl" and (token[0] != "text" or token[1].strip()):
            return token
    return None


def _line_shape(line: list[_Token]) -> str:
    """Classify a line.

    "cli" (starts with a CLI keyword), "tags" (statement and comment tags
    only), "blank", or "other".
    """
    first = _significant(line)
    if first is None:
        return "blank"
    if first[0] == "text":
        return "cli" if _CLI_LINE.match(first[1]) else "other"
    if all(
        kind in ("%", "#", "nl") or (kind == "text" and not text.strip()) for kind, text in line
    ):
        return "tags"
    return "other"


def _precise(body: list[_Token]) -> tuple[str, str] | None:
    """("keep" | "mask", tail) if a value on its line is precise, else None."""
    tags = [token for token in body if token[0] != "text"]
    if not tags:
        text = "".join(t for _, t in body)
        if _METAVAR_ALONE.fullmatch(text):
            return ("keep", "")
        quoted = _QUOTED_ALONE.fullmatch(text)
        return ("mask", quoted.group("tail")) if quoted else None
    if len(tags) != 1 or tags[0][0] != "{" or not _BARE_REFERENCE.match(tags[0][1]):
        return None
    at = body.index(tags[0])
    before = "".join(t for _, t in body[:at])
    after = "".join(t for _, t in body[at + 1 :])
    opened = _QUOTE_OPEN.fullmatch(before)
    if opened and re.fullmatch(rf"[^\S\n]*{re.escape(opened.group('q'))}[^\S\n]*", after):
        return ("keep", "")
    return None


class _Scanner:
    """Walk a tokenized template line by line; see the comment block above."""

    def __init__(self, tokens: list[_Token]):
        self.lines = _lines(tokens)
        self.parts: list[_Text | _Tag | _Value] = []
        self.values: list[_Value] = []
        self.tags: list[_Tag] = []
        self.statement_texts: list[str] = []
        self.blocks: list[tuple[str, bool]] = []  # open capturing blocks
        self.secret_blocks = 0
        self.depth = 0
        self.communities: list[bool] = []  # open config blocks
        self.in_community = 0
        self.builds_directive = False

    @property
    def capture(self) -> int:
        return 2 if self.secret_blocks else int(bool(self.blocks))

    # -- tags ------------------------------------------------------------

    def _tag(self, kind: str, text: str) -> _Tag:
        tag = _Tag(kind, text)
        self.tags.append(tag)
        if kind == "#":
            return tag
        tag.spans = [m.span() for m in _LITERAL.finditer(text, 2, len(text) - 2)]
        pieces: list[str] = []
        last = 0
        for start, end in tag.spans:
            pieces += [text[last:start], " " * (end - start)]
            last = end
        pieces.append(text[last:])
        tag.blank = "".join(pieces)
        statement = _STATEMENT.match(text)
        code_start = statement.end() if statement else 2
        tag.code_directive = any(
            _secret_value_start(line, False, False, False) >= 0
            for line in tag.blank[code_start:-2].split("\n")
        )
        if tag.code_directive or any(
            text[s] in "'\"" and _holds_directive(text[s + 1 : e - 1]) for s, e in tag.spans
        ):
            self.builds_directive = True
        if kind == "%":
            self._track_statement(tag, statement)
        return tag

    def _track_statement(self, tag: _Tag, statement: re.Match[str] | None) -> None:
        """Follow block depth and capturing blocks; flag sets of secret-looking names."""
        keyword = statement.group("keyword").lower() if statement else ""
        if statement and keyword == "set":
            tail = _STATEMENT_TAIL.search(tag.text)
            end = tail.start() if tail else len(tag.text)
            assign = _top_level_assign(tag.blank, statement.end(), end)
            target = tag.blank[statement.end() : assign if assign >= 0 else end].split("|")[0]
            if assign < 0:
                self._open_block("set", _is_secret_name(target))
            elif _is_secret_name(target):
                tag.secret_assign = assign
        elif keyword in _CAPTURING:
            self._open_block(keyword, keyword == "call")
        elif keyword in _BLOCK_OPENERS:
            self.depth += 1
        elif keyword.startswith("end"):
            self.depth = max(0, self.depth - 1)
            if self.blocks and self.blocks[-1][0] == keyword[3:]:
                self.secret_blocks -= self.blocks.pop()[1]

    def _open_block(self, keyword: str, secret: bool) -> None:
        self.depth += 1
        self.blocks.append((keyword, secret))
        self.secret_blocks += secret

    def _take(self, line: list[_Token]) -> list[_Text | _Tag]:
        """A line's tokens as parts, tags tracked."""
        out: list[_Text | _Tag] = []
        for kind, text in line:
            if kind in _TAG_KINDS:
                out.append(self._tag(kind, text))
            elif kind == "unterminated":
                out.append(_Text(MASK_VALUE))
            else:
                out.append(_Text(text, self.capture))
        return out

    # -- values ----------------------------------------------------------

    def _extend(self, value: _Value, tokens: list[_Token]) -> None:
        """Add tokens to an opaque value, watching for its closing quote."""
        for kind, text in tokens:
            if kind in _TAG_KINDS:
                value.items.append(self._tag(kind, text))
            elif kind == "unterminated":
                value.items.append(MASK_VALUE)
            else:
                if value.quote and _closing_quote(text, 0, value.quote) >= 0:
                    value.quote = ""
                value.items.append(text)

    def _trim_follows(self, index: int) -> bool:
        """Whether the next non-blank token after line ``index`` strips the newline."""
        for j in range(index + 1, len(self.lines)):
            first = _significant(self.lines[j])
            if first is not None:
                return first[0] in _TAG_KINDS and _TRIM_OPEN.match(first[1]) is not None
        return False

    def _open(self, index: int, line: list[_Token], k: int, start: int) -> _Value | None:
        """Start the value at ``line[k][1][start:]``; return it if it stays open."""
        first = line[k][1][start:]
        rest = line[k + 1 :]
        newline = rest[-1:] if rest and rest[-1][0] == "nl" else []
        body = ([("text", first)] if first else []) + [t for t in rest if t[0] != "nl"]
        precise = _precise(body)
        value = _Value(depth=self.depth)
        self.parts.append(value)
        self.values.append(value)
        if precise and not self._trim_follows(index):
            value.precise, value.tail = precise
            for kind, text in body:
                value.items.append(self._tag(kind, text) if kind in _TAG_KINDS else text)
            self.parts.extend(_Text(text) for _, text in newline)
            return None
        if first[:1] in ("'", '"'):
            value.quote = first[0]
            value.items.append(first[0])
            body[0] = ("text", first[1:])
        self._extend(value, body + newline)
        return value

    # -- lines -----------------------------------------------------------

    def _track_config(self, line: list[_Token]) -> None:
        """Follow config/end, also behind tags that open the line."""
        at = next((k for k, (kind, text) in enumerate(line) if kind == "text" and text.strip()), -1)
        if at < 0:
            return
        match = _CONFIG_LINE.match(line[at][1])
        if match:
            # A path a tag writes could be a community table.
            unknown = any(kind in _TAG_KINDS for kind, _ in line[at + 1 :])
            community = unknown or is_snmp_community_block(match.group("path"))
            self.communities.append(community)
            self.in_community += community
        elif _END_LINE.match(line[at][1]) and self.communities:
            self.in_community -= self.communities.pop()

    def _line(self, index: int, line: list[_Token]) -> _Value | None:
        """Render a line of plain text and tags; return a value it leaves open."""
        first = _significant(line)
        statement = first is not None and first[0] == "text" and first[1].lstrip()[:1] in ("#", "%")
        self._track_config(line)
        for k, (kind, text) in enumerate(line):
            if kind == "text":
                start = _secret_value_start(
                    text,
                    k > 0 and line[k - 1][0] in _TAG_KINDS,
                    k + 1 < len(line) and line[k + 1][0] not in ("text", "nl"),
                    self.in_community > 0,
                )
                head = text if start < 0 else text[:start]
                if head:
                    self.parts.append(_Text(head, self.capture, statement))
                    if statement:
                        self.statement_texts.append(head)
                if start >= 0:
                    return self._open(index, line, k, start)
            elif kind == "nl":
                self.parts.append(_Text(text))
            elif kind == "unterminated":
                self.parts.append(_Text(MASK_VALUE))
            else:
                self.parts.append(self._tag(kind, text))
        return None

    def scan(self) -> None:
        value: _Value | None = None
        pending = False
        for index, line in enumerate(self.lines):
            if value is not None:
                if value.quote:
                    self._extend(value, line)
                    continue
                shape = _line_shape(line)
                if shape == "tags":
                    taken = self._take(line)
                    if self.depth <= value.depth:
                        self.parts.extend(taken)
                        value, pending = None, True
                    else:
                        value.items.extend(t.text if isinstance(t, _Text) else t for t in taken)
                    continue
                if shape != "cli":
                    self._extend(value, line)
                    continue
                value = None
            elif pending:
                shape = _line_shape(line)
                if shape in ("tags", "blank"):
                    self.parts.extend(self._take(line))
                    continue
                pending = False
                if shape != "cli":
                    value = _Value(depth=self.depth)
                    self.parts.append(value)
                    self.values.append(value)
                    self._extend(value, line)
                    continue
            value = self._line(index, line)

    # -- result ----------------------------------------------------------

    def mask_all(self) -> bool:
        """Whether a secret value could be built from the template's own literals."""
        if self.builds_directive:
            return True
        names: set[str] = set()
        bare: set[int] = set()
        for value in self.values:
            for item in value.items:
                if not isinstance(item, _Tag) or item.kind == "#":
                    continue
                match = _BARE_REFERENCE.match(item.text)
                if match is None:
                    return True
                names.add(match.group("name").split(".")[0])
                bare.add(id(item))
        if not names:
            return False
        return any(
            tag.kind != "#"
            and id(tag) not in bare
            and not names.isdisjoint(_WORD.findall(tag.blank))
            for tag in self.tags
        ) or any(not names.isdisjoint(_WORD.findall(text)) for text in self.statement_texts)

    def render(self, mask_all: bool) -> str:
        out: list[str] = []
        for part in self.parts:
            if isinstance(part, _Value):
                out.append(_render_value(part))
            elif isinstance(part, _Tag):
                out.append(_render_tag(part, mask_all))
            elif part.text.strip() and (
                part.capture == 2 or (mask_all and (part.capture or part.line_statement))
            ):
                out.append(MASK_VALUE)
            else:
                out.append(part.text)
        return "".join(out)


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


def _render_tag(tag: _Tag, mask_all: bool) -> str:
    text = tag.text
    if tag.kind == "#":
        body = text[2:-2]
        return text[:2] + _redact(body, False, "{%" in body or "{{" in body) + text[-2:]
    if tag.code_directive:
        return text[:2] + MASK_VALUE + text[-2:]
    if tag.secret_assign >= 0:
        rest = text[tag.secret_assign + 1 :]
        start = len(text) - len(rest.lstrip())
        tail = _STATEMENT_TAIL.search(text)
        return text[:start] + MASK_VALUE + text[tail.start() if tail else len(text) :]
    out: list[str] = []
    last = 0
    for start, end in tag.spans:
        literal = text[start:end]
        quoted = literal[0] in "'\""
        if not (mask_all or (quoted and _holds_directive(literal[1:-1]))):
            continue
        out.append(text[last:start])
        out.append(f"{literal[0]}{MASK_VALUE}{literal[0]}" if quoted else MASK_VALUE)
        last = end
    text = "".join(out) + text[last:]
    return _JINJA_SECRET_LITERAL.sub(
        lambda m: f"{m.group('key')}{m.group('lq')}{MASK_VALUE}{m.group('lq')}", text
    )


def _render_value(value: _Value) -> str:
    if value.precise == "keep":
        return "".join(item if isinstance(item, str) else item.text for item in value.items)
    if value.precise == "mask":
        return MASK_VALUE + value.tail
    if all(isinstance(item, str) and not item.strip() for item in value.items):
        return "".join(str(item) for item in value.items)
    if not str(value.items[-1]).endswith("\n"):
        return MASK_VALUE
    before = value.items[-2] if len(value.items) > 1 else ""
    return MASK_VALUE + ("\r\n" if isinstance(before, str) and before.endswith("\r") else "\n")


def _redact(script: str, plain: bool, mask_all: bool) -> str:
    scanner = _Scanner(_tokenize(script, plain))
    scanner.scan()
    return scanner.render(mask_all or scanner.mask_all())


def redact_cli_template_script(script: str, template_type: Any = None) -> str:
    """Mask secrets in a CLI template body.

    ``template_type`` is the template's ``type`` ("cli"/0 or "jinja"/1); a
    plain CLI template is scanned as CLI text, anything else as Jinja.
    Keeps the directive or variable name visible, so the result still shows
    that a template sets a password and, for a bare ``{{ var }}`` or
    ``$(var)`` reference, which variable it comes from. See the comment
    block above for what is masked when.
    """
    return _redact(script, _is_plain_cli_type(template_type), False)


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
    and ENC blobs, SNMP community names, secret-named Jinja ``{% set %}``
    assignments, and secret-keyed string literals inside Jinja tags. A bare
    variable reference (``set psksecret {{ psk }}``, ``$(psk)``) is kept,
    since it names where the value comes from. Any other value is masked up
    to the next CLI line, and if a Jinja template could compute a secret
    from its own constants, those constants are masked too. A template whose
    ``type`` is "cli" is read as plain CLI; any other type as Jinja.

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
                "script": (
                    redact_cli_template_script(script, template.get("type"))
                    if isinstance(script, str)
                    else script
                ),
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
