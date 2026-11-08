"""Fail-closed redaction: CLI templates, install previews and free text.

Every dummy secret below contains the marker ``S3CR``; a redactor passes a
case when no marker comes back. The cases are the reproductions from the
1.13.1 second re-audit, kept verbatim so a regression shows the exact form
that leaked.
"""

import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import template_tools
from fortimanager_mcp.tools.device_proxy_tools import _is_secret_field
from fortimanager_mcp.utils.install_preview import redact_preview, redact_task_text
from fortimanager_mcp.utils.responses import redact
from fortimanager_mcp.utils.validation import redact_config_text_secrets

MARK = "S3CR"


def _redact(script: str, template_type: Any = None) -> str:
    return template_tools.redact_cli_template_script(script, template_type)


# -----------------------------------------------------------------------------
# CLI templates
# -----------------------------------------------------------------------------

#: A secret value continued across lines by whitespace control or trim_blocks.
WHITESPACE_CONTROL = {
    "ws_if_multiline": (
        "config vpn ipsec phase1-interface\n edit vpn1\n  set psksecret {% if site == 'A' -%}\n"
        "    S3CRa\n  {%- else -%}\n    S3CRb\n  {%- endif %}\n next\nend\n"
    ),
    "ws_expr_nl": "set password {{ '' -}}\nS3CRc\n",
    "ws_comment_nl": "set password {#- c -#}\n  S3CRd\n",
    "trim_blocks_style": "set password {% if x %}\nS3CR1\n{% endif %}\n",
    "ltrim_next_line": 'set password "abc"\n{%- if x %}S3CRe{% endif %}\nnext\n',
    "ltrim_after_ref": "set password {{ p }}\n\n   {{- 'S3CRf' }}\nnext\n",
    "rtrim_bare_ref": "set password {{ p -}}\n  S3CRg\nnext\n",
    "trailing_endif_rtrim": "set password x{% endif -%}\n S3CRh\n",
}

#: Community names whose Jinja references must count toward mask_all.
COMMUNITY = {
    "community_hint_free": (
        "{% set ro = 'S3CR3' %}\nconfig system snmp community\nedit 1\nset name {{ ro }}\nnext\nend\n"
    ),
    "community_macro": (
        "{% macro comm() %}S3CRj{% endmacro %}\nconfig system snmp community\n edit 1\n"
        "  set name {{ comm() }}\n next\nend\n"
    ),
    "community_jinja_after": (
        "config system snmp community\nedit 1\nset name {{ c }}\nnext\nend\n{% set c = 'S3CR5' %}"
    ),
    "community_quoted_cfg": 'config "system snmp community"\nedit 1\nset name S3CR2\nnext\nend\n',
    "community_trail": "config system snmp community  # comment\nedit 1\nset name S3CR3\nnext\nend\n",
    "community_switch": "config switch-controller snmp-community\nedit 1\nset name S3CR4\nnext\nend\n",
    "community_wireless": "config community\nedit 1\nset name S3CR6\nnext\nend\n",
    "community_upper": "CONFIG SYSTEM SNMP COMMUNITY\nEDIT 1\nSET NAME S3CR7\nNEXT\nEND\n",
    "community_behind_tag": (
        "{% set c = 'S3CR6' %}config system snmp community\nedit 1\nset name {{ c }}\nnext\nend\n"
    ),
}

#: Remaining probe cases (p1-p3) that leaked before this change.
CONSTRUCTS = {
    "comment_tag2": "{# {% set p = 'S3CR8' %} #}set password {{ p }}",
    "comment_old_pw": "{# {% set p = 'S3CR2' %} #}",
    "expr_tag2": "{{ 'set pass' ~ 'word S3CRH' }}",
    "nbsp_set": "set\xa0password S3CRI\n",
    "quoted_dir": 'set "password" S3CRP\n',
    "underscore_dir": "set private_key S3CRQ\n",
    "set_in_macro_call": "{% call m() %}S3CRU{% endcall %}",
    "line_stmt": "# set p = 'S3CRZ'\nset password {{ p }}\n",
    "nested_dict_update": (
        "{% set d = {} %}{{ d.update({'k': {'q': 1}}, p='S3CRg') or '' }}set password {{ d.p }}\n"
    ),
    "cli_pw_with_brace": 'set password "Ab{#Cd"\nset comments "S3CRl#}"\n',
    "cli_pw_brace2": 'config system admin\n edit a\n  set password "x{{S3CRm"\n next\nend\nset alias "}}"\n',
    "cli_pw_brace3": 'set password "x{%S3CRn"\nset alias "%}"\n',
    "enc_after_tag": "set {{ field }} ENC S3CRq\n",
    "dir_from_tag": "set {{ 'password' }} S3CRr\n",
    "dir_tag_concat": "set pass{{ 'word' }} S3CRs\n",
    "dir_after_expr": "{{ 'set' }} password S3CRt\n",
    "set_glued_tag": "set{{ ' password' }} S3CRu\n",
    "set_metavar_dir": "set $(field) S3CRv\n",
    "literal_builds_directive": "{% set p = 'S3CRw' %}{{ 'set password ' ~ p }}\n",
}


@pytest.mark.parametrize(
    "script",
    [*WHITESPACE_CONTROL.values(), *COMMUNITY.values(), *CONSTRUCTS.values()],
    ids=[*WHITESPACE_CONTROL, *COMMUNITY, *CONSTRUCTS],
)
def test_template_secret_does_not_come_back(script: str) -> None:
    out = _redact(script)
    assert MARK not in out, out


def test_whitespace_control_masks_to_the_next_cli_line() -> None:
    out = _redact(WHITESPACE_CONTROL["ws_if_multiline"])
    assert out == (
        "config vpn ipsec phase1-interface\n edit vpn1\n  set psksecret ***REDACTED***\n"
        "  {%- endif %}\n next\nend\n"
    )


def test_a_closing_tag_line_does_not_reopen_plain_text() -> None:
    # After the value ends at a closing tag line, a line that is not CLI is
    # still treated as part of it (trim_blocks can join it to the value).
    out = _redact("set password {% if a %}\nx\n{% endif %}\nS3CRx\nnext\n")
    assert MARK not in out
    assert out.endswith("{% endif %}\n***REDACTED***\nnext\n")


def test_precise_values_keep_their_reference() -> None:
    script = (
        "config system snmp community\n edit 1\n  set name {{ snmp_ro }}\n next\nend\n"
        "config system admin\n edit a\n  set password $(pw)\n  set accprofile x\n next\nend\n"
        'set psksecret "{{ psk }}"\n'
    )
    assert _redact(script) == script
    assert _redact('set password "abc"\nnext\n') == "set password ***REDACTED***\nnext\n"


class TestPlainCliTemplate:
    """Type 0 ("cli") templates are FortiOS CLI: braces are not Jinja there."""

    BRACE = 'config system admin\n edit a\n  set password "x{{S3CR"\n next\nend\nset alias "}}"\n'

    @pytest.mark.parametrize("template_type", [0, "0", "cli", "CLI"])
    def test_braces_in_a_plain_template_are_text(self, template_type: Any) -> None:
        out = _redact(self.BRACE, template_type)
        assert MARK not in out
        assert out == (
            'config system admin\n edit a\n  set password ***REDACTED***\n next\nend\nset alias "}}"\n'
        )

    @pytest.mark.parametrize("template_type", [None, 1, "jinja", "unknown", True])
    def test_unknown_or_jinja_type_fails_closed(self, template_type: Any) -> None:
        assert MARK not in _redact(self.BRACE, template_type)

    def test_plain_template_with_metavars_is_unchanged(self) -> None:
        script = (
            'config system interface\n    edit "port1"\n        set alias "WAN $(site)"\n'
            '    next\nend\nconfig system admin\n    edit "ops"\n        set password $(ops_pw)\n'
            "    next\nend\n"
        )
        assert _redact(script, 0) == script

    @pytest.mark.asyncio
    async def test_get_cli_template_passes_the_type(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {"name": "a", "type": 0, "script": self.BRACE})
        with patch.object(template_tools, "get_fmg_client", return_value=mock_client):
            result = await template_tools.get_cli_template(adom="demo", name="a")
        body = result["cli_template"]["script"]
        assert MARK not in body
        assert 'set alias "}}"' in body


# -----------------------------------------------------------------------------
# Install preview
# -----------------------------------------------------------------------------

_CLI = 'config system admin\n    edit "a"\n        set password S3CR1\n    next\nend\n'
_PEM = 'config vpn certificate local\n edit c\n  set private-key "-----BEGIN\nS3CR2\n-----END"\n next\nend\n'
_COMM = "config system snmp community\n edit 1\n  set name S3CR3\n next\nend\n"
_ENV = json.dumps([{"result": _CLI + _PEM + _COMM}])

PREVIEW = {
    "list_trunc_item": [_ENV[:-5]],
    "list_trunc_item_dbl": [json.dumps(_ENV)[:-5]],
    "list_trunc_item_mixed": ["header", _ENV[:-5], "trailer"],
    "prefixed_escaped": "Preview: " + json.dumps(_CLI)[1:-1],
    "comm_trunc_json": json.dumps({"result": _COMM})[:-3],
    "comm_trunc_compact": json.dumps({"result": _COMM}, separators=(",", ":"))[:-3],
    "Password_case": " set Password S3CR6\n",
    "env_trunc": _ENV[:-5],
}


@pytest.mark.parametrize("value", PREVIEW.values(), ids=PREVIEW)
def test_preview_secret_does_not_come_back(value: Any) -> None:
    out = redact_preview(value)
    assert MARK not in json.dumps(out), out


def test_preview_value_with_an_escaped_quote_keeps_raw_handling() -> None:
    out = redact_preview('set password "ab\\" S3CRv" \nset alias x\n')
    assert MARK not in out


@pytest.mark.parametrize("depth", [900, 100_000])
def test_deeply_nested_preview_does_not_raise(depth: int) -> None:
    redact_preview("[" * depth + "]" * depth)
    redact_preview("[" * depth)


# -----------------------------------------------------------------------------
# Free text (task lines, error messages)
# -----------------------------------------------------------------------------

TASK_TEXT = {
    "kv_json_escaped": 'payload "{\\"password\\": \\"S3CR7\\"}"',
    "kv_fat_arrow": "password => S3CR8",
    "kv_psk_space": "psksecret ENC S3CRa",
    "kv_quoted_esc": 'password="ab\\"S3CRb"',
    "inline_set_case": "err: set Password S3CRe",
    "kv_bracket": "{'password': b'S3CRi'}",
    "community_task": "config system snmp community edit 1 set name S3CRj",
    "kv_unicode_sep": "password：S3CRk",
    "enc_generic": "value ENC S3CRAbCdEfGhIjKlMnOp==",
}


@pytest.mark.parametrize("text", TASK_TEXT.values(), ids=TASK_TEXT)
def test_task_text_secret_does_not_come_back(text: str) -> None:
    assert MARK not in redact_task_text(text)


def test_redact_keeps_ordinary_text() -> None:
    text = "policy 12 install failed on device FGT-1 (vdom root): name exists"
    assert redact(text) == text


# -----------------------------------------------------------------------------
# Device proxy selector field names
# -----------------------------------------------------------------------------


def test_secret_field_spelling_with_underscores() -> None:
    assert _is_secret_field("snmp_community.name")


# -----------------------------------------------------------------------------
# 1 MB pathological inputs
# -----------------------------------------------------------------------------

MB = 1_000_000
_PLAIN = "config system interface\n edit port1\n  set ip 10.0.0.1 255.255.255.0\n next\nend\n"

PATHOLOGICAL = {
    "pw_bare_refs": (_redact, "set password {{ p }}\n" * (MB // 21)),
    "many_literals_one_tag": (_redact, "{% set x = [" + "1," * (MB // 2) + "] %}"),
    "open_set_stack": (_redact, "{% set a %}x" * (MB // 12)),
    "config_no_end": (_redact, "config a\n" * (MB // 9)),
    "tags": (_redact, "{{ a }}" * (MB // 7)),
    "unterminated": (_redact, "{%" * (MB // 2)),
    "quotes": (_redact, "{{ '" + "\\'" * (MB // 2)),
    "set_lines": (_redact, "set " * (MB // 4)),
    "long_identifier": (_redact, "{{ " + "a" * MB + " }}"),
    "long_identifier_literal": (_redact, "{{ " + "a" * MB + " ~ 'x' }}"),
    "opaque_values": (_redact, "set password {% if a %}x{% endif %}\n" * (MB // 38)),
    "blank_lines": (_redact, "set password {{ p }}\n" + "\n" * MB),
    "plain_cli": (_redact, _PLAIN * (MB // len(_PLAIN))),
    "preview_config_no_end": (redact_preview, "config a\n" * (MB // 9)),
    "preview_list": (redact_preview, ["config a"] * 100_000),
    "preview_trunc_json": (redact_preview, json.dumps([{"result": _CLI * (MB // len(_CLI))}])[:-5]),
    "revision_config_no_end": (redact_config_text_secrets, "config a\n" * (MB // 9)),
    "task_community": (redact_task_text, "community " * (MB // 10)),
    "task_many_set": (redact_task_text, "set " * (MB // 4)),
}


@pytest.mark.parametrize("fn,payload", PATHOLOGICAL.values(), ids=PATHOLOGICAL)
def test_one_megabyte_redacts_quickly(fn: Any, payload: Any) -> None:
    start = time.perf_counter()
    fn(payload)
    assert time.perf_counter() - start < 3.0
