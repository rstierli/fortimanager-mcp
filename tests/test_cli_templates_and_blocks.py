"""CLI template, policy block and task listing reads."""

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import dvm_tools, policy_tools, system_tools, template_tools


def _client_get(mock_client: FortiManagerClient, mock: MagicMock, payload: Any) -> None:
    mock.get.return_value = (0, payload)


class TestCliTemplates:
    @pytest.mark.asyncio
    async def test_list_omits_scripts(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _client_get(
            mock_client,
            mock_fmg_instance,
            [{"name": "a", "type": 1, "description": "d", "variables": ["branch_id"]}],
        )
        with patch.object(template_tools, "get_fmg_client", return_value=mock_client):
            result = await template_tools.list_cli_templates(adom="demo")

        assert result["cli_templates"] == [
            {"name": "a", "type": "jinja", "description": "d", "variables": ["branch_id"]}
        ]
        assert "script" not in mock_fmg_instance.get.call_args.kwargs["fields"]

    @pytest.mark.asyncio
    async def test_get_redacts_secrets_in_the_script(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        script = 'config system admin\n    edit "admin"\n        set password hunter2\nend\n'
        _client_get(mock_client, mock_fmg_instance, {"name": "a", "type": 0, "script": script})
        with patch.object(template_tools, "get_fmg_client", return_value=mock_client):
            result = await template_tools.get_cli_template(adom="demo", name="a")

        assert mock_fmg_instance.get.call_args[0][0] == ("/pm/config/adom/demo/obj/cli/template/a")
        assert result["cli_template"]["type"] == "cli"
        assert "hunter2" not in result["cli_template"]["script"]
        assert 'edit "admin"' in result["cli_template"]["script"]

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(template_tools, "get_fmg_client", return_value=None):
            result = await template_tools.get_cli_template(adom="demo", name="a")
        assert "error" in result


class TestPolicyBlocks:
    @pytest.mark.asyncio
    async def test_lists_blocks(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _client_get(mock_client, mock_fmg_instance, [{"name": "b", "type": "pblock"}])
        with patch.object(policy_tools, "get_fmg_client", return_value=mock_client):
            result = await policy_tools.list_policy_blocks(adom="demo")

        assert mock_fmg_instance.get.call_args[0][0] == "/pm/pblock/adom/demo"
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_reads_block_policies(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _client_get(mock_client, mock_fmg_instance, [{"policyid": 1, "name": "p"}])
        with patch.object(policy_tools, "get_fmg_client", return_value=mock_client):
            result = await policy_tools.list_policy_block_policies(
                adom="demo", block="b", fields=["name"], limit=5, offset=2
            )

        assert mock_fmg_instance.get.call_args[0][0] == (
            "/pm/config/adom/demo/pblock/b/firewall/policy"
        )
        assert mock_fmg_instance.get.call_args.kwargs["range"] == [2, 5]
        assert result["policies"] == [{"policyid": 1, "name": "p"}]


class TestScopeMember:
    @pytest.mark.asyncio
    async def test_get_firewall_policy_asks_for_install_on(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _client_get(mock_client, mock_fmg_instance, {"policyid": 6})
        with patch.object(policy_tools, "get_fmg_client", return_value=mock_client):
            await policy_tools.get_firewall_policy("demo", "pkg", 6)

        assert mock_fmg_instance.get.call_args.kwargs["option"] == ["scope member"]


class TestListTasks:
    def _tasks(self) -> list[dict[str, Any]]:
        now = int(time.time())
        return [
            {"id": 1, "start_tm": now - 7200, "line": [{"detail": "x"}]},
            {"id": 3, "start_tm": now - 60, "line": [{"detail": "y"}]},
            {"id": 2, "start_tm": now - 120, "line": [{"detail": "z"}]},
        ]

    async def _list(self, **kwargs: Any) -> dict[str, Any]:
        client = MagicMock()
        client.list_tasks = AsyncMock(return_value=self._tasks())
        with patch.object(system_tools, "_get_client", return_value=client):
            return await system_tools.list_tasks(**kwargs)

    @pytest.mark.asyncio
    async def test_newest_first_without_lines(self) -> None:
        result = await self._list(limit=2)

        assert [t["id"] for t in result["tasks"]] == [3, 2]
        assert result["total"] == 3
        assert all("line" not in t for t in result["tasks"])

    @pytest.mark.asyncio
    async def test_since_hours(self) -> None:
        result = await self._list(since_hours=1)
        assert [t["id"] for t in result["tasks"]] == [3, 2]

    @pytest.mark.asyncio
    async def test_include_lines(self) -> None:
        result = await self._list(include_lines=True)
        assert all("line" in t for t in result["tasks"])


class TestDeviceInterfaces:
    @pytest.mark.asyncio
    async def test_asks_for_vlans(self) -> None:
        client = MagicMock()
        client.proxy_call = AsyncMock(return_value=[])
        with patch.object(dvm_tools, "_get_client", return_value=client):
            await dvm_tools.get_device_interfaces("demo", "branch3")

        resource = client.proxy_call.await_args.kwargs["resource"]
        assert resource == "/api/v2/monitor/system/interface?include_vlan=true"


class TestCliTemplateRedaction:
    """redact_cli_template_script: CLI and Jinja bodies (1.13.0 review)."""

    @staticmethod
    def _redact(script: str) -> str:
        return template_tools.redact_cli_template_script(script)

    def test_plain_set_secret_is_masked(self) -> None:
        out = self._redact("config vpn ipsec phase1-interface\n    set psksecret s3cr3t\nend")
        assert "s3cr3t" not in out
        assert "set psksecret ***REDACTED***" in out
        assert out.endswith("end")

    def test_enc_value_is_masked_whatever_the_directive(self) -> None:
        out = self._redact('set password ENC AbCdEf==\nset custom-field "ENC QWERTY=="\n')
        assert "AbCdEf" not in out
        assert "QWERTY" not in out

    def test_bare_variable_reference_is_kept(self) -> None:
        script = (
            'set psksecret {{ psk }}\nset password "{{ admin.password }}"\nset psksecret $(psk)'
        )
        assert self._redact(script) == script

    def test_reference_with_a_filter_or_literal_is_masked(self) -> None:
        out = self._redact(
            "set psksecret {{ psk | default('fallback-psk') }}\nset password {{ \"lit\" ~ suffix }}"
        )
        assert "fallback-psk" not in out
        assert '"lit"' not in out

    def test_set_after_a_jinja_tag_on_the_same_line(self) -> None:
        out = self._redact("{% if hub %}set psksecret hubsecret{% endif %}")
        assert "hubsecret" not in out
        assert out.startswith("{% if hub %}set psksecret ***REDACTED***")
        assert out.endswith("{% endif %}")

    def test_conditional_literal_value_is_masked(self) -> None:
        out = self._redact("set password {% if a %}one{% else %}two{% endif %}")
        assert "one" not in out and "two" not in out

    def test_jinja_inline_set_with_secret_name(self) -> None:
        out = self._redact(
            '{% set psk = "k1" %}\n{%- set hub_pass = \'k2\' -%}\n{% set hostname = "branch1" %}'
        )
        assert "k1" not in out and "k2" not in out
        assert "{% set psk = ***REDACTED*** %}" in out
        assert '{% set hostname = "branch1" %}' in out

    def test_jinja_block_set_with_secret_name(self) -> None:
        out = self._redact("{% set tunnel_key %}\nmultiline-secret\n{% endset %}\nnext")
        assert "multiline-secret" not in out
        assert out.endswith("next")

    def test_jinja_dict_and_keyword_literals(self) -> None:
        out = self._redact(
            '{% set creds = {"user": "admin", "password": "p1"} %}\n'
            "{{ render(psk='p2', name='hub1') }}\n"
            '{% if snmp_community == "p3" %}x{% endif %}'
        )
        for leaked in ("p1", "p2", "p3"):
            assert f'"{leaked}"' not in out and f"'{leaked}'" not in out
        assert '"admin"' in out
        assert "name='hub1'" in out

    def test_multiline_quoted_value_is_dropped_to_its_closing_quote(self) -> None:
        for quote in ('"', "'"):
            out = self._redact(
                f"set private-key {quote}-----BEGIN KEY-----\nbody\n-----END KEY-----{quote}\nnext"
            )
            assert "body" not in out and "END KEY" not in out, quote
            assert out == "set private-key ***REDACTED***\nnext"

    def test_non_secret_lines_are_untouched(self) -> None:
        script = (
            "config system interface\n"
            '    edit "{{ wan }}"\n'
            "        set alias wan1\n"
            "        set ip 192.0.2.1 255.255.255.0\n"
            "    next\n"
            "end"
        )
        assert self._redact(script) == script

    def test_set_after_a_jinja_comment_on_the_same_line(self) -> None:
        out = self._redact("{# note #}set password Secr3t\n{#- n -#}  set psksecret Secr3t")
        assert "Secr3t" not in out
        assert out.startswith("{# note #}set password ***REDACTED***")

    def test_pw_names_are_secret(self) -> None:
        out = self._redact(
            "{% set pw = 'Secr3t1' %}\n{% set admin_pwd = 'Secr3t2' %}\n"
            "{% set root_passwd = 'Secr3t3' %}"
        )
        for leaked in ("Secr3t1", "Secr3t2", "Secr3t3"):
            assert leaked not in out, leaked

    def test_assignment_behind_a_secret_set_reference_is_masked(self) -> None:
        script = (
            "{% set x = 'Secr3t' %}\n"
            "{% set y %}Secr3t2{% endset %}\n"
            "{% set creds = namespace(v='Secr3t3') %}\n"
            "set password {{ x }}\n"
            "set psksecret {{ y | trim }}\n"
            'set passwd "{{ creds.v }}"\n'
        )
        out = self._redact(script)
        for leaked in ("Secr3t", "Secr3t2", "Secr3t3"):
            assert leaked not in out, leaked
        # The reference itself stays visible: it says where the value is from.
        assert "set password {{ x }}" in out
        assert 'set passwd "{{ creds.v }}"' in out

    def test_secret_keys_inside_a_dict_literal_are_masked(self) -> None:
        out = self._redact(
            "{% set admin = {'name':'x','pw':'Secr3t'} %}\n"
            '{% set wifi = {"ssid": "corp", "wifi_passphrase": "Secr3t2"} %}'
        )
        assert "Secr3t" not in out
        assert "'name':'x'" in out
        assert '"ssid": "corp"' in out

    def test_block_set_with_a_filter_is_masked(self) -> None:
        out = self._redact(
            "{% set psk | trim %}Secr3t{% endset %}\n"
            "{%- set tunnel_key | replace('a', 'b') -%}\nSecr3t2\n{%- endset -%}\nnext"
        )
        assert "Secr3t" not in out
        assert out.endswith("next")

    def test_legit_jinja_template_is_untouched(self) -> None:
        script = (
            "{# Branch bootstrap #}\n"
            "{% set wan = 'port1' %}\n"
            "{% set site = {'name': 'b1', 'id': 1} %}\n"
            "{% set banner | upper %}welcome{% endset %}\n"
            "config system interface\n"
            '    edit "{{ wan }}"\n'
            "        set alias {{ site.name }}\n"
            "        set description {{ banner }}\n"
            "    next\n"
            "end\n"
            "{# admin #}set password {{ admin_password }}\n"
            "set psksecret $(psk)"
        )
        assert self._redact(script) == script

    # 1.13.1 re-audit: the redactor tokenizes the template instead of
    # matching one pattern per construct; each case below is a regression pin.

    def _assert_masked(self, script: str, *secrets: str) -> str:
        out = self._redact(script)
        for secret in secrets:
            assert secret not in out, (secret, out)
        return out

    def test_every_set_on_one_line_is_examined(self) -> None:
        out = self._assert_masked(
            "{% if x %}set password {{ a }}{% else %}set password Lit4{% endif %}", "Lit4"
        )
        assert out.startswith("{% if x %}set password {{ a }}{% else %}set password ***")
        self._assert_masked(
            "{% if a %}set alias x{% endif %}{% if b %}set psksecret Lit6{% endif %}", "Lit6"
        )
        self._assert_masked("set alias x\rset password Lit7", "Lit7")

    def test_plus_openers(self) -> None:
        self._assert_masked("{%+ set q='Lit7' %}\nset password {{ q }}", "Lit7")
        self._assert_masked("{%+ set psk %}Lit8{%+ endset %}", "Lit8")
        self._assert_masked("{%+ set psk = 'Lit9' %}", "Lit9")

    def test_tuple_targets(self) -> None:
        self._assert_masked("{% set (psk, y) = ('Lit9', 1) %}", "Lit9")
        self._assert_masked("{% set (a, b) = ('Lit10', 1) %}\nset password {{ a }}", "Lit10")
        self._assert_masked("{% set a, b = 'Lit11', 'x' %}\nset password {{ a }}", "Lit11")

    def test_tag_closer_inside_a_string_literal(self) -> None:
        self._assert_masked("{% set q = 'a%}Lit9' %}\nset password {{ q }}", "Lit9")
        self._assert_masked("{% set psk = 'ab%}Lit11' %}", "Lit11")

    def test_literals_reaching_a_secret_through_other_constructs(self) -> None:
        for script, secret in (
            ("{% macro m() %}Lit13{% endmacro %}\nset password {{ m() }}", "Lit13"),
            ("{% for x in ['Lit14'] %}\nset password {{ x }}\n{% endfor %}", "Lit14"),
            ("{% with s = 'Lit15' %}\nset password {{ s }}\n{% endwith %}", "Lit15"),
            ("{% set ns = namespace(k='Lit27') %}\nset password {{ ns.k }}", "Lit27"),
            ("{% set l = [] %}{% do l.append('Lit28') %}\nset password {{ l[0] }}", "Lit28"),
            ("{% set pin = 4711 %}\nset sim-pin {{ pin }}", "4711"),
            ("{% set q %}Lit16\nset password {{ q }}", "Lit16"),
        ):
            self._assert_masked(script, secret)

    def test_the_reference_stays_readable_when_literals_are_masked(self) -> None:
        out = self._redact("{% set wan = 'port1' %}{% set q = 'Lit1' %}\nset password {{ q }}")
        assert "Lit1" not in out and "port1" not in out
        assert "set password {{ q }}" in out
        assert "{% set wan = " in out

    def test_unterminated_tag_masks_the_rest(self) -> None:
        out = self._assert_masked("set alias a\n{% set x = 'Lit1", "Lit1")
        assert out.startswith("set alias a\n")

    def test_secret_inside_a_jinja_comment(self) -> None:
        self._assert_masked("{# old: set password Lit1 #}\nend", "Lit1")

    def test_uppercase_and_tabs(self) -> None:
        self._assert_masked("SET PASSWORD Lit1\nset\tpsksecret Lit2", "Lit1", "Lit2")

    def test_quoted_value_around_a_reference(self) -> None:
        script = 'set password "{{ x }}"\nset psksecret "$(psk)"\nnext'
        assert self._redact(script) == script
        self._assert_masked('set password "ab{{ x }}Lit1"', "Lit1", "ab")

    def test_secret_directive_inside_a_literal(self) -> None:
        self._assert_masked("{{ 'set password Lit1' }}", "Lit1")

    @pytest.mark.asyncio
    async def test_get_cli_template_uses_the_template_redactor(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        script = "{% set psk = 'k1' %}\nset psksecret {{ psk }}\n"
        _client_get(mock_client, mock_fmg_instance, {"name": "a", "type": 1, "script": script})
        with patch.object(template_tools, "get_fmg_client", return_value=mock_client):
            result = await template_tools.get_cli_template(adom="demo", name="a")

        body = result["cli_template"]["script"]
        assert "k1" not in body
        assert "set psksecret {{ psk }}" in body
