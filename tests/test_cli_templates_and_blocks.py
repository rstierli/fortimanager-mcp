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
