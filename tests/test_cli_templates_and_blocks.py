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
            result = await template_tools.list_cli_templates(adom="production")

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
            result = await template_tools.get_cli_template(adom="production", name="a")

        assert mock_fmg_instance.get.call_args[0][0] == (
            "/pm/config/adom/production/obj/cli/template/a"
        )
        assert result["cli_template"]["type"] == "cli"
        assert "hunter2" not in result["cli_template"]["script"]
        assert 'edit "admin"' in result["cli_template"]["script"]

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(template_tools, "get_fmg_client", return_value=None):
            result = await template_tools.get_cli_template(adom="production", name="a")
        assert "error" in result


class TestPolicyBlocks:
    @pytest.mark.asyncio
    async def test_lists_blocks(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _client_get(mock_client, mock_fmg_instance, [{"name": "b", "type": "pblock"}])
        with patch.object(policy_tools, "get_fmg_client", return_value=mock_client):
            result = await policy_tools.list_policy_blocks(adom="production")

        assert mock_fmg_instance.get.call_args[0][0] == "/pm/pblock/adom/production"
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_reads_block_policies(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        _client_get(mock_client, mock_fmg_instance, [{"policyid": 1, "name": "p"}])
        with patch.object(policy_tools, "get_fmg_client", return_value=mock_client):
            result = await policy_tools.list_policy_block_policies(
                adom="production", block="b", fields=["name"], limit=5, offset=2
            )

        assert mock_fmg_instance.get.call_args[0][0] == (
            "/pm/config/adom/production/pblock/b/firewall/policy"
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
            await policy_tools.get_firewall_policy("production", "pkg", 6)

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
            await dvm_tools.get_device_interfaces("production", "branch3")

        resource = client.proxy_call.await_args.kwargs["resource"]
        assert resource == "/api/v2/monitor/system/interface?include_vlan=true"
