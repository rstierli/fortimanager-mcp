"""Metadata variable and BGP template writes, and the profile group read."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import dvm_tools, sdwan_tools, security_profile_tools
from fortimanager_mcp.utils.validation import MASK_VALUE

BRANCH_ID = {
    "name": "branch_id",
    "type": 0,
    "dynamic_mapping": [
        {"_scope": [{"name": "branch1", "vdom": "global"}], "value": "1"},
        {"_scope": [{"name": "branch1", "vdom": "root"}], "value": "3"},
        {"_scope": [{"name": "branch2", "vdom": "root"}], "value": "1"},
    ],
}


def _dvm_client(variable: dict[str, Any] = BRANCH_ID) -> MagicMock:
    client = MagicMock()
    client.get_metadata_variables = AsyncMock(return_value=[variable])
    client.update_metadata_mapping = AsyncMock(return_value={})
    client.add_metadata_mapping = AsyncMock(return_value={})
    return client


async def _set(client: MagicMock, **kwargs: Any) -> dict[str, Any]:
    kwargs = {"adom": "demo", "name": "branch_id", "device": "branch1", **kwargs}
    kwargs.setdefault("value", "1")
    with patch.object(dvm_tools, "_get_client", return_value=client):
        return await dvm_tools.set_metadata_variable(**kwargs)


class TestSetMetadataVariable:
    @pytest.mark.asyncio
    async def test_changes_every_scope_of_the_device(self) -> None:
        client = _dvm_client()
        result = await _set(client)

        assert result["changes"] == [
            {"vdom": "global", "old": "1", "new": "1"},
            {"vdom": "root", "old": "3", "new": "1"},
        ]
        assert client.update_metadata_mapping.await_count == 2
        client.add_metadata_mapping.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_vdom_limits_the_change(self) -> None:
        client = _dvm_client()
        await _set(client, vdom="root")

        client.update_metadata_mapping.assert_awaited_once_with(
            "demo", "branch_id", "branch1", "root", "1"
        )

    @pytest.mark.asyncio
    async def test_device_without_mapping_gets_a_global_one(self) -> None:
        client = _dvm_client()
        await _set(client, device="branch9")

        client.add_metadata_mapping.assert_awaited_once_with(
            "demo", "branch_id", "branch9", "global", "1"
        )

    @pytest.mark.asyncio
    async def test_unknown_variable_is_refused(self) -> None:
        client = _dvm_client()
        result = await _set(client, name="missing")

        assert result["error_code"] == "not_found"
        client.update_metadata_mapping.assert_not_awaited()
        client.add_metadata_mapping.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["1\nconfig system admin", "1\r", "1\x00"])
    async def test_control_characters_are_refused(self, value: str) -> None:
        client = _dvm_client()
        result = await _set(client, value=value)

        assert result["error_code"] == "validation_error"
        client.get_metadata_variables.assert_not_awaited()
        client.update_metadata_mapping.assert_not_awaited()
        client.add_metadata_mapping.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_redaction_marker_is_not_written_back(self) -> None:
        client = _dvm_client({**BRANCH_ID, "type": 1})
        result = await _set(client, value=MASK_VALUE)

        assert result["error_code"] == "validation_error"
        client.update_metadata_mapping.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_mapping_without_vdom_is_ignored(self) -> None:
        client = _dvm_client(
            {
                **BRANCH_ID,
                "dynamic_mapping": [
                    {"_scope": [{"name": "branch1"}], "value": "7"},
                    {"_scope": [{"name": "branch1", "vdom": "root"}], "value": "3"},
                ],
            }
        )
        result = await _set(client)

        assert result["changes"] == [{"vdom": "root", "old": "3", "new": "1"}]

    @pytest.mark.asyncio
    async def test_password_values_are_not_echoed(self) -> None:
        client = _dvm_client({**BRANCH_ID, "type": 1})
        result = await _set(client, value="hunter2")

        assert "hunter2" not in str(result)
        assert "3" not in str(result["changes"])
        assert {c["new"] for c in result["changes"]} == {MASK_VALUE}

    @pytest.mark.asyncio
    async def test_client_addresses_a_mapping_by_device_and_vdom(
        self, mock_client: Any, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {})
        await mock_client.update_metadata_mapping("demo", "branch_id", "b1", "root", "1")

        assert mock_fmg_instance.update.call_args[0][0] == (
            "/pm/config/adom/demo/obj/fmg/variable/branch_id/dynamic_mapping/b1/root"
        )


def _sdwan_client() -> MagicMock:
    client = MagicMock()
    client.get_bgp_template_neighbor_group = AsyncMock(
        side_effect=[{"route-reflector-client": 0}, {"route-reflector-client": 1}]
    )
    client.update_bgp_template_neighbor_group = AsyncMock(return_value={})
    return client


async def _update(client: MagicMock, settings: dict[str, Any]) -> dict[str, Any]:
    with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
        return await sdwan_tools.update_bgp_template(
            adom="demo",
            name="sites_HUB1_BGP",
            neighbor_group="EDGE",
            settings=settings,
        )


class TestUpdateBgpTemplate:
    @pytest.mark.asyncio
    async def test_reports_before_and_after(self) -> None:
        client = _sdwan_client()
        result = await _update(client, {"route-reflector-client": "enable"})

        client.update_bgp_template_neighbor_group.assert_awaited_once_with(
            "demo", "sites_HUB1_BGP", "EDGE", {"route-reflector-client": "enable"}
        )
        assert result["before"] == {"route-reflector-client": 0}
        assert result["after"] == {"route-reflector-client": 1}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "settings",
        [
            {},
            {"remote-as": "65001"},
            {"password": "x"},
            {"route-reflector-client": True},
            {"advertisement-interval": 601},
            {"advertisement-interval": True},
        ],
    )
    async def test_refused_before_any_call(self, settings: dict[str, Any]) -> None:
        client = _sdwan_client()
        result = await _update(client, settings)

        assert "error" in result
        client.get_bgp_template_neighbor_group.assert_not_awaited()
        client.update_bgp_template_neighbor_group.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_client_url(self, mock_client: Any, mock_fmg_instance: MagicMock) -> None:
        mock_fmg_instance.update.return_value = (0, {})
        await mock_client.update_bgp_template_neighbor_group(
            "demo", "t", "EDGE", {"next-hop-self": "enable"}
        )

        assert mock_fmg_instance.update.call_args[0][0] == (
            "/pm/config/adom/demo/template/router_bgp/t/router/bgp/neighbor-group/EDGE"
        )

    @pytest.mark.asyncio
    async def test_the_group_is_read_from_the_table(
        self, mock_client: Any, mock_fmg_instance: MagicMock
    ) -> None:
        """Measured on 8.0.2: the group's own URL ignores ``fields`` and omits the flag."""
        mock_fmg_instance.get.return_value = (
            0,
            [{"name": "EDGE", "route-reflector-client": 1, "advertisement-interval": 5}],
        )
        row = await mock_client.get_bgp_template_neighbor_group(
            "demo", "t", "EDGE", ["advertisement-interval", "route-reflector-client"]
        )

        args, kwargs = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/adom/demo/template/router_bgp/t/router/bgp/neighbor-group"
        assert kwargs["fields"] == ["name", "advertisement-interval", "route-reflector-client"]
        assert kwargs["filter"] == ["name", "==", "EDGE"]
        assert row["route-reflector-client"] == 1

    @pytest.mark.asyncio
    async def test_a_missing_group_is_not_found(
        self, mock_client: Any, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])
        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client):
            result = await sdwan_tools.update_bgp_template(
                adom="demo",
                name="t",
                neighbor_group="NOPE",
                settings={"next-hop-self": "enable"},
            )

        assert result["error_code"] == "not_found"
        mock_fmg_instance.update.assert_not_called()


class TestGetProfileGroup:
    @pytest.mark.asyncio
    async def test_reads_the_group(self, mock_client: Any, mock_fmg_instance: MagicMock) -> None:
        mock_fmg_instance.get.return_value = (0, {"name": "default", "ips-sensor": ["default"]})
        with patch.object(security_profile_tools, "get_fmg_client", return_value=mock_client):
            result = await security_profile_tools.get_profile_group("demo", "default")

        assert mock_fmg_instance.get.call_args[0][0] == (
            "/pm/config/adom/demo/obj/firewall/profile-group/default"
        )
        assert result["profile_group"]["ips-sensor"] == ["default"]
