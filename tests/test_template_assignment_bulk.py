"""Tests for assign_system_template_bulk and assign_sdwan_template_bulk.

Both submit a single ADD against a scope-member table structurally
identical to device_group_tools.add_devices_to_group_bulk (#78): FortiManager
reports no per-device result, and the client raises on any non-zero code,
so a returned len(devices) count was a claim the appliance never made.

The scope each of them sends is checked, and so is the ``vdom`` of the
single-device assign and unassign tools (#139).
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import sdwan_tools, template_tools


class TestAssignSystemTemplateBulk:
    @pytest.mark.asyncio
    async def test_reports_requested_count_not_a_fabricated_outcome(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {})

        with patch.object(template_tools, "get_fmg_client", return_value=mock_client):
            result = await template_tools.assign_system_template_bulk(
                adom="root",
                template="Branch-Profile",
                devices=[{"name": "FGT-1", "vdom": "root"}, {"name": "FGT-2", "vdom": "root"}],
            )

        assert result["success"] is True
        assert result["requested_count"] == 2
        assert "requested_count" in result
        assert "does not confirm" in result["message"]


class TestAssignSdwanTemplateBulk:
    @pytest.mark.asyncio
    async def test_reports_requested_count_not_a_fabricated_outcome(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {})

        with patch.object(sdwan_tools, "get_fmg_client", return_value=mock_client):
            result = await sdwan_tools.assign_sdwan_template_bulk(
                adom="root",
                template="Branch-SDWAN",
                devices=[{"name": "FGT-1", "vdom": "root"}],
            )

        assert result["success"] is True
        assert result["requested_count"] == 1
        assert "does not confirm" in result["message"]


#: (module, tool) for the two bulk tools. Both send ``devices`` as the
#: scope member of one ADD.
BULK_TOOLS = [
    (template_tools, "assign_system_template_bulk"),
    (sdwan_tools, "assign_sdwan_template_bulk"),
]


class TestBulkScopeIsValidated:
    """The bulk tools check each entry as add_devices_bulk does (#139 item 8).
    The ADD is mocked to succeed, so only the check can refuse."""

    @pytest.mark.parametrize(("module", "tool"), BULK_TOOLS)
    @pytest.mark.parametrize(
        "devices",
        [
            [],
            [{"vdom": "root"}],
            [{"name": "FGT-1", "vdom": ""}],
            [{"name": "FGT-1", "vdom": "root/../x"}],
            [{"name": "../x", "vdom": "root"}],
            [{"name": "FGT-1", "vdom": "root", "extra": 1}],
            {"name": "FGT-1", "vdom": "root"},
            "FGT-1",
        ],
    )
    @pytest.mark.asyncio
    async def test_a_bad_entry_is_refused(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        module: Any,
        tool: str,
        devices: Any,
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {})

        with patch.object(module, "get_fmg_client", return_value=mock_client):
            result = await getattr(module, tool)(adom="root", template="T1", devices=devices)

        assert result.get("error_code") == "validation_error"
        mock_fmg_instance.add.assert_not_called()

    @pytest.mark.parametrize(("module", "tool"), BULK_TOOLS)
    @pytest.mark.asyncio
    async def test_a_padded_entry_is_sent_stripped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        module: Any,
        tool: str,
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {})

        with patch.object(module, "get_fmg_client", return_value=mock_client):
            result = await getattr(module, tool)(
                adom="root",
                template="T1",
                devices=[{"name": " FGT-1 ", "vdom": " root "}, {"name": "FGT-2"}],
            )

        assert result["success"] is True
        assert mock_fmg_instance.add.call_args.kwargs["data"] == [
            {"name": "FGT-1", "vdom": "root"},
            {"name": "FGT-2"},
        ]


#: (module, tool, template argument, pyFMG verb) for the single-device tools.
SINGLE_TOOLS = [
    (template_tools, "assign_system_template", "template", "add"),
    (template_tools, "unassign_system_template", "template", "delete"),
    (sdwan_tools, "assign_sdwan_template", "template", "add"),
    (sdwan_tools, "unassign_sdwan_template", "template", "delete"),
    (template_tools, "assign_template_group", "template_group", "add"),
]


class TestSingleToolVdomIsValidated:
    """The single-device tools sent ``vdom`` as given (#139 item 8). It is
    checked as every other ``vdom`` argument is."""

    @pytest.mark.parametrize(("module", "tool", "template_arg", "verb"), SINGLE_TOOLS)
    @pytest.mark.parametrize("vdom", ["", "root/../x", "root;x"])
    @pytest.mark.asyncio
    async def test_a_bad_vdom_is_refused(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        module: Any,
        tool: str,
        template_arg: str,
        verb: str,
        vdom: str,
    ) -> None:
        getattr(mock_fmg_instance, verb).return_value = (0, {})

        with patch.object(module, "get_fmg_client", return_value=mock_client):
            result = await getattr(module, tool)(
                adom="root", device="FGT-1", vdom=vdom, **{template_arg: "T1"}
            )

        assert result.get("error_code") == "validation_error"
        getattr(mock_fmg_instance, verb).assert_not_called()

    @pytest.mark.parametrize(("module", "tool", "template_arg", "verb"), SINGLE_TOOLS)
    @pytest.mark.asyncio
    async def test_a_padded_vdom_is_sent_stripped(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        module: Any,
        tool: str,
        template_arg: str,
        verb: str,
    ) -> None:
        getattr(mock_fmg_instance, verb).return_value = (0, {})

        with patch.object(module, "get_fmg_client", return_value=mock_client):
            result = await getattr(module, tool)(
                adom="root", device="FGT-1", vdom=" root ", **{template_arg: "T1"}
            )

        assert result["success"] is True
        assert getattr(mock_fmg_instance, verb).call_args.kwargs["data"] == [
            {"name": "FGT-1", "vdom": "root"}
        ]
