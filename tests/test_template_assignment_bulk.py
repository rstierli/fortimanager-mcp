"""Tests for assign_system_template_bulk and assign_sdwan_template_bulk.

Both submit a single ADD against a scope-member table structurally
identical to device_group_tools.add_devices_to_group_bulk (#78): FortiManager
reports no per-device result, and the client raises on any non-zero code,
so a returned len(devices) count was a claim the appliance never made.
"""

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
