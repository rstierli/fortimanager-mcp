"""Tests for dvm_tools.delete_devices_bulk.

Uses only neutral/example values since this is a public repository.
"""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import dvm_tools


class TestDeleteDevicesBulk:
    @pytest.mark.asyncio
    async def test_deletes_a_list_of_devices(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {"taskid": 42})

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.delete_devices_bulk("root", ["FGT-Old1", "FGT-Old2"])

        assert result["status"] == "success"
        assert result["deleted_count"] == 2
        args, kwargs = mock_fmg_instance.execute.call_args
        assert args[0] == "/dvm/cmd/del/dev-list"
        assert kwargs["del-dev-member-list"] == [{"name": "FGT-Old1"}, {"name": "FGT-Old2"}]

    @pytest.mark.asyncio
    async def test_a_bare_string_is_one_device_not_iterated_as_characters(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """devices="FGT-01" must delete one device, not six single-character
        bogus device entries (upstream #71 -- the fix landed in
        device_group_tools.py but not here). Reachable via the dynamic
        dispatcher, which passes parameters as dict[str, Any] with nothing
        enforcing the list[str] annotation."""
        mock_fmg_instance.execute.return_value = (0, {"taskid": 42})

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.delete_devices_bulk("root", "FGT-01")

        assert result["status"] == "success"
        assert result["deleted_count"] == 1
        kwargs = mock_fmg_instance.execute.call_args.kwargs
        assert kwargs["del-dev-member-list"] == [{"name": "FGT-01"}]

    @pytest.mark.asyncio
    async def test_rejects_a_dict(self, mock_client: FortiManagerClient) -> None:
        """list({"devices": [...]}) returns the dict's keys, not its
        values -- a caller nesting the argument one level too deep must be
        refused, not silently add/remove a device literally named
        "devices"."""
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.delete_devices_bulk("root", {"devices": ["FGT-01"]})

        assert result["status"] == "error"
