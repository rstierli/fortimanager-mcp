"""Tests for the script execution log tools.

FortiManager answers the script-log endpoints with a success envelope and no
``data`` member when there is nothing to report. pyfmg hands back
``result["data"]`` when the member exists and the whole result object when it
does not, so that envelope reaches the client as if it were a record.
"""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import script_tools

# What pyfmg returns for a response with no ``data`` member, as FortiManager
# 8.0.2 sends for an ADOM with no script history.
EMPTY_SUMMARY_ENVELOPE = {
    "status": {"code": 0, "message": "OK"},
    "url": "/dvmdb/adom/root/script/log/summary",
}
EMPTY_LATEST_ENVELOPE = {
    "status": {"code": 0, "message": "OK"},
    "url": "/dvmdb/adom/root/script/log/latest",
}

SUMMARY_RECORDS = [
    {"exec_time": "Thu Jun 11 23:00:06 2026", "log_id": 61, "script_name": "check-a", "seq": 1},
    {"exec_time": "Thu Jun 11 22:50:26 2026", "log_id": 41, "script_name": "check-b", "seq": 2},
]


class TestScriptLogSummary:
    @pytest.mark.asyncio
    async def test_an_envelope_with_no_data_is_not_a_log_record(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, EMPTY_SUMMARY_ENVELOPE)

        with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
            result = await script_tools.get_script_log_summary(adom="root")

        assert result == {"adom": "root", "device": None, "count": 0, "logs": []}

    @pytest.mark.asyncio
    async def test_records_are_returned_and_counted(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, SUMMARY_RECORDS)

        with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
            result = await script_tools.get_script_log_summary(adom="root")

        assert result["count"] == 2
        assert result["logs"] == SUMMARY_RECORDS

    @pytest.mark.asyncio
    async def test_a_single_record_object_is_still_one_record(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, SUMMARY_RECORDS[0])

        with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
            result = await script_tools.get_script_log_summary(adom="root")

        assert result["count"] == 1
        assert result["logs"] == [SUMMARY_RECORDS[0]]


class TestScriptLogLatest:
    @pytest.mark.asyncio
    async def test_an_envelope_with_no_data_is_reported_as_no_log(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, EMPTY_LATEST_ENVELOPE)

        with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
            result = await script_tools.get_script_log_latest(adom="root")

        assert result == {"log": None}

    @pytest.mark.asyncio
    async def test_a_log_is_returned_as_received(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        latest = {
            "content": "Starting log (Run on device)\n",
            "exec_time": "Thu Jun 11 23:00:06 2026",
        }
        mock_fmg_instance.get.return_value = (0, latest)

        with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
            result = await script_tools.get_script_log_latest(adom="root")

        assert result == {"log": latest}
