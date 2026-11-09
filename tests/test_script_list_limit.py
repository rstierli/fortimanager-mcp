"""list_scripts applies ``limit`` in the tool, so the answer says what it left out."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import script_tools


async def _list(
    mock_client: FortiManagerClient, mock_fmg_instance: MagicMock, names: int, **kwargs: Any
) -> dict[str, Any]:
    mock_client._fmg_version = (7, 6, 5)
    mock_fmg_instance.get.return_value = (0, [{"name": f"s{i}", "target": 0} for i in range(names)])
    with patch.object(script_tools, "get_fmg_client", return_value=mock_client):
        result: dict[str, Any] = await script_tools.list_scripts(adom="demo", **kwargs)
    return result


class TestListScriptsSaysWhenTheLimitCut:
    @pytest.mark.asyncio
    async def test_total_counts_what_the_default_limit_left_out(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        result = await _list(mock_client, mock_fmg_instance, 250)

        assert len(result["scripts"]) == 100
        assert (result["count"], result.get("total")) == (100, 250)

    @pytest.mark.asyncio
    async def test_a_limit_of_one_is_the_smallest_accepted(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        result = await _list(mock_client, mock_fmg_instance, 3, limit=1)

        assert [s["name"] for s in result["scripts"]] == ["s0"]
        assert (result["count"], result.get("total")) == (1, 3)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("limit", [0, -1, None, "5", 2.0, True])
    async def test_a_limit_that_is_not_a_positive_integer_is_refused(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock, limit: Any
    ) -> None:
        result = await _list(mock_client, mock_fmg_instance, 3, limit=limit)

        assert result.get("error_code") == "validation_error", result
        assert "limit" in result["error"]
        mock_fmg_instance.get.assert_not_called()
