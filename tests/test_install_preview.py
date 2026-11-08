"""The complete install preview: stage, render, fetch, release.

FortiManager only previews the package asked about when the install is
staged first (flags=["preview"]) and the render names that staging task;
the staged copy must then be cancelled or the devices stay held by an
install-wizard session. Envelopes below are the shapes FMG 8.0.2 returned
live.
"""

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import policy_tools
from fortimanager_mcp.utils import install_gate, task_guard
from fortimanager_mcp.utils.config import get_settings
from fortimanager_mcp.utils.install_preview import parse_preview_message

DEVICES = [{"name": "branch1", "vdom": "root"}]

PREVIEW_CLI = (
    "=== Preview result ===\n"
    "config vpn ipsec phase1-interface\n"
    '    edit "HUB1-VPN1"\n'
    "        set psksecret ENC LiveSecret==\n"
    "    next\n"
    "end\n"
    "config firewall policy\n"
    "    edit 3\n"
    '        set service "ALL"\n'
    "    next\n"
    "end\n"
)


def _message(*results: tuple[str, str]) -> dict[str, Any]:
    return {
        "message": json.dumps([{"name": name, "oid": 1917, "result": cli} for name, cli in results])
    }


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
    get_settings.cache_clear()
    install_gate._reset()
    task_guard._reset()
    yield
    install_gate._reset()
    task_guard._reset()
    get_settings.cache_clear()


def _client(
    stage_state: int = 4,
    render_state: int = 4,
    result: Any = None,
) -> MagicMock:
    client = MagicMock()
    client.install_package = AsyncMock(return_value={"task": 11})
    client.install_device = AsyncMock(return_value={"task": 11})
    client.install_preview = AsyncMock(return_value={"task": 12})
    client.get_task = AsyncMock(
        side_effect=lambda tid: {"state": stage_state if tid == 11 else render_state}
    )
    client.get_task_line = AsyncMock(
        return_value=[
            {
                "name": "branch1[copy]",
                "state": 5,
                "detail": "Aborted due to previous error",
                "history": [
                    {
                        "detail": "Compiling dynamic interface (seq 1, id voice.fortilink) "
                        "fail: invalid value"
                    }
                ],
            }
        ]
    )
    client.get_preview_result = AsyncMock(
        return_value=result if result is not None else _message(("branch1", PREVIEW_CLI))
    )
    client.cancel_install = AsyncMock(return_value={})
    client.get_package = AsyncMock(return_value={"obj ver": 10})
    return client


async def _preview(client: MagicMock, package: str | None = "sites_BRANCH_PPKG") -> Any:
    with patch.object(policy_tools, "get_fmg_client", return_value=client):
        return await policy_tools.preview_install("production", package, DEVICES)


class TestPreviewFlow:
    @pytest.mark.asyncio
    async def test_stages_renders_with_staging_task_and_releases(self) -> None:
        client = _client()
        result = await _preview(client)

        assert result["status"] == "success"
        client.install_package.assert_awaited_once_with(
            adom="production", pkg="sites_BRANCH_PPKG", scope=DEVICES, flags=["preview"]
        )
        # The render names the staging task: without it FMG previews its
        # last install task instead of this package.
        assert client.install_preview.await_args.kwargs["preview_taskid"] == 11
        client.get_preview_result.assert_awaited_once_with("production", DEVICES, preview_taskid=11)
        client.cancel_install.assert_awaited_once_with("production", preview_taskid=11)
        assert result["task_id"] == 12
        assert result["staging_task_id"] == 11

    @pytest.mark.asyncio
    async def test_returns_per_device_cli_redacted(self) -> None:
        result = await _preview(_client())

        [device] = result["devices"]
        assert device["name"] == "branch1"
        assert device["has_changes"] is True
        assert 'set service "ALL"' in device["preview"]
        assert "LiveSecret" not in device["preview"]
        assert "set psksecret ***REDACTED***" in device["preview"]

    @pytest.mark.asyncio
    async def test_no_preview_result_means_no_changes(self) -> None:
        client = _client(result=_message(("branch1", "=== No preview result ===\n")))
        result = await _preview(client)
        assert result["devices"][0]["has_changes"] is False
        assert result["message"] == "Install would push no changes"

    @pytest.mark.asyncio
    async def test_records_the_render_task_for_the_install_gate(self) -> None:
        await _preview(_client())
        assert install_gate.find_preview("production", "sites_BRANCH_PPKG", DEVICES) == 12
        assert install_gate.recorded_revision("production", "sites_BRANCH_PPKG", DEVICES) == 10

    @pytest.mark.asyncio
    async def test_device_settings_preview_stages_install_device(self) -> None:
        client = _client()
        result = await _preview(client, package=None)

        assert result["status"] == "success"
        client.install_device.assert_awaited_once_with(
            adom="production", scope=DEVICES, flags=["preview"]
        )
        client.install_package.assert_not_called()
        # No package, nothing for the package install gate to authorize.
        assert install_gate._PREVIEWS == {}

    @pytest.mark.asyncio
    async def test_releases_task_slots(self) -> None:
        await _preview(_client())
        assert task_guard.in_flight() == 0


class TestNothingToInstall:
    @pytest.mark.asyncio
    async def test_no_changes_is_not_a_failure(self) -> None:
        client = _client(stage_state=8)
        client.get_task_line = AsyncMock(
            return_value=[{"name": "production:", "state": 8, "detail": "no changes on device"}]
        )

        result = await _preview(client, package=None)

        assert result["status"] == "success"
        assert result["devices"] == [{"name": "branch1", "has_changes": False, "preview": ""}]
        assert result["message"] == "Install would push no changes"
        client.install_preview.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_other_warning_stays_a_failure(self) -> None:
        client = _client(stage_state=8)
        client.get_task_line = AsyncMock(
            return_value=[{"name": "branch1", "state": 8, "detail": "device is locked"}]
        )

        result = await _preview(client, package=None)

        assert result["status"] == "error"
        assert result["task_lines"][0]["detail"] == "device is locked"


class TestPreviewFailure:
    @pytest.mark.asyncio
    async def test_failed_stage_returns_fmg_reason_and_still_releases(self) -> None:
        client = _client(stage_state=5)
        result = await _preview(client)

        assert result["status"] == "error"
        assert result["error"] == "preview_failed"
        assert result["step"] == "stage"
        assert result["task_id"] == 11
        assert "voice.fortilink" in json.dumps(result["task_lines"])
        client.install_preview.assert_not_called()
        client.cancel_install.assert_awaited_once_with("production", preview_taskid=11)
        assert install_gate._PREVIEWS == {}

    @pytest.mark.asyncio
    async def test_failed_render_still_releases_the_stage(self) -> None:
        client = _client(render_state=5)
        result = await _preview(client)

        assert result["error"] == "preview_failed"
        assert result["step"] == "render"
        client.cancel_install.assert_awaited_once_with("production", preview_taskid=11)

    @pytest.mark.asyncio
    async def test_result_fetch_error_still_releases_the_stage(self) -> None:
        client = _client()
        client.get_preview_result.side_effect = RuntimeError("no devices")
        result = await _preview(client)

        assert result["status"] == "error"
        client.cancel_install.assert_awaited_once_with("production", preview_taskid=11)

    @pytest.mark.asyncio
    async def test_cancel_failure_does_not_lose_the_preview(self) -> None:
        client = _client()
        client.cancel_install.side_effect = RuntimeError("session gone")
        result = await _preview(client)
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_empty_scope_is_refused_before_staging(self) -> None:
        client = _client()
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            result = await policy_tools.preview_install("production", "pkg", [])
        assert result["status"] == "error"
        client.install_package.assert_not_called()


class TestPreviewEnvelope:
    def test_decodes_the_json_message(self) -> None:
        decoded = parse_preview_message(_message(("branch1", PREVIEW_CLI)))
        assert decoded is not None
        assert decoded[0]["result"] == PREVIEW_CLI

    def test_plain_text_message_is_not_an_envelope(self) -> None:
        assert parse_preview_message({"message": "config system admin\nend\n"}) is None
        assert parse_preview_message({"status": 1}) is None

    @pytest.mark.asyncio
    async def test_get_preview_result_redacts_inside_the_json_message(self) -> None:
        """Redacting the still-encoded message misses every secret: its
        newlines are \\n escapes, so no line starts with 'set psksecret'."""
        client = _client()
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            result = await policy_tools.get_preview_result("production", DEVICES, 11)

        assert result["status"] == "success"
        assert "LiveSecret" not in json.dumps(result)
        assert result["preview"]["message"][0]["name"] == "branch1"
        client.get_preview_result.assert_awaited_once_with("production", DEVICES, preview_taskid=11)
