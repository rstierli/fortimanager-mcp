"""The complete install preview: stage, render, fetch, release.

FortiManager only previews the package asked about when the install is
staged first (flags=["preview"]) and the render names that staging task;
the staged copy must then be cancelled or the devices stay held by an
install-wizard session. Envelopes below are the shapes FMG 8.0.2 returned
live.
"""

import asyncio
import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import policy_tools, system_tools
from fortimanager_mcp.utils import install_gate, install_preview, task_guard
from fortimanager_mcp.utils.config import get_settings
from fortimanager_mcp.utils.install_preview import parse_preview_message, staged_preview_supported

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
    version: tuple[int, int, int] = (8, 0, 2),
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
    client._detect_version = AsyncMock(return_value=version)
    return client


async def _preview(client: MagicMock, package: str | None = "branch_pkg") -> Any:
    with patch.object(policy_tools, "get_fmg_client", return_value=client):
        return await policy_tools.preview_install("demo", package, DEVICES)


class TestPreviewFlow:
    @pytest.mark.asyncio
    async def test_stages_renders_with_staging_task_and_releases(self) -> None:
        client = _client()
        result = await _preview(client)

        assert result["status"] == "success"
        client.install_package.assert_awaited_once_with(
            adom="demo", pkg="branch_pkg", scope=DEVICES, flags=["preview"]
        )
        # The render names the staging task: without it FMG previews its
        # last install task instead of this package.
        assert client.install_preview.await_args.kwargs["preview_taskid"] == 11
        client.get_preview_result.assert_awaited_once_with("demo", DEVICES, preview_taskid=11)
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)
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
        assert install_gate.find_preview("demo", "branch_pkg", DEVICES) == 12
        assert install_gate.recorded_revision("demo", "branch_pkg", DEVICES) == 10

    @pytest.mark.asyncio
    async def test_device_settings_preview_stages_install_device(self) -> None:
        client = _client()
        result = await _preview(client, package=None)

        assert result["status"] == "success"
        client.install_device.assert_awaited_once_with(
            adom="demo", scope=DEVICES, flags=["preview"]
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
            return_value=[{"name": "demo:", "state": 8, "detail": "no changes on device"}]
        )

        result = await _preview(client, package=None)

        assert result["status"] == "success"
        assert result["devices"] == [{"name": "branch1", "has_changes": False, "preview": ""}]
        assert result["message"] == "FortiManager found nothing to install: no changes on device"
        assert result["task_lines"][0]["detail"] == "no changes on device"
        client.install_preview.assert_not_awaited()
        # Whatever the stage left behind is released too.
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)

    @pytest.mark.asyncio
    async def test_no_installing_devices_is_nothing_to_install(self) -> None:
        """FMG 8.0.2 ends the stage of a package not assigned to the device
        in state 8 with "No installing devices" (measured live)."""
        client = _client(stage_state=8)
        client.get_task_line = AsyncMock(
            return_value=[{"name": "demo:pkg", "state": 8, "detail": "No installing devices"}]
        )

        result = await _preview(client)

        assert result["status"] == "success"
        assert result["devices"][0]["has_changes"] is False
        assert "No installing devices" in result["message"]
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)

    @pytest.mark.asyncio
    async def test_nothing_to_install_authorizes_no_install(self) -> None:
        """The staging task (state warning) is what gets recorded, so the
        strict gate refuses: there is no reviewed change to install."""
        client = _client(stage_state=8)
        client.get_task_line = AsyncMock(
            return_value=[{"name": "demo:pkg", "state": 8, "detail": "no changes on device"}]
        )
        await _preview(client)
        assert install_gate.find_preview("demo", "branch_pkg", DEVICES) == 11

        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.install_package("demo", "branch_pkg", DEVICES)

        assert result["status"] == "error"
        assert result["error"] == "preview_required"
        assert "found nothing to install" in result["message"]
        # Only the preview's own stage call: no real install was sent.
        assert client.install_package.await_count == 1
        assert client.install_package.await_args.kwargs["flags"] == ["preview"]

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
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)
        assert install_gate._PREVIEWS == {}

    @pytest.mark.asyncio
    async def test_failed_render_still_releases_the_stage(self) -> None:
        client = _client(render_state=5)
        result = await _preview(client)

        assert result["error"] == "preview_failed"
        assert result["step"] == "render"
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)

    @pytest.mark.asyncio
    async def test_result_fetch_error_still_releases_the_stage(self) -> None:
        client = _client()
        client.get_preview_result.side_effect = RuntimeError("no devices")
        result = await _preview(client)

        assert result["status"] == "error"
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)

    @pytest.mark.asyncio
    async def test_cancel_failure_does_not_lose_the_preview(self) -> None:
        client = _client()
        client.cancel_install.side_effect = RuntimeError("session gone")
        result = await _preview(client)
        assert result["status"] == "success"
        assert result["devices"][0]["has_changes"] is True
        # ...but the caller is told the devices may still be held, and how
        # to release them.
        assert "task 11" in result["warning"]
        assert "could not be released" in result["warning"]
        assert '"preview_taskid": 11' in result["warning"]

    @pytest.mark.asyncio
    async def test_cancel_failure_after_failed_step_is_reported(self) -> None:
        client = _client(render_state=5)
        client.cancel_install.side_effect = RuntimeError("session gone")
        result = await _preview(client)
        assert result["error"] == "preview_failed"
        assert "task 11" in result["release_warning"]

    @pytest.mark.asyncio
    async def test_stage_stuck_pending_is_released(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A stage that never finishes (e.g. "Blocked by preview/install
        wizard") times out -- and is still cancelled."""
        monkeypatch.setattr(install_preview, "_POLL_INTERVAL", 0.01)
        monkeypatch.setattr(install_preview, "MIN_PREVIEW_TIMEOUT", 0)
        client = _client(stage_state=0)
        client.get_task_line = AsyncMock(
            return_value=[{"name": "branch1", "state": 0, "detail": "Blocked by preview wizard"}]
        )
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            result = await policy_tools.preview_install("demo", "branch_pkg", DEVICES, timeout=0)
        assert result["error"] == "preview_failed"
        assert result["step"] == "stage"
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("cancels", [1, 2])
    async def test_cancelled_tool_call_still_releases(self, cancels: int) -> None:
        """A tool call cancelled mid-preview (client gone, server stopping)
        sends the release from its own task, shielded from the cancel. Two
        cancels model anyio's cancel scope, which re-cancels the task at
        every await until it exits."""
        client = _client(stage_state=0)
        release_sent = asyncio.Event()

        async def slow_cancel(*args: Any, **kwargs: Any) -> dict[str, Any]:
            await asyncio.sleep(0.05)
            release_sent.set()
            return {}

        client.cancel_install = AsyncMock(side_effect=slow_cancel)
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            call = asyncio.create_task(policy_tools.preview_install("demo", "branch_pkg", DEVICES))
            await asyncio.sleep(0.05)  # staged, now polling the stage task
            for _ in range(cancels):
                call.cancel()
                await asyncio.sleep(0)
            with pytest.raises(asyncio.CancelledError):
                await call
        await asyncio.wait_for(release_sent.wait(), 1)
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)
        await asyncio.sleep(0)
        assert not install_preview._BACKGROUND_RELEASES

    @pytest.mark.asyncio
    async def test_release_refused_at_shutdown_is_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Past the shutdown budget the client refuses to send: the preview
        polls fail, the release is refused too, and the log says how to
        release the session by hand."""
        not_sent = ConnectionError("Not sent: the server is stopping")
        client = _client(stage_state=0)
        client.get_task = AsyncMock(side_effect=not_sent)
        client.cancel_install = AsyncMock(side_effect=not_sent)
        with caplog.at_level(logging.ERROR):
            result = await _preview(client)
        assert result["status"] == "error"
        assert "/securityconsole/package/cancel/install" in caplog.text
        assert '"preview_taskid": 11' in caplog.text

    @pytest.mark.asyncio
    async def test_empty_scope_is_refused_before_staging(self) -> None:
        client = _client()
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            result = await policy_tools.preview_install("demo", "pkg", [])
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
            result = await policy_tools.get_preview_result("demo", DEVICES, 11)

        assert result["status"] == "success"
        assert "LiveSecret" not in json.dumps(result)
        assert result["preview"]["message"][0]["name"] == "branch1"
        client.get_preview_result.assert_awaited_once_with("demo", DEVICES, preview_taskid=11)


class TestVersionGate:
    """preview_taskid scopes the release to this preview only where it is
    documented (FNDN 7.6.7) or measured (8.0.2). Elsewhere cancel/install is
    ADOM-wide per the docs, so the staged flow is not used."""

    @pytest.mark.parametrize(
        ("version", "staged"),
        [
            ((7, 0, 14), False),
            ((7, 2, 11), False),
            ((7, 4, 8), False),
            ((7, 6, 5), False),
            ((7, 6, 6), False),
            ((7, 6, 7), True),
            ((7, 6, 8), True),
            ((8, 0, 0), False),
            ((8, 0, 1), False),
            ((8, 0, 2), True),
            ((8, 2, 0), True),
        ],
    )
    def test_staged_preview_supported(self, version: tuple[int, int, int], staged: bool) -> None:
        assert staged_preview_supported(version) is staged

    @pytest.mark.asyncio
    async def test_older_build_keeps_the_render_only_preview(self) -> None:
        client = _client(version=(7, 4, 8))
        result = await _preview(client)

        assert result["status"] == "success"
        assert result["staged"] is False
        assert result["task_id"] == 12
        assert "wait_for_task(12)" in result["message"]
        assert "preview_taskid" in result["warning"]
        client.install_preview.assert_awaited_once_with(adom="demo", scope=DEVICES, flags=["json"])
        # Nothing staged, so nothing to release with an ADOM-wide cancel.
        client.install_package.assert_not_called()
        client.cancel_install.assert_not_called()
        # The gate still records it, as before 1.13.0.
        assert install_gate.find_preview("demo", "branch_pkg", DEVICES) == 12

    @pytest.mark.asyncio
    async def test_older_build_install_package_preview_does_not_stage(self) -> None:
        client = _client(version=(7, 6, 5))
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.install_package("demo", "branch_pkg", DEVICES, preview=True)
        assert result["status"] == "success"
        assert result["preview"] is True
        client.install_package.assert_not_called()
        client.cancel_install.assert_not_called()


class TestGateEndToEnd:
    """A fresh preview authorizes exactly one install (FMG_INSTALL_SAFETY=strict)."""

    @pytest.mark.asyncio
    async def test_one_preview_one_install(self) -> None:
        client = _client()
        await _preview(client)
        client.install_package.reset_mock()
        client.install_package.return_value = {"task": 50}

        with patch.object(system_tools, "get_fmg_client", return_value=client):
            first = await system_tools.install_package("demo", "branch_pkg", DEVICES)
            second = await system_tools.install_package("demo", "branch_pkg", DEVICES)

        assert first["status"] == "success"
        assert first["task_id"] == 50
        client.install_package.assert_awaited_once_with(
            adom="demo", pkg="branch_pkg", scope=DEVICES, flags=["none"]
        )
        assert second["status"] == "error"
        assert second["error"] == "preview_required"

    @pytest.mark.asyncio
    async def test_install_package_preview_authorizes_like_preview_install(self) -> None:
        client = _client()
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            previewed = await system_tools.install_package(
                "demo", "branch_pkg", DEVICES, preview=True
            )
        assert previewed["status"] == "success"
        assert previewed["preview"] is True
        assert previewed["devices"][0]["has_changes"] is True
        client.cancel_install.assert_awaited_once_with("demo", preview_taskid=11)
        assert install_gate.find_preview("demo", "branch_pkg", DEVICES) == 12

    @pytest.mark.asyncio
    async def test_strict_refusal_names_the_current_flow(self) -> None:
        client = _client()
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.install_package("demo", "branch_pkg", DEVICES)
        assert result["error"] == "preview_required"
        assert "Run preview_install for the same ADOM, package and devices" in result["message"]
        client.install_package.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_scope_install_refused(self) -> None:
        client = _client()
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.install_package("demo", "branch_pkg", [])
        assert result["status"] == "error"
        client.install_package.assert_not_called()
