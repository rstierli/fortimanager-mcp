"""Async-task anti-exhaustion guard (bundle C of #11).

Covers the shared in-flight budget for task-spawning tools (spawn_guarded /
mark_task_done / TTL reclaim) and the deadline-bounded polling contract in
wait_for_task.
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import system_tools
from fortimanager_mcp.utils import task_guard
from fortimanager_mcp.utils.task_guard import (
    TASK_CONCURRENCY_LIMIT,
    TaskSlotsExhausted,
    in_flight,
    mark_task_done,
    spawn_guarded,
)


@pytest.fixture(autouse=True)
def _clean_slots() -> Any:
    """Each test starts and ends with an empty slot registry."""
    task_guard._reset()
    yield
    task_guard._reset()


async def _submit_task(task_id: int = 42) -> dict[str, Any]:
    return {"task": task_id}


class TestSpawnGuarded:
    @pytest.mark.asyncio
    async def test_spawn_holds_slot_until_done(self) -> None:
        """A spawned task holds a slot; mark_task_done releases it."""
        result = await spawn_guarded("install_package", lambda: _submit_task(42))
        assert result == {"task": 42}
        assert in_flight() == 1
        mark_task_done(42)
        assert in_flight() == 0

    @pytest.mark.asyncio
    async def test_dvm_style_taskid_key_is_recognized(self) -> None:
        """Results using the 'taskid' key (dvm endpoints) also bind the slot."""

        async def submit() -> dict[str, Any]:
            return {"taskid": 7}

        await spawn_guarded("add_device", submit)
        assert in_flight() == 1
        mark_task_done(7)
        assert in_flight() == 0

    @pytest.mark.asyncio
    async def test_no_task_in_result_releases_slot(self) -> None:
        """A synchronous result (no task id) does not hold a slot."""

        async def submit() -> dict[str, Any]:
            return {"status": "done synchronously"}

        await spawn_guarded("install_package", submit)
        assert in_flight() == 0

    @pytest.mark.asyncio
    async def test_submit_failure_releases_slot(self) -> None:
        """A failed submit releases its reservation; nothing runs on the FMG."""

        async def submit() -> dict[str, Any]:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await spawn_guarded("install_package", submit)
        assert in_flight() == 0

    @pytest.mark.asyncio
    async def test_exhausted_refuses_fast_without_submitting(self) -> None:
        """At the limit, spawn_guarded raises and never calls submit."""
        for i in range(TASK_CONCURRENCY_LIMIT):
            await spawn_guarded("install_package", lambda i=i: _submit_task(i))

        submit = AsyncMock()
        with pytest.raises(TaskSlotsExhausted) as exc:
            await spawn_guarded("execute_script_on_device", submit)
        submit.assert_not_called()
        msg = str(exc.value)
        assert "execute_script_on_device" in msg
        assert str(TASK_CONCURRENCY_LIMIT) in msg

    @pytest.mark.asyncio
    async def test_concurrent_spawns_cannot_overshoot(self) -> None:
        """The slot is reserved before submit is awaited, so racing spawns
        cannot exceed the limit even while every submit is still pending."""
        release = asyncio.Event()

        async def slow_submit() -> dict[str, Any]:
            await release.wait()
            return {"task": 1}

        pending = [
            asyncio.ensure_future(spawn_guarded("install_package", slow_submit))
            for _ in range(TASK_CONCURRENCY_LIMIT)
        ]
        await asyncio.sleep(0)  # let every spawn reserve its slot

        with pytest.raises(TaskSlotsExhausted):
            await spawn_guarded("install_package", slow_submit)

        release.set()
        await asyncio.gather(*pending)

    @pytest.mark.asyncio
    async def test_ttl_reclaims_abandoned_slot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A slot whose task is never observed terminal expires after the TTL,
        so a caller that never polls cannot permanently exhaust the budget."""
        monkeypatch.setattr(task_guard, "TASK_SLOT_TTL", 0.0)
        await spawn_guarded("install_package", lambda: _submit_task(42))
        assert in_flight() == 0  # expired immediately and reclaimed

    @pytest.mark.asyncio
    async def test_mark_task_done_unknown_id_is_noop(self) -> None:
        """Releasing a task id that holds no slot must not raise."""
        await spawn_guarded("install_package", lambda: _submit_task(42))
        mark_task_done(999)
        assert in_flight() == 1


def _mock_client_with_get_task(side_effect: Any) -> MagicMock:
    client = MagicMock()
    client.get_task = AsyncMock(side_effect=side_effect)
    return client


class TestWaitForTaskHardening:
    @pytest.mark.asyncio
    async def test_terminal_state_releases_spawn_slot(self) -> None:
        """wait_for_task observing a terminal state frees the task's slot."""
        await spawn_guarded("install_package", lambda: _submit_task(42))
        assert in_flight() == 1

        client = _mock_client_with_get_task([{"state": 4}])
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.wait_for_task(42, timeout=5, poll_interval=1)

        assert result["status"] == "success"
        assert result["completed"] is True
        assert in_flight() == 0

    @pytest.mark.asyncio
    async def test_poll_timeouts_share_bounded_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deadline-bounded polls that time out re-poll on a shared budget and
        then surface a structured task_poll_failed envelope."""
        monkeypatch.setattr(system_tools, "POLL_CALL_TIMEOUT", 0.01)

        async def wedged_poll(task_id: int) -> dict[str, Any]:
            await asyncio.sleep(1.0)
            return {"state": 1}

        client = MagicMock()
        client.get_task = MagicMock(side_effect=lambda task_id: wedged_poll(task_id))
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.wait_for_task(42, timeout=30, poll_interval=1)

        assert result["status"] == "error"
        assert result["error"] == "task_poll_failed"
        assert result["completed"] is False
        assert result["task_id"] == 42
        # 1 initial poll + MAX_TASK_POLL_FAILURES recovery polls, then give up.
        assert client.get_task.call_count == task_guard.MAX_TASK_POLL_FAILURES + 1

    @pytest.mark.asyncio
    async def test_poll_recovers_within_budget(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A single wedged poll burns budget but the wait still succeeds."""
        monkeypatch.setattr(system_tools, "POLL_CALL_TIMEOUT", 0.01)

        async def wedged_poll(task_id: int) -> dict[str, Any]:
            await asyncio.sleep(1.0)
            return {"state": 1}

        calls = {"n": 0}

        def get_task(task_id: int) -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                return wedged_poll(task_id)
            return _submit_done(task_id)

        async def _submit_done(task_id: int) -> dict[str, Any]:
            return {"state": 4}

        client = MagicMock()
        client.get_task = MagicMock(side_effect=get_task)
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.wait_for_task(42, timeout=30, poll_interval=1)

        assert result["status"] == "success"
        assert result["completed"] is True

    @pytest.mark.asyncio
    async def test_wait_timeout_is_clamped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A huge caller timeout is clamped to MAX_TASK_WAIT_TIMEOUT."""
        monkeypatch.setattr(system_tools, "MAX_TASK_WAIT_TIMEOUT", 0)

        client = _mock_client_with_get_task([{"state": 1}])
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.wait_for_task(42, timeout=999999, poll_interval=1)

        assert result["status"] == "error"
        assert result["completed"] is False
        assert "timed out after 0 seconds" in result["message"]

    @pytest.mark.asyncio
    async def test_api_errors_surface_immediately(self) -> None:
        """Non-timeout poll errors keep existing semantics: no re-poll loop."""
        client = _mock_client_with_get_task(RuntimeError("task not found"))
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.wait_for_task(42, timeout=30, poll_interval=1)

        assert result["status"] == "error"
        assert client.get_task.await_count == 1


class TestSpawnSitesAreGuarded:
    """The exhausted error envelope reaches callers of the wired tools."""

    @pytest.mark.asyncio
    async def test_install_package_returns_envelope_when_exhausted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fortimanager_mcp.utils.config import get_settings

        for i in range(TASK_CONCURRENCY_LIMIT):
            await spawn_guarded("install_package", lambda i=i: _submit_task(i))

        # Disable the preview-before-install gate: this test is about the
        # task-slot budget, which is checked after the gate.
        monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
        monkeypatch.setenv("FMG_INSTALL_SAFETY", "disabled")
        get_settings.cache_clear()
        client = MagicMock()
        client.install_package = AsyncMock()
        try:
            with patch.object(system_tools, "get_fmg_client", return_value=client):
                result = await system_tools.install_package(
                    adom="root", package="default", devices=[{"name": "FGT1", "vdom": "root"}]
                )
        finally:
            get_settings.cache_clear()

        assert result["status"] == "error"
        assert result["error"] == "task_slots_exhausted"
        assert result["operation"] == "install_package"
        client.install_package.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_script_returns_envelope_when_exhausted(self) -> None:
        from fortimanager_mcp.tools import script_tools

        for i in range(TASK_CONCURRENCY_LIMIT):
            await spawn_guarded("install_package", lambda i=i: _submit_task(i))

        client = MagicMock()
        client.execute_script = AsyncMock()
        # Stored-script safety check runs before the spawn; give it a benign body.
        client.get_script = AsyncMock(return_value={"type": "cli", "content": "get system status"})
        with patch.object(script_tools, "get_fmg_client", return_value=client):
            result = await script_tools.execute_script_on_device(
                adom="root", script="audit", device="FGT1"
            )

        assert result["status"] == "error"
        assert result["error"] == "task_slots_exhausted"
        assert result["operation"] == "execute_script_on_device"
        client.execute_script.assert_not_called()
