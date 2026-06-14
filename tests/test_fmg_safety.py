"""FMG-specific safety additions (bundle D of #11).

Covers the preview-before-install gate, ADOM lock tracking + shutdown
release, and per-item bulk delete reporting.
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import policy_tools, system_tools
from fortimanager_mcp.utils import adom_locks, install_gate, task_guard
from fortimanager_mcp.utils.config import get_settings

DEVICES = [{"name": "FGT1", "vdom": "root"}]


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Isolated registries + settings per test."""
    monkeypatch.setenv("FORTIMANAGER_HOST", "test.example.com")
    get_settings.cache_clear()
    install_gate._reset()
    adom_locks._reset()
    task_guard._reset()
    yield
    install_gate._reset()
    adom_locks._reset()
    task_guard._reset()
    get_settings.cache_clear()


def _client(**methods: Any) -> MagicMock:
    client = MagicMock()
    for name, value in methods.items():
        setattr(client, name, AsyncMock(**value) if isinstance(value, dict) else value)
    return client


async def _install(client: MagicMock, preview: bool = False) -> dict[str, Any]:
    with patch.object(system_tools, "get_fmg_client", return_value=client):
        return await system_tools.install_package(
            adom="root", package="default", devices=DEVICES, preview=preview
        )


class TestInstallGateRegistry:
    @pytest.mark.asyncio
    async def test_record_find_consume(self) -> None:
        install_gate.record_preview("root", "default", DEVICES, 7)
        assert install_gate.find_preview("root", "default", DEVICES) == 7
        install_gate.consume_preview("root", "default", DEVICES)
        assert install_gate.find_preview("root", "default", DEVICES) is None

    @pytest.mark.asyncio
    async def test_scope_key_is_order_insensitive(self) -> None:
        two = [{"name": "B", "vdom": "root"}, {"name": "A", "vdom": "root"}]
        install_gate.record_preview("root", "default", two, 7)
        assert install_gate.find_preview("root", "default", list(reversed(two))) == 7

    @pytest.mark.asyncio
    async def test_different_scope_does_not_match(self) -> None:
        install_gate.record_preview("root", "default", DEVICES, 7)
        other = [{"name": "FGT2", "vdom": "root"}]
        assert install_gate.find_preview("root", "default", other) is None

    @pytest.mark.asyncio
    async def test_expired_preview_is_dropped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(install_gate, "PREVIEW_VALIDITY_TTL", -1.0)
        install_gate.record_preview("root", "default", DEVICES, 7)
        assert install_gate.find_preview("root", "default", DEVICES) is None


class TestPreviewBeforeInstallGate:
    @pytest.mark.asyncio
    async def test_strict_refuses_without_preview(self) -> None:
        client = _client(install_package={"return_value": {"task": 1}})
        result = await _install(client)
        assert result["status"] == "error"
        assert result["error"] == "preview_required"
        assert result["recommendation"] == "preview_install"
        client.install_package.assert_not_called()

    @pytest.mark.asyncio
    async def test_strict_installs_with_verified_preview(self) -> None:
        install_gate.record_preview("root", "default", DEVICES, 7)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 4}},  # preview done
        )
        result = await _install(client)
        assert result["status"] == "success"
        assert result["task_id"] == 2
        assert "warning" not in result
        # The preview is spent: a second install needs a fresh one.
        second = await _install(client)
        assert second["status"] == "error"
        assert second["error"] == "preview_required"

    @pytest.mark.asyncio
    async def test_strict_refuses_unfinished_preview(self) -> None:
        install_gate.record_preview("root", "default", DEVICES, 7)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 1}},  # still running
        )
        result = await _install(client)
        assert result["status"] == "error"
        assert "not finished" in result["message"]
        client.install_package.assert_not_called()

    @pytest.mark.asyncio
    async def test_strict_refuses_failed_preview(self) -> None:
        install_gate.record_preview("root", "default", DEVICES, 7)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 5}},  # preview errored
        )
        result = await _install(client)
        assert result["status"] == "error"
        assert "state 'error'" in result["message"]
        client.install_package.assert_not_called()

    @pytest.mark.asyncio
    async def test_preview_flag_bypasses_gate(self) -> None:
        """install_package(preview=True) is itself a dry run — no gate."""
        client = _client(install_package={"return_value": {"task": 3}})
        result = await _install(client, preview=True)
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_warn_mode_installs_with_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FMG_INSTALL_SAFETY", "warn")
        get_settings.cache_clear()
        client = _client(install_package={"return_value": {"task": 2}})
        result = await _install(client)
        assert result["status"] == "success"
        assert "without a verified preview" in result["warning"]

    @pytest.mark.asyncio
    async def test_disabled_mode_skips_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FMG_INSTALL_SAFETY", "disabled")
        get_settings.cache_clear()
        client = _client(install_package={"return_value": {"task": 2}})
        result = await _install(client)
        assert result["status"] == "success"
        assert "warning" not in result
        client.get_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_preview_install_records_for_gate(self) -> None:
        client = _client(install_preview={"return_value": {"task": 9}})
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            result = await policy_tools.preview_install(
                adom="root", package="default", devices=DEVICES
            )
        assert result["status"] == "success"
        assert install_gate.find_preview("root", "default", DEVICES) == 9


class TestAdomLockTracking:
    @pytest.mark.asyncio
    async def test_lock_unlock_tracks_state(self) -> None:
        client = _client(
            lock_adom={"return_value": {}},
            unlock_adom={"return_value": {}},
        )
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            await system_tools.lock_adom("root")
            assert adom_locks.held_locks() == ["root"]
            await system_tools.unlock_adom("root")
            assert adom_locks.held_locks() == []

    @pytest.mark.asyncio
    async def test_failed_lock_is_not_tracked(self) -> None:
        client = _client(lock_adom={"side_effect": RuntimeError("locked by other admin")})
        with patch.object(system_tools, "get_fmg_client", return_value=client):
            result = await system_tools.lock_adom("root")
        assert result["status"] == "error"
        assert adom_locks.held_locks() == []

    @pytest.mark.asyncio
    async def test_release_held_locks_unlocks_all(self) -> None:
        adom_locks.record_lock("root")
        adom_locks.record_lock("branch")
        client = _client(unlock_adom={"return_value": {}})
        await adom_locks.release_held_locks(client)
        assert adom_locks.held_locks() == []
        assert client.unlock_adom.await_count == 2

    @pytest.mark.asyncio
    async def test_release_swallows_unlock_failure(self) -> None:
        adom_locks.record_lock("root")
        client = _client(unlock_adom={"side_effect": RuntimeError("connection lost")})
        await adom_locks.release_held_locks(client)  # must not raise
        # Still tracked, but shutdown proceeds; the FMG session end releases it.
        assert adom_locks.held_locks() == ["root"]

    @pytest.mark.asyncio
    async def test_release_is_deadline_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(adom_locks, "UNLOCK_TIMEOUT", 0.01)
        adom_locks.record_lock("root")

        async def wedged(adom: str) -> dict[str, Any]:
            await asyncio.sleep(1.0)
            return {}

        client = MagicMock()
        client.unlock_adom = MagicMock(side_effect=wedged)
        await adom_locks.release_held_locks(client)  # returns promptly, no raise


class TestBulkDeletePartialSuccess:
    async def _bulk(self, client: MagicMock, ids: list[int]) -> dict[str, Any]:
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            return await policy_tools.delete_firewall_policies_bulk(
                adom="root", package="default", policyids=ids
            )

    @pytest.mark.asyncio
    async def test_all_succeed(self) -> None:
        client = _client(delete_firewall_policy={"return_value": {}})
        result = await self._bulk(client, [1, 2, 3])
        assert result["status"] == "success"
        assert result["deleted"] == [1, 2, 3]
        assert result["deleted_count"] == 3
        assert result["failed"] == []

    @pytest.mark.asyncio
    async def test_partial_failure_reports_per_item(self) -> None:
        def delete(adom: str, pkg: str, policyid: int) -> Any:
            async def run() -> dict[str, Any]:
                if policyid == 2:
                    raise RuntimeError("does not exist")
                return {}

            return run()

        client = MagicMock()
        client.delete_firewall_policy = MagicMock(side_effect=delete)
        result = await self._bulk(client, [1, 2, 3])
        assert result["status"] == "partial"
        assert result["deleted"] == [1, 3]
        assert result["deleted_count"] == 2
        assert [f["policyid"] for f in result["failed"]] == [2]
        assert "message" in result["failed"][0]

    @pytest.mark.asyncio
    async def test_all_fail(self) -> None:
        client = _client(delete_firewall_policy={"side_effect": RuntimeError("nope")})
        result = await self._bulk(client, [1, 2])
        assert result["status"] == "error"
        assert result["deleted"] == []
        assert len(result["failed"]) == 2

    @pytest.mark.asyncio
    async def test_empty_ids_rejected(self) -> None:
        client = _client()
        result = await self._bulk(client, [])
        assert result["status"] == "error"


class TestPreviewRevisionGate:
    """Revision fingerprinting closes the TOCTOU between preview and install
    (issue #25): a package edited after the preview must force a re-preview.
    """

    @pytest.mark.asyncio
    async def test_preview_install_records_revision(self) -> None:
        client = _client(
            install_preview={"return_value": {"task": 9}},
            get_package={"return_value": {"name": "default", "obj ver": 5}},
        )
        with patch.object(policy_tools, "get_fmg_client", return_value=client):
            result = await policy_tools.preview_install(
                adom="root", package="default", devices=DEVICES
            )
        assert result["status"] == "success"
        assert install_gate.recorded_revision("root", "default", DEVICES) == 5

    @pytest.mark.asyncio
    async def test_unchanged_revision_installs(self) -> None:
        install_gate.record_preview("root", "default", DEVICES, 7, revision=5)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 4}},
            get_package={"return_value": {"obj ver": 5}},
        )
        result = await _install(client)
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_changed_revision_refuses_stale_and_expires(self) -> None:
        install_gate.record_preview("root", "default", DEVICES, 7, revision=5)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 4}},
            get_package={"return_value": {"obj ver": 6}},  # edited since preview
        )
        result = await _install(client)
        assert result["status"] == "error"
        assert result["error"] == "preview_stale"
        assert "changed since the preview" in result["message"]
        assert "5 -> 6" in result["message"]
        client.install_package.assert_not_called()
        # The stale record is expired: the next attempt reports no preview.
        assert install_gate.find_preview("root", "default", DEVICES) is None
        second = await _install(client)
        assert second["error"] == "preview_required"

    @pytest.mark.asyncio
    async def test_legacy_record_without_revision_installs(self) -> None:
        """A record carrying no revision (fetch failed at preview time, or an
        older build without `obj ver`) degrades to TTL + single-use."""
        install_gate.record_preview("root", "default", DEVICES, 7)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 4}},
        )
        result = await _install(client)
        assert result["status"] == "success"
        client.get_package.assert_not_called()

    @pytest.mark.asyncio
    async def test_unverifiable_revision_refuses_in_strict(self) -> None:
        """Recorded revision exists but the install-time fetch fails: strict
        mode must refuse rather than install unverified."""
        install_gate.record_preview("root", "default", DEVICES, 7, revision=5)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 4}},
            get_package={"side_effect": RuntimeError("connection lost")},
        )
        result = await _install(client)
        assert result["status"] == "error"
        assert result["error"] == "preview_required"
        assert "could not be verified" in result["message"]
        client.install_package.assert_not_called()

    @pytest.mark.asyncio
    async def test_warn_mode_installs_stale_with_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FMG_INSTALL_SAFETY", "warn")
        get_settings.cache_clear()
        install_gate.record_preview("root", "default", DEVICES, 7, revision=5)
        client = _client(
            install_package={"return_value": {"task": 2}},
            get_task={"return_value": {"state": 4}},
            get_package={"return_value": {"obj ver": 6}},
        )
        result = await _install(client)
        assert result["status"] == "success"
        assert "changed since the preview" in result["warning"]
