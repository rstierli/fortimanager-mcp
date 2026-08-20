"""Tests for fmg_ops_tools module."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import fmg_ops_tools
from fortimanager_mcp.utils import task_guard


@pytest.fixture(autouse=True)
def _clean_task_slots() -> Any:
    """trigger_fmg_backup now spawns under the shared task-guard budget --
    each test starts and ends with an empty registry so a slot left held by
    one test can't spuriously exhaust another (here or in a different file,
    since the registry is process-global)."""
    task_guard._reset()
    yield
    task_guard._reset()


MOCK_LICENSE = {
    "contract": [
        {
            "account": "foo@bar.com",
            "company": "Fortinet",
            "contract_item": ["ADOM-1-06-20260525:0:5000:5000:0"],
            "industry": "Technology",
            "serial": "FMVMMLREDACTED79",
        }
    ],
    "count": 1,
}

MOCK_CAPTURE_DEFS = [
    {
        "host": "10.0.0.1",
        "id": 1,
        "interface": "port1",
        "ipv6": "enable",
        "max-packet-count": 4000,
        "non-ip": "enable",
        "port": "80",
        "protocol": "6",
        "vlan": "1001",
    },
    {
        "host": "",
        "id": 2,
        "interface": "port3",
        "ipv6": None,
        "max-packet-count": 4000,
        "non-ip": None,
        "port": "1111",
        "protocol": "",
        "vlan": "",
    },
]

MOCK_CAPTURE_PROGRESS = [
    {"id": 1, "max_packets": 4000, "packets": 1308, "running": 0},
    {"id": 2, "max_packets": 4000, "packets": 407, "running": 1},
]


class TestBackup:
    """Test trigger_fmg_backup."""

    @pytest.mark.asyncio
    async def test_backup_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test triggering a backup returns a task ID."""
        mock_fmg_instance.execute.return_value = (0, {"taskid": 837})

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_backup(
                service="ftp",
                server="10.210.35.207",
                filename="tmp/fmg_backup.dat",
                username="tiger",
                userpasswd="fortinet",
                passwd="fortinet",
            )

        assert result["status"] == "success"
        assert result["task_id"] == 837
        assert mock_fmg_instance.execute.call_args.args[0] == "/sys/backup"
        sent_data = mock_fmg_instance.execute.call_args.kwargs["data"]
        assert sent_data["service"] == "ftp"
        assert sent_data["server"] == "10.210.35.207"
        assert sent_data["filename"] == "tmp/fmg_backup.dat"
        assert sent_data["passwd"] == "fortinet"
        # Code review found this call spawned an FMG task outside the shared
        # task_guard budget entirely -- now it must hold a slot like every
        # other task-spawning tool.
        assert task_guard.in_flight() == 1

    @pytest.mark.asyncio
    async def test_backup_blocked_when_task_slots_exhausted(
        self, mock_client: FortiManagerClient
    ) -> None:
        from fortimanager_mcp.utils.task_guard import TASK_CONCURRENCY_LIMIT

        for i in range(TASK_CONCURRENCY_LIMIT):
            await task_guard.spawn_guarded("other", lambda i=i: _fake_task(i))

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_backup(
                service="ftp", server="10.210.35.207", filename="tmp/fmg_backup.dat"
            )

        assert result["status"] == "error"
        assert result["error_code"] == "task_slots_exhausted"

    @pytest.mark.asyncio
    async def test_backup_invalid_service(self, mock_client: FortiManagerClient) -> None:
        """Test backup rejects an unsupported transfer service."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_backup(
                service="rsync",
                server="10.210.35.207",
                filename="tmp/fmg_backup.dat",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_backup_invalid_filename(self, mock_client: FortiManagerClient) -> None:
        """Test backup rejects a filename with injection characters."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_backup(
                service="ftp",
                server="10.210.35.207",
                filename="tmp/`whoami`.dat",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_backup_invalid_port(self, mock_client: FortiManagerClient) -> None:
        """Test backup rejects an out-of-range port."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_backup(
                service="ftp",
                server="10.210.35.207",
                filename="tmp/fmg_backup.dat",
                port=99999,
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_backup_not_connected(self) -> None:
        """Test backup when client not connected."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=None):
            result = await fmg_ops_tools.trigger_fmg_backup(
                service="ftp",
                server="10.210.35.207",
                filename="tmp/fmg_backup.dat",
            )

        assert result["status"] == "error"


class TestRestore:
    """Test trigger_fmg_restore."""

    @pytest.mark.asyncio
    async def test_restore_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test triggering a restore succeeds."""
        mock_fmg_instance.execute.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_restore(
                service="ftp",
                server="10.210.35.207",
                filename="tmp/fmg_backup.dat",
                username="tiger",
                userpasswd="fortinet",
                confirm=True,
            )

        assert result["status"] == "success"
        assert mock_fmg_instance.execute.call_args.args[0] == "/sys/restore"
        sent_data = mock_fmg_instance.execute.call_args.kwargs["data"]
        assert sent_data["filename"] == "tmp/fmg_backup.dat"

    @pytest.mark.asyncio
    async def test_restore_invalid_server(self, mock_client: FortiManagerClient) -> None:
        """Test restore rejects a malformed server address."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_restore(
                service="ftp",
                server="10.210.35.207; rm -rf /",
                filename="tmp/fmg_backup.dat",
                confirm=True,
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_restore_not_connected(self) -> None:
        """Test restore when client not connected."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=None):
            result = await fmg_ops_tools.trigger_fmg_restore(
                service="ftp",
                server="10.210.35.207",
                filename="tmp/fmg_backup.dat",
                confirm=True,
            )

        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_restore_blocked_without_confirm(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Under the default FMG_RESTORE_SAFETY=strict, restore must be
        refused -- with no FMG call attempted -- unless confirm=True is
        explicitly passed. Restoring replaces FMG's entire configuration."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.trigger_fmg_restore(
                service="ftp",
                server="10.210.35.207",
                filename="tmp/fmg_backup.dat",
            )

        assert result["status"] == "error"
        assert result["error_code"] == "confirmation_required"
        mock_fmg_instance.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_restore_allowed_when_safety_disabled(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from fortimanager_mcp.utils.config import get_settings

        monkeypatch.setenv("FMG_RESTORE_SAFETY", "disabled")
        get_settings.cache_clear()
        mock_fmg_instance.execute.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        try:
            with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
                result = await fmg_ops_tools.trigger_fmg_restore(
                    service="ftp",
                    server="10.210.35.207",
                    filename="tmp/fmg_backup.dat",
                )
        finally:
            get_settings.cache_clear()

        assert result["status"] == "success"
        mock_fmg_instance.execute.assert_called_once()


class TestPacketCaptureList:
    """Test list_packet_captures."""

    @pytest.mark.asyncio
    async def test_list_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test listing packet capture definitions."""
        mock_fmg_instance.get.return_value = (0, MOCK_CAPTURE_DEFS)

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.list_packet_captures()

        assert result["status"] == "success"
        assert result["count"] == 2
        assert mock_fmg_instance.get.call_args.args[0] == "/cli/global/system/sniffer"

    @pytest.mark.asyncio
    async def test_list_not_connected(self) -> None:
        """Test listing when client not connected."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=None):
            result = await fmg_ops_tools.list_packet_captures()

        assert result["status"] == "error"


class TestPacketCaptureAdd:
    """Test add_packet_capture."""

    @pytest.mark.asyncio
    async def test_add_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test adding a packet capture definition returns its assigned ID."""
        mock_fmg_instance.add.return_value = (0, {"id": 12})

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.add_packet_capture(
                interface="port8",
                host="10.1.2.3",
                max_packet_count=300,
            )

        assert result["status"] == "success"
        assert result["capture_id"] == 12
        assert mock_fmg_instance.add.call_args.args[0] == "/cli/global/system/sniffer"
        sent_data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert sent_data["id"] == 0
        assert sent_data["interface"] == "port8"
        assert sent_data["host"] == "10.1.2.3"
        assert sent_data["max-packet-count"] == 300
        assert sent_data["ipv6"] == "disable"
        assert sent_data["non-ip"] == "disable"

    @pytest.mark.asyncio
    async def test_add_capture_bool_flags_translate_to_enable(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test capture_ipv6/capture_non_ip True map to the FMG 'enable' string."""
        mock_fmg_instance.add.return_value = (0, {"id": 13})

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.add_packet_capture(
                interface="port1",
                capture_ipv6=True,
                capture_non_ip=True,
            )

        assert result["status"] == "success"
        sent_data = mock_fmg_instance.add.call_args.kwargs["data"]
        assert sent_data["ipv6"] == "enable"
        assert sent_data["non-ip"] == "enable"

    @pytest.mark.asyncio
    async def test_add_invalid_interface(self, mock_client: FortiManagerClient) -> None:
        """Test add_packet_capture rejects an invalid interface name."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.add_packet_capture(interface="port1; rm -rf /")

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_add_invalid_max_packet_count(self, mock_client: FortiManagerClient) -> None:
        """Test add_packet_capture rejects a non-positive max_packet_count."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.add_packet_capture(interface="port1", max_packet_count=0)

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"


class TestPacketCaptureLifecycle:
    """Test start/stop_packet_capture."""

    @pytest.mark.asyncio
    async def test_start_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test starting a packet capture."""
        mock_fmg_instance.execute.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.start_packet_capture(1)

        assert result["status"] == "success"
        assert mock_fmg_instance.execute.call_args.args[0] == "/cli/global/system/sniffer"
        sent_data = mock_fmg_instance.execute.call_args.kwargs["data"]
        assert sent_data == {"action": "start", "id": 1}

    @pytest.mark.asyncio
    async def test_stop_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test stopping a packet capture."""
        mock_fmg_instance.execute.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.stop_packet_capture(1)

        assert result["status"] == "success"
        sent_data = mock_fmg_instance.execute.call_args.kwargs["data"]
        assert sent_data == {"action": "stop", "id": 1}

    @pytest.mark.asyncio
    async def test_start_not_connected(self) -> None:
        """Test start when client not connected."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=None):
            result = await fmg_ops_tools.start_packet_capture(1)

        assert result["status"] == "error"


class TestPacketCaptureStatus:
    """Test get_packet_capture_status."""

    @pytest.mark.asyncio
    async def test_status_all(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test getting status for all capture definitions."""
        mock_fmg_instance.execute.return_value = (0, MOCK_CAPTURE_PROGRESS)

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.get_packet_capture_status()

        assert result["status"] == "success"
        assert result["count"] == 2
        sent_data = mock_fmg_instance.execute.call_args.kwargs["data"]
        assert sent_data == {"action": "progress"}

    @pytest.mark.asyncio
    async def test_status_filtered_by_id(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test status filters down to the requested capture_id."""
        mock_fmg_instance.execute.return_value = (0, MOCK_CAPTURE_PROGRESS)

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.get_packet_capture_status(capture_id=2)

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["captures"][0]["id"] == 2
        assert result["captures"][0]["running"] == 1


class TestLicense:
    """Test get_fmg_license."""

    @pytest.mark.asyncio
    async def test_license_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test getting license status."""
        mock_fmg_instance.execute.return_value = (0, MOCK_LICENSE)

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.get_fmg_license()

        assert result["status"] == "success"
        assert result["license"]["count"] == 1
        assert result["license"]["contract"][0]["serial"] == "FMVMMLREDACTED79"
        assert mock_fmg_instance.execute.call_args.args[0] == "/um/license/self"

    @pytest.mark.asyncio
    async def test_license_not_connected(self) -> None:
        """Test license when client not connected."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=None):
            result = await fmg_ops_tools.get_fmg_license()

        assert result["status"] == "error"


class TestDeleteTask:
    """Test delete_task."""

    @pytest.mark.asyncio
    async def test_delete_success(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Test deleting a completed task."""
        mock_fmg_instance.delete.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.delete_task(11111)

        assert result["status"] == "success"
        assert mock_fmg_instance.delete.call_args.args[0] == "/task/task/11111"

    @pytest.mark.asyncio
    async def test_delete_releases_held_task_slot(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Code review found delete_task never released a task_guard slot
        (mark_task_done was never called) -- repeatedly deleting tasks
        spawned elsewhere would leak slots until TTL, eventually exhausting
        the budget with nothing actually running."""
        await task_guard.spawn_guarded("fmg_backup", lambda: _fake_task(11111))
        assert task_guard.in_flight() == 1

        mock_fmg_instance.delete.return_value = (0, {"status": {"code": 0, "message": "OK"}})
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.delete_task(11111)

        assert result["status"] == "success"
        assert task_guard.in_flight() == 0

    @pytest.mark.asyncio
    async def test_delete_of_untracked_task_is_a_noop_release(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """mark_task_done for a task id that never held a slot (e.g. spawned
        by a previous server process) must not error."""
        mock_fmg_instance.delete.return_value = (0, {"status": {"code": 0, "message": "OK"}})
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.delete_task(99999)

        assert result["status"] == "success"
        assert task_guard.in_flight() == 0

    @pytest.mark.asyncio
    async def test_delete_not_connected(self) -> None:
        """Test delete when client not connected."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=None):
            result = await fmg_ops_tools.delete_task(11111)

        assert result["status"] == "error"


async def _fake_task(task_id: int) -> dict[str, Any]:
    return {"task": task_id}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["../../sys/status", "1 OR 1=1", 1.5, True, None, -3])
    async def test_a_bad_task_id_never_reaches_the_url(
        self, bad: Any, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """upstream #71: task_id was interpolated straight into
        /task/task/{id} with nothing enforcing its shape. Full mode carries
        the int annotation; dynamic mode passes parameters as
        dict[str, Any], which is the mode the newer modules are wired into.

        Asserts the delete never happened, not just that the call errored --
        an error after the request has gone out is not a guard."""
        with patch.object(fmg_ops_tools, "get_fmg_client", return_value=mock_client):
            result = await fmg_ops_tools.delete_task(bad)

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        mock_fmg_instance.delete.assert_not_called()
