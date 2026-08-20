"""Tests for firmware_tools module."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.utils import task_guard

MOCK_UPGRADE_PATH_RESPONSE = {
    "upgrade_path": [
        {
            "name": "FGT-01",
            "oid": 662,
            "path": ["6.0.8-303", "6.2.4-1112", "6.4.1-1637"],
        }
    ]
}

MOCK_VERSION_LIST_RESPONSE = {
    "status": "success",
    "version_list": [
        {
            "platform": "FortiGate-VM64-KVM",
            "product": "FGT",
            "versions": [
                {"type": "GA", "version": "6.4.6-b1852"},
                {"type": "GA", "version": "7.2.9-b1688"},
            ],
        }
    ],
}

MOCK_IMAGE_LIST_RESPONSE = {
    "status": "success",
    "image_list": [
        {
            "build": "b0180",
            "date": "211019",
            "image_path": "/var/fwm/image/FGVMK6_7.2.9_b1688_FORTINET.out",
            "image_size": 239100126,
            "platform": "FortiGate-VM64-KVM",
            "product": "FGT",
            "version": "7.2.9-b1688",
        }
    ],
}

MOCK_UPGRADE_REPORT_RESPONSE = {
    "report": [
        [
            {
                "end-time": 1700776054,
                "name": "FGT-01",
                "oid": 175,
                "package-status": 0,
                "start-time": 1700775638,
                "taskid": 9,
            }
        ]
    ]
}


@pytest.fixture(autouse=True)
def _clean_task_slots() -> Any:
    """Each test starts and ends with an empty task-slot registry."""
    task_guard._reset()
    yield
    task_guard._reset()


@pytest.fixture
def mock_client_configured(
    mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
) -> FortiManagerClient:
    """Configure mock client with firmware-endpoint responses."""

    def mock_execute(url: str, **kwargs: Any) -> tuple[int, Any]:
        if url == "/um/image/upgrade":
            if kwargs.get("flags") == "f_preview":
                return (0, MOCK_UPGRADE_PATH_RESPONSE)
            # Real trigger: create_task="enable" is always sent.
            assert kwargs.get("create_task") == "enable"
            return (0, {"taskid": 869})
        if url == "/um/image/version/list":
            return (0, MOCK_VERSION_LIST_RESPONSE)
        if url == "/um/image/list":
            return (0, MOCK_IMAGE_LIST_RESPONSE)
        return (0, {})

    def mock_get(url: str, **kwargs: Any) -> tuple[int, Any]:
        if url == "um/image/upgrade/report":
            return (0, MOCK_UPGRADE_REPORT_RESPONSE)
        return (0, {})

    mock_fmg_instance.execute.side_effect = mock_execute
    mock_fmg_instance.get.side_effect = mock_get
    return mock_client


class TestGetFirmwareUpgradePath:
    """Tests for get_firmware_upgrade_path (preview, non-destructive)."""

    @pytest.mark.asyncio
    async def test_returns_path(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.get_firmware_upgrade_path(
                device="FGT-01", target_version="6.4.1-1637"
            )

        assert result["status"] == "success"
        assert result["upgrade_path"] == ["6.0.8-303", "6.2.4-1112", "6.4.1-1637"]

    @pytest.mark.asyncio
    async def test_forces_preview_flag(self, mock_client_configured: FortiManagerClient) -> None:
        """Even if callers could pass flags, this tool always uses f_preview
        internally so it can never trigger a real upgrade."""
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.get_firmware_upgrade_path(
                device="FGT-01", target_version="6.4.1-1637"
            )

        # The mock only returns upgrade_path data (not a taskid) when
        # flags=="f_preview" was actually sent -- see mock_execute above.
        assert "upgrade_path" in result
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_invalid_version_rejected(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.get_firmware_upgrade_path(
                device="FGT-01", target_version="not a version; drop table"
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_invalid_device_name_rejected(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.get_firmware_upgrade_path(
                device="../etc/passwd", target_version="6.4.1"
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=None):
            result = await firmware_tools.get_firmware_upgrade_path(
                device="FGT-01", target_version="6.4.1"
            )

        assert result["status"] == "error"


class TestListAvailableFirmware:
    """Tests for list_available_firmware (FortiGuard + imported catalog)."""

    @pytest.mark.asyncio
    async def test_returns_version_list(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.list_available_firmware(
                platform="FortiGate-VM64-KVM", product="FGT"
            )

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["version_list"][0]["platform"] == "FortiGate-VM64-KVM"

    @pytest.mark.asyncio
    async def test_omits_optional_params(self, mock_client_configured: FortiManagerClient) -> None:
        """platform/product are both optional per the How-To Guide."""
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.list_available_firmware()

        assert result["status"] == "success"


class TestListFirmwareImages:
    """Tests for list_firmware_images (FMG local disk)."""

    @pytest.mark.asyncio
    async def test_returns_image_list(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.list_firmware_images(system="FGT")

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["image_list"][0]["product"] == "FGT"


class TestUpgradeDeviceFirmware:
    """Tests for upgrade_device_firmware (device-affecting, async task)."""

    @pytest.mark.asyncio
    async def test_returns_task_id(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.upgrade_device_firmware(
                device="FGT-01", target_version="6.4.1-1637", confirm=True
            )

        assert result["status"] == "success"
        assert result["task_id"] == 869

    @pytest.mark.asyncio
    async def test_valid_flag_accepted(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.upgrade_device_firmware(
                device="FGT-01",
                target_version="6.4.1-1637",
                flags="f_skip_fortiguard_img",
                confirm=True,
            )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_the_validated_flag_reaches_the_upgrade_call(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """upstream #69: test_valid_flag_accepted above asserts only that the
        call succeeded, so hardcoding flags=None in the client call left the
        suite green. Validating a flag and then dropping it is worse than
        refusing it: the caller asked to skip the config retrieve and gets a
        plain upgrade instead, on a real reboot."""
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.upgrade_device_firmware(
                device="FGT-01",
                target_version="6.4.1-1637",
                flags="f_skip_retrieve",
                confirm=True,
            )

        assert result["status"] == "success"
        upgrade_calls = [
            call
            for call in mock_fmg_instance.execute.call_args_list
            if call.args and call.args[0] == "/um/image/upgrade"
        ]
        assert len(upgrade_calls) == 1
        assert upgrade_calls[0].kwargs.get("flags") == "f_skip_retrieve"

    @pytest.mark.asyncio
    async def test_invalid_flag_rejected(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.upgrade_device_firmware(
                device="FGT-01", target_version="6.4.1-1637", flags="f_preview", confirm=True
            )

        # f_preview is reserved for get_firmware_upgrade_path and rejected here.
        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_invalid_version_rejected_before_spawn(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        from fortimanager_mcp.tools import firmware_tools
        from fortimanager_mcp.utils.task_guard import in_flight

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.upgrade_device_firmware(
                device="FGT-01", target_version="", confirm=True
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        # No task slot should be held for a request that never reached FMG.
        assert in_flight() == 0

    @pytest.mark.asyncio
    async def test_task_slots_exhausted(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools
        from fortimanager_mcp.utils.task_guard import TASK_CONCURRENCY_LIMIT

        # Fill every slot with an unrelated in-flight task.
        for i in range(TASK_CONCURRENCY_LIMIT):
            await task_guard.spawn_guarded("other", lambda i=i: _fake_task(i))

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.upgrade_device_firmware(
                device="FGT-01", target_version="6.4.1-1637", confirm=True
            )

        assert result["status"] == "error"
        assert result["error"] == "task_slots_exhausted"

    @pytest.mark.asyncio
    async def test_blocked_without_confirm(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        """PR #65 review (Christian): upgrade_device_firmware reboots a
        real managed device with no gate of any kind -- unlike
        trigger_fmg_restore, which this batch already gated. spawn_guarded
        bounds concurrency, it does not gate whether the call is allowed."""
        from fortimanager_mcp.tools import firmware_tools
        from fortimanager_mcp.utils.task_guard import in_flight

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.upgrade_device_firmware(
                device="FGT-01", target_version="6.4.1-1637"
            )

        assert result["status"] == "error"
        assert result["error_code"] == "confirmation_required"
        # No task slot held for a call refused before it ever reached spawn_guarded.
        assert in_flight() == 0

    @pytest.mark.asyncio
    async def test_allowed_when_firmware_safety_disabled(
        self,
        mock_client_configured: FortiManagerClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from fortimanager_mcp.tools import firmware_tools
        from fortimanager_mcp.utils.config import get_settings

        monkeypatch.setenv("FMG_FIRMWARE_SAFETY", "disabled")
        get_settings.cache_clear()

        try:
            with patch.object(
                firmware_tools, "get_fmg_client", return_value=mock_client_configured
            ):
                result = await firmware_tools.upgrade_device_firmware(
                    device="FGT-01", target_version="6.4.1-1637"
                )
        finally:
            get_settings.cache_clear()

        assert result["status"] == "success"


async def _fake_task(task_id: int) -> dict[str, Any]:
    return {"task": task_id}


class TestGetFirmwareUpgradeReport:
    """Tests for get_firmware_upgrade_report."""

    @pytest.mark.asyncio
    async def test_returns_report(self, mock_client_configured: FortiManagerClient) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.get_firmware_upgrade_report(
                device="FGT-01", profile_name="fgt_to_740"
            )

        assert result["status"] == "success"
        assert result["profile_name"] == "fgt_to_740"
        assert result["report"][0][0]["name"] == "FGT-01"

    @pytest.mark.asyncio
    async def test_sends_fields_nested_under_data(
        self, mock_client_configured: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """Live-verified against fmg-prod-01: pyfmg flat-merges kwargs for
        the 'get' method type, but the How-To Guide's captured request nests
        adom/devices/flags/name under 'data' -- a flat call fails live with
        "The data is invalid for the selected URL". Must send a single
        data= kwarg, not spread fields as separate kwargs."""
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            await firmware_tools.get_firmware_upgrade_report(
                device="FGT-01", profile_name="fgt_to_740"
            )

        _, kwargs = mock_fmg_instance.get.call_args
        assert "data" in kwargs
        assert kwargs["data"]["devices"] == [{"name": "FGT-01"}]
        assert kwargs["data"]["name"] == "fgt_to_740"
        assert kwargs["data"]["flags"] == 0
        # nothing spread as a top-level sibling kwarg
        assert "devices" not in kwargs
        assert "name" not in kwargs

    @pytest.mark.asyncio
    async def test_invalid_profile_name_rejected(
        self, mock_client_configured: FortiManagerClient
    ) -> None:
        from fortimanager_mcp.tools import firmware_tools

        with patch.object(firmware_tools, "get_fmg_client", return_value=mock_client_configured):
            result = await firmware_tools.get_firmware_upgrade_report(
                device="FGT-01", profile_name=""
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
