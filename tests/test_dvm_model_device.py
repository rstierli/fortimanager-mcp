"""Unit tests for Device Manager (DVM) tools.

Covers add_model_device version mapping, credential sanitization on
add_device, connection_status validation in search_devices, and device-name
validation parity across the bulk device tools.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import dvm_tools


async def _add(os_version: str) -> dict[str, Any]:
    client = MagicMock()
    client.add_device = AsyncMock(return_value={"device": {}})
    with patch.object(dvm_tools, "get_fmg_client", return_value=client):
        result = await dvm_tools.add_model_device(
            adom="root",
            name="MODEL-FGT",
            serial_number="FGT60FTK00000001",
            platform="FortiGate-60F",
            os_version=os_version,
        )
    assert result["status"] == "success", result
    return client.add_device.call_args.kwargs["device"]


class TestModelDeviceVersionMapping:
    """Version mapping verified live against FMG 7.6.7.

    FMG expects the major version in os_ver ("7.0") and the minor in a
    separate mr field; sending "7.6" as os_ver fails with "Unsupported
    device/ADOM version".
    """

    @pytest.mark.asyncio
    async def test_minor_version_goes_to_mr_field(self) -> None:
        device = await _add("7.6")
        assert device["os_ver"] == "7.0"
        assert device["mr"] == 6

    @pytest.mark.asyncio
    async def test_dot_zero_keeps_mr_zero(self) -> None:
        device = await _add("7.0")
        assert device["os_ver"] == "7.0"
        assert device["mr"] == 0


class TestAddDeviceCredentialSanitization:
    """add_device must never echo plaintext credentials back to the caller,
    even when FMG returns the submitted device object in its response."""

    @pytest.mark.asyncio
    async def test_echoed_device_dict_strips_admin_password(self) -> None:
        client = MagicMock()
        client.add_device = AsyncMock(
            return_value={
                "device": {
                    "name": "FGT-Branch1",
                    "ip": "192.168.1.1",
                    "adm_usr": "admin",
                    "adm_pass": "secret123",
                    "adm_passwd": "secret123",
                },
                "taskid": 42,
            }
        )
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_device(
                adom="root",
                name="FGT-Branch1",
                ip="192.168.1.1",
                admin_user="admin",
                admin_pass="secret123",
            )
        assert result["status"] == "success", result
        assert "adm_pass" not in result["device"]
        assert "adm_passwd" not in result["device"]
        assert result["device"]["name"] == "FGT-Branch1"
        assert result["task_id"] == 42


class TestSearchDevicesConnectionStatus:
    @pytest.mark.asyncio
    async def test_invalid_status_returns_error(self) -> None:
        client = MagicMock()
        client.list_devices = AsyncMock(return_value=[])
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.search_devices(connection_status="bogus")
        assert result["status"] == "error", result
        assert result["error_code"] == "validation_error"
        client.list_devices.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("status", "expected_val"),
        [("up", 1), ("UP", 1), ("down", 2), ("Down", 2)],
    )
    async def test_valid_status_maps_to_filter(self, status: str, expected_val: int) -> None:
        client = MagicMock()
        client.list_devices = AsyncMock(return_value=[])
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.search_devices(connection_status=status)
        assert result["status"] == "success", result
        sent_filter = client.list_devices.call_args.kwargs["filter"]
        assert ["conn_status", "==", expected_val] in sent_filter


class TestBulkDeviceNameValidation:
    @pytest.mark.asyncio
    async def test_add_bulk_invalid_name_returns_validation_error(self) -> None:
        client = MagicMock()
        client.add_device_list = AsyncMock(return_value={"taskid": 1})
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_devices_bulk(
                adom="root",
                devices=[{"name": "bad/name", "ip": "10.0.0.1"}],
            )
        assert result["status"] == "error", result
        assert result["error_code"] == "validation_error"
        client.add_device_list.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_bulk_valid_names_pass(self) -> None:
        client = MagicMock()
        client.add_device_list = AsyncMock(return_value={"taskid": 1})
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_devices_bulk(
                adom="root",
                devices=[
                    {"name": "FGT-Site1", "ip": "10.0.1.1", "adm_pass": "p1"},
                    {"name": "FGT-Site2", "ip": "10.0.2.1", "adm_pass": "p2"},
                ],
            )
        assert result["status"] == "success", result
        assert result["added_count"] == 2
        # Credentials must be stripped from the returned device dicts.
        for device in result["devices"]:
            assert "adm_pass" not in device
        client.add_device_list.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_bulk_invalid_name_returns_validation_error(self) -> None:
        client = MagicMock()
        client.delete_device_list = AsyncMock(return_value={"taskid": 1})
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.delete_devices_bulk(
                adom="root",
                devices=["good-name", "bad/name"],
            )
        assert result["status"] == "error", result
        assert result["error_code"] == "validation_error"
        client.delete_device_list.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_bulk_valid_names_pass(self) -> None:
        client = MagicMock()
        client.delete_device_list = AsyncMock(return_value={"taskid": 5})
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.delete_devices_bulk(
                adom="root",
                devices=["FGT-Old1", "FGT-Old2"],
            )
        assert result["status"] == "success", result
        assert result["deleted_count"] == 2
        client.delete_device_list.assert_called_once()
