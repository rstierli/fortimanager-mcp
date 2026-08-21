"""Tests for device_group_tools: device group CRUD, membership, nesting.

Uses only neutral/example values since this is a public repository. All FMG
calls are mocked (unit-level only) -- no live device or FortiManager needed.
"""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import device_group_tools


@pytest.fixture
def mock_client_ok(
    mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
) -> FortiManagerClient:
    """Mock client whose add/set/delete calls all succeed."""

    def ok(url: str, **kwargs):
        return (0, {"status": {"code": 0, "message": "OK"}})

    mock_fmg_instance.add.side_effect = ok
    mock_fmg_instance.set.side_effect = ok
    mock_fmg_instance.delete.side_effect = ok
    mock_fmg_instance.update.side_effect = ok
    return mock_client


# =============================================================================
# create_device_group / delete_device_group
# =============================================================================


class TestCreateDeviceGroup:
    @pytest.mark.asyncio
    async def test_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.create_device_group(
                adom="root", name="Branch-Firewalls", os_type="fos", description="test group"
            )

        assert result["status"] == "success"
        assert result["group"]["name"] == "Branch-Firewalls"

        called_url = mock_fmg_instance.add.call_args[0][0]
        assert called_url == "/dvmdb/adom/root/group"
        sent_data = mock_fmg_instance.add.call_args.kwargs.get("data")
        assert sent_data == {"name": "Branch-Firewalls", "os_type": "fos", "desc": "test group"}

    @pytest.mark.asyncio
    async def test_default_os_type_is_unknown(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.create_device_group(adom="root", name="Grp1")

        assert result["status"] == "success"
        sent_data = mock_fmg_instance.add.call_args.kwargs.get("data")
        assert sent_data["os_type"] == "unknown"
        assert "desc" not in sent_data

    @pytest.mark.asyncio
    async def test_invalid_os_type_rejected(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.create_device_group(
                adom="root", name="Grp1", os_type="bogus"
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_invalid_adom_rejected(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.create_device_group(adom="bad adom!", name="Grp1")
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with _patched(None):
            result = await device_group_tools.create_device_group(adom="root", name="Grp1")
        assert result["status"] == "error"


class TestDeleteDeviceGroup:
    @pytest.mark.asyncio
    async def test_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.delete_device_group(adom="root", name="Grp1")

        assert result["status"] == "success"
        called_url = mock_fmg_instance.delete.call_args[0][0]
        assert called_url == "/dvmdb/adom/root/group/Grp1"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with _patched(None):
            result = await device_group_tools.delete_device_group(adom="root", name="Grp1")
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_invalid_group_name_rejected(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.delete_device_group(adom="root", name="bad/name;drop")
        assert result["status"] == "error"


# =============================================================================
# add_device_to_group / remove_device_from_group (single)
# =============================================================================


class TestSingleDeviceMembership:
    @pytest.mark.asyncio
    async def test_add_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_device_to_group(
                adom="root", group="Branch-Firewalls", device="FGT-Branch1"
            )

        assert result["status"] == "success"
        called_url = mock_fmg_instance.add.call_args[0][0]
        assert called_url == "/dvmdb/adom/root/group/Branch-Firewalls/object member"
        sent_data = mock_fmg_instance.add.call_args.kwargs.get("data")
        assert sent_data == [{"name": "FGT-Branch1", "vdom": "root"}]

    @pytest.mark.asyncio
    async def test_add_custom_vdom(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            await device_group_tools.add_device_to_group(
                adom="root", group="Grp1", device="FGT-1", vdom="vd1"
            )
        sent_data = mock_fmg_instance.add.call_args.kwargs.get("data")
        assert sent_data == [{"name": "FGT-1", "vdom": "vd1"}]

    @pytest.mark.asyncio
    async def test_remove_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.remove_device_from_group(
                adom="root", group="Branch-Firewalls", device="FGT-Branch1"
            )

        assert result["status"] == "success"
        called_url = mock_fmg_instance.delete.call_args[0][0]
        assert called_url == "/dvmdb/adom/root/group/Branch-Firewalls/object member"
        sent_data = mock_fmg_instance.delete.call_args.kwargs.get("data")
        assert sent_data == [{"name": "FGT-Branch1", "vdom": "root"}]

    @pytest.mark.asyncio
    async def test_add_invalid_device_name_rejected(
        self, mock_client_ok: FortiManagerClient
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_device_to_group(
                adom="root", group="Grp1", device="bad;device"
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_add_invalid_vdom_rejected(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_device_to_group(
                adom="root", group="Grp1", device="FGT-1", vdom="bad vdom!"
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with _patched(None):
            result = await device_group_tools.add_device_to_group(
                adom="root", group="Grp1", device="FGT-1"
            )
        assert result["status"] == "error"


# =============================================================================
# add_devices_to_group_bulk / remove_devices_from_group_bulk
# =============================================================================


class TestBulkDeviceMembership:
    @pytest.mark.asyncio
    async def test_add_bulk_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_devices_to_group_bulk(
                adom="root", group="Grp1", devices=["FGT-1", "FGT-2"]
            )

        assert result["status"] == "success"
        assert result["added_count"] == 2
        sent_data = mock_fmg_instance.add.call_args.kwargs.get("data")
        assert sent_data == [
            {"name": "FGT-1", "vdom": "root"},
            {"name": "FGT-2", "vdom": "root"},
        ]

    @pytest.mark.asyncio
    async def test_remove_bulk_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.remove_devices_from_group_bulk(
                adom="root", group="Grp1", devices=["FGT-1", "FGT-2"]
            )

        assert result["status"] == "success"
        assert result["removed_count"] == 2
        sent_data = mock_fmg_instance.delete.call_args.kwargs.get("data")
        assert sent_data == [
            {"name": "FGT-1", "vdom": "root"},
            {"name": "FGT-2", "vdom": "root"},
        ]

    @pytest.mark.asyncio
    async def test_add_bulk_empty_list_errors(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_devices_to_group_bulk(
                adom="root", group="Grp1", devices=[]
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_remove_bulk_empty_list_errors(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.remove_devices_from_group_bulk(
                adom="root", group="Grp1", devices=[]
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_add_bulk_rejects_one_bad_name(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_devices_to_group_bulk(
                adom="root", group="Grp1", devices=["FGT-1", "bad;name"]
            )
        assert result["status"] == "error"


# =============================================================================
# add_group_to_group / remove_group_from_group (nesting)
# =============================================================================


class TestGroupNesting:
    @pytest.mark.asyncio
    async def test_add_group_to_group_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_group_to_group(
                adom="root", parent_group="All-Branches", child_group="Branch-Firewalls"
            )

        assert result["status"] == "success"
        called_url = mock_fmg_instance.add.call_args[0][0]
        assert called_url == "/dvmdb/adom/root/group/All-Branches/object member"
        sent_data = mock_fmg_instance.add.call_args.kwargs.get("data")
        # A nested-group member has no vdom key (distinguishes it from a device member).
        assert sent_data == [{"name": "Branch-Firewalls"}]

    @pytest.mark.asyncio
    async def test_remove_group_from_group_success(
        self, mock_client_ok: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.remove_group_from_group(
                adom="root", parent_group="All-Branches", child_group="Branch-Firewalls"
            )

        assert result["status"] == "success"
        called_url = mock_fmg_instance.delete.call_args[0][0]
        assert called_url == "/dvmdb/adom/root/group/All-Branches/object member"
        sent_data = mock_fmg_instance.delete.call_args.kwargs.get("data")
        assert sent_data == [{"name": "Branch-Firewalls"}]

    @pytest.mark.asyncio
    async def test_self_nesting_rejected(self, mock_client_ok: FortiManagerClient) -> None:
        with _patched(mock_client_ok):
            result = await device_group_tools.add_group_to_group(
                adom="root", parent_group="Grp1", child_group="Grp1"
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with _patched(None):
            result = await device_group_tools.add_group_to_group(
                adom="root", parent_group="Grp1", child_group="Grp2"
            )
        assert result["status"] == "error"


# =============================================================================
# Helpers
# =============================================================================


def _patched(client):
    """Patch device_group_tools.get_fmg_client to return the given client (or None)."""
    return patch.object(device_group_tools, "get_fmg_client", return_value=client)


class TestBulkDeviceArgumentShape:
    """A bare string is one device name, not one per character.

    upstream #71: devices="FGT-01" was iterated character by character into
    six single-character names, each of which passes the device-name
    pattern, so nothing downstream noticed and six bogus members were sent.
    """

    @pytest.mark.asyncio
    async def test_a_bare_string_adds_one_device(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {})

        with patch.object(device_group_tools, "get_fmg_client", return_value=mock_client):
            result = await device_group_tools.add_devices_to_group_bulk(
                "root", "Branch-Firewalls", "FGT-01"
            )

        assert result["status"] == "success"
        assert result["added_count"] == 1
        members = mock_fmg_instance.add.call_args.kwargs["data"]
        assert [m["name"] for m in members] == ["FGT-01"]

    @pytest.mark.asyncio
    async def test_a_bare_string_removes_one_device(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.delete.return_value = (0, {})

        with patch.object(device_group_tools, "get_fmg_client", return_value=mock_client):
            result = await device_group_tools.remove_devices_from_group_bulk(
                "root", "Branch-Firewalls", "FGT-01"
            )

        assert result["status"] == "success"
        assert result["removed_count"] == 1

    @pytest.mark.asyncio
    async def test_a_real_list_is_unchanged(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.add.return_value = (0, {})

        with patch.object(device_group_tools, "get_fmg_client", return_value=mock_client):
            result = await device_group_tools.add_devices_to_group_bulk(
                "root", "Branch-Firewalls", ["FGT-01", "FGT-02"]
            )

        assert result["added_count"] == 2
