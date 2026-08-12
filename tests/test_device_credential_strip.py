"""No READ path may return a managed device's admin password.

`add_device` and `add_devices_bulk` have always stripped the credential
from the object FortiManager echoes back. No read path did, so the stored
password came out of `list_devices`, `get_device`, `search_devices` and
`get_device_status`.

Asking FortiManager for a narrow field list does not help: `fields` is a
hint, not a bound. Measured on live 7.6.7, `list_adoms(fields=["name"])`
returns `name` AND `oid`, and the client passes `fields` through
untouched, so `get_device_status`'s explicit list cannot keep the
credential out either.

Values here are invented; no credential from any estate appears.
"""

import inspect
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import dvm_tools, system_tools

SECRET = "not-a-real-password"

#: A dvmdb device record as the read paths receive it, with the admin
#: password under both spellings FortiManager uses, plus the two other
#: secrets a record carries: the FGFM tunnel pre-shared key and the device
#: certificate key. All four use the same value, so every `SECRET not in
#: repr(result)` assertion below covers all four.
DEVICE_WITH_CREDENTIAL = {
    "name": "FGT-01",
    "ip": "192.0.2.1",
    "sn": "FGT60F0000000001",
    "adm_usr": "admin",
    "adm_pass": SECRET,
    "adm_passwd": SECRET,
    "psk": SECRET,
    "private_key": SECRET,
    "conn_status": 1,
    "os_ver": "7.4.4",
}


class TestNoReadPathReturnsTheCredential:
    @pytest.mark.asyncio
    async def test_list_devices(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [dict(DEVICE_WITH_CREDENTIAL)])

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client):
            result = await system_tools.list_devices(adom="root")

        assert SECRET not in repr(result)
        assert result["devices"][0]["name"] == "FGT-01"
        assert result["devices"][0]["adm_usr"] == "admin"

    @pytest.mark.asyncio
    async def test_get_device(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, dict(DEVICE_WITH_CREDENTIAL))

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client):
            result = await system_tools.get_device(name="FGT-01", adom="root")

        assert SECRET not in repr(result)
        assert result["device"]["name"] == "FGT-01"

    @pytest.mark.asyncio
    async def test_get_device_status(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [dict(DEVICE_WITH_CREDENTIAL)])

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.get_device_status(adom="root")

        assert SECRET not in repr(result)
        # The decoded status fields still arrive.
        assert result["devices"][0]["conn_status_str"]

    @pytest.mark.asyncio
    async def test_search_devices(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [dict(DEVICE_WITH_CREDENTIAL)])

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.search_devices(adom="root", name_filter="FGT")

        assert SECRET not in repr(result)
        assert result["devices"][0]["name"] == "FGT-01"

    @pytest.mark.asyncio
    async def test_list_device_vdoms(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """The same record class, reached by its own tool.

        `get_device(include_details=True)` strips VDOM subobjects, so a raw
        `list_device_vdoms` would make the same record safe by one route
        and not the other.
        """
        mock_fmg_instance.get.return_value = (0, [{"name": "root", "adm_pass": SECRET}])

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.list_device_vdoms(device="FGT-01", adom="root")

        assert SECRET not in repr(result)
        assert result["vdoms"][0]["name"] == "root"

    @pytest.mark.asyncio
    async def test_a_credential_nested_in_a_vdom_subobject_is_also_gone(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """include_details pulls VDOM sub-objects, so the walk must recurse."""
        record = dict(DEVICE_WITH_CREDENTIAL)
        record["vdom"] = [{"name": "root", "adm_pass": SECRET}]
        mock_fmg_instance.get.return_value = (0, record)

        with patch.object(system_tools, "get_fmg_client", return_value=mock_client):
            result = await system_tools.get_device(name="FGT-01", adom="root", include_details=True)

        assert SECRET not in repr(result)
        assert result["device"]["vdom"][0]["name"] == "root"


class TestTheStripCannotBeForgotten:
    """A future device-returning tool must not silently miss the strip."""

    def test_every_device_returning_tool_calls_the_helper(self) -> None:
        """ADD YOUR TOOL HERE if it returns a dvmdb device record.

        This list is fixed, not discovered, so it cannot catch a new tool
        on its own: it proves the tools it names still strip, and nothing
        about the one you just wrote. Discovering the set automatically
        would mean matching on tool names or return shapes, and either
        heuristic passes silently on the tool it fails to recognise, which
        is the same blind spot with more machinery.
        """
        expected = {
            (system_tools, "list_devices"),
            (system_tools, "get_device"),
            (dvm_tools, "get_device_status"),
            (dvm_tools, "search_devices"),
            (dvm_tools, "add_device"),
            (dvm_tools, "add_devices_bulk"),
            (dvm_tools, "list_device_vdoms"),
        }

        for module, name in expected:
            source = inspect.getsource(getattr(module, name))
            assert "strip_device_credentials" in source or "DEVICE_CREDENTIAL_KEYS" in source, (
                f"{module.__name__}.{name} returns device records without stripping credentials"
            )

    def test_the_write_paths_share_one_key_set(self) -> None:
        """The two spellings were duplicated as literals in two places.

        That duplication is why the read-side fix I wrote first covered
        only one spelling. There is one definition now.
        """
        source = inspect.getsource(dvm_tools)
        assert '"adm_pass", "adm_passwd"' not in source, (
            "a literal credential-key list has reappeared; use DEVICE_CREDENTIAL_KEYS"
        )
