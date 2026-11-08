"""Unit tests for Device Manager (DVM) tools.

Covers add_model_device version mapping, credential sanitization on
add_device, connection_status validation in search_devices, and device-name
validation parity across the bulk device tools.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import dvm_tools
from fortimanager_mcp.utils.errors import ResourceNotFoundError
from fortimanager_mcp.utils.validation import MASK_VALUE


def _absent(client: MagicMock) -> MagicMock:
    """No device with this name or serial exists before the add."""
    client.get_device = AsyncMock(side_effect=ResourceNotFoundError("nope", code=-3))
    client.list_devices = AsyncMock(return_value=[])
    return client


async def _add(os_version: str) -> dict[str, Any]:
    client = _absent(MagicMock())
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
                    # FortiManager echoes the record back, so the echo carries
                    # every secret the record holds, not only the password
                    # that was submitted.
                    "psk": "secret123",
                    "private_key": "secret123",
                    "private_key_status": 1,
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
        assert "secret123" not in repr(result)
        for key in ("adm_pass", "adm_passwd", "psk", "private_key"):
            assert key not in result["device"], key
        # Not a secret: it reports whether a key is set, not the key.
        assert result["device"]["private_key_status"] == 1
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
                    {
                        "name": "FGT-Site2",
                        "ip": "10.0.2.1",
                        "adm_passwd": "p2",
                        "psk": "p2",
                        "private_key": "p2",
                    },
                ],
            )
        assert result["status"] == "success", result
        assert result["requested_count"] == 2
        # Every secret must be stripped from the returned device dicts, not
        # just the password spelling this test started with.
        assert "p1" not in repr(result["devices"])
        assert "p2" not in repr(result["devices"])
        for device in result["devices"]:
            for key in ("adm_pass", "adm_passwd", "psk", "private_key"):
                assert key not in device, key
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
        assert result["requested_count"] == 2
        client.delete_device_list.assert_called_once()


async def _add_with(
    get: AsyncMock | None = None, **kwargs: Any
) -> tuple[dict[str, Any], MagicMock]:
    client = _absent(MagicMock())
    client.add_device = AsyncMock(return_value={"device": {}})
    client.get = get or AsyncMock(return_value={})
    client.get_metadata_variables = AsyncMock(return_value=[])
    with patch.object(dvm_tools, "get_fmg_client", return_value=client):
        result = await dvm_tools.add_model_device(
            adom="demo",
            name="branch1",
            serial_number="FGVM020000123456",
            platform="FortiGate-VM64-KVM",
            **kwargs,
        )
    return result, client


class TestModelDeviceBlueprint:
    """Blueprint, meta variables, groups and patch level on a model device."""

    @pytest.mark.asyncio
    async def test_patch_level_is_split_out(self) -> None:
        result, client = await _add_with(os_version="7.4.12")
        assert result["status"] == "success", result
        device = client.add_device.call_args.kwargs["device"]
        assert (device["os_ver"], device["mr"], device["patch"]) == ("7.0", 4, 12)

    @pytest.mark.asyncio
    async def test_two_part_version_sends_no_patch(self) -> None:
        _, client = await _add_with(os_version="7.4")
        assert "patch" not in client.add_device.call_args.kwargs["device"]

    @pytest.mark.asyncio
    async def test_blueprint_and_meta_variables_use_the_gui_keys(self) -> None:
        result, client = await _add_with(
            os_version="7.4",
            device_blueprint="branch_standalone_blueprint",
            meta_variables={"hostname": "branch1", "branch_id": 1, "port3": "192.0.2.1/24"},
        )
        assert result["status"] == "success", result
        device = client.add_device.call_args.kwargs["device"]
        assert device["device blueprint"] == "branch_standalone_blueprint"
        assert device["meta variables"] == {
            "hostname": "branch1",
            "branch_id": "1",
            "port3": "192.0.2.1/24",
        }

    @pytest.mark.asyncio
    async def test_groups_are_sent_top_level_with_root_vdom(self) -> None:
        _, client = await _add_with(groups=["spoke"])
        assert client.add_device.call_args.kwargs["groups"] == [{"name": "spoke", "vdom": "root"}]

    @pytest.mark.asyncio
    async def test_no_new_fields_when_not_asked(self) -> None:
        _, client = await _add_with()
        kwargs = client.add_device.call_args.kwargs
        assert kwargs["groups"] is None
        assert "device blueprint" not in kwargs["device"]
        assert "meta variables" not in kwargs["device"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "meta",
        [
            {"bad name": "x"},
            {"$(inject)": "x"},
            {"port1": ["192.0.2.1"]},
            {"port1": None},
            {"flag": True},
            {"long": "x" * 256},
            ["not", "a", "dict"],
            # A template pastes the value into CLI as is: a line break would
            # add CLI lines to the next install.
            {"hostname": "b1\nconfig system admin\nedit evil"},
            {"hostname": "b1\rend"},
            {"hostname": "b1\tx"},
            {"hostname": "b1\x00"},
            {"hostname": "b1\x7f"},
            # The marker this server puts in place of a password value.
            {"psk": MASK_VALUE},
            # A value that ends a quoted CLI value, escapes, starts a comment,
            # or reads as a template expression or another variable.
            {"desc": 'x" next'},
            {"desc": "x\\"},
            {"desc": "Branch #1"},
            {"desc": "{{ psk }}"},
            {"desc": "{% if 1 %}"},
            {"desc": "{# c #}"},
            {"desc": "$(psk)"},
            # C1 controls and the Unicode line and paragraph separators.
            {"desc": "b1\x85end"},
            {"desc": "b1\x9b"},
            {"desc": "b1\u2028end"},
            {"desc": "b1\u2029end"},
        ],
    )
    async def test_invalid_meta_variables_are_refused_before_any_call(self, meta: Any) -> None:
        result, client = await _add_with(meta_variables=meta)
        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        client.add_device.assert_not_called()
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_meta_variable_value_with_spaces_and_symbols_is_kept(self) -> None:
        banner = "Branch 1 (EMEA) - $site no.1, O'Hare @ 50% {x} [a]: ok/ok & ü"
        result, client = await _add_with(meta_variables={"banner": banner, "port3": "192.0.2.1/24"})
        assert result["status"] == "success", result
        assert client.add_device.call_args.kwargs["device"]["meta variables"] == {
            "banner": banner,
            "port3": "192.0.2.1/24",
        }

    @pytest.mark.asyncio
    async def test_refused_meta_character_is_named_in_the_error(self) -> None:
        result, _ = await _add_with(meta_variables={"desc": "Branch #1"})
        assert "'#'" in result["message"], result

    @pytest.mark.asyncio
    @pytest.mark.parametrize("serial", ["", "NOTASERIAL", "FGVM0200;rm", "FG12"])
    async def test_invalid_primary_serial_is_refused(self, serial: str) -> None:
        client = MagicMock()
        client.add_device = AsyncMock(return_value={"device": {}})
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_model_device(
                adom="demo", name="branch1", serial_number=serial
            )
        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        client.add_device.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_blueprint_name_is_refused(self) -> None:
        result, client = await _add_with(device_blueprint="bad;name")
        assert result["status"] == "error"
        client.add_device.assert_not_called()


_SECONDARY = {"name": "branch3-1", "serial_number": "FGVM020000123458", "priority": 100}


class TestModelHaCluster:
    """A model HA cluster is one add/device call carrying ha_mode, ha_group_name
    and an ha_slave table that lists every member, the primary included."""

    @pytest.mark.asyncio
    async def test_cluster_fields_and_member_table(self) -> None:
        result, client = await _add_with(
            ha_mode="AP",
            ha_group_name="branch3_cluster",
            ha_priority=200,
            ha_members=[_SECONDARY],
        )
        assert result["status"] == "success", result
        device = client.add_device.call_args.kwargs["device"]
        assert device["ha_mode"] == "AP"
        assert device["ha_group_name"] == "branch3_cluster"
        assert device["ha_slave"] == [
            {
                "name": "branch1",
                "sn": "FGVM020000123456",
                "prio": 200,
                "role": "master",
                "idx": 0,
            },
            {
                "name": "branch3-1",
                "sn": "FGVM020000123458",
                "prio": 100,
                "role": "slave",
                "idx": 1,
            },
        ]

    @pytest.mark.asyncio
    async def test_member_serial_is_normalized(self) -> None:
        result, client = await _add_with(
            ha_mode="AP",
            ha_group_name="c",
            ha_members=[{**_SECONDARY, "serial_number": " fgvm020000123458 "}],
        )
        assert result["status"] == "success", result
        assert client.add_device.call_args.kwargs["device"]["ha_slave"][1]["sn"] == (
            "FGVM020000123458"
        )

    @pytest.mark.asyncio
    async def test_standalone_sends_no_ha_fields(self) -> None:
        _, client = await _add_with()
        device = client.add_device.call_args.kwargs["device"]
        assert not {"ha_mode", "ha_group_name", "ha_slave"} & device.keys()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ha_mode": "AP", "ha_members": [_SECONDARY]},  # no group name
            {"ha_mode": "AP", "ha_group_name": "c"},  # no members
            {"ha_mode": "ELBC", "ha_group_name": "c", "ha_members": [_SECONDARY]},
            {"ha_group_name": "c", "ha_members": [_SECONDARY]},  # no mode
            {
                "ha_mode": "AP",
                "ha_group_name": "c",
                "ha_members": [{**_SECONDARY, "serial_number": "FGVM020000123456"}],
            },
            {
                "ha_mode": "AP",
                "ha_group_name": "c",
                "ha_members": [{**_SECONDARY, "priority": 300}],
            },
            {"ha_mode": "AP", "ha_group_name": "c", "ha_members": [{"name": "x"}]},
            {"ha_mode": "AP", "ha_group_name": "c", "ha_priority": -1, "ha_members": [_SECONDARY]},
            # Member serials are held to the same format as the primary's.
            {
                "ha_mode": "AP",
                "ha_group_name": "c",
                "ha_members": [{**_SECONDARY, "serial_number": "not-a-serial"}],
            },
            {
                "ha_mode": "AP",
                "ha_group_name": "c",
                "ha_members": [{**_SECONDARY, "serial_number": "FGVM0200;00123458"}],
            },
            # The primary's serial in another case is still the primary.
            {
                "ha_mode": "AP",
                "ha_group_name": "c",
                "ha_members": [{**_SECONDARY, "serial_number": "fgvm020000123456"}],
            },
            {"ha_mode": "AP", "ha_group_name": "c" * 37, "ha_members": [_SECONDARY]},
        ],
    )
    async def test_invalid_cluster_is_refused_before_any_call(self, kwargs: dict[str, Any]) -> None:
        result, client = await _add_with(**kwargs)
        assert result["status"] == "error"
        client.add_device.assert_not_called()


_VARIABLES = [
    {
        "name": "hostname",
        "type": 0,
        "value": "default-host",
        "dynamic_mapping": [
            {"_scope": [{"name": "branch2", "vdom": "global"}], "value": "branch2"},
        ],
    },
    {"name": "branch_id", "type": 0, "value": "0", "dynamic_mapping": None},
    {
        "name": "psk",
        "type": "password",
        "value": "s3cret",
        "dynamic_mapping": [{"_scope": [{"name": "branch2", "vdom": "global"}], "value": "x"}],
    },
]


def _var_client() -> MagicMock:
    client = MagicMock()
    client.get_metadata_variables = AsyncMock(return_value=_VARIABLES)
    return client


class TestMetadataVariables:
    @pytest.mark.asyncio
    async def test_list_flattens_mappings_and_redacts_passwords(self) -> None:
        client = _var_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.list_metadata_variables(adom="demo")
        assert result["status"] == "success", result
        client.get_metadata_variables.assert_awaited_once_with("demo")
        by_name = {v["name"]: v for v in result["variables"]}
        assert by_name["hostname"]["mappings"] == [
            {"device": "branch2", "vdom": "global", "value": "branch2"}
        ]
        assert by_name["branch_id"]["mappings"] == []
        assert "s3cret" not in str(result) and ": 'x'" not in str(result)
        assert by_name["psk"]["default"] == MASK_VALUE

    @pytest.mark.asyncio
    async def test_list_for_device_gives_effective_values(self) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=_var_client()):
            result = await dvm_tools.list_metadata_variables(adom="demo", device="branch2")
        assert result["device_values"]["hostname"] == {"value": "branch2", "source": "device"}
        assert result["device_values"]["branch_id"] == {"value": "0", "source": "default"}

    @pytest.mark.asyncio
    async def test_check_classifies_each_variable(self) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=_var_client()):
            result = await dvm_tools.check_device_variables(
                adom="demo",
                device="branch2",
                expected={"hostname": "branch2", "branch_id": 2, "nope": "1"},
            )
        assert result["status"] == "success", result
        assert result["ok"] is False
        assert result["match"] == ["hostname"]
        assert result["not_mapped"] == [{"name": "branch_id", "expected": "2", "default": "0"}]
        assert result["undefined"] == ["nope"]

    @pytest.mark.asyncio
    async def test_check_reports_mismatch_and_ok(self) -> None:
        with patch.object(dvm_tools, "get_fmg_client", return_value=_var_client()):
            bad = await dvm_tools.check_device_variables(
                adom="demo", device="branch2", expected={"hostname": "other"}
            )
            good = await dvm_tools.check_device_variables(
                adom="demo", device="branch2", expected={"hostname": "branch2"}
            )
        assert bad["mismatch"] == [{"name": "hostname", "expected": "other", "actual": "branch2"}]
        assert good["ok"] is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "expected", [{"bad name": "x"}, {"hostname": "b2\nend"}, {"hostname": 'b2"'}]
    )
    async def test_check_refuses_invalid_expected(self, expected: dict[str, Any]) -> None:
        client = _var_client()
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.check_device_variables(
                adom="demo", device="branch2", expected=expected
            )
        assert result["status"] == "error"
        client.get_metadata_variables.assert_not_called()


_GUI_BLUEPRINT: dict[str, Any] = {
    "platform": "FortiGate-VM64",
    "port-provisioning": 1,
    "vm-log-disk": 1,
    "linked-to-model": False,
    "enforce-device-config": 0,
    "autolink-retrieve": False,
    "prefer-img-ver": "7.0.17-b682|0",
    "firmware-template": "campus_emea",
    "download_from_fgd": False,
    "sdwan-management": 0,
    "dev-group": ["emea_spokes"],
    "folder": "/",
    "auth-template": "branch_templates_FAT",
    "prerun-cliprof": "cluster_bootstrap",
    "pkg": "branch_pkg",
    "cluster-worker": [],
    "prov-type": "template-group",
    "template-group": "branch_templates",
    "templates": [],
}


def _not_found_for(*fragments: str) -> AsyncMock:
    """client.get that raises -3 for URLs containing any fragment."""

    async def get(url: str, **_: Any) -> Any:
        if any(f in url for f in fragments):
            raise ResourceNotFoundError("Object does not exist", code=-3)
        return {}

    return AsyncMock(side_effect=get)


class TestInlineBlueprint:
    """The GUI's inline blueprint object (blueprint option unchecked)."""

    @pytest.mark.asyncio
    async def test_gui_capture_is_normalized_and_sent(self) -> None:
        result, client = await _add_with(device_blueprint=_GUI_BLUEPRINT, confirm=True)
        assert result["status"] == "success", result
        bp = client.add_device.call_args.kwargs["device"]["device blueprint"]
        assert bp["vm-log-disk"] == "enable"
        assert bp["linked-to-model"] == "disable"
        assert bp["enforce-device-config"] == "disable"
        assert bp["auth-template"] == "branch_templates_FAT"
        assert bp["prerun-cliprof"] == "cluster_bootstrap"
        assert bp["dev-group"] == ["emea_spokes"]
        assert bp["template-group"] == "branch_templates"
        assert "unverified_references" not in result

    @pytest.mark.asyncio
    async def test_every_named_object_is_looked_up(self) -> None:
        get = AsyncMock(return_value={})
        await _add_with(get=get, device_blueprint=_GUI_BLUEPRINT, confirm=True)
        urls = [c.args[0] for c in get.call_args_list]
        assert "/pm/pkg/adom/demo/branch_pkg" in urls
        assert "/pm/tmplgrp/adom/demo/branch_templates" in urls
        assert "/dvmdb/adom/demo/group/emea_spokes" in urls
        assert (
            "/pm/config/adom/demo/obj/fmg/fabric/authorization/template/branch_templates_FAT"
            in urls
        )
        assert "/pm/config/adom/demo/obj/cli/template/cluster_bootstrap" in urls
        assert "/pm/fwmprof/adom/demo/campus_emea" in urls

    @pytest.mark.asyncio
    async def test_missing_reference_refuses_the_add(self) -> None:
        result, client = await _add_with(
            get=_not_found_for("cluster_bootstrap", "/group/emea_spokes"),
            device_blueprint=_GUI_BLUEPRINT,
            confirm=True,
        )
        assert result["status"] == "error"
        assert result["error_code"] == "blueprint_reference_missing"
        assert result["missing"] == [
            "device group 'emea_spokes'",
            "pre-run CLI template 'cluster_bootstrap'",
        ]
        client.add_device.assert_not_called()

    @pytest.mark.asyncio
    async def test_cli_template_group_satisfies_cliprofs(self) -> None:
        result, _ = await _add_with(
            get=_not_found_for("/cli/template/"),
            device_blueprint={"cliprofs": ["branch_templates_CLIGRP"]},
        )
        assert result["status"] == "success", result

    @pytest.mark.asyncio
    async def test_lookup_failure_is_reported_not_blocking(self) -> None:
        async def get(url: str, **_: Any) -> Any:
            if "fwmprof" in url:
                raise RuntimeError("unsupported url")
            return {}

        result, client = await _add_with(
            get=AsyncMock(side_effect=get), device_blueprint=_GUI_BLUEPRINT, confirm=True
        )
        assert result["status"] == "success", result
        assert result["unverified_references"] == ["firmware template 'campus_emea'"]
        client.add_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_saved_blueprint_must_exist(self) -> None:
        result, client = await _add_with(
            get=_not_found_for("/fmg/device/blueprint/"),
            device_blueprint="no_such_blueprint",
        )
        assert result["status"] == "error"
        assert result["missing"] == ["device blueprint 'no_such_blueprint'"]
        client.add_device.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "blueprint",
        [
            {"ha-password": ["secret"]},
            {"unknown-key": "x"},
            {"prov-type": "magic"},
            {"prov-type": "template-group"},
            {"prov-type": "templates", "templates": []},
            {"vm-log-disk": "maybe"},
            {"dev-group": [1]},
            {"pkg": ["a"]},
            {"port-provisioning": -1},
            {"prerun-cliprof": ["a", "b"]},
            # Names are looked up by URL: a "/" or ".." would address
            # another object than the one named.
            {"dev-group": ["spokes/../other"]},
            {"template-group": "../branch_templates"},
            {"firmware-template": "a/b"},
            {"prerun-cliprof": "a/../b"},
            {"cliprofs": ["x;y"]},
            {"pkg": "../pkg"},
        ],
    )
    async def test_invalid_inline_blueprint_is_refused(self, blueprint: dict[str, Any]) -> None:
        result, client = await _add_with(device_blueprint=blueprint)
        assert result["status"] == "error"
        client.get.assert_not_called()
        client.add_device.assert_not_called()


_SERIAL = "FGVM020000123456"


def _partial_client(before: Any, after: Any, serial_users: list[Any] | None = None) -> MagicMock:
    """add_device fails; get_device answers ``before`` then ``after``.

    Each of before/after is a record dict, or an exception to raise.
    """
    client = MagicMock()
    client.get = AsyncMock(return_value={})
    client.add_device = AsyncMock(side_effect=RuntimeError("boom"))
    client.get_device = AsyncMock(side_effect=[before, after])
    client.list_devices = AsyncMock(return_value=serial_users or [])
    return client


async def _add_partial(client: MagicMock) -> dict[str, Any]:
    with patch.object(dvm_tools, "get_fmg_client", return_value=client):
        return await dvm_tools.add_model_device(adom="demo", name="branch1", serial_number=_SERIAL)


_NOT_FOUND = ResourceNotFoundError("nope", code=-3)


class TestPartialCreation:
    @pytest.mark.asyncio
    async def test_failed_add_with_device_present_is_flagged(self) -> None:
        client = _partial_client(_NOT_FOUND, {"name": "branch1", "sn": _SERIAL})
        result = await _add_partial(client)
        assert result["status"] == "error"
        assert result["partially_created"] is True
        assert "delete it" in result["message"]
        client.get_device.assert_awaited_with("branch1", adom="demo")

    @pytest.mark.asyncio
    async def test_failed_add_without_device_is_plain_error(self) -> None:
        client = _partial_client(_NOT_FOUND, _NOT_FOUND)
        result = await _add_partial(client)
        assert result["status"] == "error"
        assert "partially_created" not in result

    @pytest.mark.asyncio
    async def test_existing_name_is_refused_and_never_called_partial(self) -> None:
        client = _partial_client({"name": "branch1", "sn": "FGVM020000999999"}, None)
        result = await _add_partial(client)
        assert result["status"] == "error"
        assert result["error_code"] == "device_exists"
        assert result.get("partially_created") is not True
        assert "delete" not in result["message"].lower()
        assert "already exists" in result["message"]
        client.add_device.assert_not_called()

    @pytest.mark.asyncio
    async def test_serial_in_use_is_refused(self) -> None:
        client = _partial_client(
            _NOT_FOUND, None, serial_users=[{"name": "branch9", "sn": _SERIAL.lower()}]
        )
        result = await _add_partial(client)
        assert result["status"] == "error"
        assert result["error_code"] == "device_exists"
        assert "branch9" in result["message"]
        assert "delete" not in result["message"].lower()
        client.add_device.assert_not_called()

    @pytest.mark.asyncio
    async def test_present_after_with_other_serial_is_not_claimed(self) -> None:
        client = _partial_client(_NOT_FOUND, {"name": "branch1", "sn": "FGVM020000999999"})
        result = await _add_partial(client)
        assert result["status"] == "error"
        assert result.get("partially_created") is not True
        assert "delete" not in result["message"].lower()

    @pytest.mark.asyncio
    async def test_unverified_before_is_never_claimed_partial(self) -> None:
        client = _partial_client(RuntimeError("lookup failed"), {"name": "branch1", "sn": _SERIAL})
        result = await _add_partial(client)
        assert result["status"] == "error"
        client.add_device.assert_called_once()
        assert result.get("partially_created") is not True
        assert result.get("device_present") is True
        assert "delete" not in result["message"].lower()

    @pytest.mark.asyncio
    async def test_failure_before_the_add_is_not_checked_for_partial(self) -> None:
        # The name existed all along; the call fails before it adds anything.
        client = _partial_client({"name": "branch1", "sn": _SERIAL}, None)
        client.get_device = AsyncMock(return_value={"name": "branch1", "sn": _SERIAL})
        with (
            patch.object(
                dvm_tools,
                "_check_blueprint_references",
                AsyncMock(side_effect=RuntimeError("x")),
            ),
            patch.object(dvm_tools, "get_fmg_client", return_value=client),
        ):
            result = await dvm_tools.add_model_device(
                adom="demo",
                name="branch1",
                serial_number=_SERIAL,
                device_blueprint={"pkg": "branch_pkg"},
            )
        assert result["status"] == "error"
        client.add_device.assert_not_called()
        assert "partially_created" not in result
        assert "delete" not in result["message"].lower()


class TestModelDeviceFlags:
    @pytest.mark.asyncio
    async def test_flags_are_passed_and_task_id_returned(self) -> None:
        client = _absent(MagicMock())
        client.get = AsyncMock(return_value={})
        client.add_device = AsyncMock(return_value={"device": {}, "taskid": 42})
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_model_device(
                adom="demo",
                name="branch5",
                serial_number="FGVM020000123459",
                flags=["create_task"],
            )
        assert result["status"] == "success", result
        assert result["task_id"] == 42
        assert client.add_device.call_args.kwargs["flags"] == ["create_task"]

    @pytest.mark.asyncio
    async def test_unknown_flag_is_refused(self) -> None:
        result, client = await _add_with(flags=["force"])
        assert result["status"] == "error"
        client.add_device.assert_not_called()


_TASK_FAILED = {
    "state": 5,
    "line": [
        {
            "history": [
                {"detail": "2026-10-12 23:59:42:adddev", "state": 1},
                {
                    "detail": "2026-10-12 23:59:44:Pre-run CLI template [cluster_bootstrap] "
                    "error: invalid ip\n",
                    "state": 5,
                },
                {
                    "detail": "2026-10-12 23:59:44:Authorization template [branch_templates_FAT] "
                    "generation error: datasrc invalid",
                    "state": 5,
                },
                {"detail": "2026-10-12 23:59:44:devadderror", "state": 5},
            ]
        }
    ],
}


def _task_client(*task_states: dict[str, Any]) -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock(return_value={})
    client.add_device = AsyncMock(return_value={"taskid": 337})
    client.get_task = AsyncMock(side_effect=list(task_states))
    client.get_device = AsyncMock(
        side_effect=[_NOT_FOUND, {"name": "branch5", "sn": "FGVM020000123459"}]
    )
    client.list_devices = AsyncMock(return_value=[])
    client.get_metadata_variables = AsyncMock(return_value=[])
    return client


class TestBlueprintAddRunsAsTask:
    async def _add(self, client: MagicMock, **kwargs: Any) -> dict[str, Any]:
        with (
            patch.object(dvm_tools, "get_fmg_client", return_value=client),
            patch.object(dvm_tools.asyncio, "sleep", AsyncMock()),
        ):
            return await dvm_tools.add_model_device(
                adom="demo",
                name="branch5",
                serial_number="FGVM020000123459",
                device_blueprint={"pkg": "branch_pkg"},
                **kwargs,
            )

    @pytest.mark.asyncio
    async def test_failed_steps_are_reported(self) -> None:
        client = _task_client({"state": 1}, _TASK_FAILED)
        result = await self._add(client)
        assert client.add_device.call_args.kwargs["flags"] == ["create_task", "nonblocking"]
        assert result["status"] == "error"
        assert result["error_code"] == "model_device_task_failed"
        assert result["task_state"] == "error"
        assert result["partially_created"] is True
        assert result["task_errors"] == [
            "Pre-run CLI template [cluster_bootstrap] error: invalid ip",
            "Authorization template [branch_templates_FAT] generation error: datasrc invalid",
        ]

    @pytest.mark.asyncio
    async def test_clean_task_is_success(self) -> None:
        client = _task_client({"state": 4, "line": [{"history": []}]})
        result = await self._add(client)
        assert result["status"] == "success", result
        assert result["task_id"] == 337

    @pytest.mark.asyncio
    async def test_caller_flags_are_respected(self) -> None:
        client = _task_client()
        client.add_device = AsyncMock(return_value={"device": {}})
        result = await self._add(client, flags=["create_task"])
        assert result["status"] == "success", result
        assert client.add_device.call_args.kwargs["flags"] == ["create_task"]
        client.get_task.assert_not_called()


class TestTaskErrorsAreScrubbed:
    """Task history detail is device/FMG text: scrubbed and bounded (L8)."""

    @pytest.mark.asyncio
    async def test_detail_is_redacted_folded_and_capped(self) -> None:
        history = [
            {"detail": "2026-10-12 23:59:44:Pre-run error: password=hunter2", "state": 5},
            {"detail": "2026-10-12 23:59:44:" + "x" * 2000, "state": 5},
            {"detail": "line one\nline two", "state": 5},
        ] + [{"detail": f"step {i} error", "state": 5} for i in range(100)]
        client = _task_client({"state": 5, "line": [{"history": history}]})
        result = await TestBlueprintAddRunsAsTask()._add(client)
        errors = result["task_errors"]
        assert "hunter2" not in repr(result)
        assert all(len(e) <= 300 for e in errors)
        assert "line one line two" in errors
        assert len(errors) <= dvm_tools._MAX_TASK_ERRORS


class TestFirmwareBlueprintNeedsConfirm:
    """A blueprint that enforces a firmware version needs confirm=True (L9)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "blueprint",
        [
            {"firmware-template": "campus_emea"},
            {"prefer-img-ver": "7.0.17-b682|0"},
            _GUI_BLUEPRINT,
        ],
    )
    async def test_inline_firmware_blueprint_is_refused_without_confirm(
        self, blueprint: dict[str, Any]
    ) -> None:
        result, client = await _add_with(device_blueprint=blueprint)
        assert result["status"] == "error"
        assert result["error_code"] == "confirmation_required"
        client.add_device.assert_not_called()
        client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_inline_firmware_blueprint_with_confirm_is_added(self) -> None:
        result, client = await _add_with(
            device_blueprint={"firmware-template": "campus_emea"}, confirm=True
        )
        assert result["status"] == "success", result
        client.add_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_blueprint_without_firmware_needs_no_confirm(self) -> None:
        result, _ = await _add_with(device_blueprint={"pkg": "branch_pkg", "prefer-img-ver": ""})
        assert result["status"] == "success", result

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "saved",
        [
            {"name": "bp", "firmware-template": ["campus_emea"]},
            {"name": "bp", "prefer-img-ver": "7.4.5-b2702|0"},
        ],
    )
    async def test_saved_firmware_blueprint_is_refused_without_confirm(
        self, saved: dict[str, Any]
    ) -> None:
        result, client = await _add_with(get=AsyncMock(return_value=saved), device_blueprint="bp")
        assert result["status"] == "error"
        assert result["error_code"] == "confirmation_required"
        client.add_device.assert_not_called()
        ok, client = await _add_with(
            get=AsyncMock(return_value=saved), device_blueprint="bp", confirm=True
        )
        assert ok["status"] == "success", ok

    @pytest.mark.asyncio
    async def test_saved_blueprint_without_firmware_needs_no_confirm(self) -> None:
        result, _ = await _add_with(
            get=AsyncMock(return_value={"name": "bp", "firmware-template": []}),
            device_blueprint="bp",
        )
        assert result["status"] == "success", result

    @pytest.mark.asyncio
    async def test_unreadable_saved_blueprint_needs_confirm(self) -> None:
        result, client = await _add_with(
            get=AsyncMock(side_effect=RuntimeError("unsupported")), device_blueprint="bp"
        )
        assert result["status"] == "error"
        assert result["error_code"] == "confirmation_required"
        client.add_device.assert_not_called()

    @pytest.mark.asyncio
    async def test_gate_off_when_firmware_safety_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fortimanager_mcp.utils.config import get_settings

        monkeypatch.setenv("FMG_FIRMWARE_SAFETY", "disabled")
        get_settings.cache_clear()
        try:
            result, _ = await _add_with(device_blueprint={"firmware-template": "campus_emea"})
        finally:
            get_settings.cache_clear()
        assert result["status"] == "success", result


_ECHO_VARIABLES = [
    {"name": "hostname", "type": 0, "value": ""},
    {"name": "vpn_token", "type": "password", "value": ""},
]


class TestMetaVariableEcho:
    """The echoed device must not carry password-type meta-variable values.

    ``vpn_token``, not ``psk``: strip_device_credentials already drops a key
    named ``psk`` at any depth, which would hide what is tested here.
    """

    @pytest.mark.asyncio
    async def test_password_type_values_are_masked_in_the_echo(self) -> None:
        meta = {"hostname": "branch1", "vpn_token": "Secr3t-tok"}
        client = _absent(MagicMock())
        client.get = AsyncMock(return_value={})
        client.add_device = AsyncMock(
            return_value={"device": {"name": "branch1", "meta variables": dict(meta)}}
        )
        client.get_metadata_variables = AsyncMock(return_value=_ECHO_VARIABLES)
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_model_device(
                adom="demo",
                name="branch1",
                serial_number=_SERIAL,
                meta_variables=meta,
            )
        assert result["status"] == "success", result
        echoed = result["device"]["meta variables"]
        assert echoed == {"hostname": "branch1", "vpn_token": MASK_VALUE}
        assert "Secr3t-tok" not in repr(result)
        # What went to FortiManager is the real value.
        sent = client.add_device.call_args.kwargs["device"]["meta variables"]
        assert sent["vpn_token"] == "Secr3t-tok"

    @pytest.mark.asyncio
    async def test_submitted_config_echo_is_masked_too(self) -> None:
        # FMG echoes no device, so the submitted device_config is returned.
        client = _absent(MagicMock())
        client.get = AsyncMock(return_value={})
        client.add_device = AsyncMock(return_value={})
        client.get_metadata_variables = AsyncMock(return_value=_ECHO_VARIABLES)
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_model_device(
                adom="demo",
                name="branch1",
                serial_number=_SERIAL,
                meta_variables={"hostname": "b1", "vpn_token": "Secr3t-tok"},
            )
        assert result["status"] == "success", result
        assert result["device"]["meta variables"] == {"hostname": "b1", "vpn_token": MASK_VALUE}
        sent = client.add_device.call_args.kwargs["device"]["meta variables"]
        assert sent["vpn_token"] == "Secr3t-tok"

    @pytest.mark.asyncio
    async def test_unknown_variable_types_mask_every_value(self) -> None:
        client = _absent(MagicMock())
        client.get = AsyncMock(return_value={})
        client.add_device = AsyncMock(return_value={})
        client.get_metadata_variables = AsyncMock(side_effect=RuntimeError("no access"))
        with patch.object(dvm_tools, "get_fmg_client", return_value=client):
            result = await dvm_tools.add_model_device(
                adom="demo",
                name="branch1",
                serial_number=_SERIAL,
                meta_variables={"hostname": "branch1", "vpn_token": "Secr3t-tok"},
            )
        assert result["status"] == "success", result
        assert result["device"]["meta variables"] == {
            "hostname": MASK_VALUE,
            "vpn_token": MASK_VALUE,
        }
        sent = client.add_device.call_args.kwargs["device"]["meta variables"]
        assert sent["vpn_token"] == "Secr3t-tok"
