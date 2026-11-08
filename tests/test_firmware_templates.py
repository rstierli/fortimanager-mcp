"""Firmware template tools: list, create (catalog-checked, unassigned), delete.

Template and catalog shapes are the ones FMG 8.0.2 returned live.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import firmware_tools

CAMPUS_EMEA = {
    "name": "campus_emea",
    "type": "fwmprof",
    "fwmprof setting": {
        "description": None,
        "enforced version": [
            {
                "flags": 104,
                "platform": "FortiGate-VM64-KVM",
                "product": 1,
                "upgrade-path": 1,
                "version": "7.4.12-b02902",
            }
        ],
        "image-source": 1,
        "schedule-day": None,
        "schedule-end-time": "23:59",
        "schedule-start-time": "00:00",
        "schedule-type": 1,
    },
    "scope member": [{"name": "emea_spokes"}, {"name": "branch1", "vdom": "root"}],
}

CATALOG = {
    "version_list": [
        {
            "platform": "FortiGate-VM64-KVM",
            "product": "FGT",
            "versions": [
                {"version": "7.4.9-b2829"},
                {"version": "7.4.12-b2902"},
                {"version": "7.6.7-b3704"},
            ],
        },
        {"platform": "FortiAP-432FR", "product": "FAP", "versions": [{"version": "7.4.5-b0700"}]},
    ]
}


def _client(templates: list[dict[str, Any]] | None = None) -> MagicMock:
    client = MagicMock()
    stored = list(templates if templates is not None else [CAMPUS_EMEA])

    async def create(adom: str, template: dict[str, Any]) -> dict[str, Any]:
        setting = dict(template["fwmprof setting"])
        setting["image-source"] = {"fds": 1, "fmg": 0}[setting["image-source"]]
        setting["schedule-type"] = {"daily": 1, "weekly": 4}[setting["schedule-type"]]
        setting["enforced version"] = [
            {**v, "product": {"fgt": 1, "fap": 2}[v["product"]], "upgrade-path": 1}
            for v in setting["enforced version"]
        ]
        stored.append({**template, "fwmprof setting": setting})
        return {}

    client.list_firmware_templates = AsyncMock(side_effect=lambda adom: list(stored))
    client.list_available_firmware = AsyncMock(return_value=CATALOG)
    client.create_firmware_template = AsyncMock(side_effect=create)
    client.delete_firmware_template = AsyncMock(return_value={})
    return client


async def _call(client: MagicMock, tool: str, **kwargs: Any) -> dict[str, Any]:
    with patch.object(firmware_tools, "get_fmg_client", return_value=client):
        result: dict[str, Any] = await getattr(firmware_tools, tool)(**kwargs)
    return result


class TestListFirmwareTemplates:
    @pytest.mark.asyncio
    async def test_decodes_enums_and_assignment(self) -> None:
        result = await _call(_client(), "list_firmware_templates", adom="demo")

        assert result["status"] == "success"
        [template] = result["templates"]
        assert template["image_source"] == "fds"
        assert template["schedule"]["type"] == "daily"
        assert template["versions"] == [
            {
                "platform": "FortiGate-VM64-KVM",
                "product": "fgt",
                "version": "7.4.12-b02902",
                "upgrade_path": "auto",
            }
        ]
        assert template["assigned_to"] == ["emea_spokes", "branch1[root]"]


class TestCreateFirmwareTemplate:
    VERSIONS = [{"platform": "FortiGate-VM64-KVM", "version": "7.4.9"}]

    @pytest.mark.asyncio
    async def test_bare_version_resolves_to_the_catalog_build(self) -> None:
        client = _client()
        result = await _call(
            client,
            "create_firmware_template",
            name="branch3_upgrade",
            versions=self.VERSIONS,
            adom="demo",
        )

        assert result["status"] == "success", result
        sent = client.create_firmware_template.await_args.args[1]
        assert sent["name"] == "branch3_upgrade"
        assert sent["fwmprof setting"]["enforced version"] == [
            {
                "platform": "FortiGate-VM64-KVM",
                "product": "fgt",
                "upgrade-path": "auto",
                "version": "7.4.9-b2829",
                "flags": 104,
            }
        ]
        assert "scope member" not in sent
        assert result["template"]["versions"][0]["version"] == "7.4.9-b2829"
        assert result["template"]["assigned_to"] == []

    @pytest.mark.asyncio
    async def test_unknown_version_is_refused_with_nearby_ones(self) -> None:
        client = _client()
        result = await _call(
            client,
            "create_firmware_template",
            name="t",
            versions=[{"platform": "FortiGate-VM64-KVM", "version": "7.4.99"}],
        )

        assert result["status"] == "error"
        assert "7.4.9-b2829" in result["message"]
        client.create_firmware_template.assert_not_called()

    @pytest.mark.asyncio
    async def test_existing_name_is_refused(self) -> None:
        client = _client()
        result = await _call(
            client, "create_firmware_template", name="campus_emea", versions=self.VERSIONS
        )
        assert result["status"] == "error"
        client.create_firmware_template.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_fortigate_entries_use_gui_flags(self) -> None:
        client = _client()
        await _call(
            client,
            "create_firmware_template",
            name="aps",
            versions=[{"platform": "FortiAP-432FR", "version": "7.4.5"}],
        )
        entry = client.create_firmware_template.await_args.args[1]["fwmprof setting"][
            "enforced version"
        ][0]
        assert (entry["product"], entry["flags"]) == ("fap", 0)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"versions": []},
            {"versions": [{"platform": "FortiGate-VM64-KVM"}]},
            {"versions": VERSIONS * 2},
            {"versions": VERSIONS, "schedule_type": "weekly"},
            {"versions": VERSIONS, "schedule_days": ["monday"]},
            {"versions": VERSIONS, "schedule_start_time": "25:00"},
            {"versions": VERSIONS, "image_source": "usb"},
        ],
    )
    async def test_malformed_input_is_refused(self, kwargs: dict[str, Any]) -> None:
        client = _client()
        result = await _call(client, "create_firmware_template", name="t", **kwargs)
        assert result["status"] == "error"
        client.create_firmware_template.assert_not_called()

    @pytest.mark.asyncio
    async def test_weekly_schedule_sends_days(self) -> None:
        client = _client()
        await _call(
            client,
            "create_firmware_template",
            name="weekend",
            versions=self.VERSIONS,
            schedule_type="weekly",
            schedule_days=["Saturday", "sunday"],
        )
        setting = client.create_firmware_template.await_args.args[1]["fwmprof setting"]
        assert setting["schedule-type"] == "weekly"
        assert setting["schedule-day"] == ["saturday", "sunday"]


class TestDeleteFirmwareTemplate:
    @pytest.mark.asyncio
    async def test_assigned_template_is_refused(self) -> None:
        client = _client()
        result = await _call(client, "delete_firmware_template", name="campus_emea")

        assert result["status"] == "error"
        assert result["error"] == "template_assigned"
        assert result["assigned_to"] == ["emea_spokes", "branch1[root]"]
        client.delete_firmware_template.assert_not_called()

    @pytest.mark.asyncio
    async def test_unassigned_template_is_deleted(self) -> None:
        client = _client([{**CAMPUS_EMEA, "name": "spare", "scope member": None}])
        result = await _call(client, "delete_firmware_template", name="spare", adom="demo")

        assert result["status"] == "success"
        client.delete_firmware_template.assert_awaited_once_with("demo", "spare")

    @pytest.mark.asyncio
    async def test_missing_template(self) -> None:
        client = _client()
        result = await _call(client, "delete_firmware_template", name="nope")
        assert result["error"] == "not_found"
