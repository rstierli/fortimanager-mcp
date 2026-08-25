"""Tests for dvm_tools.delete_devices_bulk.

Uses only neutral/example values since this is a public repository.
"""

from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import dvm_tools


class TestDeleteDevicesBulk:
    @pytest.mark.asyncio
    async def test_deletes_a_list_of_devices(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {"taskid": 42})

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.delete_devices_bulk("root", ["FGT-Old1", "FGT-Old2"])

        assert result["status"] == "success"
        assert result["requested_count"] == 2
        args, kwargs = mock_fmg_instance.execute.call_args
        assert args[0] == "/dvm/cmd/del/dev-list"
        assert kwargs["del-dev-member-list"] == [{"name": "FGT-Old1"}, {"name": "FGT-Old2"}]

    @pytest.mark.asyncio
    async def test_a_bare_string_is_one_device_not_iterated_as_characters(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """devices="FGT-01" must delete one device, not six single-character
        bogus device entries (upstream #71 -- the fix landed in
        device_group_tools.py but not here). Reachable via the dynamic
        dispatcher, which passes parameters as dict[str, Any] with nothing
        enforcing the list[str] annotation."""
        mock_fmg_instance.execute.return_value = (0, {"taskid": 42})

        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.delete_devices_bulk("root", "FGT-01")

        assert result["status"] == "success"
        assert result["requested_count"] == 1
        kwargs = mock_fmg_instance.execute.call_args.kwargs
        assert kwargs["del-dev-member-list"] == [{"name": "FGT-01"}]

    @pytest.mark.asyncio
    async def test_rejects_a_dict(self, mock_client: FortiManagerClient) -> None:
        """list({"devices": [...]}) returns the dict's keys, not its
        values -- a caller nesting the argument one level too deep must be
        refused, not silently add/remove a device literally named
        "devices"."""
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.delete_devices_bulk("root", {"devices": ["FGT-01"]})

        assert result["status"] == "error"


class TestBulkDeviceOpsDoNotFabricateCounts:
    """These two submit a TASK. The outcome lives in the task, not here.

    Both returned ``len(devices)`` as the outcome count and a message in
    the past tense the instant FortiManager accepted the request, before
    the task had run at all. So "Deleted 2 devices" was reported for a
    job whose per-device results did not exist yet, and a device that
    fails inside the task is indistinguishable from one that succeeds.

    Same class as #78 on the group tools, and the same class the policy
    layer already refused: ``delete_firewall_policies_bulk`` carries a
    comment saying the previous single filtered DELETE "reported
    len(policyids) as deleted no matter how many IDs actually matched".
    It fixed that by counting real per-item results. These cannot, since
    there is one task for the whole batch, so they report the request
    size and point at ``task_id`` instead.
    """

    @pytest.mark.asyncio
    async def test_delete_bulk_does_not_report_an_outcome_count(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {"taskid": 42})
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.delete_devices_bulk("root", ["FGT-Old1", "FGT-Old2"])

        assert result["status"] == "success"
        assert "deleted_count" not in result
        assert result["requested_count"] == 2
        assert result["task_id"] == 42

    @pytest.mark.asyncio
    async def test_add_bulk_does_not_report_an_outcome_count(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {"taskid": 43})
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.add_devices_bulk(
                "root", [{"name": "FGT-New1"}, {"name": "FGT-New2"}]
            )

        assert result["status"] == "success"
        assert "added_count" not in result
        assert result["requested_count"] == 2
        assert result["task_id"] == 43

    @pytest.mark.asyncio
    async def test_the_messages_point_at_the_task_rather_than_claim_completion(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """An LLM reading the message rather than the keys must not be
        told the devices were already added or deleted."""
        mock_fmg_instance.execute.return_value = (0, {"taskid": 44})
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            deleted = await dvm_tools.delete_devices_bulk("root", ["FGT-Old1"])
            added = await dvm_tools.add_devices_bulk("root", [{"name": "FGT-New1"}])

        for result in (deleted, added):
            assert "task 44" in result["message"]
        assert not deleted["message"].startswith("Deleted")
        assert not added["message"].startswith("Added")


class TestAddDevicesBulkShapeCoercion:
    """``add_devices_bulk`` takes ``list[dict]`` and checked neither (#86).

    Its three sibling bulk-device tools got ``coerce_device_name_list`` in
    PR #74, which rejects a dict explicitly and turns a bare string into a
    one-element list. This one takes dicts rather than names, so it could
    not share that helper and got nothing instead.

    Measured before the fix, both wrong shapes reaching the same opaque
    place:

        devices={"name": "FGT-01"}  ->  'str' object is not a mapping
                                        error_code internal_error
        devices="FGT-01"            ->  'str' object is not a mapping

    A dict is truthy and iterates its KEYS, and a string is truthy and
    iterates its CHARACTERS, so ``if not devices`` catches neither. Both
    reach ``{**device, ...}`` and raise a TypeError swallowed by the
    generic handler, instead of the ValidationError the equivalent mistake
    gets one module over.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "devices",
        [
            {"name": "FGT-01"},
            "FGT-01",
            [{"name": "FGT-01"}, "FGT-02"],
            [None],
            [["FGT-01"]],
        ],
    )
    async def test_a_wrong_shape_is_refused_clearly(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock, devices: object
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {"taskid": 1})
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.add_devices_bulk("root", devices)  # type: ignore[arg-type]

        assert result["status"] == "error"
        assert result.get("error_code") == "validation_error"
        mock_fmg_instance.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_the_documented_shape_still_works(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        """The regression guard, so the check cannot become a refuser."""
        mock_fmg_instance.execute.return_value = (0, {"taskid": 42})
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.add_devices_bulk(
                "root", [{"name": "FGT-01", "ip": "192.0.2.1"}]
            )
        assert result["status"] == "success"
        assert result["requested_count"] == 1

    @pytest.mark.asyncio
    async def test_an_empty_list_is_still_its_own_message(
        self, mock_client: FortiManagerClient
    ) -> None:
        """Unchanged: empty is a different mistake from wrong-shaped and
        keeps its own wording."""
        with patch.object(dvm_tools, "get_fmg_client", return_value=mock_client):
            result = await dvm_tools.add_devices_bulk("root", [])
        assert result["status"] == "error"
        assert "No devices provided" in result["message"]
