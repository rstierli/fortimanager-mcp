"""Tests for revision_tools module: list/diff/revert across device DB, ADOM
DB, and firewall policy/object revision history.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from fortimanager_mcp.api.client import FortiManagerClient
from fortimanager_mcp.tools import revision_tools
from fortimanager_mcp.utils.config import get_settings

# =============================================================================
# Device DB revisions
# =============================================================================


class TestListDeviceRevisions:
    @pytest.mark.asyncio
    async def test_lists_revisions_with_base_ver(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (
            0,
            {
                "base_ver": 8,
                "revinfo": [
                    {"revision": 8, "comments": "", "instusr": "admin"},
                    {"revision": 7, "comments": "objects", "instusr": "ips-admin"},
                ],
            },
        )

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.list_device_revisions("hub2")

        assert result["status"] == "success"
        assert result["base_ver"] == 8
        assert result["count"] == 2
        args, kwargs = mock_fmg_instance.execute.call_args
        assert args[0] == "/deployment/get/device/revision"
        assert kwargs["device"] == "hub2"

    @pytest.mark.asyncio
    async def test_rejects_invalid_device_name(self, mock_client: FortiManagerClient) -> None:
        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.list_device_revisions("bad name!")

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(revision_tools, "get_fmg_client", return_value=None):
            result = await revision_tools.list_device_revisions("hub2")

        assert result["status"] == "error"


class TestGetDeviceRevision:
    @pytest.mark.asyncio
    async def test_checks_out_specific_revision(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {"content": "config text", "revision": 8})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.get_device_revision("hub2", revision=8)

        assert result["status"] == "success"
        assert result["content"] == "config text"
        assert result["revision"] == 8
        args, kwargs = mock_fmg_instance.execute.call_args
        assert args[0] == "/deployment/checkout/revision"
        assert kwargs == {"device": "hub2", "revision": 8}

    @pytest.mark.asyncio
    async def test_default_is_latest_revision(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {"content": "latest", "revision": 8})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.get_device_revision("hub2")

        assert result["status"] == "success"
        _, kwargs = mock_fmg_instance.execute.call_args
        assert kwargs["revision"] == -1

    @pytest.mark.asyncio
    async def test_rejects_zero_revision(self, mock_client: FortiManagerClient) -> None:
        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.get_device_revision("hub2", revision=0)

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"


class TestDiffDeviceRevision:
    @pytest.mark.asyncio
    async def test_reports_unified_diff_when_changed(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        def mock_execute(url: str, **kwargs):
            if url == "/deployment/checkout/revision":
                return (0, {"content": "config system global\n    set hostname old\nend\n"})
            if url == "/deployment/export/config":
                return (0, {"content": "config system global\n    set hostname new\nend\n"})
            raise AssertionError(f"unexpected url {url}")

        mock_fmg_instance.execute.side_effect = mock_execute

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.diff_device_revision("hub2", revision=7)

        assert result["status"] == "success"
        assert result["changed"] is True
        assert "-    set hostname old" in result["diff"]
        assert "+    set hostname new" in result["diff"]

    @pytest.mark.asyncio
    async def test_reports_unchanged_when_identical(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        def mock_execute(url: str, **kwargs):
            return (0, {"content": "same config\n"})

        mock_fmg_instance.execute.side_effect = mock_execute

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.diff_device_revision("hub2", revision=7)

        assert result["status"] == "success"
        assert result["changed"] is False
        assert result["diff"] == ""


class TestRevertDeviceRevision:
    @pytest.mark.asyncio
    async def test_reverts_and_flags_install_still_needed(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (
            0,
            {"status": {"code": 0, "message": "OK"}, "url": "/deployment/revert"},
        )

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.revert_device_revision("foobar", revision=2)

        assert result["status"] == "success"
        assert "install_device_settings" in result["message"]
        args, kwargs = mock_fmg_instance.execute.call_args
        assert args[0] == "/deployment/revert"
        assert kwargs == {"device": "foobar", "revision": 2}


# =============================================================================
# ADOM DB revisions
# =============================================================================


class TestListAdomRevisions:
    @pytest.mark.asyncio
    async def test_lists_revisions(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            [
                {"version": 1, "name": "rev1", "desc": "initial"},
                {"version": 2, "name": "rev2", "desc": "second"},
            ],
        )

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.list_adom_revisions("demo")

        assert result["status"] == "success"
        assert result["count"] == 2
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/dvmdb/adom/demo/revision"

    @pytest.mark.asyncio
    async def test_rejects_invalid_adom(self, mock_client: FortiManagerClient) -> None:
        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.list_adom_revisions("bad adom!")

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"


class TestGetAdomRevision:
    @pytest.mark.asyncio
    async def test_gets_single_revision(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, {"version": 2, "name": "rev2"})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.get_adom_revision("demo", revision=2)

        assert result["status"] == "success"
        assert result["revision"]["version"] == 2
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/dvmdb/adom/demo/revision/2"


class TestDiffAdomRevision:
    @pytest.mark.asyncio
    async def test_returns_summary_once_percent_complete(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        def mock_execute(url: str, *args, **kwargs):
            if url == "/cache/diff/start":
                assert kwargs == {"dst": "adom/demo", "src": "adom/demo/revision/3"}
                return (0, {"token": "tok-123"})
            if url == "/cache/diff/get/summary":
                # token must be a flat sibling of 'url', not nested under 'data'
                assert args == ({"token": "tok-123"},)
                return (0, {"percent": 100, "obj": {"changed": 1}, "pkg": {"changed": 0}})
            if url == "cache/diff/end":
                assert args == ({"token": "tok-123"},)
                return (0, {"status": {"code": 0, "message": "OK"}})
            raise AssertionError(f"unexpected url {url}")

        mock_fmg_instance.execute.side_effect = mock_execute

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.diff_adom_revision("demo", revision=3)

        assert result["status"] == "success"
        assert result["obj"] == {"changed": 1}
        assert result["pkg"] == {"changed": 0}
        # cache_diff_end must always be called to close the job
        end_calls = [
            c for c in mock_fmg_instance.execute.call_args_list if c.args[0] == "cache/diff/end"
        ]
        assert len(end_calls) == 1

    @pytest.mark.asyncio
    async def test_times_out_and_still_closes_the_diff_job(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        def mock_execute(url: str, *args, **kwargs):
            if url == "/cache/diff/start":
                return (0, {"token": "tok-stuck"})
            if url == "/cache/diff/get/summary":
                return (0, {"percent": 37, "obj": {}, "pkg": {}})
            if url == "cache/diff/end":
                return (0, {"status": {"code": 0, "message": "OK"}})
            raise AssertionError(f"unexpected url {url}")

        mock_fmg_instance.execute.side_effect = mock_execute

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.diff_adom_revision(
                "demo", revision=3, timeout=1, poll_interval=1
            )

        assert result["status"] == "error"
        end_calls = [
            c for c in mock_fmg_instance.execute.call_args_list if c.args[0] == "cache/diff/end"
        ]
        assert len(end_calls) == 1

    @pytest.mark.asyncio
    async def test_missing_token_is_an_error(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.execute.return_value = (0, {})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.diff_adom_revision("demo", revision=3)

        assert result["status"] == "error"


class TestRevertAdomRevision:
    @pytest.mark.asyncio
    async def test_clones_revision_and_returns_new_version(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.clone.return_value = (0, {"version": 4})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.revert_adom_revision("dc_emea", revision=1)

        assert result["status"] == "success"
        assert result["reverted_from"] == 1
        assert result["new_revision"] == 4
        args, kwargs = mock_fmg_instance.clone.call_args
        assert args[0] == "/dvmdb/adom/dc_emea/revision/1"
        data = kwargs["data"]
        assert data["name"] == "Restored-rev_1"
        assert data["locked"] == 0
        assert "Revert of ADOM Revision #1" in data["desc"]

    @pytest.mark.asyncio
    async def test_honors_custom_name_desc_and_locked(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.clone.return_value = (0, {"version": 9})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.revert_adom_revision(
                "dc_emea", revision=1, name="my-restore", desc="custom desc", locked=True
            )

        assert result["status"] == "success"
        _, kwargs = mock_fmg_instance.clone.call_args
        assert kwargs["data"]["name"] == "my-restore"
        assert kwargs["data"]["desc"] == "custom desc"
        assert kwargs["data"]["locked"] == 1


# =============================================================================
# Firewall policy / object revisions
# =============================================================================


class TestListPolicyRevisions:
    @pytest.mark.asyncio
    async def test_lists_change_log_for_a_policy(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (
            0,
            [
                {
                    "act": 1,
                    "key": "14",
                    "config": json.dumps({"policyid": 14, "name": "Policy_001"}),
                    "timestamp": 1708327673,
                    "user": "admin",
                }
            ],
        )

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.list_policy_revisions("demo", "ppkg_001", policyid=14)

        assert result["status"] == "success"
        assert result["count"] == 1
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/adom/demo/_objrev/pkg/ppkg_001/firewall/policy/14"

    @pytest.mark.asyncio
    async def test_lists_change_log_for_whole_package_without_policyid(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.get.return_value = (0, [])

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.list_policy_revisions("demo", "ppkg_001")

        assert result["status"] == "success"
        args, _ = mock_fmg_instance.get.call_args
        assert args[0] == "/pm/config/adom/demo/_objrev/pkg/ppkg_001/firewall/policy"


class TestDiffPolicyPackage:
    @pytest.mark.asyncio
    async def test_returns_package_scoped_summary(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        def mock_execute(url: str, *args, **kwargs):
            if url == "/cache/diff/start":
                return (0, {"token": "tok-pkg"})
            if url == "/cache/diff/get/summary/pkg/ppkg_001":
                return (
                    0,
                    {
                        "percent": 100,
                        "obj": {"changed": 1, "summary": [{"category": 181, "size": 4}]},
                    },
                )
            if url == "cache/diff/end":
                return (0, {"status": {"code": 0, "message": "OK"}})
            raise AssertionError(f"unexpected url {url}")

        mock_fmg_instance.execute.side_effect = mock_execute

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.diff_policy_package("demo", "ppkg_001", revision=3)

        assert result["status"] == "success"
        assert result["summary"]["summary"][0]["category"] == 181


class TestRevertFirewallPolicy:
    @pytest.mark.asyncio
    async def test_reverts_from_json_string_snapshot_and_strips_oid(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        snapshot = json.dumps({"policyid": 14, "name": "Policy_001", "oid": 11310})
        mock_fmg_instance.update.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.revert_firewall_policy(
                "demo", "ppkg_001", snapshot, revision_note="Revert from create time"
            )

        assert result["status"] == "success"
        assert result["policyid"] == 14
        args, _ = mock_fmg_instance.update.call_args
        assert args[0] == "/pm/config/adom/demo/pkg/ppkg_001/firewall/policy"
        payload = args[1]
        assert payload["data"]["policyid"] == 14
        assert "oid" not in payload["data"]
        assert payload["revision note"] == "Revert from create time"

    @pytest.mark.asyncio
    async def test_reverts_from_dict_snapshot_without_note(
        self, mock_client: FortiManagerClient, mock_fmg_instance: MagicMock
    ) -> None:
        mock_fmg_instance.update.return_value = (0, {"status": {"code": 0, "message": "OK"}})

        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.revert_firewall_policy(
                "demo", "ppkg_001", {"policyid": 3, "name": "Policy_003"}
            )

        assert result["status"] == "success"
        args, _ = mock_fmg_instance.update.call_args
        payload = args[1]
        assert "revision note" not in payload

    @pytest.mark.asyncio
    async def test_rejects_snapshot_without_policyid(self, mock_client: FortiManagerClient) -> None:
        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.revert_firewall_policy(
                "demo", "ppkg_001", {"name": "no id here"}
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_rejects_invalid_json_string(self, mock_client: FortiManagerClient) -> None:
        with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
            result = await revision_tools.revert_firewall_policy(
                "demo", "ppkg_001", "{not valid json"
            )

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_blocked_when_overly_permissive(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A revert writes an arbitrary caller-supplied policy payload, same as
        create/update -- srcaddr=all + dstaddr=all + action=accept must be
        refused under strict policy safety exactly like create_firewall_policy,
        not silently write through an unguarded path."""
        monkeypatch.setenv("FMG_POLICY_SAFETY", "strict")
        get_settings.cache_clear()
        snapshot = {
            "policyid": 14,
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "action": "accept",
        }

        try:
            with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
                result = await revision_tools.revert_firewall_policy("demo", "ppkg_001", snapshot)
        finally:
            get_settings.cache_clear()

        assert result["status"] == "error"
        assert "message" in result
        mock_fmg_instance.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_allowed_when_policy_safety_disabled(
        self,
        mock_client: FortiManagerClient,
        mock_fmg_instance: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("FMG_POLICY_SAFETY", "disabled")
        get_settings.cache_clear()
        mock_fmg_instance.update.return_value = (0, {"status": {"code": 0, "message": "OK"}})
        snapshot = {
            "policyid": 14,
            "srcaddr": ["all"],
            "dstaddr": ["all"],
            "service": ["ALL"],
            "action": "accept",
        }

        try:
            with patch.object(revision_tools, "get_fmg_client", return_value=mock_client):
                result = await revision_tools.revert_firewall_policy("demo", "ppkg_001", snapshot)
        finally:
            get_settings.cache_clear()

        assert result["status"] == "success"
        mock_fmg_instance.update.assert_called_once()


# =============================================================================
# Shared validators
# =============================================================================


class TestValidateRevision:
    def test_accepts_positive_int(self) -> None:
        assert revision_tools._validate_revision(5) == 5

    def test_rejects_non_int(self) -> None:
        with pytest.raises(revision_tools.ValidationError):
            revision_tools._validate_revision("5")  # type: ignore[arg-type]

    def test_rejects_zero_and_negative(self) -> None:
        with pytest.raises(revision_tools.ValidationError):
            revision_tools._validate_revision(0)
        with pytest.raises(revision_tools.ValidationError):
            revision_tools._validate_revision(-5)

    def test_minus_one_rejected_unless_latest_allowed(self) -> None:
        with pytest.raises(revision_tools.ValidationError):
            revision_tools._validate_revision(-1)
        assert revision_tools._validate_revision(-1, allow_latest=True) == -1


class TestPreparePolicySnapshot:
    def test_parses_json_string(self) -> None:
        snapshot = revision_tools._prepare_policy_snapshot(json.dumps({"policyid": 1}))
        assert snapshot == {"policyid": 1}

    def test_strips_oid_from_dict(self) -> None:
        snapshot = revision_tools._prepare_policy_snapshot({"policyid": 1, "oid": 999})
        assert "oid" not in snapshot

    def test_rejects_non_object_json(self) -> None:
        with pytest.raises(revision_tools.ValidationError):
            revision_tools._prepare_policy_snapshot(json.dumps([1, 2, 3]))
