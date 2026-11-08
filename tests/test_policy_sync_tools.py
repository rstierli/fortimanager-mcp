"""Package-vs-device firewall policy comparison.

Fixtures follow what FMG 8.0.2 returned live for a FortiOS 7.4.12 branch:
the device DB revision is flat CLI text (no indentation, defaults
omitted), package policies come back verbose (enum names, every field),
and a policy block appears in the package as one entry carrying
``_policy_block``.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fortimanager_mcp.tools import policy_sync_tools as pst

REVISION = """#config-version=FGVMK6-7.00-FW-build2902-000000:opmode=0:vdom=0:user=admin
config system interface
edit "port3"
set vdom "root"
next
end
config firewall policy
edit 1071741825
set name "Health Check Access"
set uuid f27eccf0-1435-51ef-9025-d46289affb63
set action accept
set srcintf "Branch-Lo"
set dstintf "HUB1"
set srcaddr "sites_Br_Loopback"
set dstaddr "sites_Loopback"
set schedule "always"
set service "ALL"
next
edit 1
set name "VPN_IN"
set uuid 68111ece-fa46-51ed-2f56-0b02f6279c7d
set action accept
set srcintf "HUB1"
set dstintf "port3"
set srcaddr "RFC1918-GRP"
set dstaddr "RFC1918-GRP"
set schedule "always"
set service "ALL"
set utm-status enable
set logtraffic all
set comments "two
lines, set action deny"
set profile-type group
set profile-group "default"
next
edit 3
set name "INET_OUT"
set uuid 6817a596-fa46-51ed-13fd-3955433f9224
set action accept
set srcintf "port3"
set dstintf "WAN1" "WAN2"
set nat enable
set srcaddr "RFC1918-GRP"
set dstaddr "all"
set schedule "always"
set service "Web Access"
next
end
"""


def _pkg_policy(policyid: int, uuid: str, **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "policyid": policyid,
        "uuid": uuid,
        "action": "accept",
        "status": "enable",
        "nat": "disable",
        "logtraffic": "utm",
        "utm-status": "disable",
        "profile-type": "single",
        "schedule": ["always"],
        "srcaddr6": [],
        "dstaddr6": [],
        "av-profile": [],
        "ssl-ssh-profile": ["no-inspection"],
    }
    base.update(fields)
    return base


PKG_POLICIES = [
    {"policyid": 4, "action": "deny", "_policy_block": "sites_BBLK", "uuid": "f2808ff4"},
    _pkg_policy(
        1,
        "68111ece-fa46-51ed-2f56-0b02f6279c7d",
        name="VPN_IN",
        srcintf=["HUB1"],
        dstintf=["port3"],
        srcaddr=["RFC1918-GRP"],
        dstaddr=["RFC1918-GRP"],
        service=["ALL"],
        **{
            "utm-status": "enable",
            "logtraffic": "all",
            "profile-type": "group",
            "profile-group": ["default"],
        },
    ),
    _pkg_policy(
        3,
        "6817a596-fa46-51ed-13fd-3955433f9224",
        name="INET_OUT",
        srcintf=["port3"],
        dstintf=["WAN2", "WAN1"],
        srcaddr=["RFC1918-GRP"],
        dstaddr=["all"],
        service=["ALL"],
        nat="enable",
        **{"scope member": [{"name": "emea_spokes"}]},
    ),
    _pkg_policy(
        5,
        "f76a663c-143c-51ef-dfd2-c3271d617bbd",
        name="INET_OUT_CLOUD",
        **{"scope member": [{"name": "emea_spokes_cloud"}]},
    ),
]

BLOCK_POLICIES = [
    _pkg_policy(
        1071741825,
        "f27eccf0-1435-51ef-9025-d46289affb63",
        name="Health Check Access",
        srcintf=["Branch-Lo"],
        dstintf=["HUB1"],
        srcaddr=["sites_Br_Loopback"],
        dstaddr=["sites_Loopback"],
        service=["ALL"],
    )
]

GROUPS = [
    {"name": "EMEA", "object member": [{"name": "emea_spokes"}, {"name": "emea_spokes_cloud"}]},
    {"name": "emea_spokes", "object member": [{"name": "branch1", "vdom": "root"}]},
    {"name": "emea_spokes_cloud", "object member": [{"name": "branch2", "vdom": "root"}]},
]


def _device_db(revision: str = REVISION) -> list[dict[str, Any]]:
    """The device DB table as FMG returns it verbose: every field present."""
    rows = []
    for policy in pst.parse_firewall_policies(revision):
        row: dict[str, Any] = {"nat": "disable", "status": "enable", "srcaddr6": []}
        row.update({k: v[0] if k == "uuid" else v for k, v in policy.items()})
        rows.append(row)
    return rows


def _client(
    revision: str = REVISION,
    status: str = "out of sync",
    device_db: list[dict[str, Any]] | None = None,
    interfaces: list[dict[str, Any]] | None = None,
    variables: list[dict[str, Any]] | None = None,
) -> MagicMock:
    client = MagicMock()
    client.get_package_status = AsyncMock(
        return_value=[
            {"dev": "branch1", "vdom": "root", "pkg": "sites_BRANCH_PPKG", "status": status},
            {"dev": "branch2", "vdom": "root", "pkg": "sites_BRANCH_PPKG", "status": "installed"},
        ]
    )
    client.get_device_revision_content = AsyncMock(
        return_value={"content": revision, "revision": 27}
    )
    client.get_device_revisions = AsyncMock(
        return_value={
            "revinfo": [
                {
                    "revision": 27,
                    "instime": "2026-10-22 18:04:50",
                    "comments": "Auto update from device",
                    "instusr": "admin",
                }
            ]
        }
    )
    table = device_db if device_db is not None else _device_db(revision)

    async def get_verbose(url: str, **_: Any) -> Any:
        if url.startswith("/pm/config/device/"):
            return table
        return BLOCK_POLICIES if "/pblock/sites_BBLK/" in url else PKG_POLICIES

    async def get(url: str, **_: Any) -> Any:
        if url.endswith("/obj/dynamic/interface"):
            return interfaces or []
        if url.endswith("/obj/fmg/variable"):
            return variables or []
        if url == "/dvmdb/adom/demo/device/branch1":
            return {"name": "branch1", "platform_str": "FortiGate-VM64-KVM"}
        return GROUPS

    client.get_verbose = AsyncMock(side_effect=get_verbose)
    client.get = AsyncMock(side_effect=get)
    return client


async def _check(client: MagicMock, **kwargs: Any) -> dict[str, Any]:
    with patch.object(pst, "get_fmg_client", return_value=client):
        return await pst.check_device_policy_sync("demo", "branch1", **kwargs)


DRIFT = {
    "policyid": 3,
    "name": "INET_OUT",
    "differences": {"service": {"package": ["ALL"], "revision": ["Web Access"]}},
}


class TestParseFirewallPolicies:
    def test_reads_policies_in_order_with_quoted_lists(self) -> None:
        policies = pst.parse_firewall_policies(REVISION)
        assert [p["policyid"] for p in policies] == [1071741825, 1, 3]
        assert policies[2]["dstintf"] == ["WAN1", "WAN2"]
        assert policies[0]["name"] == ["Health Check Access"]

    def test_a_multiline_value_is_not_read_as_directives(self) -> None:
        policies = pst.parse_firewall_policies(REVISION)
        vpn_in = policies[1]
        assert vpn_in["action"] == ["accept"]
        assert vpn_in["comments"] == ["two\nlines, set action deny"]

    def test_multi_vdom_reads_only_the_requested_vdom(self) -> None:
        config = (
            "config vdom\nedit root\nnext\nedit dmz\nnext\nend\n"
            "config global\nend\n"
            "config vdom\n"
            "edit root\n"
            "config firewall policy\n    edit 7\n        set action accept\n    next\nend\n"
            "next\n"
            "edit dmz\n"
            "config firewall policy\n    edit 9\n        set action deny\n    next\nend\n"
            "next\n"
            "end\n"
        )
        assert [p["policyid"] for p in pst.parse_firewall_policies(config, "root")] == [7]
        assert [p["policyid"] for p in pst.parse_firewall_policies(config, "dmz")] == [9]

    def test_nested_config_inside_a_policy_is_skipped(self) -> None:
        config = (
            "config firewall policy\nedit 2\nset action accept\n"
            "config sub\nedit 1\nset action deny\nnext\nend\n"
            "set status disable\nnext\nend\n"
        )
        [policy] = pst.parse_firewall_policies(config)
        assert policy["action"] == ["accept"]
        assert policy["status"] == ["disable"]


class TestCheckDevicePolicySync:
    @pytest.mark.asyncio
    async def test_reports_the_drifted_field_and_nothing_else(self) -> None:
        result = await _check(_client(), source="revision")

        assert result["status"] == "success"
        assert result["in_sync"] is False
        assert result["package"] == "sites_BRANCH_PPKG"
        assert result["install_status"] == "out of sync"
        assert list(result["comparisons"]) == ["package_vs_revision"]
        cmp = result["comparisons"]["package_vs_revision"]
        assert cmp["modified"] == [DRIFT]
        assert cmp["only_in_package"] == []
        assert cmp["only_in_revision"] == []
        assert cmp["order_matches"] is True
        assert result["revision"]["comment"] == "Auto update from device"

    @pytest.mark.asyncio
    async def test_policy_scoped_to_another_group_is_not_expected(self) -> None:
        result = await _check(_client())
        assert result["not_targeted"] == [{"policyid": 5, "name": "INET_OUT_CLOUD"}]
        summary = result["comparisons"]["package_vs_revision"]["summary"]
        assert summary["package_policies"] == 3

    @pytest.mark.asyncio
    async def test_policy_block_members_are_matched_by_uuid(self) -> None:
        result = await _check(_client())
        assert result["comparisons"]["package_vs_revision"]["summary"]["matched"] == 3

    @pytest.mark.asyncio
    async def test_defaults_omitted_by_fortios_compare_clean(self) -> None:
        """An installed package must not flag every `nat disable`."""
        clean = REVISION.replace('set service "Web Access"', 'set service "ALL"')
        result = await _check(_client(clean, status="installed"))
        assert result["in_sync"] is True
        assert all(c["modified"] == [] for c in result["comparisons"].values())

    @pytest.mark.asyncio
    async def test_missing_and_extra(self) -> None:
        reordered = REVISION.replace("edit 1\n", "edit 99\n").replace(
            "68111ece-fa46-51ed-2f56-0b02f6279c7d", "11111111-0000-0000-0000-000000000000"
        )
        cmp = (await _check(_client(reordered)))["comparisons"]["package_vs_revision"]
        assert cmp["only_in_package"] == [{"policyid": 1, "name": "VPN_IN"}]
        assert cmp["only_in_revision"] == [{"policyid": 99, "name": "VPN_IN"}]

    @pytest.mark.asyncio
    async def test_reordered_policies_are_reported(self) -> None:
        header, _, rest = REVISION.partition("config firewall policy\n")
        edits = rest.removesuffix("end\n").split("next\n")[:3]
        moved = (
            header
            + "config firewall policy\n"
            + "next\n".join([edits[2], edits[0], edits[1]])
            + "next\nend\n"
        )
        cmp = (await _check(_client(moved)))["comparisons"]["package_vs_revision"]
        assert cmp["order_matches"] is False
        assert cmp["revision_order"] == [3, 1071741825, 1]
        assert cmp["package_order"] == [1071741825, 1, 3]

    @pytest.mark.asyncio
    async def test_no_assigned_package_is_an_explicit_error(self) -> None:
        client = _client()
        client.get_package_status.return_value = []
        result = await _check(client)
        assert result["status"] == "error"
        assert result["error"] == "no_package_assigned"

    @pytest.mark.asyncio
    async def test_bad_revision_is_refused(self) -> None:
        client = _client()
        result = await _check(client, revision=0)
        assert result["status"] == "error"
        client.get_device_revision_content.assert_not_called()

    @pytest.mark.asyncio
    async def test_bad_source_is_refused(self) -> None:
        client = _client()
        result = await _check(client, source="live")
        assert result["status"] == "error"
        client.get_package_status.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("vdom", ["..", "root/../x", "a;b", ""])
    async def test_bad_vdom_is_refused(self, vdom: str) -> None:
        client = _client()
        result = await _check(client, vdom=vdom)
        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        client.get_package_status.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("block", ["..", "../../pkg/x", "a/b", "x;y"])
    async def test_a_policy_block_name_is_validated_before_the_url(self, block: str) -> None:
        """The name comes from FortiManager, but it still lands in a URL."""
        client = _client()
        policies = [{**PKG_POLICIES[0], "_policy_block": block}, *PKG_POLICIES[1:]]
        verbose = client.get_verbose.side_effect

        async def get_verbose(url: str, **kwargs: Any) -> Any:
            if "/pkg/" in url:
                return policies
            return await verbose(url, **kwargs)

        client.get_verbose = AsyncMock(side_effect=get_verbose)
        result = await _check(client)

        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        assert not any("/pblock/" in c.args[0] for c in client.get_verbose.call_args_list)


class TestDeviceDbSource:
    @pytest.mark.asyncio
    async def test_device_db_only_skips_the_revision(self) -> None:
        client = _client()
        result = await _check(client, source="device_db")

        assert list(result["comparisons"]) == ["package_vs_device_db"]
        [drift] = result["comparisons"]["package_vs_device_db"]["modified"]
        assert drift["differences"] == {
            "service": {"package": ["ALL"], "device_db": ["Web Access"]}
        }
        client.get_device_revision_content.assert_not_called()
        assert "revision" not in result

    @pytest.mark.asyncio
    async def test_both_agree_when_nothing_is_staged(self) -> None:
        result = await _check(_client())
        assert set(result["comparisons"]) == {
            "package_vs_revision",
            "package_vs_device_db",
            "device_db_vs_revision",
        }
        assert result["comparisons"]["device_db_vs_revision"]["in_sync"] is True

    @pytest.mark.asyncio
    async def test_a_change_staged_in_fmg_shows_between_device_db_and_revision(self) -> None:
        """Device DB already has the package value, the device does not yet."""
        staged = _device_db(REVISION.replace('set service "Web Access"', 'set service "ALL"'))
        result = await _check(_client(device_db=staged))

        cmps = result["comparisons"]
        assert cmps["package_vs_device_db"]["in_sync"] is True
        assert cmps["package_vs_revision"]["modified"] == [DRIFT]
        [staged_change] = cmps["device_db_vs_revision"]["modified"]
        assert staged_change["differences"] == {
            "service": {"device_db": ["ALL"], "revision": ["Web Access"]}
        }
        assert result["in_sync"] is False


class TestInterfaceMapping:
    VL_LAN = [
        {
            "name": "vl_lan",
            "value": "port3",
            "dynamic_mapping": [
                {"_scope": [{"name": "branch1", "vdom": "global"}], "value": "vl_lan"}
            ],
        }
    ]
    PORT3 = [{"name": "port3", "default-mapping": 1, "defmap-intf": "$(vl_lan)"}]

    @pytest.mark.asyncio
    async def test_default_mapping_resolves_the_device_variable(self) -> None:
        """Live case: normalized port3 defaults to $(vl_lan), vl_lan on branch3."""
        on_device = REVISION.replace('"port3"', '"vl_lan"').replace(
            'set service "Web Access"', 'set service "ALL"'
        )
        result = await _check(_client(on_device, interfaces=self.PORT3, variables=self.VL_LAN))
        assert result["interface_mapping"] == {"port3": ["vl_lan"]}
        assert result["in_sync"] is True

    @pytest.mark.asyncio
    async def test_per_device_mapping_wins_over_the_default(self) -> None:
        interfaces = [
            {
                "name": "port3",
                "default-mapping": 1,
                "defmap-intf": "$(vl_lan)",
                "dynamic_mapping": [
                    {"_scope": [{"name": "branch1", "vdom": "root"}], "local-intf": ["lan2"]}
                ],
            }
        ]
        on_device = REVISION.replace('"port3"', '"lan2"').replace(
            'set service "Web Access"', 'set service "ALL"'
        )
        result = await _check(_client(on_device, interfaces=interfaces, variables=self.VL_LAN))
        assert result["interface_mapping"] == {"port3": ["lan2"]}
        assert result["in_sync"] is True

    @pytest.mark.asyncio
    async def test_platform_mapping_wins_over_the_default(self) -> None:
        interfaces = [
            {
                "name": "port3",
                "default-mapping": 1,
                "defmap-intf": "$(vl_lan)",
                "platform_mapping": [
                    {"name": "FortiGate-100E", "intf-zone": "port3"},
                    {"name": "FortiGate-VM64-KVM", "intf-zone": "lan3"},
                ],
            }
        ]
        on_device = REVISION.replace('"port3"', '"lan3"').replace(
            'set service "Web Access"', 'set service "ALL"'
        )
        result = await _check(_client(on_device, interfaces=interfaces, variables=self.VL_LAN))
        assert result["interface_mapping"] == {"port3": ["lan3"]}
        assert result["in_sync"] is True

    @pytest.mark.asyncio
    async def test_other_platforms_fall_through_to_the_default(self) -> None:
        """Live case: port3 lists 68 platforms, none of them FortiGate-VM64-KVM."""
        interfaces = [
            {
                **self.PORT3[0],
                "platform_mapping": [{"name": "FortiGate-100E", "intf-zone": "port3"}],
            }
        ]
        on_device = REVISION.replace('"port3"', '"vl_lan"').replace(
            'set service "Web Access"', 'set service "ALL"'
        )
        result = await _check(_client(on_device, interfaces=interfaces, variables=self.VL_LAN))
        assert result["interface_mapping"] == {"port3": ["vl_lan"]}

    @pytest.mark.asyncio
    async def test_per_device_mapping_wins_over_the_platform(self) -> None:
        interfaces = [
            {
                "name": "port3",
                "platform_mapping": [{"name": "FortiGate-VM64-KVM", "intf-zone": "lan3"}],
                "dynamic_mapping": [
                    {"_scope": [{"name": "branch1", "vdom": "root"}], "local-intf": ["lan2"]}
                ],
            }
        ]
        on_device = REVISION.replace('"port3"', '"lan2"').replace(
            'set service "Web Access"', 'set service "ALL"'
        )
        result = await _check(_client(on_device, interfaces=interfaces))
        assert result["interface_mapping"] == {"port3": ["lan2"]}

    @pytest.mark.asyncio
    async def test_unresolved_mapping_still_reports_with_a_note(self) -> None:
        on_device = REVISION.replace('"port3"', '"vl_lan"')
        result = await _check(_client(on_device), source="revision")
        modified = result["comparisons"]["package_vs_revision"]["modified"]
        vpn_in = next(m for m in modified if m["policyid"] == 1)
        assert vpn_in["differences"]["dstintf"] == {"package": ["port3"], "revision": ["vl_lan"]}
        assert "mapping" in vpn_in["note"]
        # _interface_map resolves per-platform mappings; the note must not
        # claim otherwise.
        assert "not resolved" not in vpn_in["note"]
        assert "per-platform" in vpn_in["note"]


class TestTargeting:
    def test_nested_group_resolves_to_the_device(self) -> None:
        groups = {g["name"]: g["object member"] for g in GROUPS}
        assert pst._targets_device([{"name": "EMEA"}], "branch2", "root", groups)
        assert not pst._targets_device([{"name": "emea_spokes"}], "branch2", "root", groups)

    def test_direct_device_member_checks_the_vdom(self) -> None:
        scope = [{"name": "branch1", "vdom": "dmz"}]
        assert not pst._targets_device(scope, "branch1", "root", {})
        assert pst._targets_device(scope, "branch1", "dmz", {})

    def test_no_scope_targets_every_device(self) -> None:
        assert pst._targets_device(None, "branch1", "root", {})

    def test_a_group_cycle_terminates(self) -> None:
        groups = {"a": [{"name": "b"}], "b": [{"name": "a"}]}
        assert not pst._targets_device([{"name": "a"}], "branch1", "root", groups)


class TestPackageInstallStatus:
    @pytest.mark.asyncio
    async def test_filters_to_one_device(self) -> None:
        client = _client()
        with patch.object(pst, "get_fmg_client", return_value=client):
            result = await pst.get_package_install_status("demo", "branch2")
        assert result["packages"] == [
            {
                "device": "branch2",
                "vdom": "root",
                "package": "sites_BRANCH_PPKG",
                "install_status": "installed",
            }
        ]
