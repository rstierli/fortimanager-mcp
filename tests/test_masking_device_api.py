"""Masking of the 1.13.0 device-state tools: BGP, IPsec diagnosis, routes, raw API.

Same adversarial question as ``test_masking_leak``: run the real tool on a
mocked appliance, mask its result the way the boundary does, then look for
every original address anywhere in the output. Values are documentation
or RFC 1918 addresses only.
"""

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from fortimanager_mcp.masking import fields
from fortimanager_mcp.masking.fpe_engine import FPEEngine
from fortimanager_mcp.masking.tokens import PLACEHOLDER_MARK
from fortimanager_mcp.masking.wrapper import OutputMasker
from fortimanager_mcp.tools import device_proxy_tools, sdwan_tools

KEY = "2DE79D232DF5585D68CE47882AE256D6"

PEER = "198.51.100.252"
LOCAL = "198.51.100.3"
LEARNED_NET = "203.0.113.0"
ROUTER_ID = "192.0.2.253"
REMOTE_GW = "203.0.113.1"
UNDERLAY_IP = "192.0.2.10"
STATIC_NET = "198.51.100.64"
STATIC_GW = "192.0.2.254"
SESSION_SRC = "10.20.30.40"
SESSION_DST = "10.50.60.70"
ARP_MAC = "00:09:0f:aa:bb:cc"
NETMASK = "255.255.255.0"


@pytest.fixture()
def masker(monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FMG_MASKING_KEY", KEY)
    return OutputMasker(FPEEngine(KEY))


def _text(value: Any) -> str:
    return json.dumps(value, default=str)


def _proxied(results: Any) -> list[dict[str, Any]]:
    return [{"response": {"results": results}, "status": {"code": 0, "message": "OK"}}]


class TestTable:
    def test_live_state_keys_are_plain_ip_carriers(self) -> None:
        for key in ("neighbor_ip", "local_ip", "learned_from", "next_hop", "remote_gateway"):
            assert fields.FIELD_TYPES[key] == fields.IP

    def test_address_or_name_keys_are_not_also_carriers(self) -> None:
        """Two handlers for one key would mask it twice."""
        other = (
            set(fields.FIELD_TYPES)
            | set(fields.COMPOSITE_SUBNET)
            | set(fields.COMPOSITE_FQDN)
            | set(fields.COMPOSITE_RANGE)
            | set(fields.COMPOSITE_WILDCARD_IP)
        )
        assert set(fields.COMPOSITE_ADDRESS_OR_NAME) & other == set()
        for key in fields.COMPOSITE_ADDRESS_OR_NAME:
            assert fields.canonical_key(key) == key

    def test_the_raw_api_tool_is_a_passthrough_tool(self) -> None:
        assert "query_device_api" in fields.PASSTHROUGH_TOOLS

    def test_names_and_free_text_never_mask(self) -> None:
        assert fields.FREE_TEXT_KEYS & set(fields.COMPOSITE_ADDRESS_OR_NAME) == set()
        assert fields.ROUTING_KEYS_NEVER_MASK & set(fields.COMPOSITE_ADDRESS_OR_NAME) == set()


class TestAddressOrName:
    @pytest.mark.parametrize(
        "value",
        [
            ["corp-net", "all"],  # SD-WAN service dst: address NAMES
            "$(router_id)",  # template variable
            7,  # integer id
            "0.0.0.0",
        ],
    )
    def test_a_non_address_is_left_alone(self, masker: OutputMasker, value: Any) -> None:
        for key in ("dst", "router_id", "prefix"):
            assert masker.mask_result({key: value}) == {key: value}

    def test_a_pair_masks_the_network_and_keeps_the_mask(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"prefix": [STATIC_NET, NETMASK]})["prefix"]
        assert out[1] == NETMASK
        assert FPEEngine(KEY).unmask_ip_token(out[0]) == STATIC_NET

    @pytest.mark.parametrize("value", [f"{LEARNED_NET}/24", f"{LEARNED_NET} {NETMASK}"])
    def test_the_string_forms_keep_their_mask(self, masker: OutputMasker, value: str) -> None:
        out = masker.mask_result({"prefix": value})["prefix"]
        assert LEARNED_NET not in out
        assert out.endswith("/24") or out.endswith(NETMASK)

    def test_an_ipv6_prefix_is_masked(self, masker: OutputMasker) -> None:
        """The ip6-prefix-list gap the table used to document."""
        out = masker.mask_result({"ipv6": {"ip6-prefix-list": [{"prefix": "2001:db8:1::/64"}]}})
        prefix = out["ipv6"]["ip6-prefix-list"][0]["prefix"]
        assert "2001:db8:1::" not in prefix
        assert prefix.endswith("/64")

    def test_an_address_in_an_unknown_shape_fails_closed(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"dst": f"via {STATIC_GW} only"})["dst"]
        assert out.startswith(PLACEHOLDER_MARK)


class TestBgpStatus:
    @pytest.mark.asyncio
    async def test_no_address_survives(self, masker: OutputMasker) -> None:
        answers = {
            "/api/v2/monitor/router/bgp/neighbors": [
                {"neighbor_ip": PEER, "local_ip": LOCAL, "remote_as": 65000, "state": "Established"}
            ],
            "/api/v2/monitor/router/bgp/paths": [
                {
                    "nlri_prefix": LEARNED_NET,
                    "nlri_prefix_len": 24,
                    "learned_from": PEER,
                    "next_hop": PEER,
                    "is_best": True,
                }
            ],
            "/api/v2/monitor/router/ipv4": [
                {"type": "bgp", "ip_mask": f"{LEARNED_NET}/24", "gateway": PEER, "interface": "t1"}
            ],
        }
        client = AsyncMock()
        client.proxy_call = AsyncMock(side_effect=lambda **kw: _proxied(answers[kw["resource"]]))
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_bgp_status(adom="demo", device="branch1")
        assert result["summary"]["learned_path_count"] == 1

        out = _text(masker.mask_tool_result(result, "get_device_bgp_status"))
        for value in (PEER, LOCAL, LEARNED_NET):
            assert value not in out
        assert "branch1" in out
        assert "/24" in out


class TestBgpConfigAndRoutes:
    def test_bgp_summary_masks_router_id_and_prefixes(self, masker: OutputMasker) -> None:
        summary = sdwan_tools._summarize_bgp(
            {
                "as": 65000,
                "router-id": ROUTER_ID,
                "neighbor": [{"ip": PEER, "remote-as": 65000}],
                "neighbor-range": [{"id": 1, "prefix": [LEARNED_NET, NETMASK]}],
                "network": [{"id": 1, "prefix": [STATIC_NET, NETMASK]}],
            }
        )
        out = _text(masker.mask_result({"summary": summary}))
        for value in (ROUTER_ID, PEER, LEARNED_NET, STATIC_NET):
            assert value not in out
        assert NETMASK in out

    @pytest.mark.asyncio
    async def test_static_routes_mask_dst_and_gateway(self, masker: OutputMasker) -> None:
        client = AsyncMock()
        client.get_device_static_routes = AsyncMock(
            return_value=[
                {"seq-num": 1, "dst": [STATIC_NET, NETMASK], "gateway": STATIC_GW},
                {"seq-num": 2, "dstaddr": ["corp-net"], "sdwan-zone": ["WAN"]},
            ]
        )
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.get_device_static_routes(device="branch1")

        out = _text(masker.mask_tool_result(result, "get_device_static_routes"))
        for value in (STATIC_NET, STATIC_GW):
            assert value not in out
        assert "corp-net" in out
        assert NETMASK in out


class TestIpsecDiagnosis:
    @pytest.mark.asyncio
    async def test_no_address_survives(self, masker: OutputMasker) -> None:
        gateway = {
            "name": "HUB1-VPN1",
            "type": 0,
            "interface": ["port2"],
            "remote-gw": REMOTE_GW,
            "network-id": 1,
        }
        live = {
            "system/interface": {"port2": {"link": True, "ip": UNDERLAY_IP}},
            "vpn/ipsec": [
                {"name": "HUB1-VPN1", "rgwy": REMOTE_GW, "proxyid": [{"status": "down"}]}
            ],
            "virtual-wan/members": [{"interface": "port2", "link": "up"}],
            "virtual-wan/health-check": {},
        }
        client = AsyncMock()
        client.get_device_ipsec_phase1_interface = AsyncMock(return_value=gateway)
        client.get_device_interface_config = AsyncMock(return_value=[{"status": 1}])
        client.proxy_call = AsyncMock(
            side_effect=lambda **kw: _proxied(live[kw["resource"].removeprefix("/api/v2/monitor/")])
        )
        with patch.object(sdwan_tools, "get_fmg_client", return_value=client):
            result = await sdwan_tools.diagnose_ipsec_tunnel(
                device="branch1", tunnel="HUB1-VPN1", adom="demo"
            )
        assert result["verdict"] == "tunnel_down"

        out = _text(masker.mask_tool_result(result, "diagnose_ipsec_tunnel"))
        for value in (REMOTE_GW, UNDERLAY_IP):
            assert value not in out
        assert "HUB1-VPN1" in out


class TestQueryDeviceApi:
    """Arbitrary FortiOS keys: masked by value shape on this tool only."""

    @staticmethod
    async def _query(results: Any, path: str) -> dict[str, Any]:
        client = AsyncMock()
        client.proxy_call = AsyncMock(
            return_value=[
                {
                    "response": {"http_status": 200, "version": "v7.4.12", "results": results},
                    "status": {"code": 0, "message": "OK"},
                }
            ]
        )
        with patch.object(device_proxy_tools, "get_fmg_client", return_value=client):
            return await device_proxy_tools.query_device_api(path, device="branch1", adom="demo")

    @pytest.mark.asyncio
    async def test_session_addresses_are_masked_by_shape(self, masker: OutputMasker) -> None:
        result = await self._query(
            {
                "details": [
                    {
                        "saddr": SESSION_SRC,
                        "daddr": SESSION_DST,
                        "srcintf": "port3",
                        "policyid": 7,
                        "proto": "tcp",
                        "dport": 443,
                        "srcmac": ARP_MAC,
                    }
                ]
            },
            "/api/v2/monitor/firewall/session",
        )
        out = masker.mask_tool_result(result, "query_device_api")
        text = _text(out)

        for value in (SESSION_SRC, SESSION_DST, ARP_MAC):
            assert value not in text
        session = out["results"]["details"][0]
        assert session["srcintf"] == "port3"
        assert session["policyid"] == 7
        assert session["dport"] == 443
        assert out["version"] == "v7.4.12"
        assert out["path"] == "/api/v2/monitor/firewall/session"
        assert out["device"] == "branch1"

    @pytest.mark.asyncio
    async def test_names_comments_and_versions_stay_clear(self, masker: OutputMasker) -> None:
        result = await self._query(
            [
                {
                    "name": "srv-web",
                    "q_origin_key": "srv-web",
                    "comment": "host 198.51.100.9",
                    "subnet": f"198.51.100.9 {NETMASK}",
                    "firmware": "v7.4.12 build2795",
                    "build_str": "7.4.12.2795",
                    "oid": "1.3.6.1.4.1.12356",
                }
            ],
            "/api/v2/cmdb/firewall/address",
        )
        entry = masker.mask_tool_result(result, "query_device_api")["results"][0]

        assert entry["name"] == "srv-web"
        assert entry["q_origin_key"] == "srv-web"
        assert entry["comment"] == "host 198.51.100.9"
        assert entry["firmware"] == "v7.4.12 build2795"
        assert entry["build_str"] == "7.4.12.2795"
        assert entry["oid"] == "1.3.6.1.4.1.12356"
        assert not entry["subnet"].startswith("198.51.100.9")

    @pytest.mark.asyncio
    async def test_an_entry_key_that_is_an_address_is_masked(self, masker: OutputMasker) -> None:
        """A BGP neighbor is keyed by its peer IP: q_origin_key repeats the
        masked ``ip`` (security audit M11)."""
        result = await self._query(
            [
                {"ip": PEER, "q_origin_key": PEER, "remote-as": 65001},
                {"name": f"{STATIC_NET}/26", "mkey": f"{STATIC_NET} 255.255.255.192"},
                {"name": ARP_MAC, "q_origin_key": f"{UNDERLAY_IP}-{STATIC_GW}"},
            ],
            "/api/v2/cmdb/router/bgp/neighbor",
        )
        out = masker.mask_tool_result(result, "query_device_api")
        text = _text(out["results"])

        for value in (PEER, STATIC_NET, ARP_MAC, UNDERLAY_IP, STATIC_GW):
            assert value not in text
        assert out["results"][0]["remote-as"] == 65001
        assert out["results"][1]["name"].endswith("/26")

    def test_a_name_that_only_embeds_an_address_stays(self, masker: OutputMasker) -> None:
        """Names route calls; an embedded address in one stays out of scope."""
        record = {"results": [{"name": f"srv-{PEER}", "q_origin_key": f"srv-{PEER}"}]}
        out = masker.mask_tool_result(record, "query_device_api")
        assert out == record

    def test_a_dict_key_that_is_an_address_is_masked(self, masker: OutputMasker) -> None:
        """FortiOS keys some monitor results by address: the key leaked whole."""
        record = {
            "results": {
                PEER: {"state": "established"},
                f"{LEARNED_NET}/24": {"paths": 2},
                ARP_MAC: "port3",
                f"peer {LOCAL}": 1,
                "port1": {"status": "up"},
            }
        }
        out = masker.mask_tool_result(record, "query_device_api")["results"]
        text = _text(out)

        for value in (PEER, LEARNED_NET, ARP_MAC, LOCAL):
            assert value not in text
        assert out["port1"] == {"status": "up"}
        assert {"state": "established"} in out.values()
        assert any(key.endswith("/24") for key in out)

    def test_other_tools_keep_address_shaped_keys(self, masker: OutputMasker) -> None:
        record = {"by_peer": {PEER: 1}}
        assert masker.mask_tool_result(record, "get_device_status") == record

    @pytest.mark.parametrize(
        "text",
        [
            f"cannot reach {PEER}.",
            f"x.{PEER}",
            f"({PEER}).",
            "via 2001:db8::5.",
            "peer 2001:db8::5: down",
        ],
    )
    def test_an_address_beside_a_dot_fails_closed(self, masker: OutputMasker, text: str) -> None:
        """The dotted-run guard read a sentence's full stop as part of the address (L11)."""
        out = masker.mask_tool_result({"results": [{"msg": text}]}, "query_device_api")
        assert out["results"][0]["msg"].startswith(PLACEHOLDER_MARK)

    @pytest.mark.asyncio
    async def test_an_embedded_address_fails_closed(self, masker: OutputMasker) -> None:
        result = await self._query(
            [{"status_text": f"peer {PEER}:179 idle", "v6_note": "via 2001:db8::5 now"}],
            "/api/v2/monitor/router/bgp/neighbors",
        )
        entry = masker.mask_tool_result(result, "query_device_api")["results"][0]
        assert entry["status_text"].startswith(PLACEHOLDER_MARK)
        assert entry["v6_note"].startswith(PLACEHOLDER_MARK)

    def test_other_tools_do_not_mask_unknown_keys(self, masker: OutputMasker) -> None:
        """Shape detection is scoped: a named-key tool keeps its contract."""
        record = {"saddr": SESSION_SRC}
        assert masker.mask_tool_result(record, "get_device_status") == record

    def test_the_mode_does_not_leak_past_the_call(self, masker: OutputMasker) -> None:
        masker.mask_tool_result({"saddr": SESSION_SRC}, "query_device_api")
        assert masker.mask_result({"saddr": SESSION_SRC}) == {"saddr": SESSION_SRC}
