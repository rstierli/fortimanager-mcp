"""Tests for policy_lookup_tools module."""

from unittest.mock import AsyncMock, patch

import pytest

from fortimanager_mcp.tools import policy_lookup_tools

# Proxy envelope shape as documented in the How-To Guide's "How to do a
# policy lookup?" example (008_policy_package_management.rst) -- a no-match
# result against 8.8.8.8. Neutral/example values only.
MOCK_NO_MATCH = [
    {
        "response": {
            "action": "select",
            "build": 8348,
            "http_method": "GET",
            "name": "policy-lookup",
            "path": "firewall",
            "results": {"success": False},
            "status": "success",
            "vdom": "root",
        },
        "status": {"code": 0, "message": "OK"},
        "target": "branch1_fgt",
    }
]

# A matched-policy shape is not documented anywhere in the FNDN swagger or
# How-To Guide, so tests only assert on the fields that ARE documented
# (results.success) and pass the rest of the payload through unchanged.
MOCK_MATCH = [
    {
        "response": {
            "results": {"success": True, "policyid": 3},
        },
        "status": {"code": 0, "message": "OK"},
        "target": "branch1_fgt",
    }
]


def _client(proxy_return: object) -> AsyncMock:
    client = AsyncMock()
    client.proxy_call = AsyncMock(return_value=proxy_return)
    return client


class TestPolicyLookup:
    @pytest.mark.asyncio
    async def test_no_match_returns_matched_false(self) -> None:
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="DEMO",
                device="branch1_fgt",
                srcintf="vl_lan",
                protocol=6,
                dest="8.8.8.8",
            )

        assert result["status"] == "success"
        assert result["matched"] is False
        assert result["result"] == {"success": False}

    @pytest.mark.asyncio
    async def test_match_passes_through_result(self) -> None:
        client = _client(MOCK_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=6,
                dest="10.0.0.5",
            )

        assert result["matched"] is True
        assert result["result"]["policyid"] == 3

    @pytest.mark.asyncio
    async def test_query_and_target_shape(self) -> None:
        """protocol is sent as BOTH protocol and protocol_number (How-To Guide
        example carries both, identically valued); target follows the same
        adom/device proxy path used elsewhere in this codebase."""
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="DEMO",
                device="branch1_fgt",
                srcintf="vl_lan",
                protocol=6,
                sourceip="192.0.2.1",
                sourceport=1234,
                destport=443,
                dest="8.8.8.8",
            )

        assert result["query"] == {
            "protocol": 6,
            "protocol_number": 6,
            "dest": "8.8.8.8",
            "destport": 443,
            "srcintf": "vl_lan",
            "sourceip": "192.0.2.1",
            "sourceport": 1234,
        }
        call_kwargs = client.proxy_call.call_args.kwargs
        assert call_kwargs["action"] == "get"
        assert call_kwargs["target"] == ["/adom/DEMO/device/branch1_fgt"]
        assert call_kwargs["resource"].startswith("/api/v2/monitor/firewall/policy-lookup/select?")
        assert "protocol=6" in call_kwargs["resource"]
        assert "protocol_number=6" in call_kwargs["resource"]

    @pytest.mark.asyncio
    async def test_optional_fields_omitted_when_not_given(self) -> None:
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=6,
                dest="8.8.8.8",
            )

        # destport defaults to 0 ("any port") per the How-To Guide example;
        # srcintf/sourceip/sourceport stay absent rather than being sent empty.
        assert result["query"] == {
            "protocol": 6,
            "protocol_number": 6,
            "dest": "8.8.8.8",
            "destport": 0,
        }

    @pytest.mark.asyncio
    async def test_package_is_echoed_not_sent(self) -> None:
        """package has no effect on the RPC -- the documented endpoint has no
        package selector -- but is echoed back for the caller's own bookkeeping."""
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=6,
                dest="8.8.8.8",
                package="default",
            )

        assert result["package_hint"] == "default"
        assert "package" not in result["query"]

    @pytest.mark.asyncio
    async def test_vdom_bracket_suffix_accepted(self) -> None:
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ[vdom2]",
                protocol=6,
                dest="8.8.8.8",
            )
        assert result["status"] == "success"
        assert result["device"] == "FGT-HQ[vdom2]"

    @pytest.mark.asyncio
    async def test_not_connected(self) -> None:
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=None):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=6,
                dest="8.8.8.8",
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_invalid_protocol_rejected(self) -> None:
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=99,
                dest="8.8.8.8",
            )
        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"
        assert client.proxy_call.await_count == 0

    @pytest.mark.asyncio
    async def test_invalid_dest_ip_rejected(self) -> None:
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=6,
                dest="not-an-ip",
            )
        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_invalid_device_name_rejected(self) -> None:
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="bad name; drop",
                protocol=6,
                dest="8.8.8.8",
            )
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_invalid_port_rejected(self) -> None:
        client = _client(MOCK_NO_MATCH)
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=6,
                dest="8.8.8.8",
                destport=70000,
            )
        assert result["status"] == "error"
        assert result["error_code"] == "validation_error"

    @pytest.mark.asyncio
    async def test_off_shape_proxy_response_yields_none_matched(self) -> None:
        client = _client({"unexpected": "shape"})
        with patch.object(policy_lookup_tools, "get_fmg_client", return_value=client):
            result = await policy_lookup_tools.policy_lookup(
                adom="root",
                device="FGT-HQ",
                protocol=6,
                dest="8.8.8.8",
            )
        assert result["status"] == "success"
        assert result["matched"] is None
        assert result["result"] is None


class TestProxyResultsHelper:
    def test_off_shape_returns_none(self) -> None:
        assert policy_lookup_tools._proxy_results({"no": "envelope"}) is None
        assert policy_lookup_tools._proxy_results([]) is None

    def test_unwraps_documented_envelope(self) -> None:
        assert policy_lookup_tools._proxy_results(MOCK_NO_MATCH) == {"success": False}


class TestProtocolAllowlist:
    """upstream #71: the allowlist stopped at ICMP/TCP/UDP and refused GRE,
    ESP, AH and SCTP, which a firewall policy can match on just as well. A
    VPN transit policy is exactly the kind of rule an operator wants to
    test."""

    @pytest.mark.parametrize(
        ("protocol", "name"), [(47, "GRE"), (50, "ESP"), (51, "AH"), (132, "SCTP")]
    )
    def test_the_protocols_that_used_to_be_refused_are_known(self, protocol, name):
        assert policy_lookup_tools._KNOWN_PROTOCOLS[protocol] == name

    @pytest.mark.parametrize("protocol", [1, 6, 17])
    def test_the_original_three_still_work(self, protocol):
        assert protocol in policy_lookup_tools._KNOWN_PROTOCOLS

    def test_an_unassigned_protocol_is_still_refused(self):
        """Still an allowlist, not an open field."""
        assert 253 not in policy_lookup_tools._KNOWN_PROTOCOLS
