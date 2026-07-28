"""Marker recognition: what the input guard will and will not refuse.

These tests pin the two tiers described in ``masking/tokens.py``. Getting
them wrong is not a cosmetic bug: a missed marker means a token can be
written into estate configuration, and an over-broad marker means an
ordinary hostname stops working as an argument.
"""

import pytest

from fortimanager_mcp.masking import tokens

# The FortiAnalyzer string alphabet, which the ported engine reuses. "~"
# is in it, which is exactly the character a hand-written pattern misses.
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-._~"
SUFFIX = "masked.invalid"


@pytest.fixture()
def pattern() -> "tokens.re.Pattern[str]":
    return tokens.strict_pattern(ALPHABET, SUFFIX)


class TestStrictRecognition:
    @pytest.mark.parametrize(
        "token",
        [
            "ip4-a1b2-192.0.2.19",
            "ip6-a1b2-2001.db8",
            "mac-a1b2-00.11.22.33.44.55",
            "sn-a1b2-abc123xyz",
            "url-a1b2-mfrggzdf",
            "host-a1b2-kqwerty",
            "user-a1b2-zxcvb",
            "abcdef.a1b2.masked.invalid",
            "masked-unrepresentable-0a1b2c3d4e",
        ],
    )
    def test_every_emitted_form_is_recognized(
        self, token: str, pattern: "tokens.re.Pattern[str]"
    ) -> None:
        assert tokens.contains_token(token, pattern)

    def test_tilde_payload_is_recognized(self, pattern: "tokens.re.Pattern[str]") -> None:
        """The string cipher emits "~"; a hand-written class would miss it."""
        assert tokens.contains_token("sn-a1b2-ab~cd~ef", pattern)

    def test_case_insensitive(self, pattern: "tokens.re.Pattern[str]") -> None:
        assert tokens.contains_token("IP4-A1B2-192.0.2.19", pattern)
        assert tokens.contains_token("Host-a1b2-kqwerty", pattern)

    @pytest.mark.parametrize(
        "text",
        [
            "investigate ip4-a1b2-192.0.2.19 tomorrow",
            "note:ip4-a1b2-192.0.2.19",
            "config system global\n set hostname host-a1b2-kqwerty\nend",
            "contact abcdef.a1b2.masked.invalid for details",
        ],
    )
    def test_embedded_tokens_are_recognized(
        self, text: str, pattern: "tokens.re.Pattern[str]"
    ) -> None:
        """A token inside a comment or a script body would be written verbatim."""
        assert tokens.contains_token(text, pattern)


class TestStrictNonRecognition:
    @pytest.mark.parametrize(
        "value",
        [
            "192.0.2.19",
            "srv-web-dmz",
            "www.example.com",
            "FGVM020000123456",
            "root",
            "allow web traffic from the branch office",
            "unmasked.invalid",
            "myhost-a1b2-kqwerty",
        ],
    )
    def test_ordinary_values_are_not_tokens(
        self, value: str, pattern: "tokens.re.Pattern[str]"
    ) -> None:
        assert not tokens.contains_token(value, pattern)

    def test_ordinary_prefixed_name_inside_a_sentence_is_not_a_token(
        self, pattern: "tokens.re.Pattern[str]"
    ) -> None:
        """A real device named host-branch-01 must stay usable in free text."""
        assert not tokens.contains_token("replace host-branch-01 next week", pattern)

    def test_documented_collision_a_name_shaped_exactly_like_a_token(
        self, pattern: "tokens.re.Pattern[str]"
    ) -> None:
        """A real name of the form host-<4 hex>-<rest> reads as a token.

        Accepted residual, inherited from the FortiAnalyzer marker
        scheme: "abcd" is valid hex, so host-abcd-server is
        indistinguishable from a hostname token. The consequence is a
        refused argument, never a wrong value, and the whole-scalar tier
        refuses every "host-" argument anyway.
        """
        assert tokens.contains_token("decommission host-abcd-server", pattern)


class TestLooseRecognition:
    @pytest.mark.parametrize(
        "value",
        [
            "ip4-a1b2-192.0.2.19",
            "sn-truncated",
            "host-branch-01",
            "MAC-A1B2-garbage",
            "abcdef.a1b2.masked.invalid",
            "masked-unrepresentable-0a1b2c3d",
        ],
    )
    def test_whole_scalar_markers_are_refused(self, value: str) -> None:
        assert tokens.looks_token_shaped(value, SUFFIX)

    @pytest.mark.parametrize(
        "value",
        ["192.0.2.19", "srv-web-dmz", "www.example.com", "unmasked.invalid", "root"],
    )
    def test_ordinary_whole_scalars_pass(self, value: str) -> None:
        assert not tokens.looks_token_shaped(value, SUFFIX)


def test_reserved_suffix_is_dotted() -> None:
    """Without the dot, unmasked.invalid would read as a token."""
    assert tokens.reserved_suffix("masked.invalid") == ".masked.invalid"
    assert tokens.reserved_suffix(".masked.invalid") == ".masked.invalid"
