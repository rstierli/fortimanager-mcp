"""FPE engine: round trips, FortiManager envelopes, cross-sibling equality.

The engine is a port of the FortiAnalyzer one (issue #34). Two properties
matter beyond "it encrypts": every masked value must come back exactly,
and the ciphertext must still match what the sibling MCP produces for the
same value and key, since that shared namespace is the reason the port
reuses FortiAnalyzer's tweak labels rather than minting its own.
"""

import pytest

from fortimanager_mcp.masking.fpe_engine import FPEEngine, MaskingError

# Documentation key, never a real one. Same key used to generate the
# golden vectors below from the FortiAnalyzer engine.
KEY = "2DE79D232DF5585D68CE47882AE256D6"


@pytest.fixture()
def engine() -> FPEEngine:
    return FPEEngine(KEY)


class TestKeyHandling:
    def test_rejects_non_hex_key(self) -> None:
        with pytest.raises(MaskingError):
            FPEEngine("not-hex-at-all-not-hex-at-all-xx")

    def test_rejects_wrong_length_key(self) -> None:
        with pytest.raises(MaskingError):
            FPEEngine("2DE79D23")

    def test_from_env_requires_the_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FMG_MASKING_KEY", raising=False)
        with pytest.raises(MaskingError):
            FPEEngine.from_env()

    def test_from_env_reads_the_fmg_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FMG_MASKING_KEY", KEY)
        assert FPEEngine.from_env().key_id == FPEEngine(KEY).key_id


class TestPrimitiveRoundTrips:
    @pytest.mark.parametrize("value", ["192.0.2.19", "198.51.100.7", "203.0.113.254"])
    def test_ipv4(self, engine: FPEEngine, value: str) -> None:
        token = engine.mask_ip(value)
        assert token != value
        assert engine.unmask_ip(token) == value

    def test_ipv6(self, engine: FPEEngine) -> None:
        token = engine.mask_ip("2001:db8::1")
        assert token != "2001:db8::1"
        assert engine.unmask_ip(token) == "2001:db8::1"

    def test_mac(self, engine: FPEEngine) -> None:
        token = engine.mask_mac("00:11:22:33:44:55")
        assert engine.unmask_mac(token) == "00:11:22:33:44:55"

    def test_hostname(self, engine: FPEEngine) -> None:
        token = engine.mask_hostname("fgt-branch-01")
        assert engine.unmask_hostname(token) == "fgt-branch-01"

    def test_domain(self, engine: FPEEngine) -> None:
        token = engine.mask_domain("www.example.com")
        assert engine.unmask_domain(token) == "www.example.com"

    def test_username_preserves_case(self, engine: FPEEngine) -> None:
        token = engine.mask_username("Admin")
        assert engine.unmask_username(token) == "Admin"

    def test_masking_is_deterministic(self, engine: FPEEngine) -> None:
        """The model must be able to correlate a value across tool calls."""
        assert engine.mask_ip("192.0.2.19") == engine.mask_ip("192.0.2.19")


class TestEnvelopes:
    def test_ipv4_envelope_round_trip(self, engine: FPEEngine) -> None:
        token = engine.mask_ip_token("192.0.2.19")
        assert token.startswith(f"ip4-{engine.key_id}-")
        assert engine.unmask_ip_token(token) == "192.0.2.19"

    def test_ipv6_envelope_round_trip(self, engine: FPEEngine) -> None:
        token = engine.mask_ip_token("2001:db8::1")
        assert token.startswith(f"ip6-{engine.key_id}-")
        assert engine.unmask_ip_token(token) == "2001:db8::1"

    def test_mac_envelope_round_trip(self, engine: FPEEngine) -> None:
        token = engine.mask_mac_token("00:11:22:33:44:55")
        assert token.startswith(f"mac-{engine.key_id}-")
        assert engine.unmask_mac_token(token) == "00:11:22:33:44:55"

    def test_envelope_carries_the_bare_ciphertext(self, engine: FPEEngine) -> None:
        """The envelope is presentation only: the ciphertext is unchanged.

        This is what keeps the port interoperable with the sibling MCP.
        """
        assert engine.mask_ip_token("192.0.2.19").endswith(engine.mask_ip("192.0.2.19"))

    def test_wrong_family_marker_is_refused(self, engine: FPEEngine) -> None:
        token = engine.mask_ip_token("192.0.2.19").replace("ip4-", "ip6-", 1)
        with pytest.raises(MaskingError):
            engine.unmask_ip_token(token)

    def test_cross_type_token_is_refused(self, engine: FPEEngine) -> None:
        with pytest.raises(MaskingError):
            engine.unmask_ip_token(engine.mask_mac_token("00:11:22:33:44:55"))

    def test_foreign_key_id_is_refused(self, engine: FPEEngine) -> None:
        token = engine.mask_ip_token("192.0.2.19")
        foreign = token.replace(f"ip4-{engine.key_id}-", "ip4-ffff-", 1)
        with pytest.raises(MaskingError):
            engine.unmask_ip_token(foreign)

    def test_malformed_envelope_is_refused(self, engine: FPEEngine) -> None:
        with pytest.raises(MaskingError):
            engine.unmask_ip_token("ip4-zzzz-garbage")


class TestSerialSealing:
    @pytest.mark.parametrize(
        "serial",
        [
            "FGVM020000123456",
            "FGT60FTK20012345",
            "FMG-VM0000000001",
            "fg100f0000000001",
            "FGT81FTK24001234567890",
        ],
    )
    def test_serial_round_trips_byte_exact(self, engine: FPEEngine, serial: str) -> None:
        """Serials are uppercase; the string alphabet is not, hence the shield."""
        token = engine.seal_serial(serial)
        assert token.startswith(f"sn-{engine.key_id}-")
        assert serial.lower() not in token.lower()
        assert engine.unseal_serial(token) == serial

    def test_case_distinct_serials_get_distinct_tokens(self, engine: FPEEngine) -> None:
        assert engine.seal_serial("FGVM020000123456") != engine.seal_serial("fgvm020000123456")

    def test_serial_and_url_domains_are_separate(self, engine: FPEEngine) -> None:
        """Same bytes under two labels must not produce the same ciphertext."""
        value = "FGVM020000123456"
        serial_ct = engine.seal_serial(value).split("-", 2)[2]
        url_ct = engine.mask_url_tail(value).split("-", 2)[2]
        assert serial_ct != url_ct

    def test_empty_serial_is_refused(self, engine: FPEEngine) -> None:
        with pytest.raises(MaskingError):
            engine.seal_serial("   ")

    def test_foreign_key_id_is_refused(self, engine: FPEEngine) -> None:
        token = engine.seal_serial("FGVM020000123456")
        with pytest.raises(MaskingError):
            engine.unseal_serial(token.replace(f"sn-{engine.key_id}-", "sn-ffff-", 1))


class TestCrossSiblingGoldenVectors:
    """Fixed vectors produced by the FortiAnalyzer engine, same key.

    Generated once from fortianalyzer-mcp upstream/main
    (src/fortianalyzer_mcp/masking/fpe_engine.py) with KEY above. If a
    port ever renames a tweak label or changes a derivation, these break,
    which is the point: the shared namespace is a contract, not a
    coincidence.
    """

    KEY_ID = "2a85"
    IPV4 = "142.101.213.168"
    IPV6 = "a5b0:6182:60e4:448e:2c73:df9c:3a39:7ee4"
    MAC = "6e:c2:1b:5e:0e:6f"
    HOSTNAME = "host-2a85-1uk-r2r2yn0nv"
    DOMAIN = "xe5xeaqdwkn7hep.2a85.masked.invalid"
    USERNAME = "user-2a85-_gqB1"

    def test_key_id_matches(self, engine: FPEEngine) -> None:
        assert engine.key_id == self.KEY_ID

    def test_ip_ciphertext_matches(self, engine: FPEEngine) -> None:
        assert engine.mask_ip("192.0.2.19") == self.IPV4
        assert engine.mask_ip("2001:db8::1") == self.IPV6

    def test_mac_ciphertext_matches(self, engine: FPEEngine) -> None:
        assert engine.mask_mac("00:11:22:33:44:55") == self.MAC

    def test_string_tokens_match_verbatim(self, engine: FPEEngine) -> None:
        """These forms are byte-identical across the siblings, not just equal ciphertext."""
        assert engine.mask_hostname("fgt-branch-01") == self.HOSTNAME
        assert engine.mask_domain("www.example.com") == self.DOMAIN
        assert engine.mask_username("admin") == self.USERNAME

    def test_envelope_wraps_the_shared_ciphertext(self, engine: FPEEngine) -> None:
        assert engine.mask_ip_token("192.0.2.19") == f"ip4-{self.KEY_ID}-{self.IPV4}"
