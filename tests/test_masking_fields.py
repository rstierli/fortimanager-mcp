"""The carrier table as policy: what masks, what must never mask.

The table is the one place where a mistake is silent. A missing carrier
leaks a value with every test still green, and a routing key added by
accident breaks every follow-up call that used the name.
"""

import pytest

from fortimanager_mcp.masking import fields


class TestCanonicalKey:
    def test_folds_the_three_spellings_fortimanager_uses(self) -> None:
        assert fields.canonical_key("start-ip") == "start_ip"
        assert fields.canonical_key("start_ip") == "start_ip"
        assert fields.canonical_key("Start-IP") == "start_ip"

    def test_folds_the_spaced_system_status_forms(self) -> None:
        """get_system_status returns "Serial Number" and "Hostname" live."""
        assert fields.canonical_key("Serial Number") == "serial_number"
        assert fields.canonical_key("Hostname") == "hostname"
        assert fields.canonical_key("Serial Number") in fields.FIELD_TYPES
        assert fields.canonical_key("Hostname") in fields.FIELD_TYPES


class TestTablePolicy:
    def test_no_routing_key_is_a_carrier(self) -> None:
        """Names route later calls; masking one breaks the call, not privacy."""
        overlap = set(fields.FIELD_TYPES) & fields.ROUTING_KEYS_NEVER_MASK
        assert overlap == set()

    def test_every_carrier_has_a_known_type(self) -> None:
        known = {
            fields.IP,
            fields.MAC,
            fields.HOSTNAME,
            fields.USERNAME,
            fields.DOMAIN,
            fields.EMAIL,
            fields.SERIAL,
            fields.IP_OR_HOST,
        }
        assert set(fields.FIELD_TYPES.values()) <= known

    def test_all_keys_are_canonical(self) -> None:
        """A non-canonical entry would never be found at lookup time."""
        for key in fields.FIELD_TYPES:
            assert fields.canonical_key(key) == key

    def test_serials_use_the_sealing_type(self) -> None:
        """The hostname cipher lowercases; serials must survive byte-exact."""
        assert fields.FIELD_TYPES["sn"] == fields.SERIAL
        assert fields.FIELD_TYPES["serial_number"] == fields.SERIAL

    def test_free_text_is_not_a_carrier(self) -> None:
        """Documented carve-out: tokens in prose get written back as config."""
        for key in ("comment", "comments", "description"):
            assert key not in fields.FIELD_TYPES


class TestComposites:
    def test_composites_are_not_also_scalar_carriers(self) -> None:
        """Two handlers for one key would mask it twice."""
        composites = (
            set(fields.COMPOSITE_SUBNET)
            | set(fields.COMPOSITE_WILDCARD_IP)
            | set(fields.COMPOSITE_FQDN)
        )
        assert composites & set(fields.FIELD_TYPES) == set()

    def test_fqdn_is_a_composite_because_wildcards_share_the_key(self) -> None:
        """8.0.0 returns {"fqdn": "*.google.com"} in the same key as a plain name."""
        assert "fqdn" in fields.COMPOSITE_FQDN
        assert "fqdn" not in fields.FIELD_TYPES

    def test_wildcard_address_and_wildcard_fqdn_are_different_things(self) -> None:
        """ "wildcard" is an IP plus mask; a wildcard FQDN is a domain string."""
        assert set(fields.COMPOSITE_WILDCARD_IP) & set(fields.COMPOSITE_FQDN) == set()


class TestSkipValues:
    def test_structural_values_are_skipped(self) -> None:
        """Live 8.0.0 ships subnet ["0.0.0.0", "0.0.0.0"] on stock objects."""
        for value in ("0.0.0.0", "any", "all", ""):
            assert value in fields.SKIP_VALUES

    def test_skip_values_are_lowercase_for_comparison(self) -> None:
        for value in fields.SKIP_VALUES:
            assert value == value.lower()


class TestUsernames:
    """Account and client names are identifiers and mask as such (security audit L14)."""

    @pytest.mark.parametrize("key", ["username", "user_name", "user"])
    def test_the_key_is_a_username_carrier(self, key: str) -> None:
        assert fields.FIELD_TYPES[key] == fields.USERNAME

    def test_srcname_is_a_host_name(self) -> None:
        """FortiOS's srcname is the source device's name, not an account."""
        assert fields.FIELD_TYPES["srcname"] == fields.HOSTNAME

    @pytest.mark.parametrize("key", ["username", "user-name", "User Name", "user"])
    def test_the_value_is_masked(self, key: str, monkeypatch: pytest.MonkeyPatch) -> None:
        from fortimanager_mcp.masking.fpe_engine import FPEEngine
        from fortimanager_mcp.masking.wrapper import OutputMasker

        secret = "2DE79D232DF5585D68CE47882AE256D6"
        monkeypatch.setenv("FMG_MASKING_KEY", secret)
        engine = FPEEngine(secret)
        out = OutputMasker(engine).mask_result({"entries": [{key: "j.doe"}]})

        masked = out["entries"][0][key]
        assert masked != "j.doe"
        assert engine.unmask_username(masked) == "j.doe"

    def test_a_srcname_is_masked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from fortimanager_mcp.masking.fpe_engine import FPEEngine
        from fortimanager_mcp.masking.wrapper import OutputMasker

        secret = "2DE79D232DF5585D68CE47882AE256D6"
        monkeypatch.setenv("FMG_MASKING_KEY", secret)
        out = OutputMasker(FPEEngine(secret)).mask_result({"srcname": "laptop-jdoe"})
        assert "laptop-jdoe" not in str(out)
