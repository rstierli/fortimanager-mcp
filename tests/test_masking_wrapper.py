"""Output masking: what gets replaced, what survives, what fails closed.

Record shapes here mirror live FortiManager 7.6.7 and 8.0.0 responses
(read-only sweep, issue #34). Every value is from a documentation range
(RFC 5737, RFC 2606); no value from any real estate appears.
"""

from typing import Any

import pytest

from fortimanager_mcp.masking.fields import REDACTED
from fortimanager_mcp.masking.fpe_engine import FPEEngine
from fortimanager_mcp.masking.tokens import PLACEHOLDER_MARK
from fortimanager_mcp.masking.wrapper import OutputMasker

KEY = "2DE79D232DF5585D68CE47882AE256D6"


@pytest.fixture()
def engine() -> FPEEngine:
    return FPEEngine(KEY)


@pytest.fixture()
def masker(engine: FPEEngine, monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FMG_MASKING_KEY", KEY)
    return OutputMasker(engine)


class TestNamesStayClear:
    def test_routing_names_survive_at_every_depth(self, masker: OutputMasker) -> None:
        """A masked name would break every follow-up call that used it."""
        record = {
            "name": "srv-web-dmz",
            "adom": "root",
            "package": "Corporate/Branch",
            "ip": "192.0.2.19",
            "nested": [{"name": "grp-partners", "vdom": "root", "ip": "198.51.100.7"}],
        }

        out = masker.mask_result(record)

        assert out["name"] == "srv-web-dmz"
        assert out["adom"] == "root"
        assert out["package"] == "Corporate/Branch"
        assert out["nested"][0]["name"] == "grp-partners"
        assert out["nested"][0]["vdom"] == "root"
        assert out["ip"] != "192.0.2.19"
        assert out["nested"][0]["ip"] != "198.51.100.7"

    def test_unknown_keys_pass_through(self, masker: OutputMasker) -> None:
        record = {"os_ver": "7.6.7", "platform_str": "FortiGate-VM64", "conn_status": 1}
        assert masker.mask_result(record) == record


class TestScalarCarriers:
    def test_ip_is_masked_into_a_marked_envelope(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        out = masker.mask_result({"ip": "192.0.2.19"})
        assert out["ip"].startswith(f"ip4-{engine.key_id}-")
        assert engine.unmask_ip_token(out["ip"]) == "192.0.2.19"

    def test_serial_round_trips_with_its_case(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """The hostname cipher lowercases; a serial must come back exact."""
        out = masker.mask_result({"sn": "FGVM020000123456"})
        assert out["sn"].startswith(f"sn-{engine.key_id}-")
        assert engine.unseal_serial(out["sn"]) == "FGVM020000123456"

    def test_spaced_system_status_keys_are_masked(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """Live 7.6.7 get_system_status answers with title-cased spaced keys."""
        record = {"Serial Number": "FMG-VM0000000001", "Hostname": "FMG-LAB-01", "Build": "3737"}

        out = masker.mask_result(record)

        assert engine.unseal_serial(out["Serial Number"]) == "FMG-VM0000000001"
        assert out["Hostname"] != "FMG-LAB-01"
        assert out["Build"] == "3737"

    def test_admin_user_is_masked(self, masker: OutputMasker, engine: FPEEngine) -> None:
        out = masker.mask_result({"adm_usr": "netadmin"})
        assert engine.unmask_username(out["adm_usr"]) == "netadmin"

    def test_masking_is_deterministic_across_calls(self, masker: OutputMasker) -> None:
        first = masker.mask_result({"ip": "192.0.2.19"})["ip"]
        second = masker.mask_result({"nested": {"ip": "192.0.2.19"}})["nested"]["ip"]
        assert first == second


class TestSubnetComposite:
    def test_list_form_masks_network_keeps_netmask(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """Live 8.0.0 shape: {"subnet": ["169.254.169.254", "255.255.255.255"]}."""
        out = masker.mask_result({"subnet": ["203.0.113.0", "255.255.255.0"]})

        assert out["subnet"][1] == "255.255.255.0"
        assert out["subnet"][0] != "203.0.113.0"
        assert engine.unmask_ip_token(out["subnet"][0]) == "203.0.113.0"

    def test_prefix_string_form(self, masker: OutputMasker, engine: FPEEngine) -> None:
        out = masker.mask_result({"subnet": "203.0.113.0/24"})
        token, _, tail = out["subnet"].partition("/")
        assert tail == "24"
        assert engine.unmask_ip_token(token) == "203.0.113.0"

    def test_space_separated_string_form(self, masker: OutputMasker, engine: FPEEngine) -> None:
        out = masker.mask_result({"subnet": "203.0.113.0 255.255.255.0"})
        token, _, tail = out["subnet"].partition(" ")
        assert tail == "255.255.255.0"
        assert engine.unmask_ip_token(token) == "203.0.113.0"

    def test_structural_subnets_are_left_alone(self, masker: OutputMasker) -> None:
        """Stock 8.0.0 objects ship subnet ["0.0.0.0", "0.0.0.0"]."""
        record = {"subnet": ["0.0.0.0", "0.0.0.0"]}
        assert masker.mask_result(record) == record

    def test_wildcard_address_keeps_its_mask(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"wildcard": ["203.0.113.0", "0.0.0.255"]})
        assert out["wildcard"][1] == "0.0.0.255"
        assert out["wildcard"][0] != "203.0.113.0"


class TestFqdnComposite:
    def test_plain_fqdn_masks_whole(self, masker: OutputMasker, engine: FPEEngine) -> None:
        out = masker.mask_result({"fqdn": "mail.example.com"})
        assert out["fqdn"].endswith(f".{engine.key_id}.{engine.mask_suffix}")
        assert engine.unmask_domain(out["fqdn"]) == "mail.example.com"

    def test_wildcard_fqdn_keeps_its_label(self, masker: OutputMasker, engine: FPEEngine) -> None:
        """Live 8.0.0 returns {"fqdn": "*.google.com"} in the same key."""
        out = masker.mask_result({"fqdn": "*.example.com"})

        assert out["fqdn"].startswith("*.")
        assert PLACEHOLDER_MARK not in out["fqdn"]
        assert engine.unmask_domain(out["fqdn"][2:]) == "example.com"

    def test_wildcard_fqdn_key_takes_the_same_handler(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """A third FQDN key beside fqdn and wildcard (PR #39 review).

        It exists precisely to hold a starred name, so routing it to a
        plain DOMAIN carrier would placeholder the common case.
        """
        out = masker.mask_result({"wildcard-fqdn": "*.example.com"})

        assert out["wildcard-fqdn"].startswith("*.")
        assert PLACEHOLDER_MARK not in out["wildcard-fqdn"]
        assert engine.unmask_domain(out["wildcard-fqdn"][2:]) == "example.com"


class TestRangeComposite:
    """``iprange`` holds either one address or a start-end pair."""

    def test_pair_masks_both_ends(self, masker: OutputMasker, engine: FPEEngine) -> None:
        out = masker.mask_result({"iprange": "192.0.2.1-192.0.2.10"})

        # Not a partition on the first "-": each token is itself
        # "<kind>-<kid>-<ct>", so the joined pair holds six parts. See
        # the separator test below for why that count is stable.
        parts = out["iprange"].split("-")
        assert len(parts) == 6
        start = "-".join(parts[:3])
        end = "-".join(parts[3:])

        assert engine.unmask_ip_token(start) == "192.0.2.1"
        assert engine.unmask_ip_token(end) == "192.0.2.10"

    @pytest.mark.parametrize(
        ("low", "high"),
        [
            ("192.0.2.1", "192.0.2.10"),
            ("198.51.100.0", "198.51.100.255"),
            ("2001:db8::1", "2001:db8::ffff"),
        ],
    )
    def test_the_hyphen_separator_stays_unambiguous(
        self, masker: OutputMasker, low: str, high: str
    ) -> None:
        """The join is only reversible because a token holds no spare "-".

        A masked pair is two ``<kind>-<kid>-<ct>`` tokens joined by the
        separator they also contain, so the value can only be split back
        because ``kind``, ``kid`` and ``ct`` are each hyphen-free: the
        kinds are ip4/ip6, the key id is hex, and a masked address prints
        as dotted quad or colon-separated v6. Nothing enforces that, so
        it is asserted here rather than trusted, for both families.
        """
        out = masker.mask_result({"iprange": f"{low}-{high}"})

        assert out["iprange"].count("-") == 5

    def test_single_address_masks_as_one(self, masker: OutputMasker, engine: FPEEngine) -> None:
        out = masker.mask_result({"iprange": "192.0.2.1"})
        assert engine.unmask_ip_token(out["iprange"]) == "192.0.2.1"

    def test_stock_unset_value_is_left_alone(self, masker: OutputMasker) -> None:
        """Every stock 7.6.7 service carries iprange 0.0.0.0 (measured)."""
        assert masker.mask_result({"iprange": "0.0.0.0"}) == {"iprange": "0.0.0.0"}

    @pytest.mark.parametrize(
        "value",
        [
            "192.0.2.1-",
            "-192.0.2.10",
            "192.0.2.1-192.0.2.10-192.0.2.20",
            "192.0.2.1-not-an-address",
            "example.com-192.0.2.1",
        ],
    )
    def test_anything_that_is_not_a_range_fails_closed(
        self, masker: OutputMasker, value: str
    ) -> None:
        """An unparsed range is still full of addresses, so never pass it."""
        out = masker.mask_result({"iprange": value})

        assert out["iprange"].startswith(PLACEHOLDER_MARK)
        assert value not in out["iprange"]


class TestIpv6InterfaceAddresses:
    """``ip6-address`` carries its prefix, so it takes the subnet handler.

    The PR #39 review suggested a plain IP carrier. That cannot parse
    ``addr/prefix``: it would fail the value closed into an irreversible
    placeholder, losing both the address and the prefix an operator needs.
    """

    def test_prefix_bearing_address_keeps_its_prefix(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        out = masker.mask_result({"ipv6": {"ip6-address": "2001:db8::1/64"}})
        masked = out["ipv6"]["ip6-address"]

        assert masked.endswith("/64")
        assert PLACEHOLDER_MARK not in masked
        assert engine.unmask_ip_token(masked[: -len("/64")]) == "2001:db8::1"

    def test_bare_address_still_works(self, masker: OutputMasker, engine: FPEEngine) -> None:
        """The handler falls through to a plain IP, so it is a superset."""
        out = masker.mask_result({"ipv6": {"ip6-address": "2001:db8::1"}})
        assert engine.unmask_ip_token(out["ipv6"]["ip6-address"]) == "2001:db8::1"


class TestSecretsAreRedactedNotTokenised:
    """A credential is not an identifier, so it does not get a token.

    A token is reversible by design and stable across calls; both are
    wrong for a secret. The constant is checked before every other rule
    in the walk, so the value's shape never gets a say.
    """

    def test_admin_password_is_replaced_by_a_constant(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"name": "fgt-branch-01", "adm_pass": "not-a-real-password"})

        assert out["adm_pass"] == REDACTED
        assert "not-a-real-password" not in str(out)
        assert out["name"] == "fgt-branch-01"

    def test_a_list_valued_secret_is_replaced_whole(self, masker: OutputMasker) -> None:
        """FortiManager returns adm_pass as a list of encrypted strings.

        Recursing into it would be a chance to emit part of it, so the
        redaction does not look at the value at all.
        """
        out = masker.mask_result({"adm_pass": ["ENC aaaa", "ENC bbbb"]})

        assert out["adm_pass"] == REDACTED
        assert "ENC" not in str(out)

    def test_redaction_does_not_correlate_two_devices(self, masker: OutputMasker) -> None:
        """Two different passwords must not be distinguishable."""
        out = masker.mask_result(
            {"devices": [{"adm_pass": "secret-one"}, {"adm_pass": "secret-two"}]}
        )

        first, second = out["devices"]
        assert first["adm_pass"] == second["adm_pass"] == REDACTED

    def test_the_constant_is_not_token_shaped(self) -> None:
        """It must not read as something a caller could send back."""
        assert PLACEHOLDER_MARK not in REDACTED


class TestFailClosed:
    def test_unmaskable_value_becomes_a_placeholder(self, masker: OutputMasker) -> None:
        """Outside the cipher alphabet: never passed through raw."""
        out = masker.mask_result({"fqdn": "hosét.example.com"})
        assert out["fqdn"].startswith(PLACEHOLDER_MARK)
        assert "hosét" not in out["fqdn"]

    def test_placeholders_are_deterministic(self, masker: OutputMasker) -> None:
        first = masker.mask_result({"fqdn": "båd.example.com"})["fqdn"]
        second = masker.mask_result({"fqdn": "båd.example.com"})["fqdn"]
        assert first == second

    def test_wildcard_failure_yields_one_bare_placeholder(self, masker: OutputMasker) -> None:
        """ "*." + placeholder would not be recognizable to the input guard."""
        out = masker.mask_result({"fqdn": "*.båd.example.com"})
        assert out["fqdn"].startswith(PLACEHOLDER_MARK)

    def test_whole_result_is_withheld_when_masking_breaks(
        self, masker: OutputMasker, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(*_: Any, **__: Any) -> Any:
            raise RuntimeError("walker bug with 192.0.2.19 inside")

        monkeypatch.setattr(masker, "mask_result", explode)

        out = masker.mask_tool_result({"ip": "192.0.2.19"}, "get_device")

        assert out["status"] == "error"
        assert out["error"] == "masking_failed"
        assert "192.0.2.19" not in str(out)
        assert "walker bug" not in str(out)
