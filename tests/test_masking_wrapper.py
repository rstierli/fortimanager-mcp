"""Output masking: what gets replaced, what survives, what fails closed.

Record shapes here mirror live FortiManager 7.6.7 and 8.0.0 responses
(read-only sweep, issue #34). Every value is from a documentation range
(RFC 5737, RFC 2606); no value from any real estate appears.
"""

from typing import Any

import pytest

from fortimanager_mcp.masking.fpe_engine import FPEEngine
from fortimanager_mcp.masking.tokens import PLACEHOLDER_MARK, REDACTED, strict_pattern
from fortimanager_mcp.masking.wrapper import OutputMasker, TokenInInput, guard_args

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
        self, masker: OutputMasker, engine: FPEEngine, low: str, high: str
    ) -> None:
        """The join is only reversible because a token holds no spare "-".

        A masked pair is two ``<kind>-<kid>-<ct>`` tokens joined by the
        separator they also contain, so the value can only be split back
        because ``kind``, ``kid`` and ``ct`` are each hyphen-free: the
        kinds are ip4/ip6, the key id is hex, and a masked address prints
        as dotted quad or colon-separated v6. Nothing enforces that, so
        it is asserted here rather than trusted, for both families.

        The assertion is the round trip, not the hyphen count. Counting
        alone would pass on a value that split 6 ways but did not align
        3 and 3, which is the thing a consumer actually depends on.
        """
        out = masker.mask_result({"iprange": f"{low}-{high}"})

        parts = out["iprange"].split("-")
        assert len(parts) == 6
        assert engine.unmask_ip_token("-".join(parts[:3])) == low
        assert engine.unmask_ip_token("-".join(parts[3:])) == high

    def test_single_address_masks_as_one(self, masker: OutputMasker, engine: FPEEngine) -> None:
        out = masker.mask_result({"iprange": "192.0.2.1"})
        assert engine.unmask_ip_token(out["iprange"]) == "192.0.2.1"

    def test_a_half_structural_pair_still_masks_the_real_address(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """One structural end does not buy the other end its freedom.

        ``0.0.0.0-192.0.2.10`` masks only the right-hand side, so the
        result holds three hyphens rather than five. That breaks the
        split-six shape above, which is why it is pinned separately
        instead of being left to look like a bug later: withholding a
        real address because its partner is structural would be worse.
        """
        out = masker.mask_result({"iprange": "0.0.0.0-192.0.2.10"})
        head, _, tail = out["iprange"].partition("-")

        assert head == "0.0.0.0"
        assert engine.unmask_ip_token(tail) == "192.0.2.10"

    @pytest.mark.parametrize("value", ["0.0.0.0", "any", "all", "n/a", "-", ""])
    def test_structural_values_are_left_alone(self, masker: OutputMasker, value: str) -> None:
        """Every stock 7.6.7 service carries iprange 0.0.0.0 (measured).

        The handler's own skip check is what does this. Without the whole
        list, deleting that check survived the suite: "0.0.0.0" exits
        identically through the scalar route's skip, so it alone kills
        no mutant.
        """
        assert masker.mask_result({"iprange": value}) == {"iprange": value}

    def test_a_list_of_ranges_does_not_pass_through(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """The shape the handler did not expect must not be the shape it trusts.

        Measured before this was fixed: a list value under a composite key
        was returned verbatim, addresses and all, because every composite
        special-cased the known shapes and fell through to ``return
        value``. Multi-valued FortiManager fields are lists.
        """
        record = {"iprange": ["192.0.2.1-192.0.2.10"]}

        out = masker.mask_result(record)

        assert out != record
        assert "192.0.2.1" not in str(out)
        parts = out["iprange"][0].split("-")
        assert engine.unmask_ip_token("-".join(parts[:3])) == "192.0.2.1"

    @pytest.mark.parametrize(
        "value",
        [
            "192.0.2.1-",
            "-192.0.2.10",
            "192.0.2.1-192.0.2.10-192.0.2.20",
            "192.0.2.1-not-an-address",
            "example.com-192.0.2.1",
            # No hyphen at all, so these reach the handler's other exit.
            # Without them a mutant that returns the value unchanged there
            # survives the whole suite: every case above fails closed on
            # the pair branch instead, and proves nothing about this one.
            "example.com",
            "192.0.2",
            "unset",
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


class TestCompositesFailClosedOnUnexpectedShapes:
    """No composite may return a value it did not understand.

    This was the class of bug, not one instance of it: each composite
    special-cased the shapes FortiManager is known to use and ended in
    ``return value``, so a list under any of those keys reached the
    caller with its addresses in clear. Measured on all four before the
    fix. Parametrised so a future composite that forgets is caught here
    rather than by whoever reads the transcript.
    """

    @pytest.mark.parametrize(
        ("key", "value", "secret"),
        [
            ("iprange", ["198.51.100.10-198.51.100.20"], "198.51.100.10"),
            ("subnet", ["203.0.113.0"], "203.0.113.0"),
            ("subnet", ["203.0.113.0", "255.255.255.0", "extra"], "203.0.113.0"),
            ("wildcard", ["203.0.113.0"], "203.0.113.0"),
            ("ip6-address", ["2001:db8::1", 64], "2001:db8::1"),
            ("ip6-subnet", ["2001:db8::1"], "2001:db8::1"),
            ("fqdn", ["mail.example.com"], "mail.example.com"),
            ("wildcard-fqdn", ["*.example.com"], "example.com"),
        ],
    )
    def test_a_list_value_never_passes_through(
        self, masker: OutputMasker, key: str, value: Any, secret: str
    ) -> None:
        out = masker.mask_result({key: value})

        assert out[key] != value
        assert secret not in str(out), f"{secret} survived under {key}"

    def test_a_non_string_scalar_is_left_alone(self, masker: OutputMasker) -> None:
        """The bound on the class: an int cannot carry an address."""
        record = {"iprange": 0, "subnet": None, "fqdn": True}
        assert masker.mask_result(record) == record

    def test_the_known_two_string_subnet_shape_still_keeps_its_mask(
        self, masker: OutputMasker
    ) -> None:
        """The fix must not turn a netmask into a token.

        The list branch runs only after the known shapes, so the live
        8.0.0 [network, netmask] form is unaffected.
        """
        out = masker.mask_result({"subnet": ["203.0.113.0", "255.255.255.0"]})
        assert out["subnet"][1] == "255.255.255.0"


class TestSecretsAreRedactedNotTokenised:
    """A credential is not an identifier, so it does not get a token.

    A token is reversible by design and stable across calls; both are
    wrong for a secret. The constant is checked before every other rule
    in the walk, so the value's shape never gets a say.
    """

    @pytest.mark.parametrize(
        "key", ["adm_pass", "adm_passwd", "adm-pass", "Adm Pass", "ADM_PASS", "password"]
    )
    def test_admin_password_is_replaced_by_a_constant(self, masker: OutputMasker, key: str) -> None:
        """Both spellings, and every casing canonical_key folds onto them.

        The repo's own write-path strip covers adm_pass AND adm_passwd
        (dvm_tools.py:344), so covering one here would leave the gap the
        rest of the codebase already knows about.
        """
        out = masker.mask_result({"name": "fgt-branch-01", key: "not-a-real-password"})

        assert out[key] == REDACTED
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

    def test_the_constant_is_refused_if_it_comes_back(self, engine: FPEEngine) -> None:
        """The rule this layer states about every value it emits.

        The first version of this test asserted the opposite of its own
        docstring: it said the constant "must not read as something a
        caller could send back", and then asserted only that the
        placeholder mark was absent from it, which is precisely what let
        it be sent back unrefused. Measured with the old ``[redacted]``:
        ``guard_args`` accepted it, so a model that echoed a masked
        device record into a write would have set that literal text as
        the device's admin password with nothing objecting.

        The constant is part of the reserved vocabulary now, so the
        guard refuses it like any other emitted value.
        """
        pattern = strict_pattern(engine.str_alphabet, engine.mask_suffix)

        with pytest.raises(TokenInInput):
            guard_args({"adm_pass": REDACTED}, pattern, engine.mask_suffix)

    def test_a_plain_looking_constant_would_not_have_been_refused(self, engine: FPEEngine) -> None:
        """The negative control for the test above.

        Without this, that test passes for a constant that is refused for
        some unrelated reason, and the property it claims goes unchecked.
        """
        pattern = strict_pattern(engine.str_alphabet, engine.mask_suffix)

        guard_args({"adm_pass": "[redacted]"}, pattern, engine.mask_suffix)


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


class TestCarriersFailClosedOnNestedShapes:
    """A carrier key must never hand back a container it did not walk.

    The composites were taught to fail closed per element, but only for
    strings. A dict or a nested list under a carrier key still returned
    verbatim, and worse, the walk stopped there: a carrier nested inside
    that container was never reached. Measured on every shape below
    before the fix, including through the scalar route, which the earlier
    round did not touch at all.
    """

    @pytest.mark.parametrize(
        ("payload", "secret"),
        [
            ({"ip": {"ip": "198.51.100.5"}}, "198.51.100.5"),
            ({"ip": [{"ip": "192.0.2.1"}]}, "192.0.2.1"),
            ({"source": {"gateway": "192.0.2.9"}}, "192.0.2.9"),
            ({"subnet": [{"ip": "203.0.113.5"}]}, "203.0.113.5"),
            ({"iprange": {"start_ip": "192.0.2.1"}}, "192.0.2.1"),
            ({"iprange": [["192.0.2.1-192.0.2.10"]]}, "192.0.2.1-192.0.2.10"),
            ({"fqdn": {"fqdn": "mail.example.com"}}, "mail.example.com"),
            ({"ip6_address": [{"ip": "192.0.2.30"}]}, "192.0.2.30"),
        ],
    )
    def test_no_carrier_returns_an_unwalked_container(
        self, masker: OutputMasker, payload: dict[str, Any], secret: str
    ) -> None:
        assert secret not in str(masker.mask_result(payload))

    def test_a_nested_range_still_masks_both_ends(self, masker: OutputMasker) -> None:
        """Nested lists keep the composite handler, not the generic walk.

        Recursing a nested list through ``mask_result`` would lose the key
        context, so the strings inside would come back untouched.
        """
        out = masker.mask_result({"iprange": [["192.0.2.1-192.0.2.10"]]})
        masked = out["iprange"][0][0]
        assert masked.count("-") == 5, masked

    def test_non_containers_under_a_carrier_are_left_alone(self, masker: OutputMasker) -> None:
        assert masker.mask_result({"ip": 42}) == {"ip": 42}
        assert masker.mask_result({"ip": None}) == {"ip": None}


class TestDeviceSerialCarrier:
    """``serial`` is the proxy envelope's spelling of a device serial.

    ``get_device_realtime_status`` and ``get_device_interfaces`` return
    the FortiOS response verbatim under ``data``, and every FortiOS
    monitor envelope carries its serial at top level. Measured on a live
    7.4.12 FortiGate. The table already masked ``sn`` and
    ``serial_number``, so this spelling leaking was an inconsistency with
    its own intent rather than a scope decision.
    """

    def test_the_proxy_envelope_serial_is_masked(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        payload = {
            "status": "success",
            "data": {
                "results": {"wan1": {"mac": "ac:71:2e:71:74:9e", "ip": "104.167.217.70"}},
                "serial": "FGT70FTK22019321",
                "version": "v7.4.12",
            },
        }

        out = masker.mask_result(payload)

        assert "FGT70FTK22019321" not in str(out)
        assert engine.unseal_serial(out["data"]["serial"]) == "FGT70FTK22019321"

    def test_the_version_beside_it_is_untouched(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"serial": "FGT70FTK22019321", "version": "v7.4.12"})
        assert out["version"] == "v7.4.12"


class TestRedactionDoesNotInventSecrets:
    """An unset field must not come back reading as a withheld credential.

    ``password`` is a broad key the review did not ask for, so it lands on
    shapes that hold no secret. Replacing an empty value with the constant
    tells the caller a credential was withheld where none existed.
    """

    @pytest.mark.parametrize("empty", ["", None, 0, [], {}])
    def test_an_empty_secret_field_is_left_as_it_is(self, masker: OutputMasker, empty: Any) -> None:
        assert masker.mask_result({"password": empty}) == {"password": empty}

    def test_a_real_secret_is_still_redacted(self, masker: OutputMasker) -> None:
        assert masker.mask_result({"password": "hunter2"}) == {"password": REDACTED}
        assert masker.mask_result({"adm_pass": ["enc", "enc"]}) == {"adm_pass": REDACTED}


class TestRedactedConstantIsRefusedMidString:
    """The whole-scalar tier was fixed; the embedded tier was not.

    ``tokens`` claims the constant is reserved so that a model echoing a
    masked device record into a write cannot set it as a real password.
    That held only when the constant was the entire argument. Embedded in
    script content or a JSON body it passed the guard, which is the shape
    the claim is actually about.
    """

    @pytest.mark.parametrize(
        "argument",
        [
            f'set passwd "{REDACTED}"',
            f'{{"name": "fgt-01", "adm_pass": "{REDACTED}"}}',
            f"prefix {REDACTED} suffix",
        ],
    )
    def test_the_constant_is_refused_inside_a_larger_string(
        self, engine: FPEEngine, argument: str
    ) -> None:
        pattern = strict_pattern(engine.str_alphabet, engine.mask_suffix)
        with pytest.raises(TokenInInput):
            guard_args({"content": argument}, pattern, engine.mask_suffix)

    def test_ordinary_text_still_passes(self, engine: FPEEngine) -> None:
        pattern = strict_pattern(engine.str_alphabet, engine.mask_suffix)
        guard_args({"content": "set comment 'masked secret withheld'"}, pattern, engine.mask_suffix)


class TestReviewCarriersThatHadNoTest:
    """Every review-sourced carrier, exercised.

    Eight entries were in the table with no test of any spelling, so
    deleting them kept the suite green. A carrier nobody asserts on is a
    carrier that can be dropped by a later edit without anything failing.
    """

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("ipunnumbered", "192.0.2.11"),
            ("dhcp-relay-source-ip", "192.0.2.12"),
            ("dhcp6-relay-ip", "2001:db8::12"),
            ("dhcp6-relay-source-ip", "2001:db8::13"),
            ("vrdst6", "2001:db8::14"),
            ("virtual-mac", "00:11:22:33:44:55"),
            ("sfp-dsl-mac", "00:11:22:33:44:56"),
            ("substitute-dst-mac", "00:11:22:33:44:57"),
        ],
    )
    def test_the_value_does_not_survive(self, masker: OutputMasker, key: str, value: str) -> None:
        out = masker.mask_result({"interface": [{key: value}]})
        assert value not in str(out)


class TestInterfaceAddressPairs:
    """``ip``, ``remote-ip`` and ``secondaryip[].ip`` carry a netmask.

    Measured by the maintainer on a live FortiGate device DB: all three
    come back as ``[address, netmask]``, for example
    ``["192.168.254.254", "255.255.255.0"]``. As plain IP carriers both
    elements masked, so the netmask became a random-looking address and
    the CIDR string form collapsed to a placeholder that lost the prefix.

    The subnet handler falls back to a plain IP when there is no
    separator, so it is a superset of the scalar route and the
    single-address case is unaffected.
    """

    def test_the_netmask_survives_the_pair_form(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"ip": ["192.168.254.254", "255.255.255.0"]})
        assert out["ip"][1] == "255.255.255.0"
        assert out["ip"][0] != "192.168.254.254"

    @pytest.mark.parametrize("key", ["ip", "remote-ip"])
    def test_both_pair_carriers_keep_their_mask(self, masker: OutputMasker, key: str) -> None:
        out = masker.mask_result({key: ["10.0.0.1", "255.255.255.0"]})
        assert out[key][1] == "255.255.255.0"
        assert "10.0.0.1" not in str(out)

    def test_the_cidr_string_keeps_its_prefix(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"ip": "192.168.254.254/24"})
        assert out["ip"].endswith("/24")
        assert not out["ip"].startswith(PLACEHOLDER_MARK)

    def test_a_bare_address_still_masks_as_one(
        self, masker: OutputMasker, engine: FPEEngine
    ) -> None:
        """The scalar case the device inventory uses must not regress."""
        out = masker.mask_result({"ip": "192.0.2.50"})
        assert engine.unmask_ip_token(out["ip"]) == "192.0.2.50"

    def test_the_nested_secondary_address_is_reached(self, masker: OutputMasker) -> None:
        payload = {"secondaryip": [{"ip": ["10.1.1.1", "255.255.255.0"], "id": 1}]}
        out = masker.mask_result(payload)
        entry = out["secondaryip"][0]
        assert "10.1.1.1" not in str(out)
        assert entry["ip"][1] == "255.255.255.0"
        assert entry["id"] == 1


class TestManagementAndTrustAddresses:
    """Populated on most gateways and had no carrier at all.

    Flagged in the round-3 review as still reaching the caller in clear.
    Routed through the subnet handler rather than the scalar one for the
    same reason the interface address pair is: FortiOS writes a trusted
    host as an address plus a mask, and the handler degrades to a plain
    IP when no mask is present, so it is safe either way.
    """

    @pytest.mark.parametrize("key", ["management-ip", "trust-ip-1", "trust-ip-2", "trust-ip-3"])
    def test_the_address_does_not_survive(self, masker: OutputMasker, key: str) -> None:
        out = masker.mask_result({"interface": [{key: "192.0.2.60"}]})
        assert "192.0.2.60" not in str(out)

    @pytest.mark.parametrize("key", ["management-ip", "trust-ip-1"])
    def test_the_pair_form_keeps_its_mask(self, masker: OutputMasker, key: str) -> None:
        out = masker.mask_result({key: ["192.0.2.60", "255.255.255.0"]})
        assert out[key][1] == "255.255.255.0"
        assert "192.0.2.60" not in str(out)


class TestHealthCheckRequestDomain:
    """The SD-WAN health check's own FQDN was the one left in clear.

    ``dns-request-domain`` sits beside fields that already mask, so it
    read as an oversight rather than a decision.
    """

    def test_the_probe_domain_is_masked(self, masker: OutputMasker) -> None:
        payload = {"health-check": [{"dns-request-domain": "probe.example.com"}]}
        assert "probe.example.com" not in str(masker.mask_result(payload))

    def test_a_wildcard_probe_domain_keeps_its_star(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"dns-request-domain": "*.example.com"})
        # Both halves matter: the star survives AND the domain is gone.
        # Asserting only the star passes on an unmasked value too.
        assert out["dns-request-domain"].startswith("*.")
        assert "example.com" not in out["dns-request-domain"]


class TestDeviceSecretsAreRedactedAsDefenceInDepth:
    """``private_key`` and ``psk`` on a dvmdb device record.

    The maintainer measured that a live FMG already returns
    ``private_key`` as ``******`` and ``psk`` empty, so neither is an
    active leak. Redacted anyway: the cost of a key that never carries a
    secret is nothing, and the reverse is a credential in clear if a
    future FortiManager version stops pre-masking them.
    """

    @pytest.mark.parametrize("key", ["private_key", "private-key", "psk"])
    def test_a_populated_device_secret_is_withheld(self, masker: OutputMasker, key: str) -> None:
        assert masker.mask_result({key: "s3cret"}) == {key: REDACTED}

    def test_the_empty_form_the_appliance_actually_returns_is_left_alone(
        self, masker: OutputMasker
    ) -> None:
        """FMG returns psk empty, so redacting it would invent a secret."""
        assert masker.mask_result({"psk": ""}) == {"psk": ""}


class TestPairSecondElementMustBeAMask:
    """Keeping element two in clear is only safe when it IS a mask.

    Moving ``ip`` and ``remote-ip`` onto the subnet handler is what makes
    this reachable. The handler assumed any two-element list was
    ``[network, netmask]`` and kept the second verbatim, so an
    address-plus-address pair published a real address that the previous
    scalar route had masked. Measured against the old route::

        {"ip": ["192.0.2.50", "192.0.2.51"]}
          old -> ["ip4-...", "ip4-..."]
          new -> ["ip4-...", "192.0.2.51"]

    The maintainer measured address-plus-netmask on his hardware, so this
    is not a shape anyone has seen on these keys. It is guarded anyway
    because the cost of being wrong is a leak, and the check is cheap: a
    mask is a contiguous run of bits from one end, an address is not.
    """

    def test_a_second_address_is_not_mistaken_for_a_mask(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"ip": ["192.0.2.50", "192.0.2.51"]})
        assert "192.0.2.51" not in str(out)
        assert "192.0.2.50" not in str(out)

    def test_the_space_separated_string_form_is_guarded_too(self, masker: OutputMasker) -> None:
        out = masker.mask_result({"ip": "192.0.2.50 192.0.2.51"})
        assert "192.0.2.51" not in str(out)

    @pytest.mark.parametrize(
        ("key", "pair", "kept"),
        [
            ("subnet", ["203.0.113.0", "255.255.255.0"], "255.255.255.0"),
            ("subnet", ["203.0.113.0", "255.255.0.0"], "255.255.0.0"),
            ("wildcard", ["203.0.113.0", "0.0.0.255"], "0.0.0.255"),
            ("ip", ["192.168.254.254", "255.255.255.0"], "255.255.255.0"),
            ("ip6-address", ["2001:db8::1", "64"], "64"),
        ],
    )
    def test_real_masks_are_still_kept(
        self, masker: OutputMasker, key: str, pair: list[str], kept: str
    ) -> None:
        """Netmask, hostmask and bare prefix length all stay in clear."""
        out = masker.mask_result({key: pair})
        assert out[key][1] == kept
        assert pair[0] not in str(out)
