"""Adversarial leak tests: does anything survive masking that should not?

The other masking tests ask whether allowlisted fields get masked. That
is the easy question, and answering only it is how the sibling project
shipped a coverage hole with a green suite: a record carries identifiers
under keys the table never mentioned.

The question here is the adversarial one. Take a whole record, mask it,
then look for the original values anywhere in the output. Masked IPs are
valid IPs and masked domains are plausible domains, so scanning for
"looks like an address" proves nothing; only identity comparison does.
Each record also asserts the reverse, that intentionally clear values are
still present, so "names stay clear" cannot silently rot into "names get
masked too".

Record shapes are taken from live FortiManager 7.6.7 and 8.0.0 responses
(read-only sweep for issue #34). Every value is replaced with a
documentation value (RFC 5737, RFC 2606); no value from any real estate
appears here.
"""

import json
from typing import Any

import pytest

from fortimanager_mcp.masking.fpe_engine import FPEEngine
from fortimanager_mcp.masking.wrapper import OutputMasker

KEY = "2DE79D232DF5585D68CE47882AE256D6"

# Identifiers that must not survive masking.
DEVICE_IP = "192.0.2.19"
DEVICE_SERIAL = "FGVM020000123456"
DEVICE_ADMIN = "netadmin"
FMG_SERIAL = "FMG-VM0000000001"
FMG_HOSTNAME = "fmg-lab-01"
SUBNET_NET = "203.0.113.0"
RANGE_START = "198.51.100.200"
RANGE_END = "198.51.100.210"
FQDN_VALUE = "mail.example.com"
WILDCARD_TAIL = "example.net"

# Values that must stay readable: every one routes a later call.
DEVICE_NAME = "fgt-branch-01"
ADOM_NAME = "root"
OBJECT_NAME = "srv-web-dmz"
PACKAGE_NAME = "Corporate"
NETMASK = "255.255.255.0"


@pytest.fixture()
def masker(monkeypatch: pytest.MonkeyPatch) -> OutputMasker:
    monkeypatch.setenv("FMG_MASKING_KEY", KEY)
    return OutputMasker(FPEEngine(KEY))


DEVICE_RECORD: dict[str, Any] = {
    "status": "success",
    "device": {
        "name": DEVICE_NAME,
        "ip": DEVICE_IP,
        "sn": DEVICE_SERIAL,
        "adm_usr": DEVICE_ADMIN,
        "os_ver": "7.6",
        "platform_str": "FortiGate-VM64-KVM",
        "conn_status": 1,
        "vdom": [{"name": "root", "opmode": 1}],
    },
    "adom": ADOM_NAME,
}

SYSTEM_STATUS_RECORD: dict[str, Any] = {
    "status": "success",
    "data": {
        "Hostname": FMG_HOSTNAME,
        "Serial Number": FMG_SERIAL,
        "Version": "v7.6.7-build3737 260601 (GA.M)",
        "Platform Full Name": "FortiManager-VM64-KVM",
        "HA Mode": "Stand Alone",
        "Admin Domain Configuration": "Disabled",
    },
}

ADDRESS_RECORDS: dict[str, Any] = {
    "status": "success",
    "count": 4,
    "addresses": [
        {
            "name": OBJECT_NAME,
            "subnet": [SUBNET_NET, NETMASK],
            "type": 0,
            "associated-interface": ["any"],
            "comment": "web tier",
            "uuid": "200ac246-66a5-51f1-fcb9-4e7ebd5398d7",
        },
        {
            "name": "vpn-pool",
            "type": 1,
            "start-ip": RANGE_START,
            "end-ip": RANGE_END,
        },
        {"name": "mail-host", "type": 2, "fqdn": FQDN_VALUE, "cache-ttl": 0},
        {"name": "wildcard-partner", "type": 2, "fqdn": f"*.{WILDCARD_TAIL}"},
    ],
}

# Shapes from the SD-WAN and client-location tools added upstream on
# 07-31 (#40/#43): member gateways, health-check targets, detected-client
# records. The carrier table grew with the tool surface; these pin it.
SDWAN_GATEWAY = "203.0.113.254"
HEALTH_SERVER = "198.51.100.53"
CLIENT_IP = "192.0.2.77"
CLIENT_MAC = "00:11:22:aa:bb:cc"
CLIENT_HOSTNAME = "laptop-eng-07"

SDWAN_RECORD: dict[str, Any] = {
    "status": "success",
    "device": DEVICE_NAME,
    "members": [{"name": "wan1", "interface": "port1", "gateway": SDWAN_GATEWAY, "status": "up"}],
    "health_checks": [{"name": "default-dns", "server": HEALTH_SERVER, "members": ["wan1"]}],
}

CLIENT_LOCATION_RECORD: dict[str, Any] = {
    "status": "success",
    "device": DEVICE_NAME,
    "clients": [
        {
            "hostname": CLIENT_HOSTNAME,
            "ip": CLIENT_IP,
            "mac": CLIENT_MAC,
            "vendor": "ExampleCorp",
            "is_online": True,
            "detected_interface": "port3",
            "fortiswitch_port": "port12",
            "vlan_id": 20,
        }
    ],
}

POLICY_RECORD: dict[str, Any] = {
    "status": "success",
    "package": PACKAGE_NAME,
    "policies": [
        {
            "policyid": 1,
            "name": "allow-web",
            "srcaddr": [OBJECT_NAME],
            "dstaddr": ["all"],
            "service": ["HTTPS"],
            "action": 1,
            "status": 1,
        }
    ],
}


def masked_text(masker: OutputMasker, record: dict[str, Any]) -> str:
    return json.dumps(masker.mask_result(record))


class TestNothingLeaks:
    @pytest.mark.parametrize(
        ("record_name", "secrets"),
        [
            ("DEVICE_RECORD", [DEVICE_IP, DEVICE_SERIAL, DEVICE_ADMIN]),
            ("SYSTEM_STATUS_RECORD", [FMG_SERIAL, FMG_HOSTNAME]),
            (
                "ADDRESS_RECORDS",
                [SUBNET_NET, RANGE_START, RANGE_END, FQDN_VALUE, WILDCARD_TAIL],
            ),
            ("SDWAN_RECORD", [SDWAN_GATEWAY, HEALTH_SERVER]),
            ("CLIENT_LOCATION_RECORD", [CLIENT_IP, CLIENT_MAC, CLIENT_HOSTNAME]),
        ],
    )
    def test_no_identifier_survives(
        self, masker: OutputMasker, record_name: str, secrets: list[str]
    ) -> None:
        record = globals()[record_name]
        out = masked_text(masker, record).lower()

        for secret in secrets:
            assert secret.lower() not in out, f"{secret} survived masking in {record_name}"

    def test_serial_does_not_survive_in_any_casing(self, masker: OutputMasker) -> None:
        """Serials are sealed, so neither the exact nor a folded form appears."""
        out = masked_text(masker, DEVICE_RECORD)

        assert DEVICE_SERIAL not in out
        assert DEVICE_SERIAL.lower() not in out.lower()


class TestClearValuesStayClear:
    def test_device_record_keeps_its_routing_values(self, masker: OutputMasker) -> None:
        out = masked_text(masker, DEVICE_RECORD)

        for clear in (DEVICE_NAME, ADOM_NAME, "FortiGate-VM64-KVM", "7.6"):
            assert clear in out, f"{clear} should not have been masked"

    def test_address_records_keep_names_and_netmasks(self, masker: OutputMasker) -> None:
        out = masked_text(masker, ADDRESS_RECORDS)

        for clear in (OBJECT_NAME, "vpn-pool", "mail-host", "wildcard-partner", NETMASK):
            assert clear in out, f"{clear} should not have been masked"

    def test_policy_record_is_untouched(self, masker: OutputMasker) -> None:
        """Policies reference objects by name, so nothing in one masks."""
        assert masker.mask_result(POLICY_RECORD) == POLICY_RECORD

    def test_system_status_keeps_version_and_platform(self, masker: OutputMasker) -> None:
        out = masked_text(masker, SYSTEM_STATUS_RECORD)

        assert "v7.6.7-build3737" in out
        assert "FortiManager-VM64-KVM" in out


class TestMaskedValuesRoundTrip:
    """Masking is only useful if an operator can still resolve a token."""

    def test_device_values_come_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        device = masker.mask_result(DEVICE_RECORD)["device"]

        assert engine.unmask_ip_token(device["ip"]) == DEVICE_IP
        assert engine.unseal_serial(device["sn"]) == DEVICE_SERIAL
        assert engine.unmask_username(device["adm_usr"]) == DEVICE_ADMIN

    def test_address_values_come_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        addresses = masker.mask_result(ADDRESS_RECORDS)["addresses"]

        assert engine.unmask_ip_token(addresses[0]["subnet"][0]) == SUBNET_NET
        assert addresses[0]["subnet"][1] == NETMASK
        assert engine.unmask_ip_token(addresses[1]["start-ip"]) == RANGE_START
        assert engine.unmask_ip_token(addresses[1]["end-ip"]) == RANGE_END
        assert engine.unmask_domain(addresses[2]["fqdn"]) == FQDN_VALUE
        assert engine.unmask_domain(addresses[3]["fqdn"][2:]) == WILDCARD_TAIL

    def test_wildcard_label_survives_the_round_trip(self, masker: OutputMasker) -> None:
        addresses = masker.mask_result(ADDRESS_RECORDS)["addresses"]
        assert addresses[3]["fqdn"].startswith("*.")

    def test_sdwan_values_come_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        out = masker.mask_result(SDWAN_RECORD)

        assert engine.unmask_ip_token(out["members"][0]["gateway"]) == SDWAN_GATEWAY
        assert engine.unmask_ip_token(out["health_checks"][0]["server"]) == HEALTH_SERVER
        assert out["members"][0]["interface"] == "port1"
        assert out["health_checks"][0]["members"] == ["wan1"]

    def test_client_location_values_come_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        client = masker.mask_result(CLIENT_LOCATION_RECORD)["clients"][0]

        assert engine.unmask_ip_token(client["ip"]) == CLIENT_IP
        assert engine.unmask_mac_token(client["mac"]) == CLIENT_MAC
        assert engine.unmask_hostname(client["hostname"]) == CLIENT_HOSTNAME
        assert client["detected_interface"] == "port3"
        assert client["vlan_id"] == 20


class TestKnownCarveOuts:
    """Documented gaps, asserted so a future change has to face them."""

    def test_comments_are_not_masked(self, masker: OutputMasker) -> None:
        """Free text stays clear: masked prose gets edited and written back."""
        record = {"name": "x", "comment": f"replaces {DEVICE_IP} next week"}

        out = masker.mask_result(record)

        assert out["comment"] == record["comment"]

    def test_names_embedding_an_address_stay_clear(self, masker: OutputMasker) -> None:
        """A name routes later calls, even one that spells out an address."""
        record = {"name": f"srv-{DEVICE_IP}", "ip": DEVICE_IP}

        out = masker.mask_result(record)

        assert out["name"] == f"srv-{DEVICE_IP}"
        assert out["ip"] != DEVICE_IP
