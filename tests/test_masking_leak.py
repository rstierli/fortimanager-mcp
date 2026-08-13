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
from fortimanager_mcp.masking.tokens import REDACTED
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

# Surfaces the PR #39 review probed against live 7.6.7 and 8.0.0
# FortiManagers and found returning identifiers in clear. Each record
# nests the carrier the way the raw API object does, because the walk
# reaching a key is a separate question from the key being in the table:
# a carrier that only works at the top level is a carrier that does not
# work, and every one of these arrives inside a list of dicts.
SDWAN_SOURCE = "203.0.113.11"
SDWAN_HC_SOURCE = "203.0.113.12"
SDWAN_PREFERRED = "203.0.113.13"
SDWAN_DNS_MATCH = "198.51.100.60"
SDWAN_SOURCE6 = "2001:db8:1::11"
SDWAN_GATEWAY6 = "2001:db8:1::1"

SDWAN_RAW_RECORD: dict[str, Any] = {
    "status": "success",
    "device": DEVICE_NAME,
    # _summarize_sdwan drops these, but the raw object is returned next
    # to the summary, so they still reach the caller.
    "raw": {
        "members": [
            {
                "seq-num": 1,
                "interface": "port1",
                "source": SDWAN_SOURCE,
                "source6": SDWAN_SOURCE6,
                "gateway6": SDWAN_GATEWAY6,
                "preferred-source": SDWAN_PREFERRED,
            }
        ],
        "health-check": [
            {
                "name": "default-dns",
                "source": SDWAN_HC_SOURCE,
                "dns-match-ip": SDWAN_DNS_MATCH,
                "members": [1],
            }
        ],
    },
}

IFACE_MACADDR = "00:00:5e:00:53:01"
IFACE_V6_ADDR = "2001:db8:2::1"
IFACE_GATEWAY_ADDRESS = "192.0.2.201"
IFACE_REMOTE_IP = "192.0.2.202"
IFACE_DHCP_RELAY = "192.0.2.203"
IFACE_SNOOP_SERVER = "192.0.2.204"
IFACE_SECIP_RELAY = "192.0.2.205"
IFACE_VRIP = "192.0.2.206"
IFACE_VRDST = "192.0.2.207"
IFACE_VRIP6 = "2001:db8:2::6"

INTERFACE_RECORD: dict[str, Any] = {
    "status": "success",
    "device": DEVICE_NAME,
    "interfaces": [
        {
            "name": "port1",
            "vdom": "root",
            "macaddr": IFACE_MACADDR,
            "gateway-address": IFACE_GATEWAY_ADDRESS,
            "remote-ip": IFACE_REMOTE_IP,
            "dhcp-relay-ip": IFACE_DHCP_RELAY,
            "ipv6": {
                "ip6-address": f"{IFACE_V6_ADDR}/64",
                "vrrp6": [{"vrid": 1, "vrip6": IFACE_VRIP6}],
            },
            "dhcp-snooping-server-list": [{"name": "srv1", "server-ip": IFACE_SNOOP_SERVER}],
            "secondaryip": [{"id": 1, "secip-relay-ip": IFACE_SECIP_RELAY}],
            "vrrp": [{"vrid": 1, "vrip": IFACE_VRIP, "vrdst": IFACE_VRDST}],
        }
    ],
}

MAC_ADDR_START = "00:00:5e:00:53:10"
MAC_ADDR_END = "00:00:5e:00:53:20"
MAC_ADDR_SINGLE = "00:00:5e:00:53:30"
MAC_ADDR_DYNAMIC = "00:00:5e:00:53:40"
WILDCARD_FQDN_TAIL = "example.org"

MAC_ADDRESS_RECORDS: dict[str, Any] = {
    "status": "success",
    "addresses": [
        {
            "name": "mac-lab-printer",
            "type": 5,
            "macaddr": MAC_ADDR_SINGLE,
            "start-mac": MAC_ADDR_START,
            "end-mac": MAC_ADDR_END,
            "dynamic_mapping": [
                {"scope": [{"name": DEVICE_NAME, "vdom": "root"}], "start-mac": MAC_ADDR_DYNAMIC}
            ],
        },
        {"name": "partner-wildcard", "type": 2, "wildcard-fqdn": f"*.{WILDCARD_FQDN_TAIL}"},
    ],
}

SERVICE_RANGE_START = "198.51.100.10"
SERVICE_RANGE_END = "198.51.100.20"

SERVICE_RECORDS: dict[str, Any] = {
    "status": "success",
    "services": [
        {
            "name": "restricted-http",
            "protocol": 15,
            "iprange": f"{SERVICE_RANGE_START}-{SERVICE_RANGE_END}",
        },
        # Every stock service carries the unset form (measured on 7.6.7).
        {"name": "HTTPS", "protocol": 15, "iprange": "0.0.0.0"},
    ],
}

DEVICE_PASSWORD = "not-a-real-password"

DEVICE_STATUS_RECORD: dict[str, Any] = {
    "status": "success",
    "devices": [
        {
            "name": DEVICE_NAME,
            "ip": DEVICE_IP,
            "adm_usr": DEVICE_ADMIN,
            "adm_pass": [DEVICE_PASSWORD],
            "conn_status": 1,
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
            (
                "SDWAN_RAW_RECORD",
                [
                    SDWAN_SOURCE,
                    SDWAN_HC_SOURCE,
                    SDWAN_PREFERRED,
                    SDWAN_DNS_MATCH,
                    SDWAN_SOURCE6,
                    SDWAN_GATEWAY6,
                ],
            ),
            (
                "INTERFACE_RECORD",
                [
                    IFACE_MACADDR,
                    IFACE_V6_ADDR,
                    IFACE_GATEWAY_ADDRESS,
                    IFACE_REMOTE_IP,
                    IFACE_DHCP_RELAY,
                    IFACE_SNOOP_SERVER,
                    IFACE_SECIP_RELAY,
                    IFACE_VRIP,
                    IFACE_VRDST,
                    IFACE_VRIP6,
                ],
            ),
            (
                "MAC_ADDRESS_RECORDS",
                [
                    MAC_ADDR_SINGLE,
                    MAC_ADDR_START,
                    MAC_ADDR_END,
                    MAC_ADDR_DYNAMIC,
                    WILDCARD_FQDN_TAIL,
                ],
            ),
            ("SERVICE_RECORDS", [SERVICE_RANGE_START, SERVICE_RANGE_END]),
            ("DEVICE_STATUS_RECORD", [DEVICE_PASSWORD]),
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

    def test_sdwan_raw_values_come_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        raw = masker.mask_result(SDWAN_RAW_RECORD)["raw"]
        member, check = raw["members"][0], raw["health-check"][0]

        assert engine.unmask_ip_token(member["source"]) == SDWAN_SOURCE
        assert engine.unmask_ip_token(member["source6"]) == SDWAN_SOURCE6
        assert engine.unmask_ip_token(member["gateway6"]) == SDWAN_GATEWAY6
        assert engine.unmask_ip_token(member["preferred-source"]) == SDWAN_PREFERRED
        assert engine.unmask_ip_token(check["source"]) == SDWAN_HC_SOURCE
        assert engine.unmask_ip_token(check["dns-match-ip"]) == SDWAN_DNS_MATCH
        assert member["interface"] == "port1"

    def test_interface_values_come_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        iface = masker.mask_result(INTERFACE_RECORD)["interfaces"][0]

        assert engine.unmask_mac_token(iface["macaddr"]) == IFACE_MACADDR
        assert engine.unmask_ip_token(iface["gateway-address"]) == IFACE_GATEWAY_ADDRESS
        assert engine.unmask_ip_token(iface["vrrp"][0]["vrip"]) == IFACE_VRIP
        assert (
            engine.unmask_ip_token(iface["secondaryip"][0]["secip-relay-ip"]) == IFACE_SECIP_RELAY
        )
        assert (
            engine.unmask_ip_token(iface["dhcp-snooping-server-list"][0]["server-ip"])
            == IFACE_SNOOP_SERVER
        )
        assert engine.unmask_ip_token(iface["ipv6"]["vrrp6"][0]["vrip6"]) == IFACE_VRIP6
        # The prefix is not an identifier, so it survives beside the token.
        v6 = iface["ipv6"]["ip6-address"]
        assert v6.endswith("/64")
        assert engine.unmask_ip_token(v6[: -len("/64")]) == IFACE_V6_ADDR
        assert iface["name"] == "port1"

    def test_mac_address_values_come_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        addresses = masker.mask_result(MAC_ADDRESS_RECORDS)["addresses"]
        mac_object, wildcard = addresses

        assert engine.unmask_mac_token(mac_object["macaddr"]) == MAC_ADDR_SINGLE
        assert engine.unmask_mac_token(mac_object["start-mac"]) == MAC_ADDR_START
        assert engine.unmask_mac_token(mac_object["end-mac"]) == MAC_ADDR_END
        # dynamic_mapping is where a per-device override hides; it is
        # reached by the walk, not by a table entry of its own.
        nested = mac_object["dynamic_mapping"][0]
        assert engine.unmask_mac_token(nested["start-mac"]) == MAC_ADDR_DYNAMIC
        assert nested["scope"][0]["name"] == DEVICE_NAME
        assert wildcard["wildcard-fqdn"].startswith("*.")
        assert engine.unmask_domain(wildcard["wildcard-fqdn"][2:]) == WILDCARD_FQDN_TAIL

    def test_service_range_comes_back(self, masker: OutputMasker) -> None:
        engine = FPEEngine(KEY)
        services = masker.mask_result(SERVICE_RECORDS)["services"]

        parts = services[0]["iprange"].split("-")
        assert len(parts) == 6
        assert engine.unmask_ip_token("-".join(parts[:3])) == SERVICE_RANGE_START
        assert engine.unmask_ip_token("-".join(parts[3:])) == SERVICE_RANGE_END
        # The unset form is structural, not an address.
        assert services[1]["iprange"] == "0.0.0.0"


class TestSecretsDoNotRoundTrip:
    """The one masked field that must NOT be reversible.

    Every other carrier is a token on purpose: an operator resolves it
    later. A password is the opposite requirement, so it is asserted
    separately rather than folded into the round-trip class above.
    """

    def test_the_password_is_gone_and_not_recoverable(self, masker: OutputMasker) -> None:
        device = masker.mask_result(DEVICE_STATUS_RECORD)["devices"][0]

        assert device["adm_pass"] == REDACTED
        assert DEVICE_PASSWORD not in json.dumps(device)
        # The rest of the record still masks normally.
        assert FPEEngine(KEY).unmask_ip_token(device["ip"]) == DEVICE_IP
        assert device["name"] == DEVICE_NAME


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
