"""Which output keys carry maskable values, and which never mask.

Derivation is deliberate. The table is the union of a static pass over
every module in ``fortimanager_mcp/tools`` (each entry cites the file and
line that proves the key exists) and a read-only sweep of live
FortiManager 7.6.7 and 8.0.0 appliances (which catches keys that reach
the caller through raw API passthrough, where no literal appears in our
source). A key documented by one and absent from the other stays: the
sibling project shipped a coverage hole precisely by deleting carriers a
lab happened not to populate.

**Values mask, names never do.** Every FortiManager name is a routing
key: object, ADOM, package, VDOM, device, template and script names all
address later calls. Masking one would not obscure an identifier, it
would break every follow-up call that used it. This mirrors the
maintainer's own reasoning for leaving the FortiAnalyzer ``adom`` field
clear (sibling issue #80).

Out of scope for this version, each with a reason rather than an
oversight:

- Free text (``comment``, ``comments``, ``description``). Masking prose
  would put tokens into text an operator later edits and writes back,
  persisting pseudonyms into estate configuration. The sibling reached
  the same conclusion for its own mutable-text surfaces.
- Script content, install previews and task detail. These carry whole CLI
  configurations, so they can hold addresses, but they are documents
  rather than query results: the sibling excludes rendered report
  artifacts on the same grounds. Tokenizing them symmetrically is real
  design work, not a table entry.
- Object and policy names that embed an address (``srv-192.0.2.10``).
  Names route calls, see above.
- Device coordinates (``latitude``/``longitude`` on dvmdb records).
  Floats, so no format-preserving cipher covers them; masking would mean
  an irreversible placeholder on a value the issue #34 scope never
  claimed. Estate-location privacy is worth raising on the RFC, not
  smuggling into this table.

One consequence worth naming: ``get_device_client_location`` (upstream
#43) filters by ``ip``/``mac``/``hostname``, the first FortiManager
reader that accepts terminal values. With masking on, a masked client IP
cannot be pasted back into it; the guard refuses tokens everywhere, so
the caller must use a literal address. Restoring tokens for read-only
tools like this one is exactly what the authenticated v2 format on the
sibling RFC #40 would enable safely.
"""

# Value-type tags. The wrapper maps each to a cipher; the guard maps the
# emitted token forms back to "this is a token, refuse it".
IP = "ip"
MAC = "mac"
HOSTNAME = "hostname"
USERNAME = "username"
DOMAIN = "domain"
EMAIL = "email"
SERIAL = "serial"
#: Holds either an address or a name depending on the record; masked as
#: whichever it parses as.
IP_OR_HOST = "ip_or_host"


def canonical_key(key: str) -> str:
    """Lookup form for a field name.

    FortiManager spells the same field three ways depending on the
    surface: ``start-ip`` in the API, ``start_ip`` in tool arguments, and
    occasionally a spaced, title-cased form in reshaped output. One
    canonical form means one table entry instead of three.
    """
    return key.strip().lower().replace(" ", "_").replace("-", "_")


#: Output keys whose values mask, keyed by canonical form. Every entry
#: cites the evidence that the key exists; a key nobody could evidence is
#: not listed, because masking a field FortiManager never emits is a
#: silent no-op that reads like coverage.
FIELD_TYPES: dict[str, str] = {
    # Device inventory. dvmdb records reach the caller both reshaped and
    # as raw passthrough, so both spellings matter.
    "ip": IP,  # static: dvm_tools.py:313 (add_device device_config)
    "sn": SERIAL,  # static: dvm_tools.py:321
    "adm_usr": USERNAME,  # static: dvm_tools.py:315
    # System status arrives with spaced, title-cased keys, which
    # canonical_key folds onto these entries: "Serial Number" and
    # "Hostname" both observed live on 7.6.7 (get_system_status).
    "serial_number": SERIAL,  # live: 7.6.7 get_system_status "Serial Number"
    "hostname": HOSTNAME,  # live: 7.6.7 get_system_status "Hostname"
    # Address objects.
    "start_ip": IP,  # live: 8.0.0 list_addresses "start-ip"
    "end_ip": IP,  # live: 8.0.0 list_addresses "end-ip"
    # SD-WAN device-DB reads (upstream #40/#43, merged 2026-07-31).
    "gateway": IP,  # static: sdwan_tools.py:117 (member gateway)
    "server": IP_OR_HOST,  # static: sdwan_tools.py:128 (health-check target,
    # an IP or a hostname depending on the deployment)
    # Detected-client records (get_device_client_location, upstream #43).
    "mac": MAC,  # static: dvm_tools.py:931 (_summarize_detected_client)
    # ---------------------------------------------------------------- #
    # Carriers added from the PR #39 review. The maintainer probed
    # ``system/sdwan``, ``system/interface``, ``firewall/address`` and
    # ``firewall/service/custom`` against live 7.6.7 and 8.0.0
    # FortiManagers and found these returned in clear. They reach the
    # caller through raw API passthrough, so no literal appears in our
    # source and neither of our labs can populate them (both hold zero
    # managed devices), which is exactly the passthrough case the module
    # docstring says a single-source citation covers.
    # ---------------------------------------------------------------- #
    # SD-WAN (system/sdwan, returned raw beside the summary).
    "source": IP,  # review: members[].source, health-check[].source
    "source6": IP,  # review: SD-WAN IPv6 source
    "gateway6": IP,  # review: SD-WAN IPv6 gateway
    "preferred_source": IP,  # review: members[].preferred-source
    "dns_match_ip": IP,  # review: health-check[].dns-match-ip
    # Interface (system/interface). IPv4 variants; the v6 address keys are
    # composites below, because they carry a prefix.
    "gateway_address": IP,  # review
    "remote_ip": IP,  # review
    "ipunnumbered": IP,  # review
    "dhcp_relay_ip": IP,  # review
    "dhcp_relay_source_ip": IP,  # review
    "dhcp6_relay_ip": IP,  # review
    "dhcp6_relay_source_ip": IP,  # review
    "server_ip": IP,  # review: dhcp-snooping-server-list[].server-ip
    "secip_relay_ip": IP,  # review: secondaryip[].secip-relay-ip
    "vrip": IP,  # review: vrrp[].vrip
    "vrdst": IP,  # review: vrrp[].vrdst
    "vrip6": IP,  # review: vrrp6[].vrip6
    "vrdst6": IP,  # review: vrrp6[].vrdst6
    # The interface MAC is a different key from the ``mac`` above.
    "macaddr": MAC,  # review: system/interface macaddr, firewall/address
    "start_mac": MAC,  # review: MAC-type address, also dynamic_mapping[]
    "end_mac": MAC,  # review: MAC-type address, also dynamic_mapping[]
    # Named in the review's suggested list but NOT in its confirmed-leak
    # section, so they are schema attributes of system/interface rather
    # than observed output. Kept on the same reasoning as the wildcard
    # entry below: a surplus carrier is a no-op, a missing one leaks.
    "virtual_mac": MAC,  # review, suggested only: not individually observed
    "sfp_dsl_mac": MAC,  # review, suggested only: not individually observed
    "substitute_dst_mac": MAC,  # review, suggested only: not individually observed
}

#: Subnet-shaped keys. FortiManager returns these as a two-element
#: [network, netmask] list on address objects (observed live on 8.0.0:
#: ["169.254.169.254", "255.255.255.255"]) and as a "net/prefix" or
#: "net mask" string elsewhere. Only the network part is an identifier.
#:
#: The IPv6 keys are here rather than in FIELD_TYPES, which is a
#: deliberate departure from the PR #39 review's suggestion of
#: ``ip6_address`` as a plain IP carrier. ``ip6-address`` carries its
#: prefix (``2001:db8::1/64``), and a plain IP carrier cannot parse that:
#: it fails closed into an irreversible placeholder, so the caller loses
#: the address AND the prefix. This handler already falls through to a
#: plain IP when there is no separator, so it is a superset of the scalar
#: route for both spellings.
COMPOSITE_SUBNET: tuple[str, ...] = (
    "subnet",  # static: object_tools.py:257
    "ip6_address",  # review: ipv6.ip6-address, prefix-bearing
    "ip6_subnet",  # review: ipv6.ip6-subnet
)
#: The review also asked for "the IPv6 prefix keys" without naming them.
#: They are not guessed at here: an invented key name is an entry that
#: reads like coverage and masks nothing. Asked on the PR instead.

#: Wildcard ADDRESS: an IP plus a wildcard mask, which FortiManager
#: returns under this key on a ``type=wildcard`` address object. Distinct
#: from a wildcard FQDN despite the shared word.
#:
#: Weakest entry in this table, and labelled as such on purpose. Neither
#: lab holds a wildcard address object, and this repo cannot create one
#: (the create_address_* tools cover subnet, host, fqdn and range only),
#: so there is no live observation and no output-key literal in our
#: source to cite. The word does appear in ``policy_tools`` and
#: ``validation``, but only as a category label and an address-type
#: filter value, neither of which evidences an output key.
#:
#: Kept anyway because the field carries an address wherever it does
#: exist, and a missing carrier leaks while a surplus one is only a
#: no-op. Worth confirming against a real wildcard object before relying
#: on it.
COMPOSITE_WILDCARD_IP: tuple[str, ...] = ("wildcard",)  # unverified, see above

#: DNS names. Handled as a composite rather than a plain DOMAIN carrier
#: because FortiManager puts wildcard FQDNs in the SAME key: 8.0.0
#: list_addresses returns {"fqdn": "*.google.com"} alongside
#: {"fqdn": "gmail.com"}. The star is outside every cipher alphabet, so
#: masking the raw value would burn a wildcard entry to an irreversible
#: placeholder. The composite keeps the label and masks the domain.
#: ``wildcard-fqdn`` is a third FQDN key beside ``fqdn`` and ``wildcard``
#: (PR #39 review). It takes the same handler because its whole point is
#: the star that the handler exists to preserve.
COMPOSITE_FQDN: tuple[str, ...] = (
    "fqdn",  # live: 8.0.0 list_addresses
    "wildcard_fqdn",  # review: firewall/address wildcard-fqdn
)

#: Start-end address ranges. ``firewall/service/custom`` returns
#: ``iprange`` holding either a single address or a ``start-end`` pair
#: (``192.0.2.1-192.0.2.10``). A plain IP carrier fails the pair closed on
#: the hyphen, so both sides mask through their own handler.
#:
#: Confirmed live on 7.6.7 (list_services, every stock service carries
#: ``iprange``), though every stock value is the unset ``0.0.0.0`` that
#: SKIP_VALUES already passes through; the pair spelling is the review's
#: live observation.
COMPOSITE_RANGE: tuple[str, ...] = ("iprange",)  # live: 7.6.7 list_services

#: Keys whose value is a secret, not an identifier. These are replaced by
#: a fixed constant, never tokenised: a token is reversible by design and
#: correlatable across calls, which is the opposite of what a credential
#: needs. Checked before every other rule in the walk.
#:
#: ``adm_pass`` is the device manager password on a dvmdb device record
#: (PR #39 review). It is worth knowing WHY it reaches the caller at all:
#: ``get_device_status`` asks for an explicit ``fields`` list that does
#: not include it, but FortiManager treats ``fields`` as a hint rather
#: than a bound. Measured on 7.6.7: ``list_adoms(fields=["name"])``
#: returns ``name`` AND ``oid``, and the client passes ``fields`` through
#: untouched (api/client.py:691-697). ``list_devices`` and ``get_device``
#: request no field list at all, so they carry the whole record.
#:
#: Both spellings, because the repo's own credential strip on the write
#: paths lists both (dvm_tools.py:344 in add_device, :546 in
#: add_devices_bulk). That strip covers only those two echo paths; no
#: read path has one, which is why the field reaches a caller at all.
#:
#: ``password`` is here on direction rather than on an observation. Two
#: raw-passthrough surfaces can carry one: an SD-WAN health check with an
#: HTTP probe, and a PPPoE interface. Neither lab can populate them, so
#: this is not claimed as measured. Redacting a key that turns out never
#: to appear costs nothing; the reverse is a credential in clear.
#:
#: Deliberately NOT ``username``. A PPPoE account is an identifier and
#: belongs in FIELD_TYPES rather than here, but the name is far too
#: common to mask at any depth without parent-key scoping the walk does
#: not have. Raised on the PR instead of guessed at.
REDACT_KEYS: frozenset[str] = frozenset({"adm_pass", "adm_passwd", "password"})

#: Values that are structural rather than identifying. Masking these
#: would destroy meaning ("any" is not an address) for zero privacy gain.
SKIP_VALUES: frozenset[str] = frozenset(
    {
        "",
        # Not a bind address: these are the wildcard values FortiManager
        # ships on stock objects, which mask to nothing meaningful.
        "0.0.0.0",  # nosec B104
        "0.0.0.0/0",
        "0.0.0.0 0.0.0.0",
        "255.255.255.255",
        "::",
        # The unset MAC. It only starts mattering with the interface MAC
        # carriers above: an appliance ships it on every port that has no
        # hardware address, so without this every such port would carry a
        # token standing for nothing. Observed live on a 7.4.12 FortiGate
        # (the modem interface).
        "00:00:00:00:00:00",
        "n/a",
        "-",
        "any",
        "all",
    }
)

#: Routing keys. Documentation and a test guard, never masked.
ROUTING_KEYS_NEVER_MASK: frozenset[str] = frozenset(
    {
        "name",
        "adom",
        "package",
        "pkg",
        "vdom",
        "device",
        "devname",
        "template",
        "script",
        "policyid",
        "obj",
        "folder",
        "tool_name",
        "operation",
    }
)
