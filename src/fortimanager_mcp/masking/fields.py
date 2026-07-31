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
}

#: Subnet-shaped keys. FortiManager returns these as a two-element
#: [network, netmask] list on address objects (observed live on 8.0.0:
#: ["169.254.169.254", "255.255.255.255"]) and as a "net/prefix" or
#: "net mask" string elsewhere. Only the network part is an identifier.
COMPOSITE_SUBNET: tuple[str, ...] = ("subnet",)  # static: object_tools.py:257

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
COMPOSITE_FQDN: tuple[str, ...] = ("fqdn",)  # live: 8.0.0 list_addresses

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
