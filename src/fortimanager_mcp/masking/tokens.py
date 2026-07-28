"""The reserved marker vocabulary: what counts as a masking token.

Recognition only. Nothing here decrypts, so it has no dependency on the
engine, the carrier table or the tool boundary, all three of which need
to ask "is this a token?" without importing each other.

FortiManager is a write surface: a tool argument becomes estate
configuration. Format-preserving encryption is a permutation with no
integrity tag, so any address-shaped ciphertext decrypts to *some* valid
address. Restoring one into a write would therefore turn a stale,
rotated or foreign token into a silently wrong configuration change.
This port never decrypts an argument; it refuses tokens on the way in
(``wrapper.guard_args``), and refusal only needs recognition.

Two tiers, because the two failure modes differ:

* **strict** matches a complete, well-formed emitted token at a lexical
  boundary *anywhere* in a string. A token pasted mid-sentence into a
  comment or into script content would otherwise be written verbatim
  into the estate.
* **loose** matches a whole scalar that merely carries a reserved
  marker, well formed or not. It catches truncated and corrupted tokens
  that strict matching would let through as ordinary text.

Together they leave ordinary values usable: a device genuinely named
``host-branch-01`` still passes as a substring of a longer argument, but
is refused as a whole argument value while masking is on. That is the
documented cost of FAZ's prefix markers, and it fails in the safe
direction.
"""

import re

#: Emitted in place of a value the ciphers cannot represent. Irreversible
#: by design, so it must never be accepted back as an input either.
PLACEHOLDER_MARK = "masked-unrepresentable-"

#: Prefix-marked token families. ``ip4``/``ip6``/``mac``/``sn`` are the
#: FortiManager envelopes; ``host``/``user``/``url`` are FortiAnalyzer's
#: own forms, included because a token carried over from the sibling MCP
#: must not be writable into FortiManager either.
PREFIX_MARKERS: tuple[str, ...] = (
    "ip4-",
    "ip6-",
    "mac-",
    "sn-",
    "url-",
    "host-",
    "user-",
    PLACEHOLDER_MARK,
)

_KID = "[0-9a-f]{4}"
_PREFIX_KINDS = "ip4|ip6|mac|sn|url|host|user"


def reserved_suffix(mask_suffix: str) -> str:
    """Dotted form of the engine's domain/email marker.

    The engine's default is ``masked.invalid``. Matching on that bare
    string would also flag the unrelated literal ``unmasked.invalid``,
    so the leading dot is part of the marker.
    """
    return "." + mask_suffix.lstrip(".")


def strict_pattern(payload_alphabet: str, mask_suffix: str) -> re.Pattern[str]:
    """Compile the complete-token pattern for one engine's alphabets.

    The payload class comes from the cipher itself rather than being
    written by hand: a hand-written class that omitted a character the
    cipher can emit (the string alphabet includes ``~``) would fail to
    recognize tokens this server produced.
    """
    payload = re.escape(payload_alphabet)
    suffix = re.escape(reserved_suffix(mask_suffix))
    prefixed = rf"(?:{_PREFIX_KINDS})-{_KID}-[{payload}]+"
    suffixed = rf"[{payload}]+\.{_KID}{suffix}"
    placeholder = rf"{re.escape(PLACEHOLDER_MARK)}[0-9a-f]+"
    # The boundary is alphanumeric-only: a token pasted after punctuation
    # ("see ip4-...", "note:ip4-...") must still match, while a genuine
    # word ending in the marker text ("myhost-...") must not.
    return re.compile(
        rf"(?<![A-Za-z0-9])(?:{prefixed}|{suffixed}|{placeholder})",
        re.IGNORECASE,
    )


def contains_token(value: str, pattern: re.Pattern[str]) -> bool:
    """True when a complete token appears anywhere in the string."""
    return bool(pattern.search(value))


def looks_token_shaped(value: str, mask_suffix: str) -> bool:
    """True when the whole scalar carries a reserved marker.

    Deliberately broader than ``contains_token``: a truncated or
    corrupted token is still an attempt to use a token as an input.
    """
    lowered = value.strip().lower()
    if lowered.startswith(PREFIX_MARKERS):
        return True
    return lowered.endswith(reserved_suffix(mask_suffix).lower())
