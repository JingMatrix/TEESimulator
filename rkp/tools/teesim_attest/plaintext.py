"""Parsers for the two secure-world keybox container formats seen in the field.

Both are length-prefixed binary, not XML, and both have the same trap: slicing at fixed
offsets appears to work and produces DER fragments that look legitimate. Certificate lengths
change between versions, chain lengths change, and the tail of the buffer can retain
uncopied input. The rule the field records settled on, and the rule this module implements:

  1. read the length prefix
  2. check enough buffer remains
  3. check the DER object's leading byte *and its own internal length*
  4. only then accept the prefix

Step 3 is what makes this safe. A length prefix is accepted only when the bytes it points at
parse as a DER SEQUENCE whose internal length agrees with it, so a wrong interpretation is
rejected rather than silently yielding plausible garbage.

The integer width and endianness of the prefixes are not documented for either format, so
they are detected once from the first field and then held fixed for the whole buffer -- a
format that switched width mid-buffer would be rejected, which is the right outcome.

Two formats:

`parse_lengthprefixed` -- the plaintext a KeyMint trustlet decrypts internally:
    version/keybox number, then per algorithm a private-key DER and a certificate count
    followed by that many certificates. Measured on one device as version 1, EC DER 138 B,
    3 EC certificates, RSA DER 1794 B, 3 RSA certificates, 8624 B of plaintext and 92 B of
    unmodified tail -- that tail is the residue the third rule above exists to catch.

`parse_descriptor_payload` -- a descriptor/payload pair returned by a keybox TA read command:
    the descriptor carries magic 0x12345678, the payload length and an MD5 of the payload;
    the payload is the length-prefixed form above. Measured on one device as a 168-byte
    descriptor and an 8578-byte payload. Those two numbers describe one sample, not the
    format, so they are reported and not required.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

DESCRIPTOR_MAGIC = 0x12345678

# Only widths and byte orders a container plausibly uses; tried in this order.
_PREFIX_FORMS = ((4, "little"), (4, "big"), (2, "little"), (2, "big"))


class FormatError(ValueError):
    pass


@dataclass
class Entry:
    """One algorithm's material: a private key and its certificate chain, all DER."""

    index: int
    private_der: bytes
    certificates: list[bytes] = field(default_factory=list)

    @property
    def algorithm(self) -> str:
        """Guess from size alone -- an EC SEC1/PKCS#8 key is small, an RSA one is not."""
        return "ecdsa" if len(self.private_der) < 400 else "rsa"


@dataclass
class Plaintext:
    version: int
    entries: list[Entry]
    prefix_width: int
    prefix_order: str
    consumed: int
    tail: bytes

    @property
    def tail_len(self) -> int:
        return len(self.tail)

    @property
    def tail_is_suspicious(self) -> bool:
        """Whether the tail looks like missed content rather than input residue.

        A recorded sample leaves 92 bytes of uncopied input at the end, which is harmless.
        A tail that is large, or that itself begins with a DER SEQUENCE, means the parse
        stopped early -- most often because the buffer is truncated or because a second
        algorithm entry was not recognised.
        """
        return self.tail_len > 256 or der_length(self.tail) is not None

    def notes(self) -> list[str]:
        out = [
            f"length prefixes are {self.prefix_width}-byte {self.prefix_order}-endian",
            f"version/keybox number = {self.version}",
        ]
        for entry in self.entries:
            out.append(
                f"entry {entry.index} ({entry.algorithm}): private DER "
                f"{len(entry.private_der)} B, {len(entry.certificates)} certificate(s)"
            )
        out.append(f"consumed {self.consumed} B")
        if self.tail and self.tail_is_suspicious:
            reason = (
                "it begins with a DER SEQUENCE"
                if der_length(self.tail) is not None
                else "it is too large to be copy residue"
            )
            out.append(
                f"{self.tail_len} B of tail left unconsumed, and {reason} -- the parse "
                "probably stopped early. Treat this buffer as truncated or as a shape this "
                "parser does not know, not as a complete keybox"
            )
        elif self.tail:
            out.append(
                f"{self.tail_len} B of tail left unconsumed -- expected when the secure-world "
                "copy is shorter than the buffer; this is input residue, not keybox content"
            )
        return out


@dataclass
class Descriptor:
    magic: int
    payload_length: int | None
    payload_md5: str | None
    size: int
    raw: bytes


def der_length(data: bytes) -> int | None:
    """Total length of the DER object at `data[0:]`, or None if it is not one.

    Rejects the indefinite form outright: DER forbids it, and accepting it is how a parser is
    talked into reading past the object it was given.
    """
    if len(data) < 2 or data[0] not in (0x30, 0x31):  # SEQUENCE / SET
        return None
    first = data[1]
    if first == 0x80:
        return None  # indefinite length: not DER
    if first < 0x80:
        return 2 + first
    count = first & 0x7F
    if count == 0 or count > 4 or len(data) < 2 + count:
        return None
    length = int.from_bytes(data[2 : 2 + count], "big")
    # A minimal encoding is required: 0x81 0x7f would be non-minimal.
    if length < 0x80 or (count > 1 and data[2] == 0):
        return None
    return 2 + count + length


def _read_prefix(data: bytes, pos: int, width: int, order: str) -> tuple[int, int]:
    if pos + width > len(data):
        raise FormatError(f"truncated length prefix at offset {pos}")
    return int.from_bytes(data[pos : pos + width], order), pos + width


def _take_der(data: bytes, pos: int, claimed: int, what: str) -> bytes:
    """Take `claimed` bytes at `pos`, insisting they are one self-consistent DER object."""
    if claimed <= 0 or pos + claimed > len(data):
        raise FormatError(
            f"{what}: claimed length {claimed} does not fit at offset {pos} "
            f"({len(data) - pos} B remain)"
        )
    blob = data[pos : pos + claimed]
    actual = der_length(blob)
    if actual is None:
        raise FormatError(
            f"{what} at offset {pos} is not a DER SEQUENCE (first byte 0x{blob[0]:02x})"
        )
    if actual != claimed:
        raise FormatError(
            f"{what} at offset {pos}: prefix says {claimed} B, the DER header says {actual} B"
        )
    return blob


def _attempt(data: bytes, width: int, order: str, entries_expected: int) -> Plaintext:
    pos = 0
    version, pos = _read_prefix(data, pos, width, order)
    if not 0 <= version <= 0xFFFF:
        raise FormatError(f"implausible version/keybox number {version}")

    entries: list[Entry] = []
    for index in range(entries_expected):
        key_len, pos = _read_prefix(data, pos, width, order)
        private = _take_der(data, pos, key_len, f"entry {index} private key")
        pos += key_len

        count, pos = _read_prefix(data, pos, width, order)
        if not 1 <= count <= 8:
            raise FormatError(f"entry {index}: implausible certificate count {count}")

        certificates = []
        for n in range(count):
            cert_len, pos = _read_prefix(data, pos, width, order)
            certificates.append(
                _take_der(data, pos, cert_len, f"entry {index} certificate {n}")
            )
            pos += cert_len

        entries.append(Entry(index=index, private_der=private, certificates=certificates))

    return Plaintext(
        version=version,
        entries=entries,
        prefix_width=width,
        prefix_order=order,
        consumed=pos,
        tail=data[pos:],
    )


def parse_lengthprefixed(data: bytes) -> Plaintext:
    """Parse the plaintext container, detecting prefix width and entry count.

    Two entries (EC then RSA) is the shape every recorded sample has, but one-entry buffers
    are accepted too; the longest successful parse wins, so a two-entry buffer is never
    reported as a one-entry buffer with a huge tail.
    """
    best: Plaintext | None = None
    errors: list[str] = []
    for width, order in _PREFIX_FORMS:
        for expected in (2, 1):
            try:
                candidate = _attempt(data, width, order, expected)
            except FormatError as exc:
                errors.append(f"{width}-byte {order}-endian, {expected} entries: {exc}")
                continue
            if best is None or candidate.consumed > best.consumed:
                best = candidate
    if best is None:
        raise FormatError(
            "no length-prefix interpretation parses this buffer. Attempts:\n  "
            + "\n  ".join(errors)
        )
    return best


def parse_descriptor(data: bytes, payload: bytes | None = None) -> Descriptor:
    """Read the descriptor's documented fields: magic, payload length, payload MD5.

    Only those three are documented. The field *offsets* within the descriptor are not, so
    rather than invent them this looks for the payload length as an integer anywhere in the
    descriptor and for the MD5 at the end, which is where it is recorded as sitting. If a
    payload is supplied, the digest is checked against it.
    """
    if len(data) < 4:
        raise FormatError(f"descriptor is {len(data)} B, too short to hold a magic")

    magic = int.from_bytes(data[:4], "little")
    if magic != DESCRIPTOR_MAGIC:
        magic_be = int.from_bytes(data[:4], "big")
        if magic_be != DESCRIPTOR_MAGIC:
            raise FormatError(
                f"descriptor magic is 0x{magic:08x} (big-endian 0x{magic_be:08x}), "
                f"expected 0x{DESCRIPTOR_MAGIC:08x}"
            )
        magic = magic_be

    payload_length = None
    if payload is not None:
        want = len(payload)
        for pos in range(4, len(data) - 3):
            for order in ("little", "big"):
                if int.from_bytes(data[pos : pos + 4], order) == want:
                    payload_length = want
                    break
            if payload_length is not None:
                break

    digest = data[-16:].hex() if len(data) >= 20 else None
    return Descriptor(
        magic=magic,
        payload_length=payload_length,
        payload_md5=digest,
        size=len(data),
        raw=data,
    )


def parse_descriptor_payload(
    descriptor_bytes: bytes, payload_bytes: bytes
) -> tuple[Descriptor, Plaintext, list[str]]:
    """Parse both halves and check the integrity relation between them."""
    descriptor = parse_descriptor(descriptor_bytes, payload_bytes)
    notes: list[str] = [
        f"descriptor {descriptor.size} B, payload {len(payload_bytes)} B "
        "(both describe this sample, not the format)",
        f"magic 0x{descriptor.magic:08x} OK",
    ]

    actual_md5 = hashlib.md5(payload_bytes, usedforsecurity=False).hexdigest()
    if descriptor.payload_md5 == actual_md5:
        notes.append(f"descriptor trailing MD5 matches the payload ({actual_md5})")
    else:
        # Not necessarily a failure: the digest may sit elsewhere in this version. Say so
        # rather than claiming a mismatch the format does not support.
        where = descriptor_bytes.find(bytes.fromhex(actual_md5))
        if where >= 0:
            notes.append(
                f"payload MD5 {actual_md5} found in the descriptor at offset {where}, "
                "not at the end"
            )
        else:
            notes.append(
                f"payload MD5 {actual_md5} does not appear in the descriptor -- "
                "either a different digest algorithm or a mismatched pair"
            )

    if descriptor.payload_length == len(payload_bytes):
        notes.append("the descriptor records this payload's length")
    else:
        notes.append("the payload's length was not found as an integer in the descriptor")

    return descriptor, parse_lengthprefixed(payload_bytes), notes
