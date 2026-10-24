"""A minimal, strict CBOR reader for attestation material.

Hand-rolled rather than `cbor2`, for two reasons. The toolkit then has no third-party
dependency beyond `cryptography`, and — more importantly — checking canonical map order
needs the *encoded* bytes of each key, which a decoder returning plain Python objects
throws away. `load` therefore records, for every map it decodes, the byte string each key
encoded to, so `canonical_violations` can check RFC 8949 §4.2.1 ordering afterwards.

Only what attestation material actually uses is supported: unsigned and negative integers,
byte and text strings (definite length only), arrays, maps, `null`/`true`/`false`, and
tagged values. Indefinite-length items and floats raise, because nothing in a CSR, a DICE
chain or a provisioning extension is allowed to use them and silently accepting one would
hide a malformed encoding.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class CborError(ValueError):
    """Raised for any input this reader refuses, with the byte offset in the message."""


@dataclass
class Map:
    """A decoded CBOR map that remembers how each key was encoded.

    `pairs` keeps insertion order, which is what order checking needs; `encoded_keys`
    holds the raw bytes of the key at the same index.
    """

    pairs: list[tuple[object, object]] = field(default_factory=list)
    encoded_keys: list[bytes] = field(default_factory=list)

    def get(self, key, default=None):
        for k, v in self.pairs:
            if k == key:
                return v
        return default

    def has(self, key) -> bool:
        return any(k == key for k, _ in self.pairs)

    def keys(self):
        return [k for k, _ in self.pairs]

    def __len__(self):
        return len(self.pairs)

    def __repr__(self):
        return f"Map({self.pairs!r})"


@dataclass
class Tagged:
    tag: int
    value: object


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _need(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CborError(f"truncated at offset {self.pos}: need {n} more bytes")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def _argument(self, info: int, start: int) -> int:
        if info < 24:
            return info
        if info == 24:
            return self._need(1)[0]
        if info == 25:
            return int.from_bytes(self._need(2), "big")
        if info == 26:
            return int.from_bytes(self._need(4), "big")
        if info == 27:
            return int.from_bytes(self._need(8), "big")
        if info == 31:
            raise CborError(f"indefinite length at offset {start} is not allowed here")
        raise CborError(f"reserved additional info {info} at offset {start}")

    def item(self) -> object:
        start = self.pos
        initial = self._need(1)[0]
        major, info = initial >> 5, initial & 0x1F

        if major == 0:
            return self._argument(info, start)
        if major == 1:
            return -1 - self._argument(info, start)
        if major == 2:
            return self._need(self._argument(info, start))
        if major == 3:
            raw = self._need(self._argument(info, start))
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CborError(f"invalid UTF-8 text string at offset {start}") from exc
        if major == 4:
            return [self.item() for _ in range(self._argument(info, start))]
        if major == 5:
            count = self._argument(info, start)
            out = Map()
            for _ in range(count):
                key_start = self.pos
                key = self.item()
                out.encoded_keys.append(self.data[key_start : self.pos])
                out.pairs.append((key, self.item()))
            return out
        if major == 6:
            return Tagged(self._argument(info, start), self.item())
        # major 7
        if info == 20:
            return False
        if info == 21:
            return True
        if info == 22:
            return None
        if info == 23:
            raise CborError(f"undefined at offset {start}")
        raise CborError(f"unsupported simple/float value (info {info}) at offset {start}")


def load(data: bytes, *, allow_trailing: bool = False) -> object:
    """Decode one CBOR item. Trailing bytes are an error unless `allow_trailing`."""
    reader = _Reader(data)
    value = reader.item()
    if not allow_trailing and reader.pos != len(data):
        raise CborError(
            f"{len(data) - reader.pos} trailing byte(s) after the top-level item"
        )
    return value


def load_prefix(data: bytes) -> tuple[object, int]:
    """Decode one CBOR item and report how many bytes it consumed."""
    reader = _Reader(data)
    return reader.item(), reader.pos


def canonical_violations(value: object, path: str = "$") -> list[str]:
    """Report every map whose keys are not in RFC 8949 §4.2.1 canonical order.

    Canonical order sorts by the key's *encoded* length first, then bytewise. Duplicate
    encoded keys are reported too: they are always invalid and are a classic way to smuggle
    a second value past a verifier that reads only the first.
    """
    out: list[str] = []
    if isinstance(value, Map):
        keys = value.encoded_keys
        ranked = sorted(keys, key=lambda k: (len(k), k))
        if keys != ranked:
            out.append(f"{path}: map keys are not in canonical order")
        if len(set(keys)) != len(keys):
            out.append(f"{path}: map has duplicate keys")
        for k, v in value.pairs:
            out += canonical_violations(v, f"{path}.{k!r}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            out += canonical_violations(item, f"{path}[{i}]")
    elif isinstance(value, Tagged):
        out += canonical_violations(value.value, f"{path}(tag {value.tag})")
    return out


def dumps_int(n: int) -> bytes:
    """Encode one integer, used only to compare against an observed key encoding."""
    major, v = (0, n) if n >= 0 else (1, -1 - n)
    if v < 24:
        return bytes([major << 5 | v])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if v < 1 << (8 * size):
            return bytes([major << 5 | info]) + v.to_bytes(size, "big")
    raise CborError("integer too large to encode")


def dumps(value: object) -> bytes:
    """Encode canonically: definite lengths, shortest integer forms, sorted map keys.

    Present so the toolkit can build the test vectors it verifies, and so a caller can
    re-encode a decoded structure and compare it against the original bytes -- a mismatch
    means the original was not canonical.
    """
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return dumps_int(value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(dumps(v) for v in value)
    if isinstance(value, Tagged):
        return _head(6, value.tag) + dumps(value.value)
    if isinstance(value, Map):
        items = [(dumps(k), dumps(v)) for k, v in value.pairs]
    elif isinstance(value, dict):
        items = [(dumps(k), dumps(v)) for k, v in value.items()]
    else:
        raise CborError(f"cannot encode {type(value).__name__}")
    items.sort(key=lambda kv: (len(kv[0]), kv[0]))
    return _head(5, len(items)) + b"".join(k + v for k, v in items)


def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([major << 5 | argument])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 1 << (8 * size):
            return bytes([major << 5 | info]) + argument.to_bytes(size, "big")
    raise CborError("argument too large to encode")
