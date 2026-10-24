"""Offline verification of an RKP v3 certificate request.

Implements the acceptance relations for `generateCertificateRequestV2`'s output, structured
so that a failure says which relation broke rather than just "invalid":

    AuthenticatedRequest = [1, UdsCerts, DiceCertChain, SignedData]
    SignedData           = COSE_Sign1 over [challenge, bstr .cbor CsrPayload]
    CsrPayload           = [3, "keymint", DeviceInfo, [COSE_Key]]

The DICE chain is walked from its root: entry 0 is the UDS public key, and each later entry
is a COSE_Sign1 verified with the public key the previous entry carried. The key the last
entry carries is the one that must have signed `SignedData` -- that final check is what ties
the request to the device's measured boot, and it is the only reason the server trusts
anything in the request.

Three checks here exist because of recorded field failures rather than because the CDDL
demands them:

  * canonical CBOR map ordering, everywhere. A field at the wrong level or a non-canonical
    map is enough for the backend to answer 400.
  * a DICE chain of length exactly 2 whose entry 0 public key equals entry 1's subject public
    key is *degenerate* -- self-signed, no boot measurements. It satisfies the structural
    minimum and is recorded as a first-line cause of the backend's 444 DeviceNotRegistered.
  * the identity key and the keys being certified must differ. Requiring them to be equal
    judges a correct result a failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as asym_utils

from . import cbor

AUTHENTICATED_REQUEST_VERSION = 1
CSR_PAYLOAD_VERSION = 3
CSR_PAYLOAD_COMPONENT = "keymint"

ALG_ES256 = -7
ALG_EDDSA = -8

CWT_ISSUER = 1
CWT_SUBJECT = 2
DICE_SUBJECT_PUBLIC_KEY = -4670552
DICE_KEY_USAGE = -4670553
DICE_PROFILE_NAME = -4670554
DICE_PROFILE_VALUE = "android.15"
DICE_KEY_USAGE_CERT_SIGN = 0x20

# Optional Open DICE measurement fields. Their absence is what makes a chain degenerate.
OPTIONAL_DICE_BYTE_FIELDS = (
    -4670545,  # codeHash
    -4670546,  # codeDescriptor
    -4670547,  # configurationHash
    -4670548,  # configurationDescriptor
    -4670549,  # authorityHash
    -4670550,  # authorityDescriptor
    -4670551,  # mode
)

TEST_KEY_LABEL = -70000
P256_CURVE = 1
CURVE_25519 = 2
P256_COORD_LEN = 32

DEVICE_INFO_KEYS = {
    "brand",
    "manufacturer",
    "product",
    "model",
    "device",
    "vb_state",
    "bootloader_state",
    "vbmeta_digest",
    "os_version",
    "system_patch_level",
    "boot_patch_level",
    "vendor_patch_level",
    "security_level",
    "fused",
}
DEVICE_INFO_DOMAINS = {
    "vb_state": {"green", "yellow", "orange"},
    "bootloader_state": {"locked", "unlocked"},
    "security_level": {"tee", "strongbox"},
}


@dataclass
class Result:
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def fact(self, message: str) -> None:
        self.facts.append(message)


def verify(data: bytes) -> Result:
    """Verify an `AuthenticatedRequest`, in CBOR, as the TA returns it after unwrapping."""
    result = Result()

    try:
        request = cbor.load(data)
    except cbor.CborError as exc:
        result.fail(f"not decodable as CBOR: {exc}")
        return result

    for violation in cbor.canonical_violations(request):
        result.fail(f"non-canonical CBOR: {violation}")

    if not isinstance(request, list) or len(request) != 4:
        result.fail(
            "AuthenticatedRequest must be a 4-element array "
            f"(got {type(request).__name__} of length "
            f"{len(request) if isinstance(request, list) else 'n/a'}). If this is a map with "
            "key 61, unwrap it first -- that is the TA's response envelope, not the request."
        )
        return result

    version, uds_certs, dice_chain, signed_data = request

    if version != AUTHENTICATED_REQUEST_VERSION:
        result.fail(f"version is {version!r}, expected {AUTHENTICATED_REQUEST_VERSION}")
    if not isinstance(uds_certs, cbor.Map):
        result.fail(f"UdsCerts is {type(uds_certs).__name__}, expected a map (may be empty)")
    elif len(uds_certs) == 0:
        result.fact("UdsCerts is empty (permitted)")

    identity_key = _verify_dice_chain(dice_chain, result)
    payload = _verify_signed_data(signed_data, identity_key, result)
    if payload is not None:
        _verify_csr_payload(payload, identity_key, result)

    return result


# -- DICE ------------------------------------------------------------------------------

def _verify_dice_chain(chain: object, result: Result):
    if not isinstance(chain, list):
        result.fail(f"DiceCertChain is {type(chain).__name__}, expected an array")
        return None
    if len(chain) < 2:
        result.fail(f"DiceCertChain has {len(chain)} element(s), the minimum is 2")
        return None

    root = _cose_key(chain[0], "DiceCertChain[0] (UDS public key)", result)
    if root is None:
        return None

    current = root
    subjects: list[bytes] = []
    for index, entry in enumerate(chain[1:], start=1):
        label = f"DiceCertChain[{index}]"
        claims = _verify_cose_sign1(entry, current, label, result)
        if claims is None:
            return None
        current = _entry_subject_key(claims, label, result, subjects)
        if current is None:
            return None

    _flag_degenerate(chain, root, subjects, result)
    result.fact(f"DICE chain of {len(chain)} element(s) verified end to end")
    return current


def _entry_subject_key(claims: cbor.Map, label: str, result: Result, subjects: list[bytes]):
    if not isinstance(claims, cbor.Map):
        result.fail(f"{label} payload is {type(claims).__name__}, expected a CWT map")
        return None

    for required, name in ((CWT_ISSUER, "issuer"), (CWT_SUBJECT, "subject")):
        if not claims.has(required):
            result.fail(f"{label} is missing CWT claim {required} ({name})")

    profile = claims.get(DICE_PROFILE_NAME)
    if profile is not None and profile != DICE_PROFILE_VALUE:
        result.fail(
            f"{label} profileName is {profile!r}, expected {DICE_PROFILE_VALUE!r}"
        )

    usage = claims.get(DICE_KEY_USAGE)
    if isinstance(usage, bytes) and usage and usage[0] & DICE_KEY_USAGE_CERT_SIGN == 0:
        result.warn(f"{label} keyUsage 0x{usage[0]:02x} does not set keyCertSign")

    measured = [f for f in OPTIONAL_DICE_BYTE_FIELDS if claims.has(f)]
    if measured:
        result.fact(f"{label} carries {len(measured)} measurement field(s)")
    else:
        result.warn(
            f"{label} carries no boot measurement fields -- an entry derived from a real "
            "boot normally carries codeHash/authorityHash and friends"
        )

    raw = claims.get(DICE_SUBJECT_PUBLIC_KEY)
    if not isinstance(raw, bytes):
        result.fail(f"{label} is missing the subjectPublicKey ({DICE_SUBJECT_PUBLIC_KEY})")
        return None
    subjects.append(raw)

    try:
        key_map = cbor.load(raw)
    except cbor.CborError as exc:
        result.fail(f"{label} subjectPublicKey is not CBOR: {exc}")
        return None
    return _cose_key(key_map, f"{label} subjectPublicKey", result)


def _flag_degenerate(chain: list, root, subjects: list[bytes], result: Result) -> None:
    """A two-element chain whose UDS key is also its leaf key is self-signed and unmeasured."""
    if len(chain) != 2 or not subjects:
        return
    try:
        root_encoded = chain[0]
        same = isinstance(root_encoded, cbor.Map) and cbor.load(subjects[0]).pairs == root_encoded.pairs
    except Exception:  # noqa: BLE001
        same = False
    if same:
        result.warn(
            "degenerate DICE chain: exactly 2 elements and the UDS public key equals the "
            "leaf's subject public key, so the chain is self-signed and carries no boot "
            "measurements. Structurally valid, and a recorded first-line cause of the "
            "backend answering 444 DeviceNotRegistered"
        )


# -- COSE ------------------------------------------------------------------------------

def _cose_key(value: object, label: str, result: Result):
    """Turn a COSE_Key into a `cryptography` public key, checking the field set."""
    if not isinstance(value, cbor.Map):
        result.fail(f"{label} is {type(value).__name__}, expected a COSE_Key map")
        return None

    kty, alg, crv = value.get(1), value.get(3), value.get(-1)

    if kty == 1:  # OKP
        if alg != ALG_EDDSA:
            result.fail(f"{label}: OKP key with alg {alg!r}, expected {ALG_EDDSA} (EdDSA)")
            return None
        if crv != CURVE_25519:
            result.fail(f"{label}: OKP curve {crv!r}, expected {CURVE_25519} (Ed25519)")
            return None
        x = value.get(-2)
        if not isinstance(x, bytes) or len(x) != 32:
            result.fail(f"{label}: Ed25519 x must be 32 bytes")
            return None
        return ed25519.Ed25519PublicKey.from_public_bytes(x)

    if kty == 2:  # EC2
        if alg != ALG_ES256:
            result.fail(f"{label}: EC2 key with alg {alg!r}, expected {ALG_ES256} (ES256)")
            return None
        if crv != P256_CURVE:
            result.fail(f"{label}: EC2 curve {crv!r}, expected {P256_CURVE} (P-256)")
            return None
        x, y = value.get(-2), value.get(-3)
        for name, coord in (("x", x), ("y", y)):
            if not isinstance(coord, bytes) or len(coord) != P256_COORD_LEN:
                result.fail(f"{label}: P-256 {name} must be {P256_COORD_LEN} bytes")
                return None
        try:
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
        except ValueError as exc:
            result.fail(f"{label}: point is not on P-256 ({exc})")
            return None

    result.fail(f"{label}: unsupported key type {kty!r}")
    return None


def _verify_cose_sign1(value: object, public_key, label: str, result: Result):
    """Verify a COSE_Sign1 and return its decoded payload."""
    if not isinstance(value, list) or len(value) != 4:
        result.fail(f"{label} is not a 4-element COSE_Sign1 array")
        return None

    protected, _unprotected, payload, signature = value
    if not isinstance(protected, bytes):
        result.fail(f"{label} protected header must be a bstr")
        return None
    if not isinstance(payload, bytes):
        result.fail(f"{label} payload must be a bstr")
        return None
    if not isinstance(signature, bytes):
        result.fail(f"{label} signature must be a bstr")
        return None

    # Sig_structure = ["Signature1", protected, external_aad, payload]; RFC 9052 section 4.4.
    sig_structure = (
        b"\x84"
        + b"\x6aSignature1"
        + _bstr(protected)
        + _bstr(b"")
        + _bstr(payload)
    )

    if public_key is None:
        result.fail(f"{label}: no key available to verify against")
        return None

    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, sig_structure)
        else:
            if len(signature) != 64:
                result.fail(f"{label}: ES256 signature must be 64 bytes, got {len(signature)}")
                return None
            der = asym_utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            )
            public_key.verify(der, sig_structure, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        result.fail(f"{label}: signature does not verify")
        return None

    try:
        return cbor.load(payload)
    except cbor.CborError as exc:
        result.fail(f"{label}: payload is not CBOR: {exc}")
        return None


def _bstr(data: bytes) -> bytes:
    n = len(data)
    if n < 24:
        head = bytes([0x40 | n])
    elif n < 0x100:
        head = bytes([0x58, n])
    elif n < 0x10000:
        head = b"\x59" + n.to_bytes(2, "big")
    else:
        head = b"\x5a" + n.to_bytes(4, "big")
    return head + data


def _verify_signed_data(value: object, identity_key, result: Result):
    claims = _verify_cose_sign1(value, identity_key, "SignedData", result)
    if claims is None:
        return None
    if not isinstance(claims, list) or len(claims) != 2:
        result.fail("SignedData payload must be [challenge, bstr .cbor CsrPayload]")
        return None
    challenge, encoded = claims
    if not isinstance(challenge, bytes) or not 1 <= len(challenge) <= 64:
        result.fail(
            f"challenge must be 1..64 bytes, got "
            f"{len(challenge) if isinstance(challenge, bytes) else type(challenge).__name__}"
        )
    else:
        result.fact(f"challenge is {len(challenge)} bytes")
    if not isinstance(encoded, bytes):
        result.fail("SignedData's second element must be a bstr holding the CsrPayload")
        return None
    result.fact("SignedData verifies against the DICE chain's leaf key")
    try:
        payload = cbor.load(encoded)
    except cbor.CborError as exc:
        result.fail(f"CsrPayload is not CBOR: {exc}")
        return None
    for violation in cbor.canonical_violations(payload, "$CsrPayload"):
        result.fail(f"non-canonical CBOR: {violation}")
    return payload


# -- CsrPayload ------------------------------------------------------------------------

def _verify_csr_payload(payload: object, identity_key, result: Result) -> None:
    if not isinstance(payload, list) or len(payload) != 4:
        result.fail('CsrPayload must be [3, "keymint", DeviceInfo, keysToSign]')
        return

    version, component, device_info, keys_to_sign = payload
    if version != CSR_PAYLOAD_VERSION:
        result.fail(f"CsrPayload version is {version!r}, expected {CSR_PAYLOAD_VERSION}")
    if component != CSR_PAYLOAD_COMPONENT:
        result.fail(f"CsrPayload component is {component!r}, expected {CSR_PAYLOAD_COMPONENT!r}")

    _verify_device_info(device_info, result)
    _verify_keys_to_sign(keys_to_sign, identity_key, result)


def _verify_device_info(value: object, result: Result) -> None:
    if not isinstance(value, cbor.Map):
        result.fail(f"DeviceInfo is {type(value).__name__}, expected a map")
        return

    present = set()
    for key, val in value.pairs:
        if not isinstance(key, str):
            result.fail(f"DeviceInfo key {key!r} is not a text string")
            continue
        if key not in DEVICE_INFO_KEYS:
            result.fail(
                f"DeviceInfo carries {key!r}, which is not in the v3 field set -- a field "
                "from another CSR version at the wrong level is enough for a 400"
            )
            continue
        present.add(key)
        domain = DEVICE_INFO_DOMAINS.get(key)
        if domain and val not in domain:
            result.fail(f"DeviceInfo {key} is {val!r}, expected one of {sorted(domain)}")
        if key == "vbmeta_digest" and (not isinstance(val, bytes) or len(val) != 32):
            result.fail("DeviceInfo vbmeta_digest must be 32 bytes")

    security_level = value.get("security_level")
    count = len(value)
    if security_level == "tee" and count not in (13, 14):
        result.fail(f"DeviceInfo for tee has {count} fields, expected 13 or 14")
    elif security_level == "strongbox" and not 12 <= count <= 14:
        result.fail(f"DeviceInfo for strongbox has {count} fields, expected 12 to 14")

    missing = DEVICE_INFO_KEYS - present - {"vbmeta_digest", "fused"}
    if missing:
        result.warn("DeviceInfo omits " + ", ".join(sorted(missing)))
    else:
        result.fact(f"DeviceInfo carries {count} field(s), security_level {security_level!r}")


def _verify_keys_to_sign(value: object, identity_key, result: Result) -> None:
    if not isinstance(value, list):
        result.fail(
            f"keysToSign is {type(value).__name__}, expected an array of COSE_Keys. "
            "A bare map here is a recorded cause of the backend answering "
            '"Expected an array, got MAP"'
        )
        return
    if not value:
        result.fail("keysToSign is empty")
        return

    identity_encoded = None
    if identity_key is not None:
        try:
            identity_encoded = identity_key.public_bytes_raw()
        except Exception:  # noqa: BLE001 - EC keys have no raw form; compared below instead
            identity_encoded = None

    for index, item in enumerate(value):
        label = f"keysToSign[{index}]"
        if not isinstance(item, cbor.Map):
            result.fail(f"{label} is {type(item).__name__}, expected a COSE_Key map")
            continue
        allowed = {1, 3, -1, -2, -3, TEST_KEY_LABEL}
        extra = set(item.keys()) - allowed
        if extra:
            result.fail(f"{label} carries unexpected label(s) {sorted(extra)}")
        if item.has(TEST_KEY_LABEL) and item.get(TEST_KEY_LABEL) is not None:
            result.fail(f"{label}: the test-key marker {TEST_KEY_LABEL} must be null")
        key = _cose_key(item, label, result)
        if key is None:
            continue
        if identity_encoded is not None:
            try:
                if key.public_bytes_raw() == identity_encoded:
                    result.fail(
                        f"{label} is the DICE identity key itself. The identity key proves "
                        "the request came from the device; the key being certified must be a "
                        "different, freshly generated one"
                    )
            except Exception:  # noqa: BLE001
                pass

    result.fact(f"keysToSign carries {len(value)} key(s)")
