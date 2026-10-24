#!/usr/bin/env python3
"""Generate the test fixtures the toolkit is checked against.

Everything here is synthetic: freshly generated keys, self-signed roots, and containers built
to the recorded shapes. No real keybox, private key or device material is involved, which is
what makes the fixtures committable and the tests runnable anywhere.

Written to rkp/tools/tests/fixtures/. Re-run after changing a container format.
"""

from __future__ import annotations

import datetime
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils as asym
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from teesim_attest import cbor, csr, plaintext, provisioning  # noqa: E402

OUT = Path(__file__).resolve().parent / "fixtures"
DAY = datetime.timedelta(days=1)


def _cert(subject_key, subject_cn, issuer_key, issuer_cn, *, ca, days=3650, extension=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - DAY)
        .not_valid_after(now + days * DAY)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if extension is not None:
        builder = builder.add_extension(extension, critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _pem_key(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def _pem_cert(certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "".join(f"{pad}{line}\n" for line in text.splitlines() if line.strip())


def _keybox_xml(blocks) -> str:
    xml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<AndroidAttestation>",
        "    <NumberOfKeyboxes>1</NumberOfKeyboxes>",
        '    <Keybox DeviceID="synthetic-fixture">',
    ]
    for algorithm, key_pem, chain in blocks:
        xml += [
            f'        <Key algorithm="{algorithm}">',
            '            <PrivateKey format="pem">',
            _indent(key_pem, 16).rstrip("\n"),
            "            </PrivateKey>",
            "            <CertificateChain>",
            f"                <NumberOfCertificates>{len(chain)}</NumberOfCertificates>",
        ]
        for certificate in chain:
            xml += [
                '                <Certificate format="pem">',
                _indent(_pem_cert(certificate), 20).rstrip("\n"),
                "                </Certificate>",
            ]
        xml += ["            </CertificateChain>", "        </Key>"]
    xml += ["    </Keybox>", "</AndroidAttestation>", ""]
    return "\n".join(xml)


def _provisioning_extension(certs_issued: int, *, bound: bool, approved: bool = True):
    record = {
        1: "APPROVED" if approved else "NOT_APPROVED",
        2: "4d" * 32,
        3: "APPROVED" if approved else "NOT_APPROVED",
        4: "Synthetic/fixture/fixture:16/AAAA.000000.000/0:user/release-keys",
    }
    payload: dict[int, object] = {1: certs_issued, 3: "Synthetic"}
    if bound:
        payload[5] = record
    return x509.UnrecognizedExtension(
        x509.ObjectIdentifier(provisioning.OID), cbor.dumps(payload)
    )


# -- keyboxes ---------------------------------------------------------------------------

def keyboxes() -> None:
    # A factory-shaped keybox: RSA + EC, each a 3-certificate chain to one shared root.
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(root_key, "Fixture Root", root_key, "Fixture Root", ca=True, days=5000)

    blocks = []
    for algorithm, key in (
        ("rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("ecdsa", ec.generate_private_key(ec.SECP256R1())),
    ):
        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        intermediate = _cert(
            intermediate_key, "Fixture Batch", root_key, "Fixture Root", ca=True, days=4000
        )
        leaf = _cert(key, "Fixture Leaf", intermediate_key, "Fixture Batch", ca=True, days=3650)
        blocks.append((algorithm, _pem_key(key), [leaf, intermediate, root]))
    (OUT / "keybox-factory.xml").write_text(_keybox_xml(blocks))

    # An RKP-shaped keybox: EC only, a two-week leaf, certs_issued at the stock baseline.
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "Fixture CA3", root_key, "Fixture Root", ca=True, days=70)
    leaf = _cert(
        leaf_key,
        "Fixture RKP Leaf",
        ca_key,
        "Fixture CA3",
        ca=True,
        days=14,
        extension=_provisioning_extension(provisioning.STOCK_CERTS_ISSUED, bound=False),
    )
    (OUT / "keybox-rkp-stock.xml").write_text(
        _keybox_xml([("ecdsa", _pem_key(leaf_key), [leaf, ca, root])])
    )

    # The same, but with certs_issued far above the baseline and a NOT_APPROVED verdict --
    # a keybox that passes every cryptographic check and must still be rejected.
    leaf_key2 = ec.generate_private_key(ec.SECP256R1())
    leaf2 = _cert(
        leaf_key2,
        "Fixture RKP Leaf",
        ca_key,
        "Fixture CA3",
        ca=True,
        days=14,
        extension=_provisioning_extension(512, bound=True, approved=False),
    )
    (OUT / "keybox-rkp-not-approved.xml").write_text(
        _keybox_xml([("ecdsa", _pem_key(leaf_key2), [leaf2, ca, root])])
    )

    # A keybox whose private key belongs to a different key pair: layer 1 must catch it.
    (OUT / "keybox-mismatched-key.xml").write_text(
        _keybox_xml(
            [("ecdsa", _pem_key(ec.generate_private_key(ec.SECP256R1())), [leaf, ca, root])]
        )
    )


# -- containers -------------------------------------------------------------------------

def _der_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def containers() -> None:
    u32 = lambda n: n.to_bytes(4, "little")  # noqa: E731
    root_key = ec.generate_private_key(ec.SECP256R1())

    body = u32(1)
    for key in (
        ec.generate_private_key(ec.SECP256R1()),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    ):
        der = _der_key(key)
        body += u32(len(der)) + der
        chain = [
            _cert(key, "Fixture Leaf", root_key, "Fixture Root", ca=True),
            _cert(root_key, "Fixture Int", root_key, "Fixture Root", ca=True),
            _cert(root_key, "Fixture Root", root_key, "Fixture Root", ca=True),
        ]
        body += u32(len(chain))
        for certificate in chain:
            der_cert = certificate.public_bytes(serialization.Encoding.DER)
            body += u32(len(der_cert)) + der_cert

    # The recorded shape includes tail residue: the secure-world copy is shorter than the
    # buffer, so bytes of the original input survive. A parser must not treat them as keybox.
    (OUT / "container-plaintext.bin").write_bytes(body + bytes(92))

    digest = hashlib.md5(body, usedforsecurity=False).digest()
    descriptor = u32(plaintext.DESCRIPTOR_MAGIC) + u32(len(body))
    descriptor += bytes(168 - len(descriptor) - 16) + digest
    (OUT / "container-descriptor.bin").write_bytes(descriptor)
    (OUT / "container-payload.bin").write_bytes(body)


# -- CSRs -------------------------------------------------------------------------------

def _cose_ed(public) -> dict:
    return {1: 1, 3: csr.ALG_EDDSA, -1: csr.CURVE_25519, -2: public.public_bytes_raw()}


def _cose_ec(public) -> dict:
    numbers = public.public_numbers()
    return {
        1: 2,
        3: csr.ALG_ES256,
        -1: csr.P256_CURVE,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


def _sign1(private, payload_object) -> list:
    protected = cbor.dumps({1: csr.ALG_EDDSA})
    payload = cbor.dumps(payload_object)
    structure = cbor.dumps(["Signature1", protected, b"", payload])
    if isinstance(private, ed25519.Ed25519PrivateKey):
        signature = private.sign(structure)
    else:
        r, s = asym.decode_dss_signature(
            private.sign(structure, ec.ECDSA(hashes.SHA256()))
        )
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return [protected, cbor.Map(), payload, signature]


DEVICE_INFO = {
    "brand": "Synthetic",
    "manufacturer": "Synthetic",
    "product": "fixture",
    "model": "FIX-1",
    "device": "fixture",
    "vb_state": "green",
    "bootloader_state": "locked",
    "vbmeta_digest": bytes(32),
    "os_version": "16",
    "system_patch_level": 202601,
    "boot_patch_level": 20260105,
    "vendor_patch_level": 20260105,
    "security_level": "tee",
    "fused": 1,
}


def _entry(issuer, subject_private, *, measured):
    claims: dict[int, object] = {
        csr.CWT_ISSUER: issuer,
        csr.CWT_SUBJECT: "next",
        csr.DICE_PROFILE_NAME: csr.DICE_PROFILE_VALUE,
        csr.DICE_KEY_USAGE: bytes([csr.DICE_KEY_USAGE_CERT_SIGN]),
        csr.DICE_SUBJECT_PUBLIC_KEY: cbor.dumps(_cose_ed(subject_private.public_key())),
    }
    if measured:
        claims[-4670545] = bytes(32)  # codeHash
        claims[-4670549] = bytes(32)  # authorityHash
    return claims


def csrs() -> None:
    identity = ed25519.Ed25519PrivateKey.generate()
    uds = ed25519.Ed25519PrivateKey.generate()
    fresh = ec.generate_private_key(ec.SECP256R1())

    # A proper, measured 4-element chain.
    middle = ed25519.Ed25519PrivateKey.generate()
    chain = [
        _cose_ed(uds.public_key()),
        _sign1(uds, _entry("uds", middle, measured=True)),
        _sign1(middle, _entry("stage1", identity, measured=True)),
    ]
    signed = _sign1(identity, [b"\x01" * 16, cbor.dumps([3, "keymint", DEVICE_INFO, [_cose_ec(fresh.public_key())]])])
    (OUT / "csr-proper.cbor").write_bytes(cbor.dumps([1, cbor.Map(), chain, signed]))

    # The degenerate chain: 2 elements, UDS key == leaf key, no measurements.
    degenerate = [
        _cose_ed(identity.public_key()),
        _sign1(identity, _entry("self", identity, measured=False)),
    ]
    (OUT / "csr-degenerate-dice.cbor").write_bytes(
        cbor.dumps([1, cbor.Map(), degenerate, signed])
    )

    # The TA's response envelope, which must be unwrapped before verification.
    (OUT / "csr-envelope.cbor").write_bytes(
        cbor.dumps({61: cbor.dumps([1, cbor.Map(), chain, signed])})
    )

    # keysToSign carrying the identity key itself -- the two keys must differ.
    reused = _sign1(
        identity,
        [b"\x01" * 16, cbor.dumps([3, "keymint", DEVICE_INFO, [_cose_ed(identity.public_key())]])],
    )
    (OUT / "csr-identity-reused.cbor").write_bytes(
        cbor.dumps([1, cbor.Map(), chain, reused])
    )

    # A field from another CSR version, at the wrong level.
    foreign = dict(DEVICE_INFO)
    foreign["version"] = 2
    (OUT / "csr-foreign-field.cbor").write_bytes(
        cbor.dumps(
            [
                1,
                cbor.Map(),
                chain,
                _sign1(identity, [b"\x01" * 16, cbor.dumps([3, "keymint", foreign, [_cose_ec(fresh.public_key())]])]),
            ]
        )
    )

    # Non-canonical DeviceInfo: correct fields, wrong map order.
    unsorted = b"\xa2" + cbor.dumps("vb_state") + cbor.dumps("green")
    unsorted += cbor.dumps("brand") + cbor.dumps("Synthetic")
    body = b"\x84\x03" + cbor.dumps("keymint") + unsorted
    body += cbor.dumps([_cose_ec(fresh.public_key())])
    (OUT / "csr-non-canonical.cbor").write_bytes(
        cbor.dumps([1, cbor.Map(), chain, _sign1(identity, [b"\x01" * 16, body])])
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    keyboxes()
    containers()
    csrs()
    for path in sorted(OUT.iterdir()):
        print(f"{path.stat().st_size:>8}  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
