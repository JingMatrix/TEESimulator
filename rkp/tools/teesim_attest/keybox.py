"""Parsing and acceptance for `keybox.xml`.

Acceptance is the point of this module. A parsed keybox proves nothing: a chain that
verifies only shows the signature relations are right, and that is compatible with a random
key pair, a keybox for another purpose, a misaligned parse or a test CA. Three independent
layers are needed, and this module implements the first two:

  layer 1   PublicKey(private_EC)  == PublicKey(ec_leaf_certificate)
            PublicKey(private_RSA) == PublicKey(rsa_leaf_certificate)
  layer 2   leaf signed by intermediate, intermediate by root, root self-signed
  layer 3   trigger a fresh attestation through Android KeyStore and compare the resulting
            leaf against the keybox's own certificates -- needs a device, see the README

Layer 3 is the one usually skipped and the only one that binds the material to the handset
in front of you.

The module's constraints deliberately match what the module itself enforces in
`rust/teesim-km/src/attest.rs`: at least one of the `rsa`/`ecdsa` keys, and at least two
certificates per algorithm. A factory keybox carries both algorithms; an RKP-provisioned one
carries only EC, and loads.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.etree import ElementTree

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from . import provisioning

# Zero-width and byte-order marks that keybox files picked up from editors and chat clients,
# plus XML comments. Upstream keybox parsers choke on these, so strip before parsing.
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿"))
_COMMENT = re.compile(r"<!--.*?-->", re.S)


def clean(text: str) -> str:
    """Remove a BOM, zero-width characters and XML comments."""
    return _COMMENT.sub("", text.translate(_INVISIBLE)).strip()


@dataclass
class ChainLink:
    certificate: x509.Certificate
    subject: str
    issuer: str
    serial_hex: str
    days_remaining: int
    self_signed: bool
    signature_ok: bool | None  # verified against the next certificate up; None for the root
    provisioning: provisioning.ProvisioningInfo | None


@dataclass
class KeyEntry:
    algorithm: str
    key_bits: int | None
    private_matches_leaf: bool
    chain: list[ChainLink] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def chain_links_ok(self) -> bool:
        return all(link.signature_ok is not False for link in self.chain)

    @property
    def accepted(self) -> bool:
        """Layers 1 and 2, plus every structural rule. Layer 3 is out of scope here."""
        return (
            self.private_matches_leaf
            and self.chain_links_ok
            and len(self.chain) >= 2
            and not self.problems
        )


@dataclass
class Keybox:
    device_id: str
    keys: list[KeyEntry] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def algorithms(self) -> list[str]:
        return [k.algorithm for k in self.keys]

    @property
    def shape(self) -> str:
        """Which kind of keybox this is, from its shape alone.

        RKP issuance is P-256 only, so an EC-only keybox is RKP-provisioned and a keybox with
        both algorithms is a factory one. Leaf lifetime corroborates: an RKP leaf lives about
        two weeks, a factory leaf about ten years.
        """
        algos = set(self.algorithms)
        if algos == {"ecdsa"}:
            return "rkp-provisioned (EC only)"
        if {"rsa", "ecdsa"} <= algos:
            return "factory (RSA + EC)"
        return "unusual (" + ", ".join(sorted(algos)) + ")"

    @property
    def accepted(self) -> bool:
        return bool(self.keys) and not self.problems and all(k.accepted for k in self.keys)


def parse(xml_text: str) -> Keybox:
    root = ElementTree.fromstring(clean(xml_text))
    node = root.find(".//Keybox")
    box = Keybox(device_id=(node.get("DeviceID", "") if node is not None else ""))

    for key_node in root.iter("Key"):
        box.keys.append(_parse_key(key_node))

    if not box.keys:
        box.problems.append('no <Key algorithm="rsa"> or <Key algorithm="ecdsa">')

    # The declared count, where present, must match reality -- a mismatch means the file was
    # hand-edited and some parsers trust the declaration over the content.
    declared = root.find(".//NumberOfKeyboxes")
    if declared is not None and (declared.text or "").strip() not in ("", "1"):
        box.problems.append(f"NumberOfKeyboxes is {declared.text!r}, expected 1")

    return box


def _parse_key(node) -> KeyEntry:
    algorithm = (node.get("algorithm") or "").strip().lower()
    problems: list[str] = []

    private_node = node.find("PrivateKey")
    if private_node is None or not (private_node.text or "").strip():
        problems.append("missing or empty <PrivateKey>")
        private = None
    else:
        try:
            private = serialization.load_pem_private_key(
                _dedent_pem(private_node.text).encode(), password=None
            )
        except Exception as exc:  # noqa: BLE001 - report, do not crash the whole file
            problems.append(f"private key will not load: {exc}")
            private = None

    certificates: list[x509.Certificate] = []
    for cert_node in node.iter("Certificate"):
        text = (cert_node.text or "").strip()
        if not text:
            problems.append("empty <Certificate>")
            continue
        try:
            certificates.append(x509.load_pem_x509_certificate(_dedent_pem(text).encode()))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"certificate will not load: {exc}")

    count_node = node.find(".//NumberOfCertificates")
    if count_node is not None:
        try:
            if int((count_node.text or "0").strip()) != len(certificates):
                problems.append(
                    f"NumberOfCertificates says {count_node.text.strip()}, "
                    f"found {len(certificates)}"
                )
        except ValueError:
            problems.append(f"NumberOfCertificates is not a number: {count_node.text!r}")

    if len(certificates) < 2:
        problems.append(f"expected at least 2 certificates, found {len(certificates)}")

    chain = _describe_chain(certificates)
    matches = bool(private and certificates and _same_public_key(private, certificates[0]))
    if private and certificates and not matches:
        problems.append("private key does not match the leaf certificate's public key")

    problems += chain_order_problems(certificates)
    for index, link in enumerate(chain):
        if link.days_remaining < 0:
            problems.append(
                f"certificate {index} expired {-link.days_remaining} day(s) ago "
                f"({link.certificate.not_valid_after_utc:%Y-%m-%d})"
            )
    # The server's verdict is not overridable by a valid chain, so it is a hard problem.
    for index, link in enumerate(chain):
        if link.provisioning and link.provisioning.provisioning_ok is False:
            verdicts = ", ".join(link.provisioning.device_record.verdicts)
            problems.append(
                f"certificate {index} carries provisioning status {verdicts}"
            )

    return KeyEntry(
        algorithm=algorithm,
        key_bits=_key_bits(private),
        private_matches_leaf=matches,
        chain=chain,
        problems=problems,
    )


def _dedent_pem(text: str) -> str:
    """PEM inside keybox XML is indented; the parsers are strict about line content."""
    return "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())


def _key_bits(private) -> int | None:
    if isinstance(private, rsa.RSAPrivateKey):
        return private.key_size
    if isinstance(private, ec.EllipticCurvePrivateKey):
        return private.curve.key_size
    return None


def _same_public_key(private, certificate: x509.Certificate) -> bool:
    """Compare SPKI bytes -- the comparison the three-layer proof's first layer names."""
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    return private.public_key().public_bytes(*spki) == certificate.public_key().public_bytes(
        *spki
    )


def _describe_chain(certificates: list[x509.Certificate]) -> list[ChainLink]:
    now = datetime.now(timezone.utc)
    links: list[ChainLink] = []

    for index, certificate in enumerate(certificates):
        subject = _dn(certificate.subject)
        issuer = _dn(certificate.issuer)
        parent = certificates[index + 1] if index + 1 < len(certificates) else None
        self_signed = certificate.subject == certificate.issuer

        if parent is not None:
            signature_ok = _signature_ok(certificate, parent)
        elif self_signed:
            signature_ok = _signature_ok(certificate, certificate)
        else:
            # The chain stops before a self-signed root. Not an error by itself -- a keybox
            # may omit the root -- but nothing above this certificate was checked.
            signature_ok = None

        links.append(
            ChainLink(
                certificate=certificate,
                subject=subject,
                issuer=issuer,
                serial_hex=f"{certificate.serial_number:X}",
                days_remaining=(certificate.not_valid_after_utc - now).days,
                self_signed=self_signed,
                signature_ok=signature_ok,
                provisioning=_provisioning_of(certificate),
            )
        )
    return links


def _provisioning_of(certificate: x509.Certificate) -> provisioning.ProvisioningInfo | None:
    for extension in certificate.extensions:
        if extension.oid.dotted_string == provisioning.OID:
            raw = extension.value.public_bytes()
            try:
                return provisioning.parse(raw)
            except Exception:  # noqa: BLE001 - an undecodable extension is still a finding
                return provisioning.ProvisioningInfo(raw=raw)
    return None


def _signature_ok(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """Verify child's signature with parent's public key."""
    try:
        public = parent.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except Exception:  # noqa: BLE001 - a failed verify is the answer, not an error
        return False


def _dn(name: x509.Name) -> str:
    parts = []
    for oid, label in (
        (NameOID.COMMON_NAME, "CN"),
        (NameOID.ORGANIZATION_NAME, "O"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
        (NameOID.TITLE, "title"),
        (NameOID.SERIAL_NUMBER, "serialNumber"),
        (NameOID.COUNTRY_NAME, "C"),
    ):
        for attribute in name.get_attributes_for_oid(oid):
            parts.append(f"{label}={attribute.value}")
    return ", ".join(parts) or name.rfc4514_string()


def chain_order_problems(certificates: list[x509.Certificate]) -> list[str]:
    """Check leaf-first ordering and name linkage, independently of the signatures.

    Name linkage catches a misordered chain, not a substituted one -- which is why this is
    reported separately from `_signature_ok` rather than instead of it.
    """
    out: list[str] = []
    for index in range(len(certificates) - 1):
        if certificates[index].issuer != certificates[index + 1].subject:
            out.append(
                f"certificate {index}'s issuer is not certificate {index + 1}'s subject"
            )
    seen = set()
    for index, certificate in enumerate(certificates):
        key = certificate.public_bytes(serialization.Encoding.DER)
        if key in seen:
            out.append(f"certificate {index} is a duplicate")
        seen.add(key)
    if certificates and certificates[0].subject == certificates[0].issuer and len(certificates) > 1:
        out.append("the first certificate is self-signed -- the chain looks reversed")
    return out


def der_of(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def sha256_of(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def b64_lines(data: bytes, width: int = 64) -> str:
    text = base64.b64encode(data).decode()
    return "\n".join(text[i : i + width] for i in range(0, len(text), width))


def basic_constraints(certificate: x509.Certificate) -> str:
    try:
        value = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        return "absent"
    return f"CA:{'TRUE' if value.ca else 'FALSE'}" + (
        f", pathlen:{value.path_length}" if value.path_length is not None else ""
    )
