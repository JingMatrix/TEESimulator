#!/usr/bin/env python3
"""Tests for the attestation toolkit. Run: python3 rkp/tools/tests/test_toolkit.py

Uses only the standard library plus `cryptography`, and runs entirely against the synthetic
fixtures in `fixtures/`, so there is no network access and no device. Regenerate the fixtures
with `make_fixtures.py` after changing a container format.

The two real leaked keyboxes are checked too when a copy is available, but only for facts that are
stable: their shape, chain length and whether the private key matches the leaf. Their expiry is not
asserted, because they have expired and will stay expired. They are not in this repository — they
carry live private keys — so point `TEESIM_ATTEST_SAMPLES` at a directory holding
`rkp-keybox-sample-a.xml` and `rkp-keybox-sample-b.xml` to enable those checks; without it they skip.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

RKP = Path(__file__).resolve().parents[2]  # the rkp/ directory
sys.path.insert(0, str(RKP / "tools"))

from teesim_attest import cbor, csr, keybox, plaintext, provisioning, revocation  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLES = Path(os.environ.get("TEESIM_ATTEST_SAMPLES", RKP / "samples"))


def _read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class Cbor(unittest.TestCase):
    def test_round_trip_is_canonical(self):
        value = {3: "A", 1: 43, -70000: None, "k": [1, 2, b"\x00"]}
        encoded = cbor.dumps(value)
        self.assertEqual(cbor.canonical_violations(cbor.load(encoded)), [])
        # Re-encoding a decoded canonical structure must reproduce the bytes exactly.
        self.assertEqual(cbor.dumps(cbor.load(encoded)), encoded)

    def test_detects_non_canonical_order(self):
        # {3: "A", 1: 43} written in that order: key 3 sorts after key 1.
        raw = b"\xa2" + cbor.dumps(3) + cbor.dumps("A") + cbor.dumps(1) + cbor.dumps(43)
        self.assertTrue(cbor.canonical_violations(cbor.load(raw)))

    def test_detects_duplicate_keys(self):
        raw = b"\xa2" + cbor.dumps(1) + cbor.dumps(1) + cbor.dumps(1) + cbor.dumps(2)
        self.assertIn("duplicate", " ".join(cbor.canonical_violations(cbor.load(raw))))

    def test_rejects_indefinite_length(self):
        with self.assertRaises(cbor.CborError):
            cbor.load(bytes.fromhex("bf0101ff"))

    def test_rejects_trailing_bytes(self):
        with self.assertRaises(cbor.CborError):
            cbor.load(cbor.dumps(1) + b"\x00")

    def test_negative_label_encoding(self):
        self.assertEqual(cbor.dumps_int(csr.TEST_KEY_LABEL).hex(), "3a0001116f")


class Provisioning(unittest.TestCase):
    def test_stock_baseline_is_not_flagged(self):
        info = provisioning.parse(
            cbor.dumps({1: provisioning.STOCK_CERTS_ISSUED, 3: "Xiaomi"})
        )
        self.assertEqual(info.certs_issued, provisioning.STOCK_CERTS_ISSUED)
        self.assertFalse(any(sev == "warn" for sev, _ in info.findings()))

    def test_512_is_flagged_against_the_baseline(self):
        info = provisioning.parse(cbor.dumps({1: 512, 3: "Xiaomi"}))
        self.assertEqual(info.certs_issued_ratio, 64.0)
        self.assertTrue(any(sev == "warn" for sev, _ in info.findings()))

    def test_not_approved_is_a_failure(self):
        info = provisioning.parse(
            cbor.dumps({1: 8, 3: "X", 5: {1: "NOT_APPROVED", 3: "NOT_APPROVED"}})
        )
        self.assertIs(info.provisioning_ok, False)
        self.assertTrue(any(sev == "fail" for sev, _ in info.findings()))

    def test_unknown_keys_are_preserved(self):
        info = provisioning.parse(cbor.dumps({1: 8, 3: "X", 99: "future"}))
        self.assertEqual(info.unknown, {99: "future"})

    def test_bound_versus_anonymous(self):
        anonymous = provisioning.parse(cbor.dumps({1: 8, 3: "X"}))
        bound = provisioning.parse(cbor.dumps({1: 8, 3: "X", 5: {4: "A/b/c:16/X/Y:user/release-keys"}}))
        self.assertFalse(anonymous.fingerprint_bound)
        self.assertTrue(bound.fingerprint_bound)


class Keybox(unittest.TestCase):
    def test_factory_shape_is_accepted(self):
        box = keybox.parse((FIXTURES / "keybox-factory.xml").read_text())
        self.assertEqual(box.shape, "factory (RSA + EC)")
        self.assertTrue(box.accepted, box.keys[0].problems)
        self.assertEqual(sorted(box.algorithms), ["ecdsa", "rsa"])

    def test_rkp_shape_is_ec_only_and_accepted(self):
        box = keybox.parse((FIXTURES / "keybox-rkp-stock.xml").read_text())
        self.assertEqual(box.shape, "rkp-provisioned (EC only)")
        self.assertTrue(box.accepted, box.keys[0].problems)

    def test_not_approved_keybox_is_rejected(self):
        box = keybox.parse((FIXTURES / "keybox-rkp-not-approved.xml").read_text())
        self.assertFalse(box.accepted)
        self.assertTrue(
            any("NOT_APPROVED" in p for p in box.keys[0].problems),
            box.keys[0].problems,
        )

    def test_mismatched_private_key_is_caught(self):
        box = keybox.parse((FIXTURES / "keybox-mismatched-key.xml").read_text())
        self.assertFalse(box.keys[0].private_matches_leaf)
        self.assertFalse(box.accepted)

    def test_clean_strips_invisibles_and_comments(self):
        dirty = '﻿<!-- c -->​<?xml version="1.0"?><AndroidAttestation/>'
        self.assertEqual(keybox.clean(dirty), '<?xml version="1.0"?><AndroidAttestation/>')

    def test_real_samples_parse_with_the_documented_shape(self):
        for name in ("rkp-keybox-sample-a.xml", "rkp-keybox-sample-b.xml"):
            path = SAMPLES / name
            if not path.is_file():
                self.skipTest(f"{name} not present")
            box = keybox.parse(path.read_text())
            with self.subTest(name=name):
                self.assertEqual(box.shape, "rkp-provisioned (EC only)")
                self.assertEqual(len(box.keys), 1)
                entry = box.keys[0]
                self.assertEqual(len(entry.chain), 4)
                self.assertTrue(entry.private_matches_leaf)
                self.assertTrue(entry.chain_links_ok)
                # The leaf's CN equals its own serial, and it carries the extension.
                leaf = entry.chain[0]
                self.assertIn(leaf.serial_hex.lower(), leaf.subject.lower())
                self.assertIsNotNone(leaf.provisioning)
                self.assertEqual(leaf.provisioning.certs_issued, 512)


class Containers(unittest.TestCase):
    def test_plaintext_round_trip_and_tail_detection(self):
        parsed = plaintext.parse_lengthprefixed(_read("container-plaintext.bin"))
        self.assertEqual(parsed.version, 1)
        self.assertEqual([e.algorithm for e in parsed.entries], ["ecdsa", "rsa"])
        self.assertEqual([len(e.certificates) for e in parsed.entries], [3, 3])
        self.assertEqual(parsed.tail_len, 92)

    def test_descriptor_payload_integrity(self):
        _descriptor, parsed, notes = plaintext.parse_descriptor_payload(
            _read("container-descriptor.bin"), _read("container-payload.bin")
        )
        joined = " ".join(notes)
        self.assertIn("magic 0x12345678 OK", joined)
        self.assertIn("matches the payload", joined)
        self.assertEqual(parsed.tail_len, 0)

    def test_wrong_magic_is_rejected(self):
        with self.assertRaises(plaintext.FormatError):
            plaintext.parse_descriptor(b"\xde\xad\xbe\xef" + bytes(164))

    def test_garbage_is_rejected_not_guessed(self):
        with self.assertRaises(plaintext.FormatError):
            plaintext.parse_lengthprefixed(b"\x01\x00\x00\x00" + b"\xff" * 400)

    def test_der_length_rejects_indefinite_and_non_minimal(self):
        self.assertIsNone(plaintext.der_length(b"\x30\x80\x00\x00"))
        self.assertIsNone(plaintext.der_length(b"\x30\x81\x7f" + bytes(0x7F)))
        self.assertEqual(plaintext.der_length(b"\x30\x03\x01\x01\x00"), 5)

    def test_truncated_payload_is_flagged_not_silently_accepted(self):
        # Half a buffer still parses as a shorter valid one, so the contract is not that it
        # raises -- it is that the leftover is reported as suspicious rather than as residue.
        data = _read("container-payload.bin")
        parsed = plaintext.parse_lengthprefixed(data[: len(data) // 2])
        self.assertTrue(parsed.tail_is_suspicious)
        self.assertTrue(any("stopped early" in n for n in parsed.notes()), parsed.notes())

    def test_genuine_residue_is_not_flagged(self):
        parsed = plaintext.parse_lengthprefixed(_read("container-plaintext.bin"))
        self.assertEqual(parsed.tail_len, 92)
        self.assertFalse(parsed.tail_is_suspicious)
        self.assertTrue(any("input residue" in n for n in parsed.notes()), parsed.notes())

    def test_mid_object_truncation_raises(self):
        # Cutting inside a declared object is a hard error: the prefix and the DER header
        # disagree, which is exactly the check that stops a wrong interpretation.
        data = bytearray(_read("container-payload.bin"))
        data[4:8] = (len(data) * 4).to_bytes(4, "little")
        with self.assertRaises(plaintext.FormatError):
            plaintext.parse_lengthprefixed(bytes(data))


class Csr(unittest.TestCase):
    def test_proper_request_verifies(self):
        result = csr.verify(_read("csr-proper.cbor"))
        self.assertTrue(result.ok, result.failures)
        self.assertFalse(result.warnings, result.warnings)

    def test_degenerate_chain_verifies_but_warns(self):
        result = csr.verify(_read("csr-degenerate-dice.cbor"))
        self.assertTrue(result.ok, result.failures)
        self.assertTrue(any("degenerate" in w for w in result.warnings), result.warnings)

    def test_envelope_must_be_unwrapped(self):
        wrapped = _read("csr-envelope.cbor")
        self.assertFalse(csr.verify(wrapped).ok)
        inner = cbor.load(wrapped).get(61)
        self.assertTrue(csr.verify(inner).ok)

    def test_foreign_device_info_field_is_rejected(self):
        result = csr.verify(_read("csr-foreign-field.cbor"))
        self.assertFalse(result.ok)
        self.assertTrue(any("'version'" in f for f in result.failures), result.failures)

    def test_identity_key_may_not_be_certified(self):
        result = csr.verify(_read("csr-identity-reused.cbor"))
        self.assertFalse(result.ok)
        self.assertTrue(
            any("identity key itself" in f for f in result.failures), result.failures
        )

    def test_non_canonical_payload_is_rejected(self):
        result = csr.verify(_read("csr-non-canonical.cbor"))
        self.assertFalse(result.ok)
        self.assertTrue(
            any("canonical" in f for f in result.failures), result.failures
        )

    def test_tampered_signature_is_rejected(self):
        data = bytearray(_read("csr-proper.cbor"))
        data[-1] ^= 0xFF
        result = csr.verify(bytes(data))
        self.assertFalse(result.ok)


class Revocation(unittest.TestCase):
    def test_both_serial_encodings_match(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "status.json"
            cache.write_text(
                json.dumps(
                    {
                        "entries": {
                            "c35747a084470c3135aeefe2b8d40cd6": {
                                "status": "REVOKED",
                                "reason": "KEY_COMPROMISE",
                            },
                            "6681152659205225093": {
                                "status": "REVOKED",
                                "reason": "KEY_COMPROMISE",
                            },
                        }
                    }
                )
            )
            status = revocation.fetch(cache=cache, offline=True)
            report = revocation.check(
                [
                    int("c35747a084470c3135aeefe2b8d40cd6", 16),
                    6681152659205225093,
                    12345,
                ],
                status,
            )
            self.assertEqual(len(report.revoked), 2)
            self.assertEqual(report.counts_by_form(), {"hex": 1, "decimal": 1})

    def test_offline_without_cache_raises(self):
        with self.assertRaises(revocation.RevocationUnavailable):
            revocation.fetch(cache=None, offline=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
