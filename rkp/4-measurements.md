# 4. Measurements

Index: [the index](README.md). Companion parts: [part 1](1-protocol.md), [part 2](2-mechanisms.md),
[part 3](3-detection.md), [part 5](5-sources.md).

## Abstract

This part reports the empirical basis of the report under four headings. *Certificate validity* is a
class discriminator: measured leaf lifetimes are about 13 days for stock provisioning, 14 to 15 days
for two leaked provisioned keyboxes, and about ten years for factory batch keyboxes, with the two
populations rooted at different anchors. *The provisioning-information extension* under [object
identifier](https://www.itu.int/rec/T-REC-X.660) `1.3.6.1.4.1.11129.2.1.30` is decoded byte for byte
from both leaked samples and compared against the only schema Google publishes, which documents two
of the four labels observed; the issuance counter it carries reads 512 on both samples against a
stock baseline of 8 measured on a handset of the model one of them names. *Populations* are
censused: 551 public factory keyboxes contain no provisioned keybox at all, and 980 of the 1,744
entries in the leaf revocation list on the day of measurement are serials from that single corpus,
so 56 per cent of a global revocation list is explained by one leak. *The measured platform* is
characterised directly from vendor binaries and a secure-operating-system image: the handset at the
centre of this report runs a [Zircon](https://fuchsia.dev/fuchsia-src/concepts/kernel)
[microkernel](https://en.wikipedia.org/wiki/Microkernel) in the secure world rather than an
[OP-TEE](https://optee.readthedocs.io/) core, which excludes an entire published vulnerability
inventory from applying to it, and the
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/) secret it holds is
a created-once persisted object with a storage migration that can fail open. Threats to validity are
in [§7](#7-threats-to-validity), and [§8](#8-refutation-conditions) states what would refute each
principal claim.

---

## 1. Method

### 1.1 Definitions

A quantity is reported as *measured* where a command in [§5](#5-reproduction) produces it on the
artifacts named in [§1.2](#12-artifacts), or where a cited record contains it as an artifact read
directly rather than narrated. Where a quantity derives from a research record whose execution was
not re-run, the text attributes it to that record and the ambiguity is retained rather than averaged
away. Inferences are marked as inferences at the point of use.

Three things are absent by design. No private key material appears, including private scalars that a
cited source published in full ([part 1 §1.3](1-protocol.md#13-scope-and-conventions)). No
reproduction step requires a private working tree: every command in [§5](#5-reproduction) runs
against an artifact in this repository, a stock handset, or a public endpoint. And nothing in
[§5](#5-reproduction) contacts a provisioning endpoint; no certificate request was submitted in the
course of compiling this report.

### 1.2 Artifacts

Two keybox files are the primary artifacts, referred to as sample A and sample B. They are not
carried in this repository, since they contain live private keys that [§1.1](#11-definitions)
excludes. Their identity is fixed by digest so that any claim here can be checked against an
independently obtained copy: sample A is 5,993 bytes with
[SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) `4c1fd429…5b26c3`, sample B
5,690 bytes with SHA-256 `f87306c3…925aa5`.

Two measurement sessions stand behind this record, about five weeks apart. The earlier covers the
samples, the populations and the platform forensics of [§6](#6-the-measured-platform); the later
covers the field routes, the stock baseline and a re-measured revocation list. Where the two
disagree the later governs, and the earlier reading is recorded as withdrawn rather than deleted;
[§3.4](#34-corrections-to-earlier-readings) is that list.

One integrity note bears on [§6](#6-the-measured-platform). The binaries measured there total
approximately 770 MB and were not preserved; they are re-fetchable from the public sources named
inline, and the session record pins each by size and SHA-256 so that a re-fetch can be verified
rather than assumed. The environment image is 4,075,520 bytes with SHA-256 `eae7dc96…c326ef`; the
[KeyMint](https://source.android.com/docs/security/features/keystore) application 1,401,936 bytes,
`1a96c549…4d46614`; the KeyMint HAL 148,585 bytes, `189564b9…fde5e6`; the keybox-installer library
149,241 bytes, `633b530b…001a8d4`; and its consumer daemon 15,824 bytes, `6d48a4b4…c5f5517`.

### 1.3 Excluded detail

Route-operative constants — patch offsets, original instruction bytes and code-cave addresses — are
not reproduced, for the reason [part 2 §1.3](2-mechanisms.md#13-withheld-detail) gives: the shape of
a patched decision is the finding and its address is not. Seeds appear by digest fingerprint only.
The container-unwrapping RSA private factors recovered by one cited source are not reproduced; their
presence, location and bit length are the measurement ([part 2
§5.2](2-mechanisms.md#52-the-application-container)).

---

## 2. Two leaked provisioned keyboxes

Both are keybox files carrying one EC key and no RSA key, consistent with provisioning being
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)-only and
structurally distinguishable from a factory keybox, which carries an RSA key as well.

### 2.1 Leaf validity by material class

| Material | Leaf validity span |
|---|---|
| Sample A, provisioned | 14 d 8 h 01 m 24 s |
| Sample B, provisioned | 15 d 3 h 16 m 38 s |
| Stock issuance, measured on a handset by a cited record | ≈ 12 d 23 h |
| Factory keybox recovered from a trusted application | ≈ 10 years |
| Public factory-keybox corpus, 551 files | ≈ 10 years throughout |

Two readings follow. Leaf expiry is not pinned to a shared batch epoch in the provisioned
population: the two samples' spans differ by about 19 hours, so the value is approximately issuance
plus two weeks plus jitter rather than a fixed date. And the gap between the two populations spans
three orders of magnitude, which is what makes the conclusion of [§4.3](#43-derived-quantities)
about revocation structural rather than incidental.

### 2.2 Shared chain positions

Positions 2 through 4 are byte-identical across both samples:

| | Subject | Serial | Key | Validity span | SHA-256 |
|---|---|---|---|---|---|
| CA3 | `O=Google LLC, CN=Droid CA3` | `344B69CE…427C` | P-256 | ≈ 10 weeks | `8BC7B36F…6A38` |
| CA2 | `O=Google LLC, CN=Droid CA2` | `92425019…85FB` | P-384 | 3 years | `B8B0741E…1632` |
| root | `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` | `84A9D029…0605` | P-384 | 10 years | `6D9DB4CE…BCC0` |

The span of the issuing intermediate matters: it turns over on a scale of weeks, so an archived
chain names an instance that no longer signs. That is a second, independent clock on a hoarded chain
beyond the leaf's own two weeks.

The root is byte-identical to the EC root pinned in
[`app/.../RootPublicKey.kt`](../app/src/main/java/org/matrix/teesim/RootPublicKey.kt), so this
project's inspector already classifies these chains as Google-rooted, and [`openssl
verify`](https://docs.openssl.org/master/man1/openssl-verify/) passes for both.

That same root digest, `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0`, was
independently recorded as matching Google's published root in the stock-issuance acceptance record
of [§3.3](#33-issuance-counts), on a different handset and by a different party. It is the one
anchor in this report confirmed from two directions.

Shared intermediates carry almost no evidential weight. The backend returns a shared portion
together with a unique leaf per key ([part 1 §5.2](1-protocol.md#52-the-protocol-exchange)), so the
two intermediates and the root constitute one block handed to every requester in that issuing epoch,
and agreement between two samples is not evidence of common origin.

The factory population roots elsewhere: at the RSA root whose subject serial number is
`f92009e853b6b045`, across four distinct root serials in the 551-file corpus
([§4.1](#41-the-public-factory-corpus)). That same serial appears at the end of the factory keybox
recovered in [part 2 §5.6](2-mechanisms.md#56-acceptance-record), which independently places that
material in the factory population.

### 2.3 Revocation state of the hierarchy

Only the second intermediate carries a revocation-list distribution point,
[`android.googleapis.com/attestation/key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl).
On one live fetch the list is at number 0, with a one-year publication interval and zero revoked
entries. The intermediate tier of the provisioning hierarchy has never been revoked.

Leaf revocation is not list-based in that sense. It operates through
[`android.googleapis.com/attestation/status`](https://android.googleapis.com/attestation/status),
where neither sample leaf appears, checked against the live list of 1,744 entries at the time of
measurement ([§4.2](#42-revocation-list-snapshots)).

### 2.4 Structural fields of the leaves

Both leaves are EC P-256 with `ecdsa-with-SHA256`; both carry `CA:TRUE` marked critical; both carry
key usage `keyCertSign` only; the private key in each file matches its leaf's public key; and the
leaf serial equals its own common name — sample A's subject is `O=TEE,
CN=feaf1c15bef625ef4b0383ce55213dc4` with serial `FEAF1C15…3DC4`, sample B's `O=TEE,
CN=344dc9148ccb0cc561b4983543e9678b` with serial `344DC914…678B`.

Absent from both: any `1.3.6.1.4.1.11129.2.1.17` key-description extension, these being signing
authorities rather than attestation leaves, and any subject alternative name, extended key usage,
authority information access or path-length constraint.

The subject organisation is where the security level surfaces. It follows from the device
information's security-level field ([part 1 §2.6](1-protocol.md#26-device-self-description)), which
is also why the extension's own validated-attested-entity label is absent: the claim is already
carried in the subject ([§3.2](#32-label-dictionary)).

Both samples were issued five days apart by the same issuing intermediate, same brand, different
identities. That is suggestive of one source or one technique, but the intermediate serves global
issuance, so it is weak circumstantial evidence rather than proof of common origin. Section [part 5
§5.2](5-sources.md#52-byte-exact-attribution) establishes common origin by a different route, from
the file bytes.

---

## 3. The provisioning-information extension

### 3.1 Published schema and observed encodings

Google publishes [two
labels](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension):

```cddl
{
      1 : int,       ; certificates issued
      4 : string,    ; validated attested entity (STRONG_BOX / TEE)
}
```

with the explicit note that the map is unversioned and may gain optional fields.

Sample A's extension is 186 octets:

```
a3                              map(3)
  01  19 0200                   1 : 512
  03  66 5869616f6d69           3 : "Xiaomi"
  05  a4                        5 : map(4)
      01  68 415050524f564544     1 : "APPROVED"
      02  78 40 "4d7dbe17…fa65"   2 : "4d7dbe175510629ec6b2e9b725dfbc7fd54199cbae8058f0a8ee1eb61ab2fa65"
      03  68 415050524f564544     3 : "APPROVED"
      04  78 51 "Redmi/…keys"     4 : "Redmi/duchamp/duchamp:16/BP2A.250605.031.A3/OS3.0.303.0.WNLCNXM:user/release-keys"
```

Sample B's extension is 13 octets in its entirety:

```
a2  01 19 0200  03 66 5869616f6d69        {1: 512, 3: "Xiaomi"}
```

Label 5.2 is a text string of 64 lowercase hexadecimal characters rather than a byte string: a
32-byte digest re-encoded as text by the backend. A decoder expecting a byte string there will fail
on a valid certificate.

The size difference, 186 against 13 octets, is interpreted at the end of
[§3.2](#32-label-dictionary).

### 3.2 Label dictionary

*Label 1, certificates issued.* Documented. Observed as 512 in both samples and 8 on a stock
handset. Google's description: *an approximate number of certificates issued to the device in the
last 30 days. This value can be used as a signal for potential abuse if the value is greater than
average by some orders of magnitude.* Section [§3.3](#33-issuance-counts) supplies the average.

*Label 3.* Undocumented. Observed as `"Xiaomi"` in both: the manufacturer on record at the backend,
brand only and no model.

*Label 4, validated attested entity.* Documented, and absent from both samples. Google's
description: *a string indicating the certified origin of the attested key, directly vouched for by
the chipset manufacturer. For example, STRONG_BOX or TEE.* The same claim is carried instead in the
leaf subject ([§2.4](#24-structural-fields-of-the-leaves)), and the absence is consistent with both
requests having carried an empty certification map ([part 1
§2.7](1-protocol.md#27-certification-of-the-device-secret-public-key)).

*Label 5.* Undocumented, present only in sample A, a four-entry map. Sub-label 1 is a verdict of
approval; sub-label 2 the 32-byte digest as hexadecimal text; sub-label 3 a second, independent
verdict, also of approval; sub-label 4 a build fingerprint.

Label 5 reads structurally as two verdict-and-subject pairs, 5.1 with 5.2 and 5.3 with 5.4, the
backend recording that it validated two attributes and approved both. That pairing is an inference
from the ordering; only the content of 5.4 is self-evident.

The verdicts are not constants. They were initially catalogued as observed approvals, as though
fixed; an independent record shows a `NOT_APPROVED` verdict being issued and being dispositive
([part 2 §6.6](2-mechanisms.md#66-a-causal-correction)). They are live varying fields, which is what
makes a decoder that drops them a verifier fault rather than a cosmetic omission.

The presence of label 5 is a property of the request rather than of the device: sample B's 13-octet
extension omits it because the submission omitted the fields that trigger it, most plausibly a
difference in configuration completeness within the same tooling. Both samples are the same brand,
issued five days apart by the same intermediate, and only one carries it.

Label 5.4 is not provenance. The build fingerprint is client-supplied and unsigned: the provisioning
daemon appends it after the application signs, as an unverified map in
[`CborUtils.buildUnverifiedDeviceInfo`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java),
and the tool that produced both samples sends it to the endpoint-key endpoint as a two-field map
from a value the operator typed into a configuration file. Section
[§3.4](#34-corrections-to-earlier-readings) records the correction this forced.

The pairing therefore reads: the client asserts a fingerprint in 5.4; the backend resolves it
against its own build census and records the digest it found in 5.2, marking both approved. Label
5.2 is thus most plausibly the verified-boot metadata digest of the named build, build-scoped rather
than device-scoped, but it is what the backend looked up and not what the device reported. No device
identity leaks through it.

Three experiments would confirm that 5.2 is build-scoped, of which the first is cheapest: on any
handset of the exact model and build named in 5.4, read `ro.boot.vbmeta.digest`, or take any
attestation and read the verified-boot hash that this project's
[`Harvester.kt`](../app/src/main/java/org/matrix/teesim/Harvester.kt) already captures, equality
confirming it. Alternatively, compare 5.2 across two label-5-bearing certificates from different
devices on the same build, where equality implies build scope, or across one device's certificates
spanning an [update](https://source.android.com/docs/core/ota), where the value should change.

### 3.3 Issuance counts

Both samples read 512, which is 2⁹, on two different identities five days apart. Values reported
elsewhere are 8, 32 and 64. All five observations are powers of two, which suggests a logarithmic
bucket rather than a literal count, on five observations.

*The stock baseline.* On a stock Redmi K70E before any patching, the extension read `{1: 8, 3:
"Xiaomi"}`. The same acceptance record notes 12 certificates returned in that one batch, a leaf
validity of about 12 days and 23 hours, a root digest matching Google's published root, and a
275-byte opaque stored private key that is neither [PKCS#8](https://www.rfc-editor.org/rfc/rfc5958)
nor a P-256 scalar ([§4.4](#44-holdings-of-a-stock-device)).

Four conclusions follow.

*The count is not a fixed pool cap.* A third value exists and it is 8. The earlier reading of 512 as
more a pool cap than an organic count, which was reasonable on two identical observations, is
withdrawn ([§3.4](#34-corrections-to-earlier-readings)). The label behaves as documented.

*A stock device reads single digits.* The leaked samples read 512, approximately 64 times the stock
baseline, on the same brand, on the device model sample A's own fingerprint names, in the same
30-day window. Google's documentation frames the label as a signal where the value exceeds the
average by orders of magnitude; this gives the average a measured value.

*Under every reading both samples are extreme.* The daemon's own default target is
`EXTRA_SIGNED_KEYS_AVAILABLE_DEFAULT = 6` in
[`Settings.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java).
The documented abuse signal was saturated inside the signed certificate while issuance proceeded.

*Three counters are routinely conflated, and all three appear in that one record.* Twelve is the
number of certificates in one batch; eight is the approximate 30-day issuance count, backend-written
and signed; two is a same-day local counter in the device's own statistics file, unsigned. Only the
middle one appears in the certificate and only it is visible to a relying party. Batch size and
issuance count are different quantities and cannot be divided into each other, which is why the
conjecture that 512 implies a particular mint rate is not advanced ([part 2
§10.3](2-mechanisms.md#103-conjectures-not-advanced)).

### 3.4 Corrections to earlier readings

Each of the following was measured after an earlier reading and overturns it. They are recorded
rather than silently applied.

*The direction of resolution of label 5.2 was inverted.* The earlier reasoning ran that because the
device information carries no build fingerprint, the backend must be resolving a submitted
verified-boot digest against a build database in order to produce 5.4. The direction is the reverse:
the client supplies the fingerprint, unsigned, and the backend resolves from it
([§3.2](#32-label-dictionary)). This was established from [AOSP](https://source.android.com/) code
and the producing tool's own source.

*The device-identifier attribute is packaging metadata rather than device identity.* The attribute
`DeviceID="Xiaomi-02f7c61fec6d"` is the manufacturer string plus six random bytes, generated by the
producing tool ([part 5 §5.2](5-sources.md#52-byte-exact-attribution)). It is not a hardware address
and carries no device identity. Provenance comes from the extension rather than from the attribute.

*The distinction between anonymous and fingerprint-bound keyboxes is a property of the operator's
configuration* rather than of a donor handset. A keybox whose extension lacks label 5 constrains
nothing and pairs with any profile; one carrying label 5 pins the presented identity, because a
verifier reading 5.4 sees a specific build string and the profile must present that device or
contradict itself in a signed field. Anonymous keyboxes are therefore preferable, and where a keybox
is bound the profile should be seeded from 5.4 — while remembering that bound-ness indicates nothing
about where the key came from.

*The reading of 512 as a pool cap is withdrawn*, per [§3.3](#33-issuance-counts).

*The verdict labels are live rather than constant*, per [§3.2](#32-label-dictionary).

*One mandatory field was omitted and the request was signed regardless.* The producing tool's
default device information omits the verified-boot metadata digest, which
[`DeviceInfoV3.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV3.cddl)
makes mandatory. A genuine KeyMint application cannot omit it. Sample B's request was therefore not
produced by one: an independent confirmation of its software origin that does not rely on the byte
match of [part 5 §5.2](5-sources.md#52-byte-exact-attribution), and simultaneously a measurement
that the [grammar](https://www.rfc-editor.org/rfc/rfc8610) constraint is not enforced server-side.

---

## 4. Populations

### 4.1 The public factory corpus

All 551 files of the scraped public keybox pool were parsed, of which 533 are UTF-16LE with a
[byte-order mark](https://www.unicode.org/faq/utf_bom.html), which is a parsing trap, since a naïve
UTF-8 read silently yields nothing.

All 551 parse; zero carry an issuer in the provisioning hierarchy; zero carry object identifier
`1.3.6.1.4.1.11129.2.1.30`. The two populations do not overlap at all.

549 of 551 carry both EC and RSA keys, against the provisioned samples' EC-only shape. All leaf
spans are about ten years, and their issuance years cluster: a single year accounts for 316 of the
551 files, with the remainder spread thinly across eight other years, which is the shape of a few
bulk leaks rather than a steady trickle. Chains root at the RSA root across four distinct root
serials, where the provisioned samples root at the EC root.

Two structural findings concern the corpus itself. There are 89 distinct intermediate batch
authorities across 551 chains, approximately 5.5 keys per authority, which is the signature of a
handful of factory-file leaks rather than of diffuse per-device extraction. And there are 490
distinct key sets among 551 files, so 61 are duplicates resold, with 979 distinct private keys of
which 117 are reused across files, the maximum reuse being three. The device-identifier watermarks
concentrate accordingly: one scraper's domain appears 527 times, with four other labels accounting
for 24 files between them.

The leaked provisioned keyboxes are therefore a different population from every keybox in the known
public pool, which is what makes the revocation finding of [§4.3](#43-derived-quantities)
interpretable.

### 4.2 Revocation-list snapshots

Measured live together with [Wayback Machine](https://web.archive.org/) snapshots of the status
endpoint. Serials are bucketed by encoding, because the list is inconsistent: decimal strings for
serials up to 64 bits, hexadecimal for 16-byte ones.

Snapshots are listed oldest first, with the interval to the previous one; each is linked so that the
timestamp it carries can be read from the address rather than from this table.

| Snapshot | Interval | Total | ≤ 20 chars (decimal, ≤ 64-bit) | ≥ 30 chars (hex, 16-byte) |
|---|---|---|---|---|
| [1](https://web.archive.org/web/20240622033556id_/https://android.googleapis.com/attestation/status) | — | 94 | 39 | 55 |
| [2](https://web.archive.org/web/20241205133200id_/https://android.googleapis.com/attestation/status) | +5½ months | 467 | 161 | 306 |
| [3](https://web.archive.org/web/20250612190743id_/https://android.googleapis.com/attestation/status) | +6 months | 517 | 177 | 340 |
| [4](https://web.archive.org/web/20251220091647id_/https://android.googleapis.com/attestation/status) | +6 months | 1604 | 950 | 654 |
| [5](https://web.archive.org/web/20260706064827id_/https://android.googleapis.com/attestation/status) | +6½ months | 1720 | 962 | 758 |
| [6](https://web.archive.org/web/20260901160025id_/https://android.googleapis.com/attestation/status) | +2 months | 1742 | 974 | 768 |
| 7, live | +1 week | 1744 | 974 | 770 |
| 8, re-measured | +5½ weeks | 1761 | 981 | 780 |

Reasons given at snapshot 7: key compromise 1,718 times, software flaw 26 times.

### 4.3 Derived quantities

*One surge is one leak.* The increase from 177 to 950 in the 64-bit population across snapshots 3
and 4, a single six-month interval, coincides with the public scrape of the factory pool censused in
[§4.1](#41-the-public-factory-corpus).

980 of the 1,744 entries at snapshot 7 are serials that appear in that one 551-file corpus: 56 per
cent of the global revocation list explained by a single public leak. Snapshot 8 independently
reproduces the proportion five and a half weeks later, with 1,761 entries of which 780 contain
hexadecimal letters and 981 are digits only, giving 55.7 per cent.

Growth over the final year of the series runs at approximately 13 entries per month, all in the
16-byte population.

The inference this supports is that the revocation list is structurally the wrong lever against
provisioning-derived keyboxes. A fourteen-day leaf expires faster than a revocation cycle notices
it; neither sample leaf is listed; and the provisioning hierarchy's own revocation list is empty
([§2.3](#23-revocation-state-of-the-hierarchy)). The effective lever is removal of the device secret
public key from the provisioning registry, a backend edit invisible to any certificate-based
mechanism.

This is also where the two populations diverge operationally rather than cryptographically. A
factory batch key is long-lived and therefore reachable by revocation, at the cost of disabling
attestation for a whole production run. A provisioned leaf is short-lived and therefore unreachable,
while the identity behind it is revocable without touching any certificate. Both properties follow
from leaf lifetime ([§2.1](#21-leaf-validity-by-material-class)).

### 4.4 Holdings of a stock device

Two facts bound what the ordinary provisioning path can yield, and they are why [part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret) requires a patched
environment at all.

*The stored key is not exportable.* The private key banked by the system path on the measured stock
handset is a 275-byte opaque blob usable only by that device's KeyMint: neither PKCS#8 nor a P-256
scalar. The exportable identity is simply not in the database, on two independently measured
devices.

*The derivation label is per-vendor.* Three platforms use three labels: `rkp_bcc_km` is the live
production argument on [Trustonic Kinibi](https://www.trustonic.com/) and is absent from every
measured binary of the platform in [§6.3](#63-storage-of-the-dice-secret), while Qualcomm KeyMint
derives from `"RKP PRIVATE KEY SEED"` ([part 2
§3.2](2-mechanisms.md#32-derivation-and-storage-of-the-leaf-secret), [part 2
§4.5](2-mechanisms.md#45-the-derivation-call-site-and-its-label) and [part 2
§9.3](2-mechanisms.md#93-scope-of-the-label-measurement)).

---

## 5. Reproduction

### 5.1 Decoding a keybox and its extension

Split a keybox file into [PEM](https://www.rfc-editor.org/rfc/rfc7468) objects, then read them:

```bash
python3 - <<'PY'
import re
d = open('keybox.xml').read()
for i, (t, b) in enumerate(re.findall(r'-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----', d, re.S)):
    body = "".join(l.strip() for l in b.strip().splitlines())
    open(f'obj{i}.pem', 'w').write(
        f'-----BEGIN {t}-----\n' + "\n".join(body[j:j+64] for j in range(0, len(body), 64))
        + f'\n-----END {t}-----\n')
PY

openssl x509 -in obj1.pem -noout -text       # the leaf, including the provisioning extension as hex
openssl asn1parse -in obj1.pem               # the extension payload follows the object identifier
```

Chain verification requires both intermediates in one file, which is the common mistake, since the
`-untrusted` option takes a file rather than a repeated flag:

```bash
cat obj2.pem obj3.pem > chain.pem                # the two intermediates
openssl verify -CAfile obj4.pem -untrusted chain.pem obj1.pem
```

For the revocation-list state of [§2.3](#23-revocation-state-of-the-hierarchy):

```bash
curl -s https://android.googleapis.com/attestation/key_ca1.crl -o key_ca1.crl
openssl crl -inform DER -in key_ca1.crl -noout -text | head -20
```

### 5.2 On-device measurements

The cheapest high-value experiment available, and the one that would confirm the baseline of
[§3.3](#33-issuance-counts) from a second source. On any stock handset:

```bash
adb shell cmd remote_provisioning csr          # emits a certificate request and provisioned leaves
# then decode the returned leaves' extension as in §5.1
```

A single-digit issuance count on an ordinary device confirms the baseline independently of the
research corpus.

For the cheapest discriminating test of label 5.2, on a handset of the exact model and build:

```bash
adb shell getprop ro.boot.vbmeta.digest        # compare against the 64 hex characters of label 5.2
```

### 5.3 Population measurements

The revocation list, live and historical:

```bash
curl -s https://android.googleapis.com/attestation/status -o status.json
curl -s "http://web.archive.org/cdx/search/cdx?url=android.googleapis.com/attestation/status\
&output=json&fl=timestamp,length,digest&collapse=digest&limit=200" -o cdx.json
curl -sL "https://web.archive.org/web/<TIMESTAMP>id_/https://android.googleapis.com/attestation/status" \
     -o snapshot.json
```

Bucket the entry keys by length: at most 20 characters is a decimal-encoded serial of at most 64
bits, at least 30 is a hexadecimal 16-byte serial. Both forms must be tested when matching a leaf,
which is what [`tools/teesim_attest/revocation.py`](tools/teesim_attest/revocation.py) does.

For a corpus of keybox files, note the encoding trap of [§4.1](#41-the-public-factory-corpus):

```python
def read(path):                      # most files in the public pool are UTF-16LE with a BOM
    b = open(path, 'rb').read()
    for enc in ('utf-16', 'utf-8-sig', 'utf-8', 'latin-1'):
        try:
            s = b.decode(enc)
            if 'AndroidAttestation' in s:
                return s
        except Exception:
            pass
    return b.decode('latin-1')
```

### 5.4 Experiments that would settle a claim

*The issuance baseline*, per [§5.2](#52-on-device-measurements), would move
[§3.3](#33-issuance-counts) from one record to independent confirmation.

*Seed survival across a factory reset* is the weakest claim in the report that carries weight, being
an inference that supports the supply-against-sample argument of [part 2
§7.2](2-mechanisms.md#72-persistence-of-the-seed). It requires any Android handset: emit a
certificate request, record the device secret public key, perform a factory reset, and re-read. A
changed public key would refute it.

*Route A's surface, without exercising it*, is read-only on any Qualcomm handset:

```bash
ls -l /dev/smcinvoke /vendor/lib64/libkeymasterdeviceutils.so
nm -D --defined-only /vendor/lib64/libkeymasterdeviceutils.so | grep send_cmd
```

Presence of the device node and the symbol establishes the reachable surface of [part 2
§3.3](2-mechanisms.md#33-the-command-channel-below-the-hal). Nothing need be invoked.

### 5.5 The toolkit

Every acceptance relation of [part 3 §1](3-detection.md#1-acceptance-criteria) and every threshold
of [§3.3](#33-issuance-counts) is implemented in [`tools/`](tools/) as `teesim-attest`, with 34
tests requiring neither network nor device:

```bash
cd tools && python3 -m unittest discover -s tests -q
./teesim-attest verify     keybox.xml     # the two chain layers; exits 1 if it would not be accepted
./teesim-attest inspect    keybox.xml     # decodes the extension, compares the count against 8
./teesim-attest unpack     payload [--descriptor d]   # length-prefix and DER, tail residue classified
./teesim-attest verify-csr request.cbor   # chain walk, canonical encoding, device-information domains
./teesim-attest revocation keybox.xml     # both serial encodings, per-form counts
./teesim-attest baseline                  # every constant with its provenance
```

Run against the two samples, `inspect` reproduces the finding of [§3.3](#33-issuance-counts) from
the files themselves: both read an issuance count of 512, 64 times the stock baseline. Note that
`pytest` is not required and may not be installed; the suite is plain
[`unittest`](https://docs.python.org/3/library/unittest.html).

---

## 6. The measured platform

The handset at the centre of this report, a Redmi K70E, codename `duchamp`, on
[MediaTek](https://www.mediatek.com/) MT6897, is characterised here directly from vendor binaries
and a secure-operating-system image. It is the handset Route D targets ([part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret)), and it is the device
model named in sample A's provisioning extension
([§3.1](#31-published-schema-and-observed-encodings)). The determination of
[§6.2](#62-identification-of-the-secure-operating-system) excludes an entire published vulnerability
inventory from applying to it, which is a reusable result about reading vulnerability lists against
a platform.

### 6.1 Handset and environment census

The device is the [Redmi K70E](https://www.gsmarena.com/redmi_k70e-12716.php), China model
`2311DRK48C`, sold globally as the [POCO X6 Pro
5G](https://www.gsmarena.com/xiaomi_poco_x6_pro-12751.php), on a MediaTek [Dimensity
8300-Ultra](https://www.mediatek.com/), MT6897.

A census of all 1,902 files in the public vendor tree
[`mt6897-devs/vendor_xiaomi_duchamp`](https://github.com/mt6897-devs/vendor_xiaomi_duchamp) at
`lineage-23.2` returns 43 hits for the vendor environment name; zero for five other environment
names including Beanpod and Trustonic Kinibi. OP-TEE's normal-world userspace, comprising the
supplicant and the client library, is present, as is a hypervisor image.

The KeyMint HAL embeds its own build paths, which name OP-TEE's example tree verbatim. Its trusted
application begins with a three-byte magic followed by the environment name, and its strings carry a
porting layer — a keymaster context, a remote-provisioning context, secure-deletion storage and a
storage manager — wrapping Google's reference keymaster implementation. The vendor interface
manifest declares KeyMint [AIDL](https://source.android.com/docs/core/architecture/aidl) version 3
with both the device and remotely provisioned component instances, and no
[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox) instance;
the application itself carries a string stating that StrongBox is unsupported.

That last fact bears on two conclusions: it is why the [test
suite](https://source.android.com/docs/core/tests/vts) multi-stage requirement does not apply to
this handset ([part 2 §7.1](2-mechanisms.md#71-the-procedure-gate-by-gate)), and why a degenerate
chain is a conforming request there rather than a malformed one ([part 1
§4.5](1-protocol.md#45-legal-chain-shapes-and-deployment-phases)).

Correspondence between the public vendor tree and real firmware is established by hash rather than
by assumption. The [LineageOS](https://lineageos.org/) tree is a community extraction carrying no
manifest and no build properties, with only one commit naming a source build. [Blob
identifiers](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) from it were compared against
four independent stock firmware dumps on
[`dumps.tadiphone.dev`](https://dumps.tadiphone.dev/dumps/redmi/duchamp), which are region-specific
images from a separate provenance chain. The invariant applications match exactly across both
sources while those that churn differ between them, which is the pattern expected where the tree
tracks real firmware and those applications are genuinely rebuilt per release
([§6.6](#66-the-application-container)).

This establishes correspondence between tree and firmware. It does not establish any correspondence
between this handset and the leaked samples; see [part 2
§10.3](2-mechanisms.md#103-conjectures-not-advanced).

### 6.2 Identification of the secure operating system

The proposition that this environment is an OP-TEE derivative is true only of its normal-world stack
and its interface surface. The secure world is something else, and the distinction decides which
published vulnerabilities can apply at all.

Parsing the dynamic segment directly out of each application's
[ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) object — necessary because the images have
no section headers, so standard tools return nothing and the symbol table must be walked through the
dynamic entries — shows that every one of six examined applications, KeyMint included, lists the
standard C library, the Fuchsia input-output library, the Zircon system library and an asynchronous
dispatch library; imports 27 to 28 Zircon system calls; and imports no
[GlobalPlatform](https://globalplatform.org/specs-library/tee-internal-core-api-specification/)
symbols whatsoever.

The [imported calls](https://fuchsia.dev/reference/syscalls) span the whole capability model:
virtual memory object read, write and mapping; channel read, write and call; ports and asynchronous
waits; handle management; exception binding and resumption; clocks and timers; a cryptographic
random draw; feature queries; and a guest trap.

The secure-operating-system image settles the question outright. The environment partition carries a
vendor header naming it as [Trusted Firmware-A](https://www.trustedfirmware.org/projects/tf-a/)
stage 31, followed by a standard Zircon boot container holding an ARM64 Zircon kernel and an
[LZ4](https://github.com/lz4/lz4)-compressed [Fuchsia](https://fuchsia.dev/) boot filesystem. Marker
counts across the whole image: OP-TEE identifiers zero; six further OP-TEE internal markers,
including its application manager, its filesystem layer, its userspace library, its
pseudo-application mechanism, its architecture directory and its storage service, all zero. Against
that, the Zircon system-call prefix appears 432 times, the kernel name 20 times, the
operating-system name 17 times, alongside named services including a service host, an application
manager and a secure-element service. The OP-TEE core is entirely absent from the secure world.
These counts under-represent boot filesystem component strings, since that section is compressed.

The vendor also extends the system-call interface. The image's [virtual shared
object](https://man7.org/linux/man-pages/man7/vdso.7.html) name table lists non-upstream calls
beside the standard ones, including environment configuration and physical-address queries,
shared-memory and buffer accessors, a memory-statistics call, guest creation and trap installation,
and a [futex](https://man7.org/linux/man-pages/man2/futex.2.html) variant. This is vendor-authored
secure-kernel surface with essentially no public footprint, and it is where the platform's real
secure-kernel attack surface resides rather than in any OP-TEE vulnerability record. The presence of
a [hypervisor](https://en.wikipedia.org/wiki/Hypervisor) interface in a trusted application is
unexplained.

Every application on this platform is a Zircon userspace process. The [GlobalPlatform internal
interface](https://globalplatform.org/specs-library/tee-internal-core-api-specification/) names
appearing in the strings are statically linked in, being the vendor's own compatibility shim
compiled into each application, rather than dynamic imports or a kernel interface. The kernel
interface an application actually speaks is Zircon's.

The consequences for vulnerability applicability are sharp. At the secure kernel, no upstream OP-TEE
record can apply, because there is no such core to be the target. At the application-side
GlobalPlatform interface, the interface is inherited while the implementation is the vendor's, so an
upstream defect in the userspace library indicates a class to look for rather than the same defect.
Secure storage inherits protocol and key-hierarchy design, so a faithful reimplementation could
inherit a design flaw but not a code defect. Only the Linux driver, supplicant and client library
are genuinely forked OP-TEE code, and they are worthless as targets here, because normal-world root
is already public on this handset ([§6.5](#65-normal-world-root)).

The published chain that reaches exception level 3 on a sibling handset from the same vendor is
architecturally absent on this one: no Beanpod runtime, no corresponding application directory, no
administration application, no third environment module. A library whose name suggests the Beanpod
client is a 5,648-byte thermal shim reading a temperature node.

The conclusion generalises past this device: the large published OP-TEE vulnerability inventory does
not supply a missing step here, and the surface a compromised application faces is a general-purpose
microkernel interface with no public environment-context research at all, which is a materially
larger and differently shaped target.

### 6.3 Storage of the DICE secret

The KeyMint application's strings describe the lifecycle of the object directly. They include a
check for an existing chain-key secret, its creation, an already-created path, a success path, and
failure paths for opening, reading and writing it. They also include a migration: messages for
moving the key from the secure file system to [replay-protected
memory](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#rpmb-secure-storage),
success and failure for that move, failures to create and write a flag in that memory, and three
states for it — supported for provisioning, supported, and not supported. One source line reads,
verbatim, *"Because RPMB is not usefull, Can't read id."*

The DICE and certificate-chain tokens present are extensive: a chain-key creation routine, a main
flow, a derivation function, key-pair-from-seed and key-pair-from-identifier routines, a P-256
key-pair-from-identifier routine, a public-key derivation, sign and verify operations,
[COSE](https://www.rfc-editor.org/rfc/rfc9052) public-key encoding and sign-and-encode, a vendor
certificate generator, and both identifier names. Storage uses GlobalPlatform persistent objects
over an OP-TEE filesystem remote procedure call. Cross-world strings name a hardware-backed
certificate service with a sign-key call, a protected-data getter, a sign-authentication command and
a limit on additional authenticated data.

In OP-TEE, the [secure file
system](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html) backed by the
normal-world filesystem stores GlobalPlatform persistent objects as encrypted files in the normal
world, written through the supplicant and sealed under a hierarchy derived from a hardware unique
key. The inference this supports is that the chain-key secret is persisted rather than derived per
boot, created once on first use, and originally held in the secure file system, with a migration to
replay-protected memory that can fail. On any unit where the migration has not run or that memory is
unusable, the device's root identity resides in a normal-world file, as ciphertext. This is the
storage-layer failure-open that [part 2 §10.2](2-mechanisms.md#102-the-unbridged-step) treats as a
structural property, and it applies equally to two other persisted secrets the same application
holds.

On the curve, the only named helpers are for P-256. There is no
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032) or P-384 key-pair routine of the kind the
multi-algorithm profile carries, and the [Curve25519](https://www.rfc-editor.org/rfc/rfc7748) code
present traces to the general-purpose
[BoringSSL](https://boringssl.googlesource.com/boringssl/)-derived interface. This leans, as a
moderate inference, toward this handset's key pair being P-256. Because the binary is stripped — no
section headers and no exported dynamic function symbols, so these tokens are strings rather than
symbols — the absence of a string is not proof.

That question has a consequence. The Python minting implementation builds an Ed25519 degenerate
chain; if this handset's registered public key is P-256, an Ed25519 chain built from its seed would
fail the registry match and draw a rejection. Current upstream has added a P-256 option, so this is
no longer a contradiction, but which curve the device registers remains unmeasured.

A separate factory attestation key resides in replay-protected memory, independent of the
provisioning path: the application's strings carry fallbacks for failing to read an attestation key
and chain from that memory, and name both an RSA and an EC root attestation key.

One string is unidentified: a failure message about signing the authentication key on an unexplained
three-letter subsystem. A hash-algorithm name appears elsewhere in the same binary with nothing
tying the two together.

The derivation label the minting tooling once used, `rkp_bcc_km`, appears in zero of 16 binaries
searched on this platform: all 17 shipped applications across two builds, the KeyMint HAL, and the
environment's normal-world library. The DICE routines named above are all present in those same
files. The tool's hardware-derivation label was not read off this device. Sections
[§4.4](#44-holdings-of-a-stock-device) and [part 2
§9.3](2-mechanisms.md#93-scope-of-the-label-measurement) give that measurement its scope.

The storage path's architecture was measured directly. This platform relocated OP-TEE's
secure-storage stack out of the secure kernel and into a userspace service, which carries the
upstream code effectively verbatim: the filesystem key manager, the replay-protected filesystem, the
directory-file layer, the file-encryption-key cryptography, the
[hash-tree](https://en.wikipedia.org/wiki/Merkle_tree) synchronisation and the
[one-time-programmable](https://en.wikipedia.org/wiki/Programmable_read-only_memory) accessor for
the hardware unique key. The image contains the custom configuration system call and a
hardware-unique-key marker, and that service calls the system call to obtain the key and runs the
entire file-encryption and hash-tree stack in userspace. The KeyMint application holds none of that
cryptography: it issues filesystem calls and receives plaintext persistent-object data back.

Three consequences reshape the problem, and they are why [part 2
§10.2](2-mechanisms.md#102-the-unbridged-step) states the unbridged step as it does. The secret
transits a sibling userspace process in plaintext, so the target is that service rather than the
secure kernel. Cross-application naming is nonetheless closed: the upstream storage lookup's
identifier parameter was replaced by a storage-identifier selector, so no identifier crosses the
boundary and the service identifies its caller over an unforgeable channel, meaning that a
compromised sibling cannot simply request another application's namespace. And the storage layer
fails open, per the migration strings above.

### 6.4 Published application vulnerabilities

[TÄMU](https://arxiv.org/abs/2601.20507) — Mao, Shi, Busch and Payer, EPFL HexHive — emulates 67
trusted applications across four environments and reports 17 zero-day vulnerabilities across 11
applications, all responsibly disclosed. Its results table carries no vulnerability-identifier
column: the 17 were disclosed but never publicly numbered, so patch status cannot be checked against
any bulletin. Of those 17, 10 are on this platform, and 7 were reproduced on a physical device, two
of them yielding arbitrary-read primitives.

The intersection with this handset's shipped store of 17 applications: of the 8 applications on this
platform named in the paper, 7 ship here and one is absent. Of the 5 carrying a device-reproduced
vulnerability, all 5 ship here, two of them with arbitrary read.

Two bounds keep this honest. The vulnerabilities are in sibling applications rather than in KeyMint,
which is actively maintained ([§6.6](#66-the-application-container)). And no public dump of the
current firmware generation exists: the newest public stock dump predates the build string the
leaked sample names by roughly seven months, so the vendor-tree import is the best available proxy
for what ships today.

The emulator's public support for this platform is the cheapest high-value follow-up available: it
ships 17 containers, 16 configurations and 14 harnesses covering all eight applications named in the
paper, and its copy of one of them is byte-identical to this handset's. Its known gaps are that it
does not emulate application-to-application calls, so it cannot exercise the storage-service bridge
of [§6.3](#63-storage-of-the-dice-secret), and that the KeyMint application is prepared but
unfuzzed, its configuration recording an unresolved session entry-point offset.

### 6.5 Normal-world root

A public one-click root tool exists for this exact handset and Android version, under GPLv3, naming
the device, the chipset, kernel `6.1.138-android14-11`, Android 16 at interface level 36, and
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499). Its stated chain is a
[kernel-address](https://en.wikipedia.org/wiki/Address_space_layout_randomization) leak through a
timing [side-channel](https://en.wikipedia.org/wiki/Side-channel_attack) on a
[`pselect`](https://man7.org/linux/man-pages/man2/select.2.html) call aliased onto logged packet
data; a file-operations hijack by a priority-inheriting futex requeue race; a forged pipe-buffer
operations table yielding arbitrary kernel physical read and write; and then credential patching to
privileged user identity with full capabilities,
[seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) disabled and
[SELinux](https://source.android.com/docs/security/features/selinux) set permissive, delivering an
embedded root manager. Delivery is a library constructor through the dynamic loader's preload
mechanism. Under prerequisites it states that an unlocked bootloader is not required, the preload
path working either way.

The underlying vulnerability record, read from the registry, describes an upstream Linux defect
rather than a vendor one: a real-time-mutex waiter-removal fault in the proxy-lock rollback path
invoked from futex requeue, affected from kernel 2.6.39, with a [CVSS
3.1](https://www.first.org/cvss/v3-1/) base score of 7.8 under local access with no user
interaction. That corroborates the exploit's second stage precisely, from a source unrelated to the
tool.

What this position confers, as an inference from the capabilities described: unrestricted access to
the normal-world files backing the environment's secure storage, including the DICE secret's
container as ciphertext; the ability to drive the environment device node, the supplicant, the
client library and arbitrary application sessions, which is an open door to the vulnerable
applications of [§6.4](#64-published-application-vulnerabilities); the ability to instrument the
KeyMint HAL and the [GlobalPlatform
client](https://globalplatform.org/specs-library/tee-client-api-specification/) library; and
system-identity peer access to the keybox installer daemon of
[§6.7](#67-a-normal-world-keybox-installer). What it does not confer is access to
[TrustZone](https://www.arm.com/technologies/trustzone-for-cortex-a)-protected memory: kernel
physical read and write does not read secure-world memory and does not yield the storage sealing
key, which is derived inside the environment.

This closes an access question that previously carried a structural argument. The strongest argument
that an operator must break [verified
boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot) — and thereby
contradict the locked, approved state a forged artifact asserts — was that bootloader unlocking is
administratively blocked in the handset's home region. A locked, verified-boot-intact stock unit
reaches privileged user identity with SELinux disabled and arbitrary kernel physical read and write,
with verified-boot metadata untouched. Access is not the obstacle; [part 2
§10.2](2-mechanisms.md#102-the-unbridged-step) states what remains.

The tool names no tested build of the current firmware generation and targets a specific kernel
string, so whether it runs on the build named in sample A's extension could not be established.

### 6.6 The application container

Several designed acquisition schemes turned on this container's rollback semantics, so its header
was mapped directly across 38 images: six identifiers across four stock images and five vendor
imports.

| Offset | Size | Content | Evidence |
|---|---|---|---|
| `[0:8]` | 8 | three-byte magic plus the environment name | constant, 38 of 38 |
| `[8:12]` | 4 | a format tag | constant, 38 of 38 |
| `[12:16]` | 4 | payload length, big-endian, equal to file size less 336 | exact, 38 of 38 |
| `[16:48]` | 32 | SHA-256 of the payload | exact, 37 of 37 |
| `[48:80]` | 32 | SHA-256 of header bytes 0 to 47, the value actually signed | exact, 37 of 37 |
| `[80:336]` | 256 | [RSA-2048](https://www.rfc-editor.org/rfc/rfc8017) PSS signature | [entropy](https://en.wikipedia.org/wiki/Information_entropy) 7.24 bits per byte |

Three results follow, and each refuted a scheme.

*No version field exists in the container header.* The only fixed-position candidate never varies
across any sample or image, and the format is not OP-TEE's, so upstream reasoning about its loader
does not transfer. Anti-rollback is not absent from the platform, however: the
secure-operating-system image carries an old-version marker and the loader maintains a separate
version store, so the rollback question is where the version is tracked rather than whether it is,
and that store resides in a secure-world service rather than in a normal-world file a root process
could delete.

*Application bodies ship unencrypted.* The container is a 336-byte header followed by a plain
AArch64 ELF object: the magic appears at offset 336, the object is a 64-bit little-endian shared
object, and [entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) over the first 4
KB after the header is 2.31 bits per byte where ciphertext would sit near 8.0. Application bodies
are readable and disassemblable straight out of the vendor partition, which is what makes
third-party emulation of them ([§6.4](#64-published-application-vulnerabilities)) practical at all.

*The signature uses a random salt, so file-level hashing overcounts code churn.* Identical payloads
are re-signed differently on every image build. Comparing payloads, meaning the file past the
336-byte header, rather than whole files: four applications have one distinct payload each across
all nine sources and were never rebuilt; two others have two payloads each across five or six files,
so each was rebuilt once rather than five or six times; and the KeyMint application has three
distinct payloads across three files, so it was genuinely rebuilt three times.

That last row is the control, and it is what makes the rest readable: the extraction pipelines
demonstrably do pick up application updates. Against that control, the four applications carrying
device-reproduced defects, including both arbitrary-read primitives, have byte-identical payloads
from the launch image to the most recent vendor import, a span of more than two years. That code has
never been rebuilt.

One ordering note: the single genuine rebuild of the application with a reported buffer underflow
falls in the first nine months after launch, before the paper reporting that defect published, so it
cannot have been a fix for it. An earlier speculation to the contrary is withdrawn.

A method note, after it produced a false reading once: `git diff --name-status` marks all 17
applications as modified in the most recent commits, which is misleading, because those commits
touch approximately 1,800 files and are whole-tree re-imports. Blob identifiers must be compared
rather than diff status.

### 6.7 A normal-world keybox installer

The vendor's command-line keybox front-ends are absent from this handset, with zero matches for any
of the usual names. The capability nevertheless ships, in a 149,241-byte vendor library whose
symbols include a keybox installer taking a buffer and length, a keybox parser over an XML node, a
keybox checker, device-identifier check, clean and install routines, an installer and state check
for replay-protected memory, EC and RSA attestation checks, a key generator taking an authorisation
set and an optional attestation key, and a key-manager class with install, load, clear, prepare and
dump operations. Its strings include a normal-world keybox path it reads, a log tag, a message
pairing a device identifier with a project code, installation-failure and type-mismatch messages, a
replay-protected-memory state report, a message about a device supporting content protection at
level 1 while failing a keybox check, and — verbatim, with its original spacing — *"This device
support rkp , but not upload public key"*.

Its consumer is a 15,824-byte AArch64
[position-independent](https://en.wikipedia.org/wiki/Position-independent_code) boot service,
declared in an [init
script](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/README.md) to
run with system user identity in the system, keystore and content-protection groups, started on boot
completion.

A system-identity daemon in the keystore group therefore runs at every boot, linked against a
library that installs a keybox from a normal-world path into the environment. Whether the
application-side command it reaches is gated — by caller identity, a provisioning lock, or memory
state — could not be established here, and it is the main unanswered question about this platform.

That last string records a device state in which provisioning is supported while the device public
key was never uploaded to the backend: exactly the registration step on which [part 1
§6.1](1-protocol.md#61-validation-order-at-the-backend) shows everything to depend.

---

## 7. Threats to validity

*Nothing in [§6](#6-the-measured-platform) or in the field-route measurements was reproduced on
hardware.* What was examined is the artifact layer: file digests, container metadata, patch-script
constants, protocol constants against AOSP's grammar, and the arithmetic of every cross-part claim.
Per-route claims are attributed to the records that make them, and [part 5
§3](5-sources.md#3-appraisal) appraises each record.

*Quantities the corpus reports inconsistently.* Three issuance-adjacent counters are conflated in
the sources and are separated in [§3.3](#33-issuance-counts). Serial encodings in the revocation
list are inconsistent between decimal and hexadecimal, and a matcher that tests only one form
silently under-reports, which is why [§5.3](#53-population-measurements) tests both. The EC private
key [DER](https://www.itu.int/rec/T-REC-X.690) length differs between devices, 121 against 138
bytes, purely by which optional [SEC1](https://www.secg.org/sec1-v2.pdf) fields are present, so no
length is a format constant.

*Mutable substrate.* The revocation list, the hierarchy's own revocation list, the public vendor
tree and the upstream minting tools all change under measurement. The upstream tool's hardware-key
path was removed after it was measured, so the measurement of
[§4.4](#44-holdings-of-a-stock-device)'s label question describes a revision that no longer exists
upstream, and the vendor tree gains whole-tree re-imports that defeat diff-status reading
([§6.6](#66-the-application-container)).

*Sample size.* The bucket inference on the issuance count rests on five observations. The reading of
label 5's presence and absence rests on two samples. The platform forensics of
[§6](#6-the-measured-platform) describe one handset model, and the exclusion in
[§6.2](#62-identification-of-the-secure-operating-system) of an OP-TEE vulnerability inventory is a
statement about that platform rather than about the vendor's environments generally.

*Vulnerability feeds undercount the risk they appear to measure.* Three independent studies make the
same point from different angles: an in-situ fuzzer found 40 unique defects across four handsets
with exactly one identifier assigned at publication; a systematic study of a missing-type-check
class across 14,777 trusted applications from 545 firmware images confirmed 33 defects and disclosed
four identifiers with ten still under responsible disclosure; and the emulation paper of
[§6.4](#64-published-application-vulnerabilities) added 17 more carrying no identifiers at all. A
risk model built from a vulnerability feed alone will therefore be wrong about trusted applications,
and the absence of a record for a platform says more about who has looked than about what is there.
This report's own platform determination ([§6.2](#62-identification-of-the-secure-operating-system))
is the corollary: an inventory of records against one environment implementation says nothing about
a device running a different one.

*Absence of evidence.* Where a claim is an absence — no OP-TEE markers in the secure world, no
version field in the container header, no published cross-application primitive — the measurement
bounds the search rather than the universe. A stripped binary in particular means that the absence
of a string is not proof of the absence of code ([§6.3](#63-storage-of-the-dice-secret)).

*Point-in-time observations.* The two roots and the exclusivity dates, the published extension
schema, the backend's endpoint set and the test-suite requirements are all version- or
policy-dependent and carry the standing caution of [part 1
§8.1](1-protocol.md#81-version-dependent-claims).

---

## 8. Refutation conditions

*Leaf lifetime as a class discriminator* ([§2.1](#21-leaf-validity-by-material-class)): a
provisioned leaf with a multi-year span, or a factory keybox leaf with a two-week one.

*Non-overlap of the two populations* ([§4.1](#41-the-public-factory-corpus)): one file in the public
pool carrying an issuer in the provisioning hierarchy or the provisioning extension.

*That 56 per cent of the revocation list is one leak* ([§4.3](#43-derived-quantities)): a recount
showing materially fewer of the list's serials present in that corpus, or a demonstration that the
serial-form bucketing miscounts.

*That the issuance count is a per-device approximate 30-day figure rather than a cap*
([§3.3](#33-issuance-counts)): already settled by the existence of a third value, so what remains
open is the bucketing, which a measured non-power-of-two value would refute.

*That the stock baseline is single digits* ([§3.3](#33-issuance-counts)): a stock handset reading a
three-digit count on the experiment of [§5.2](#52-on-device-measurements).

*That label 5.2 is build-scoped* ([§3.2](#32-label-dictionary)): two label-5-bearing certificates
from different devices on the same build with different values.

*That this platform's secure world is Zircon and no OP-TEE record can reach its kernel*
([§6.2](#62-identification-of-the-secure-operating-system)): any OP-TEE core marker in the
secure-operating-system image, or a dynamic GlobalPlatform import in any application.

*That the DICE secret is created once and persisted* ([§6.3](#63-storage-of-the-dice-secret)):
contrary behaviour from an emulation of the creation routine, or a device whose public key changes
across a factory reset, which would also refute the survives-a-wipe inference of [part 2
§7.2](2-mechanisms.md#72-persistence-of-the-seed).

*That four vulnerable applications were never rebuilt* ([§6.6](#66-the-application-container)): a
differing payload for any of them in a dump of the current firmware generation. None is public,
which is this measurement's sample edge.

*That the container header carries no version field* ([§6.6](#66-the-application-container)): a
fixed-position field increasing with build date in a wider sample.

*That the derivation label is absent from this platform* ([§6.3](#63-storage-of-the-dice-secret)):
one hit in any shipped binary from this vendor or chipset family. This would not refute the
per-vendor scope note of [§4.4](#44-holdings-of-a-stock-device), which the Kinibi and Qualcomm
measurements establish independently.
