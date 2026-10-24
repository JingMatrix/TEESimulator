# 4 · The measured record

*Fourth of five. Every quantity the other four documents rely on, with what was measured, what it
bears on, and the command that reproduces it. The protocol those quantities describe is specified in
[`1-protocol.md`](1-protocol.md); the mechanisms they bear on are in
[`2-mechanisms.md`](2-mechanisms.md); the controls they feed are in
[`3-detection.md`](3-detection.md); and the weight each underlying record can carry is appraised in
[`5-sources.md`](5-sources.md). Grades and the scope rule are [`1-protocol.md`](1-protocol.md) §1.4
and §1.5.*

## Abstract

This document reports the empirical basis of the series. It has four subjects. *Certificate
validity* is a class discriminator: measured leaf lifetimes are about 13 days for stock Remote Key
Provisioning, 14 to 15 days for two leaked RKP-provisioned keyboxes, and about ten years for factory
batch keyboxes, with the two populations rooted at different Google anchors. *The
provisioning-information extension* under [OID](https://www.itu.int/rec/T-REC-X.660)
`1.3.6.1.4.1.11129.2.1.30` is decoded byte for byte from both leaked samples and compared against
the only schema Google publishes, which documents two of the four tags observed; the issuance
counter it carries reads 512 on both samples against a stock baseline of 8 measured on a handset of
the model one of them names. *Populations* are censused: 551 public factory keyboxes contain no RKP
keybox at all, and 980 of the 1744 entries in Google's leaf revocation list on the day of
measurement are serials from that single corpus — 56% of a global revocation list explained by one
leak. *The measured platform* is characterised directly from vendor binaries and a
secure-operating-system image: the handset at the centre of this series runs a
[Zircon](https://fuchsia.dev/fuchsia-src/concepts/kernel)
[microkernel](https://en.wikipedia.org/wiki/Microkernel) in the secure world rather than an
[OP-TEE](https://optee.readthedocs.io/) core, which excludes an entire published vulnerability
inventory from applying to it, and the
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/) secret it holds is
a created-once persisted object with a storage migration that can fail open. Threats to validity are
stated in §7, and §8 lists what would refute each load-bearing claim.

---

## 1. Method

### 1.1 What is measured here, and what is not

*Measured* means a command in §5 produces the value on the artifacts named in §1.2, or that a cited
record contains it as an artifact read directly rather than narrated. Where a quantity comes from a
research record whose execution was not re-run, it is marked *[REPORTED]* and the ambiguity is kept
rather than averaged away.

Three things are deliberately absent. *No private key material* appears, including private scalars
that a cited source published in full ([`1-protocol.md`](1-protocol.md) §1.5). *No reproduction step
requires a private working tree*: every command in §5 runs against an artifact in this repository, a
stock handset, or a public endpoint. And *nothing in §5 contacts a provisioning endpoint* — no
certificate request was ever submitted in the course of compiling this series.

### 1.2 The artifacts, and the record's own integrity

Two keybox XML wrappers are the primary artifacts, referred to throughout as *sample A* and *sample
B*. They are not carried in this repository: they contain live private keys, and §1.1's rule
excludes them. Their identity is fixed by digest so that any claim here can be checked against a
copy obtained independently — sample A is 5993 bytes with
[SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) `4c1fd429…5b26c3`, sample B
5690 bytes with SHA-256 `f87306c3…925aa5`.

Two measurement sessions stand behind this record, about five weeks apart. The *earlier* covers the
samples, the populations and the platform forensics of §6; the *later* covers the field routes, the
stock baseline and a re-measured revocation list. Where the two disagree, the later one wins and the
earlier reading is recorded as withdrawn rather than deleted — §3.4 is the list.

One integrity note bears on everything in §6. The binaries measured there total roughly 770 MB and
were not preserved; they are re-fetchable from the public sources named inline, and the session
record pins each by size and SHA-256 so a re-fetch can be verified rather than assumed. The TEE
image is 4,075,520 bytes with SHA-256 `eae7dc96…c326ef`; the
[KeyMint](https://source.android.com/docs/security/features/keystore) trusted application 1,401,936
bytes, `1a96c549…4d46614`; the KeyMint HAL 148,585 bytes, `189564b9…fde5e6`; the keybox-installer
library 149,241 bytes, `633b530b…001a8d4`; its consumer daemon 15,824 bytes, `6d48a4b4…c5f5517`.

### 1.3 Scope exclusions

Route-operative constants — patch offsets, original instruction bytes, code-cave addresses — are not
reproduced, for the reason [`2-mechanisms.md`](2-mechanisms.md) §1.3 gives: the shape of a patched
decision is the finding, and its address is not. Seeds appear by digest fingerprint only. The
container-unwrapping RSA private factors recovered by one cited source are not reproduced; their
presence, location and bit length are the measurement ([`2-mechanisms.md`](2-mechanisms.md) §5.2).

---

## 2. The two leaked RKP keyboxes

Both are keybox XML wrappers carrying *one `ecdsa` key and no RSA key* — consistent with RKP being
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)-only, and
structurally distinguishable from a factory keybox, which carries an RSA key too.

### 2.1 Leaf validity, by material class

The headline measurement of the series, because it separates the two populations without any
cryptography.

| Material | Leaf validity span |
|---|---|
| Sample A, RKP-provisioned | 14 d 8 h 01 m 24 s |
| Sample B, RKP-provisioned | 15 d 3 h 16 m 38 s |
| Stock RKP issuance, measured on a handset | ≈ 12 d 23 h *[REPORTED]* |
| Factory keybox recovered from a trusted application | ≈ 10 years *[PRIMARY]* |
| Public factory-keybox corpus, 551 files | ≈ 10 years throughout |

Two readings follow. *Leaf `notAfter` is not pinned to a shared batch epoch* in the RKP population:
the two samples' spans differ by about 19 hours, so the value is roughly *issuance + two weeks +
jitter* rather than a fixed expiry date. And the gap between the two populations is three orders of
magnitude, which is what makes §4.3's conclusion about revocation structural rather than incidental.

### 2.2 The shared chain positions, and the anchors

Positions 2 through 4 are *byte-identical across both samples* *[MEASURED]*:

| | Subject | Serial | Key | Validity span | SHA-256 |
|---|---|---|---|---|---|
| CA3 | `O=Google LLC, CN=Droid CA3` | `344B69CE…427C` | P-256 | ≈ 10 weeks | `8BC7B36F…6A38` |
| CA2 | `O=Google LLC, CN=Droid CA2` | `92425019…85FB` | P-384 | 3 years | `B8B0741E…1632` |
| root | `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` | `84A9D029…0605` | P-384 | 10 years | `6D9DB4CE…BCC0` |

Note the *CA3 span*: the issuing intermediate itself turns over on a scale of weeks, so an archived
chain names a CA3 instance that no longer signs. That is a second, independent clock on a hoarded
chain beyond the leaf's own two weeks.

The root is *byte-identical to the EC root pinned in*
[`app/.../RootPublicKey.kt`](../app/src/main/java/org/matrix/teesim/RootPublicKey.kt), so the
module's own inspector already classifies these chains as Google-rooted, and [`openssl
verify`](https://docs.openssl.org/master/man1/openssl-verify/) passes for both.

That same root digest — `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` — was
independently recorded as matching Google's published root in the stock-issuance acceptance record
of §3.3 *[PRIMARY]*, on a different handset, by a different party. It is the one anchor in this
series confirmed from two directions.

*Shared intermediates carry almost no evidential weight.* The backend returns a shared portion plus
a unique leaf per key ([`1-protocol.md`](1-protocol.md) §5.2), so CA3, CA2 and the root are one blob
handed to every requester in that CA3 epoch. Two samples agreeing on them is not evidence of common
origin.

The *factory* population roots elsewhere: at the RSA Google root whose subject serial number is
`f92009e853b6b045`, across four distinct root serials in the 551-file corpus (§4.1) — and that same
root serial appears at the end of the factory keybox recovered in
[`2-mechanisms.md`](2-mechanisms.md) §5.6, which independently places that material in the factory
population.

### 2.3 Revocation-list state for this hierarchy

Only *CA2* carries a [certificate-revocation-list](https://www.rfc-editor.org/rfc/rfc5280#section-5)
distribution point,
[`https://android.googleapis.com/attestation/key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl).
On one live fetch: [CRL](https://www.rfc-editor.org/rfc/rfc5280#section-5) Number 0, a one-year
publication interval, and *zero revoked entries* *[MEASURED]*. The intermediate tier of the RKP
hierarchy has never been revoked.

Leaf revocation is not CRL-based. It goes through
[`https://android.googleapis.com/attestation/status`](https://android.googleapis.com/attestation/status),
where *neither sample leaf appears* — checked against the live list of 1744 entries at the time of
measurement (§4.2).

### 2.4 Structural fields of the measured leaves

Both leaves: EC P-256 with `ecdsa-with-SHA256`; `CA:TRUE` marked critical; key usage `keyCertSign`
only; the private key in the wrapper matches the leaf's public key; and *the leaf serial equals its
own common name* — sample A's subject is `O=TEE, CN=feaf1c15bef625ef4b0383ce55213dc4` with serial
`FEAF1C15…3DC4`, sample B's `O=TEE, CN=344dc9148ccb0cc561b4983543e9678b` with serial
`344DC914…678B`.

Absent from both: any `1.3.6.1.4.1.11129.2.1.17` key-description extension — *these are signing CAs,
not attestation leaves* — and any subject alternative name, extended key usage, authority
information access or path-length constraint.

The `O=TEE` subject is where the security level surfaces. It follows from
`DeviceInfo.security_level` ([`1-protocol.md`](1-protocol.md) §2.6), which is also why the
extension's own *validated attested entity* tag is absent: the claim is already carried in the
subject (§3.2).

Both samples were issued five days apart by the *same CA3 instance*, same brand, different
identities. Suggestive of one source or one technique — but CA3 serves global RKP issuance, so this
is weak circumstantial evidence and not a common-origin proof. [`5-sources.md`](5-sources.md) §5.2
establishes common origin a different way, from the XML bytes.

---

## 3. The provisioning-information extension, OID `1.3.6.1.4.1.11129.2.1.30`

Sections 2 measures what the chain looks like. This section measures *what the backend wrote into
it* — the only part of an RKP certificate that reflects the backend's own view of the request, and
the most under-used signal in the ecosystem.

### 3.1 The published schema, and the two extensions byte for byte

Google publishes [two
keys](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension):

```cddl
{
      1 : int,       ; certificates issued
      4 : string,    ; validated attested entity (STRONG_BOX / TEE)
}
```

with the explicit note that *the map is unversioned and new optional fields may be added*.

Sample A's extension is 186 octets *[MEASURED]*:

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

Sample B's is *13 octets* — the entire extension:

```
a2  01 19 0200  03 66 5869616f6d69        {1: 512, 3: "Xiaomi"}
```

Note that tag 5.2 is a *text string of 64 lowercase hex characters*, not a byte string: a 32-byte
digest re-encoded as text by the backend. A decoder that expects a `bstr` there will fail on a valid
certificate.

The size difference, 186 against 13 octets, is the measurement §3.2's last paragraph interprets.

### 3.2 The tag dictionary — documented and observed

*Tag 1, `certs_issued`* — documented. Observed `512` in both samples, `8` on a stock handset.
Google's description: *an approximate number of certificates issued to the device in the last 30
days. This value can be used as a signal for potential abuse if the value is greater than average by
some orders of magnitude.* §3.3 supplies the average.

*Tag 3* — undocumented. Observed `"Xiaomi"` in both. The manufacturer on record at the provisioning
backend; brand only, no model.

*Tag 4, `validated_attested_entity`* — documented, and *absent from both samples*. Google's
description: *a string indicating the certified origin of the attested key, directly vouched for by
the chipset manufacturer. For example, STRONG_BOX or TEE.* The same claim is carried instead in the
leaf subject, `O=TEE` (§2.4), and the absence is consistent with both requests having carried an
empty `UdsCerts` map ([`1-protocol.md`](1-protocol.md) §2.7).

*Tag 5* — undocumented, present only in sample A, a four-entry map. Sub-tag 1 is a verdict,
`"APPROVED"`; sub-tag 2 the 32-byte digest as hex text; sub-tag 3 a second, independent verdict,
also `"APPROVED"`; sub-tag 4 a build fingerprint.

Tag 5 reads structurally as *two (verdict, subject) pairs* — 5.1 with 5.2, and 5.3 with 5.4 — the
backend recording that it validated two attributes and approved both. *That pairing is inference
from the ordering*; only 5.4's content is self-evident.

And the verdicts are *not* constants. They were initially catalogued as "observed `APPROVED`" as
though fixed; an independent record shows `NOT_APPROVED` being issued and being dispositive
([`2-mechanisms.md`](2-mechanisms.md) §6.6). They are live varying fields, which is what makes a
decoder that drops them a verifier bug rather than a cosmetic omission.

*What tag 5's presence means.* It is a property of the *request*, not of the device: sample B's
13-octet extension omits it because the submission omitted the fields that trigger it — most
plausibly a config-completeness difference in the same tooling *[INFERRED]*. Both samples are the
same brand, issued five days apart by the same CA3, and only one carries it.

*And tag 5.4 is not provenance.* The build fingerprint is client-supplied and unsigned: `rkpd`
appends it after the TA signs, as an `UnverifiedDeviceInfo` map in
[`CborUtils.buildUnverifiedDeviceInfo`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java),
and the tool that produced both samples sends it to the EEK endpoint as `cbor{'fingerprint': fp,
'id': 42}` from a value the operator typed into a configuration file *[PRIMARY]*. §3.4 records the
correction this forced.

So the pairing reads: *the client asserts a fingerprint (5.4); the backend resolves it against its
own build census and records the digest it found (5.2), marking both approved.* Tag 5.2 is therefore
most plausibly the verified-boot metadata digest *of the named build* — build-scoped, not
device-scoped — but it is what the *backend looked up*, not what the device reported. No device
identity leaks through it.

Three experiments would confirm that 5.2 is build-scoped, and the first is the cheapest: on any
handset of the exact model and build named in 5.4, read `ro.boot.vbmeta.digest`, or take any
attestation and read the verified-boot hash the module's
[`Harvester.kt`](../app/src/main/java/org/matrix/teesim/Harvester.kt) already captures; equality
confirms it. Alternatively, compare 5.2 across two tag-5-bearing certificates from different devices
on the same build — equal implies build-scoped — or across one device's certificates spanning an
[OTA](https://source.android.com/docs/core/ota), where the value should change.

### 3.3 The issuance-count observations, and the three counters adjacent to them

Both samples read `certs_issued = 512 = 2⁹`, on two different identities five days apart
*[MEASURED]*. Values reported elsewhere are 8, 32 and 64. All five observations are powers of two,
which suggests a logarithmic bucket rather than a literal count *[INFERRED, n = 5]*.

*The stock baseline.* On a stock Redmi K70E, before any patching, the extension read `{1: 8, 3:
"Xiaomi"}` *[PRIMARY]*. The same acceptance record notes 12 certificates returned in that one batch,
a leaf validity of about 12 days 23 hours, a root digest matching Google's published root, and a
*275-byte opaque stored private key* that is not [PKCS#8](https://www.rfc-editor.org/rfc/rfc5958)
and not a P-256 scalar (§4.4).

Four things follow, and they are the most reusable output of this section.

*`certs_issued` is not a fixed pool cap.* A third value exists and it is 8. The earlier reading of
512 as "more like a pool cap than an organic count", which was reasonable on two identical
observations, is withdrawn (§3.4). Tag 1 behaves as documented.

*8 is what a stock device looks like.* The leaked samples read 512 — about *64 times* the stock
baseline, on the same brand, on the device model sample A's own tag 5.4 names, in the same 30-day
window. Google's documentation frames tag 1 as a signal when the value exceeds the average by orders
of magnitude; this gives the average a measured value.

*Under every reading, both samples are extreme.* `rkpd`'s own default target is
`EXTRA_SIGNED_KEYS_AVAILABLE_DEFAULT = 6` in
[`Settings.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java).
Google's own documented abuse signal was *saturated inside the signed certificate and issuance
proceeded regardless.*

*Three different counters are routinely conflated, and all three appear in that one record.* Twelve
is the number of certificates in one batch; eight is the approximate 30-day issuance count,
backend-written and signed; two is a same-day local counter in the device's own
`rkp_daily_stats.xml`, unsigned. *Only the middle one is in the certificate, and only it is
relying-party-visible.* Batch size and issuance count are different quantities and cannot be divided
into each other — which is why the conjecture that 512 implies a particular mint rate is not
advanced ([`2-mechanisms.md`](2-mechanisms.md) §10.3).

### 3.4 Corrections the record carries against its own earlier readings

Each was measured after an earlier reading and overturns it. They are recorded rather than silently
applied, per the series convention.

*Tag 5.2's direction of resolution was inverted.* The earlier reasoning ran: because `DeviceInfo`
carries no build fingerprint, the backend must be resolving a submitted verified-boot digest against
a build database to produce 5.4. The direction is the reverse — the *client* supplies the
fingerprint, unsigned, and the backend resolves *from* it (§3.2). *[MEASURED]*, from
[AOSP](https://source.android.com/) code and the producing tool's own source.

*`DeviceID` is packaging metadata, not device identity.* The XML attribute
`DeviceID="Xiaomi-02f7c61fec6d"` is the manufacturer string plus six random bytes, generated by the
producing tool ([`5-sources.md`](5-sources.md) §5.2). It is not a MAC address and carries no device
identity. Provenance comes from the extension, not the attribute.

*"Anonymous versus fingerprint-bound" is a property of the operator's configuration*, not of a donor
handset. A keybox whose extension lacks tag 5 constrains nothing and pairs with any profile; one
carrying tag 5 pins the presented identity, because a verifier reading 5.4 sees a specific build
string and the profile must present that device or contradict itself in a signed field. So: *prefer
anonymous keyboxes, and when bound, seed the profile from 5.4* — while remembering that bound-ness
tells you nothing about where the key came from.

*The reading of 512 as a pool cap is withdrawn*, per §3.3.

*The verdict tags are live, not constant*, per §3.2.

*One mandatory field was omitted and the request was signed anyway.* The producing tool's default
device information omits `vbmeta_digest`, which
[`DeviceInfoV3.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV3.cddl)
makes mandatory *[MEASURED]*. A genuine KeyMint TA cannot omit it. Sample B's request was therefore
not TA-produced — an independent confirmation of its software origin that does not rely on the XML
byte match of [`5-sources.md`](5-sources.md) §5.2, and simultaneously a measurement that the
[CDDL](https://www.rfc-editor.org/rfc/rfc8610) constraint is not enforced server-side.

---

## 4. Populations

### 4.1 The public factory-keybox corpus contains no RKP keybox

*[MEASURED]* All 551 files of the scraped public keybox pool, of which 533 are UTF-16LE with a
[byte-order mark](https://www.unicode.org/faq/utf_bom.html) — a parsing trap worth noting, since a
naïve UTF-8 read silently yields nothing:

*All 551 parse; zero have a `Droid CA*` issuer; zero carry OID `1.3.6.1.4.1.11129.2.1.30`.* The two
populations do not overlap at all.

549 of 551 carry *both* `ecdsa` and `rsa` keys, against the RKP samples' EC-only shape. All leaf
spans are about ten years, and their issuance years cluster hard: a single year accounts for 316 of
the 551 files, with the remainder spread thinly across eight other years — the shape of a few bulk
leaks rather than a steady trickle. Chains root at the *RSA* Google root `2.5.4.5=f92009e853b6b045`
across four distinct root serials, where the RKP samples root at the *EC* `CN=Key Attestation CA1`.

Two structural findings about the corpus itself. There are *89 distinct intermediate batch CAs
across 551 chains* — about 5.5 keys per CA, which is the signature of a handful of factory-file
leaks rather than diffuse per-device self-extraction. And there are 490 distinct key sets among 551
files, so 61 are duplicates resold, with 979 distinct private keys of which 117 are reused across
files, maximum reuse three. The `DeviceID` watermarks concentrate accordingly: one scraper's domain
×527, then four other labels accounting for 24 files between them.

*The leaked RKP keyboxes are a different population from every keybox in the known public pool* —
which is what makes §4.3's revocation finding interpretable.

### 4.2 Revocation-list snapshots

*[MEASURED]*, live plus [Wayback Machine](https://web.archive.org/) snapshots of
[`android.googleapis.com/attestation/status`](https://android.googleapis.com/attestation/status).
Serials are bucketed by encoding, because the list is inconsistent: decimal strings for serials up
to 64 bits, hex for 16-byte ones.

Snapshots are listed oldest first, with the interval to the previous one; each is linked so the
timestamp it carries can be read off the address rather than from this table.

| Snapshot | Interval | Total | ≤ 20 chars (decimal, ≤ 64-bit) | ≥ 30 chars (hex, 16-byte) |
|---|---|---|---|---|
| [1](https://web.archive.org/web/20240622033556id_/https://android.googleapis.com/attestation/status) | — | 94 | 39 | 55 |
| [2](https://web.archive.org/web/20241205133200id_/https://android.googleapis.com/attestation/status) | +5½ months | 467 | 161 | 306 |
| [3](https://web.archive.org/web/20250612190743id_/https://android.googleapis.com/attestation/status) | +6 months | 517 | 177 | 340 |
| [4](https://web.archive.org/web/20251220091647id_/https://android.googleapis.com/attestation/status) | +6 months | 1604 | *950* | 654 |
| [5](https://web.archive.org/web/20260706064827id_/https://android.googleapis.com/attestation/status) | +6½ months | 1720 | 962 | 758 |
| [6](https://web.archive.org/web/20260901160025id_/https://android.googleapis.com/attestation/status) | +2 months | 1742 | 974 | 768 |
| 7, live | +1 week | *1744* | 974 | 770 |
| 8, re-measured | +5½ weeks | *1761* | 981 | 780 |

Reasons given at snapshot 7: `KEY_COMPROMISE` ×1718, `SOFTWARE_FLAW` ×26.

### 4.3 Derived quantities, and what the list can reach

*One surge is one leak.* The jump from 177 to 950 in the 64-bit population across snapshots 3 and 4
— a single six-month interval — coincides with the public scrape of the factory pool censused in
§4.1.

*[MEASURED]* *980 of the 1744 entries at snapshot 7 are serials that appear in that one 551-file
corpus* — 56% of the global revocation list explained by a single public leak. Snapshot 8
independently reproduces the proportion five and a half weeks later: 1761 entries, 780 containing
hex digits `a`–`f` and 981 digits-only, i.e. 55.7%.

Growth over the last year of the series runs about 13 entries per month, all in the 16-byte
population.

*[INFERRED]* *The revocation list is structurally the wrong lever against RKP-derived keyboxes.* A
14-day leaf expires faster than a revocation cycle notices it; neither sample leaf is listed; and
the RKP hierarchy's own CRL stands at CRL Number 0 with no entries (§2.3). The effective lever is
removing `UDS_pub` from the provisioning registry — a registry edit at the backend, invisible to any
certificate-based mechanism.

This is also where the two populations diverge operationally rather than cryptographically. A
factory batch key is long-lived and therefore *reachable* by revocation, at the cost of bricking
attestation for a whole production run. An RKP leaf is short-lived and therefore unreachable, but
the identity behind it is revocable without touching any certificate. Both properties follow from
leaf lifetime (§2.1).

### 4.4 What a stock device holds

Four facts bound what the ordinary provisioning path can yield, and they are why
[`2-mechanisms.md`](2-mechanisms.md) §6 needs a TEE patch at all.

*The stored key is not exportable.* The private key banked by the system RKP path on the measured
stock handset is a *275-byte opaque blob* usable only by that device's KeyMint — not PKCS#8, not a
P-256 scalar *[PRIMARY]*. The exportable identity is simply not in the database, on two
independently measured devices.

*The derivation label is per-vendor.* Three platforms, three labels: `rkp_bcc_km` is the live
production key-derivation argument on [Trustonic Kinibi](https://www.trustonic.com/) and is *absent
from every MiTEE binary searched* (§6.3), while Qualcomm KeyMint derives from `"RKP PRIVATE KEY
SEED"` ([`2-mechanisms.md`](2-mechanisms.md) §3.2, §4.5, §9.3).

---

## 5. Reproduction

### 5.1 Decoding a keybox and its extension

Split a keybox wrapper into [PEM](https://www.rfc-editor.org/rfc/rfc7468) objects, then read them:

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

openssl x509 -in obj1.pem -noout -text       # the leaf, including the .1.30 extension as hex
openssl asn1parse -in obj1.pem               # the ProvisioningInfo CBOR follows the OID
```

Chain verification needs both intermediates in one file, which is the common mistake — `-untrusted`
takes a file, not a repeated flag:

```bash
cat obj2.pem obj3.pem > chain.pem                # the two intermediates
openssl verify -CAfile obj4.pem -untrusted chain.pem obj1.pem
```

For the CRL state of §2.3:

```bash
curl -s https://android.googleapis.com/attestation/key_ca1.crl -o key_ca1.crl
openssl crl -inform DER -in key_ca1.crl -noout -text | head -20
```

### 5.2 On device: the extension, and the stock baseline

The single cheapest high-value experiment in this series, and the one that would confirm §3.3's
baseline from a second source. On any stock handset:

```bash
adb shell cmd remote_provisioning csr          # emits a certificate request / provisioned leaves
# then decode the returned leaves' OID 1.3.6.1.4.1.11129.2.1.30 as in §5.1
```

A single-digit tag 1 on an ordinary device confirms the baseline independently of the research
corpus.

For §3.2's cheapest discriminating test of tag 5.2, on a handset of the exact model and build:

```bash
adb shell getprop ro.boot.vbmeta.digest        # compare against tag 5.2's 64 hex characters
```

### 5.3 The population measurements

The revocation list, live and historical:

```bash
curl -s https://android.googleapis.com/attestation/status -o status.json
curl -s "http://web.archive.org/cdx/search/cdx?url=android.googleapis.com/attestation/status\
&output=json&fl=timestamp,length,digest&collapse=digest&limit=200" -o cdx.json
curl -sL "https://web.archive.org/web/<TIMESTAMP>id_/https://android.googleapis.com/attestation/status" \
     -o snapshot.json
```

Bucket the entry keys by `len(k)`: at most 20 characters is a decimal-encoded serial of at most 64
bits, at least 30 is a hex 16-byte serial. Both forms must be tested when matching a leaf, which is
what [`tools/teesim_attest/revocation.py`](tools/teesim_attest/revocation.py) does.

For a corpus of keybox files, note the encoding trap of §4.1:

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

### 5.4 The checks that would settle a graded value

*The issuance baseline* — §5.2, and it would move §3.3 from *[PRIMARY]* on one record to
independently confirmed.

*Seed survival across a factory reset* — the weakest load-bearing claim in the series, graded
*[INFERRED, strong]* and carrying the supply-versus-sample argument of
[`2-mechanisms.md`](2-mechanisms.md) §7.2. Needs any Android handset: `cmd remote_provisioning csr`,
record the DICE root public key, factory reset, re-read. A changed `UDS_pub` would refute it.

*Route A's surface, without exercising it* — read-only, on any Qualcomm handset:

```bash
ls -l /dev/smcinvoke /vendor/lib64/libkeymasterdeviceutils.so
nm -D --defined-only /vendor/lib64/libkeymasterdeviceutils.so | grep send_cmd
```

Presence of the device node and the `send_cmd` symbol establishes the reachable surface of
[`2-mechanisms.md`](2-mechanisms.md) §3.3. Nothing need be invoked.

### 5.5 The toolkit

Every acceptance relation in [`2-mechanisms.md`](2-mechanisms.md) §10 and every threshold in §3.3 is
implemented in [`tools/`](tools/) as `teesim-attest`, with 34 tests that need neither network nor
device:

```bash
cd tools && python3 -m unittest discover -s tests -q
./teesim-attest verify     keybox.xml     # the two chain layers; exits 1 if it would not be accepted
./teesim-attest inspect    keybox.xml     # decodes OID ...2.1.30, compares certs_issued against 8
./teesim-attest unpack     payload [--descriptor d]   # length-prefix + DER, tail residue classified
./teesim-attest verify-csr request.cbor   # DICE chain walk, canonical CBOR, DeviceInfo domains
./teesim-attest revocation keybox.xml     # both serial encodings, per-form counts
./teesim-attest baseline                  # every constant with its provenance
```

Run against the two samples, `inspect` reproduces §3.3's finding from the files themselves: both
read `certs_issued = 512`, 64 times the stock baseline. Note that `pytest` is not required and may
not be installed; the suite is plain [`unittest`](https://docs.python.org/3/library/unittest.html).

---

## 6. The measured platform

The handset at the centre of this series — a Redmi K70E, codename `duchamp`, on
[MediaTek](https://www.mediatek.com/) MT6897 — is characterised here directly from vendor binaries
and a secure-operating-system image. This matters for two reasons beyond the device itself. It is
the handset Route D targets ([`2-mechanisms.md`](2-mechanisms.md) §6), and it is the device model
named in sample A's own provisioning extension (§3.1). And the determination in §6.2 *excludes an
entire published vulnerability inventory* from applying to it, which is a reusable result about
reading CVE lists against a platform.

### 6.1 The handset, and the TEE census

`duchamp` is the [Redmi K70E](https://www.gsmarena.com/redmi_k70e-12716.php) (China model
`2311DRK48C`), sold globally as the [POCO X6 Pro
5G](https://www.gsmarena.com/xiaomi_poco_x6_pro-12751.php), on a MediaTek [Dimensity
8300-Ultra](https://www.mediatek.com/), MT6897. *[PRIMARY]*

*[MEASURED]* A census of all 1902 files in the public vendor tree
[`mt6897-devs/vendor_xiaomi_duchamp`](https://github.com/mt6897-devs/vendor_xiaomi_duchamp) at
`lineage-23.2`: *43 hits for `mitee`*; *zero* for `thh`, `thhadmin`, `beanpod`, `teei` or
`microtrust`; *zero* for `trustonic` or `kinibi`. OP-TEE's normal-world userspace (`tee-supplicant`,
`libteecli.so`) is present, as is a GenieZone image.

*[PRIMARY]* The KeyMint HAL embeds its own build paths, which name OP-TEE's `optee_examples` tree
verbatim. Its trusted application begins with the magic `fd 89 ee` followed by `"mitee"`, and its
strings carry a porting layer — a keymaster context, a remote-provisioning context, secure-deletion
storage and a storage manager — wrapping Google's reference keymaster implementation. The vendor
interface manifest declares KeyMint [AIDL](https://source.android.com/docs/core/architecture/aidl)
*v3* with both `IKeyMintDevice/default` and `IRemotelyProvisionedComponent/default`, and *no
[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox) instance*;
the trusted application itself carries the string `STRONGBOX: don't support`.

That last fact is load-bearing twice over: it is why the
[VTS](https://source.android.com/docs/core/tests/vts) multi-stage-DICE requirement does not apply to
this handset ([`2-mechanisms.md`](2-mechanisms.md) §7.1), and it is why a Phase-1 degenerate chain
is a conforming request there rather than a malformed one ([`1-protocol.md`](1-protocol.md) §4.5).

Correspondence between the public vendor tree and real firmware is established *by hash rather than
by assumption*. The [LineageOS](https://lineageos.org/) tree is a community extraction carrying no
manifest and no build properties, with only one commit naming a source build. Git [blob
identifiers](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) from it were compared against
four independent stock firmware dumps on
[`dumps.tadiphone.dev`](https://dumps.tadiphone.dev/dumps/redmi/duchamp) — China-region ROMs, a
separate provenance chain. The invariant trusted applications match exactly across both sources
while those that churn differ between them, which is the pattern expected when the tree tracks real
firmware and those applications are genuinely rebuilt per release (§6.6).

This establishes *tree ↔ real firmware*. It does *not* establish *this handset ↔ the leaked
samples*; see [`2-mechanisms.md`](2-mechanisms.md) §10.3.

### 6.2 MiTEE is Zircon, not OP-TEE — and what that excludes

*"MiTEE is an OP-TEE derivative" is true only of its normal-world stack and its API surface.* The
secure world is something else entirely, and the distinction decides which published vulnerabilities
can apply at all.

*[MEASURED]* Parsing `PT_DYNAMIC` directly out of each trusted application's
[ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) — necessary because the images have no
section headers, so `readelf --dyn-syms` returns nothing and the symbol table must be walked through
`DT_SYMTAB` and `DT_STRTAB` — every one of six examined TAs, including KeyMint, lists `libc.so`,
`libfdio.so`, *`libzircon.so`* and `libasync-default.so`, imports *27 to 28 Zircon syscalls*, and
imports *zero*
[GlobalPlatform](https://globalplatform.org/specs-library/tee-internal-core-api-specification/)
`TEE_*` or `utee_*` symbols.

The [imported syscalls](https://fuchsia.dev/reference/syscalls) span the whole capability model —
virtual memory object read/write and mapping, channel read/write/call, ports and async waits, handle
management, exception binding and resume, clocks and timers, a cryptographic random draw, feature
queries, and a guest trap.

*[MEASURED] The secure-operating-system image settles it outright.* The TEE partition image carries
a MediaTek header naming it `atf` — [Trusted
Firmware-A](https://www.trustedfirmware.org/projects/tf-a/) BL31 — followed by a standard Zircon
boot image container holding a `KRN8` ARM64 Zircon kernel and a `BFSB`
[LZ4](https://github.com/lz4/lz4)-compressed [Fuchsia](https://fuchsia.dev/) bootfs. Marker counts
across the whole image: `OP-TEE`/`optee` *zero*; `tee_ta_manager`, `ree_fs_ta`, `libutee`,
`pseudo_ta`, `core/arch/arm`, `SHDR_MAGIC`, `tee_svc_storage` all *zero*. Against `zx_` ×432,
`zircon` ×20, `fuchsia` ×17, and named Fuchsia services including a service host, a TA manager and a
secure-element service. *`optee_os` is entirely absent from the secure world.* The counts
under-represent bootfs component strings, since that section is compressed.

*[MEASURED] The vendor extends the Zircon syscall ABI.* The image's
[vDSO](https://man7.org/linux/man-pages/man7/vdso.7.html) name table lists non-upstream calls beside
the standard ones, including TEE configuration and physical-address queries, shared-memory and
buffer accessors, a memory-statistics call, guest creation and trap installation, and a
[futex](https://man7.org/linux/man-pages/man2/futex.2.html) variant. This is vendor-authored
secure-kernel surface with essentially no public footprint, and it is where the platform's real
secure-kernel attack surface lives — not in any OP-TEE CVE. The presence of a
*[hypervisor](https://en.wikipedia.org/wiki/Hypervisor)* API in a trusted application is unexplained
*[SPECULATIVE]*.

*Every MiTEE trusted application is a Zircon userspace process.* The [GlobalPlatform Internal
API](https://globalplatform.org/specs-library/tee-internal-core-api-specification/) names that
appear in the strings are *statically linked in* — the vendor's own compatibility shim compiled into
each application — not dynamic imports and not a kernel interface. The kernel ABI a TA actually
speaks is Zircon's.

The consequences for vulnerability applicability are sharp. At the secure kernel, *no* upstream
OP-TEE CVE can apply, because there is no `optee_os` core to be the target. At the TA-side
GlobalPlatform API, the interface is inherited but the implementation is the vendor's, so an
upstream `libutee` bug indicates a *class* to look for, not the same bug. Secure storage inherits
protocol and key-hierarchy *design*, so a faithful reimplementation could inherit a design flaw but
not a code CVE. Only the Linux driver, supplicant and client library are genuinely forked OP-TEE
code — and they are worthless as targets here, because normal-world root is already public on this
handset (§6.5).

The published chain that reaches EL3 on a *sibling* Xiaomi handset is architecturally absent on this
one: no Beanpod runtime, no `/vendor/thh/ta`, no `thhadmin`, no `teei` module. A library whose name
suggests the Beanpod client is a 5,648-byte thermal shim reading a CPU-temperature proc node.

The practical takeaway generalises past this device: *the large published OP-TEE CVE inventory does
not supply a missing step here*, and the surface a compromised TA faces is a general-purpose
microkernel ABI with no public TEE-context research at all — a materially larger and differently
shaped target.

### 6.3 Where the DICE seed lives

*[PRIMARY]* The KeyMint trusted application's strings describe the lifecycle of the object directly.
They include a check for an existing *bcc key secret*, its creation, an "already created" path, a
success path, and failure paths for opening, reading and writing it. And they include a *migration*:
messages for changing the key "from sfs to rpmb", success and failure for that change, failures to
create and write an
[RPMB](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#rpmb-secure-storage)
flag, and three RPMB states — supported for RKP, supported, and *not supported*. One source line
even reads, verbatim, *"Because RPMB is not usefull, Can't read id."*

The DICE and certificate-chain tokens present are extensive — a BCC key creation routine, a main
flow, a KDF, keypair-from-seed and keypair-from-CDI routines, *a P-256 keypair-from-CDI routine*, a
public-key derivation, sign and verify, [COSE](https://www.rfc-editor.org/rfc/rfc9052) public-key
encoding and sign-and-encode, a vendor certificate generator, and both CDI names. Storage is
GlobalPlatform persistent objects over an OP-TEE REE-filesystem RPC. Cross-world strings name a
hardware-backed certificate service with a sign-key call, a protected-data getter, a sign-MAC
command and an AAD size limit.

*[INFERRED]* In OP-TEE, the [secure file
system](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html) backed by the REE
filesystem stores GlobalPlatform persistent objects as encrypted files *in the normal world*,
written through the supplicant and sealed under a hardware-unique-key-derived hierarchy. So the *bcc
key secret* is *persisted rather than derived per boot*, *created once* on first use, and
*originally in the secure file system*, with a migration to RPMB *that can fail*. On any unit where
the migration has not run or RPMB is unusable, the device's DICE root identity sits in a
normal-world file — as ciphertext. This is the storage-layer *fail-open* that
[`2-mechanisms.md`](2-mechanisms.md) §10.2 treats as a structural property, and it applies equally
to two other persisted secrets the same application holds.

*[INFERRED, moderate]* On the DICE curve: the only named curve helpers are P-256 ones. There is no
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032) or P-384 keypair routine of the kind open-dice's
multi-algorithm profile carries, and the [Curve25519](https://www.rfc-editor.org/rfc/rfc7748) code
present traces to the general-purpose
[BoringSSL](https://boringssl.googlesource.com/boringssl/)-derived EVP surface. This leans toward
this handset's DICE keypair being *P-256*. Because the binary is stripped — no section headers and
no exported dynamic function symbols, so these tokens are *strings* rather than symbols — the
absence of a string is not proof.

That curve question has a consequence. The Python minting implementation builds an *Ed25519*
degenerate chain; if this handset's registered `UDS_pub` is P-256, an Ed25519 chain built from its
seed would fail the registry match and draw HTTP 444. Current upstream has *added* a P-256 option
*[MEASURED]*, so this is no longer a contradiction — but which curve the device actually registers
remains unmeasured.

A *separate factory* attestation key lives in RPMB, independent of the RKP path: the application's
strings carry fallbacks for failing to read an attestation key and an attestation chain from RPMB,
and name both an RSA and an EC root attestation key.

One string is unidentified: a failure message about signing the MAC key on an unexplained
three-letter subsystem. A hash-algorithm name appears elsewhere in the same binary with nothing
tying the two together.

*[MEASURED]* The derivation label the minting tooling once used — `rkp_bcc_km` — appears in *zero of
16 binaries searched* on this platform: all 17 shipped trusted applications across two builds, the
KeyMint HAL, and the TEE's normal-world library. The DICE routines named above *are* all present in
those same files. The tool's hardware-KDF label was not read off this device. §4.4 and
[`2-mechanisms.md`](2-mechanisms.md) §9.3 give that measurement its scope.

Finally, the architecture of the storage path is itself a measurement. This platform relocated
OP-TEE's secure-storage stack *out of the secure kernel and into a userspace Fuchsia service*, which
carries the upstream `core/tee/` code effectively verbatim — the filesystem key manager, the RPMB
filesystem, the directory-file layer, the file-encryption-key crypto, the
[hash-tree](https://en.wikipedia.org/wiki/Merkle_tree) sync and the
[one-time-programmable](https://en.wikipedia.org/wiki/Programmable_read-only_memory)
hardware-unique-key accessor. *[MEASURED]* the image contains the custom TEE-configuration syscall
and a hardware-unique-key marker; *[PRIMARY]* that service calls the syscall to obtain the key and
runs the entire file-encryption and hash-tree stack in userspace. The KeyMint application holds
*none* of that crypto: it issues filesystem RPCs and receives *plaintext* persistent-object data
back.

Three consequences reshape the problem, and they are why [`2-mechanisms.md`](2-mechanisms.md) §10.2
states the unbridged step the way it does. The secret *transits a sibling userspace process in
plaintext*, so the target is that service rather than the secure kernel. Cross-application *naming*
is nonetheless closed: the upstream storage lookup's UUID parameter was replaced by a
storage-identifier selector, so no UUID crosses the boundary and the service identifies its caller
by an unforgeable channel — a compromised sibling cannot simply *ask* for another application's
namespace. And the storage layer fails open, per the migration strings above.

### 6.4 Published trusted-application vulnerabilities, and the overlap with the shipped store

*[PRIMARY]* [TÄMU](https://arxiv.org/abs/2601.20507) — Mao, Shi, Busch and Payer, EPFL HexHive —
emulates 67 trusted applications across four TEEs and reports *17 zero-day vulnerabilities across 11
applications*, all responsibly disclosed. Its results table carries *no CVE column*: the 17 were
disclosed but never publicly numbered, so patch status cannot be checked against any bulletin. Of
those 17, *10 are on this platform*, and *7 were reproduced on a physical device*, with two of them
yielding arbitrary-read primitives.

*[MEASURED]* Intersection with this handset's shipped store of 17 applications: of the 8 MiTEE
applications named in the paper, *7 ship here* — one is absent. Of the *5 with a device-reproduced
vulnerability, all 5 ship here*, two of them carrying arbitrary read.

Two bounds keep this honest. The vulnerabilities are in *sibling* applications, not KeyMint — the
KeyMint application is actively maintained (§6.6). And *no public dump of the current firmware
generation exists* — the newest public stock dump predates the build string the leaked sample names
by roughly seven months — so the vendor-tree import is the best available proxy for what ships
today.

The emulator's public support for this platform is itself the cheapest high-value follow-up
available: it ships 17 containers, 16 configurations and 14 harnesses covering all eight
applications named in the paper, and its copy of one of them is byte-identical to this handset's.
Its known gaps are that it does not emulate application-to-application calls — so it cannot test the
storage-service bridge of §6.3 — and that the KeyMint application is prepared but unfuzzed, its
configuration recording an unresolved session entry-point offset.

### 6.5 Normal-world root, on a locked bootloader

*[PRIMARY]* A public one-click root tool exists for this exact handset and Android version, GPLv3,
naming the device, the system-on-chip, kernel `6.1.138-android14-11`, Android 16 (API 36), and
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499). Its stated chain is a
[kernel-address leak](https://en.wikipedia.org/wiki/Address_space_layout_randomization) through a
[`pselect`](https://man7.org/linux/man-pages/man2/select.2.html) timing
[side-channel](https://en.wikipedia.org/wiki/Side-channel_attack) aliased onto logged packet data,
file-operations hijack by a priority-inheriting futex requeue race, a forged pipe-buffer operations
table yielding *arbitrary kernel physical read and write*, then credential patching to uid 0 with
full capabilities,
[seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) disabled and
[SELinux](https://source.android.com/docs/security/features/selinux) set permissive, delivering an
embedded root manager. Delivery is a library constructor by `LD_PRELOAD`. Under prerequisites it
says, in as many words, that an unlocked bootloader is *not* required — the preload path works
either way.

*[PRIMARY]* The underlying CVE, from the MITRE record, is an upstream *Linux* bug rather than a
vendor one: a real-time-mutex waiter-removal defect in the proxy-lock rollback path invoked from
futex requeue, affected from 2.6.39, [CVSS 3.1](https://www.first.org/cvss/v3-1/) base 7.8 HIGH with
local access and no user interaction. That corroborates the exploit's second stage precisely, and
from a source unrelated to the tool.

*[INFERRED]* What this position gives: unrestricted access to the normal-world files backing the
TEE's secure storage — the DICE secret's container, as ciphertext; the ability to drive the TEE
device node, the supplicant, the client library and arbitrary trusted-application sessions, which is
an open door to the vulnerable applications of §6.4; the ability to instrument the KeyMint HAL and
the [GlobalPlatform client](https://globalplatform.org/specs-library/tee-client-api-specification/)
library; and `system`-uid peer access to the keybox installer daemon of §6.7. What it does *not*
give: [TrustZone](https://www.arm.com/technologies/trustzone-for-cortex-a)-protected memory. Kernel
physical read/write does not read secure-world memory and does not yield the storage sealing key,
which is derived inside the TEE.

*This closes the access question that previously carried a structural argument.* The strongest
argument that an operator must break [verified
boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot) — and thereby
contradict the locked, approved state a forged artifact asserts — was that bootloader unlocking is
administratively blocked in the handset's home region. A locked, verified-boot-intact stock Android
16 unit reaches uid 0 with SELinux disabled and arbitrary kernel physical read/write, with
verified-boot metadata untouched. Access is not the obstacle; §10.2 of
[`2-mechanisms.md`](2-mechanisms.md) states what remains.

*[UNVERIFIED]* The tool names no tested build of the current firmware generation and targets a
specific kernel string, so whether it runs on the build named in sample A's extension is not
established.

### 6.6 The trusted-application container, measured

Several designed acquisition schemes turned on this container's rollback semantics, so its header
was mapped directly across *38 images* — six UUIDs across four stock ROMs and five vendor imports.

| Offset | Size | Content | Evidence |
|---|---|---|---|
| `[0:8]` | 8 | magic `fd 89 ee` + `"mitee"` | constant, 38/38 |
| `[8:12]` | 4 | a format tag | *constant, 38/38* |
| `[12:16]` | 4 | payload length, *big-endian*, = filesize − 336 | exact, 38/38 |
| `[16:48]` | 32 | *SHA-256 of the payload* | exact, 37/37 |
| `[48:80]` | 32 | *SHA-256 of header bytes 0–47* — the value actually signed | exact, 37/37 |
| `[80:336]` | 256 | [RSA-2048](https://www.rfc-editor.org/rfc/rfc8017) PSS signature | [entropy](https://en.wikipedia.org/wiki/Information_entropy) 7.24 bits/byte |

Three results follow, and each killed a scheme.

*No version field exists in the container header.* The only fixed-position candidate never varies
across any sample or ROM, and the format is *not* OP-TEE's, so upstream reasoning about its TA
loader does not transfer. Anti-rollback is not absent from the platform, however: the secure-OS
image carries an old-version marker and the TA loader maintains a separate version store — so the
rollback question is *where* the version is tracked, not whether it is, and that store sits in a
secure-world service rather than a normal-world file root can delete.

*Trusted-application bodies ship unencrypted.* The container is a 336-byte header followed by a
plain AArch64 ELF: `\x7fELF` at offset 336, ELF64 LSB shared object, with an
[entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of 2.31 bits per byte over the
first 4 KB after the header where ciphertext would sit near 8.0. TA bodies are readable and
disassemblable straight out of the vendor partition, which is what makes third-party emulation of
them (§6.4) practical at all.

*The signature uses a random salt, so file-level hashing overcounts code churn.* Identical payloads
are re-signed differently on every ROM build. Comparing payloads — the file past the 336-byte header
— instead of whole files:

four applications have *one* distinct payload each across all nine sources and *were never rebuilt*;
two others have two payloads each across five or six files, so each was rebuilt *once*, not five or
six times; and the KeyMint application has three distinct payloads across three files — *genuinely
rebuilt three times.*

That last row is the *control*, and it is what makes the rest readable: the extraction pipelines
demonstrably do pick up application updates. Against that control, the four applications carrying
device-reproduced bugs — *including both arbitrary-read primitives* — have byte-identical payloads
from the launch ROM to the most recent vendor import, a span of more than two years. That code has
never been rebuilt.

One ordering note *[MEASURED]*: the single real rebuild of the application with a reported buffer
underflow falls in the first nine months after launch — *before* the paper that reported the bug
published — so it cannot have been a fix for it. An earlier speculation to the contrary is
withdrawn.

A method note worth carrying, because it produced a false reading once: `git diff --name-status`
marks all 17 applications modified in the most recent commits, which is misleading, because those
commits touch about 1800 files and are whole-tree re-imports. *Compare blob identifiers, not diff
status.*

### 6.7 A normal-world keybox installer ships on retail

*[MEASURED]* The MediaTek command-line keybox front-ends are absent from this handset — zero matches
for any of the usual names. *The capability nevertheless ships*, in a 149,241-byte vendor library
whose symbols include a keybox installer taking a buffer and length, an XML keybox parser over a
libxml node, a keybox checker, device-identifier check/clean/install routines, an RPMB key installer
and state check, EC and RSA attestation checks, a key generator taking an authorisation set and an
optional attestation key, and a key-manager class with install, load, clear, prepare and dump. Its
strings include *a normal-world keybox path it reads*, a log tag, a message pairing a device
identifier with a project code, installation-failure and type-mismatch messages, an RPMB state
report, a message about a device supporting DRM level 1 but failing a keybox check, and — verbatim,
with its original spacing — *"This device support rkp , but not upload public key"*.

*[PRIMARY]* Its consumer is a 15,824-byte AArch64
[position-independent](https://en.wikipedia.org/wiki/Position-independent_code) boot service,
declared in an [init
script](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/README.md) to
run as `user system` in groups `system keystore drmrpc`, started on `sys.boot_completed`.

So *a `system`-uid daemon in the keystore group runs at every boot, linked against a library that
installs an XML keybox from a normal-world path into the TEE.* Whether the TA-side command it
reaches is gated — by caller identity, a provisioning lock, or RPMB state — is *not established
here*, and it is the single most interesting unanswered question about this platform.

That last string is worth isolating: it records a device state in which RKP is supported but *the
device public key was never uploaded to the backend* — exactly the registration step that
[`1-protocol.md`](1-protocol.md) §6.1 shows everything depends on.

---

## 7. Threats to validity

*Nothing in §6 or in the field-route measurements was reproduced on hardware in the compiling
sessions.* What was checked locally is the artifact layer: file digests, container metadata,
patch-script constants, protocol constants against AOSP's CDDL, and the arithmetic of every
cross-document claim. Per-route claims stay at *[REPORTED]*; [`5-sources.md`](5-sources.md) §3
appraises each record.

*Quantities the corpus reports inconsistently.* Three issuance-adjacent counters are conflated in
the sources and are separated in §3.3. Serial encodings in the revocation list are inconsistent
between decimal and hex, and a matcher that tests only one form silently under-reports — which is
why §5.3 tests both. The EC private key [DER](https://www.itu.int/rec/T-REC-X.690) length differs
between devices (121 against 138 bytes) purely by which optional
[SEC1](https://www.secg.org/sec1-v2.pdf) fields are present, so no length is a format constant.

*Mutable substrate.* The revocation list, the CRL, the public vendor tree and the upstream minting
tools all change under measurement. Every value in §4.2 is dated; the upstream tool's `--hw-key`
path was removed after it was measured, so the measurement of §4.4's label question describes a
revision that no longer exists upstream; and the vendor tree gains whole-tree re-imports that defeat
diff-status reading (§6.6).

*Sample size.* The issuance-count bucket inference rests on five observations. The tag-5
presence/absence reading rests on two samples. The platform forensics of §6 describe *one* handset
model, and §6.2's exclusion of an OP-TEE CVE inventory is a statement about that platform, not about
MediaTek TEEs generally.

*Vulnerability feeds undercount the risk they appear to measure.* Three independent studies make the
same point from different angles: an in-situ fuzzer found 40 unique bugs across four handsets with
*exactly one* CVE assigned at publication; a systematic study of a missing-type-check class across
14,777 trusted applications from 545 firmware images confirmed 33 bugs and disclosed four CVEs with
ten still under responsible disclosure; and the emulation paper of §6.4 added 17 more carrying *no
CVE numbers at all.* So *a risk model built from a CVE feed alone will be wrong about trusted
applications*, and the absence of a CVE for a platform says more about who has looked than about
what is there. This series' own platform determination (§6.2) is the corollary: an inventory of CVEs
against one TEE implementation says nothing about a device running a different one.

*Absence of evidence.* Where a claim is an absence — no OP-TEE markers in the secure world, no
version field in the container header, no published cross-application primitive — the measurement
bounds the search, not the universe. A stripped binary in particular means *the absence of a string
is not proof of the absence of code* (§6.3).

*Point-in-time observations.* The two Google roots and the RKP-exclusivity dates, the published
extension schema, the backend's endpoint set and the VTS requirements are all version- or
policy-dependent and carry [`1-protocol.md`](1-protocol.md) §8.1's standing caution.

---

## 8. What would refute the load-bearing claims

*Leaf lifetime as a class discriminator* (§2.1) — an RKP leaf with a multi-year span, or a factory
keybox leaf with a two-week one.

*That the RKP and factory populations do not overlap* (§4.1) — one file in the public pool carrying
a `Droid CA*` issuer or the provisioning extension.

*That 56% of the revocation list is one leak* (§4.3) — a recount showing materially fewer of the
list's serials present in that corpus, or a demonstration that the serial-form bucketing miscounts.

*That the issuance count is a per-device approximate 30-day figure rather than a cap* (§3.3) — it is
already settled by the existence of a third value; what remains open is the bucketing, which a
measured non-power-of-two value would refute.

*That the stock baseline is single digits* (§3.3) — a stock handset reading a three-digit tag 1 on
the experiment of §5.2.

*That tag 5.2 is build-scoped* (§3.2) — two tag-5-bearing certificates from different devices on the
same build with *different* 5.2 values.

*That this platform's secure world is Zircon and no OP-TEE CVE can reach its kernel* (§6.2) — any
`optee_os` core marker in the secure-OS image, or a dynamic GlobalPlatform import in any TA.

*That the DICE secret is created-once and persisted* (§6.3) — contrary behaviour from an emulation
of the creation routine, or a device whose `UDS_pub` changes across a factory reset, which would
also refute the survives-a-wipe inference of [`2-mechanisms.md`](2-mechanisms.md) §7.2.

*That four vulnerable applications were never rebuilt* (§6.6) — a differing payload for any of them
in a dump of the current firmware generation. None is public, which is this measurement's
sample-edge.

*That the container header carries no version field* (§6.6) — a fixed-position field increasing with
build date in a wider sample.

*That `rkp_bcc_km` is absent from this platform* (§6.3) — one hit in any shipped binary from this
vendor or chipset family. Note that this would *not* refute the per-vendor scope note of §4.4, which
the Kinibi and Qualcomm measurements establish independently.
