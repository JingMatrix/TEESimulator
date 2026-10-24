# 3. Detection and defence

Index: [the index](README.md). Companion parts: [part 1](1-protocol.md), [part 2](2-mechanisms.md),
[part 4](4-measurements.md), [part 5](5-sources.md).

## Abstract

Hardware attestation is a strong negative filter and a weak positive assertion, and most
verification failures arise from treating it as the reverse. This part begins with acceptance: the
five intermediate states that resemble a result, and the three independent layers that exclude them,
including the layer that binds material to the handset in front of the verifier, which is usually
omitted. It then measures the control plane Google publishes: two trust anchors that must both
remain in the store permanently, a root whose certificate has been re-issued four times under one
unchanged public key, and a revocation list whose entries arrive in two different serial encodings,
so that a verifier rendering serials only in hexadecimal silently fails to match approximately 56
per cent of what is revoked. The detection signals follow, ordered by resistance to suppression:
chain shape, the issuance count and provisioning status in the provisioning-information extension,
leaf lifetime, fan-out on the attestation key, and pinning on first use. A forgeability analysis
states what a keybox holder authors freely, which is nearly every field inside the attestation
extension, the module hash included, and the short list of what cannot be forged. In the coverage
matrix of [§9](#9-coverage-of-mechanisms-by-control) two columns are empty: boot-chain spoofing and
relay produce genuine signatures from genuine unrevoked keys, and nothing in the certificate
distinguishes them.

---

## 1. Acceptance criteria

Both field records devote more space to acceptance than to exploitation. This is the reusable part
of all four routes, and it serves a verifier as much as an operator.

### 1.1 States that resemble success

All three extraction routes passed through these states: output exists but is not the target
material; a private key exists but is not the device identity; an HTTP 200 response arrives but the
certificate's provisioning status is unacceptable; the device booted but its measurement state is
wrong; and a certificate chain verifies but the private-key correspondence does not hold.

Each of the three layers below exists to exclude one or more of them.

### 1.2 Three layers for an extracted keybox

```
layer 1   PublicKey(private_EC)  == PublicKey(ec_leaf_certificate)
          PublicKey(private_RSA) == PublicKey(rsa_leaf_certificate)
layer 2   leaf signed by intermediate; intermediate signed by root;
          root self-signed and constraints valid
layer 3   trigger a fresh attestation through the Android keystore and compare the
          resulting leaf against the extracted keybox's certificates
```

All three are required. Layers 1 and 2 alone cannot exclude a random key pair, a keybox for another
purpose, a misaligned parse, a test authority, or well-formed material belonging to a different
device. Layer 3 is the layer usually omitted and the only one that binds the material to the handset
in front of the verifier.

### 1.3 Relations for a minted certificate chain

```
same-round leaf public key  ==  envelope signing identity
software private's public   ==  submitted key-array public key
software private's public   ==  returned leaf certificate public key
leaf -> intermediate -> root, terminating in one self-signed root
```

Additionally: the [CBOR](https://www.rfc-editor.org/rfc/rfc8949) is
[canonical](https://www.rfc-editor.org/rfc/rfc8949#section-4.2); no field foreign to the version-3
payload has entered it; the device information matches the target profile; the endpoint key and the
challenge are fresh; every returned certificate is consumed; and there is no duplicate leaf, broken
link, cycle or stray extra certificate.

The verifier in `Duck-ToolBox` implements most of this and is worth reading as a checklist. It pins
the envelope version to 1 and the payload version to 3, pins the test-key label and the
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/) profile-name label
with a required value, rejects a chain shorter than two elements, enforces canonical map ordering,
pins all 14 permitted device-information keys with their value domains (`green|yellow|orange`,
`locked|unlocked`, `tee|strongbox`), requires a 32-byte verified-boot metadata digest, enforces
field-count rules per security level, and requires every submitted key to be an ES256
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)
[COSE_Key](https://www.rfc-editor.org/rfc/rfc9052#section-7).

### 1.4 Gates the chain does not supply

*Provisioning status.* Parse [object identifier](https://www.itu.int/rec/T-REC-X.660)
`1.3.6.1.4.1.11129.2.1.30`, preserve unknown fields, and gate on the status explicitly. A
`NOT_APPROVED` verdict must not be overridable by a valid chain ([part 2
§6.6](2-mechanisms.md#66-a-causal-correction)). `Duck-ToolBox` has no such gate: the only two object
identifiers in its entire workspace are the EC public-key and P-256 curve identifiers.

*Signature verification on the returned chain.* That implementation links its chain by subject and
issuer name alone; its signature-verification type appears in exactly one file in the workspace,
where it verifies [COSE](https://www.rfc-editor.org/rfc/rfc9052) rather than
[X.509](https://www.rfc-editor.org/rfc/rfc5280). Name linkage catches a misordered chain, not a
substituted one.

*Same-round identity binding.* The [constant-time](https://en.wikipedia.org/wiki/Timing_attack)
comparison of public-key information described in [part 2
§6.4](2-mechanisms.md#64-same-round-capture), against a native request from the same boot.

The first two are the gates [part 1 §8.2](1-protocol.md#82-an-unimplemented-verification-step)
identifies as missing from this project's own inspector, and the first is the gate whose absence
cost a field result.

### 1.5 Parsing discipline

Generalising [part 2 §4.4](2-mechanisms.md#44-layout-of-the-plaintext) and [part 2
§5.5](2-mechanisms.md#55-descriptor-and-payload-format). Lengths and offsets measured in one round
describe that sample rather than the format: a descriptor length of 168 and a payload length of 8578
constitute a structural gate rather than a proof of success. Parse by length prefix; confirm every
length against the parsed object's own internal length; and never parse at fixed offsets, since the
same [SEC1](https://www.secg.org/sec1-v2.pdf) private key occupies 121 bytes on one device and 138
on another depending only on which optional fields are present. Classify the tail rather than
ignoring it: a buffer whose copy was shorter than its contents retains residue that can parse as
plausible [DER](https://www.itu.int/rec/T-REC-X.690).

### 1.6 Synthetic chains and the division of labour

`Duck-ToolBox` synthesises a degenerate two-element chain rather than accepting a captured one: the
chain head's device secret public key is the identity key's own structure, the single entry is
self-signed by the same private key and carries no boot measurements, and the length is exactly two,
the validator's own minimum. Its command-line interface exposes profile, seed, hardware key,
derivation label, curve and server address, and no input for a captured chain. The field corpus's
own issuance command passes one explicitly, sourcing the chain material from the same round's native
request, and its [HTTP
444](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RkpdException.java)
checklist lists a degenerate chain with the wrong device secret among the first things to check.

That is consistent with the tool's design rather than a defect in it: it falls back to a local test
endpoint key when the fetch fails, so the synthetic chain supports offline exercise of the protocol.
The division of labour is that the routes supply a signing capability the server will accept, while
the tooling supplies the protocol, the verifier and the product assembly. Running the tooling alone
yields a self-consistent request that will not be signed, which is [part 1
§6.2](1-protocol.md#62-self-consistency-and-anchoring) stated from the attacking side.

---

## 2. The control plane

Every value in this section was fetched live. The control plane changes, and values should be
re-measured before being relied upon.

### 2.1 Two trust anchors

On one live fetch, `https://android.googleapis.com/attestation/root` returns a bare JSON array of
[PEM](https://www.rfc-editor.org/rfc/rfc7468) strings — at the time of measurement, exactly two.

| | Legacy root | Provisioning root |
|---|---|---|
| Subject | `SERIALNUMBER=f92009e853b6b045`, self-signed | `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` |
| Certificate serial | `F1C172A699EAF51D` | `84A9D0297B0EB58AE7FF0E80DE760605` |
| Key and signature | RSA-4096, `sha256WithRSAEncryption` | [ECDSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) secp384r1, `ecdsa-with-SHA384` |
| Validity span | twenty years | ten years |
| Certificate [SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | `CEDB1CB6…800DFC` | `6D9DB4CE…BA4BCC0` |
| Public-key-information SHA-256, base64 | `/rLqdVHuMW7Uu0Q8gpO4hNv96kC2A+4+T0qJfkWA+64=` | `PuRFEqGvK+s5yIlJDGDqP4LkP11aVTL1q5QZ9nbNB+w=` |

Pinning should target the hash of the [subject public key
information](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7) rather than the certificate
fingerprint. Google's documentation lists three previously issued root certificates, with serials
`E8FA196314D2FA18`, now expired, `D50FF25BA3F2D6B3` and `C36B7C44B9AE1831`, and all three carry the
same public-key hash as the live root: one RSA key, re-issued four times. A verifier pinned on
certificate fingerprints breaks on every re-issuance, while one pinned on the public key does not.
[GrapheneOS](https://grapheneos.org/articles/attestation-compatibility-guide) correspondingly pins
five root certificates rather than one.

The widely repeated claim that the old root is [RSA-2048](https://www.rfc-editor.org/rfc/rfc8017)
and the new one RSA-4096 is wrong in both halves: the legacy root is RSA-4096 and the new one is
ECDSA P-384.

Both roots must remain in the trust store permanently. Factory-keyed devices cannot rotate, and
Google's guidance is to continue trusting chains to the legacy root irrespective of certificate
validity period, because older factory devices legitimately present expired certificates, while
provisioned certificate validity must still be checked, the short expiry being a deliberate part of
the threat model.

On the rotation schedule, attribution matters. Google's documentation states only when the new root
*"will begin signing attestation certificate chains."* The later exclusive-use point for provisioned
devices, approximately ten weeks after that, comes from a third-party enterprise publication rather
than from Google, and a frequently quoted intermediate deadline appears on no Google page and is not
carried here. The cutover should be read from Google's current page rather than from a document: a
verifier that adds the new root late rejects every provisioned chain in the interim.

### 2.2 The revocation list

Fetched twice independently, the endpoint
[`android.googleapis.com/attestation/status`](https://android.googleapis.com/attestation/status)
returns JSON with `cache-control: public, max-age=86400`, so daily refresh is the appropriate
cadence.

At the time of measurement it held 1,738 entries, all with status `REVOKED` and none `SUSPENDED`,
comprising 1,712 attributed to key compromise and 26 to a software flaw. No entry carried the
schema-permitted expiry or comment fields. The published
[draft-07](https://json-schema.org/draft-07/schema) schema requires a top-level `entries` dictionary
mapping serial to `{ status: REVOKED|SUSPENDED, expires?: YYYY-MM-DD, reason?:
UNSPECIFIED|KEY_COMPROMISE|CA_COMPROMISE|SUPERSEDED|SOFTWARE_FLAW, comment?: <=140 chars }`. The
common reading that revocation is permanent and suspension temporary is a conventional
[certificate-revocation-list](https://www.rfc-editor.org/rfc/rfc5280#section-5) interpretation; the
schema assigns no permanence semantics at all.

Growth, from a community archive of eight successive snapshots spanning ten months: 1,594, 1,604,
1,608, 1,614, 1,638, 1,654, 1,720, 1,738. That is approximately 144 additions over the period,
arriving in clusters — 24 in nine days at one point, 66 over about ten weeks at another — rather
than as one publicised mass revocation. The independent series measured for [part 4
§4.2](4-measurements.md#42-revocation-list-snapshots) agrees and carries the snapshot links for
anyone re-deriving it.

Three semantics are commonly mistaken, each observed in the field. The list is not exhaustive:
absence means that no non-valid status is recorded, never that a certificate is proven good. Every
certificate in the chain must be looked up, because when a keybox leaks it is the intermediate that
is revoked and the attacker-generated leaf will never be listed, so a verifier that checks only the
leaf checks the one certificate that cannot be revoked. And a verifier should fail closed: Google's
own reference implementation fails closed on download or parse failure, which is the correct posture
for an anti-abuse verifier and the opposite of the usual default.

Revocation is also reactive by design. Google documents that leaks surface through analysis of
attestation data in the wild, discovery of keys on public sites, and researcher reports; that
revocation *"typically"* occurs within several days of discovery but may take longer; that it is
*"usually delayed if the devices affected can be securely re-provisioned"*; and that the scale of
impact affects timelines. That documented delay is the window a relying party's own analytics must
cover.

### 2.3 Serial-number encoding

The published schema states that the dictionary key is *"the certificate serial number in lowercase
hex"*, with a name pattern of `^[a-f1-9][a-f0-9]*$`, leading zeros stripped, matching the output of
Java's `BigInteger.toString(16)`. Google's reference verifier implements exactly that.

Against the live list, the 1,738 entries divide into two disjoint populations. 766 entries are 30 to
32 characters long and all contain letters in the range `a` to `f`: 128-bit serials in hexadecimal.
972 entries are 17 to 20 characters long and not one contains any letter in that range. The
probability that 972 genuine 19-hexadecimal-digit strings all avoid six of sixteen digits is
vanishing. Read as decimal, every one fits in 64 bits, and the division between 19 and 20 digits
matches the distribution of uniformly random 64-bit integers in decimal.

The division is measured; the interpretation as decimal encoding is an inference. Those 972 entries
are syntactically valid lowercase hexadecimal under the schema's own pattern, which is why nothing
rejects them and why the failure is invisible. No Google statement acknowledging a mixed encoding
could be found.

The operational consequence is that a verifier rendering each certificate serial only as lowercase
hexadecimal silently fails to match approximately 56 per cent of the currently revoked entries, most
plausibly including the older factory-keybox population that matters most, which [part 4
§4.3](4-measurements.md#43-derived-quantities) shows to be 56 per cent of the list by an independent
route.

The remedy is two lines and an instrument: parse each serial as a [big
integer](https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html), test membership for
both base-16 and base-10 renderings, optionally together with zero-stripped and lower-cased
variants, and count rejections attributable to each form. A decimal-match counter that remains zero
over a large sample indicates that revocation is probably not being enforced for the older keybox
population at all. [`tools/teesim_attest/revocation.py`](tools/teesim_attest/revocation.py)
implements both forms with per-form counts.

### 2.4 The reach of revocation

*A factory batch key is reachable.* It is long-lived, so it remains valid when the leak is noticed,
at the cost that revoking it disables attestation for an entire production run, which is why
revocation is delayed where re-provisioning is possible.

*A provisioned leaf is not reachable.* It expires faster than a revocation cycle notices it; neither
leaked sample leaf is listed; and the provisioning hierarchy's own revocation list stands at number
zero with no entries ([part 4 §2.3](4-measurements.md#23-revocation-state-of-the-hierarchy)). The
effective lever is de-registration, the removal of the device secret public key from the
provisioning registry, which is a backend edit invisible to any certificate-based mechanism, and
which [§10.1](#101-the-provisioning-backend) argues should be the fast path.

*Neither is reachable for boot-chain spoofing or relay*, because the key and the chain are genuine
and unrevoked. Section [§9](#9-coverage-of-mechanisms-by-control) renders that as the two empty
columns of the matrix.

---

## 3. Chain shape as a provisioning discriminator

Google publishes a reference verifier,
[`android/keyattestation`](https://github.com/android/keyattestation), under Apache-2.0 in
[Kotlin](https://kotlinlang.org/), which encodes the canonical order that
`KeyStore.getCertificateChain()` returns:

1. the *leaf*, carrying the key-attestation extension;
2. the *attestation certificate*, carrying the provisioning-information extension where the device
   is remotely provisioned;
3. an *intermediate*, absent where attestation is software-backed;
4. a *second intermediate*, present only where the device is remotely provisioned;
5. the *root*.

It requires at least three certificates and that the last be self-issued. The discriminators are
based on distinguished names and are directly implementable: *factory-provisioned* where the
intermediate's subject contains a serial-number [relative distinguished
name](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4), object identifier `2.5.4.5`;
*remotely provisioned* where the intermediate's subject is `CN="Droid CA2", O="Google LLC"`. For
provisioned chains the attestation certificate's subject organisation maps `"TEE"` to a
trusted-environment level and `"StrongBox"` to a secure-element level; for factory chains only
[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox) is reliably
encoded, through a case-insensitive substring in the attestation or intermediate subject.

One mechanical detail matters to a reimplementation: the library's accessor for the intermediate is
the last non-root certificate, because the trust anchor is dropped — the batch certificate on a
factory chain, the second intermediate on a provisioned chain.

Google states one caveat itself: the remote-provisioning test carries an internal note to switch to
fields in the provisioning root, so the name test is acknowledged as a stopgap. Detectors keyed on
that string may silently misclassify later chains.

A verifier should record a five-tuple per verification — chain length, provisioning method, security
level from the [distinguished name](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4),
attestation security level from the extension, and the root public-key hash — and alert where the
name-derived level disagrees with the extension level, where the provisioning method is unknown, or
where the chain is longer than the canonical four for factory and five for provisioned chains.

That shape test is the class discriminator this report measured from the other direction: a
four-certificate EC-only chain under the P-384 root is provisioned, while a three-certificate chain
carrying both algorithms under the RSA root, with a ten-year leaf, is a factory keybox ([part 4
§2](4-measurements.md#2-two-leaked-provisioned-keyboxes) and [part 4
§4.1](4-measurements.md#41-the-public-factory-corpus)). They are different populations with
different failure modes, and scoring them alike is wrong in both directions.

---

## 4. Rules at the extension level

### 4.1 The first occurrence of the attestation extension

Google's caution concerns an active attack rather than a parsing nicety: *"Don't assume that the
[key attestation](https://source.android.com/docs/security/features/keystore/attestation)
certificate extension is in the leaf certificate of the chain. Only the first occurrence of the
extension in the chain can be trusted. Any further instances of the extension have not been issued
by the secure hardware and might have been issued by an attacker extending the chain while
attempting to create fake attestations for untrusted keys."*

The procedural form is to find the certificate nearest the root that carries the extension; the
reference library achieves the same by fixing the leaf and attestation positions.

A verifier should count occurrences of object identifier `1.3.6.1.4.1.11129.2.1.17`, treating
exactly one as normal and two or more as an active attack to be logged as such rather than merely
rejected, and should verify that the attested public key equals the key it is about to trust for the
session, a check whose absence renders the rest of the chain irrelevant.

### 4.2 The provisioning-information extension

Object identifier `1.3.6.1.4.1.11129.2.1.30`, decoded byte for byte in [part 4
§3](4-measurements.md#3-the-provisioning-information-extension). It is Google's own purpose-built
abuse signal and almost nobody parses it. The reference library models only the issuance count and
exposes a logging hook; the security-level field must be parsed by the verifier.

*Issuance count, label 1.*
[Documented](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension)
as *an approximate number of certificates issued to the device in the last 30 days* that *can be
used as a signal for potential abuse if the value is greater than average by some orders of
magnitude*. It resides inside the signed certificate, so it is readable by any relying party, and a
rooted client cannot lower it without breaking the chain signature. It is the one field here that is
both visible to an adversary and unalterable by one.

What the documentation never supplied is the average. Section [part 4
§3.3](4-measurements.md#33-issuance-counts) supplies it: a stock handset read 8, while both leaked
samples read 512, approximately 64 times the baseline for the device class one of them names, in the
same 30-day window. Two cautions keep the comparison honest. All five observed values are powers of
two, which suggests a logarithmic bucket rather than a literal count, so the field should be treated
as an order of magnitude, which is how the documentation frames it in any case. And three counters
are routinely conflated: certificates returned in one batch, this signed 30-day figure, and an
unsigned same-day counter in the device's own statistics file. Only the middle one appears in the
certificate.

This is the strongest built-in signal against a handset being operated as a signing oracle, because
a handset acting as attestation-for-hire consumes certificates far faster than a genuine user's.

*Validated attested entity, label 4.* Documented as *a string indicating the certified origin of the
attested key, directly vouched for by the chipset manufacturer*, for example a trusted environment
or a secure element. A verifier should parse it and assert that it equals the attestation security
level in the key description, a disagreement between the backend's view and the device's claim being
a strong forgery indicator. It is absent from both measured samples, where the claim is carried
instead in the leaf subject ([part 4 §3.2](4-measurements.md#32-label-dictionary)).

*Provisioning status.* The undocumented verdict fields were initially catalogued as a constant
approval; an independent field record shows a `NOT_APPROVED` verdict occurring and being dispositive
([part 2 §6.6](2-mechanisms.md#66-a-causal-correction)). They are live varying verdicts, which is
what makes a decoder that drops them a verifier fault rather than a cosmetic omission. Unknown
fields should be preserved, the status surfaced, and nothing permitted to override it: not a digest
match, not a chain verification.

*Verification procedure.* Find the certificate nearest the root carrying this extension; where it is
present, the key-attestation extension must be in the immediately subsequent certificate.

### 4.3 Expiry by provisioning method

Enforce validity dates strictly on P-384-rooted, provisioning-shaped chains. This is what ages out
hoarded and relayed chains and forces an attacker to keep a live oracle online.

Do not enforce expiry on chains rooted in the legacy RSA root, where older factory devices
legitimately present expired certificates ([§2.1](#21-two-trust-anchors)).

Log the observed validity span: a provisioning-shaped chain with a multi-year window is anomalous on
its face. Measured spans are about 13 days for stock issuance, 14 to 15 days for the two leaked
samples, and about ten years for a factory keybox ([part 4
§2.1](4-measurements.md#21-leaf-validity-by-material-class)), so the two classes are three orders of
magnitude apart and the test requires no tuning.

---

## 5. Forgeability

### 5.1 Fields a keybox holder authors

With a leaked keybox, everything inside the attestation extension is attacker-chosen and internally
consistent by construction, because the attacker signs the leaf. That includes the attestation and
[KeyMint](https://source.android.com/docs/security/features/keystore) version numbers, the claimed
security level, the entire root-of-trust structure — verified-boot key, device-locked flag,
verified-boot state and hash — the operating-system version and all three patch levels, the
application identity, the whole identity-attestation set, and the module hash.

The same holds one layer up in the provisioning request: brand, model, fuse state, verified-boot
state, bootloader state, security level and the patch levels are operator-authored configuration
lines ([part 2 §7.1](2-mechanisms.md#71-the-procedure-gate-by-gate)), and the leaf's subject
organisation is downstream of one of them. A provisioning-rooted chain attests that a registered
identity requested a certificate within the last two weeks. It attests nothing about the handset in
front of the verifier.

### 5.2 The module hash

The module hash, label 724, is the SHA-256 of a DER-encoded set of package-name and version pairs,
retrievable client-side from API level 36. Its inputs are the installed module package names and
versions, which are world-readable, so a rooted attacker recomputes the expected value offline, and
a public spoofing module already does, reproducing the set ordering.

It adds no cryptographic resistance against a keybox holder. It catches only attackers who omit it
or present a value inconsistent with the operating-system version and patch level they also claim.
It is optional in the current schemas, so its absence is a soft anomaly score rather than a
specification violation; only its presence below the version that introduced it is structurally
impossible.

### 5.3 Properties that cannot be forged

A signature chaining to a Google root, without a keybox. A keybox whose serial is in the revocation
list, once Google lists it. And the issuance count and provisioning status in the
provisioning-information extension, which the backend asserts inside a Google-signed certificate
about a request it saw ([§4.2](#42-the-provisioning-information-extension)).

### 5.4 Application-identity binding

The application-identity field, label 709, is forgeable by a keybox holder, and the opposite is
often asserted. Its signing-certificate digests are digests of public certificates extractable from
any package, so no private signing key is needed to recompute them, and the field resides in the
software-enforced list of a leaf that the keybox holder signs.

The claim that it *"cannot be matched without the target's private signing key"* is correct only for
the relay class, where an honest platform on a clean device writes the field. Against relay it is
decisive; against a keybox holder it is worthless. The control should be scoped accordingly, and a
documented relay service mode explicitly substitutes the client's application details before
signing.

Proof of possession likewise does not close the relay, since the attacker relays every signing
operation. It converts a cheap one-shot into a live proxy that must remain online, adding latency,
cost and observability: an economic control rather than a cryptographic one.

---

## 6. Structural and encoder checks

These checks have low false-positive rates and incomplete coverage.

Google's reference parser already checks canonical label ordering and logs where authorisation-list
labels violate ascending order. That log line should be promoted to a scored anomaly.

The root of trust should be read only from the hardware-enforced list, never from system properties
and never from a platform-integrity verdict alone. Only the hardware-enforced list, under a
Google-rooted chain, is a claim the secure hardware makes; a root-of-trust or identity field
appearing in the software-enforced list while the chain claims a trusted environment is an anomaly.

Key origin should indicate a generated rather than an imported key, and the requested purposes
should match the relying party's protocol.

Impossible combinations are worth testing: an attestation version inconsistent with the claimed
operating-system version; an operating-system patch level in year-month form against vendor and boot
patch levels in year-month-day form, mutually plausible and not in the future; a secure-element
claim from a model with no [secure
element](https://source.android.com/docs/security/best-practices/hardware); and device-unique
attestation where it cannot appear.

A per-model, per-build fingerprint of the exact DER byte layout a real population produces allows
alerting on chains that are cryptographically valid but structurally off that manifold. This class
of check is defeated outright by a spoofer that embeds [AOSP](https://source.android.com/)'s own
reference implementation, which is what this project is, so it should be treated as
low-false-positive and incomplete.

One rule should be kept as a heuristic rather than a requirement: the proposition that the KeyMint
security level must equal the attestation security level is a third-party hardening rule rather than
an AOSP requirement. The two fields describe different things and no Google document mandates
equality.

---

## 7. Statistical and behavioural signals

### 7.1 Fan-out on the attestation key

This is the highest-yield signal available before revocation, and it requires nobody's cooperation.

Index on the SHA-256 of the attestation certificate's subject public key information rather than on
its serial, and count distinct account identifiers, install identifiers, network [autonomous
systems](https://www.rfc-editor.org/rfc/rfc1930) and application-reported build fingerprints per key
per rolling window. Genuine [hardware
attestation](https://source.android.com/docs/security/features/keystore/attestation) keys have
narrow fan-out; shared keyboxes and oracles do not. The published operational rule is that a key
belonging to a device from one manufacturer should never be reported in use by a device from
another, and that remotely provisioned keys should not be shared across notably different devices.

Clustering by chipset, board or contract manufacturer should precede any judgement that cross-brand
use is anomalous, because one design house building a reference platform for several brands can
legitimately provision one credential pool across nominally unrelated nameplates.

A cheaper variant is available to anyone holding a corpus of presented chains: count distinct
installs per leaf serial. It is the one trace the design cannot suppress.

### 7.2 Trust on first use

Pinning on first use, with monotonic non-decrease, is the strongest single defence against a leaked
keybox being used on an account that previously enrolled from genuine hardware, and it catches the
common spoofer failure of patch levels drifting downward or jumping implausibly between sessions.

The GrapheneOS attestation server is the best public worked example. At pairing it stores the pinned
certificates, verified-boot key, operating-system version, the three patch levels, application
version and security level, then rejects any later attestation that regresses any of them, with
explicit floors. It also enforces single-use challenges, requires a trusted-environment or
secure-element level, requires a secure element for new pairings, requires the device-locked flag
and a verified or self-signed boot state, uses a separate per-pairing attestation key, and rejects
any verified-boot key outside a curated published fingerprint map.

### 7.3 Expectation maps

*Model to expected provisioning method.* After the root cutover, a device that self-reports as a
modern provisioning-capable model while presenting a legacy-RSA-rooted chain is presenting a
factory-key or forged-keybox chain, which is exactly the population where keybox spoofing occurs.
This operates before Google revokes anything.

*Per-model expected boot-hash sets.* Against boot-chain spoofing, revocation cannot help, the key
and chain being genuine. The only device-side residue is the verified-boot metadata digest and the
verified-boot key hash: a device reporting a locked state while carrying a boot hash matching no
manufacturer-signed release for that model is detectable where those sets are maintained.

*Presence of the provisioning daemon.* The daemon ships as an updatable module, so its version is a
meaningful integrity input. A device reporting a modern release with a stale, absent, disabled or
replaced daemon is anomalous, and debloating guides that recommend removing it break key generation,
so its absence on an otherwise healthy device is a strong tamper signal.

*Consistency of virtualisation instances.* The unique identifier in the hardware information
distinguishes the trusted-environment and virtual-machine instances ([part 1
§5.7](1-protocol.md#57-provisioning-for-protected-virtual-machines)); a key pool in which the
virtual instance's identifier is missing or duplicated indicates an emulated HAL.

### 7.4 Pool invariants

Two invariants from the provisioning daemon's own database schema ([part 1
§5.5](1-protocol.md#55-on-disk-storage)) are observable consequences rather than internal details. A
provisioned certificate presented long past the expiry recorded for its pool entry, or the same
provisioned certificate serving two distinct application identities, indicates that the
blob-and-certificate pair was lifted from the database and replayed rather than used through the
normal path.

### 7.5 Signals of unestablished value

*Latency and jitter.* A relayed signature carries a network round trip that a local signature does
not, so the distribution should be bimodal or shifted. This is conjectural: no cited source measures
it, and nothing establishes that the distributions separate reliably against an attacker who
deliberately adds jitter.

*Keybox-distribution feeds as intelligence.* The keyboxes presented next week are published this
week, so pre-blocking their issuer serials gets ahead of the documented several-day revocation
latency. The mechanism is sound; its yield is unmeasured here. One related rule is certain: the AOSP
software-attestation keybox should be rejected outright, since it chains to a test root and never to
Google ([part 4 §4.1](4-measurements.md#41-the-public-factory-corpus) measures the distribution of
the public corpus).

---

## 8. Platform-integrity verdicts

[Play Integrity](https://developer.android.com/google/play/integrity) device-recognition verdicts
are worth incorporating, provided their boundary is respected.

On Android 13 and later, basic integrity requires a Google-provided attestation [root of
trust](https://source.android.com/docs/security/features/verifiedboot/verified-boot); device
integrity requires hardware-backed proof that the bootloader is locked and the loaded operating
system is a certified manufacturer image; and strong integrity additionally requires security
updates within the last year for both the operating system and the vendor partition. On Android 12
and earlier, strong integrity does not require recent updates, so it should be paired with the
reported interface version. An empty verdict array is itself a signal, indicating interface hooking,
rooting, system compromise or a non-Play emulator.

Three optional signals are directly relevant: a device-activity level that buckets request volume
per hour, an application-access-risk verdict, and device recall, which stores per-device bits with
month-granularity write dates that survive reinstallation and factory reset. Device recall is the
most useful anti-oracle primitive the platform exposes, since a device flagged once remains flagged
through a reset.

The boundary is that these verdicts assess the device environment rather than making a statement
about a particular key. They do not bind a key for later use, do not supply an application identity
to check against a relying party's own signing certificate, and do not establish possession.

Use them as a contradiction test: an empty device-recognition verdict arriving alongside a chain
claiming a verified boot state and a locked device is a direct contradiction and a high-confidence
spoofing signal. The same test applies within the certificate layer, since a short-lived,
Google-rooted provisioning chain attesting an unlocked bootloader or an unverified boot state is
contradictory on its face: production certificates should not issue to a device outside normal mode.

---

## 9. Coverage of mechanisms by control

Mechanism letters are the custody classes of [part 2 §2.1](2-mechanisms.md#21-custody-classes).

| Control | A. keybox leak | C. interposition | D. provisioning abuse | E. in-place replay | F. boot-chain spoof | G. relay | H. environment exploit |
|---|---|---|---|---|---|---|---|
| Pin roots by public key; reject the software root | — | catches software-root fakes | — | — | — | — | — |
| Revocation on every certificate, both serial encodings | catches, after latency | catches, same keybox | catches, same keybox | — | misses | partial, keybox-host mode only | — |
| Chain shape and model-to-method map | catches on provisioning-capable models | catches | catches | — | misses | misses | misses |
| Expiry enforcement on provisioned chains | — | — | — | bounds to the leaf lifetime | — | bounds hoarded chains | — |
| Application-identity binding | misses, forgeable | misses, forgeable | misses | partial | misses | catches cross-application relay | — |
| Proof of possession and session binding | misses | misses | misses | partial | misses | raises cost, does not close | misses, key already left |
| Fan-out on the attestation key | catches before revocation | catches | catches | — | weak | catches | — |
| Issuance-count outliers | — | — | — | catches | — | catches provisioning oracles | — |
| Pinning on first use, monotonic patch levels | catches on returning accounts | catches | catches | partial | partial | partial | catches downgrades |
| Patch-level and model risk table | — | — | — | — | only control | — | primary control |
| Per-model expected boot-hash sets | — | — | — | — | only device-side residue | — | — |
| Device recall and activity level | partial | partial | partial | partial | partial | catches farms | — |
| Encoder and layout checks | catches hand-built | misses reference-implementation emulation | — | — | — | misses, genuine | misses, genuine |

No row catches anything in the boot-chain-spoofing or relay columns. Both produce genuine signatures
from genuine, unrevoked keys, and nothing in the certificate distinguishes them.

---

## 10. Recommendations by actor

### 10.1 The provisioning backend

In order of yield.

*Rate-limit issuance per registered device secret public key.* The counter already exists: the
issuance count in the extension establishes that it is computed. Converting a published signal into
an enforced cap, with a raise available on request for test racks and the virtual-machine
population, reduces one captured seed from over 512 certificates per month to a trickle and removes
the economics without altering the protocol.

*Enforce the device-information grammar at the signing endpoint.* One measured request omitted the
mandatory verified-boot metadata digest and was signed regardless ([part 4
§3.4](4-measurements.md#34-corrections-to-earlier-readings)). The limit is that this is a one-line
evasion, since both independent tools can supply the field, so it raises the floor rather than
retiring the tool class. The durable version is the next item.

*Join the registry to the request.* Cross-check the submitted brand, model, device and product
strings and the verified-boot digest against the model the public key was registered as. The backend
already resolves the digest, which is what the extension's fifth label records, so this is one
lookup, and it prevents a registered identity certifying a build it was never shipped with. Then
bind the build fingerprint into the signed payload rather than accepting it unsigned at the
endpoint-key fetch ([part 1 §2.6](1-protocol.md#26-device-self-description)).

*Make de-registration the fast path.* With two-week leaves the status list is structurally blind
([§2.4](#24-the-reach-of-revocation)), so the path from detection of abuse to removal of the public
key must be short and automatic.

*Retire degenerate deployment for new registrations*, and not only where a secure element is
declared. On a degenerate chain one 32-byte secret is the entire device identity ([part 1
§4.5](1-protocol.md#45-legal-chain-shapes-and-deployment-phases)). Requiring a non-empty
certification map gives the manufacturer a revocable intermediate instead of a bare registry lookup.

*Give the provisioning daemon a distinguishable client identity.* A reimplementation in Python or
Rust is at present indistinguishable from the platform daemon at the transport layer, because the
daemon sends no API key, no client certificate and no pinned transport ([part 1
§5.2](1-protocol.md#52-the-protocol-exchange)).

### 10.2 The chipset and handset vendor

Drawn from the platform measured in [part 4 §6](4-measurements.md#6-the-measured-platform), though
each generalises.

*Rebuild trusted applications carrying published memory-safety defects.* Four applications with
device-reproduced defects, two of them yielding arbitrary read, have not been rebuilt since the
handset's launch image, across nine independent sources spanning more than two years, against a
control that demonstrably detects updates.

*Assume normal-world root on a locked handset.* A public one-click tool reaches privileged user
identity with [SELinux](https://source.android.com/docs/security/features/selinux) disabled and
kernel physical read and write on a locked, verified-boot-intact stock device ([part 4
§6.5](4-measurements.md#65-normal-world-root)). Any defence that assumed an unlock requirement as a
barrier is void.

*Bind application secure storage to the application image rather than to its bare identifier.*
Deriving the per-application storage key from the signed image digest rather than from the
identifier renders every downgrade and transplant route worthless in one change, and also defeats
the insider-signing variant.

*Restore a monotonic version field inside the signed region of the container, and enforce it against
replay-protected storage.* The measured container header has no such field ([part 4
§6.6](4-measurements.md#66-the-application-container)), which is what made two designed rollback
schemes worth considering at all.

*Stop shipping application bodies in the clear.* A 336-byte header followed by a plain AArch64
[ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) at 2.31 bits of
[entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) per byte is what makes
third-party emulation and fuzzing of these applications practical.

*Audit normal-world keybox installers.* A boot service running with system identity in the keystore
group, linked against a library that installs a keybox from a normal-world path, is a write-in
surface resident on retail hardware ([part 4
§6.7](4-measurements.md#67-a-normal-world-keybox-installer)). Whether the application-side command
is gated is not established, and it should be, by the vendor, with a published answer.

*Keep the DICE signing service out of the KeyMint application's address space*, as upstream
[Trusty](https://source.android.com/docs/security/features/trusty) does. Collapsing them converts
any KeyMint defect into a compromise of the provisioning identity.

### 10.3 The relying party

In order of yield.

1. *Add the P-384 root, retain the RSA root permanently, and pin by public-key hash*
   ([§2.1](#21-two-trust-anchors)). Add a metric for chains rejected for an unknown root: a spike
   across many genuine users is a rotation alarm rather than an attack.
2. *Correct revocation checking* ([§2.2](#22-the-revocation-list),
   [§2.3](#23-serial-number-encoding)): refresh daily, check every serial in the chain including
   intermediates, normalise serials in both decimal and hexadecimal, and fail closed where the list
   cannot be refreshed. A chain that validates cryptographically while its intermediate is listed is
   a confirmed abuse event worth logging rather than merely rejecting.
3. *Use Google's reference verifier* and keep local logic as a scoring layer over its typed
   results. It already implements the expiry asymmetry, the chain shape, fail-closed revocation and
   the refusal of a software attestation root as a trust anchor.
4. *Parse the extension directly and read the root of trust only from the hardware-enforced list*
   ([§6](#6-structural-and-encoder-checks)). Enforce the device-locked flag and a verified or
   self-signed boot state; where alternative operating systems are permitted, pin an allow-list of
   verified-boot keys.
5. *Bind the application identity* to the exact package name and the digests of every signing
   certificate legitimately shipped, as an allow-list rather than a wildcard. This closes
   cross-application relay and does nothing against a keybox holder
   ([§5.4](#54-application-identity-binding)).
6. *Issue a [single-use nonce](https://www.rfc-editor.org/rfc/rfc4949) for every attestation and
   every assertion*, with a tight time budget.
7. *Require proof of possession in session*: after chain validation, a signature over a fresh
   challenge by the attested key. It does not close the relay
   ([§5.4](#54-application-identity-binding)).
8. *Bind the request and count it.* Include the security-critical parameters of the operation in
   the signed assertion so that a proxied signature cannot be retargeted, and check a strictly
   increasing counter.
9. *Re-attest continuously rather than once at enrolment*, and treat any long-lived credential
   minted on a device later found to be on vulnerable firmware as potentially cloned.
10. *Maintain a policy table* mapping device family to a minimum acceptable patch level, derived
    from
    vendor bulletins rather than from the Android bulletin alone. Note the recursion: patch-level
    fields are themselves attested by the environment under suspicion, so they should be treated as
    advisory once a compromise is suspected.
11. *Do not treat a secure-element claim as a trust upgrade on its own.* It is attacker-controlled
    in
    the forgery case, and in the relay case the oracle's signature is genuine, which is arguably worse
    for the defender. Credit it only where the chain is provisioning-rooted, unrevoked, and consistent
    with the model's known hardware.
12. *Never soften root pinning for test devices.* Test certificates are engineered by design not to
    chain to a production root ([part 1 §6.3](1-protocol.md#63-rejection-at-provisioning-and-at-consumption)).
13. *Rate-limit signing per key* and alert on anomalous volume from one enrolment, which is the
    direct
    counter to the [side-channel](https://en.wikipedia.org/wiki/Side-channel_attack) class, one
    instance of which required roughly twelve thousand signatures over fourteen hours.
14. *Report confirmed cases to Google.* Researcher reports are a documented revocation trigger, so
    local detections shorten the gap for everyone.
15. *Pair hardware attestation with an independent signal*, and do not rely on the revocation list
    for
    provisioned material at all ([§2.4](#24-the-reach-of-revocation)).

### 10.4 The limits of attestation

A hardware attestation establishes that a key with the stated properties was created inside a secure
environment holding a Google-rooted attestation credential, on a device whose verified-boot state
and patch levels were as stated at the time of key creation, on behalf of a caller with the stated
package identity.

It does not and cannot establish that the entity now asking a relying party to trust that key is the
owner of the device; that the Android userspace between the application and KeyMint is honest; or
that the request originated on the same device that signed it.

Because a rooted device retains full and legitimate access to its own uncompromised secure world,
its owner can always operate it as a signing oracle for a remote party. No key is stolen, nothing is
revocable, the bootloader is genuinely locked on the signing device, and the signature is genuinely
hardware-backed. The formal statement is published: *"There is no field in the KeyDescription that
binds the attestation to the transport, the session, or the device presenting it. The nonce is the
only freshness signal."*

The residual ceiling is therefore that attestation forces forgery into one of three forms: a leaked
private key, which is revocable and detectable at scale; an exploit of the secure world, which is
patchable and bindable to a patch level; or a live, online, per-signature relay, which is expensive,
latency-visible, stateful and rate-limitable. Everything that distinguishes the third from a
legitimate user is non-cryptographic and must be layered on.

Three further specifics are not addressed by any migration. Migrating to provisioning-only devices
eliminates the leaked-keybox class entirely and changes nothing about relay or in-place use, which
is worth stating to any team planning around the transition. Collapse of the boot chain is invisible
to revocation, the key and chain being genuine, so the levers are per-model boot-hash expectations,
vendor patch pressure, and exclusion of device families with unpatchable mask-ROM defects rather
than gating them on patch level. And a relying party cannot observe the deployment phase, the
certification map or the device secret public key, so degenerate-phase devices deliver materially
less assurance than the architecture implies and that fact is invisible at the certificate layer
([part 1 §4.5](1-protocol.md#45-legal-chain-shapes-and-deployment-phases)); it has to be gathered
out of band.

The stance this supports is that attestation is a strong negative filter, cheaply excluding the
mass-market zero-cost attacker, and a weak positive assertion. A risk engine should be designed so
that a perfect attestation raises the ceiling on what a session may do but never by itself
authorises the highest tier, which should be reserved for actions additionally gated on behavioural,
account-history and out-of-band signals, those being the only signals a signing oracle cannot proxy.

---

## 11. Implications for TEESimulator

*The keybox parser is already correct and the documentation was stricter than the code.*
[`rust/teesim-km/src/attest.rs`](../rust/teesim-km/src/attest.rs) requires at least one of the RSA
and EC algorithms and at least two certificates per algorithm, which is what allows a
provisioning-shaped keybox — one EC key and a four-certificate chain — to load at all. A factory
keybox is the other shape, EC and RSA with three certificates each; both load.

*The acceptance relations of [§1](#1-acceptance-criteria) are executable.* [`tools/`](tools/)
implements them as `teesim-attest`, with 34 tests requiring neither network nor device: `verify` for
the two chain layers of [§1.2](#12-three-layers-for-an-extracted-keybox), `inspect` for the
extension decode and the issuance-count comparison of
[§4.2](#42-the-provisioning-information-extension), `unpack` for the length-prefixed container
parsing of [§1.5](#15-parsing-discipline) with tail residue classified, `verify-csr` for the chain
walk, canonical encoding and device-information domains of
[§1.3](#13-relations-for-a-minted-certificate-chain), `revocation` for both serial encodings of
[§2.3](#23-serial-number-encoding), and `baseline` for every constant with its provenance. The field
routes' device-side tooling is deliberately not ported, and [the toolkit](tools/README.md) states
which and why.

*The inspector requires the two gates of [§1.4](#14-gates-the-chain-does-not-supply)*, and porting
them is transcription rather than design. They belong in
[`app/.../KeyboxInspector.kt`](../app/src/main/java/org/matrix/teesim/KeyboxInspector.kt), which
already parses chains, verifies each certificate against its parent, classifies the root and checks
revocation, and decodes no provisioning extension ([part 1
§8.2](1-protocol.md#82-an-unimplemented-verification-step)). It should decode the extension at
keybox load and render the issuance count, the manufacturer and the verdict-and-subject pairs,
stating plainly that the build fingerprint is unsigned client input; classify each loaded keybox as
provisioning-derived or factory from chain shape per
[§3](#3-chain-shape-as-a-provisioning-discriminator); show days remaining per chain position rather
than a bare expiry boolean, because a two-week leaf expiring mid-session is a user-visible failure
the present interface cannot explain; and warn where a fingerprint-bound keybox contradicts the
active profile.

*The verdict surface needs one correction.* The existing triad of revoked, Google-signed and
chain-verifies is structurally incomplete for provisioned material: absence from the status list
means nothing there, and the provisioning hierarchy's revocation list is empty
([§2.4](#24-the-reach-of-revocation)). The interface should state this rather than render a mark
that encodes no information.

*Two properties of the emulation layer are correctness requirements rather than cosmetics.* The key
array carries bare keys and the authentication tag is stripped before transmission, so nothing
downstream should model it as a server-side binding ([part 1
§2.4](1-protocol.md#24-key-generation-and-the-authenticated-public-key)). And the device-information
grammar makes the verified-boot metadata digest mandatory, so a conforming emulation must emit it,
which is simultaneously the cheapest server-side detector against every tool in this class
([§10.1](#101-the-provisioning-backend)).

*The properties remain read-only.* The three provisioning properties are read and never written
([part 1 §7.3](1-protocol.md#73-denial-of-the-provisioning-lookup)): changing a device-wide
provisioning-only or daemon-enable property would itself be a conspicuous detection point of exactly
the kind [§7.3](#73-expectation-maps) recommends to defenders.
