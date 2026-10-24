# 3 · Detection and defence

*Third of five. [`2-mechanisms.md`](2-mechanisms.md) establishes how attestation material is taken;
this document is the defensive half — how to tell a genuine result from a plausible byte string,
what Google's own control plane actually contains, which signals a presenter can and cannot
suppress, and what each party in the chain can fix. The protocol is specified in
[`1-protocol.md`](1-protocol.md), the numbers are in [`4-measurements.md`](4-measurements.md), and
the grading scheme and scope rule are [`1-protocol.md`](1-protocol.md) §1.4 and §1.5. Everything in
§1 is executable in [`tools/`](tools/).*

## Abstract

Hardware attestation is a strong *negative* filter and a weak *positive* assertion, and most
verification failures come from treating it as the reverse. This document works through that
asymmetry. It begins with *acceptance*: the five intermediate states that look like a result and the
three independent layers that exclude them, including the one layer — binding the material to the
handset in front of you — that is usually skipped. It then measures the control plane Google
publishes: two trust anchors that must both stay in the store permanently, a root whose certificate
has been re-issued four times under one unchanged public key, and a revocation list whose entries
arrive in *two different serial encodings*, so that a verifier rendering serials only as hex
silently misses roughly 56% of what is revoked. The detection signals follow, ordered by how hard
they are to suppress: chain shape, the provisioning-information extension's issuance count and
status, leaf lifetime, fan-out on the attestation key, and trust-on-first-use pinning. A
forgeability triage states plainly what a keybox holder authors freely — which is nearly every field
inside the attestation extension, the module hash included — and the short list of what cannot be
forged. The coverage matrix of §9 is the summary result, and its two empty columns are the point:
*boot-chain spoofing and relay produce genuine signatures from genuine unrevoked keys, and nothing
in the certificate distinguishes them.*

---

## 1. Acceptance: distinguishing a result from a byte string

Both field reports spend more space on acceptance than on exploitation, and they are right to. This
is the reusable part of all four routes, and it is as much a verifier's checklist as an operator's.

### 1.1 The five states that resemble success

All three extraction routes passed through these, and every one of them looks like a result: output
exists but is not the target material; a private key exists but is not the device identity; HTTP 200
arrives but the certificate's provisioning status is unacceptable; the device booted but its
measurement state is wrong; a certificate chain verifies but the private-key correspondence does not
hold.

Each of the three layers below exists to exclude one or more of these.

### 1.2 For an extracted keybox: three independent layers

```
layer 1   PublicKey(private_EC)  == PublicKey(ec_leaf_certificate)
          PublicKey(private_RSA) == PublicKey(rsa_leaf_certificate)
layer 2   leaf signed by intermediate; intermediate signed by root;
          root self-signed and constraints valid
layer 3   trigger a fresh attestation through the Android keystore and compare the
          resulting leaf against the extracted keybox's certificates
```

All three are required. Layers 1 and 2 alone cannot exclude a random key pair, a keybox for another
purpose, a misaligned parse, a test CA, or well-formed material belonging to a *different* device.

*Layer 3 is the one usually skipped and the only one that binds the material to the handset in front
of you.*

### 1.3 For a minted provisioning chain: the relation set

```
same-round CDI_Leaf public  ==  AuthenticatedRequest signing identity
software private's public   ==  keysToSign public key
software private's public   ==  returned leaf certificate public key
leaf -> intermediate -> root, terminating in one self-signed root
```

Plus: the [CBOR](https://www.rfc-editor.org/rfc/rfc8949) is
[canonical](https://www.rfc-editor.org/rfc/rfc8949#section-4.2); no field foreign to the version-3
payload has leaked in; `DeviceInfo` matches the target profile; the endpoint key and the challenge
are fresh; every returned certificate is consumed; and there is no duplicate leaf, broken link,
cycle or stray extra certificate.

`Duck-ToolBox`'s verifier is a usable implementation of most of this and worth reading as a
checklist. It pins the `AuthenticatedRequest` version to 1 and the payload version to 3, pins the
test-key label and the
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/) profile-name label
with a required profile value, rejects a DICE chain shorter than two elements, enforces [canonical
CBOR](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) map ordering, pins all 14 permitted
`DeviceInfo` keys with their value domains (`green|yellow|orange`, `locked|unlocked`,
`tee|strongbox`), requires a 32-byte `vbmeta_digest`, enforces field-count rules per security level,
and requires every `keysToSign` entry to be an ES256
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)
[COSE_Key](https://www.rfc-editor.org/rfc/rfc9052#section-7). *[MEASURED]*

### 1.4 Three gates that no reading of the chain supplies

*Provisioning status.* Parse [OID](https://www.itu.int/rec/T-REC-X.660) `1.3.6.1.4.1.11129.2.1.30`,
*preserve unknown fields*, and gate on the status explicitly. A `NOT_APPROVED` must not be
overridable by a valid chain ([`2-mechanisms.md`](2-mechanisms.md) §6.6). `Duck-ToolBox` has no such
gate — the only two OIDs in its entire workspace are the EC public-key and P-256 curve identifiers.
*[MEASURED]*

*Real [X.509](https://www.rfc-editor.org/rfc/rfc5280) signature verification on the returned chain.*
`Duck-ToolBox` links its chain by subject and issuer *name* only; its signature-verification type
appears in exactly one file in the workspace, where it verifies
[COSE](https://www.rfc-editor.org/rfc/rfc9052) rather than X.509. Name linkage catches a misordered
chain, not a substituted one. *[MEASURED]*

*Same-round identity binding.* The [constant-time](https://en.wikipedia.org/wiki/Timing_attack)
`SubjectPublicKeyInfo` comparison of [`2-mechanisms.md`](2-mechanisms.md) §6.4, against a native
request from the same boot.

The first two are exactly the gates [`1-protocol.md`](1-protocol.md) §8.2 identifies as missing from
the module's own inspector, and the first is the gate whose absence cost a field result.

### 1.5 Parsing discipline, and why structural gates are not proofs

Generalising [`2-mechanisms.md`](2-mechanisms.md) §4.4 and §5.5. Lengths and offsets measured in one
round describe *that sample*, not the format: a descriptor length of 168 and a payload length of
8578 are a structural gate, not a success proof. Parse by length prefix; confirm every length
against the parsed object's own internal length; never parse by fixed offset, since the same
[SEC1](https://www.secg.org/sec1-v2.pdf) private key is 121 bytes on one device and 138 on another
depending only on which optional fields are present. And classify the tail rather than ignoring it:
a buffer whose copy was shorter than its contents leaves residue *that can parse as plausible
[DER](https://www.itu.int/rec/T-REC-X.690)*.

### 1.6 Synthetic chains, and the division of labour

Worth recording because it bears on how much a tool proves. `Duck-ToolBox` *synthesises* a
degenerate two-element DICE chain rather than accepting a captured one *[MEASURED]*: the chain
head's "UDS public key" *is* the identity key's own COSE_Key, the single entry is self-signed by the
same private key and carries no boot measurements, and the length is exactly two — the validator's
own minimum. Its command-line interface exposes profile, seed, hardware key, KDF label, curve and
server URL, and *no input for a captured chain*. The field corpus's own issuance command passes one
explicitly, sourcing the DICE material from the same round's native request, and its [HTTP
444](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RkpdException.java)
checklist lists *degenerate DICE, wrong UDS* among the first things to check. *[PRIMARY]*

That is consistent with the tool's design rather than a defect in it — it falls back to a local test
endpoint key when the fetch fails, so the synthetic chain supports offline exercise of the protocol.
The accurate statement is a division of labour: *the routes supply a signing capability the server
will accept; the tooling supplies the protocol, the verifier and the product assembly.* Running the
tooling alone yields a self-consistent request that will not be signed — which is
[`1-protocol.md`](1-protocol.md) §6.2 restated from the attacker's side.

---

## 2. The control plane, as measured

Everything in this section was fetched live and is dated. It changes; re-measure before relying on a
value.

### 2.1 Two trust anchors, and why to pin the [SubjectPublicKeyInfo](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7)

*[MEASURED]*, on one live fetch. `https://android.googleapis.com/attestation/root` returns a bare
JSON array of [PEM](https://www.rfc-editor.org/rfc/rfc7468) strings — at the time of measurement,
*exactly two*.

| | Legacy root | RKP root |
|---|---|---|
| Subject | `SERIALNUMBER=f92009e853b6b045`, self-signed | `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` |
| Certificate serial | `F1C172A699EAF51D` | `84A9D0297B0EB58AE7FF0E80DE760605` |
| Key / signature | *RSA-4096*, `sha256WithRSAEncryption` | *[ECDSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) secp384r1*, `ecdsa-with-SHA384` |
| Validity span | twenty years | ten years |
| Certificate [SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | `CEDB1CB6…800DFC` | `6D9DB4CE…BA4BCC0` |
| SPKI SHA-256, base64 | `/rLqdVHuMW7Uu0Q8gpO4hNv96kC2A+4+T0qJfkWA+64=` | `PuRFEqGvK+s5yIlJDGDqP4LkP11aVTL1q5QZ9nbNB+w=` |

*Pin the SubjectPublicKeyInfo hash, not the certificate fingerprint.* Google's documentation lists
three previously issued root certificates, with serials `E8FA196314D2FA18` (now expired),
`D50FF25BA3F2D6B3` and `C36B7C44B9AE1831` — and *all three carry the same SPKI SHA-256 as the live
root.* One RSA key, re-issued four times. A verifier pinned on certificate fingerprints breaks on
every re-issuance; one pinned on SPKI does not.
[GrapheneOS](https://grapheneos.org/articles/attestation-compatibility-guide) correspondingly pins
five root certificates rather than one.

The widely repeated claim that *"the old root is [RSA-2048](https://www.rfc-editor.org/rfc/rfc8017)
and the new one is RSA-4096"* is wrong in both halves: the legacy root is RSA-4096 and the new one
is ECDSA P-384. *[MEASURED]*

*Both roots must remain in the trust store permanently.* Factory-keyed devices cannot rotate, and
Google's own guidance is to keep trusting chains to the legacy root *regardless of certificate
validity period*, because older factory devices legitimately present expired certificates — while
*RKP certificate validity must still be checked*, since the short expiry is a deliberate part of the
threat model.

*On the rotation schedule, with attribution.* Google's documentation states only when the new root
*"will begin signing attestation certificate chains."* The later exclusive-use point for RKP-enabled
devices — roughly ten weeks after that — comes from a third-party enterprise blog rather than from
Google, and a frequently quoted intermediate deadline appears on no Google page and is not carried
here. *[UNVERIFIED]* for the exclusive-use point. Read the cutover from Google's current page, not
from a document: *a verifier that adds the new root late rejects every RKP chain in the interim*,
which is the failure this paragraph exists to prevent.

### 2.2 The revocation list: schema, semantics and growth

*[MEASURED]*, fetched twice independently.
[`https://android.googleapis.com/attestation/status`](https://android.googleapis.com/attestation/status)
is JSON with `cache-control: public, max-age=86400`, so *daily refresh is the right cadence*.

At the time of measurement: *1,738 entries, 100% `REVOKED` with zero `SUSPENDED`; 1,712
`KEY_COMPROMISE` and 26 `SOFTWARE_FLAW`.* No entry carried the schema-permitted `expires` or
`comment` fields. The published [draft-07](https://json-schema.org/draft-07/schema) schema requires
a top-level `entries` dictionary mapping serial to `{ status: REVOKED|SUSPENDED, expires?:
YYYY-MM-DD, reason?: UNSPECIFIED|KEY_COMPROMISE|CA_COMPROMISE|SUPERSEDED|SOFTWARE_FLAW, comment?:
<=140 chars }`. The common reading that *REVOKED is permanent and SUSPENDED temporary* is a
conventional [CRL](https://www.rfc-editor.org/rfc/rfc5280#section-5) interpretation; *the schema
assigns no permanence semantics at all.*

Growth, from a community archive of eight successive snapshots spanning ten months: 1,594 → 1,604 →
1,608 → 1,614 → 1,638 → 1,654 → 1,720 → 1,738. About *144 additions over those ten months, arriving
in clusters* — 24 in nine days at one point, 66 over about ten weeks at another — rather than as one
publicised mass revocation. The independent series measured for
[`4-measurements.md`](4-measurements.md) §4.2 agrees, and carries the dated snapshot links for
anyone re-deriving it.

Three semantics verifiers get wrong, each of which has been observed in the field:

*The list is not exhaustive.* Absence means "no non-valid status recorded", never "proven good".

*Every certificate in the chain must be looked up.* When a keybox leaks it is the *intermediate*
that gets revoked, and the attacker-generated leaf will never be listed. A verifier that checks only
the leaf checks the one certificate that cannot be revoked.

*Fail closed.* Google's own reference implementation fails closed on download or parse failure,
which is the correct posture for an anti-abuse verifier and the opposite of the usual default.

*And revocation is reactive by design.* Google documents that leaks surface through analysis of
attestation data in the wild, discovery of keys on public sites, and researcher reports; that
revocation *"typically"* happens within several days of discovery but may take longer; that it is
*"usually delayed if the devices affected can be securely re-provisioned"*; and that the scale of
impact affects timelines. *That documented delay is the window your own analytics must cover.*

### 2.3 The serial-encoding trap

The highest-value implementation finding in this series, because it is silent.

The published schema says the dictionary key is *"the certificate serial number in lowercase hex"*,
with a `propertyNames` pattern of `^[a-f1-9][a-f0-9]*$` — leading zeros stripped, matching Java's
`BigInteger.toString(16)`. Google's reference verifier implements exactly that.

*[MEASURED]* Against the live list, the 1,738 entries split into two disjoint populations. *766
entries* are 30 to 32 characters and all contain `a`–`f` letters: 128-bit serials in hex. *972
entries* are 17 to 20 characters and *not one contains any `a`–`f` letter*. The probability of 972
genuine 19-hex-digit strings all avoiding six of sixteen digits is vanishing. Read as *decimal*,
every one fits in 64 bits, and the 19-versus-20-digit split matches what uniformly random 64-bit
integers look like in decimal.

*The measurement is fact; the reading is [INFERRED].* Note that those 972 entries *are*
syntactically valid lowercase hex under the schema's own pattern — which is precisely why nothing
rejects them and why the failure is invisible. No Google statement acknowledging a mixed encoding
could be found.

*Operational consequence: a verifier that renders each certificate serial only as lowercase hex
silently fails to match roughly 56% of the currently revoked entries* — most likely including the
older factory-keybox population that matters most, which [`4-measurements.md`](4-measurements.md)
§4.3 shows is 56% of the list by a completely independent route.

The fix is two lines and an instrument: parse each serial as a [big
integer](https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html), test membership for
*both* base-16 and base-10 renderings, optionally plus zero-stripped and lower-cased variants — and
then *count rejections attributable to each form.* If the decimal-match counter is zero over a large
sample, revocation is probably not being enforced for the older keybox population at all.
[`tools/teesim_attest/revocation.py`](tools/teesim_attest/revocation.py) implements both forms with
per-form counts.

### 2.4 What revocation reaches, and what it cannot

Collecting the consequences, because they differ by material class and the difference is structural
rather than incidental.

*A factory batch key is reachable.* It is long-lived, so it is still valid when the leak is noticed
— at the cost that revoking it breaks attestation for an entire production run, which is why
revocation is delayed when re-provisioning is possible.

*An RKP leaf is not reachable.* It expires faster than a revocation cycle notices it; neither leaked
sample leaf is listed; and the RKP hierarchy's own CRL stands at CRL Number 0 with no entries
([`4-measurements.md`](4-measurements.md) §2.3). *The effective lever is de-registration — removing
`UDS_pub` from the provisioning registry* — which is a backend edit invisible to any
certificate-based mechanism, and which §10.1 argues should be the fast path.

*Neither is reachable for boot-chain spoofing or relay*, because the key and the chain are genuine
and unrevoked. §9 makes that the matrix's two empty columns.

---

## 3. Chain shape as a provisioning-method discriminator

Google publishes a reference verifier,
[`android/keyattestation`](https://github.com/android/keyattestation) (Apache-2.0,
[Kotlin](https://kotlinlang.org/)), and it encodes the canonical order that
`KeyStore.getCertificateChain()` returns:

1. *leaf* — carries the key-attestation extension
2. *attestation certificate* — carries the provisioning-information extension if remotely
provisioned
3. *intermediate* — absent if attestation is software-backed
4. *a second intermediate* — present *only* if remotely provisioned
5. *root*

It requires at least three certificates and that the last is self-issued. The discriminators are
distinguished-name based and directly implementable: *factory-provisioned* if the intermediate's
subject contains a `serialNumber` [relative distinguished
name](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4) (OID `2.5.4.5`); *remotely
provisioned* if the intermediate's subject is `CN="Droid CA2", O="Google LLC"`. For RKP the
attestation certificate's subject `O` maps `"TEE"` to a trusted-environment level and `"StrongBox"`
to a secure-element level; for factory chains only
[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox) is reliably
encoded, through a case-insensitive `"strongbox"` substring in the attestation or intermediate
subject.

A mechanical detail if you reimplement it: the library's accessor for "the intermediate" is the
*last non-root* certificate, because the trust anchor is dropped — the batch certificate on a
factory chain, the Droid CA2 certificate on an RKP chain.

*One caveat Google states itself:* the remote-provisioning test carries an internal note to switch
to fields in the RKP root, so the `"Droid CA2"` name test is acknowledged as a stopgap. Chain-shape
detectors keyed on that string may silently misclassify later chains.

*Record a five-tuple per verification* — chain length, provisioning method, security level from the
[distinguished name](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4),
`attestationSecurityLevel` from the extension, and the root SPKI hash — and alert when the
name-derived level disagrees with the extension level, when the provisioning method is unknown, or
when the chain is longer than the canonical four (factory) or five (RKP).

That shape test is also the class discriminator this series measured from the other direction: a
four-certificate EC-only chain under the P-384 root is RKP; a three-certificate chain with both
algorithms under the RSA root, with a ten-year leaf, is a factory keybox
([`4-measurements.md`](4-measurements.md) §2, §4.1). *They are different populations with different
failure modes, and scoring them alike is wrong in both directions.*

---

## 4. Extension-level rules

### 4.1 Only the first occurrence of the key-attestation extension may be trusted

Google's caution is explicit and is about an active attack rather than a parsing nicety: *"Don't
assume that the [key
attestation](https://source.android.com/docs/security/features/keystore/attestation) certificate
extension is in the leaf certificate of the chain. Only the first occurrence of the extension in the
chain can be trusted. Any further instances of the extension have not been issued by the secure
hardware and might have been issued by an attacker extending the chain while attempting to create
fake attestations for untrusted keys."*

The procedural form is "find the certificate nearest the root that carries the extension"; the
reference library achieves the same by fixing the leaf and attestation positions.

*Count occurrences of OID `1.3.6.1.4.1.11129.2.1.17`: exactly one is normal, and two or more is an
active attack that should be logged as such rather than merely rejected.* And verify that the
attested public key equals the key you are about to trust for the session — a check whose absence
makes the rest of the chain irrelevant.

### 4.2 The provisioning-information extension

OID `1.3.6.1.4.1.11129.2.1.30`, decoded byte for byte in [`4-measurements.md`](4-measurements.md)
§3. It is Google's own purpose-built abuse signal and *almost nobody parses it*. Google's reference
library models only the issuance count and exposes a logging hook; the security-level field must be
parsed by the verifier.

*Issuance count, tag 1.*
[Documented](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension)
as *an approximate number of certificates issued to the device in the last 30 days* that *can be
used as a signal for potential abuse if the value is greater than average by some orders of
magnitude*. It sits inside the signed certificate, so it is readable by any relying party and *a
rooted client cannot lower it without breaking the chain signature* — the one field in this document
that is both adversary-visible and adversary-unalterable.

What the documentation never supplied is the average. [`4-measurements.md`](4-measurements.md) §3.3
supplies it: a stock handset read *8*; both leaked samples read *512*, about 64 times the baseline
for the device class one of them names, in the same 30-day window. Two cautions keep the comparison
honest. All five observed values are powers of two, which suggests a logarithmic bucket rather than
a literal count *[INFERRED]* — so treat it as order-of-magnitude, which is how the documentation
frames it anyway. And three different counters are routinely conflated: certificates returned in one
batch, this signed 30-day figure, and an unsigned same-day counter in the device's own statistics
file. *Only the middle one is in the certificate.*

This is the strongest built-in signal against a handset being farmed as a signing oracle, because a
phone acting as attestation-for-hire burns certificates far faster than a real user's.

*Validated attested entity, tag 4.* Documented as *a string indicating the certified origin of the
attested key, directly vouched for by the chipset manufacturer* — for example `TEE` or `STRONG_BOX`.
Parse it and *assert it equals `attestationSecurityLevel` in the key description*: a disagreement
between the provisioning backend's view and the device's claim is a strong forgery indicator. It is
absent from both measured samples, where the claim is carried instead in the leaf subject
([`4-measurements.md`](4-measurements.md) §3.2).

*Provisioning status.* The undocumented verdict fields were initially catalogued as constant
`APPROVED`; an independent field record shows `NOT_APPROVED` occurring and being *dispositive*
([`2-mechanisms.md`](2-mechanisms.md) §6.6). They are live varying verdicts, which is what makes a
decoder that drops them a verifier bug rather than a cosmetic omission. *Preserve unknown fields,
surface the status, and let nothing override it* — not a digest match, not a chain verification.

*Verification procedure.* Find the certificate nearest the root carrying this extension; if present,
the key-attestation extension must be in the *immediately subsequent* certificate.

### 4.3 Expiry, branched on provisioning method

Enforce `notBefore` and `notAfter` strictly on P-384-rooted, RKP-shaped chains. This is what ages
out hoarded and relayed chains and forces an attacker to keep a live oracle online.

*Do not* enforce expiry on chains rooted in the legacy RSA root, where older factory devices
legitimately present expired certificates (§2.1).

And log the observed `notAfter − notBefore` span: an RKP-shaped chain with a multi-year validity
window is anomalous on its face. Measured spans are about 13 days for stock RKP issuance, 14 to 15
days for the two leaked samples, and about ten years for a factory keybox
([`4-measurements.md`](4-measurements.md) §2.1), so the two classes are three orders of magnitude
apart and the test needs no tuning.

---

## 5. Forgeability triage

### 5.1 What a keybox holder authors freely

*With a leaked keybox, everything inside the attestation extension is attacker-chosen and internally
consistent by construction*, because the attacker signs the leaf himself. That includes the
attestation and [KeyMint](https://source.android.com/docs/security/features/keystore) version
numbers, the claimed security level, *the entire `RootOfTrust` sequence* — verified-boot key,
device-locked flag, verified-boot state and hash — the OS version and all three patch levels, the
application identity, the whole identity-attestation set, and the module hash.

The same holds one layer up in the provisioning request: brand, model, `fused`, `vb_state=green`,
`bootloader_state=locked`, `security_level=tee` and the patch levels are *operator-authored
configuration lines* ([`2-mechanisms.md`](2-mechanisms.md) §7.1), and the leaf's `O=TEE` subject is
downstream of one of them. *An RKP-rooted chain attests that a registered DICE identity asked for a
certificate within the last two weeks. It attests nothing about the handset in front of you.*

### 5.2 The module hash is not anti-spoofing

Worth a specific correction, because it is widely assumed to be.

The module hash (tag 724) is the SHA-256 of a DER-encoded `SET OF` package-name and version pairs,
retrievable client-side from API 36. Its inputs are the installed module package names and versions,
which are *world-readable*, so a rooted attacker recomputes the exact expected value offline — and a
public spoofing module already does, reproducing the DER `SET` ordering.

It adds *no cryptographic resistance against a keybox holder.* It catches only attackers who omit it
or present a value inconsistent with the OS version and patch level they also claim. It is also
optional in the current schemas, so its *absence* is a soft anomaly score rather than a
specification violation; only its *presence* below the version that introduced it is structurally
impossible.

### 5.3 What cannot be forged

Short list, and it is the whole positive case for certificate-layer detection:

A signature chaining to a Google root, without a keybox. A keybox whose serial is in the revocation
list, once Google lists it. And *the provisioning-information extension's issuance count and
status*, which the backend asserts inside a Google-signed certificate about a request it saw (§4.2).

### 5.4 Application-identity binding, scoped correctly

The application-identity field (tag 709) is *forgeable by a keybox holder*, and the opposite is
often asserted. Its signing-certificate digests are digests of *public* certificates extractable
from any package, so no private signing key is needed to recompute them, and the field sits in the
software-enforced list of a leaf the keybox holder signs himself.

The claim that it *"cannot be matched without the target's private signing key"* is correct *only
for the relay class*, where an honest clean-device platform writes the field. Against relay it is
decisive; against a keybox holder it is worthless. Scope the control accordingly — and note that a
documented relay service mode explicitly substitutes the client's application details before
signing.

Proof-of-possession likewise *does not close* the relay: the attacker relays every signing
operation. It converts a cheap one-shot into a live proxy that must stay online, adding latency,
cost and observability. *An economic control, not a cryptographic one.*

---

## 6. Structural and encoder checks

Low false-positive, incomplete coverage. Worth having, worth not over-trusting.

Google's reference parser already checks canonical tag ordering and logs when authorisation-list
tags violate ascending order. *Promote that from a log line to a scored anomaly.*

Read the root-of-trust *only from the hardware-enforced list*, never from system properties and
never from a platform-integrity verdict alone. Only the hardware-enforced list, under a
Google-rooted chain, is a claim the secure hardware makes; a root-of-trust or identity field
appearing in the software-enforced list while the chain claims a trusted environment is a red flag.

Check key origin indicates a *generated*, not imported, key, and that requested purposes match your
protocol.

Check for impossible combinations: an attestation version inconsistent with the claimed OS version;
an OS patch level in `YYYYMM` against vendor and boot patch levels in `YYYYMMDD`, mutually plausible
and not in the future; a StrongBox claim from a model with no [secure
element](https://source.android.com/docs/security/best-practices/hardware); device-unique
attestation where it cannot appear.

Build a per-model, per-build fingerprint of the exact DER byte layout your real population produces,
and alert on chains that are cryptographically valid but structurally off that manifold. *This class
of check is defeated outright by a spoofer that embeds [AOSP](https://source.android.com/)'s own
reference implementation* — which is exactly what this project is — so treat it as
low-false-positive and incomplete.

One rule to keep as a heuristic rather than a requirement: *"the KeyMint security level must equal
the attestation security level"* is a third-party hardening rule, not an AOSP requirement. The two
fields describe different things and no Google document mandates equality.

---

## 7. Statistical and behavioural signals

### 7.1 Fan-out on the attestation key

*The highest-yield pre-revocation signal, and it needs nobody's cooperation.*

Index on the *SHA-256 of the attestation certificate's SubjectPublicKeyInfo* — not its serial — and
count distinct account identifiers, install identifiers, network [autonomous
systems](https://www.rfc-editor.org/rfc/rfc1930) and app-reported build fingerprints per key per
rolling window. Real [hardware
attestation](https://source.android.com/docs/security/features/keystore/attestation) keys have
narrow fan-out; shared keyboxes and oracles do not. The published operational rule is that a key
belonging to a device from one manufacturer should never be reported in use by a device from
another, and that remotely provisioned keys should not be shared across notably different devices.

*Cluster by chipset, board or contract manufacturer before calling cross-brand use anomalous*,
because one design house building a reference platform for several brands can legitimately provision
one credential pool across nominally unrelated nameplates.

A cheaper variant of the same idea, available to anyone holding a corpus of presented chains: *count
distinct installs per leaf serial.* It is the one trace the design cannot suppress.

### 7.2 Trust on first use, with monotonic non-decrease

The strongest single defence against a leaked keybox being used on an account that previously
enrolled from genuine hardware, and it catches the common spoofer failure of patch levels drifting
downward or jumping implausibly between sessions.

GrapheneOS's attestation server is the best public worked example. At pairing it stores the pinned
certificates, verified-boot key, OS version, OS, vendor and boot patch levels, application version
and security level, then rejects any later attestation that regresses any of them, with explicit
floors. It also enforces single-use challenges, requires a trusted-environment or secure-element
level, requires a [secure element](https://source.android.com/docs/security/best-practices/hardware)
for *new* pairings, requires the device-locked flag and a verified or self-signed boot state, uses a
separate per-pairing attestation key, and rejects any verified-boot key outside a curated published
fingerprint map.

### 7.3 Model, boot-hash and platform-integrity expectations

*A model-to-expected-provisioning-method map.* After the root cutover, a device that self-reports as
a modern RKP-capable model while presenting a legacy-RSA-rooted chain is presenting a factory-key or
forged-keybox chain — exactly the population where keybox spoofing lives. *This works before Google
revokes anything.*

*Per-model expected boot-hash sets.* Against boot-chain spoofing, revocation cannot help because the
key and chain are genuine. The only device-side residue is the verified-boot metadata digest and the
verified-boot key hash: a device reporting locked while carrying a boot hash matching no
manufacturer-signed release for that model is detectable *if* those sets are maintained.

*Provisioning-daemon presence.* The RKP daemon ships as an updatable module, so its version is a
meaningful integrity input. A device reporting a modern Android release with a stale, absent,
disabled or replaced provisioning daemon is anomalous — and debloating guides that recommend
removing it break key generation, so its absence on a supposedly healthy device is a strong tamper
signal.

*Virtualisation-instance consistency.* `RpcHardwareInfo.uniqueId` distinguishes the
trusted-environment and virtual-machine provisioning instances ([`1-protocol.md`](1-protocol.md)
§5.7); a key pool where the virtual instance's identifier is missing or duplicated indicates an
emulated HAL.

### 7.4 Pool invariants visible to a relying party

Two invariants from the provisioning daemon's own database schema ([`1-protocol.md`](1-protocol.md)
§7.6) are observable consequences rather than internal details. An RKP certificate presented long
past the expiry recorded for its pool entry, or *the same RKP certificate serving two distinct
application identities*, indicates the blob-and-certificate pair was lifted from the database and
replayed rather than used through the normal path.

### 7.5 Signals whose value is not established

Recorded so they are not mistaken for measurements.

*Latency and jitter.* A relayed signature carries a network round trip that a local secure-world
signature does not, so the distribution should be bimodal or shifted. *[SPECULATIVE]* — no cited
source measures it, and nothing establishes that the distributions separate reliably against an
attacker who deliberately adds jitter.

*Keybox-distribution feeds as intelligence.* The keyboxes presented next week are published this
week, so pre-blocking their issuer serials gets ahead of the documented several-day revocation
latency. The mechanism is sound; its yield is unmeasured here. One related rule *is* certain: reject
the AOSP software-attestation keybox outright, since it chains to a test root and never to Google
([`4-measurements.md`](4-measurements.md) §4.1 measures how the public corpus is distributed).

---

## 8. Platform-integrity verdicts as a complement

[Play Integrity](https://developer.android.com/google/play/integrity)'s device-recognition verdicts
are worth wiring in, provided their boundary is respected.

On Android 13 and later, basic integrity requires a Google-provided attestation [root of
trust](https://source.android.com/docs/security/features/verifiedboot/verified-boot); device
integrity requires *hardware-backed* proof that the bootloader is locked and the loaded OS is a
certified manufacturer image; and strong integrity additionally requires security updates within the
last year for both the OS and the vendor partition. On Android 12 and earlier, strong integrity does
not require recent updates, so pair it with the reported SDK version. *An empty verdict array is
itself the signal* — API hooking, rooting, system compromise, or a non-Play emulator.

Three optional signals are directly relevant here: a device-activity level that buckets request
volume per hour, an *appAccessRisk* verdict, and *device recall*, which stores per-device bits with
month-granularity write dates that *survive reinstall and factory reset.* Device recall is the
single most useful anti-oracle primitive the platform exposes: a farm device flagged once stays
flagged through a reset.

*What it does not do.* It is an assessment of the device *environment*, not a statement about *your*
key. It does not bind a key you will later use, does not give you an application identity to check
against your own signing certificate, and does not prove possession.

*The highest-value combination* is a contradiction test: an empty device-recognition verdict
arriving alongside a chain claiming a [verified
boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot) state and a
locked device is a direct contradiction and a high-confidence spoofing signal. The same test applies
within the certificate layer — a short-lived, Google-rooted RKP chain attesting an unlocked
bootloader or an unverified boot state is contradictory on its face, since production RKP
certificates should not issue to a device outside normal DICE mode.

---

## 9. Coverage: which control catches which mechanism

Mechanism letters are the custody taxonomy of [`2-mechanisms.md`](2-mechanisms.md) §2.

| Control | A. keybox leak | C. interposition | D. provisioning abuse | E. in-place replay | F. boot-chain spoof | G. relay | H. TEE exploit |
|---|---|---|---|---|---|---|---|
| Pin roots by SPKI; reject the software root | — | *catches* software-root fakes | — | — | — | — | — |
| Revocation on *every* certificate, both serial encodings | *catches*, after latency | *catches*, same keybox | *catches*, same keybox | — | *misses* | partial, keybox-host mode only | — |
| Chain shape + model-to-method map | *catches* on RKP-capable models | *catches* | *catches* | — | *misses* | *misses* | *misses* |
| Expiry enforcement on RKP chains | — | — | — | *bounds* to the leaf lifetime | — | *bounds* hoarded chains | — |
| Application-identity binding | *misses*, forgeable | *misses*, forgeable | *misses* | partial | *misses* | *catches* cross-app relay | — |
| Proof-of-possession + session binding | *misses* | *misses* | *misses* | partial | *misses* | *raises cost*, does not close | *misses*, key already left |
| Fan-out on attestation-key SPKI | *catches pre-revocation* | *catches* | *catches* | — | weak | *catches* | — |
| Issuance-count outliers | — | — | — | *catches* | — | *catches* RKP oracles | — |
| Trust on first use + monotonic patch levels | *catches* on returning accounts | *catches* | *catches* | partial | partial | partial | *catches* downgrades |
| Patch-level and model risk table | — | — | — | — | *only control* | — | *primary control* |
| Per-model expected boot-hash sets | — | — | — | — | *only device-side residue* | — | — |
| Device recall / activity level | partial | partial | partial | partial | partial | *catches* farms | — |
| Encoder and DER-manifold checks | *catches* hand-built | *misses* reference-implementation emulation | — | — | — | *misses*, genuine | *misses*, genuine |

*The rows with no "catches" in the F and G columns are the point.* Boot-chain spoofing and relay
produce genuine signatures from genuine, unrevoked keys, and nothing in the certificate can
distinguish them.

---

## 10. Mitigation by actor

### 10.1 The provisioning backend

Ordered by yield. These follow directly from the measurements, and the first is the single
highest-yield change available anywhere in this document.

*Rate-limit issuance per registered `UDS_pub`.* The counter already exists — the issuance count in
the extension proves it is computed. Turning a published signal into an *enforced cap*, with a raise
available on request for test racks and the virtual-machine population, reduces one captured seed
from 512-plus per month to a trickle and removes the economics without touching the protocol.

*Enforce the device-information [CDDL](https://www.rfc-editor.org/rfc/rfc8610) at the signing
endpoint.* One measured request omitted the mandatory verified-boot metadata digest and was signed
anyway ([`4-measurements.md`](4-measurements.md) §3.4). State the limit honestly: this is a one-line
evasion, since both independent tools can supply the field, so it raises the floor rather than
retiring the tool class. The durable version is the next item.

*Join the registry to the request.* Cross-check the submitted brand, model, device and product
strings and the verified-boot digest against the model the `UDS_pub` was registered as. The backend
already resolves the digest — that is what the extension's tag 5 records — so this is one lookup,
and it stops a registered identity certifying a build it was never shipped with. Then *bind the
build fingerprint into the signed payload* rather than accepting it unsigned at the endpoint-key
fetch ([`1-protocol.md`](1-protocol.md) §2.6).

*Make de-registration the fast path.* With two-week leaves the status list is structurally blind
(§2.4), so the path from "abuse detected" to "`UDS_pub` removed" must be short and automatic.

*Retire Phase-1 degenerate DICE for new registrations*, not only where a secure element is declared.
On a degenerate chain one 32-byte secret is the entire device identity
([`1-protocol.md`](1-protocol.md) §4.5). Requiring a non-empty `UdsCerts` gives the manufacturer a
revocable intermediate instead of a bare registry lookup.

*Give the provisioning daemon a distinguishable client identity.* Today a reimplementation in Python
or Rust is indistinguishable from the platform daemon at the transport layer, because the daemon
sends no API key, no client certificate and no pinned TLS ([`1-protocol.md`](1-protocol.md) §5.2).

### 10.2 The chipset and handset vendor

From the platform measured in [`4-measurements.md`](4-measurements.md) §6, but each generalises.

*Rebuild trusted applications with published memory-safety bugs.* Four applications with
device-reproduced bugs, two of them yielding arbitrary read, have not been rebuilt since the
handset's launch ROM — across nine independent sources spanning more than two years, against a
control that demonstrably detects updates. *This is the single most actionable finding in the
series.*

*Assume normal-world root on a locked handset.* A public one-click tool reaches uid 0 with
[SELinux](https://source.android.com/docs/security/features/selinux) disabled and kernel physical
read/write on a locked, verified-boot-intact stock device ([`4-measurements.md`](4-measurements.md)
§6.5). Any defence that assumed an unlock requirement as a barrier is void.

*Bind trusted-application secure storage to the application image, not to its bare identifier.*
Deriving the per-application storage key from the signed image digest rather than from the UUID
makes every downgrade and transplant route worthless in one change, and it also defeats the
insider-signing variant.

*Restore a monotonic version field inside the signed region of the container, and enforce it against
replay-protected storage.* The measured container header has no such field
([`4-measurements.md`](4-measurements.md) §6.6), which is what made two designed rollback schemes
worth considering at all.

*Stop shipping application bodies in the clear.* A 336-byte header followed by a plain AArch64
[ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) at 2.31 bits of
[entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) per byte is what makes
third-party emulation and fuzzing of these applications practical.

*Audit normal-world keybox installers.* A `system`-uid, keystore-group boot service linked against a
library that installs an XML keybox from a normal-world path is a write-in surface resident on
retail hardware ([`4-measurements.md`](4-measurements.md) §6.7). Whether the application-side
command is gated is not established, and it should be — by the vendor, with a published answer.

*Keep the DICE signing service out of the KeyMint application's address space*, as upstream
[Trusty](https://source.android.com/docs/security/features/trusty) does. Collapsing them converts
any KeyMint bug into a DICE compromise.

### 10.3 The relying party, by yield

1. *Add the P-384 root now, keep the RSA root permanently, and pin by SPKI hash* (§2.1). Add a
metric for "chain rejected: unknown root" — a spike across many genuine users is a rotation alarm,
not an attack.
2. *Fix revocation checking* (§2.2, §2.3): refresh daily, check *every* serial in the chain
including intermediates, normalise serials as *both* decimal and hex, and *fail closed* when the
list cannot be refreshed. A chain that validates cryptographically but whose intermediate is listed
is a confirmed abuse event worth logging, not merely rejecting.
3. *Use Google's reference verifier* and keep your own logic as a scoring layer on top of its typed
results. It already gets the expiry asymmetry, the chain shape, fail-closed revocation and the
refusal of a software attestation root as a trust anchor correct.
4. *Parse the extension yourself and read the root of trust only from the hardware-enforced list*
(§6). Enforce the device-locked flag and a verified or self-signed boot state; if you permit
alternative operating systems, pin a verified-boot-key allow-list.
5. *Bind the application identity* to your exact package name and the digests of every signing
certificate you legitimately ship, as an allow-list rather than a wildcard. This kills cross-app
relay and does nothing against a keybox holder (§5.4).
6. *Issue a [single-use nonce](https://www.rfc-editor.org/rfc/rfc4949) for every attestation and
   every assertion*, with a tight time budget.
7. *Require proof-of-possession in session*: after chain validation, a signature over a fresh
challenge by the attested key. Be honest that it does not close the relay (§5.4).
8. *Bind the request and count it.* Include the security-critical parameters of the operation in the
signed assertion so a proxied signature cannot be retargeted, and check a strictly increasing
counter.
9. *Re-attest continuously rather than once at enrolment*, and treat any long-lived credential
minted on a device later found to be on vulnerable firmware as potentially cloned.
10. *Maintain a policy table* mapping device family to a minimum acceptable patch level, derived
    from *vendor* bulletins rather than the Android bulletin alone. Note the recursion: patch-level
    fields are themselves attested by the environment under suspicion, so treat them as advisory
    once a compromise is suspected.
11. *Do not treat a secure-element claim as a trust upgrade on its own.* It is attacker-controlled
    in the forgery case, and in the relay case the oracle's signature is genuine — arguably worse
    for the defender. Credit it only when the chain is RKP-rooted, unrevoked, and consistent with
    the model's known hardware.
12. *Never soften root pinning for test devices.* Test certificates are engineered by design not to
    chain to a production root ([`1-protocol.md`](1-protocol.md) §6.3).
13. *Rate-limit signing per key* and alert on anomalous volume from one enrolment — the direct
    counter to the [side-channel](https://en.wikipedia.org/wiki/Side-channel_attack) class, which
    needed roughly twelve thousand signatures over fourteen hours.
14. *Feed confirmed cases back to Google.* Researcher reports are a documented revocation trigger,
    so local detections shorten the gap for everyone.
15. *Pair hardware attestation with an independent signal*, and do not rely on the revocation list
    for RKP material at all (§2.4).

### 10.4 What hardware attestation cannot prove at all

State this plainly to product teams, because it is a property of the trust boundary rather than a
bug awaiting a patch.

*A hardware attestation proves* that a key with the stated properties was created inside a secure
environment holding a Google-rooted attestation credential, on a device whose verified-boot state
and patch levels were as stated *at key-creation time*, on behalf of a caller with the stated
package identity.

*It does not and cannot prove* that the entity now asking you to trust that key is the owner of the
device; that the Android userspace between your application and KeyMint is honest; or that the
request originated on the same device that signed it.

Because a rooted device retains full, *legitimate* access to its own uncompromised secure world, its
owner can always operate it as a signing oracle for a remote party. No key is stolen, nothing is
revocable, the bootloader really is locked on the signing device, and the signature really is
hardware-backed. The formal statement of this is published: *"There is no field in the
KeyDescription that binds the attestation to the transport, the session, or the device presenting
it. The nonce is the only freshness signal."*

So the residual ceiling is that attestation forces forgery into one of three lanes: *a leaked
private key*, which is revocable and detectable at scale; *a secure-world exploit*, which is
patchable and bindable to a patch level; or *a live, online, per-signature relay*, which is
expensive, latency-visible, stateful and rate-limitable. Everything that distinguishes the third
from a legitimate user is non-cryptographic and must be layered on.

Three further specifics that no migration fixes:

*Migrating to RKP-only devices eliminates the leaked-keybox class entirely and changes nothing about
relay or in-place use.* Say this to any team planning around the transition.

*Boot-chain collapse is invisible to revocation*, because the key and chain are genuine. The levers
are per-model boot-hash expectations, vendor patch pressure, and excluding device families with
unpatchable mask-ROM breaks rather than gating them on patch level.

*A relying party cannot see the DICE deployment phase, the `UdsCerts` map, or `UDS_pub`.* Phase-1
devices deliver materially less assurance than the architecture implies, and that is invisible at
the certificate layer ([`1-protocol.md`](1-protocol.md) §4.5). It has to be gathered out of band.

*The stance to adopt:* attestation is a strong negative filter — it cheaply excludes the
mass-market, zero-cost attacker — and a weak positive assertion. Design the risk engine so that a
perfect attestation raises the ceiling on what a session may do but never by itself authorises the
highest tier; reserve that tier for actions additionally gated on behavioural, account-history and
out-of-band signals, which are the only signals a signing oracle cannot proxy.

---

## 11. Consequences for the simulator

*The keybox parser is already correct and the documentation was stricter than the code.*
[`rust/teesim-km/src/attest.rs`](../rust/teesim-km/src/attest.rs) requires *at least one* of the RSA
and EC algorithms and at least two certificates per algorithm — which is what lets an RKP-shaped
keybox, one EC key and a four-certificate chain, load at all. A factory keybox is the other shape,
EC *and* RSA with three certificates each; both load.

*The acceptance relations of §1 are executable.* [`tools/`](tools/) implements them as
`teesim-attest`, with 34 tests needing neither network nor device: `verify` for the two chain layers
of §1.2, `inspect` for the extension decode and the issuance-count comparison of §4.2, `unpack` for
the length-prefixed container parsing of §1.5 with tail residue classified, `verify-csr` for the
DICE chain walk, canonical CBOR and device-information domains of §1.3, `revocation` for both serial
encodings of §2.3, and `baseline` for every constant with its provenance. The field routes'
*device-side* tooling is deliberately not ported, and [`tools/README.md`](tools/README.md) says
which and why.

*The inspector is the highest-value port, and it is transcription rather than design.* The two gates
of §1.4 belong in
[`app/.../KeyboxInspector.kt`](../app/src/main/java/org/matrix/teesim/KeyboxInspector.kt), which
already parses chains, verifies each certificate against its parent, classifies the root and checks
revocation — and decodes *no* provisioning extension ([`1-protocol.md`](1-protocol.md) §8.2).
Concretely, it should: decode the extension at keybox load and render the issuance count, the
manufacturer and the verdict-and-subject pairs, *flagging plainly that the build fingerprint is
unsigned client input*; classify each loaded keybox as RKP-derived or factory from chain shape per
§3; show *days remaining* per chain position rather than a bare `expired` boolean, because a
two-week leaf expiring mid-session is a user-visible failure the present interface cannot explain;
and warn when a fingerprint-bound keybox contradicts the active profile.

*The verdict surface needs one honesty fix.* The existing revoked / Google-signed / chain-verifies
triad is *structurally incomplete for RKP*: absence from the status list means nothing there, and
the RKP hierarchy's CRL is at CRL Number 0 (§2.4). The interface should say so rather than render a
green tick that encodes no information.

*Two things to keep straight in the emulation layer*, both correctness requirements rather than
cosmetics. `KeysToSign` carries bare COSE_Keys and the MAC is stripped before transmission, so
nothing downstream should model it as a server-side binding ([`1-protocol.md`](1-protocol.md) §2.4).
And the device-information CDDL makes the verified-boot metadata digest mandatory, so a conforming
emulation must emit it — which is simultaneously the cheapest server-side detector against every
tool in this class (§10.1).

*Finally, the properties stay read-only.* The three RKP properties are read and never written
([`1-protocol.md`](1-protocol.md) §7.3): flipping a device-wide `rkp_only` or daemon-enable flag
would itself be a conspicuous detection point of exactly the kind §7.3 of this document recommends
to defenders.
