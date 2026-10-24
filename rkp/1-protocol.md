# 1 · Android [Remote Key Provisioning](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning) — protocol, trust model, and the limits of simulation

*Companions: [`2-mechanisms.md`](2-mechanisms.md), how attestation material is taken from real
handsets; [`3-detection.md`](3-detection.md), what a defender can do about it;
[`4-measurements.md`](4-measurements.md), every number this series relies on;
[`5-sources.md`](5-sources.md), where each claim comes from. The acceptance relations stated here
are executable in [`tools/`](tools/).*

## Abstract

Remote Key Provisioning replaced Android's factory-provisioned batch attestation keys with
short-lived per-device certificates issued by a Google backend over the device's lifetime. The trust
anchor moves from a key burned into a production run to a registration event: the backend signs for
a device only if the root of that device's
[DICE](https://source.android.com/docs/security/features/dice) chain is a public key some
manufacturer enrolled on a vetted factory line. This part reconstructs the wire protocol as
[AOSP](https://source.android.com/) defines it — three interleaved version axes, the
canonical-[CBOR](https://www.rfc-editor.org/rfc/rfc8949) and
[COSE](https://www.rfc-editor.org/rfc/rfc9052) rules that decide byte equality, the
`AuthenticatedRequest<CsrPayload>` envelope, and the DICE chain with its [CBOR Web
Token](https://www.rfc-editor.org/rfc/rfc8392) entries — and then analyses the trust relation it
establishes. For a simulator the result is sharp: every structural property of the exchange is
reproducible and none of them decides anything, because acceptance is membership in a set the
verifier fixed before it saw the message. Two independent anchors enforce that — a registered
[Unique Device
Secret](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md) at
provisioning time, a pinned Google root at consumption time — and either defeats a self-rooted chain
alone. One correction to the prior record: the layer-identifier derivation in
[`open-dice`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c) masks the
high bit of its first output byte, an operation the formula this series previously carried omitted,
and the omission breaks chain linkage while presenting as a signature bug.

---

## 1. Introduction

### 1.1 What factory provisioning could not do

Before Android 12 a device attested with a *batch key*: an RSA and an EC private key, with
Google-rooted certificate chains, injected on the production line and shared across a manufacturing
batch. Three properties became untenable at scale. The key is long-lived — chains measured from
leaked factory keyboxes carry ten-year leaves ([`4-measurements.md`](4-measurements.md) §2.1). It is
shared, so one extraction compromises every handset in the batch. And it is unrevocable in practice,
because revoking the batch bricks attestation for every device that shipped with it; the public
revocation list is dominated by exactly that event, with 56% of its entries tracing to a single
scraped corpus of 551 factory keyboxes ([`4-measurements.md`](4-measurements.md) §4.3).

RKP changes all three. Keys are per-device, minted on demand, and valid for roughly two weeks; the
long-term secret never leaves the chip; and revocation is a registry edit at the backend rather than
a certificate-list entry. The cost is a new dependency: the device must prove, on every request,
that it is a device a manufacturer enrolled.

### 1.2 The two anchors

*The provisioning anchor* binds device to backend. The RKP server signs keys only for a device whose
DICE chain terminates in a `UDS_pub` that a manufacturer registered out of band, at the factory,
before the device shipped. The failure mode is HTTP 444,
[`DEVICE_NOT_REGISTERED`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RkpdException.java).

*The consumption anchor* binds key to relying party. Apps and [Play
Integrity](https://developer.android.com/google/play/integrity) verify an attestation chain that
must terminate at a Google attestation root they pinned in advance.

Trust here is membership in a set the verifier decided on beforehand, never a property
manufacturable inside the artifact. §6 works through the consequences.

### 1.3 Companions, and where the apparatus lives

The four companion documents are exclusive in subject: [`2-mechanisms.md`](2-mechanisms.md) is what
has been done to real handsets, [`3-detection.md`](3-detection.md) what a defender can do about it,
[`4-measurements.md`](4-measurements.md) every number either relies on, and
[`5-sources.md`](5-sources.md) where each number came from. The apparatus has one copy only: the
grading scheme (§1.4), the scope rule (§1.5) and the reference list (§9) are stated here and nowhere
else in the series.

### 1.4 Evidentiary grading

Every substantive claim in this series carries one of six grades, and no grade is promoted when a
claim moves between documents.

*[MEASURED]* — reproduced locally by a command this series publishes. *[PRIMARY]* — read directly
from a primary artifact: AOSP source, a vendor binary, a CVE record, a published paper, a signed
certificate. *[REPORTED]* — asserted by a research record whose supporting artifacts exist but whose
execution was not re-run. *[INFERRED]* — reasoning over graded facts, with the inference stated.
*[SPECULATIVE]* — conjecture, carried only where naming it is useful. *[UNVERIFIED]* — asserted by a
source that could not be independently confirmed.

Version-dependent claims are additionally marked *⚠︎ver* and must be re-checked against
[`cs.android.com`](https://cs.android.com/android/platform/superproject/main) or
[Gitiles](https://android.googlesource.com/) raw for the exact `android-*` branch being emulated,
never the GitHub mirror, which lags and rewrites paths.

### 1.5 Scope

*Secret extraction is out of scope as a procedure.* The simulator manufactures its own keys and
never needs a real one. These documents reconstruct mechanisms, formats and acceptance relations so
that the simulation is faithful and the detection advice is correct. They cite digests, symbol
names, offsets and extents as evidence that a mechanism exists, and they reproduce no private key
material — including where a cited source recovered and published it. Instruction bytes and command
numbers are given where they identify a defect class and withheld where they are the operative
content of a route rather than evidence of one. Seeds are discussed by digest fingerprint only.

---

## 2. The component interface

### 2.1 Three version axes

Three different version numbers travel together and none of them is the others. This is the largest
single source of byte mismatch.

| HAL `RpcHardwareInfo.versionNumber` | Android | CSR method | `AuthenticatedRequest` ver | `CsrPayload` ver | `DeviceInfo` internal `version` | EEK / test mode |
|---|---|---|---|---|---|---|
| v1 | 12 (S) | `generateCertificateRequest` | — (`ProtectedData`) | — | `1` | required |
| v2 | 13 (T) | `generateCertificateRequest` | — | — | `2` | required |
| v3 | 14 (U) → main | `generateCertificateRequestV2` | `1` | `3` | *removed* | absent |

In v3 the CSR carries `AuthenticatedRequest` schema version 1 and `CsrPayload` schema version 3,
while `DeviceInfo` no longer carries a version key at all. `RpcHardwareInfo.versionNumber == 3` is
the switch that tells `rkpd` to call `generateCertificateRequestV2` and skip everything EEK-related;
the guard reads `if (getVersion() < 3)`. *⚠︎ver*

### 2.2 The [AIDL](https://source.android.com/docs/core/architecture/aidl) surface

The component is declared in Android's interface definition language as
[`IRemotelyProvisionedComponent.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl)
in package `android.hardware.security.keymint`, marked `@VintfStability`:

```java
RpcHardwareInfo getHardwareInfo();

byte[] generateEcdsaP256KeyPair(in boolean testMode,
                                out MacedPublicKey macedPublicKey);   // returns an opaque key_blob

// HAL v1/v2 — deprecated in v3; a v3 component MUST throw STATUS_REMOVED
byte[] generateCertificateRequest(in boolean testMode, in MacedPublicKey[] keysToSign,
                                  in byte[] endpointEncryptionCertChain, in byte[] challenge,
                                  out DeviceInfo deviceInfo, out ProtectedData protectedData);

// HAL v3+ — the current path
byte[] generateCertificateRequestV2(in MacedPublicKey[] keysToSign, in byte[] challenge);
```

The return values differ in kind and are easy to transpose. `generateEcdsaP256KeyPair` returns an
opaque wrapped private key and delivers the public half through the `out` parameter.
`generateCertificateRequest` returns only the `keysToSignMac`, the
[COSE_Mac0](https://www.rfc-editor.org/rfc/rfc9052#section-6) tag over the key array, with the rest
of the request split across `deviceInfo` and `protectedData`. `generateCertificateRequestV2` returns
the entire CSR as one canonically encoded `byte[]`.

Errors arrive as `ServiceSpecificException`: `STATUS_FAILED=1`, `STATUS_INVALID_MAC=2`,
`STATUS_PRODUCTION_KEY_IN_TEST_REQUEST=3`, `STATUS_TEST_KEY_IN_PRODUCTION_REQUEST=4`,
`STATUS_INVALID_EEK=5`, `STATUS_REMOVED=6`. Codes 3 and 4 encode the EEK-era rule that one request
may not mix production keys with a test `MacedPublicKey` — marked by the presence of
[COSE_Key](https://www.rfc-editor.org/rfc/rfc9052#section-7) label `-70000` and MAC'd under a
32-byte all-zero key.

Three parcelables are CBOR carriers rather than structured types: `MacedPublicKey{byte[] macedKey}`
is a COSE_Mac0, `DeviceInfo{byte[] deviceInfo}` a [canonical
CBOR](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) map, and `ProtectedData{byte[]
protectedData}` a [COSE_Encrypt](https://www.rfc-editor.org/rfc/rfc9052#section-5) that exists only
in v1/v2.

### 2.3 Hardware info

[`RpcHardwareInfo.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/RpcHardwareInfo.aidl):

```java
parcelable RpcHardwareInfo {
    const int CURVE_NONE = 0, CURVE_P256 = 1, CURVE_25519 = 2, MIN_SUPPORTED_NUM_KEYS_IN_CSR = 20;
    int    versionNumber;                      // matches CsrPayload version (1|2|3)
    String rpcAuthorName;
    int    supportedEekCurve = CURVE_NONE;     // deprecated as of v3
    @nullable String uniqueId;                 // added v2; <=32 chars; per-SoC, NOT per-device
    int    supportedNumKeysInCsr = MIN_SUPPORTED_NUM_KEYS_IN_CSR;  // source default 4, MUST be >=20 for v3
}
```

A v3 simulator reports `versionNumber=3`, `supportedNumKeysInCsr >= 20` and a stable coarse
`uniqueId` that names an SoC class rather than an individual device. `supportedEekCurve` needs a
caveat the prior record stated without one: `CURVE_NONE` is semantically right for v3, since there
is no endpoint encryption key any more, but [VTS](https://source.android.com/docs/core/tests/vts)
has been observed to fail an implementation that reports it. Model the value the target branch's VTS
accepts, and treat an unqualified recommendation here as version-dependent. *⚠︎ver*

### 2.4 Key generation and the MAC'd public key

Every provisionable leaf key is
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) / ES256
regardless of the DICE chain's own curve. The public half comes back as a COSE_Mac0 so the component
can later prove, inside the CSR method, that a key it is asked to certify is one it generated.
[`PublicKey.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/PublicKey.cddl):

```cddl
PublicKey = {                 ; COSE_Key, RFC 9052 §7
    1 :  2,    ; kty : EC2
    3 : -7,    ; alg : ES256
    -1 : 1,    ; crv : P256
    -2 : bstr, ; X, big-endian
    -3 : bstr, ; Y, big-endian
    ? -70000 : nil   ; presence => TEST key (K_mac = 32 x 0x00). Deprecated in v3 — omit.
}
```

The MAC is `HMAC-SHA256(K_mac, MAC_structure)` with context `"MAC0"` and protected header `{1: 5}`.

`K_mac` is a contract, not a construction. Only two rules are observable: the key that produced a
`MacedPublicKey` must verify it inside the CSR method, and a test key uses 32 zero bytes. In v3
`K_mac` never leaves the device, so a faithful simulator may pick any stable 32-byte
[HMAC](https://www.rfc-editor.org/rfc/rfc2104) key. TEESimulator derives one through
`derive_bytes_from_hbk` over the fixed label `b"teesim-rpc-hbk"` in
[`rust/teesim-km/src/device.rs`](../rust/teesim-km/src/device.rs).

That freedom cuts the other way, and [`2-mechanisms.md`](2-mechanisms.md) §7.1 turns it into a step
of the minting pipeline: because the TA strips the MAC before building the CSR, the backend receives
no evidence that a submitted key was ever TA-generated. The MAC is a device-internal check, and an
implementation that forgets to perform it has no second line of defence.

### 2.5 The v3 certificate request

[`generateCertificateRequestV2.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl):

```cddl
Csr = AuthenticatedRequest<CsrPayload>

AuthenticatedRequest<T> = [
    version: 1,                      ; AuthenticatedRequest schema version
    UdsCerts,                        ; optional vendor certification of UDS_Pub (§2.7)
    DiceCertChain,                   ; UDS_Pub -> ... -> the KeyMint DICE leaf (§4)
    SignedData<[
        challenge: bstr .size (0..64),   ; the server nonce, from the method parameter
        bstr .cbor T,                    ; the CsrPayload, embedded as bstr-wrapped CBOR
    ]>,                              ; COSE_Sign1 under CDI_Leaf_Priv
]

CsrPayload = [
    version: 3,
    CertificateType,                 ; tstr: "keymint" | "widevine" | "rkp-vm"
    DeviceInfo,                      ; the DeviceInfoV3 map (§2.6)
    KeysToSign,                      ; [ * PublicKey ] — BARE public keys, MACs verified and stripped
]
```

The payload is double-wrapped: the `CsrPayload` is canonically encoded, then embedded as a `bstr
.cbor` inside the signed array. The challenge appears exactly once, beside that embedded payload,
not per key.

The signature is a [COSE_Sign1](https://www.rfc-editor.org/rfc/rfc9052#section-4) over an [RFC 9052
§4.4](https://www.rfc-editor.org/rfc/rfc9052#section-4.4) `Sig_structure`, and it is the most common
byte-faithfulness error in the protocol:

```cddl
SignedData<Data> = [
    protected:   bstr .cbor { 1 : AlgorithmEdDSA / AlgorithmES256 / AlgorithmES384 },
    unprotected: {},
    payload:     bstr .cbor Data / nil,
    signature:   bstr,
]
SignedDataSigStruct<Data> = [    ; THIS is what gets signed
    context: "Signature1",
    protected: bstr .cbor { 1 : ... },
    external_aad: bstr .size 0,  ; h''
    payload: bstr .cbor Data / nil,
]
```

What is signed is the `Sig_structure`, not the payload. Build `["Signature1", protected_bstr, h'',
payload_bstr]`, encode it canonically, then sign. The `protected` bytes must be byte-identical in
the COSE_Sign1 and in the `Sig_structure`: encode once and reuse the bytes, because two canonical
encoders can agree on a value and still disagree on a header nobody re-checked.

In the vendored reference TA, `generate_cert_req_v2` in
[`third_party/keymint/ta/src/rkp.rs`](../third_party/keymint/ta/src/rkp.rs) produces this shape and
`generate_cert_req` the v1/v2 one.

### 2.6 Device self-description

[`DeviceInfoV3.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV3.cddl):

```cddl
DeviceInfo = {
    "brand": tstr, "manufacturer": tstr, "product": tstr, "model": tstr, "device": tstr,
    "vb_state": "green" / "yellow" / "orange",
    "bootloader_state": "locked" / "unlocked",
    "vbmeta_digest": bstr,
    ? "os_version": tstr,            ; optional in the grammar, mandatory for security_level "tee"
    "system_patch_level": uint,      ; YYYYMM
    "boot_patch_level": uint,        ; YYYYMMDD
    "vendor_patch_level": uint,      ; YYYYMMDD
    "security_level": "tee" / "strongbox",
    "fused": 1 / 0,                  ; 1 if secure-boot fuses are blown
}
```

The five identity strings map to `ro.product.*`. V1 and V2 marked most of them optional; V3 makes
them mandatory and dropped both the internal `"version"` key and the older `"att_id_state"`. The
apparent contradiction around `os_version` is a split between grammar and policy: the
[CDDL](https://www.rfc-editor.org/rfc/rfc8610) marks it optional, a HAL and backend rule requires it
when `security_level` is `"tee"`, so model it present. *⚠︎ver*

`security_level` is where a per-level TA design surfaces on the wire: emit the level of the instance
producing the request. The backend compares `DeviceInfo` across a device's requests for consistency,
so whatever is emitted must be stable per device.

Two properties of this map are established empirically rather than from the specification, and both
matter more than its grammar. `vbmeta_digest` is mandatory and a genuine TA cannot omit it, which
makes an omission positive evidence that a request was not TA-produced
([`4-measurements.md`](4-measurements.md) §3.4). And the build fingerprint is not in this map at all:
`rkpd` appends it afterwards, unsigned, as an `UnverifiedDeviceInfo` map in
[`CborUtils.buildUnverifiedDeviceInfo`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java).
Everything a relying party might read here as device identity is therefore either operator-authored
or appended outside the signature.

### 2.7 UDS certification

```cddl
UdsCerts    = { * SignerName => UdsCertChain }   ; SignerName = tstr, the endorsing authority
UdsCertChain = [ + X509Certificate ]             ; DER, root -> ... -> leaf certifying UDS_Pub
```

This lets a vendor attest that `UDS_Pub` belongs to a genuine part; the backend maps `SignerName` to
an out-of-band root. It may legitimately be an empty map `{}` where the platform provides no UDS
certification, but a backend that expects vendor UDS certificates will reject an empty one, so which
is correct is a property of the target deployment. *⚠︎ver* The reference field is `uds_certs` in
[`rkp.rs`](../third_party/keymint/ta/src/rkp.rs).

### 2.8 The v1/v2 shape, and what v3 deleted

Needed only to present as HAL v1 or v2; in v3 the legacy method must throw `STATUS_REMOVED`.

`MacedKeys` is a COSE_Mac0 over `[ * PublicKey ]` whose tag is the method's return value, with MAC
input `["MAC0", {1:5}, h'', bstr .cbor [*PublicKey]]`. The EEK chain arriving in
`endpointEncryptionCertChain` is a sequence of [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) or
P-256 COSE_Sign1s ending in an endpoint encryption COSE_Key — `EekX25519` with `crv` 4, or `EekP256`
— both at `alg -25`, carrying a `kid`, validated against a root hardcoded in the component.
`ProtectedData` is a COSE_Encrypt at `{1: 3}`
([A128GCM](https://www.rfc-editor.org/rfc/rfc9053#section-4.1)) with the IV in the unprotected
header, recipient algorithm `{1: -25}`
([ECDH-ES](https://www.rfc-editor.org/rfc/rfc9053#section-6.2) +
[HKDF](https://www.rfc-editor.org/rfc/rfc5869)-256), the content key derived from ECDH between an
ephemeral sender key and the EEK.

The crux of v1/v2 is `SignedMac`: a COSE_Sign1 whose payload is `K_mac` itself, signed by the DICE
leaf and encrypted to the EEK inside `ProtectedData`, with `SignedMacAad = [challenge,
VerifiedDeviceInfo, tag: keysToSignMac]`. The server decrypts, recovers `K_mac`, and only then
verifies the `MacedKeys` tag.

V3 deletes that entire round trip. Authenticity comes from the DICE signature over the whole
`CsrPayload`; `K_mac` stays on the device; `testMode` disappears from the CSR method;
`ProtectedData` and the EEK vanish. For a v3-only simulator all of §2.8 is dead weight — and, per
[`2-mechanisms.md`](2-mechanisms.md) §7.3, finding unused `ProtectedData` code in a tool is
therefore not evidence that the tool was never run; two independent implementations build the
structure and then discard it.

---

## 3. Deterministic encoding

Byte equality with a real device is decided here, not in the structure definitions. Every RKP
structure must be [deterministically encoded](https://www.rfc-editor.org/rfc/rfc8949#section-4.2),
and
[`system/libcppbor`](https://cs.android.com/android/platform/superproject/main/+/main:system/libcppbor)'s
`canonicalize()` is the de facto oracle.

### 3.1 Canonical CBOR as [cppbor](https://cs.android.com/android/platform/superproject/main/+/main:system/libcppbor/) computes it

Definite-length encodings only; shortest-form integers and headers; map keys sorted by encoded key
bytes, per [RFC 8949 §4.2](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) core determinism.

The sorting rule is where generic CBOR libraries diverge, and the divergence is silent. For COSE's
small integer labels, positive labels `0, 1, 2, …` encode as single bytes `0x00, 0x01, 0x02, …`
while negative labels encode as `-1 → 0x20`, `-2 → 0x21`, and so on. So `-1` sorts after `3`,
because `0x20 > 0x03`. Sorting labels by numeric value produces a well-formed CBOR map that is not
the one the device emits, and nothing downstream complains until a signature fails. Match cppbor's
tie-break, not a library's notion of canonical.

For text-string keys, as in `DeviceInfo`, the same rule means shorter keys sort before longer ones
and ties break bytewise, which is not alphabetical order.

`bstr .cbor X` means: encode `X` canonically, then wrap those bytes in a byte string. The
encode-once-reuse-bytes discipline of §2.5 applies to every `protected` header shared between a COSE
object and its signature or MAC structure.

### 3.2 COSE labels and algorithms

| Purpose | COSE alg | Value |
|---|---|---|
| [ECDSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) P-256 / [SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | ES256 | `-7` |
| ECDSA P-384 / SHA-384 | ES384 | `-35` |
| Ed25519 | EdDSA | `-8` |
| HMAC-SHA-256 | HMAC 256/256 | `5` |
| ECDH-ES + HKDF-256 (v1/v2 EEK) | — | `-25` |
| AES-128-GCM (v1/v2 `ProtectedData`) | A128GCM | `3` |

Header labels: `1` alg, `2` crit, `3` content type, `4` kid, `5` IV, `-1` ephemeral key. COSE_Key
labels: `1` kty (`1` = OKP, `2` = EC2), `2` kid, `3` alg, `-1` crv (`1` = P-256, `2` = P-384, `4` =
[X25519](https://www.rfc-editor.org/rfc/rfc7748), `6` = Ed25519), `-2` x, `-3` y. Definitions are in
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and [RFC
9053](https://www.rfc-editor.org/rfc/rfc9053).

### 3.3 Signature value encoding

ECDSA signatures in COSE are the fixed-width `r‖s` form, each coordinate left-zero-padded to the
curve size: 32 bytes for P-256, 48 for P-384. They are not
[ASN.1](https://www.itu.int/rec/T-REC-X.680) [DER](https://www.itu.int/rec/T-REC-X.690), which is
what every general-purpose crypto library returns by default. Ed25519 is the raw 64-byte `R‖S` of
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032). This is the most frequently reported cause of a
chain that parses, links by name, and fails to verify.

---

## 4. DICE

### 4.1 The model

The device holds a hardware secret, the *Unique Device Secret*. Each boot stage measures the stage it
is about to launch, folds those measurements into a one-way [key-derivation
function](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) to produce a fresh *[Compound Device
Identifier](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md)* for
that next stage, and emits a certificate binding the two stages' public keys. Chaining from the
UDS-derived root to the last stage yields the DICE chain, which Android calls `Bcc` in RKP v1/v2 and
`DiceCertChain` in v3. The leaf stage is the
[KeyMint](https://source.android.com/docs/security/features/keystore)/RKP component, and its DICE
private key signs the CSR of §2.5.

The chain proves that this exact software stack, on this genuine device, is asking. It is not the
chain an application sees at attestation time; those are different hierarchies that meet only inside
Google's infrastructure (§6.1).

### 4.2 The derivation, verbatim

The normative reference is
[`open-dice`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md),
with the Android profile in
[`docs/android.md`](https://android.googlesource.com/platform/external/open-dice/+/refs/heads/main/docs/android.md)
and the implementation in
[`src/dice.c`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c). Crypto
defaults are [SHA-512](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), HKDF-SHA-512 and
Ed25519, with P-256 and P-384 profiles also defined; `DICE_CDI_SIZE` is 32 and `DICE_HASH_SIZE` 64.
*⚠︎ver*

The UDS is fused at manufacture and latched: readable only by the first mutable code, which is the
DICE engine itself, then hardware-locked before control passes on. No later stage, including the
KeyMint leaf, can read it. It is never transmitted; what leaves the device is `UDS_pub`, called
`DK_pub` in the `Bcc` CDDL, the first element of the chain.

Each layer supplies five measurements of the stage about to launch, as `DiceInputValues`: a 64-byte
code hash; a configuration descriptor or value, from which a configuration hash is computed; a
64-byte authority hash over the verifying key or policy; a one-byte mode; and 64 bytes of hidden
input that appears in no certificate. Two CDIs are derived, and which inputs feed which is the whole
design:

```
attest_input_hash = SHA-512( Code ‖ Config ‖ Authority ‖ Mode ‖ Hidden )   ; all five
seal_input_hash   = SHA-512( Authority ‖ Mode ‖ Hidden )                   ; the last three only

CDI_Attest' = HKDF-SHA512(IKM = CDI_Attest, salt = attest_input_hash, info = "CDI_Attest", L = 32)
CDI_Seal'   = HKDF-SHA512(IKM = CDI_Seal,   salt = seal_input_hash,   info = "CDI_Seal",   L = 32)
```

At stage 0 the input keying material is the UDS itself. `CDI_Attest` changes when any layer's code or
configuration changes, so it is an identity of the exact running stack, and it backs the certificate
keys. `CDI_Seal` omits code and configuration and so survives firmware updates from the same vendor,
which is what lets sealed data outlive an [OTA](https://source.android.com/docs/core/ota); it never
appears in the chain.

The mode byte is `0` not-configured, `1` normal, `2` debug, `3` recovery. A model of a locked
production device uses `1` throughout.

### 4.3 Layer keys and identifiers, including the masking step

Each layer's key pair and its 20-byte identifier come from fixed-salt HKDF over `CDI_Attest`:

```
seed = HKDF(IKM = CDI_Attest, salt = kAsymSalt, info = "Key Pair", L = DICE_PRIVATE_KEY_SEED_SIZE)
id   = HKDF(IKM = encoded_public_key, salt = kIdSalt, info = "ID", L = 20)
id[0] &= 0x7f                                      ; <- the step previously omitted
```

*[PRIMARY]* The masking line is in
[`src/dice.c`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c): the first
output byte has its high bit cleared before the identifier is rendered as 40 lowercase hex
characters. The formula this series previously carried stopped at the HKDF call. An implementation
that omits the mask produces identifiers differing from a real device's in one bit, for about half
of all public keys, which breaks the chain-linking invariant below. The symptom is a chain whose
entries each verify in isolation but which no verifier will stitch, and it presents as a signature
bug rather than the string mismatch it is.

The chain-linking invariant is `Issuer(entry N) == Subject(entry N-1) == hex(ID(pubkey of layer
N-1))`. It is how a verifier assembles the chain independently of ordering. HKDF one-wayness gives
forward secrecy of the UDS while determinism makes the chain a faithful fingerprint of the boot:
different software yields a different `CDI_Attest`, hence a different leaf key, hence a different
Subject.

### 4.4 Chain entries

```cddl
DiceCertChain = [
    PubKeyEd25519 / PubKeyECDSA256 / PubKeyECDSA384,   ; UDS_Pub — a BARE COSE_Key, no entry wraps it
    + DiceChainEntry,                                   ; root..leaf; the last is the KeyMint DICE leaf
]
DiceChainEntry = [                                     ; COSE_Sign1, untagged
    protected: bstr .cbor { 1 : AlgorithmEdDSA / AlgorithmES256 / AlgorithmES384 },
    unprotected: {},
    payload:   bstr .cbor DiceChainEntryPayload,
    signature: bstr,                                   ; signed by the PREVIOUS entry's key
]
DiceChainEntryInput = [ "Signature1", protected, external_aad: bstr .size 0, payload ]

DiceChainEntryPayload = {                              ; a CWT, RFC 8392
    1 : tstr,                                          ; Issuer — the parent's 40-hex ID
    2 : tstr,                                          ; Subject — this key's 40-hex ID
    -4670554 : tstr,                                   ; Profile Name, e.g. "android.15"   (v3+)
    -4670552 : bstr .cbor PubKey,                      ; Subject Public Key
    -4670553 : bstr,                                   ; Key Usage — keyCertSign is 0x20
    -4670545 : bstr,                                   ; Code Hash
  ? -4670546 : bstr,                                   ; Code Descriptor
    -4670547 : bstr,                                   ; Configuration Hash  (mandatory in v3)
    -4670548 : bstr .cbor ConfigurationDescriptor,     ; Configuration Descriptor
    -4670549 : bstr,                                   ; Authority Hash
  ? -4670550 : bstr,                                   ; Authority Descriptor
    -4670551 : bstr,                                   ; Mode, one byte
}
ConfigurationDescriptor = {
  ? -70002 : tstr,        ; component name
  ? -70003 : int / tstr,  ; component or firmware version
  ? -70004 : null,        ; resettable
  ? -70005 : uint,        ; security version   (v3+)
  ? -70006 : null,        ; RKP VM marker      (v3+)
}
```

The v1/v2 `Bcc` in
[`ProtectedData.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/ProtectedData.aidl)
is the same shape minus the v3 deltas: no Profile Name, Configuration Hash optional rather than
mandatory, no P-384, and a configuration descriptor restricted to `-70002/-70003/-70004`. `Bcc =
[DK_pub, + BccEntry]` annotates its last entry `KM_pub`, so the final entry's Subject Public Key is
the KeyMint component's own public key. The signature structure is identical and merely renamed
`BccEntryInput`.

Public keys appear in three forms, and the coordinate endianness differs by curve:

```cddl
PubKeyEd25519  = { 1:1, 3:-8,  -1:6, -2:bstr }            ; OKP, Ed25519, X — LITTLE-endian (RFC 8032)
PubKeyECDSA256 = { 1:2, 3:-7,  -1:1, -2:bstr, -3:bstr }   ; EC2, P-256, X/Y — BIG-endian (SEC1)
PubKeyECDSA384 = { 1:2, 3:-35, -1:2, -2:bstr, -3:bstr }   ; EC2, P-384, X/Y — BIG-endian
```

Wrong endianness yields a well-formed chain whose signatures do not verify.

One deviation reads like a contradiction in the sources. The Android DICE profile emits digests at
their actual hash length — 32 bytes for SHA-256, 48 for SHA-384, 64 for SHA-512 — deliberately
departing from the Open Profile for DICE, where all digests are padded to 64. This does not
contradict `DICE_HASH_SIZE = 64` in `dice.c`: that is the engine's internal buffer, and a SHA-512
profile genuinely emits 64 bytes. The rule bites only when a stage measured with SHA-256 or SHA-384
must emit 32 or 48 bytes rather than a zero-padded 64-byte field. Do not zero-pad emitted digests.

### 4.5 The two legal shapes, and the three deployment phases

Per stage N the loop is: stage N-1, holding `CDI_Attest(N-1)` and key `K_{N-1}`, measures stage N,
derives `CDI_Attest(N)` and thence `K_N` and `Subject(N)`, sets `Issuer` to `ID(N-1)`, builds the
[CWT](https://www.rfc-editor.org/rfc/rfc8392) carrying `K_N`'s public half, wraps it in a COSE_Sign1
signed with `K_{N-1}`, appends it, hands the CDIs to stage N, and wipes the parent CDI. The private
`K_leaf` is consequently the only DICE private key any runtime code still holds, and it is the key
that signs the RKP `SignedData`.

Two shapes are protocol-legal. A *full multi-stage chain* carries one entry per boot stage: ROM,
bootloader, TEE, KeyMint. A *degenerate chain* is a single self-signed entry where `UDS_Pub` equals
the Subject Public Key; the `+ DiceChainEntry` one-or-more quantifier permits it, and it is the
natural minimal shape for a simulator that mints its own root. *⚠︎ver*

These map onto the deployment phases AOSP documents in
[`hardware/interfaces/security/rkp/README.md`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/README.md):
*Phase 1*, degenerate DICE with a TEE root and a single self-signed certificate; *Phase 2*, DICE
proper with a hardware root per the Android profile; *Phase 3*, SoC-vendor-certified DICE, where
`UDS_Pub` is extracted and certified at the factory.

Phase 1 has an exact security consequence: on a Phase-1 device the backend has no per-boot-stage
measurement to evaluate, so a compromise that yields use or extraction of that single key pair
yields the ability to authenticate arbitrary certificate requests as that device, and the backend has
no firmware-hash signal with which to refuse.

*[PRIMARY]* AOSP detects the shape but does not uniformly refuse it. `remote_prov_utils` declares the
error string `"DICE chain is degenerate"` and returns it from two call sites, and the
chain-comparison helper reports which instance carries one. But the default-instance VTS test skips
on a degenerate chain — `GTEST_SKIP() << "Skipping test: Only a proper DICE chain has a mode set."` —
while the hard assertion is on the
[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox) instance,
whose requirement additionally applies from vendor API level 202404. Degenerate chains are therefore
diagnosed, fatal for StrongBox, and tolerated for the default TEE instance.

That is why the off-device minting pipeline of [`2-mechanisms.md`](2-mechanisms.md) §7 works on a
handset declaring no StrongBox: a degenerate chain built around one stolen seed is a conforming
request, not a malformed one. It is also the deployment the public minting tool targets, its own
documentation describing a degenerate chain in which the UDS equals the leaf, self-signed. The tool
is not a general break of RKP; it is a break of RKP-on-Phase-1, gated entirely on possessing a leaf
seed.

### 4.6 Populating a fabricated chain

Generate a random `K_uds`; per layer either derive `K_i` by the §4.2 recipe over that fake UDS, which
gives stable Subjects across runs, or generate `K_i` randomly, which is simpler and still
structurally valid. Fill measurements with plausible constants — `codeHash = SHA(componentName ‖
version)`, `authorityHash = SHA("vendor-verified-boot-key")`, `mode = 1`, `keyUsage = 0x20` — sign
each entry with `K_{i-1}`, let the leaf's Subject Public Key be the key the emulated KeyMint uses for
RKP, and serialise canonically per §3.1. Keep `UdsCerts` self-rooted or empty: a `UdsCerts` chain
reaching a real manufacturer root is the one genuinely out-of-scope piece, since the backend pins
real vendor CAs.

---

## 5. The deployment path

### 5.1 What "rkpd" is

Despite the name, `rkpd` is not a native daemon. Across releases it is an app process bound on
demand, plus a system-server
[binder](https://source.android.com/docs/core/architecture/hidl/binder-ipc) shim. On Android 12 it
is the `RemoteProvisioner` app (`com.android.remoteprovisioner`) scheduling a `JobService`. From
Android 13 onward it is
[`rkpdapp`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/)
(`com.android.rkpdapp`), shipped inside the `com.android.rkpd`
[APEX](https://source.android.com/docs/core/ota/apex), with `PeriodicProvisioner` implemented as an
`androidx.work.Worker`. Android 11 and earlier have no RKP at all, which makes RKP presence a clean
discriminator between the `keystore2` and `keystore1` code paths.

### 5.2 The HTTP exchange

1.
[`SystemInterface.generateEcdsaP256KeyPair()`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/interfaces/SystemInterface.java)
yields a `(key_blob, MacedPublicKey)` pair, banked in `rkpd`'s [Room
database](https://developer.android.com/training/data-storage/room). 2.
[`ServerInterface.fetchGeek()`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/interfaces/ServerInterface.java)
POSTs to `:fetchEekChain`, returning a challenge, `numExtraAttestationKeys`, and rollout
configuration. The GEEK chain itself is v1/v2-only; the endpoint name is legacy and reused, and "v3"
is a schema version rather than a URL component. *⚠︎ver, backend-defined*
3. `generateCertificateRequestV2(keysToSign, challenge)` produces the CBOR CSR.
4. `requestSignedCertificates(csr)` POSTs to `:signCertificates?challenge=…&request_id=…`.
5. The backend validates (§6.1), signs, and returns per-key DER chains.
[`CborUtils.parseSignedCertificates()`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java)
decomposes the response into a *shared* portion, root and intermediates, and a *unique* leaf per key,
concatenating `leaf ‖ shared`. Nothing in the response is secret; it is public certificates.
6. `rkpd` banks `(keyBlob, certChain)` pairs keyed by (IRPC name, client uid, key id), with sticky
assignment so an application's attestation identity stays stable.

Two trigger paths have distinct timing signatures, which matters for anything trying to observe
provisioning: ahead-of-time top-up by `PeriodicProvisioner` under the
[WorkManager](https://developer.android.com/topic/libraries/architecture/workmanager) unique work
name `"ProvisioningJob"`, targeting roughly six extra keys valid at least three days out; and lazy
inline provisioning on a `getKey` pool miss, which performs a network round trip on the calling
thread.

There is a server-side kill switch: `numExtraAttestationKeys == 0` disables RKP and triggers
`mKeyDao.deleteAllKeys()`.

Retry behaviour is region-aware. The connect timeout is selected from `gsm.operator.iso-country`
(`SYNC_CONNECT_TIMEOUT_RESTRICTED_MS = 400` versus `_OPEN_MS = 1000`); backoff starts at
`BACKOFF_TIME_MS = 100` and doubles, but only while the error is an `RkpdException` and only within
`max_request_time ≈ 20000 ms`. Hard faults — `SocketTimeoutException`, `IOException` — are not
retried. An error budget (`failure_counter`, `failure_start_time`, `failure_data`, capped at 1 MiB)
and a bad-certificate window act as a circuit breaker. The error taxonomy is `DEVICE_NOT_REGISTERED`,
meaning the DICE root is unknown to the backend, plus `HTTP_CLIENT_ERROR` and `HTTP_SERVER_ERROR`.
See
[`Settings.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java)
for the tunables.

*[PRIMARY]* `ServerInterface.requestData()` sets no HTTP headers at all: no API key, no `X-Goog-*`,
no client certificate, no TLS pinning, no `network_security_config`. The endpoints are
`remoteprovisioning.googleapis.com/v1:fetchEekChain` and `/v1:signCertificates`. The only
authentication in the exchange is the DICE signature inside the CSR body, which is what makes the
off-device minting of [`2-mechanisms.md`](2-mechanisms.md) §7 a client-side exercise rather than a
network attack.

### 5.3 Consumption in keystore2

[`RegistrationBinder`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RegistrationBinder.java)
implements `android.security.rkp.IRegistration` with `getKey(keyId, cb)`, `cancelGetKey(cb)` and
`storeUpgradedKeyAsync(old, new, cb)`. `getKey` evicts stale keys, looks in the pool by (IRPC name,
client uid, key id), provisions inline on a miss, and marshals a `RemotelyProvisionedKey{ byte[]
keyBlob; byte[] encodedCertChain; }`. `storeUpgradedKeyAsync` rewrites a pool row across a KeyMint
`upgradeKey` without re-provisioning.

On the consumer side,
[`remote_provisioning.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/remote_provisioning.rs)
and
[`attestation_key_utils.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/attestation_key_utils.rs):
when an application requests attestation — a challenge is present, no `attestKey` descriptor was
supplied, and the key is not device-unique — `get_attest_key_info` calls
[`rkpd_client::get_rkpd_attestation_key`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/rkpd_client.rs),
which reaches `IRemoteProvisioning.getRegistration(irpcName)` and then `IRegistration.getKey`.

The pooled key is the issuer, not the attested key. KeyMint mints the application's real key and
signs its leaf using the pooled blob as `ATTEST_KEY`; `keystore2` prepends the RKP
`encodedCertChain`, so the application reads `app-leaf → RKP-provisioned key → … → Google root`
directly off the `generateKey` reply. It is then stored split as `CERT` (the leaf) and `CERT_CHAIN`
(the rest) in `/data/misc/keystore/persistent.sqlite`.

### 5.4 The rkp_only fork, and the two Google roots

The most consequential behavioural fork is `is_rkp_only()`, which reads
`remote_provisioning.<tee|strongbox>.rkp_only`. With it off, a failed RKP lookup falls back to the
factory batch key, recorded by the metric `FALL_BACK_DURING_HYBRID`. With it on, failure is fatal:
`generateKey` fails outright rather than produce an unattested key. Any interception strategy has to
branch on this, and §7.3 explains why. The source comment gives the rationale: depending on the
release, RKP may not have been mandatory for the TEE or StrongBox instances, so a lookup failure is
working-as-intended and should allow natural fallback to the factory key.

This corrects a widely repeated narrative. The claim that the hybrid hole is being closed by
updating the provisioning module to return key-not-found cannot work as described: the fallback
decision lives in keystore2, platform code keyed on a vendor-set property, and any error from the
daemon triggers it when `rkp_only` is false. The existence of hybrid devices is real; the
enforcement story is not established. *[UNVERIFIED]*

Two pool-policy details are easy to get backwards. `GeekResponse.NO_EXTRA_KEY_UPDATE`, the value −1,
does not mean the backend is suppressing pool growth; it is the sentinel for "the server sent no
value, leave the setting alone". A backend suppressing growth sends `num_extra_attestation_keys =
0`, the kill switch of §5.2. And Google's "up to two months" certificate lifetime is an upper bound
rather than a fixed term; measured spans are about two weeks
([`4-measurements.md`](4-measurements.md) §2.1). Note also that "out of keys" is a family rather
than one error: transient, permanent, pending-connectivity and requires-system-upgrade variants are
mapped separately into keystore2's error space, and conflating them produces the wrong retry
behaviour.

Two Google roots now discriminate provenance: the long-standing RSA-4096 hardware-attestation root
used for factory batch keys, and the EC P-384 root `CN=Key Attestation CA1` used for RKP, which
began signing at a published cutover and became exclusive for RKP-enabled devices roughly ten weeks
later. *⚠︎ver* Both are pinned in
[`app/.../RootPublicKey.kt`](../app/src/main/java/org/matrix/teesim/RootPublicKey.kt), and the
measured chain positions under the EC root are in [`4-measurements.md`](4-measurements.md) §2.2.

### 5.5 On-disk storage, and what root actually gets

*The provisioning daemon's pool* is a
[Room](https://developer.android.com/training/data-storage/room) database named `rkpd_database` with
a single entity, whose table `provisioned_keys` carries `key_blob` as primary key plus `irpc_hal` —
the `RpcHardwareInfo.uniqueId`, which is why that identifier must be stable across reboots —
`public_key`, `certificate_chain`, an indexed `expiration_time`, `client_uid` and `key_id`, with a
unique composite index on `(client_uid, key_id, irpc_hal)`. The MAC'd public key and the COSE key are
not columns; they live on a separate in-memory class and are never persisted.

*keystore2's store* is `persistent.sqlite` under `/data/misc/keystore`, alongside a per-boot
database. Its tables are `keyentry`, `blobentry`, `blobmetadata`, `keyparameter`, `keymetadata` and
`grant`, with subcomponent types `KEY_BLOB=0`, `CERT=1` and `CERT_CHAIN=2`, the split §5.3
describes. In Android 13 keystore2 owned the RKP pool itself, through a `KeyType::Attestation`
variant and four dedicated functions; on current `main` only `Client` and `Super` remain, because
the pool moved to the daemon, although some attestation metadata tags survive. *⚠︎ver*

Root can read both stores in full and obtains only ciphertext blobs and public certificates. The
key-encryption key is derived inside KeyMint from a hardware root key.
[SELinux](https://source.android.com/docs/security/features/selinux) labels the directory, and the
namespace identifiers in keystore2's own access-control configuration are enforced by the daemon
rather than the kernel, so a root process that defeats SELinux gains file access and nothing
cryptographic.

This is the measurement behind a common category error. Dumping these tables yields many provisioned
key entries, which is the likely origin of claims to have "extracted a lot of RKP keys"; what comes
out is a wrapped blob and a public chain. [`4-measurements.md`](4-measurements.md) §4.4 reaches the
same result from a second direction: a stock device's stored provisioning key is a 275-byte opaque
blob, neither [PKCS#8](https://www.rfc-editor.org/rfc/rfc5958) nor a scalar.

### 5.6 Test mode is inert by construction

Four independent mechanisms make it so, all of them v1/v2 only.

First, the marker's definition: label `-70000` present means the key is a test key and `K_mac` is
all zeros, so a test `MacedPublicKey` is authenticated under a publicly known key and is useless as
evidence. The reference TA computes the MAC under 32 zero bytes in test mode. Second, strict mode
segregation, enforced by the status codes of §2.2: a request may not mix test and production keys,
and `generateCertificateRequestV2` must never accept a test key at all — the reference TA scans
every COSE key for the marker before MAC verification. Third, in test mode any endpoint key is
accepted, and correspondingly the test chain must contain freshly generated keys rather than the real
ones, so a test request carries a throwaway DICE chain and leaks no device identity. Fourth, the
backend checks the marker and issues test certificates that deliberately do not chain to a trusted
root.

From v3 the whole path is gone. One nuance if you read the reference TA: it raises `Removed` only
when the configured version is above v2, and for a v1/v2 configuration falls through to
`Unimplemented`, so the reference TA never implements the v1/v2 request path at all.

The residual risk is a vendor wiring bug — test keys receiving production certificates, or a backend
accepting test-tagged requests on a production endpoint — not a protocol flaw, and root pinning
already defeats it.

### 5.7 A second population of RKP keys, outside the TEE

The [Android Virtualization Framework](https://source.android.com/docs/core/virtualization)
provisions keys for privileged virtual machines through the same machinery, identified by the RKP VM
marker, configuration-descriptor key `-70006` from §4.4, plus a component name. The rule is
positional: if a chain begins from the root with zero or more entries without the marker, followed
only by entries with it up to and including the leaf, it describes a VM the backend may provision to;
and implementations must include the first marker as early as possible after the divergence between
TEE and non-TEE components, before the Android bootloader loads. The leaf's component name selects
the key type — `"rkp-vm"`, `"keymint"` or `"widevine"` — and a chain with no marker describes a TEE
component eligible for attestation keys. Anything else gets nothing.

Attestation is two-tier: the RKP VM attests to the backend, which compares its DICE root against
registered public keys, and other protected VMs then attest against the RKP VM.

A set of RKP private keys and a DICE chain therefore live inside a protected VM isolated by the
[hypervisor](https://en.wikipedia.org/wiki/Hypervisor) rather than inside the TEE: a different
isolation boundary with a different exploit population. SELinux reflects the split, giving the daemon
two distinct HAL client attributes. For a verifier the consequence is in
[`3-detection.md`](3-detection.md) §7.3: `RpcHardwareInfo.uniqueId` distinguishes the two instances,
so a pool where the virtual instance's identifier is missing or duplicated indicates an emulated HAL.

---

## 6. Trust analysis

### 6.1 The backend's validation order

1. CBOR and CDDL well-formedness of the CSR.
2. The `SignedData` COSE_Sign1 verifies under the DICE leaf key, and the embedded challenge matches
the one issued — freshness and anti-replay.
3. Every `DiceChainEntry` link verifies from `UDS_pub` to the leaf, with `Issuer`/`Subject`
identifiers linking as in §4.3.
4. `UDS_pub`, or the [X.509](https://www.rfc-editor.org/rfc/rfc5280) chain in `UdsCerts`, resolves to
a registered root. This is the check that carries the whole relation. Two enrollment paths exist: a
direct `UDS_pub` allow-list, where the OEM extracts and uploads each device's public key at the
factory; or OEM-signed `UdsCerts`, where an OEM key is itself registered with the server. Either way
the anchor is a manufacturing-time registration event on a line the operator vets. Revocation lives
here too, which is what makes per-device rotation feasible without bricking hardware.
5. Device state and eligibility: `DeviceInfo` sanity, mode, known-good hashes.
6. Only then are X.509 certificates issued for `KeysToSign`, chaining to a Google root.

### 6.2 Self-consistent versus anchored

A synthetic DICE chain is trivially self-consistent and can be made byte-perfect: correct CDDL,
correct COSE_Sign1, verifying signatures, the challenge echoed back. None of that decides anything.
Verification is not "do the signatures link up" but "does the link-up terminate at an anchor I
trusted before I ever saw this message". Anyone can mint a root and sign their own layers; only a
holder of a key whose public half was pre-registered or pinned can satisfy the second question.

### 6.3 Defeated twice, independently

At provisioning, step 4 asks whether `UDS_pub` resolves to a registered root; a synthetic root was
never enrolled at a vetted factory, so no production certificate is ever issued. At consumption, the
verifier asks whether the chain terminates at the pinned Google root and is unrevoked; a self-rooted
chain does not, so it is rejected regardless of internal validity.

Exactly two things would make step 4 succeed, and both lie outside cryptography. Chain to a real
registered UDS, which requires the genuine device's hardware-resident DICE private key and is the
subject of [`2-mechanisms.md`](2-mechanisms.md). Or get a synthetic root registered, which is a
manufacturing-enrollment or PKI compromise rather than a shortcut.

Test and degenerate chains are deliberately un-anchored by the same logic. HAL v1/v2 `testMode` used
a fresh, unregistered key so vendors could exercise the pipeline, and results were marked test-only
and never honoured. V3 removed the notion entirely: `generateCertificateRequestV2` has no `testMode`,
and the legacy method must raise `STATUS_REMOVED`. No code path upgrades a self-consistent chain to a
trusted one.

### 6.4 What the consumption side checks

This is the half a simulator must satisfy. KeyMint's leaf carries a `KeyDescription` under
[OID](https://www.itu.int/rec/T-REC-X.660) `1.3.6.1.4.1.11129.2.1.17`: the attestation challenge, the
attestation security level (Software, TEE, StrongBox), a `softwareEnforced` and a `hardwareEnforced`
`AuthorizationList` (purpose, algorithm, key size, origin, authentication binding), and a
`RootOfTrust{verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash}`. Only the
`hardwareEnforced` list, under a chain rooted at Google, is a claim the secure hardware makes.

A verifier checks: the chain to a pinned Google root; revocation against Google's published status
endpoint; the challenge matching the nonce it supplied; security level TEE or StrongBox rather than
Software; key properties and origin; and boot state — `verifiedBootState == Verified`, `deviceLocked
== true`. Batch-provisioned and RKP-provisioned keys terminate at the same Google roots, so verifier
logic is identical in both cases; RKP's advantage is operational rather than cryptographic.

A separate extension, OID `1.3.6.1.4.1.11129.2.1.30`, appears on RKP *signer* certificates and
carries what the backend recorded about the request. Almost no verifier reads it;
[`4-measurements.md`](4-measurements.md) §3 decodes it byte for byte.

---

## 7. TEESimulator

### 7.1 What is already present

The vendored AOSP KeyMint carries a complete IRPC implementation that nothing routes to.

[`third_party/keymint/ta/src/rkp.rs`](../third_party/keymint/ta/src/rkp.rs) implements `uds_certs`,
`rpc_device_info`, `generate_ecdsa_p256_keypair` — which computes the MAC, builds the
`MacedPublicKey` and rejects test mode on V3+ — and both `generate_cert_req` and
`generate_cert_req_v2`, each calling `get_dice_info`. `KeyMintTa::process` in
[`ta/src/lib.rs`](../third_party/keymint/ta/src/lib.rs) already routes `RpcGetHardwareInfo`,
`RpcGenerateEcdsaP256KeyPair`, `RpcGenerateCertificateRequest` and
`RpcGenerateCertificateV2Request`, and the TA wrapper in
[`rust/teesim-km/src/lib.rs`](../rust/teesim-km/src/lib.rs) forwards straight into
`self.inner.process(req)`. The TA could serve IRPC today; nothing sends it those transactions.

The DICE integration contract is the trait `RetrieveRpcArtifacts` in
[`third_party/keymint/ta/src/device.rs`](../third_party/keymint/ta/src/device.rs), with
`get_dice_info` and `sign_data`, the structs `DiceInfo` and `PubDiceArtifacts{uds_certs,
dice_cert_chain}`, the `CsrSigningAlgorithm` enum over ES256/ES384/EdDSA, `RpcV2TestCDIPriv`, and a
ready-made `NoOpRetrieveRpcArtifacts` stub. `RpcInfoV3` is already constructed with a real
`supported_num_of_keys_in_csr`, and each `Ta` is pinned to one `SecurityLevel` at construction.

Keyboxes carrying only an EC key — the shape an RKP-extracted keybox has — are already first-class
signing inputs. [`rust/teesim-km/src/attest.rs`](../rust/teesim-km/src/attest.rs) parses `<Key
algorithm="rsa|ecdsa">`, requires at least one key and at least two certificates, and its
`pick(prefer_ec)`/`batch()` helpers make every leaf EC-signed when the keybox carries only an EC
P-256 key, as a real RKP device does. The re-sign path lives in
[`resign.rs`](../rust/teesim-km/src/resign.rs).

The RKP AIDL is vendored under `third_party/interfaces/security/rkp/aidl/` but not compiled: the
top-level `CMakeLists.txt` globs only `keymint`, `secureclock` and `sharedsecret`. No typed IRPC
server exists natively.

[`common/control.h`](../common/control.h) is the per-security-level configuration push channel —
`TsBootInfo` and `TsProfile`, staged through `teesim_cfg_begin`/`add_profile`/`commit` and parsed by
`ApplyConfig` in [`common/control.cpp`](../common/control.cpp). Any RKP or DICE configuration field
has to extend that struct and parse layer.

### 7.2 The three cut points

The stub is `struct NoRpc` in [`rust/teesim-km/src/device.rs`](../rust/teesim-km/src/device.rs).
`derive_bytes_from_hbk` is real; `get_dice_info` and `sign_data` both return `Err(Unimplemented,
"remote provisioning is not supported")`. The doc comment states the intent: the interceptor never
routes `IRemotelyProvisionedComponent` calls there, so only the HBK derivation needs to work.

### 7.3 Deny, not serve

TEESimulator injects into `keystore2` and
[PLT-hooks](https://maskray.me/blog/2021-09-19-all-about-procedure-linkage-table)
`AIBinder_transact` in [`keymint/keymint_hook.cpp`](../keymint/keymint_hook.cpp), gating on
`IsHandled(code) && IsKeyMintProxy(binder)` with a descriptor-only match against
`IKeyMintDevice::descriptor`, and breaking recursion with a thread-local forwarding flag. Besides
redirecting KeyMint to the in-process TA, it denies the RKP lookup for target applications:

- `IsRkpProvisioning(binder)` matches the descriptor `android.security.rkp.IRemoteProvisioning` —
`keystore2`'s own outbound call to `rkpd`, made on the application's [binder
thread](https://source.android.com/docs/core/architecture/hidl/binder-ipc), so `getCallingUid` is
the application's uid.
- `teesim_is_target_uid(uid)` scopes the effect to target applications only.
- `GetRegIsStrongBox` reads the `irpcName` argument (`"strongbox"` versus `"default"`) by splicing a
throwaway prepared parcel, so no wire format is hardcoded; `ReadRkpOnly` then consults
`remote_provisioning.{tee,strongbox}.rkp_only`.

The branch is forced by §5.4. Not rkp-only: deny `getRegistration`, `keystore2` falls back to "no
attest key", appends nothing, and the TA's keybox-rooted chain survives intact. rkp-only: do not
deny, because denial would make `generateKey` return an error; the log records `RKP: NOT denying …`.

The three ground-truth properties are dumped once at install by `LogRkpPolicySnapshot()`, and they
are only read, never written. Flipping a device-wide `rkp_only` or `enable_rkpd` would itself be a
conspicuous detection point; the rationale is in [`keymint/README.md`](../keymint/README.md).

The `ATTEST_KEY` hole is closed separately: creating an `ATTEST_KEY` is always minted in the TA, so
the simulator holds the private key and can patch the [root of
trust](https://source.android.com/docs/security/features/verifiedboot/verified-boot) on every leaf,
and a startup purge (`ReAttest.purgeTargetAttestKeys` → `KeystoreDb.deleteTargetAttestKeys`) deletes
pre-existing foreign, Google- or RKP-rooted attest keys, restarting `keystore2` to evict its
in-memory cache when a raw database delete was needed.

The WebUI surfaces `remote_provisioning.tee.rkp_only`, `remote_provisioning.strongbox.rkp_only` and
`persist.device_config.remote_key_provisioning_native.enable_rkpd` as a user-driven escape hatch.
*⚠︎ver* Nothing in the codebase intercepts or emulates `rkpd` itself.

### 7.4 Seams, ranked

1. *Deny at `keystore2`'s outbound `getRegistration`* — the current approach. Least invasive, one
readable string, per-uid and per-level. Its one limit is that an rkp-only level has no fallback,
which is why `ATTEST_KEY` is always minted in the TA.
2. *Intercept the returned `RemotelyProvisionedKey`* — substitute a keybox-rooted
`AttestationKey{keyBlob, issuerSubjectName}` whose blob the TA actually holds: mint a TA attest key
and hand its blob plus a keybox leaf back as the "pooled" key. This covers rkp-only regular-key
attestation without any fallback, and it is the natural next step.
3. *Hook the IRPC HAL* — pointless for defeating attestation, since it only shapes the CSR sent to
Google, and risky, since it perturbs real provisioning for every application. Relevant only to
simulate a device end to end for the backend, which §1.5 puts out of scope.
4. *Hook `rkpd`* — requires injecting into the APEX-packaged `com.android.rkpdapp`, far more
fragile.
5. *Rewrite `CERT_CHAIN` rows* — what `ReAttest` already does for pre-existing keys, idempotently,
writing the same `CERT` + `CERT_CHAIN` split `keystore2` uses. A repair pass, not an interception: it
cannot fix a chain the application already read off the reply.

### 7.5 The gap list for a self-rooted serving implementation

*P1.* Replace `device::NoRpc` with a DICE-backed `RetrieveRpcArtifacts`: implement `get_dice_info`
to return a synthesised `PubDiceArtifacts` plus a `CsrSigningAlgorithm`, and `sign_data` to sign with
the modelled CDI-leaf key in COSE `r‖s` form. This is where a simulated DICE chain is minted, with no
hardware secret involved.

*P1.* Add a CBOR/COSE DICE-chain and `UdsCerts` builder. None exists; the reference expects these
bytes ready-made. Build per §4.4 from configuration.

*P2.* Plumb the DICE identity through configuration end to end: new fields in
`TsBootInfo`/`TsProfile`, through `ApplyConfig` into `TaConfig`, pushed by `Resolver.kt` and
`App.resolveAndPush`, carrying a modelled `UDS_pub`, a DICE profile name and a signing algorithm.

*P2.* Route IRPC transactions into the TA, as an alternative to denial and mutually exclusive with it
per level: compile the vendored `android.hardware.security.rkp` AIDL, add a local
`BnRemotelyProvisionedComponent` in `keymint/keymint_router.cpp`, add a descriptor match in
`keymint_hook.cpp`, and translate the three methods into `kmr_wire` requests — `teesim_km.h` exposes
no RPC entry point today.

*P2.* Decide per level whether to serve or deny, and reconcile that with the `rkp_only` gating.

*P3.* Optionally replace the passive property view in the WebUI with a "simulate RKP/DICE" profile
toggle.

For `keystore1` there is nothing to do: Android 10 and 11 predate RKP (§7.6).

### 7.6 keystore1

[`keystore/binder_interceptor.cpp`](../keystore/binder_interceptor.cpp) PLT-hooks
[`ioctl`](https://man7.org/linux/man-pages/man2/ioctl.2.html) on `libbinder`, watches for
`BR_TRANSACTION`, and rewrites the target to a local `BBinder` stub;
[`keystore/keystore_router.cpp`](../keystore/keystore_router.cpp) selects between release-specific
ordinal tables for Android 10 and 11, because `IKeystoreService` shifted ordinals when `reset()` was
removed and `finish()` grew. `teesim_cfg_resign` always returns false for this hook. Attestation
there uses factory batch keys only.

---

## 8. Limitations

### 8.1 Version-dependent claims to re-verify

Against the target `android-*` branch, and against
[`cs.android.com`](https://cs.android.com/android/platform/superproject/main) rather than the GitHub
mirror: the DICE Profile Name value and the exact `DiceChainEntryPayload` and
`ConfigurationDescriptor` key sets; the `DeviceInfo` field set and optionality, including the
mandatory-for-TEE `os_version` rule; the `supportedNumKeysInCsr` minimum and the `supportedEekCurve`
VTS behaviour of §2.3; the open-dice crypto profile and the un-padded-digest deviation;
degenerate-chain acceptance and the three deployment phases; the server response framing and
endpoint set, which are backend-defined; `UdsCerts` presence and format; the `keystore2`-internal
`IRemoteProvisioning` and `IRegistration` descriptors and the `remote_provisioning.*` and
`remote_key_provisioning_native` property semantics; the two Google roots and the RKP-exclusivity
dates; and the provisioning-information extension, where only two tags are documented, the map is
explicitly unversioned, and the tags observed in the field are undocumented and may change without
notice.

### 8.2 The one unimplemented check

[`app/.../KeyboxInspector.kt`](../app/src/main/java/org/matrix/teesim/KeyboxInspector.kt) verifies
each certificate against its parent, classifies the root via
[`RootPublicKey.kt`](../app/src/main/java/org/matrix/teesim/RootPublicKey.kt), and checks revocation
through [`RevocationList.kt`](../app/src/main/java/org/matrix/teesim/RevocationList.kt). It decodes
no provisioning extension: `1.3.6.1.4.1.11129.2.1.17` is the only Google OID the tree handles. So
the WebUI shows chain validity, expiry and revocation, and shows nothing about provisioning status
or issuance count — the two fields that, per [`4-measurements.md`](4-measurements.md) §3 and
[`2-mechanisms.md`](2-mechanisms.md) §9, discriminate a sound keybox from a worthless one and are
visible to any relying party.

The decode is already prototyped off-device in
[`tools/teesim_attest/provisioning.py`](tools/teesim_attest/provisioning.py), which preserves unknown
fields, gates on status, and compares the issuance count against the measured stock baseline.
Porting it into `KeyboxInspector` is transcription rather than design, because the inspector already
does the hard parts. It is not undertaken here.

Alongside it, the bare `expired` boolean at
[`app/.../KeyAdmin.kt`](../app/src/main/java/org/matrix/teesim/KeyAdmin.kt) should become
days-remaining on every certificate in the chain. That boolean was adequate only while keyboxes
lasted years; leaf lifetime is now a class discriminator, about two weeks for RKP against about ten
years for a factory batch key ([`4-measurements.md`](4-measurements.md) §2.1).

### 8.3 Where the platform is heading, and one claim graded refuted

A verifier that hard-codes two roots will break again.

*Root rotation.* P-384 signing began at a cutover Google publishes; the exclusive-use point for
RKP-enabled devices, roughly ten weeks later, is reported by a third party rather than by Google
(§5.4, and [`3-detection.md`](3-detection.md) §2.1). Check both against current documentation rather
than against this text, because a verifier that misses the second rejects every RKP chain. Legacy
devices keep the RSA root indefinitely, so build the trust store as configuration, supporting more
than two roots and more than one signature algorithm.

*Post-quantum, Android 17.* Native ML-DSA-65 and ML-DSA-87 in the keystore through the standard
key-pair generator API, with key material isolated in secure hardware; ML-DSA in [Verified
Boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot)'s signature
checks; and a stated transition of remote attestation to post-quantum compliance *"by updating
KeyMint's certificate chains to support quantum-resistant algorithms"*. The attestation schema
already documents a version 500 key description whose authorisation list adds an ML-DSA variant
field, so a third attestation-root generation is coming.

*Virtual-machine provisioning*, per §5.7, extends the model to workloads outside KeyMint and creates
a second isolation boundary with a distinct exploit population.

*Trusted HALs for secure-environment clients.* A device-state interface lets a KeyMint instance
running in a VM ask whether the device is in its manufacturing phase, explicitly *"a guardrail,
ensuring that sensitive Device ID data is only provisioned to the secure environment while the
device is at the factory"*; alongside it, interfaces for hardware-bound crypto keys, secure storage,
and a protocol for authenticating clients before granting access. *⚠︎ver:* on `main` the tree
carries only the storage, crypto, HDCP and authentication-manager interfaces; the device-state one
appears on release branches. The direction is to narrow what the secure environment will accept and
from whom, not to strengthen anything cryptographically.

*Delivery is itself a mitigation.* RKP became an updatable module in Android 14, so provisioning
policy can change without a vendor OTA, which is why the factory-key sunset can move faster than the
Android version curve suggests.

*One claim graded refuted.* Google's own sources disagree about when RKP became mandatory. The
developer documentation says devices launching with Android 16 support only RKP, *"expanding on the
Android 15 policy where RKP support was optional"*; the platform documentation's RKP page says
*"Android 15 requires all devices to implement it"*; and the Compatibility Definition Document,
verbatim in both the Android 15 and Android 16 editions, still permits factory batch keys —
*"Alternatively, the Remote Key Provisioning solution may be used to provision short-lived
attestation keys to the device."* So "Android 15 requires all devices to implement RKP" is refuted as
a normative statement and is not used in this series.

The defensible timeline: RKP in AOSP from Android 12, optional; mandated for devices launching with
Android 13; devices launching with Android 16 support only RKP; and the Compatibility Definition
Document through Android 16 still describing factory batch keys as a permitted alternative. This is a
launch-version rule, not an upgrade rule: a device that shipped on Android 11 and was updated keeps
its factory keybox, which is why the leaked-keybox population does not shrink along the Android
version curve ([`4-measurements.md`](4-measurements.md) §4.1 measures that population).

---

## 9. References

The series' single reference list. Companion documents cite it rather than repeating it.

### Normative — AOSP, verified against `refs/heads/main`

*RKP HAL.*
[`IRemotelyProvisionedComponent.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl)
·
[`RpcHardwareInfo.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/RpcHardwareInfo.aidl)
·
[`MacedPublicKey.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/MacedPublicKey.cddl)
·
[`PublicKey.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/PublicKey.cddl)
·
[`DeviceInfoV3.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV3.cddl)
·
[`generateCertificateRequestV2.cddl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl)
·
[`ProtectedData.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/ProtectedData.aidl)
·
[`security/rkp/README.md`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/README.md)

*rkpd.*
[`ServerInterface.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/interfaces/ServerInterface.java)
·
[`SystemInterface.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/interfaces/SystemInterface.java)
·
[`RegistrationBinder.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RegistrationBinder.java)
·
[`PeriodicProvisioner.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/provisioner/PeriodicProvisioner.java)
·
[`CborUtils.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java)
·
[`Settings.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java)
·
[`RkpdException.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RkpdException.java)

*keystore2.*
[`remote_provisioning.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/remote_provisioning.rs)
·
[`attestation_key_utils.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/attestation_key_utils.rs)
·
[`rkpd_client.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/rkpd_client.rs)

*DICE and encoding.* [`open-dice`
specification](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md) ·
[`src/dice.c`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c) · [Android
DICE
profile](https://android.googlesource.com/platform/external/open-dice/+/refs/heads/main/docs/android.md)
·
[`system/libcppbor`](https://cs.android.com/android/platform/superproject/main/+/main:system/libcppbor)

### Normative — Google documentation

[Remote key
provisioning](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning) ·
[Key attestation](https://source.android.com/docs/security/features/keystore/attestation), including
the [provisioning-information extension
schema](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension),
the only published CDDL for OID `1.3.6.1.4.1.11129.2.1.30` ·
[DICE](https://source.android.com/docs/security/features/dice) · Verified Boot · [Leaf revocation
status](https://android.googleapis.com/attestation/status) ·
[`key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl)

### Standards

[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and [RFC
9053](https://www.rfc-editor.org/rfc/rfc9053) (COSE structures and algorithms) · [RFC
8392](https://www.rfc-editor.org/rfc/rfc8392) (CWT) · [RFC 8949
§4.2](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) (deterministic CBOR) · [RFC
8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519) · [NIST SP
800-108r1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) ([counter-mode
KDF](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final)s) ·
[GlobalPlatform](https://globalplatform.org/specs-library/tee-internal-core-api-specification/) TEE
Internal Core API v1.3.1 and TEE Client API v1.0

### Field reports and tooling appraised in this series

[kanxue thread 293244](https://bbs.kanxue.com/thread-293244.htm) — the Qualcomm signing oracle ·
[kanxue thread 293246](https://bbs.kanxue.com/thread-293246.htm) — the three-device retrospective ·
[`gungnir-sanye/tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction)
— the engineering corpus behind the retrospective ·
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox) — an independent normal-world
RKP client, CSR builder and verifier, used here as a protocol oracle ·
[`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw) — the readable Python
implementation of the same pipeline. Each is appraised in [`5-sources.md`](5-sources.md) §3.

### Academic

[TÄMU](https://arxiv.org/abs/2601.20507) — Mao, Shi, Busch and Payer, emulating trusted applications
at the GlobalPlatform API layer, with [tooling](https://github.com/HexHive/taemu) ·
[FIASCO](https://nebelwelt.net/blog/2025/1227-fiasco.html) — HexHive at 39C3, with
[slides](https://hexhive.epfl.ch/publications/files/25CCC-presentation.pdf) and
[tooling](https://github.com/HexHive/beanpod_fiasco) · *Spill the TeA* and *GlobalConfusion*, USENIX
Security · [Quarkslab on bypassing Android hardware
attestation](https://blog.quarkslab.com/bypassing-android-hardware-attestation.html), with a
[demo](https://github.com/quarkslab/android-hardware-attestation-demo)

### Companion documents

[`2-mechanisms.md`](2-mechanisms.md) · [`3-detection.md`](3-detection.md) ·
[`4-measurements.md`](4-measurements.md) · [`5-sources.md`](5-sources.md) ·
[`tools/README.md`](tools/README.md)
