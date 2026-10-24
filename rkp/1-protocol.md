# 1. The Remote Key Provisioning protocol and its trust model

Index: [the index](README.md). Companion parts: [part 2](2-mechanisms.md), [part 3](3-detection.md),
[part 4](4-measurements.md), [part 5](5-sources.md).

## Abstract

Remote Key Provisioning (RKP) replaced Android's factory-provisioned batch attestation keys with
short-lived per-device certificates issued by a Google backend over the lifetime of the device. The
trust anchor moved from a key burned into a production run to a registration event: the backend
signs for a device only if the root of that device's [Device Identifier Composition
Engine](https://source.android.com/docs/security/features/dice) (DICE) chain is a public key that a
manufacturer enrolled on a vetted factory line. This part reconstructs the device-side protocol as
[AOSP](https://source.android.com/) defines it — three interleaved version axes, the canonical
[CBOR](https://www.rfc-editor.org/rfc/rfc8949) and [COSE](https://www.rfc-editor.org/rfc/rfc9052)
rules that determine byte equality, the `AuthenticatedRequest<CsrPayload>` envelope, and the DICE
chain with its [CBOR Web Token](https://www.rfc-editor.org/rfc/rfc8392) entries — and then analyses
the trust relation the protocol establishes. The result bounds what a simulator can achieve: every
structural property of the exchange is reproducible, and none of them is decisive, because
acceptance is membership in a set the verifier fixed before it saw the message. Two independent
anchors enforce that membership, a registered [Unique Device
Secret](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md) at
provisioning time and a pinned Google root at consumption time, and either defeats a self-rooted
chain alone. One correction to the prior record is reported: the layer-identifier derivation in
[open-dice](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c) masks the high
bit of its first output byte, an operation absent from the formula this report previously carried,
whose omission breaks chain linkage while presenting as a signature fault.

---

## 1. Introduction

### 1.1 Factory provisioning and its limitations

Before Android 12 a device attested with a *batch key*: an RSA and an EC private key, with
Google-rooted certificate chains, injected on the production line and shared across a manufacturing
batch. Three properties of that design became untenable at scale.

The key is long-lived. Chains measured from leaked factory keyboxes carry ten-year leaves ([part 4
§2.1](4-measurements.md#21-leaf-validity-by-material-class)). It is shared, so a single extraction
compromises every handset in the batch. And it is unrevocable in practice, because revoking the
batch disables attestation for every device that shipped with it; the public revocation list is
dominated by exactly that event, with 56 per cent of its entries traceable to one scraped corpus of
551 factory keyboxes ([part 4 §4.3](4-measurements.md#43-derived-quantities)).

RKP addresses all three. Keys are per-device, minted on demand, and valid for roughly two weeks; the
long-term secret never leaves the chip; and revocation is a registry edit at the backend rather than
a certificate-list entry. The cost is a new dependency: on every request the device must prove that
it is a device some manufacturer enrolled.

### 1.2 Two anchors of trust

The *provisioning anchor* binds device to backend. The RKP server signs keys only for a device whose
DICE chain terminates in a `UDS_pub` that a manufacturer registered out of band, at the factory,
before the device shipped. The failure mode is HTTP 444,
[`DEVICE_NOT_REGISTERED`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RkpdException.java).

The *consumption anchor* binds key to relying party. Applications and [Play
Integrity](https://developer.android.com/google/play/integrity) verify an attestation chain that
must terminate at a Google attestation root pinned in advance.

Trust in this protocol is therefore membership in a set the verifier decided upon beforehand, and
not a property that can be manufactured inside the artifact. Section
[§6](#6-analysis-of-the-trust-relation) develops the consequences.

### 1.3 Scope and conventions

*Secret extraction is out of scope as a procedure.* The simulator manufactures its own keys and
never requires a real one. This report reconstructs mechanisms, formats and acceptance relations so
that the simulation is faithful and the detection advice correct. It cites digests, symbol names,
offsets and extents as evidence that a mechanism exists, and reproduces no private key material,
including where a cited source recovered and published it. Instruction bytes and command numbers
appear where they identify a defect class and are withheld where they constitute the operative
content of a route rather than evidence of one. Seeds are discussed by digest fingerprint only.

*Claims are attributed where they are made.* A measurement states what was measured and gives the
command that reproduces it ([part 4 §5](4-measurements.md#5-reproduction)). A claim that rests on a
third-party account not reproduced here says so at the point of use, and [part 5
§3](5-sources.md#3-appraisal) appraises how much weight each such account carries. No claim gains
strength by being repeated in another part. Where a later measurement overturns earlier text, the
earlier reading is recorded as withdrawn rather than deleted; [part 4
§3.4](4-measurements.md#34-corrections-to-earlier-readings) and [part 5
§5.4](5-sources.md#54-corrections-of-record) are those lists.

*Version dependence.* AOSP is a moving target. Claims about field sets, acceptance behaviour and
property semantics are version-dependent, and [§8.1](#81-version-dependent-claims) collects them.
They must be re-checked against [Android Code
Search](https://cs.android.com/android/platform/superproject/main) or
[Gitiles](https://android.googlesource.com/) raw output for the exact `android-*` branch being
emulated, and not against the GitHub mirror, which lags and rewrites paths.

---

## 2. The remotely provisioned component interface

### 2.1 Three version axes

Three distinct version numbers travel together, and none of them determines the others. This is the
largest single source of byte mismatch between an implementation and a real device.

| HAL `RpcHardwareInfo.versionNumber` | Android | CSR method | `AuthenticatedRequest` version | `CsrPayload` version | `DeviceInfo` internal version | EEK and test mode |
|---|---|---|---|---|---|---|
| v1 | 12 (S) | `generateCertificateRequest` | — (`ProtectedData`) | — | 1 | required |
| v2 | 13 (T) | `generateCertificateRequest` | — | — | 2 | required |
| v3 | 14 (U) onward | `generateCertificateRequestV2` | 1 | 3 | removed | absent |

In version 3 the certificate-signing request carries `AuthenticatedRequest` schema version 1 and
`CsrPayload` schema version 3, while `DeviceInfo` carries no version key at all.
`RpcHardwareInfo.versionNumber == 3` is the switch that directs the provisioning daemon to call
`generateCertificateRequestV2` and to skip everything related to the endpoint encryption key; the
guard reads `if (getVersion() < 3)`. The field set is version-dependent
([§8.1](#81-version-dependent-claims)).

### 2.2 The AIDL surface

The component is declared in Android's [interface definition
language](https://source.android.com/docs/core/architecture/aidl) as
[`IRemotelyProvisionedComponent.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl),
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

The three return values differ in kind and are readily transposed. `generateEcdsaP256KeyPair`
returns an opaque wrapped private key and delivers the public half through the output parameter.
`generateCertificateRequest` returns only `keysToSignMac`, the
[COSE_Mac0](https://www.rfc-editor.org/rfc/rfc9052#section-6) tag over the key array, with the
remainder of the request split across `deviceInfo` and `protectedData`.
`generateCertificateRequestV2` returns the entire request as one canonically encoded byte string.

Errors arrive as `ServiceSpecificException` with codes `STATUS_FAILED=1`, `STATUS_INVALID_MAC=2`,
`STATUS_PRODUCTION_KEY_IN_TEST_REQUEST=3`, `STATUS_TEST_KEY_IN_PRODUCTION_REQUEST=4`,
`STATUS_INVALID_EEK=5` and `STATUS_REMOVED=6`. Codes 3 and 4 encode the rule, specific to the
endpoint-encryption era, that one request may not mix production keys with a test `MacedPublicKey`,
the latter marked by the presence of [COSE_Key](https://www.rfc-editor.org/rfc/rfc9052#section-7)
label `-70000` and authenticated under a 32-byte all-zero key.

Three parcelables are CBOR carriers rather than structured types: `MacedPublicKey{byte[] macedKey}`
is a COSE_Mac0, `DeviceInfo{byte[] deviceInfo}` a [canonical
CBOR](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) map, and `ProtectedData{byte[]
protectedData}` a [COSE_Encrypt](https://www.rfc-editor.org/rfc/rfc9052#section-5) structure that
exists only in versions 1 and 2.

### 2.3 Hardware information

From
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

A version-3 implementation reports `versionNumber=3`, `supportedNumKeysInCsr` of at least 20, and a
stable coarse `uniqueId` naming a system-on-chip class rather than an individual device. The
`supportedEekCurve` field requires a qualification the prior record omitted: `CURVE_NONE` is
semantically correct for version 3, since no endpoint encryption key exists, but the [vendor test
suite](https://source.android.com/docs/core/tests/vts) has been observed to fail an implementation
that reports it. Model the value the target branch's test suite accepts, and treat any unqualified
recommendation as version-dependent.

### 2.4 Key generation and the authenticated public key

Every provisionable leaf key is
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) with ES256,
irrespective of the curve used by the DICE chain. The public half is returned as a COSE_Mac0 so that
the component can later establish, inside the request method, that a key it is asked to certify is
one it generated. From
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

The authentication tag is `HMAC-SHA256(K_mac, MAC_structure)` with context `"MAC0"` and protected
header `{1: 5}`.

`K_mac` is a contract rather than a construction. Only two rules are observable: the key that
produced a `MacedPublicKey` must verify it inside the request method, and a test key uses 32 zero
bytes. In version 3 `K_mac` never leaves the device, so an implementation may use any stable 32-byte
[HMAC](https://www.rfc-editor.org/rfc/rfc2104) key. TEESimulator derives one through
`derive_bytes_from_hbk` over the fixed label `b"teesim-rpc-hbk"` in
[`rust/teesim-km/src/device.rs`](../rust/teesim-km/src/device.rs).

The same freedom has a consequence on the attacking side, which [part 2
§7.1](2-mechanisms.md#71-the-procedure-gate-by-gate) develops as a step of the minting procedure:
because the trusted application strips the tag before assembling the request, the backend receives
no evidence that a submitted key was ever generated inside a trusted application. The tag is a
device-internal check, and an implementation that omits it has no second line of defence.

### 2.5 The version-3 certificate request

From
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

The payload is wrapped twice: `CsrPayload` is canonically encoded and then embedded as a `bstr
.cbor` inside the signed array. The challenge appears exactly once, beside that embedded payload,
and not once per key.

The signature is a [COSE_Sign1](https://www.rfc-editor.org/rfc/rfc9052#section-4) over an [RFC 9052
§4.4](https://www.rfc-editor.org/rfc/rfc9052#section-4.4) `Sig_structure`, which is the most
frequent byte-faithfulness error in the protocol:

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

What is signed is the `Sig_structure`, not the payload: construct `["Signature1", protected_bstr,
h'', payload_bstr]`, encode it canonically, then sign. The protected bytes must be byte-identical in
the COSE_Sign1 and in the `Sig_structure`, so they should be encoded once and the bytes reused; two
canonical encoders can agree on a value and still disagree on a header that nobody re-checks.

In the vendored reference application, `generate_cert_req_v2` in
[`third_party/keymint/ta/src/rkp.rs`](../third_party/keymint/ta/src/rkp.rs) produces this structure
and `generate_cert_req` the version-1 and version-2 one.

### 2.6 Device self-description

From
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

The five identity strings map to `ro.product.*`. Versions 1 and 2 marked most of them optional;
version 3 makes them mandatory and drops both the internal version key and the older
`"att_id_state"`. The apparent contradiction around `os_version` resolves as a division between
grammar and policy: the [CDDL](https://www.rfc-editor.org/rfc/rfc8610) marks it optional while a HAL
and backend rule requires it when `security_level` is `"tee"`, so it should be modelled as present.
The field set is version-dependent ([§8.1](#81-version-dependent-claims)).

The `security_level` field is where a per-level trusted-application design becomes visible on the
wire: an implementation emits the level of the instance producing the request. The backend compares
`DeviceInfo` across a device's requests for consistency, so whatever is emitted must be stable per
device.

Two properties of this map are established empirically rather than from the specification, and both
bear more weight than its grammar. First, `vbmeta_digest` is mandatory and a genuine trusted
application cannot omit it, which makes an omission positive evidence that a request was not
produced by one ([part 4 §3.4](4-measurements.md#34-corrections-to-earlier-readings)). Second, the
build fingerprint is not in this map at all: the provisioning daemon appends it afterwards,
unsigned, as an `UnverifiedDeviceInfo` map in
[`CborUtils.buildUnverifiedDeviceInfo`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java).
Everything a relying party might read here as device identity is therefore either operator-authored
or appended outside the signature.

### 2.7 Certification of the device secret public key

```cddl
UdsCerts    = { * SignerName => UdsCertChain }   ; SignerName = tstr, the endorsing authority
UdsCertChain = [ + X509Certificate ]             ; DER, root -> ... -> leaf certifying UDS_Pub
```

This structure allows a vendor to attest that `UDS_Pub` belongs to a genuine part, the backend
mapping `SignerName` to an out-of-band root. It may legitimately be an empty map where the platform
provides no such certification, but a backend that expects vendor certification will reject an empty
one, so which is correct is a property of the target deployment. The reference field is `uds_certs`
in [`rkp.rs`](../third_party/keymint/ta/src/rkp.rs).

### 2.8 The version-1 and version-2 request

This structure is needed only in order to present as HAL version 1 or 2; in version 3 the legacy
method must throw `STATUS_REMOVED`.

`MacedKeys` is a COSE_Mac0 over `[ * PublicKey ]` whose tag is the method's return value, with
authentication input `["MAC0", {1:5}, h'', bstr .cbor [*PublicKey]]`. The endpoint-encryption chain
arriving in `endpointEncryptionCertChain` is a sequence of
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032) or P-256 COSE_Sign1 structures ending in an
endpoint encryption COSE_Key — `EekX25519` with curve 4, or `EekP256` — both at algorithm `-25`,
carrying a key identifier, validated against a root hardcoded in the component. `ProtectedData` is a
COSE_Encrypt at `{1: 3}` ([A128GCM](https://www.rfc-editor.org/rfc/rfc9053#section-4.1)) with the
initialisation vector in the unprotected header, recipient algorithm `{1: -25}`
([ECDH-ES](https://www.rfc-editor.org/rfc/rfc9053#section-6.2) with
[HKDF](https://www.rfc-editor.org/rfc/rfc5869)-256), and the content key derived by Diffie-Hellman
between an ephemeral sender key and the endpoint key.

The essential element of versions 1 and 2 is `SignedMac`: a COSE_Sign1 whose payload is `K_mac`
itself, signed by the DICE leaf and encrypted to the endpoint key inside `ProtectedData`, with
`SignedMacAad = [challenge, VerifiedDeviceInfo, tag: keysToSignMac]`. The server decrypts, recovers
`K_mac`, and only then verifies the `MacedKeys` tag.

Version 3 deletes that round trip entirely. Authenticity derives from the DICE signature over the
whole payload; `K_mac` remains on the device; `testMode` disappears from the request method; and
`ProtectedData` and the endpoint key vanish. For a version-3 implementation this section is
inapplicable, and, as [part 2 §7.3](2-mechanisms.md#73-components-the-procedure-does-not-need)
records, the presence of unused `ProtectedData` code in a tool is therefore not evidence that the
tool was never run: two independent implementations construct the structure and then discard it.

---

## 3. Deterministic encoding

Byte equality with a real device is determined here rather than by the structure definitions. Every
RKP structure must be [deterministically
encoded](https://www.rfc-editor.org/rfc/rfc8949#section-4.2), and the `canonicalize()` routine of
[`system/libcppbor`](https://cs.android.com/android/platform/superproject/main/+/main:system/libcppbor)
is the de facto reference.

### 3.1 Canonical CBOR

Definite-length encodings only; shortest-form integers and headers; map keys sorted by encoded key
bytes, per [RFC 8949 §4.2](https://www.rfc-editor.org/rfc/rfc8949#section-4.2).

The sorting rule is where general-purpose CBOR libraries diverge, and the divergence is silent. For
the small integer labels used by COSE, positive labels `0, 1, 2, …` encode as single bytes `0x00,
0x01, 0x02, …` while negative labels encode as `-1 → 0x20`, `-2 → 0x21`, and so on. Label `-1`
therefore sorts after label `3`, because `0x20 > 0x03`. Sorting labels by numeric value yields a
well-formed CBOR map that is not the map the device emits, and nothing downstream objects until a
signature fails.

For text-string keys, as in `DeviceInfo`, the same rule means that shorter keys sort before longer
ones and that ties break bytewise, which is not alphabetical order.

The notation `bstr .cbor X` means: encode `X` canonically, then wrap those bytes in a byte string.
The encode-once-and-reuse discipline of [§2.5](#25-the-version-3-certificate-request) applies to
every protected header shared between a COSE object and its signature or authentication structure.

### 3.2 COSE labels and algorithms

| Purpose | Algorithm | Value |
|---|---|---|
| [ECDSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) P-256 with [SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) | ES256 | `-7` |
| ECDSA P-384 with SHA-384 | ES384 | `-35` |
| Ed25519 | EdDSA | `-8` |
| HMAC-SHA-256 | HMAC 256/256 | `5` |
| ECDH-ES with HKDF-256 (v1/v2 endpoint key) | — | `-25` |
| AES-128-GCM (v1/v2 `ProtectedData`) | A128GCM | `3` |

Header labels are `1` algorithm, `2` critical, `3` content type, `4` key identifier, `5`
initialisation vector, `-1` ephemeral key. COSE_Key labels are `1` key type (`1` OKP, `2` EC2), `2`
key identifier, `3` algorithm, `-1` curve (`1` P-256, `2` P-384, `4`
[X25519](https://www.rfc-editor.org/rfc/rfc7748), `6` Ed25519), `-2` x, `-3` y. Definitions are in
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and [RFC
9053](https://www.rfc-editor.org/rfc/rfc9053).

### 3.3 Signature value encoding

ECDSA signatures in COSE take the fixed-width `r‖s` form, each coordinate left-zero-padded to the
curve size: 32 bytes for P-256, 48 for P-384. They are not
[ASN.1](https://www.itu.int/rec/T-REC-X.680) [DER](https://www.itu.int/rec/T-REC-X.690), which is
what general-purpose cryptographic libraries return by default. Ed25519 signatures are the raw
64-byte `R‖S` of [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032). This is the most frequently
reported cause of a chain that parses, links by name, and fails to verify.

---

## 4. The DICE key hierarchy

### 4.1 Construction

The device holds a hardware secret, the Unique Device Secret. Each boot stage measures the stage it
is about to launch, folds those measurements into a one-way [key-derivation
function](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) to produce a fresh [Compound Device
Identifier](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md)
(CDI) for that next stage, and emits a certificate binding the public keys of the two stages.
Chaining from the secret-derived root to the final stage yields the DICE chain, which Android calls
`Bcc` in RKP versions 1 and 2 and `DiceCertChain` in version 3. The leaf stage is the
[KeyMint](https://source.android.com/docs/security/features/keystore) and RKP component, and its
DICE private key signs the request of [§2.5](#25-the-version-3-certificate-request).

The chain establishes that a particular software stack, on a particular genuine device, is making
the request. It is not the chain an application sees at attestation time; those are separate
hierarchies that meet only inside Google's infrastructure
([§6.1](#61-validation-order-at-the-backend)).

### 4.2 The derivation

The normative reference is the [open-dice
specification](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md),
with the Android profile in
[`docs/android.md`](https://android.googlesource.com/platform/external/open-dice/+/refs/heads/main/docs/android.md)
and the implementation in
[`src/dice.c`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c).
Cryptographic defaults are [SHA-512](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf),
HKDF-SHA-512 and Ed25519, with P-256 and P-384 profiles also defined; `DICE_CDI_SIZE` is 32 and
`DICE_HASH_SIZE` is 64. The profile is version-dependent ([§8.1](#81-version-dependent-claims)).

The Unique Device Secret is fused at manufacture and latched: readable only by the first mutable
code, which is the DICE engine itself, and then hardware-locked before control passes on. No later
stage, the KeyMint leaf included, can read it. It is never transmitted; what leaves the device is
`UDS_pub`, called `DK_pub` in the `Bcc` grammar, the first element of the chain.

Each layer supplies five measurements of the stage about to launch, as `DiceInputValues`: a 64-byte
code hash; a configuration descriptor or value, from which a configuration hash is computed; a
64-byte authority hash over the verifying key or policy; a one-byte mode; and 64 bytes of hidden
input that appears in no certificate. Two identifiers are derived, and the division of inputs
between them is the essential design decision:

```
attest_input_hash = SHA-512( Code ‖ Config ‖ Authority ‖ Mode ‖ Hidden )   ; all five
seal_input_hash   = SHA-512( Authority ‖ Mode ‖ Hidden )                   ; the last three only

CDI_Attest' = HKDF-SHA512(IKM = CDI_Attest, salt = attest_input_hash, info = "CDI_Attest", L = 32)
CDI_Seal'   = HKDF-SHA512(IKM = CDI_Seal,   salt = seal_input_hash,   info = "CDI_Seal",   L = 32)
```

At stage 0 the input keying material is the device secret itself. `CDI_Attest` changes when the code
or configuration of any layer changes, so it is an identity of the exact running stack, and it backs
the certificate keys. `CDI_Seal` omits code and configuration and therefore survives firmware
updates from the same vendor, which is what allows sealed data to outlive an [over-the-air
update](https://source.android.com/docs/core/ota); it never appears in the chain.

The mode byte takes the values 0 for not configured, 1 for normal, 2 for debug and 3 for recovery. A
model of a locked production device uses 1 throughout.

### 4.3 Layer keys and identifiers

Each layer's key pair and its 20-byte identifier derive from fixed-salt HKDF over `CDI_Attest`:

```
seed = HKDF(IKM = CDI_Attest, salt = kAsymSalt, info = "Key Pair", L = DICE_PRIVATE_KEY_SEED_SIZE)
id   = HKDF(IKM = encoded_public_key, salt = kIdSalt, info = "ID", L = 20)
id[0] &= 0x7f                                      ; the step previously omitted
```

The masking line appears in
[`src/dice.c`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c): the first
output byte has its high bit cleared before the identifier is rendered as 40 lowercase hexadecimal
characters. The formula this report previously carried stopped at the HKDF call. An implementation
that omits the mask produces identifiers differing from a real device's in one bit for about half of
all public keys, which breaks the linking invariant below. The symptom is a chain whose entries each
verify in isolation but which no verifier will assemble, and it presents as a signature fault rather
than as the string mismatch it is.

The linking invariant is `Issuer(entry N) == Subject(entry N-1) == hex(ID(public key of layer
N-1))`. It allows a verifier to assemble the chain independently of ordering. One-wayness of HKDF
gives forward secrecy of the device secret, while determinism makes the chain a faithful fingerprint
of the boot: different software yields a different `CDI_Attest`, hence a different leaf key, hence a
different subject.

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

The version-1 and version-2 `Bcc` in
[`ProtectedData.aidl`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/ProtectedData.aidl)
has the same shape without the version-3 additions: no profile name, configuration hash optional
rather than mandatory, no P-384, and a configuration descriptor restricted to labels
`-70002/-70003/-70004`. The grammar `Bcc = [DK_pub, + BccEntry]` annotates its last entry `KM_pub`,
so the final entry's subject public key is the KeyMint component's own public key. The signature
structure is identical and merely renamed `BccEntryInput`.

Public keys appear in three forms, and coordinate endianness differs by curve:

```cddl
PubKeyEd25519  = { 1:1, 3:-8,  -1:6, -2:bstr }            ; OKP, Ed25519, X — LITTLE-endian (RFC 8032)
PubKeyECDSA256 = { 1:2, 3:-7,  -1:1, -2:bstr, -3:bstr }   ; EC2, P-256, X/Y — BIG-endian (SEC1)
PubKeyECDSA384 = { 1:2, 3:-35, -1:2, -2:bstr, -3:bstr }   ; EC2, P-384, X/Y — BIG-endian
```

Incorrect endianness yields a well-formed chain whose signatures do not verify.

One deviation in the sources reads like a contradiction. The Android DICE profile emits digests at
their actual hash length — 32 bytes for SHA-256, 48 for SHA-384, 64 for SHA-512 — departing
deliberately from the Open Profile for DICE, in which all digests are padded to 64. This does not
contradict `DICE_HASH_SIZE = 64` in `dice.c`, which is the engine's internal buffer size, and a
SHA-512 profile genuinely emits 64 bytes. The rule applies only where a stage measured with SHA-256
or SHA-384 must emit 32 or 48 bytes instead of a zero-padded 64-byte field. Emitted digests are not
to be zero-padded.

### 4.5 Legal chain shapes and deployment phases

For stage N the loop is: stage N-1, holding `CDI_Attest(N-1)` and key `K_{N-1}`, measures stage N,
derives `CDI_Attest(N)` and from it `K_N` and `Subject(N)`, sets `Issuer` to `ID(N-1)`, builds the
[CBOR Web Token](https://www.rfc-editor.org/rfc/rfc8392) carrying the public half of `K_N`, wraps it
in a COSE_Sign1 signed with `K_{N-1}`, appends it, hands the identifiers to stage N, and erases the
parent identifier. The private `K_leaf` is consequently the only DICE private key that any runtime
code still holds, and it is the key that signs the request.

Two shapes are protocol-legal. A *full multi-stage chain* carries one entry per boot stage: ROM,
bootloader, trusted execution environment, KeyMint. A *degenerate chain* is a single self-signed
entry in which `UDS_Pub` equals the subject public key; the one-or-more quantifier on
`DiceChainEntry` permits it, and it is the natural minimal shape for an implementation that mints
its own root.

These correspond to the deployment phases AOSP documents in
[`hardware/interfaces/security/rkp/README.md`](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/README.md):
phase 1, degenerate DICE with a root in the trusted execution environment and a single self-signed
certificate; phase 2, DICE proper with a hardware root per the Android profile; phase 3,
vendor-certified DICE, in which `UDS_Pub` is extracted and certified at the factory.

Phase 1 has an exact security consequence. On a phase-1 device the backend has no per-boot-stage
measurement to evaluate, so a compromise that yields use or extraction of that single key pair
yields the ability to authenticate arbitrary certificate requests as that device, and the backend
holds no firmware-hash signal with which to refuse.

AOSP detects the degenerate shape but does not uniformly refuse it. The helper `remote_prov_utils`
declares the error string `"DICE chain is degenerate"` and returns it from two call sites, and the
chain-comparison helper reports which instance carries one. The default-instance test in the vendor
test suite, however, skips on a degenerate chain — `GTEST_SKIP() << "Skipping test: Only a proper
DICE chain has a mode set."` — while the hard assertion applies to the
[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox) instance,
whose requirement additionally takes effect from vendor API level 202404. Degenerate chains are
therefore diagnosed, fatal for StrongBox, and tolerated for the default instance.

This is why the off-device minting procedure of [part 2
§7](2-mechanisms.md#7-off-device-certificate-minting) succeeds on a handset that declares no
StrongBox instance: a degenerate chain constructed around one stolen seed is a conforming request
rather than a malformed one. It is also the deployment that the public minting tool targets, its own
documentation describing a degenerate chain in which the device secret equals the leaf, self-signed.
That tool is not a general break of RKP but a break of RKP on phase-1 deployments, conditional on
possession of a leaf seed.

### 4.6 Construction of a synthetic chain

Generate a random device secret; for each layer either derive `K_i` by the recipe of
[§4.2](#42-the-derivation) over that secret, which yields stable subjects across runs, or generate
`K_i` at random, which is simpler and still structurally valid. Populate the measurements with
plausible constants — `codeHash = SHA(componentName ‖ version)`, `authorityHash =
SHA("vendor-verified-boot-key")`, `mode = 1`, `keyUsage = 0x20` — sign each entry with `K_{i-1}`,
let the subject public key of the leaf be the key the emulated KeyMint uses for provisioning, and
serialise canonically per [§3.1](#31-canonical-cbor). Keep `UdsCerts` self-rooted or empty: a
certification chain reaching a real manufacturer root is the one element genuinely out of reach,
since the backend pins real vendor authorities.

---

## 5. The provisioning path on the device

### 5.1 The provisioning daemon

Despite its name, `rkpd` is not a native daemon. Across releases it is an application process bound
on demand together with a system-server
[binder](https://source.android.com/docs/core/architecture/hidl/binder-ipc) shim. On Android 12 it
is the `RemoteProvisioner` application, package `com.android.remoteprovisioner`, scheduling a
`JobService`. From Android 13 onward it is
[`rkpdapp`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/),
package `com.android.rkpdapp`, shipped inside the `com.android.rkpd`
[APEX](https://source.android.com/docs/core/ota/apex), with `PeriodicProvisioner` implemented as an
`androidx.work.Worker`. Android 11 and earlier have no provisioning path at all, which makes its
presence a discriminator between the `keystore2` and `keystore1` code paths.

### 5.2 The protocol exchange

1. [`SystemInterface.generateEcdsaP256KeyPair()`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/interfaces/SystemInterface.java)
   yields a key-blob and authenticated-public-key pair, banked in the daemon's [Room
   database](https://developer.android.com/training/data-storage/room).
2. [`ServerInterface.fetchGeek()`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/interfaces/ServerInterface.java)
   posts to `:fetchEekChain`, returning a challenge, `numExtraAttestationKeys`, and rollout
   configuration. The endpoint-key chain itself belongs to versions 1 and 2 only; the endpoint name
   is legacy and reused, and version 3 is a schema version rather than a path component. The
   response framing is backend-defined and version-dependent ([§8.1](#81-version-dependent-claims)).
3. `generateCertificateRequestV2(keysToSign, challenge)` produces the CBOR request.
4. `requestSignedCertificates(csr)` posts to `:signCertificates?challenge=…&request_id=…`.
5. The backend validates ([§6.1](#61-validation-order-at-the-backend)), signs, and returns per-key
   DER chains.
   [`CborUtils.parseSignedCertificates()`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/CborUtils.java)
   decomposes the response into a shared portion, comprising root and intermediates, and a unique
   leaf per key, concatenating leaf and shared portion. Nothing in the response is secret; it is
   public certificates.
6. The daemon banks key-blob and certificate-chain pairs keyed by component name, client identifier
   and key identifier, with sticky assignment, so that an application's attestation identity remains
   stable.

Two trigger paths have distinct timing signatures, which matters to anything attempting to observe
provisioning. Ahead-of-time top-up runs in `PeriodicProvisioner` under the
[WorkManager](https://developer.android.com/topic/libraries/architecture/workmanager) unique work
name `"ProvisioningJob"`, targeting roughly six extra keys valid at least three days out. Lazy
inline provisioning occurs on a pool miss in `getKey` and performs a network round trip on the
calling thread.

A server-side kill switch exists: `numExtraAttestationKeys == 0` disables provisioning and triggers
`mKeyDao.deleteAllKeys()`.

Retry behaviour is region-aware. The connect timeout is selected from `gsm.operator.iso-country`,
with `SYNC_CONNECT_TIMEOUT_RESTRICTED_MS = 400` against `_OPEN_MS = 1000`; backoff starts at
`BACKOFF_TIME_MS = 100` and doubles, but only while the error is an `RkpdException` and only within
`max_request_time`, approximately 20,000 ms. Hard faults — socket timeouts and input-output
exceptions — are not retried. An error budget comprising `failure_counter`, `failure_start_time` and
`failure_data`, capped at one mebibyte, together with a bad-certificate window, acts as a circuit
breaker. The error taxonomy comprises `DEVICE_NOT_REGISTERED`, meaning that the DICE root is unknown
to the backend, plus `HTTP_CLIENT_ERROR` and `HTTP_SERVER_ERROR`. The tunables are in
[`Settings.java`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java).

`ServerInterface.requestData()` sets no HTTP headers at all: no API key, no `X-Goog-*` header, no
client certificate, no transport pinning and no network security configuration. The endpoints are
`remoteprovisioning.googleapis.com/v1:fetchEekChain` and `/v1:signCertificates`. The only
authentication in the exchange is the DICE signature inside the request body, which is what makes
the off-device minting of [part 2 §7](2-mechanisms.md#7-off-device-certificate-minting) a
client-side exercise rather than a network attack.

### 5.3 Consumption in keystore2

[`RegistrationBinder`](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/RegistrationBinder.java)
implements `android.security.rkp.IRegistration` with `getKey(keyId, cb)`, `cancelGetKey(cb)` and
`storeUpgradedKeyAsync(old, new, cb)`. The `getKey` method evicts stale keys, looks in the pool by
component name, client identifier and key identifier, provisions inline on a miss, and marshals a
`RemotelyProvisionedKey{ byte[] keyBlob; byte[] encodedCertChain; }`. The `storeUpgradedKeyAsync`
method rewrites a pool row across a KeyMint `upgradeKey` without re-provisioning.

On the consumer side, in
[`remote_provisioning.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/remote_provisioning.rs)
and
[`attestation_key_utils.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/attestation_key_utils.rs):
when an application requests attestation, meaning that a challenge is present, no attestation-key
descriptor was supplied and the key is not device-unique, `get_attest_key_info` calls
[`rkpd_client::get_rkpd_attestation_key`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/rkpd_client.rs),
which reaches `IRemoteProvisioning.getRegistration(irpcName)` and then `IRegistration.getKey`.

The pooled key is the issuer rather than the attested key. KeyMint mints the application's key and
signs its leaf using the pooled blob as the attestation key; `keystore2` prepends the provisioned
certificate chain, so the application reads a chain from its own leaf through the provisioned key to
a Google root directly off the `generateKey` reply. The result is stored split as `CERT`, the leaf,
and `CERT_CHAIN`, the remainder, in `/data/misc/keystore/persistent.sqlite`.

### 5.4 The rkp_only branch and the two Google roots

The most consequential behavioural fork is `is_rkp_only()`, which reads
`remote_provisioning.<tee|strongbox>.rkp_only`. With the property off, a failed provisioning lookup
falls back to the factory batch key, recorded by the metric `FALL_BACK_DURING_HYBRID`. With it on,
failure is fatal and `generateKey` fails outright rather than produce an unattested key. Any
interception strategy must branch on this, for the reason
[§7.3](#73-denial-of-the-provisioning-lookup) gives. The source comment states the rationale:
depending on the release, provisioning may not have been mandatory for either instance, so a lookup
failure is working as intended and should permit fallback to the factory key.

This corrects a widely repeated account. The claim that the hybrid path is being closed by updating
the provisioning module to return key-not-found cannot operate as described: the fallback decision
resides in `keystore2`, which is platform code keyed on a vendor-set property, and any error from
the daemon triggers it while `rkp_only` is false. The existence of hybrid devices is established;
the enforcement account is not, and could not be confirmed from any source read for this report.

Two pool-policy details are easy to invert. The value `GeekResponse.NO_EXTRA_KEY_UPDATE`, which is
−1, does not indicate that the backend is suppressing pool growth; it is the sentinel for a response
that carried no value, leaving the setting unchanged. A backend suppressing growth sends
`num_extra_attestation_keys = 0`, the kill switch of [§5.2](#52-the-protocol-exchange). And the
documented certificate lifetime of up to two months is an upper bound rather than a fixed term;
measured spans are about two weeks ([part 4
§2.1](4-measurements.md#21-leaf-validity-by-material-class)). Note also that running out of keys is
a family of errors rather than one: transient, permanent, pending-connectivity and
requires-system-upgrade variants map separately into the error space of `keystore2`, and conflating
them produces incorrect retry behaviour.

Two Google roots now discriminate provenance: the long-standing RSA-4096 hardware-attestation root
used for factory batch keys, and the EC P-384 root `CN=Key Attestation CA1` used for remote
provisioning, which began signing at a published cutover and became exclusive for provisioned
devices approximately ten weeks later. Both are pinned in
[`app/.../RootPublicKey.kt`](../app/src/main/java/org/matrix/teesim/RootPublicKey.kt), and the
measured chain positions under the EC root are in [part 4
§2.2](4-measurements.md#22-shared-chain-positions).

### 5.5 On-disk storage

The provisioning daemon's pool is a Room database named `rkpd_database` with a single entity, whose
table `provisioned_keys` carries `key_blob` as primary key together with `irpc_hal`, which holds
`RpcHardwareInfo.uniqueId` and is the reason that identifier must be stable across reboots, plus
`public_key`, `certificate_chain`, an indexed `expiration_time`, `client_uid` and `key_id`, with a
unique composite index over client identifier, key identifier and component. The authenticated
public key and the COSE key are not columns: they live on a separate in-memory class and are never
persisted.

The store used by `keystore2` is `persistent.sqlite` under `/data/misc/keystore`, alongside a
per-boot database. Its tables are `keyentry`, `blobentry`, `blobmetadata`, `keyparameter`,
`keymetadata` and `grant`, with subcomponent types `KEY_BLOB=0`, `CERT=1` and `CERT_CHAIN=2`, the
split described in [§5.3](#53-consumption-in-keystore2). In Android 13 `keystore2` owned the
provisioning pool itself, through a `KeyType::Attestation` variant and four dedicated functions; on
current `main` only `Client` and `Super` remain, because the pool moved to the daemon, although some
attestation metadata tags survive. This is version-dependent ([§8.1](#81-version-dependent-claims)).

A root process can read both stores in full and obtains only ciphertext blobs and public
certificates. The key-encryption key is derived inside KeyMint from a hardware root key.
[SELinux](https://source.android.com/docs/security/features/selinux) labels the directory, and the
namespace identifiers in the access-control configuration of `keystore2` are enforced by the daemon
rather than by the kernel, so a root process that defeats SELinux gains file access and nothing
cryptographic.

This measurement bears on a common category error. Dumping these tables yields many provisioned key
entries, which is the likely origin of claims to have extracted large numbers of provisioned keys;
what emerges is a wrapped blob and a public chain. Section [part 4
§4.4](4-measurements.md#44-holdings-of-a-stock-device) reaches the same result from a second
direction: a stock device's stored provisioning key is a 275-byte opaque blob, neither
[PKCS#8](https://www.rfc-editor.org/rfc/rfc5958) nor a scalar.

### 5.6 Test mode

Four independent mechanisms render test mode inert, all of them specific to versions 1 and 2.

First, the definition of the marker: the presence of label `-70000` means the key is a test key and
that `K_mac` is all zeros, so a test `MacedPublicKey` is authenticated under a publicly known key
and is useless as evidence. The reference application computes the tag under 32 zero bytes in test
mode.

Second, strict mode segregation, enforced by the status codes of [§2.2](#22-the-aidl-surface): a
request may not mix test and production keys, and `generateCertificateRequestV2` must never accept a
test key at all, the reference application scanning every key for the marker before verification.

Third, in test mode any endpoint key is accepted, and correspondingly the test chain must contain
freshly generated keys rather than the real ones, so a test request carries a throwaway chain and
leaks no device identity.

Fourth, the backend checks the marker and issues test certificates that deliberately do not chain to
a trusted root.

From version 3 the path is removed. One detail is worth noting when reading the reference
application: it raises a removal error only when the configured version is above 2, and for a
version-1 or version-2 configuration falls through to an unimplemented error, so it never implements
the legacy request path at all.

The residual risk is a vendor wiring fault — test keys receiving production certificates, or a
backend accepting test-tagged requests on a production endpoint — rather than a protocol flaw, and
root pinning already defeats it.

### 5.7 Provisioning for protected virtual machines

The [Android Virtualization Framework](https://source.android.com/docs/core/virtualization)
provisions keys for privileged virtual machines through the same machinery, identified by the
virtual-machine marker, configuration-descriptor label `-70006` from [§4.4](#44-chain-entries),
together with a component name. The rule is positional: a chain that begins at the root with zero or
more entries lacking the marker, followed only by entries carrying it up to and including the leaf,
describes a machine the backend may provision to, and implementations must include the first marker
as early as possible after the divergence between components inside and outside the trusted
environment, before the Android bootloader loads. The component name of the leaf selects the key
type — `"rkp-vm"`, `"keymint"` or `"widevine"` — and a chain with no marker describes a
trusted-environment component eligible for attestation keys. Any other arrangement receives nothing.

Attestation is two-tier: the provisioning machine attests to the backend, which compares its DICE
root against registered public keys, and other protected machines then attest against it.

A set of provisioned private keys and a DICE chain therefore reside inside a protected machine
isolated by the [hypervisor](https://en.wikipedia.org/wiki/Hypervisor) rather than inside the
trusted execution environment: a different isolation boundary with a different exploit population.
SELinux reflects the division by giving the daemon two distinct HAL client attributes. For a
verifier the consequence is in [part 3 §7.3](3-detection.md#73-expectation-maps):
`RpcHardwareInfo.uniqueId` distinguishes the two instances, so a pool in which the virtual
instance's identifier is missing or duplicated indicates an emulated HAL.

---

## 6. Analysis of the trust relation

### 6.1 Validation order at the backend

1. Well-formedness of the request against the CBOR and CDDL grammars.
2. The signed-data structure verifies under the DICE leaf key, and the embedded challenge matches
   the one issued, which supplies freshness and anti-replay.
3. Every chain entry verifies from `UDS_pub` to the leaf, with issuer and subject identifiers
   linking as in [§4.3](#43-layer-keys-and-identifiers).
4. `UDS_pub`, or the [X.509](https://www.rfc-editor.org/rfc/rfc5280) chain in `UdsCerts`, resolves
   to a registered root. This is the step that carries the relation. Two enrolment paths exist: a
   direct allow-list of public keys, in which the manufacturer extracts and uploads each device's
   key at the factory; or vendor-signed certification, in which a manufacturer key is itself
   registered with the server. Either way the anchor is a manufacturing-time registration event on a
   line the operator vets. Revocation lives here too, which is what makes per-device rotation
   feasible without disabling hardware.
5. Device state and eligibility: consistency of the device information, mode, and known-good
   hashes.
6. Only then are certificates issued for the submitted keys, chaining to a Google root.

### 6.2 Self-consistency and anchoring

A synthetic chain is trivially self-consistent and can be made byte-perfect: correct grammar,
correct signature structures, verifying signatures, and the challenge echoed back. None of those
properties is decisive. Verification does not ask whether the signatures link up but whether the
linkage terminates at an anchor the verifier trusted before it saw the message. Anyone can mint a
root and sign their own layers; only the holder of a key whose public half was pre-registered or
pinned can satisfy the second question.

### 6.3 Rejection at provisioning and at consumption

At provisioning, step 4 of [§6.1](#61-validation-order-at-the-backend) asks whether `UDS_pub`
resolves to a registered root. A synthetic root was never enrolled at a vetted factory, so no
production certificate is issued. At consumption, the verifier asks whether the chain terminates at
a pinned Google root and is unrevoked. A self-rooted chain does not, so it is rejected irrespective
of internal validity.

Exactly two courses would satisfy step 4, and both lie outside cryptography: chaining to a real
registered device secret, which requires that device's hardware-resident private key and is the
subject of [part 2](2-mechanisms.md); or obtaining registration for a synthetic root, which is a
manufacturing-enrolment or public-key-infrastructure compromise rather than a shortcut.

Test and degenerate chains are deliberately unanchored by the same logic. The `testMode` parameter
of versions 1 and 2 used a fresh, unregistered key so that vendors could exercise the pipeline, and
results were marked test-only and never honoured. Version 3 removed the notion entirely:
`generateCertificateRequestV2` has no such parameter, and the legacy method must raise a removal
error. No code path promotes a self-consistent chain to a trusted one.

### 6.4 Verification at the consumption side

This is the half that a simulator must satisfy. The KeyMint leaf carries a key description under
[object identifier](https://www.itu.int/rec/T-REC-X.660) `1.3.6.1.4.1.11129.2.1.17`, comprising the
attestation challenge, the attestation security level (software, trusted environment, or secure
element), a software-enforced and a hardware-enforced authorisation list covering purpose,
algorithm, key size, origin and authentication binding, and a root-of-trust structure carrying the
verified-boot key, the device-locked flag, the verified-boot state and the verified-boot hash. Only
the hardware-enforced list, under a chain rooted at Google, is a claim the secure hardware makes.

A verifier checks the chain to a pinned Google root; revocation against the published status
endpoint; that the challenge matches the nonce it supplied; that the security level is the trusted
environment or a secure element rather than software; the key properties and origin; and the boot
state, requiring a verified state and a locked device. Batch-provisioned and remotely provisioned
keys terminate at the same Google roots, so verifier logic is identical in both cases, and the
advantage of remote provisioning is operational rather than cryptographic.

A separate extension, object identifier `1.3.6.1.4.1.11129.2.1.30`, appears on provisioning signer
certificates and carries what the backend recorded about the request. Almost no verifier reads it;
[part 4 §3](4-measurements.md#3-the-provisioning-information-extension) decodes it byte for byte.

---

## 7. Application to TEESimulator

### 7.1 The existing implementation

The vendored AOSP KeyMint carries a complete provisioning implementation to which nothing is routed.

[`third_party/keymint/ta/src/rkp.rs`](../third_party/keymint/ta/src/rkp.rs) implements `uds_certs`,
`rpc_device_info` and `generate_ecdsa_p256_keypair`, the last computing the tag, building the
authenticated public key and rejecting test mode from version 3 onward, together with both
`generate_cert_req` and `generate_cert_req_v2`, each calling `get_dice_info`. `KeyMintTa::process`
in [`ta/src/lib.rs`](../third_party/keymint/ta/src/lib.rs) already routes the four provisioning
requests, and the wrapper in [`rust/teesim-km/src/lib.rs`](../rust/teesim-km/src/lib.rs) forwards
directly into `self.inner.process(req)`. The application could therefore serve the interface today;
nothing sends it those transactions.

The integration contract is the trait `RetrieveRpcArtifacts` in
[`third_party/keymint/ta/src/device.rs`](../third_party/keymint/ta/src/device.rs), with
`get_dice_info` and `sign_data`, the structures `DiceInfo` and `PubDiceArtifacts{uds_certs,
dice_cert_chain}`, the `CsrSigningAlgorithm` enumeration over ES256, ES384 and EdDSA,
`RpcV2TestCDIPriv`, and a ready-made `NoOpRetrieveRpcArtifacts` stub. `RpcInfoV3` is already
constructed with a real `supported_num_of_keys_in_csr`, and each application instance is pinned to
one security level at construction.

Keyboxes carrying only an EC key, which is the shape a provisioning-derived keybox has, are already
first-class signing inputs. [`rust/teesim-km/src/attest.rs`](../rust/teesim-km/src/attest.rs) parses
the `<Key algorithm="rsa|ecdsa">` element, requires at least one key and at least two certificates,
and its `pick(prefer_ec)` and `batch()` helpers make every leaf EC-signed when the keybox carries
only an EC P-256 key, as a provisioned device does. The re-signing path is in
[`resign.rs`](../rust/teesim-km/src/resign.rs).

The provisioning AIDL is vendored under `third_party/interfaces/security/rkp/aidl/` but not
compiled: the top-level `CMakeLists.txt` globs only `keymint`, `secureclock` and `sharedsecret`. No
typed server exists natively.

[`common/control.h`](../common/control.h) is the per-security-level configuration channel, defining
`TsBootInfo` and `TsProfile`, staged through `teesim_cfg_begin`, `add_profile` and `commit`, and
parsed by `ApplyConfig` in [`common/control.cpp`](../common/control.cpp). Any provisioning or DICE
configuration field must extend that structure and its parse layer.

### 7.2 The unimplemented DICE interface

The stub is `struct NoRpc` in [`rust/teesim-km/src/device.rs`](../rust/teesim-km/src/device.rs).
`derive_bytes_from_hbk` is implemented; `get_dice_info` and `sign_data` both return an unimplemented
error with the message that remote provisioning is not supported. The documentation comment states
the intent: the interceptor never routes provisioning calls there, so only the hardware-backed-key
derivation needs to work.

### 7.3 Denial of the provisioning lookup

TEESimulator injects into `keystore2` and
[hooks](https://maskray.me/blog/2021-09-19-all-about-procedure-linkage-table) `AIBinder_transact` in
[`keymint/keymint_hook.cpp`](../keymint/keymint_hook.cpp) through the procedure linkage table,
gating on `IsHandled(code) && IsKeyMintProxy(binder)` with a descriptor-only match against
`IKeyMintDevice::descriptor`, and breaking recursion with a thread-local forwarding flag. Besides
redirecting KeyMint to the in-process application, it denies the provisioning lookup for target
applications:

- `IsRkpProvisioning(binder)` matches the descriptor `android.security.rkp.IRemoteProvisioning`,
  which is the outbound call `keystore2` makes to the daemon on the application's binder thread, so
  that `getCallingUid` returns the application's identifier.
- `teesim_is_target_uid(uid)` scopes the effect to target applications.
- `GetRegIsStrongBox` reads the component-name argument, `"strongbox"` against `"default"`, by
  splicing a throwaway prepared parcel, so no wire format is hardcoded; `ReadRkpOnly` then consults
  the two `rkp_only` properties.

The branch is forced by [§5.4](#54-the-rkp_only-branch-and-the-two-google-roots). Where the level is
not provisioning-only, denying the registration call causes `keystore2` to fall back to having no
attestation key, to append nothing, and to leave the application's keybox-rooted chain intact. Where
the level is provisioning-only, denial must not occur, because it would make `generateKey` return an
error; the log records that the lookup was not denied.

The three ground-truth properties are recorded once at install by `LogRkpPolicySnapshot()`, and they
are read and never written. Changing a device-wide `rkp_only` or daemon-enable property would itself
be a conspicuous detection point; the rationale is in [`keymint/README.md`](../keymint/README.md).

The attestation-key path is closed separately: an attestation key is always minted in the
application, so the simulator holds the private key and can set the [root of
trust](https://source.android.com/docs/security/features/verifiedboot/verified-boot) on every leaf,
and a startup purge, `ReAttest.purgeTargetAttestKeys` into `KeystoreDb.deleteTargetAttestKeys`,
deletes pre-existing foreign attestation keys rooted at Google or at the provisioning hierarchy,
restarting `keystore2` to evict its in-memory cache where a direct database deletion was required.

The web interface surfaces the two `rkp_only` properties and
`persist.device_config.remote_key_provisioning_native.enable_rkpd` as a user-driven escape hatch.
Nothing in the codebase intercepts or emulates the daemon itself.

### 7.4 Candidate interception points

1. *Denial at the outbound registration call in `keystore2`*, the current approach. Least invasive,
   one readable descriptor, scoped per application and per level. Its limitation is that a
   provisioning-only level has no fallback, which is why attestation keys are always minted in the
   application.
2. *Interception of the returned provisioned key*, substituting an attestation-key descriptor whose
   blob the application actually holds: mint an application attestation key and return its blob with
   a keybox leaf as the pooled key. This covers provisioning-only regular-key attestation without
   any fallback and is the natural next step.
3. *Hooking the provisioning HAL*, which is ineffective against attestation, since it shapes only
   the request sent to the backend, and risky, since it perturbs real provisioning for every
   application. It is relevant only to simulating a device end to end for the backend, which
   [§1.3](#13-scope-and-conventions) places out of scope.
4. *Hooking the daemon*, which requires injecting into the APEX-packaged application and is
   considerably more fragile.
5. *Rewriting certificate-chain rows*, which `ReAttest` already does idempotently for pre-existing
   keys, writing the same split that `keystore2` uses. This is a repair pass rather than an
   interception: it cannot correct a chain the application has already read from the reply.

### 7.5 Requirements for a serving implementation

Replace `device::NoRpc` with a DICE-backed implementation of `RetrieveRpcArtifacts`: `get_dice_info`
returning synthesised public artifacts together with a signing algorithm, and `sign_data` signing
with the modelled leaf key in the fixed-width COSE form. This is where a simulated chain is minted,
with no hardware secret involved.

Add a CBOR and COSE builder for the chain and the certification map. None exists; the reference
expects these bytes ready-made. Build them per [§4.4](#44-chain-entries) from configuration.

Plumb the identity through configuration end to end: new fields in `TsBootInfo` and `TsProfile`,
through `ApplyConfig` into the application configuration, pushed by `Resolver.kt` and
`App.resolveAndPush`, carrying a modelled `UDS_pub`, a profile name and a signing algorithm.

Route provisioning transactions into the application, as an alternative to denial and mutually
exclusive with it per level: compile the vendored AIDL, add a local `BnRemotelyProvisionedComponent`
in `keymint/keymint_router.cpp`, add a descriptor match in `keymint_hook.cpp`, and translate the
three methods into wire requests, since `teesim_km.h` exposes no entry point for them today.

Decide per level whether to serve or to deny, and reconcile that decision with the `rkp_only`
gating. Optionally, replace the passive property view in the web interface with a profile toggle.

For `keystore1` there is nothing to do, since Android 10 and 11 predate the protocol
([§7.6](#76-the-keystore1-path)).

### 7.6 The keystore1 path

[`keystore/binder_interceptor.cpp`](../keystore/binder_interceptor.cpp) hooks
[`ioctl`](https://man7.org/linux/man-pages/man2/ioctl.2.html) on `libbinder`, watches for incoming
transactions, and rewrites the target to a local stub;
[`keystore/keystore_router.cpp`](../keystore/keystore_router.cpp) selects between release-specific
ordinal tables for Android 10 and 11, because `IKeystoreService` shifted ordinals when `reset()` was
removed and `finish()` grew. The function `teesim_cfg_resign` always returns false for this hook.
Attestation there uses factory batch keys only.

---

## 8. Limitations

### 8.1 Version-dependent claims

The following must be re-verified against the target `android-*` branch, and against [Android Code
Search](https://cs.android.com/android/platform/superproject/main) rather than the GitHub mirror:
the DICE profile name value and the exact payload and configuration-descriptor label sets; the
device information field set and optionality, including the rule that makes the operating-system
version mandatory for the trusted-environment level; the minimum key count and the endpoint-curve
test-suite behaviour of [§2.3](#23-hardware-information); the open-dice cryptographic profile and
the unpadded-digest deviation; acceptance of degenerate chains and the three deployment phases; the
server response framing and endpoint set, which are backend-defined; the presence and format of the
certification map; the internal provisioning descriptors in `keystore2` and the semantics of the
`remote_provisioning.*` and `remote_key_provisioning_native` properties; the two Google roots and
the exclusivity dates; and the provisioning-information extension, where only two labels are
documented, the map is explicitly unversioned, and the labels observed in the field are undocumented
and may change without notice.

### 8.2 An unimplemented verification step

[`app/.../KeyboxInspector.kt`](../app/src/main/java/org/matrix/teesim/KeyboxInspector.kt) verifies
each certificate against its parent, classifies the root through
[`RootPublicKey.kt`](../app/src/main/java/org/matrix/teesim/RootPublicKey.kt), and checks revocation
through [`RevocationList.kt`](../app/src/main/java/org/matrix/teesim/RevocationList.kt). It decodes
no provisioning extension: `1.3.6.1.4.1.11129.2.1.17` is the only Google object identifier the tree
handles. The web interface therefore shows chain validity, expiry and revocation, and shows nothing
of provisioning status or issuance count — the two fields that, per [part 4
§3](4-measurements.md#3-the-provisioning-information-extension) and [part 2
§9](2-mechanisms.md#9-routes-refuted-before-publication), discriminate a sound keybox from a
worthless one and are visible to any relying party.

The decode is already prototyped off-device in
[`tools/teesim_attest/provisioning.py`](tools/teesim_attest/provisioning.py), which preserves
unknown fields, gates on status, and compares the issuance count against the measured stock
baseline. Porting it into the inspector is transcription rather than design, because the inspector
already performs the harder parts. It is not undertaken in this report.

Alongside it, the bare expiry boolean in
[`app/.../KeyAdmin.kt`](../app/src/main/java/org/matrix/teesim/KeyAdmin.kt) should become a count of
days remaining for every certificate in the chain. That boolean was adequate only while keyboxes
lasted years; leaf lifetime is now a class discriminator, about two weeks for provisioned keys
against about ten years for a factory batch key ([part 4
§2.1](4-measurements.md#21-leaf-validity-by-material-class)).

### 8.3 Direction of the platform

A verifier that hard-codes two roots will break again.

*Root rotation.* Signing under the P-384 root began at a cutover Google publishes; the exclusive-use
point for provisioned devices, approximately ten weeks later, is reported by a third party rather
than by Google ([§5.4](#54-the-rkp_only-branch-and-the-two-google-roots) and [part 3
§2.1](3-detection.md#21-two-trust-anchors)). Both should be read from current documentation rather
than from this text, because a verifier that misses the second rejects every provisioned chain in
the interim. Legacy devices retain the RSA root indefinitely, so a trust store should be
configuration rather than code, supporting more than two roots and more than one signature
algorithm.

*Post-quantum algorithms in Android 17.* Native ML-DSA-65 and ML-DSA-87 in the keystore through the
standard key-pair generator interface, with key material isolated in secure hardware; ML-DSA in
[verified boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot)
signature checks; and a stated transition of remote attestation to post-quantum compliance *"by
updating KeyMint's certificate chains to support quantum-resistant algorithms"*. The attestation
schema already documents a version-500 key description whose authorisation list adds a variant field
for that algorithm family, so a third generation of attestation root is to be expected.

*Provisioning for virtual machines*, per [§5.7](#57-provisioning-for-protected-virtual-machines),
extends the model to workloads outside KeyMint and creates a second isolation boundary with a
distinct exploit population.

*Trusted interfaces for secure-environment clients.* A device-state interface lets a KeyMint
instance running in a virtual machine ask whether the device is in its manufacturing phase,
described as *"a guardrail, ensuring that sensitive Device ID data is only provisioned to the secure
environment while the device is at the factory"*; alongside it are interfaces for hardware-bound
keys, secure storage, and a protocol for authenticating clients before granting access. On `main`
the tree carries only the storage, cryptographic, content-protection and authentication-manager
interfaces, with the device-state one appearing on release branches. The direction is to narrow what
the secure environment will accept and from whom.

*Delivery as mitigation.* Provisioning became an updatable module in Android 14, so policy can
change without a vendor update, which is why the factory-key sunset can move faster than the Android
version curve suggests.

*One claim refuted.* Google's own sources disagree about when the protocol became mandatory. The
developer documentation states that devices launching with Android 16 support only remote
provisioning, *"expanding on the Android 15 policy where RKP support was optional"*; the platform
documentation states that *"Android 15 requires all devices to implement it"*; and the Compatibility
Definition Document, verbatim in both the Android 15 and Android 16 editions, still permits factory
batch keys — *"Alternatively, the Remote Key Provisioning solution may be used to provision
short-lived attestation keys to the device."* The proposition that Android 15 requires all devices
to implement the protocol is therefore refuted as a normative statement and is not used in this
report.

The defensible timeline is that the protocol entered AOSP in Android 12 as an option; was mandated
for devices launching with Android 13; devices launching with Android 16 support only it; and the
Compatibility Definition Document through Android 16 still describes factory batch keys as a
permitted alternative. This is a launch-version rule rather than an upgrade rule: a device that
shipped on Android 11 and was updated retains its factory keybox, which is why the leaked-keybox
population does not shrink along the Android version curve ([part 4
§4.1](4-measurements.md#41-the-public-factory-corpus)).

---

## 9. References

The single reference list for this report; companion parts cite it rather than repeating it.

### AOSP sources

*Provisioning HAL.*
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

*Provisioning daemon.*
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

*Keystore.*
[`remote_provisioning.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/remote_provisioning.rs)
·
[`attestation_key_utils.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/attestation_key_utils.rs)
·
[`rkpd_client.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/rkpd_client.rs)

*DICE and encoding.* [open-dice
specification](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md) ·
[`src/dice.c`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c) · [Android
DICE
profile](https://android.googlesource.com/platform/external/open-dice/+/refs/heads/main/docs/android.md)
·
[`system/libcppbor`](https://cs.android.com/android/platform/superproject/main/+/main:system/libcppbor)

### Google documentation

[Remote key
provisioning](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning) ·
[Key attestation](https://source.android.com/docs/security/features/keystore/attestation), including
the [provisioning-information extension
schema](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension),
the only published grammar for object identifier `1.3.6.1.4.1.11129.2.1.30` ·
[DICE](https://source.android.com/docs/security/features/dice) · [Leaf revocation
status](https://android.googleapis.com/attestation/status) ·
[`key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl)

### Standards

[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and [RFC
9053](https://www.rfc-editor.org/rfc/rfc9053), COSE structures and algorithms · [RFC
8392](https://www.rfc-editor.org/rfc/rfc8392), CBOR Web Token · [RFC 8949
§4.2](https://www.rfc-editor.org/rfc/rfc8949#section-4.2), deterministic CBOR · [RFC
8032](https://www.rfc-editor.org/rfc/rfc8032), Ed25519 · [NIST SP
800-108r1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final), [counter-mode key
derivation](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) ·
[GlobalPlatform](https://globalplatform.org/specs-library/tee-internal-core-api-specification/) TEE
Internal Core API v1.3.1 and TEE Client API v1.0

### Field records and tooling

[kanxue thread 293244](https://bbs.kanxue.com/thread-293244.htm), the Qualcomm signing oracle, whose
content is recorded in [appendix A](A-record-signing-oracle.md) · [kanxue thread
293246](https://bbs.kanxue.com/thread-293246.htm), the three-device retrospective, recorded in
[appendix B](B-record-three-devices.md) ·
[`gungnir-sanye/tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction),
the engineering corpus behind the retrospective ·
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), an independent normal-world
provisioning client, request builder and verifier, used here as a protocol reference ·
[`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw), a Python implementation of the
same pipeline. Each is appraised in [part 5 §3](5-sources.md#3-appraisal).

### Academic literature

[TÄMU](https://arxiv.org/abs/2601.20507), Mao, Shi, Busch and Payer, on emulating trusted
applications at the GlobalPlatform interface layer, with [tooling](https://github.com/HexHive/taemu)
· [FIASCO](https://nebelwelt.net/blog/2025/1227-fiasco.html), HexHive at 39C3, with
[slides](https://hexhive.epfl.ch/publications/files/25CCC-presentation.pdf) and
[tooling](https://github.com/HexHive/beanpod_fiasco) · *Spill the TeA* and *GlobalConfusion*, USENIX
Security · [Quarkslab on bypassing Android hardware
attestation](https://blog.quarkslab.com/bypassing-android-hardware-attestation.html), with a
[demonstration](https://github.com/quarkslab/android-hardware-attestation-demo)

### Companion documents

[part 2](2-mechanisms.md) · [part 3](3-detection.md) · [part 4](4-measurements.md) · [part
5](5-sources.md) · [appendix A](A-record-signing-oracle.md) · [appendix
B](B-record-three-devices.md) · [the toolkit](tools/README.md)
