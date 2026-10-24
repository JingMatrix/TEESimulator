# 2. Mechanisms of attestation-material compromise

Index: [the index](README.md). Companion parts: [part 1](1-protocol.md), [part 3](3-detection.md),
[part 4](4-measurements.md), [part 5](5-sources.md).

## Abstract

A faithful simulator must know which secret an adversary holds, because the five objects routinely
called "the attestation key" differ in what possession confers and in how long it lasts, from one
key's worth of attestation to the lifetime of a handset. This part separates them and then
reconstructs four published acquisition routes: a signing oracle on a Qualcomm
[KeyMint](https://source.android.com/docs/security/features/keystore) application that extracts
nothing and requires no bootloader unlock; plaintext observation inside a [Trustonic
Kinibi](https://www.trustonic.com/)
[trustlet](https://github.com/Trustonic/trustonic-tee-user-space); caller-gate relaxation on a
Beanpod and [L4Re](https://l4re.org/) keybox application; and same-boot capture of a final leaf
identifier under proper
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/). Read together the
four share a structure that none states alone: in no route is a cipher broken, a key factored or a
digest forged. Every cryptographic check still executes; what changes is what the code does with the
result, after which the secret is observed where authentic code had already placed it in cleartext.
Two consequences follow for the defensive side. The mechanism class is well evidenced while the
individual constants are single-sourced, so the structure of
[§8](#8-common-structure-of-the-four-routes) carries more weight than any one narrative. And the
signals that discriminate a compromised keybox from a sound one are not cryptographic: they are an
issuance count and a provisioning status that the backend writes into the signed certificate, and
that almost no verifier reads.

---

## 1. Introduction

### 1.1 Problem statement

Section [part 1 §6.3](1-protocol.md#63-rejection-at-provisioning-and-at-consumption) establishes
that a synthetic chain is rejected independently at two points, and that only two courses would
satisfy the provisioning check: chaining to a genuine registered root, or obtaining registration for
a synthetic one. The second is a manufacturing-enrolment problem that no public work addresses. This
part concerns the first: what has to be taken from a device, and how it has been taken.

The problem divides cleanly. Everything downstream of holding the right secret — building a
conforming request, obtaining a signature, assembling a keybox — is a fully reconstructed and
reproducible procedure with no unsolved step in it ([§7](#7-off-device-certificate-minting)).
Everything upstream was an open absence until four routes were published, and those routes operate
in a manner that none of the candidate designs anticipated
([§9](#9-routes-refuted-before-publication)).

### 1.2 The evidence base

Four routes across four trusted execution environments. Route A derives from a public post on a
Qualcomm handset, whose content is recorded in [appendix A](A-record-signing-oracle.md). Routes B, C
and D derive from a single retrospective, recorded in [appendix B](B-record-three-devices.md), and
from the engineering corpus behind it,
[`gungnir-sanye/tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction).

Three routes from one corpus are not three independent confirmations. They are three different
mechanisms on three genuinely different platforms — [Trustonic
Kinibi](https://www.trustonic.com/solutions/trustonic-secured-platform/), Beanpod on L4Re, and MiTEE
on [Zircon](https://fuchsia.dev/fuchsia-src/concepts/kernel) — from one research effort, and the
fact that the platforms differ is the principal reason the set is informative. Route A is a separate
post on a fourth platform with a separate toolchain; whether it shares authorship could not be
determined from the archived pages, so it is treated as independent, which is the generous reading
in one direction and the risky one in the other.

Route A carries more weight than its single source because its wire format is independently
confirmed. [`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), an unrelated Rust
implementation, encodes the same command word, the same two
[CBOR](https://www.rfc-editor.org/rfc/rfc8949) labels and the same response wrapping, and neither
source cites the other ([§3.5](#35-request-format)). That agreement is the strongest single
corroboration in this part.

Nothing here was reproduced on hardware. What was examined locally is the artifact layer: file
digests, container metadata, patch-script constants, protocol constants against
[AOSP](https://source.android.com/)'s [CDDL](https://www.rfc-editor.org/rfc/rfc8610), and the
arithmetic of every cross-part claim. The retrospective's own front matter declines to assert that
every historical command was re-executed by a human. Per-route claims are therefore attributed to
the records that make them, [§10](#10-limits-of-the-evidence) states what would settle each, and
[part 5 §3](5-sources.md#3-appraisal) appraises each record in detail. The structure of
[§8](#8-common-structure-of-the-four-routes) should be weighted above any single route's narrative.

### 1.3 Withheld detail

Per [part 1 §1.3](1-protocol.md#13-scope-and-conventions), symbol names, function names and command
numbers appear where they identify a defect, because that is what allows a defender to look for the
same defect and, in several cases, what allows an independent reader to check the claim. Patch
offsets, original instruction bytes and code-cave addresses are withheld, because together they
constitute a ready-to-apply patch rather than evidence that a patchable decision exists. The
distinction costs the reader nothing analytically: the finding is that one branch on a verification
result had to be neutralised, not where that branch sits.

---

## 2. Objects of compromise

Two orthogonal questions precede any route. Who holds the key and who signs with it
([§2.1](#21-custody-classes)), which determines whether revocation is the appropriate remedy; and
which of five distinct objects was obtained ([§2.2](#22-five-distinct-secrets)), which determines
what the holder can then do.

### 2.1 Custody classes

Three custody tags suffice. *Key leaves* means that raw private key material exists outside the
secure world in usable form, so that revocation and rotation apply. *Used in place* means that a
genuine secure world signs attacker-chosen data with a key it still holds, or that an attacker signs
with a key that was already outside a secure world; revocation may or may not help, while binding
and behavioural controls do. *Not applicable* means that no secret is involved.

The classes are lettered so that [part 3 §9](3-detection.md#9-coverage-of-mechanisms-by-control) can
score controls against them.

*A — supply-chain leakage of a factory batch key.* Key leaves, from the provisioning pipeline rather
than from a device: the delivery artifact is a keybox file whose private keys are in plaintext by
construction at the point of provisioning. Key reuse is normative, the Compatibility Definition
Document requiring the same attestation key per stock-keeping unit unless more than 100,000 units
are produced, after which a different key may be used per further 100,000. The privacy rationale is
unlinkability; the security consequence is that one leak compromises a six-figure device population
and that revoking it disables attestation for every honest owner in that batch. The cost of one file
against the cost to 100,000 users is the economics of the leaked-keybox market, and this class
rather than any environment exploit accounts for substantially all observed attestation fraud. The
public population is censused in [part 4 §4.1](4-measurements.md#41-the-public-factory-corpus).

*B — the published AOSP software attestation key.* Not applicable: the private key is in public
source control. Root pinning rejects it, and it never chains to Google.

*C — normal-world KeyMint interposition and application emulation.* Used in place of an
already-leaked key. The attacker's in-process code signs, and revocation helps only through the
underlying keybox. This is the class this project implements, which is why the structural checks of
[part 3 §6](3-detection.md#6-structural-and-encoder-checks) are noted there as defeated by it.

*D — abuse of the factory provisioning path.* The key is written in rather than read out: a
normal-world installer hands a keybox to the secure world, which then signs honestly with an
attacker-supplied key. Such an installer shipping on retail hardware is measured in [part 4
§6.7](4-measurements.md#67-a-normal-world-keybox-installer).

*E — in-place use of genuine device keys.* Used in place: a blob and certificate lifted from the
keystore database and replayed through the attestation-key parameter, so that the genuine secure
world signs attacker-chosen leaves. Revocation does not help, the key being genuine and unrevoked,
and the scope is bounded to the originating device and the certificate's lifetime.

*F — collapse of the boot chain below the trusted environment.* Used in place, with a falsified
measured state: the device's own genuine, unrevoked key signs an attestation reporting a locked
bootloader. Nothing is available to revoke, which is why the F column of [part 3
§9](3-detection.md#9-coverage-of-mechanisms-by-control) is almost empty.

*G — relay and signing-oracle attacks.* Nothing moves. A genuine remote secure world signs the
relying party's challenge and the chain is forwarded. The architectural finding is published:
*"There is no field in the KeyDescription that binds the attestation to the transport, the session,
or the device presenting it. The nonce is the only freshness signal."* No vulnerability identifier
has been assigned to this class, because the mechanism is sound and only its composition is not.
Section [§3](#3-route-a-a-signing-oracle-on-qualcomm-keymint) is the same architecture collapsed
onto a single handset.

*H — exploitation of the secure world.* The only class in which key material genuinely leaves a
secure world. Two decades of cases share a shape that is widely misreported: the dominant pattern
obtains code execution or arbitrary read in the secure world and then recovers the derived
blob-wrapping key, so that application key blobs decrypt offline, or reads one particular
application's plaintext key material. It almost never recovers the KeyMint attestation root key
itself. The canonical case is a key-blob derivation flaw whose own paper states the consequence: the
application continues to sign attestation certificates honestly, for keys the attacker can
subsequently extract. Every downstream property the certificate implies — device binding,
non-exportability, authentication-bound usage — collapses while the chain verifies perfectly. That
paper's most transferable finding is that the attestation commits neither to the cryptographic
method used to secure the key nor to the application's version, so a relying party cannot express a
policy of accepting only keys secured by a non-vulnerable derivation version, and the patch level
does not disambiguate because one firmware supported both. Sections
[§4](#4-route-b-plaintext-observation-in-a-kinibi-trustlet) and
[§5](#5-route-c-caller-gate-relaxation-on-a-beanpod-keybox-application) are modern instances, and
[part 4 §6.2](4-measurements.md#62-identification-of-the-secure-operating-system) shows that an
earlier published chain on a sibling handset is architecturally inapplicable to the platform
measured here.

*I — privileged exposure of the chain and the device secret public key.* The key does not leave;
this is an identifier leak. A root process that defeats
[SELinux](https://source.android.com/docs/security/features/selinux) calls the certificate-request
method itself and receives, in cleartext, the certification map and the whole chain: the device
secret public key plus every firmware code, configuration and authority hash. Enforcement is SELinux
and [binder](https://source.android.com/docs/core/architecture/hidl/binder-ipc) access control
rather than cryptography. The correct characterisation is a privacy and fingerprinting exposure: a
permanent, unresettable, reset-surviving device identifier together with a precise firmware
inventory and an offline oracle for which firmware a device runs. It is not a path to forging
requests for another device, because the request signature requires the leaf private key, which
remains inside the component and is constrained to request structures.

*J — relocation rather than elimination of supply-chain trust.* No device key is extracted; a
genuine backend signs for a fraudulent identity. The anchor moves from a key burned into a
production run to a registration event on a factory line ([part 1
§6.1](1-protocol.md#61-validation-order-at-the-backend)), and
[§7](#7-off-device-certificate-minting) is what follows when one registered identity is captured.

*K — rollback of a trusted application.* Nothing by itself; a force multiplier for class H. Section
[part 4 §6.6](4-measurements.md#66-the-application-container) measures why one platform's container
makes it attractive, and [§9.2](#92-refutations-by-measurement) records why two designed schemes
resting on it nonetheless failed.

*L — fault injection and physical attack.* Mixed custody, and out of scope as a procedure ([part 1
§1.3](1-protocol.md#13-scope-and-conventions)).

Exactly two classes, A and H, involve raw private key material outside a secure world, and A
accounts for substantially all observed fraud. Every other class is a genuine secure world doing
what it was asked, which is why patching environments and rotating keys does not address them, and
why [part 3](3-detection.md) is the other half of this analysis rather than an appendix to it.

### 2.2 Five distinct secrets

The retrospective names the conflation of these objects as the most common error in the area. They
are not interchangeable and not the same kind of thing.

A *factory attestation keybox* holds EC and RSA batch private keys with Google-rooted chains,
provisioned at manufacture and shared across a production run. It confers the ability to sign
attestation leaves offline, indefinitely, until Google revokes the batch. Measured leaf lifetimes
run about ten years on the one recovered in [§5.6](#56-acceptance-record).

The *Unique Device Secret* is the immutable hardware root of the chain ([part 1
§4.2](1-protocol.md#42-the-derivation)). It confers everything below it, for the lifetime of the
handset. No published route obtains one.

A *raw compound identifier* is an intermediate value captured before the remaining boot stages have
folded their measurements in. It confers nothing directly: it is an input to further derivation, and
a 32-byte value from which some public key can be derived is not thereby a device secret or a usable
identity.

The *final leaf identifier*, `CDI_Leaf`, is the scalar that signs the outer envelope of a
certificate request. It confers a renewable provisioning identity: its holder can mint Google-signed
chains over arbitrary locally generated
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) keys, repeatedly,
until a measured boot component changes. This is the object Route D takes and the object the
procedure of [§7](#7-off-device-certificate-minting) consumes.

A *native per-key scalar* is the private key KeyMint generated for one specific attestation key. It
confers one key's worth of attestation and closes only against its own authenticated public key and
leaf.

### 2.3 Consequences of conflation

The leaf identifier is not a constant of the model. The derivation is `CDI_next = KDF(CDI_current,
measurement, code_id, configuration)`, the recipe of [part 1 §4.2](1-protocol.md#42-the-derivation),
so changing the preloader, the little kernel, the environment image, `init_boot`, the [active
slot](https://source.android.com/docs/core/ota/ab), the measurement configuration or the
secure-world load state changes the leaf. Route D therefore cannot flash a patched image, reboot,
and collect an identity for later use: the identity it would collect belongs to the patched boot,
and a historical leaf cannot be stapled into a later round. The design of
[§6.4](#64-same-round-capture) follows from this.

A value from which a working public key can be derived is not thereby a root. The most careful
sentence in either field record bounds its own result: in the handset's current application path,
the 32 bytes output by the [key-derivation
function](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final), after verification against the same
round's public key, certificate request and signature relations, can serve as an input to that
device's current software provisioning identity. Not a universal device secret, and not a
cross-device reusable root. The corpus maintains the same discipline in its artifacts, publishing
only a digest fingerprint of the seed and never the bytes.

### 2.4 Supply and sample

A leaked leaf certificate together with its private key is a *sample*: it expires on its own
schedule, about two weeks for provisioned keys, and cannot be renewed. A *provisioning identity* is
a *supply*: it has no expiry, appears in no certificate that could be revoked, is never rotated, and
mints fresh leaves indefinitely.

Route A occupies a middle ground that neither category covers. The attacker never learns a secret,
so nothing can leak or be revoked, but minting requires the handset to be present and reachable: an
unlimited on-device minting capability rather than either a permanent offline one or a two-week
sample.

---

## 3. Route A: a signing oracle on Qualcomm KeyMint

No key leaves the device and no bootloader unlock is required. The source is the post recorded in
[appendix A](A-record-signing-oracle.md), cross-checked against the device crate of
[`Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), which implements the same wire protocol
independently. In the taxonomy of [§2.1](#21-custody-classes) this is a signing-oracle attack with
the oracle inside the target handset rather than on a second one, and with a named missing check in
place of an instrumentation hook. It is the cheapest route by a wide margin and the only one
carrying no risk of rendering the device unbootable.

### 3.1 Antecedent failures

The post frames the area as two established approaches: *harvesting*, extracting a leaf identifier
from the trusted environment and then minting offline without limit, and *proxy signing*, letting
the device perform a normal certificate request. The oracle is a third: take no seed, bypass the
system flow, and have the application sign a request over the attacker's own public key with the
genuine leaf identifier.

It exists because harvesting failed on that handset, and the failure map establishes the cost of the
alternative. Across the [boot-ROM](https://en.wikipedia.org/wiki/Boot_ROM) download surface the post
reports: the first-stage stub's data segment accepted a write, but that stub never executes; its
header and program headers were rejected before the data was pulled; four later
[ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) images were rejected after the pull;
program-header redirection was rejected up front for all of them; the memory-debug greeting was
refused; and firehose `peek` and `poke` returned "peek is disabled on secure boot devices", while
`configure`, `read` and `getstorageinfo` worked, leaving partition reads available and no memory
primitive. All 33 [fastboot](https://source.android.com/docs/setup/test/running) commands yielded no
memory read or write. A nonce-reuse probe of ten certificate requests over ten challenges found zero
repeated [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) `R` values, so the implementation is
conformant in that respect. Appendix A carries the per-surface rejection codes.

The conclusion drawn is that this handset's primary bootloader already fixes the loader defect on
which the corresponding published vulnerability depends, so the download-mode route does not hold
there. One positive by-product survived: the device's genuine leaf *public* key, recovered from a
certificate request by verifying the signer of its signed data. The private half was never reached
and, per [§3.4](#34-the-omitted-verification), was never needed.

### 3.2 Derivation and storage of the leaf secret

Full linear disassembly of the KeyMint image, reported byte-identical to the live partition,
recovered a dispatch table of 96 commands and the request path:

```
GENERATE_CSR_V2 (0x3122)
  -> generateCsrHandlerV2
  -> generateBcc
  -> derive_device_private_key        ; the CDI_Leaf derivation point
```

On this platform the leaf identifier is a 32-byte Ed25519 seed derived as `KDF(SHK, "RKP PRIVATE KEY
SEED")`, where `SHK` is the hardware secret of the system-on-chip key ladder, resident at a fixed
address in the application's global area at runtime with its public key adjacent.

That derivation label is not the one measured on Trustonic Kinibi
([§4.5](#45-the-derivation-call-site-and-its-label)). Three platforms use three different labels,
which is the evidence base for the scope note of [§9.3](#93-scope-of-the-label-measurement) and a
standing caution against assuming that a label transfers between vendors.

### 3.3 The command channel below the HAL

Android's own client does not address the application directly. It goes through the [binder
HAL](https://source.android.com/docs/core/architecture/hidl/binder-ipc), whose
[interface](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl)
is shaped so that private keys cannot escape: `generateEcdsaP256KeyPair` returns an authenticated
public key and retains the private half, and `generateCertificateRequestV2` takes those blobs back
([part 1 §2.2](1-protocol.md#22-the-aidl-surface)).

On this platform the application is also reachable below that HAL, and `Duck-ToolBox` gates on
exactly the two artifacts that make it reachable, measured locally in its source: the device node
`/dev/smcinvoke` and the vendor library `/vendor/lib64/libkeymasterdeviceutils.so`.

The obvious approaches fail. There is no `/dev/qseecom`; `libQSEEComAPI.so` is a compatibility shim
over MINK inter-process communication in which `start_app` works while `send_cmd` is refused by the
object model. What works is to replicate the HAL's own behaviour: load the vendor utility library
dynamically, construct its `KeymasterUtils` object for the trusted-environment security level, and
call `send_cmd`, which is a MINK invocation over ordinary heap buffers against the application name
`keymaster64`. The handset had root with SELinux still enforcing.

`Duck-ToolBox` resolves the same class by its three mangled symbols:

```
_ZN14keymasterutils14KeymasterUtilsC1E26keymaster_security_level_t
_ZN14keymasterutils14KeymasterUtilsD1Ev
_ZN14keymasterutils14KeymasterUtils8send_cmdEPvjS1_j
```

The signature `send_cmd(void* req, uint32_t req_len, void* rsp, uint32_t rsp_len)` is a raw byte
channel. Nothing in it is aware that a binder HAL exists, and nothing in it enforces what the HAL's
type signatures were enforcing.

### 3.4 The omitted verification

Under `generateCertificateRequestV2` the application is specified to receive authenticated public
keys and to verify each tag before certifying the key. That tag, computed with a device-unique key
the normal world does not hold, is the only element of the protocol binding a to-be-certified public
key to the environment that generated it. [AOSP's
grammar](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl)
types the field accordingly, precisely so that a key the application never produced cannot enter a
request ([part 1 §2.4](1-protocol.md#24-key-generation-and-the-authenticated-public-key)).

The post reports that the verification routine, `parseMacTags`, is cross-referenced only from the
version-1 request path and from a fixed-variant command. The ordinary path never calls it.

The surrounding validation is not weak. The challenge carries a hard 64-byte bound enforced by an
explicit compare-and-branch, every memory copy is clamped to a minimum, and the CBOR cursor is
tracked; the post found no out-of-bounds read anywhere on the surface. One function is simply not
wired into one path.

Everything downstream then behaves as designed. The application signs the outer envelope with the
genuine leaf identifier, emits the genuine chain and the genuine device information, and the backend
verifies all of it and returns a Google-rooted chain over the attacker's public key, whose private
half was generated on the host and never existed inside the trusted environment.

### 3.5 Request format

The request is a command word followed by a CBOR map with exactly two entries, as
[`crates/duck-rkp-device/src/protocol.rs`](https://github.com/eltavine/Duck-ToolBox/blob/main/crates/duck-rkp-device/src/protocol.rs)
builds it:

```rust
pub(crate) const CSR_COMMAND: u32 = 0x3122;

let payload = encode(&Value::Map(vec![
    (int(4),  Value::Bytes(challenge.to_vec())),
    (int(57), Value::Bytes(encode(&Value::Array(vec![public_key.clone()]))?)),
]))?;
let mut request = CSR_COMMAND.to_le_bytes().to_vec();
request.extend_from_slice(&payload);
```

Label 4 is the challenge, a byte string of at most 64 bytes. Label 57 is the key array, a byte
string holding a CBOR array of [COSE_Key](https://www.rfc-editor.org/rfc/rfc9052#section-7)
structures. The response is a single-entry map under label 61 and must be unwrapped. The key uses
the standard P-256 form `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.

Exactly two fields are permitted; a third yields an error return. `Duck-ToolBox` validates all of
this before transmission — two entries with labels exactly 4 and 57, a challenge of 1 to 64 bytes,
exactly one key, that key a five-field structure with the correct type, algorithm and curve triple,
32-byte affine coordinates, and a curve-equation check on the point — and re-validates in the worker
subprocess immediately before the system call.

The wire format agrees exactly between the two sources. The post derives request framing of `LE32
command ‖ payload` and response framing of `LE32 return-code ‖ LE32 length ‖ payload` from
entry-point disassembly; the Rust implementation encodes the same. Neither cites the other.

### 3.6 Procedure and failure modes

```
[host]   generate a P-256 key pair, retain the private key
[host]   fetchEekChain -> the backend issues a challenge
[host]   assemble {4: challenge, 57: bstr([our COSE_Key])}
[device] send command 0x3122 -> the application does not verify the tag, encodes the public key
         into the payload, signs with the genuine leaf identifier, returns the full request
[host]   unwrap the response -> POST signCertificates?challenge=...
[host]   the backend returns a four-level chain -> assemble keybox.xml
```

Three failure modes were forced out by HTTP 400 responses. The key field must be an array rather
than a bare map, the error text being "expected an array, got MAP". The substantive error, which
produces the same message, is submitting the application's single-entry response map rather than its
contents; unwrapping first makes the request pass immediately. And version 2 of the schema has no
`ProtectedData` field, the second element of the envelope being a possibly empty certification map,
so no endpoint encryption key need be constructed. The third of these settles a question about
tooling provenance to which [§7.3](#73-components-the-procedure-does-not-need) returns.

### 3.7 Result

The production endpoint returned HTTP 200 and a four-level chain:

```
CN=<public key hash>, O=TEE  ->  CN=Droid CA3  ->  CN=Droid CA2  ->  Key Attestation CA1
```

Acceptance was established as follows: the leaf's public key equals the public half of the host
private key; every chain signature verifies in turn; and the assembled keybox pairs with the private
key. Repeated runs all succeeded.

That shape matches the two leaked samples of [part 4
§2](4-measurements.md#2-two-leaked-provisioned-keyboxes) exactly: four certificates, a leaf with
subject organisation `TEE` and a common name equal to the certificate's own serial, then two
intermediates and the EC root. An independent source producing the same shape is evidence that the
measurement generalises to provisioning issuance rather than describing one producer's output.

Two further observations confirm conclusions reached elsewhere from the other direction. The chain
carries no device-model fields, the leaf's common name being a hash of the public key. And
substituting an unrelated handset's build fingerprint in the endpoint-key fetch still results in a
signed request, because the device information is determined by the application's internal
provisioning state and never reaches the final certificate. At this layer, changing the device model
is a pseudo-requirement; what controls the attested model is the interposition layer above, whether
a keystore interception module or this project's own profile system.

### 3.8 A second reachable secret

Once the channel is open, the post reports probing two further commands, one of which is a separate
defect.

A command named for generation of a fresh-replay and device-secret value returned a 32-byte
hardware-derived value directly, with the provisioning gate failing to prevent it. The static audit
had expected a production device to reject the call; in practice it was open. This is not required
for the oracle, but it is a second reachable secret on the same surface, and the kind of result that
should be checked before concluding that a command surface is uninteresting.

The other probe returned a negative: a neighbouring command is not an arbitrary authentication
oracle but a P-256 key-pair generation and authentication backend.

### 3.9 Preconditions

`Duck-ToolBox` [gates the
route](https://github.com/eltavine/Duck-ToolBox/blob/main/crates/duck-rkp-device/src/status.rs) on
five checks, of which exactly one is root: root, the `android_arm64` target, a Qualcomm
system-on-chip, the device node present, and the vendor library present. Its vendor test accepts an
empty manufacturer string or one containing "qualcomm", and its own tests assert that Google and
[MediaTek](https://www.mediatek.com/) are rejected. The crate advertises its limits as partial
device support and provisioning-only.

No bootloader unlock, no environment patch, no seed, and no change to device state: request
generation is read-only and touches neither the lock state nor the download mode. The route ceases
to work if the application wires its tag verification into the version-2 path, or if the backend
changes policy.

---

## 4. Route B: plaintext observation in a Kinibi trustlet

A key does leave the device: a factory keybox, and separately a 32-byte output of the provisioning
derivation call. The mechanism is replacement of a trusted application rather than exploitation of
one. The source is chapter 1 of the retrospective recorded in [appendix
B](B-record-three-devices.md), with the artifact layer read from the engineering corpus.

### 4.1 Environment

A Nothing Phone (2a), model A142, device `Pacman`, on MediaTek MT6886, Android 14, build
`Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys`. The environment is
Trustonic Kinibi, with `tee-1-1`, `keystore2` and `vendor.keymint-trustonic` all running. The boot
state `ro.boot.verifiedbootstate` reads `orange`, meaning unlocked. The KeyMint trustlet resides in
the [MobiCore](https://github.com/Trustonic/trustonic-tee-user-space) registry under
`/vendor/app/mcRegistry/`. The tutorial gates every step on exact
[SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) values for its three input
binaries and refuses to proceed on a mismatch.

### 4.2 The chain of defects

The record is emphatic that the vulnerability is a sequence rather than a point:

```
unlocked bootloader
  -> boot-chain verification policy defect
  -> controlled load of a modified little kernel and environment image
  -> the trustlet load boundary is relaxed
  -> a modified KeyMint trustlet enters the secure world
  -> the application reads and decrypts the factory keybox object normally
  -> plaintext exists briefly in application stack and heap
  -> it is saved before the parser runs
  -> it is copied into the mapped buffer before the handler returns
  -> a normal-world client reads the buffer back
  -> the host parses the DER, private keys and certificate chains
```

What is exploited is not the encryption of the keybox object. The researcher obtained the ability to
load a modified trustlet in the same environment, and the modified application added a
normal-world-observable output path for plaintext that the genuine code had already decrypted. That
distinction is what makes the route transferable in principle and untransferable in practice
([§8.4](#84-binding-to-exact-binaries)).

### 4.3 Interface and instrumentation

Reverse engineering located three [interface
commands](https://github.com/Trustonic/trustonic-tee-user-space) on the trustlet: one that loads and
processes the attestation keybox object, one for attestation identifiers, and one that closes the
session.

The patch changes exactly two branch targets, and the shape rather than the addresses is the
finding. The first hook fires after decryption completes and before the parser is called, saving the
plaintext pointer and length. The second fires after the parser completes and before the handler
returns, copying the saved plaintext into the mapped buffer. Both hooks are additive: the original
decryption runs, the original parser runs, and the original return value is preserved.

Preserving the return value is what allows the operator to exclude the case of a successful return
with incorrect content, which is the most common false positive in this area ([part 3
§1.1](3-detection.md#11-states-that-resemble-success)).

The normal-world side is a direct client of the environment's communication library rather than the
Java keystore interface: it opens the device and the trustlet by identifier, maps a buffer, notifies
and waits. In its provisioning variant it issues the trustlet's P-256 key-generation command
followed by a close.

### 4.4 Layout of the plaintext

The decrypted keybox is not XML but a length-prefixed sequence, and the expected output for this
device is exact: a version or keybox-number field of 1; an EC private key in
[DER](https://www.itu.int/rec/T-REC-X.690) of 138 bytes with three certificates; an RSA private key
in DER of 1794 bytes with three certificates; a total plaintext length of 8624 bytes; and 92 bytes
of tail that the copy did not overwrite.

That last figure matters. The copy is shorter than the buffer, so 92 bytes of the original input
survive at the end. Treating the whole mapped buffer as plaintext yields a trailing fragment of
unrelated input that can still parse as plausible DER. A parser must read the length prefix, confirm
each length against the DER object's own internal length, and never work from fixed offsets, a rule
[part 3 §1.5](3-detection.md#15-parsing-discipline) generalises.

### 4.5 The derivation call site and its label

A second, independent patch variant targets a key-derivation call site rather than the keybox
parser, and records the production call's own arguments at the hook: label `"rkp_bcc_km"`, label
length 10, output length 32, mode 1, with the evidence recorded as the label, a derivation status of
zero, a 32-byte output length, a pointer marker, and the SHA-256 of the seed alone.

Two cross-checks make this more than one record's assertion. The recorded label length equals the
length of the string, so the label is the string itself rather than a placeholder. And
`Duck-ToolBox`, an unrelated implementation, ships exactly that label as [its
default](https://github.com/eltavine/Duck-ToolBox/blob/main/ui/src/features/rkp/draft.ts) and
derives with an [AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493) [counter-mode
derivation](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) over a big-endian counter
concatenated with the label. Two independent codebases converging on one ten-character label is good
evidence that the label is real for this application family.

Route A records a different label on Qualcomm
([§3.2](#32-derivation-and-storage-of-the-leaf-secret)). The label is per-platform and must be
established on the target rather than assumed; [§9.3](#93-scope-of-the-label-measurement) states
what that costs a previously published measurement.

### 4.6 The negative control

The same direct client is run against the stock trustlet and the mapped buffer compared before and
after the call. It does not change.

That is what establishes that the stock path emits no plaintext, and therefore that the plaintext
later observed came from the patch rather than from the buffer's prior contents. A result without
this control is not interpretable, and [part 3 §1](3-detection.md#1-acceptance-criteria) is built
around the point.

---

## 5. Route C: caller-gate relaxation on a Beanpod keybox application

A key leaves the device: a factory keybox with both EC and RSA keys and full chains. The source is
chapter 2 of the retrospective recorded in [appendix B](B-record-three-devices.md) and the matching
corpus chapter. This is the best-evidenced of the three extraction routes: the acceptance record is
complete and every stage carries a digest.

### 5.1 Environment

A Redmi Note 11T Pro, vendor device `xaga`, on MIUI `V13.0.5.0.SLOMIXM`, kernel
`5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928`. Slot `_b` only; slot `_a` was kept stock
throughout. The environment is Beanpod on L4Re: the service stopped before extraction is
`vendor.keymint-beanpod`, the loader is an L4Re module, and the build gate includes a digest check
on that module. The keybox application and the loader are both pinned by SHA-256.

The published HexHive [FIASCO](https://nebelwelt.net/blog/2025/1227-fiasco.html) chain targets the
same environment family on a sibling handset, reaches exception level 3 and leaks a
content-protection key, and its [65
slides](https://hexhive.epfl.ch/publications/files/25CCC-presentation.pdf) contain no occurrence of
*attestation*, *keymaster*, *keymint*, *RKP*, *DICE*, *CDI*, *UDS* or
*[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox)*. Route C
targets the same environment family, the same vendor and a sibling handset, and its object is the
attestation keybox. The two results are independent and complementary: one published the privilege
escalation without touching attestation, and the other touches attestation without needing the
escalation.

### 5.2 The application container

The keybox application is not a bare ELF object. Container metadata read locally records an `ENC-TA`
magic, a payload size of 14,760 bytes with a 473-byte trailer at that offset, a header
[CRC-32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check), an encrypted image of 15,233 bytes,
and a decrypted ELF of 14,760 bytes whose magic was verified. Both the stock and patched digests are
recorded.

The loader parses the container, unwraps the symmetric material with an internal RSA key, recovers
an [AES-CTR](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) key and
initialisation vector, decrypts the ELF, verifies the payload digest, and hands the application to
the secure world.

The RSA key that unwraps the container is embedded in the loader and recoverable. The metadata
records a 1024-bit key at a known loader file offset, with public exponent 65537 and all
Chinese-remainder parameters present and self-checked: `P·Q = N`, `QINV·Q ≡ 1 (mod P)`, `DP = D mod
(P-1)`, `DQ = D mod (Q-1)`. The private factors are not reproduced here; the finding is their
presence, location and bit length. The unwrapped symmetric material is 60 bytes following a PKCS#1
v1.5 separator, carrying an encryption flag, a protocol version, a 16-byte key, and a 16-byte
initialisation vector whose low 8 bytes are zero, which is counter mode with a 64-bit nonce and a
64-bit counter.

The signing key was not obtained, and the record says so. Having no original signing private key,
the modified application's vendor signature cannot genuinely become valid. The patched application
is re-encrypted but not re-signed, and the loader has to be made to continue past the failure.

### 5.3 Two neutralised decisions

A two-instruction patch set, each instruction replaced by a no-operation. In the loader, the branch
that acts on the signature-verification result no longer aborts the load. In the keybox application,
the comparison feeding the caller-mode gate on the read handler no longer rejects a plain client.

Neither instruction removes a cryptographic check. Each neutralises one decision taken on the result
of a check that still runs: the container is still parsed, the key still unwrapped, the image still
decrypted, the digest still computed. The command-type and parameter-type checks were deliberately
left intact, because deleting the dispatcher gate wholesale would have produced an unbounded
invocation surface rather than a bounded read experiment.

The builder refuses to run unless the stock digests, the original instruction bytes, the sizes, a
counter-mode round-trip read-back and the loader module digest all match, which is
[§8.4](#84-binding-to-exact-binaries) in practice.

### 5.4 Extraction

Deployment writes only the little-kernel and environment partitions of the [inactive
slot](https://source.android.com/docs/core/ota/ab), after verifying serial, product, kernel, slot,
partition sizes and all four partitions' stock digests, with pre-write backups, full read-back
verification and automatic restoration on any mid-flight failure. The patched application is then
[bind-mounted](https://man7.org/linux/man-pages/man8/mount.8.html) over the stock path at runtime
rather than written to the vendor partition, so that a reboot restores the factory application.

Extraction then invokes one existing read command only; the write commands on the same dispatcher
are never opened. The success output records a zero status from context initialisation, session open
and command invocation, a payload length, a descriptor length, and an explicit verification marker.

### 5.5 Descriptor and payload format

```
descriptor (168 B)                       payload (8578 B)
  magic 0x12345678                         length prefix
  payload length                           EC private DER
  two key/certificate entries              EC certificate chain
  per-entry offset / size / count          length prefix
  payload digest (MD5)                     RSA private DER
                                           RSA certificate chain
```

For this round a payload SHA-256 and [MD5](https://www.rfc-editor.org/rfc/rfc1321) are recorded, and
the descriptor's embedded digest equals the computed payload MD5.

The figures 168 and 8578 describe this round's sample and not the format. They constitute a
structural gate rather than a proof of success, and a parser must not trust the descriptor's offsets
alone: the payload carries its own length prefixes, which must then be confirmed against each DER
object's internal length.

### 5.6 Acceptance record

For both algorithms the public key recovered from the private DER equals the leaf certificate's
public key; each chain has three certificates; and [`openssl
verify`](https://docs.openssl.org/master/man1/openssl-verify/) returns a pass. The EC private DER is
121 bytes here against 138 on Route B, the same [SEC1](https://www.secg.org/sec1-v2.pdf) object with
and without its optional parameters and public-key fields, which is why fixed-offset parsing fails
across devices.

Both chains terminate in one self-signed root whose serial number is `f92009e853b6b045`, the same
RSA Google root serial to which the 551 factory keyboxes of [part 4
§4.1](4-measurements.md#41-the-public-factory-corpus) chain, which independently places this
material in the factory population rather than the provisioned one.

The leaf certificates carry a ten-year validity, categorically unlike the roughly two-week
provisioned leaves of [part 4 §2.1](4-measurements.md#21-leaf-validity-by-material-class), and that
is why [part 3 §4.3](3-detection.md#43-expiry-by-provisioning-method) can use leaf lifetime as a
class discriminator.

---

## 6. Route D: same-boot capture of the DICE leaf secret

A key leaves the device: the final leaf identity scalar, the one object in
[§2.2](#22-five-distinct-secrets) that constitutes a renewable provisioning identity. The source is
chapter 3 of the retrospective recorded in [appendix B](B-record-three-devices.md) and the matching
corpus chapter.

The handset is a Redmi K70E, codename `duchamp`, on MediaTek MT6897; every step in the corpus gates
on the device name. Its environment is MiTEE, which [part 4
§6](4-measurements.md#6-the-measured-platform) establishes independently to be a
[Zircon](https://fuchsia.dev/reference/syscalls) and [Fuchsia](https://fuchsia.dev/) secure
operating system rather than an [OP-TEE](https://optee.readthedocs.io/) core, a determination that
decides which published vulnerabilities can apply at all.

That is also the device model named inside one of the two leaked keyboxes' provisioning extension
([part 4 §3.2](4-measurements.md#32-label-dictionary)). Section
[§10.3](#103-conjectures-not-advanced) works through what that convergence does and does not
establish.

### 6.1 Revision of the objective

The round began aiming at an early device secret or root seed, and six findings forced a different
objective: the raw identifier, the final leaf and the native per-key scalar are different objects
([§2.2](#22-five-distinct-secrets)); the final leaf is measurement-dependent; patching the
environment or a boot component changes the downstream chain; a 32-byte value from which a public
key can be derived is not thereby the device secret; the earlier the stage, the more it contaminates
later measurements; and holding one identity value does not by itself permit construction of a
request the backend will accept.

The replacement objective is a seven-step sequence: establish a stock baseline; separate the raw
identifier from the final leaf; capture the final leaf within one secure-world boot; build the
software request from that same round's chain and device information; generate a new software P-256
key; obtain the backend's chain over that key; and restore the device.

### 6.2 Exact-frame patching

What was patched requires precision. The vendor RSA signature bytes were not forged and the verifier
still runs; body and header digests are preserved. What changed is the secure-boot provider's
handling of the verification return value: a non-zero result no longer immediately blocks the
subsequent load, while container parsing, decompression and the length contract must all still hold.
Describing this as a forged signature would misstate both the location of the defect and the
capability obtained. It is a loader error-handling boundary, the same class as Route C's loader
branch.

Early attempts rendered the device unbootable. Full-image recompression candidates destroyed the
[LZ4](https://github.com/lz4/lz4) frame tail, the certificate window or the device tree, and the
handset halted at the boot logo. The conclusion drawn at the time, that all environment patches halt
at the logo, was wrong. The constraint is the compressed-frame and loader contract, and the approach
that works is exact-frame: preserve the original frame structure, change only the minimum bytes near
the target instruction, keep the decompressed length identical, leave every other compressed block
byte-identical, leave the frame tail, certificates and device tree untouched, and re-verify image
structure and digests.

### 6.3 One-shot binding at boot

The dynamic experiment does not leave a patched image on disk. It stages a stock restore image;
triggers only when target device, slot and digest all match; boots the candidate image for that boot
only; captures the same-round leaf and certificate request; and restores the on-disk image to stock
once the system is up, without restarting the current secure world. The next boot is stock.

After boot completes the on-disk image is stock, and that does not establish that the candidate
image did not run. The restoration returns the disk to a safe state while preserving the results of
the current secure-world boot. What must be examined jointly, rather than the disk image, are the
boot markers, the runtime namespace, the application digest, the restore record and the boot
identifier.

### 6.4 Same-round capture

Capture order is mandatory, and follows from [§2.3](#23-consequences-of-conflation):

```
stock or approved research environment
  -> native zero-key certificate request
  -> verify that round's chain, outer signature and device information
  -> capture the final leaf scalar
  -> derive its public-key information
  -> constant-time comparison against the leaf public key of the same round's native request
  -> save the identity only on a match
```

The anti-pattern is to capture a 32-byte value, find a certificate request days later, staple the
two together and submit them. It cannot work, because the leaf is measurement-bound: request, chain,
device information, challenge and identity scalar must all come from one round.

The baseline the corpus records for this device is the gate: a SHA-256 of the device secret
public-key information, and a SHA-256 of the leaf public-key information. A candidate offline seed
is accepted only if it reproduces those public keys, independently verifies a request under a fresh
challenge, and yields a returned leaf matching the saved private key.

### 6.5 Two keys that must differ

```
leaf identity private key              software P-256 private key
  -> signs the device-identity request    -> its public key enters keysToSign
  -> the backend validates chain          -> the backend signs that public key
     and device information               -> returned leaf public key == software public key
```

Requiring these two to be equal judges a correct outcome a failure. The identity key establishes
that the request came from this device; the software key is the one that will carry subsequent
attestation. `Duck-ToolBox` implements exactly this division: the request identity comes from the
configured seed or hardware key, while the key array carries freshly generated P-256 keys with
[rejection sampling](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf).

### 6.6 A causal correction

An early round returned a `NOT_APPROVED` verdict, which was attributed to the modification of the
chain. That round, however, changed several variables together: a modified chain, plus historical or
mismatched device information, plus a new challenge, request and server state. It therefore shows
only that the combination failed.

A later control kept the same modified chain and substituted clean device information matching the
target device profile, and recorded an approval. What that licenses: a modified chain is not a
sufficient rejection condition; the complete device-information tuple and the server-side registered
profile are plausibly decisive gates; the control is evidence from decomposing a combination rather
than a single-field proof; and without a single-field comparison no individual field can be named as
the root cause.

The second half of the correction concerns a verifier fault rather than a protocol fact. An early
acceptance parser dropped unknown fields of the [provisioning-information
extension](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension)
and so marked a certificate carrying a `NOT_APPROVED` verdict as a pass. The root cause was not a
signature error; the signatures were sound. The verifier lost the server's status field. Hence the
rule this report adopts:

```
X.509 and DICE signatures mathematically valid
          !=
server-side provisioning status acceptable
```

Unknown fields must be preserved, the status gated on explicitly, and never overridden by a digest
match or a chain verification.

---

## 7. Off-device certificate minting

The routes supply a signing capability. This section concerns what is done with one, and unlike the
acquisition half it is fully reconstructed, with every gate in it either inapplicable or free. It is
reconstructed from two independent normal-world implementations,
[`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw) and
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), and from the two leaked
keyboxes whose bytes [part 5 §5](5-sources.md#5-provenance-of-the-keybox-samples) traces to one of
them.

### 7.1 The procedure, gate by gate

*Step 1: hold a 32-byte seed for a registry-recognised identity.* This is the acquisition problem of
[§3](#3-route-a-a-signing-oracle-on-qualcomm-keymint) to
[§6](#6-route-d-same-boot-capture-of-the-dice-leaf-secret). Everything after it is inexpensive.

*Step 2: build a degenerate chain* — a bare device-secret
[COSE](https://www.rfc-editor.org/rfc/rfc9052) key plus one self-signed
[COSE_Sign1](https://www.rfc-editor.org/rfc/rfc9052#section-4) entry, with an empty certification
map. The gate that should prevent this is the [test
suite](https://source.android.com/docs/core/tests/vts) requirement for a multi-stage chain, and it
is inapplicable: that requirement is hard only where a secure element is declared at vendor API
level 202404 or later, and the measured handset declares none ([part 4
§6.1](4-measurements.md#61-handset-and-environment-census)). Degenerate deployment is an [officially
supported
phase](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/README.md)
([part 1 §4.5](1-protocol.md#45-legal-chain-shapes-and-deployment-phases)), so this is a conforming
request rather than a malformed one.

*Step 3: generate P-256 key pairs in software and place bare keys in the key array.* The gate is the
authentication tag ([part 1
§2.4](1-protocol.md#24-key-generation-and-the-authenticated-public-key)), and it is structurally
inapplicable rather than merely weak. The
[grammar](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl)
types the field as bare keys. The application verifies each tag and then strips it; the reference
implementation pushes only the encoded public key into the payload. The tag never leaves the device,
so the backend receives no cryptographic evidence that any submitted key was generated inside a
trusted application. Forging a tag is unnecessary, because whoever signs the request bypasses the
check entirely.

*Step 4: post to the endpoint-key endpoint with an unsigned, operator-typed fingerprint, then post
the request.* The gate is the registry match on the device secret public key, and it passes, because
the seed belongs to a registered device. The only failure mode is HTTP 444. And there is nothing
else to pass: the daemon's own transport layer sets no API key, no client certificate and no pinning
([part 1 §5.2](1-protocol.md#52-the-protocol-exchange)), so the endpoint is reachable by any client
that can produce a valid signature.

*Step 5: the backend stamps the provisioning extension and signs.* Two gates exist here on paper and
both were inert in the measured cases. The
[grammar](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV3.cddl)
makes the verified-boot metadata digest mandatory, and one leaked sample's request omitted it and
was signed anyway. And the documented abuse counter read 512 against a measured stock baseline of 8,
so the backend's own abuse signal was saturated inside the signed certificate while issuance
proceeded ([part 4 §3.3](4-measurements.md#33-issuance-counts)).

*Step 6: emit a keybox file, which a module manager copies over the consumer's keybox path.* No
gate; this is the ordinary install flow on an already-rooted consumer device.

The yield is unbounded Google-signed P-256 leaves under a live intermediate, roughly fourteen days
each, from one identity, indefinitely, with the donor handset destroyed, resold, or never touched
again.

### 7.2 Persistence of the seed

The registry holds the device secret public key that the manufacturer extracted at manufacture. Were
the seed random and stored in wipe-visible storage, a factory reset would change that public key and
permanently reject the handset, behaviour no shipping fleet exhibits. The object therefore survives
a wipe. This is an inference from observed fleet behaviour rather than a measurement.

The honest boundary is that survival of a wipe is all this forces, and not derivation from fuses.
The measured KeyMint application on the handset of [part 4
§6.3](4-measurements.md#63-storage-of-the-dice-secret) carries a migration of exactly this object
from a secure file system to [replay-protected
memory](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#rpmb-secure-storage),
and that storage survives a userdata wipe, so random-once-then-persisted is consistent with
everything observed.

The consequence is the distinction of [§2.4](#24-supply-and-sample). A seed has no expiry, is never
rotated, and appears in no certificate that could be revoked. The fourteen-day leaf lifetime is the
operator's refresh cadence rather than a decay function.

### 7.3 Components the procedure does not need

It does not need a hardware key ladder. The Python implementation once carried a hardware-key path
with a counter-mode derivation, documenting itself as the derivation observed in environment calls,
and its own documentation stated that on real devices the key resides in a system-on-chip internal
key ladder and is not software-accessible. Current upstream has removed that path entirely, leaving
only a bare seed input, and has added a P-256 curve option. The operative input is therefore one
32-byte seed of unstated provenance, and the only party known to have held a working one asserted no
extraction capability.

It also does not need the `ProtectedData` structure, and this retires an inference the earlier
record carried. Finding that structure computed and then discarded in a tool was listed among the
signs that the tool had never been run. The third failure mode of
[§3.6](#36-procedure-and-failure-modes) gives the benign explanation: version 2 has no such field,
and both independent implementations construct it regardless. That indicator is withdrawn; the
others in the same adjudication — a hardcoded empty certification map, the repository hygiene, the
unanswered issue — are unaffected ([part 5 §5.4](5-sources.md#54-corrections-of-record)).

---

## 8. Common structure of the four routes

### 8.1 Decisions rather than primitives

Route A: an authentication-tag parser that is not called on one path. Route B: a load boundary
relaxed enough to admit a modified trustlet. Route C: one branch on a signature-verification result,
and one caller-mode comparison. Route D: one error branch on a loader's verification return.

In no route is a cipher broken, a key factored or a digest forged. Every cryptographic check still
executes; what changes is what the code does with the result.

The defensive consequence is direct. Auditing cryptography finds none of these. What finds them is
asking, for every check, what happens on failure, and whether any path reaches the protected
operation without the check having been consulted at all.

### 8.2 Observation of existing cleartext

Route B copies plaintext the authentic decryption produced. Route C invokes the authentic read
handler. Route D captures the authentic derivation's output. Route A never sees the secret and still
obtains the signature.

This generalises an older observation about key handling inside a trusted environment, the one
[Quarkslab's relay work](https://blog.quarkslab.com/bypassing-android-hardware-attestation.html)
rests on: at the right instant the secret is plaintext in a buffer, and the problem reduces to
getting code to run there at that instant. Encrypting a secret at rest protects it against a cold
lift and against nothing else, which is why the cold-lift candidate of
[§9.1](#91-the-candidate-field) collapses into the lane above it.

### 8.3 Entry and exit as separate problems

*Entry* takes the form of a boot chain admitting a component, a container mishandling a failure, a
caller gate loosely bound to a command, plaintext with an observable lifetime, or a request path
omitting key-provenance binding. *Exit* takes the form of a mapped buffer, a descriptor and payload,
a certificate request, a signed-data structure, or a returned certificate chain.

Establishing entry does not establish exit. The negative control of [§4.6](#46-the-negative-control)
is the discipline this implies, and the five states of [part 3
§1.1](3-detection.md#11-states-that-resemble-success) are what occurs without it.

### 8.4 Binding to exact binaries

Every route's patch is bound to exact binaries. Route C's builder gates on the stock application,
loader and module digests and refuses to run otherwise. Route B gates on three input digests. Route
D gates on device, slot and digest before the one-shot binding fires.

The consequence is that an [over-the-air update](https://source.android.com/docs/core/ota), a
downgrade, a kernel change, a slot change, or another handset of the same model requires
re-disassembly. These are routes rather than tools. It also bounds the threat usefully: an operator
can reuse a route across a fleet of identical units only by repeating the analysis per unit, which
is why the economics favour the single captured seed of [§7](#7-off-device-certificate-minting) over
repeated extraction.

### 8.5 Boot-bound identity

Section [§2.3](#23-consequences-of-conflation) as an operational constraint: because the leaf
identifier folds in every measured component, a captured identity belongs to the boot that produced
it. That is what forces Route D's one-shot design ([§6.3](#63-one-shot-binding-at-boot)), what makes
the capture order of [§6.4](#64-same-round-capture) mandatory, and what makes capture now and mint
later structurally impossible rather than merely unreliable.

A successful capture is therefore self-limiting for the attacker in a way that a factory keybox is
not: the identity ceases to work when the device's measured state changes. Against that, the
observation of [§7.2](#72-persistence-of-the-seed) that the seed survives a wipe is the
counterweight, the seed being stable even though a leaf derived under a patched boot is not.

### 8.6 Unlock requirements

Three of four routes require an unlocked bootloader and a controlled boot-chain load. Route A
requires root only.

This inverts an expectation. The candidate design that appeared most attractive, normal-world root
into a sibling-application compromise ([§9.1](#91-the-candidate-field)), was attractive precisely
because it passes without unlocking, and the routes that produced results are the unlock-requiring
ones. The one route that needs no unlock arrives there by not taking a secret at all.

### 8.7 Comparison

| | A (Qualcomm) | B (Kinibi) | C (Beanpod) | D (MiTEE) |
|---|---|---|---|---|
| Handset | any Qualcomm, reported | Nothing 2a / `Pacman` | Redmi Note 11T Pro / `xaga` | Redmi K70E / `duchamp` |
| Unlock required | no | yes | yes | yes |
| Root required | yes | yes | yes | yes |
| Environment modified | no | yes, trustlet | yes, loader and application | yes, image, exact-frame |
| Risk to device | none | boot chain | boot chain, slot-isolated | boot chain, auto-restore |
| Object obtained | nothing; a signature | factory keybox, and a 32-byte derivation output | factory keybox, EC and RSA | final leaf identifier |
| Reusable offline | no; the handset must be present | yes | yes | yes |
| Result lifetime | per invocation | leaf expiry | ten years | until a measurement changes |
| Transfers to a sibling unit | plausibly, same chipset family | no; re-disassembly | no; re-disassembly | no; re-disassembly |

---

## 9. Routes refuted before publication

Before the four routes were published, the acquisition problem was attacked by design: seven
end-to-end schemes, each reviewed through three adversarial lenses — stage-to-stage entailment,
citation audit, and parsimony. Twenty of twenty-one verdicts refuted the scheme under review or
reduced it to conjecture.

The refutations are measurements, several of them transfer to other platforms, and the one candidate
that survived proved to be the one the published routes avoid.

### 9.1 The candidate field

*Non-technical custody* requires no unpublished primitive: insider or provisioning-line access where
the device secret public key is extracted and uploaded, an authorised service or repair channel, a
pre-production or unfused unit registered in the same bulk step, or a purchased seed with no
upstream knowledge. Each produces a byte-identical artifact, and the leaked samples carry positive
evidence pointing this way ([part 5 §5.3](5-sources.md#53-claims-not-established)).

*Normal-world root into a sibling-application compromise* was the strongest technical candidate, and
its first three stages all pass. Stage 1 reaches arbitrary kernel physical read and write and
disables SELinux on a locked stock handset: the [public one-click
tool](https://github.com/Colorful-glassblock/duchamp-root) for that handset chains an
[address-layout](https://en.wikipedia.org/wiki/Address_space_layout_randomization) leak through a
[futex](https://man7.org/linux/man-pages/man2/futex.2.html) requeue race
([CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499)) to a forged pipe-operations
table, and its own prerequisites note that the delivery mechanism works whether or not the
bootloader is unlocked ([part 4 §6.5](4-measurements.md#65-normal-world-root)). Stage 2 copies the
normal-world files backing the environment's [secure file
system](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html), SELinux being off
and the files ordinary. Stage 3 drives one of five device-reproduced
[TÄMU](https://arxiv.org/abs/2601.20507) defects that ship on this handset, two of them
arbitrary-read, into code execution inside the secure world ([part 4
§6.4](4-measurements.md#64-published-application-vulnerabilities)). Stage 4 is the problem: crossing
from that application to KeyMint's own secret. No published primitive bridges it.

*Cold lift of the sealed storage object* collapses into the candidate above. The object's ciphertext
resides in normal-world storage and root copies it trivially; nothing in the normal world advances
past that, because the sealing key is derived from a [hardware unique
key](https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html#hardware-unique-key)
inside the environment. Conditional on code execution with the application's identity the lift is
unnecessary, since the object can be opened through the ordinary interface; absent that, the lift is
useless. No encrypted trusted-storage blob has appeared in circulation, while seeds and finished
keyboxes have.

*A boot-stage or preloader route* remains conjectural. A [vendor
advisory](https://corp.mediatek.com/product-security-bulletin) in the right stage, with the right
primitive class and access model, listing the right chipset among its affected parts, predates the
mints by six months. Three considerations prevent it from being the answer: it speaks of
identifiers, and a chip identifier is by design a public value used in secure boot; its affected
list spans 35 chipsets, so the presence of any one is near-uninformative; and no source ties it to
DICE material.

### 9.2 Refutations by measurement

*An identifier squat* — serving an older signed KeyMint application for the same identifier so as to
inherit its storage namespace — requires two unpublished primitives in series, and the second does
not substitute for the third: an older genuine signed application is an older genuine application
faithfully performing KeyMint, not attacker code reading a secret. Its premise of transfer from
upstream also fails, because the container magic is not OP-TEE's ([part 4
§6.6](4-measurements.md#66-the-application-container)).

*Deleting a version floor* so as to replay any signed application fails on measurement: no version
field exists anywhere in the signed container header across 38 images, so there is no floor in the
header to reset; the platform's version store resides in a secure-world loader service rather than
in a normal-world file a root process could delete; and the four applications worth downgrading to
were never rebuilt at all, so there is nothing to roll back to ([part 4
§6.6](4-measurements.md#66-the-application-container)).

*A deprivilege-window capture* on the normal-world side of a hardware-backed certificate service was
refuted by the device's own binaries: no
[Trusty](https://source.android.com/docs/security/features/trusty) port name and no Trusty
communication device node appears in any of the handset's 17 applications; the KeyMint HAL's link
against the Trusty client library is an unused dependency with zero corresponding undefined symbols,
its only transport symbols being the five [GlobalPlatform
client](https://globalplatform.org/specs-library/tee-client-api-specification/) calls; and the
device speaks an older command interface than the AOSP service being reasoned about. The oracle
under analysis was not the code this device runs.

*A signed-custody ladder read*, in which secure debug drives the chip's derivation service, is
stage-incoherent: a download agent displaces the boot chain, so in download mode there is no
environment and no secret in any memory to read. Its arithmetic also fails, the tool computing a
counter-mode construction with no separator byte, no context and no length encoding, which is not
[NIST SP 800-108r1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) [§4.1](#41-environment) and
cannot be what a validated derivation service computes.

### 9.3 Scope of the label measurement

Every scheme resting on the derivation label `rkp_bcc_km` was refuted by measurement: the label is
absent from all 17 applications on the measured handset, from its environment kernel module and from
its KeyMint HAL, along with the derivation function name and a fallback label.

The measurement stands; its scope did not. Section
[§4.5](#45-the-derivation-call-site-and-its-label) records that same label as the live production
argument on Trustonic Kinibi, confirmed twice over, and
[§3.2](#32-derivation-and-storage-of-the-leaf-secret) records a third, different label on Qualcomm.
The label is per-vendor. The refutation of platform-specific schemes resting on it remains correct;
what must not be carried forward is the generalisation that no shipped device uses it. A measured
fact about one platform became wrong only when read as a fact about all of them.

The larger correction is that the published routes sit outside the entire designed field. None of
them crosses from a sibling application. They relax one decision in the component that decides
whether to load an application, run a minimally modified genuine application, and observe the secret
the genuine code path has already decrypted. The candidate class may be called substitution of a
boot-chain or container error branch. Its cost is an unlocked bootloader, exact-version binding, and
a risk to the device that the sibling-application candidate does not carry.

This changes the standing conclusion in one direction only. The proposition that no published route
goes from a sibling-application defect to KeyMint's own secret remains true as stated: nobody
published that crossing. But the inference it supported, that device-side acquisition is
unreconstructed, no longer follows, because the crossing proves to be avoidable. Becoming the
application makes crossing to it unnecessary.

### 9.4 Revision of an inherited assessment

The broader threat model this report inherited assessed device-side extraction of a provisioning
identity as not demonstrated, with very high confidence, on a structural argument: the downstream
minting tooling takes the seed as a command-line argument it cannot obtain, and the tool's only open
issue, how to export a leaf seed from a handset, was unanswered.

That structural argument is answered, and the four routes are the answer. The assessment belongs at
reported but not independently reproduced, with moderate confidence that no verified public
demonstration exists and low confidence that the capability does not exist. The distinction the old
assessment was built on survives — no peer-reviewed result demonstrates this, and nothing in this
report was reproduced on hardware — but the argument that the tooling cannot obtain its input can no
longer be carried as the reason, because four named mechanisms for obtaining it have been published.

Route A changes the question rather than answering it. It reaches a Google-signed chain without
extracting any seed, so the proposition as phrased, that a leaf identifier be extracted, can be
false while its consequence, minting Google-rooted chains over attacker-chosen keys, is achieved. A
proposition about key extraction is the wrong thing to assess; the question is whether an adversary
can obtain Google-signed chains over keys of their choosing, and the answer is that two independent
mechanism classes achieve it.

In the custody terms of [§2.1](#21-custody-classes), routes B, C and D are the first published cases
of class H by replacement of a trusted application rather than exploitation of one, and Route A is
class G with the oracle inside the target handset: the same architecture previously published across
two handsets, collapsed onto one, with a named missing check in place of an instrumentation hook.

---

## 10. Limits of the evidence

### 10.1 Support for each principal claim

*Measured locally, and so the firmest.* That the wire format of `Duck-ToolBox` matches the
independently disassembled one ([§3.5](#35-request-format)); that its five gating checks and vendor
exclusions are as stated ([§3.9](#39-preconditions)); that the Kinibi derivation label is the
default of an unrelated implementation ([§4.5](#45-the-derivation-call-site-and-its-label)); that
the label, the derivation function name and a fallback label are absent from every measured binary
of the platform in [§9.3](#93-scope-of-the-label-measurement); that no version field exists in the
container header across 38 images ([§9.2](#92-refutations-by-measurement)); that the implementation
has neither a provisioning-status gate nor [X.509](https://www.rfc-editor.org/rfc/rfc5280) signature
verification ([part 3 §1.4](3-detection.md#14-gates-the-chain-does-not-supply)); and that a Pixel 7
fails three of the five gates ([§10.4](#104-a-negative-case-the-pixel-7)).

*Read from an artifact rather than narrated.* Route C's container metadata, the location and bit
length of the embedded unwrapping key, and its stock and patched digests
([§5.2](#52-the-application-container)); Route C's acceptance record
([§5.6](#56-acceptance-record)); Route D's device gate and baseline public-key digests
([§6](#6-route-d-same-boot-capture-of-the-dice-leaf-secret), [§6.4](#64-same-round-capture)); the
stock issuance baseline ([part 3 §4.2](3-detection.md#42-the-provisioning-information-extension));
and the per-stage digest gates in every builder ([§8.4](#84-binding-to-exact-binaries)).

*Reported by a record whose execution was not re-run, and therefore to be treated with most
caution.* That Route A's request handler omits the tag verification and that the parser is
referenced only from two other commands ([§3.4](#34-the-omitted-verification)); that Route A yields
a Google-signed chain in practice ([§3.7](#37-result)); that a hardware-derived value is returned
with no provisioning gate ([§3.8](#38-a-second-reachable-secret)); that an arbitrary build
fingerprint is accepted ([§3.7](#37-result)); and that routes B, C and D were executed as recorded
([§4](#4-route-b-plaintext-observation-in-a-kinibi-trustlet) to
[§6](#6-route-d-same-boot-capture-of-the-dice-leaf-secret)).

*Inferred from graded facts.* That the issuance count is a logarithmic bucket, now from five
observations including one that is not 512 ([part 3
§4.2](3-detection.md#42-the-provisioning-information-extension)); and that a seed survives a factory
reset ([§7.2](#72-persistence-of-the-seed)).

What would settle each reported claim: an independent disassembly showing the same cross-references;
a returned chain whose leaf public key matches a host-generated private key, together with the
invocation trace; one invocation on any production handset of that platform; a rejected request
differing only in the fingerprint; and independent re-execution from the stock inputs through each
builder's gates.

### 10.2 The unbridged step

Reaching another application's secret from a compromised sibling requires either a secure-kernel
compromise or a defect in the shared storage service. Neither is published, and the architecture of
the measured platform narrows the question rather than widening it: the platform relocated the
secure-storage stack out of the secure kernel and into a userspace service that holds the device's
hardware unique key and handles every application's plaintext objects ([part 4
§6.3](4-measurements.md#63-storage-of-the-dice-secret)). The target is therefore a named userspace
process rather than an unpublished kernel exploit. But cross-application naming is closed, since the
storage call's identifier parameter was replaced by a selector and the service identifies its caller
over an unforgeable channel.

The candidate of [§9.1](#91-the-candidate-field) therefore establishes opportunity and access rather
than a completed chain: the vulnerable code was never rebuilt and reaching it requires only a public
root, while the crossing remains unpublished. And the correction of
[§9.3](#93-scope-of-the-label-measurement) applies: the objective that the crossing would serve is
reachable without it.

### 10.3 Conjectures not advanced

*That the leaked samples came from the measured research handset.* The convergence is real: the same
device model, the same tool family, and the same week, the research effort's stock baseline, its
submission package and both samples all falling inside a nine-day window. But two signed fields
argue against it. The research device read an issuance count of 8, while both samples read 512,
which would require hundreds of mints inside the same 30-day window from a deliberately rationed,
gated, one-shot issuance posture. And that effort's earlier submission was rejected for carrying a
`NOT_APPROVED` verdict, whereas sample A carries approval in both verdict positions. The conjecture
is not advanced, and the improvement over the earlier position that nothing binds it is that the
reason is now measured. The test that would settle it is a comparison of leaf public keys or
serials.

*That the two samples are one identity.* Unsupported. The device-identifier attribute is random
([part 3 §5.1](3-detection.md#51-fields-a-keybox-holder-authors)) and the leaf common name equals
the certificate's own serial. Neither file carries a device identifier.

*That an issuance count of 512 implies a particular mint rate or a subscription service.* This
requires bucket semantics and a single-key batch size simultaneously, and neither is measured. What
survives is that 512 is extreme against the daemon's own [default extra-key
target](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java)
of 6, and that the backend's abuse signal was saturated while issuance proceeded.

*That a preloader advisory reaches DICE or key-ladder material.* Conjectural, for the three reasons
in [§9.1](#91-the-candidate-field).

*That the seed is derived from an immutable hardware root* rather than generated once and persisted.
Conjectural, and the migration strings of [part 4
§6.3](4-measurements.md#63-storage-of-the-dice-secret) lean against derivation.

### 10.4 A negative case: the Pixel 7

The handset `panther`, a Pixel 7 on Google Tensor GS201, fails three of the five gates listed in
[§3.9](#39-preconditions): the chipset test, the device-node presence test and the vendor-library
presence test, while passing root and the architecture check. The crate's own test asserts that a
Google manufacturer string is rejected.

Root confers nothing here. With no command device node and no vendor library, the only reachable
entry is the binder HAL, which returns an authenticated public key and retains the private half
inside the environment. There is no command channel below it to misuse, so Route A has no surface.
Routes B through D are each bound to a specific environment and a specific loader defect, and this
platform runs Trusty with a [Titan
M2](https://security.googleblog.com/2021/10/pixel-6-setting-new-standard-for-mobile.html) [secure
element](https://source.android.com/docs/security/best-practices/hardware), which none of the four
addresses.

The standing caution applies: Trusty's clean record reflects absent analysis rather than
demonstrated robustness. The absence of a route is a statement about the published corpus rather
than about difficulty.
