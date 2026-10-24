# 2 · Mechanisms of attestation-material compromise

*Where [`1-protocol.md`](1-protocol.md) specifies what the protocol requires, this part records what
has been done to real handsets. Numbers are in [`4-measurements.md`](4-measurements.md); the
provenance and weight of each source is appraised in [`5-sources.md`](5-sources.md); the grading
scheme and the scope rule are [`1-protocol.md`](1-protocol.md) §1.4 and §1.5.*

## Abstract

A faithful simulator needs to know which secret an adversary holds, because the five objects
routinely called "the attestation key" differ in what possession confers and in how long it lasts,
from one key's worth of attestation to the lifetime of a handset. This part separates them, then
reconstructs four published acquisition routes: a signing oracle on Qualcomm
[KeyMint](https://source.android.com/docs/security/features/keystore) that extracts nothing and
needs no bootloader unlock; plaintext observation inside a [Trustonic
Kinibi](https://www.trustonic.com/)
[trustlet](https://github.com/Trustonic/trustonic-tee-user-space); caller-gate relaxation on a
Beanpod/[L4Re](https://l4re.org/) keybox trusted application; and same-boot capture of a final
`CDI_Leaf` under proper
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/). Read together
they share a pattern none of them states alone: in no route is a cipher broken, a key factored or a
digest forged. Every cryptographic check still runs; what changes is what the code does with the
answer, and the secret is then observed where authentic code had already placed it in cleartext. Two
consequences follow for the defensive side. The mechanism class is established with high confidence
while the individual numbers are single-sourced, so the pattern of §8 should be weighted above any
one narrative. And the signals that discriminate a compromised keybox from a sound one are not
cryptographic at all: they are an issuance count and a provisioning status that the backend writes
into the signed certificate, and that essentially no verifier reads.

---

## 1. Introduction

### 1.1 What is being asked

[`1-protocol.md`](1-protocol.md) §6.3 establishes that a synthetic chain is defeated twice over, and
that only two things would make the provisioning check succeed: chaining to a genuine registered
root, or getting a synthetic root registered. The second is a manufacturing-enrollment problem and
nothing public addresses it. This part is about the first: what has to be taken from a device, and
how it has been taken.

The answer splits cleanly. Everything downstream of holding the right secret — building a conforming
CSR, getting Google to sign it, assembling a keybox — is a fully reconstructed, reproducible pipeline
with no unsolved step in it (§7). Everything upstream was an open absence until four routes were
published, and those routes work in a way none of the designed candidates anticipated (§9).

### 1.2 The evidence base, and the weight it carries

Four routes, four trusted execution environments. Route A comes from a public post on a Qualcomm
handset ([kanxue 293244](https://bbs.kanxue.com/thread-293244.htm)); routes B, C and D come from a
single retrospective ([kanxue 293246](https://bbs.kanxue.com/thread-293246.htm)) and the engineering
corpus behind it,
[`gungnir-sanye/tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction).

Three of four from one corpus is not three independent confirmations. They are three different
mechanisms on three genuinely different platforms — [Trustonic
Kinibi](https://www.trustonic.com/solutions/trustonic-secured-platform/), Beanpod on L4Re, and MiTEE
on [Zircon](https://fuchsia.dev/fuchsia-src/concepts/kernel) — from one research effort, and that the
platforms really do differ is the main reason the set is informative. Route A is a separate post on a
fourth platform with a separate toolchain; whether it shares authorship could not be determined, so
it is treated as independent, which is the generous reading in one direction and the risky one in
the other.

Route A is worth more than its single source because its wire format is independently confirmed.
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), an unrelated Rust
implementation, encodes the same command word, the same two
[CBOR](https://www.rfc-editor.org/rfc/rfc8949) labels and the same response wrapping, and neither
source cites the other (§3.5). That agreement is the strongest single piece of corroboration here.

Nothing in this part was reproduced on hardware. What was checked locally is the artifact layer: file
digests, container metadata, patch-script constants, protocol constants against
[AOSP](https://source.android.com/)'s [CDDL](https://www.rfc-editor.org/rfc/rfc8610), and the
arithmetic of every cross-document claim. The retrospective's own front matter declines to assert
that every historical command was re-executed by a human. Per-route claims therefore stay at
*[REPORTED]*; §10 lists what would settle each one, and [`5-sources.md`](5-sources.md) §3 appraises
each record in detail. Weight the pattern of §8 above any single route's narrative.

### 1.3 What this part withholds

Per [`1-protocol.md`](1-protocol.md) §1.5, symbol names, function addresses and command numbers are
given where they identify a defect, because that is what lets a defender look for the same defect
and, in several cases, what lets an independent reader check the claim. Patch offsets, original
instruction bytes and code-cave addresses are withheld, because together they are a ready-to-apply
patch rather than evidence that a patchable decision exists. The distinction costs the reader nothing
analytically: knowing that one branch on a verification result had to be neutralised is the finding;
knowing its address is not.

---

## 2. What is compromised: custody classes, and five secrets

Two orthogonal questions have to be answered before any route makes sense. Who holds the key and who
signs with it (§2.1), which decides whether revocation is even the right remedy. And which of five
different objects was obtained (§2.2), which decides what the holder can then do.

### 2.1 Custody: who holds the key, and who signs

Three custody tags suffice. *Key leaves* means raw private key material exists outside the secure
world in usable form, so revocation and rotation apply. *Used in place* means a genuine secure world
signs attacker-chosen data with a key it still holds, or an attacker signs with a key that was
already outside a secure world; revocation may or may not help, and binding plus behavioural controls
do. *Not applicable* means no secret is involved at all.

The classes are lettered so that [`3-detection.md`](3-detection.md) §9 can score controls against
them.

*A — factory batch-key supply-chain leakage.* Key leaves, from the provisioning pipeline rather than
from a device: the delivery artifact is a keybox XML file whose private keys are in plaintext by
construction at the point of provisioning. Key reuse is normative — the Compatibility Definition
Document requires the same attestation key per SKU unless more than 100,000 units are produced, after
which a different key may be used per further 100,000. The privacy rationale is unlinkability; the
security consequence is that one leak compromises a six-figure device population and revoking it
breaks attestation for every honest owner in that batch. Attacker cost of one file against defender
cost of 100,000 users is the economics of the leaked-keybox market, and this class — not any TEE
exploit — accounts for essentially all observed attestation fraud.
[`4-measurements.md`](4-measurements.md) §4.1 censuses the public population.

*B — the published AOSP software attestation key.* Not applicable: the private key is in public
source control. Rejected by root pinning, and it never chains to Google.

*C — normal-world KeyMint interposition and TA emulation.* Used in place of an already-leaked key.
The attacker's in-process code signs; revocation helps only through the underlying keybox. This is
the class this project implements, which is why [`3-detection.md`](3-detection.md) §6's structural
checks are noted there as defeated by it.

*D — abuse of the factory provisioning path.* The key is written in, not read out: a normal-world
installer hands a keybox to the secure world, which then signs honestly with an attacker-supplied
key. [`4-measurements.md`](4-measurements.md) §6.7 measures such an installer shipping on retail
hardware.

*E — in-place use of genuine device keys.* Used in place: a blob and certificate lifted from the
keystore database and replayed through the attestation-key parcelable, so the genuine secure world
signs attacker-chosen leaves. Revocation does not help, the key being genuine and unrevoked, and the
scope is bounded to the originating device and the certificate's lifetime.

*F — boot-chain collapse below the TEE.* Used in place, with a falsified measured state: the device's
own real, unrevoked key signs an attestation reporting a locked bootloader. There is nothing to
revoke, which is why [`3-detection.md`](3-detection.md) §9's F column is almost empty.

*G — relay and signing-oracle attacks.* Nothing moves. A genuine remote secure world signs the
relying party's challenge and the chain is forwarded. The architectural finding is published:
*"There is no field in the KeyDescription that binds the attestation to the transport, the session,
or the device presenting it. The nonce is the only freshness signal."* No CVE has ever been assigned
to this class, because the mechanism is sound and only the protocol composition is not. §3 is the
same architecture collapsed onto one handset.

*H — secure-world exploitation.* The only class where key material genuinely leaves a secure world.
Two decades of cases share a shape that is widely misreported: the dominant pattern obtains code
execution or arbitrary read in the secure world and then recovers the derived blob-wrapping key so
application keyblobs decrypt offline, or reads a particular TA's plaintext key material, almost never
the KeyMint attestation root key itself. The canonical case is a keyblob-KDF flaw whose own paper
states the consequence: the TA continues to sign attestation certificates honestly, for keys the
attacker can subsequently extract. Every downstream property the certificate implies — device
binding, non-exportability, auth-bound usage — collapses while the chain verifies perfectly. That
paper's most transferable finding is that the attestation does not commit to the cryptographic method
used to secure the key, nor even to the TA's version, so a relying party cannot express "only accept
keys secured by a non-vulnerable key-derivation version", and the patch level does not disambiguate
because one firmware supported both. §4 and §5 are modern instances;
[`4-measurements.md`](4-measurements.md) §6.2 shows that an earlier published chain on a sibling
handset is architecturally inapplicable to the platform measured here.

*I — privileged exposure of the DICE chain and `UDS_pub`.* Key does not leave: this is an identifier
leak. A root process that defeats
[SELinux](https://source.android.com/docs/security/features/selinux) calls the certificate-request
method itself and receives, in cleartext CBOR, the `UdsCerts` map and the whole chain — `UDS_pub`
plus every firmware code, configuration and authority hash. Enforcement is SELinux and
[binder](https://source.android.com/docs/core/architecture/hidl/binder-ipc) access control, not
cryptography. This is a privacy and fingerprinting exposure: a permanent, unresettable,
reset-surviving device identifier plus a precise firmware inventory and an offline oracle for which
firmware a device runs. It is not a path to forging requests for another device, because the request
signature needs the leaf private key, which stays inside the component and is constrained to request
structures.

*J — RKP relocates supply-chain trust rather than eliminating it.* No device key is extracted; a
genuine backend signs for a fraudulent identity. The anchor moves from a key burned into a production
run to a registration event on a factory line ([`1-protocol.md`](1-protocol.md) §6.1), and §7 is what
happens when one registered identity is captured.

*K — trusted-application rollback.* Nothing by itself; a force multiplier for H.
[`4-measurements.md`](4-measurements.md) §6.6 measures why one platform's container makes it
attractive, and §9.2 records why two designed schemes resting on it still failed.

*L — fault injection and physical attack.* Mixed custody, and out of scope as a procedure
([`1-protocol.md`](1-protocol.md) §1.5).

Exactly two classes, A and H, involve raw private key material outside a secure world, and A accounts
for essentially all observed fraud. Every other class is a genuine secure world doing what it was
asked, which is why patching TEEs and rotating keys does not fix them, and why
[`3-detection.md`](3-detection.md) is the other half of this part.

### 2.2 Five secrets that are not the same secret

The retrospective names the conflation of these objects as the most common error in the area. They
are not interchangeable and not even the same kind of thing.

A *factory attestation keybox* holds EC and RSA batch private keys with Google-rooted chains,
provisioned at manufacture and shared across a production run. It buys the ability to sign
attestation leaves offline, indefinitely, until Google revokes the batch. Measured leaf lifetimes run
about ten years on the one measured in §5.6.

The *[Unique Device
Secret](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md)* is the
immutable hardware root of the DICE chain ([`1-protocol.md`](1-protocol.md) §4.2). It buys everything
below it, for the lifetime of the handset. No published route obtains one.

A *raw CDI* is an intermediate [Compound Device
Identifier](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md)
captured before the remaining boot stages have folded their measurements in. It buys nothing
directly: it is an input to further derivation, and a 32-byte value that successfully derives some
public key is not thereby a UDS or a usable identity.

The *final `CDI_Leaf`* is the scalar that signs the outer `AuthenticatedRequest` of an RKP
certificate request. It buys a renewable provisioning identity: the holder can mint Google-signed
chains over arbitrary locally generated
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) keys, repeatedly,
until a measured boot component changes. This is the object Route D takes and the object the
off-device pipeline of §7 consumes.

A *native per-key scalar* is the private key KeyMint generated for one specific RKP attestation key.
It buys one key's worth of attestation, and it closes only against its own `MacedPublicKey` and leaf.

### 2.3 Why the conflation is consequential

`CDI_Leaf` is not a constant of the model. The derivation is `CDI_next = KDF(CDI_current,
measurement, code_id, configuration)`, the open-dice recipe of [`1-protocol.md`](1-protocol.md) §4.2,
so changing the preloader, the little kernel, the TEE image, `init_boot`, the [active
slot](https://source.android.com/docs/core/ota/ab), the measurement configuration or the secure-world
load state changes the leaf. Route D therefore cannot flash a patched TEE, reboot, and collect an
identity for later use: the identity it would collect belongs to the patched boot, and a historical
leaf cannot be stapled into a later round. Everything in §6.4 follows from this.

A value that derives a working public key is not thereby a root. The most careful sentence in either
field report bounds its own result: in the handset's current TA path, the 32 bytes output by the
[key-derivation function](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) — after verification
against the same-round public key, certificate request and signature relations — can serve as an
input to that device's current software RKP identity. Not a universal UDS, and not a cross-device
reusable root. The corpus keeps the same discipline in its artifacts, publishing only a digest
fingerprint of the seed and never the bytes.

### 2.4 Supply and sample

A leaked leaf certificate plus its private key is a *sample*: it expires on its own schedule, about
two weeks for RKP, and cannot be renewed. A *provisioning identity* is a *supply*: it has no expiry,
appears in no certificate that could be revoked, is never rotated, and mints fresh leaves
indefinitely.

Route A occupies a middle ground neither category covers. The attacker never learns any secret, so
there is nothing to leak or revoke, but minting requires the handset to be present and reachable: an
unlimited on-device minting capability rather than either a permanent offline one or a two-week
sample.

---

## 3. Route A — a signing oracle on Qualcomm KeyMint

No key leaves the device and no bootloader unlock is required. Source: [kanxue
293244](https://bbs.kanxue.com/thread-293244.htm), cross-checked against
[`Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox)'s device crate, which implements the same
wire protocol independently. The taxonomy class is a signing-oracle attack with the oracle inside the
target handset rather than on a second one, and with a named missing check in place of an
instrumentation hook. It is the cheapest route by a wide margin and the only one with no bricking
risk.

### 3.1 The failure that produced it

The post frames the area as two established approaches: *harvesting*, prising a `CDI_Leaf` out of the
TEE and then minting offline without limit, and *proxy signing*, letting the device run a normal
certificate request. The oracle is a third — take no seed, do not use the system RKP flow, and have
the TA sign a request over the attacker's own public key with the real `CDI_Leaf`.

It exists because harvesting failed on that handset, and the failure map establishes the cost of the
alternative. *[REPORTED]* Across the [boot-ROM](https://en.wikipedia.org/wiki/Boot_ROM) download
surface: the RV32 stub's data segment accepted a write but the stub never executes; its header and
program headers were rejected before the data was pulled; four later
[ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) images were rejected after the pull;
program-header redirection was rejected up front for all of them; the Sahara memory-debug greeting
was refused; firehose `peek`/`poke` returned *peek is disabled on secure boot devices*, while
`configure`, `read` and `getstorageinfo` worked, leaving partition reads available and no memory
primitive. All 33 [fastboot](https://source.android.com/docs/setup/test/running) commands yielded no
memory read or write. A nonce-reuse probe — ten certificate requests over ten challenges — found zero
repeated [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) `R` values, so the implementation is
conformant there too.

The conclusion drawn is that this handset's primary bootloader already fixes the loader defect the
corresponding CVE depends on, so the download-mode route does not hold there. One positive by-product
survived: the device's real `CDI_Leaf` *public* key, recovered from a certificate request by
verifying the `SignedData` signer. The private half was never reached and, per §3.4, never needed to
be.

### 3.2 Where the secret lives, and where the signing happens

Full linear disassembly of the KeyMint image, reported byte-identical to the live partition,
recovered a 96-command dispatch table and the request flow *[REPORTED]*:

```
GENERATE_CSR_V2(0x3122)
  -> generateCsrHandlerV2
  -> generateBcc
  -> derive_device_private_key        ; the CDI_Leaf derivation point
```

On this platform `CDI_Leaf` is a 32-byte Ed25519 seed derived as `KDF(SHK, "RKP PRIVATE KEY SEED")`,
where `SHK` is the system-on-chip key-ladder hardware secret, and it is resident at a fixed address
in the TA's global area at runtime, with its public key adjacent.

That label is not the one measured on Trustonic Kinibi (§4.5). Three platforms, three different
labels, which is the evidence base for the scope note in §9.3 and a standing warning against
assuming a KDF label transfers between vendors.

### 3.3 The channel below the HAL

Android's own client never talks to the TA directly. It goes through the [binder
HAL](https://source.android.com/docs/core/architecture/hidl/binder-ipc), whose
[AIDL](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl)
is shaped so private keys cannot escape: `generateEcdsaP256KeyPair` hands back a MAC'd public key and
keeps the private half inside, and `generateCertificateRequestV2` takes those blobs back
([`1-protocol.md`](1-protocol.md) §2.2).

On Qualcomm the TA is also reachable below that HAL, and `Duck-ToolBox` gates on exactly the two
artifacts that make it reachable *[MEASURED]*: the device node `/dev/smcinvoke` and the vendor
library `/vendor/lib64/libkeymasterdeviceutils.so`.

The obvious approaches fail *[REPORTED]*: there is no `/dev/qseecom`; `libQSEEComAPI.so` is a
compatibility shim over MINK IPC where `start_app` works but `send_cmd` is refused by the object
model. What works is copying what the HAL does — `dlopen` the vendor utility library, construct its
`KeymasterUtils` object for the TEE security level, and call `send_cmd`: a MINK invocation over
ordinary heap buffers, against the TA application name `keymaster64`. The handset had root with
SELinux still enforcing.

`Duck-ToolBox` resolves the same C++ class by its three mangled symbols *[MEASURED]*:

```
_ZN14keymasterutils14KeymasterUtilsC1E26keymaster_security_level_t
_ZN14keymasterutils14KeymasterUtilsD1Ev
_ZN14keymasterutils14KeymasterUtils8send_cmdEPvjS1_j
```

`send_cmd(void* req, uint32_t req_len, void* rsp, uint32_t rsp_len)` is a raw byte channel. Nothing
in it knows a binder HAL exists, and nothing in it enforces what the HAL's type signatures were
enforcing.

### 3.4 The defect: one uncalled function

Under `generateCertificateRequestV2` the TA is specified to receive `MacedPublicKey[]` and verify
each MAC before certifying the key. That MAC, computed with a device-unique key the normal world does
not hold, is the only thing in the protocol binding a to-be-certified public key to the TEE that
generated it. [AOSP's
CDDL](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl)
types the field as `MacedPublicKey` precisely so a key the TA never produced cannot enter a request
([`1-protocol.md`](1-protocol.md) §2.4).

*[REPORTED]* The MAC-verification routine, `parseMacTags`, is called only from the version-1 request
path and from a `CSR_V2_FIXED` command. The ordinary `0x3122` path never calls it.

The surrounding validation is not weak. The challenge carries a hard 64-byte bound enforced by an explicit compare-and-branch,
every `memcpy` is clamped to a minimum, and the CBOR cursor is tracked. The post found no
out-of-bounds read anywhere on the surface. One function is simply not wired into one path.

Everything downstream then behaves as designed. The TA signs the outer `AuthenticatedRequest` with
the real `CDI_Leaf`, emits the real DICE chain and the real `DeviceInfo`, and the backend verifies all
of it and returns a genuine Google-rooted chain over the attacker's public key, whose private half
was generated on the host and never existed inside the TEE.

### 3.5 The request, byte for byte

The request is a command word followed by a CBOR map with exactly two entries *[MEASURED]*, as
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

Label `4` is the challenge, a byte string of at most 64 bytes. Label `57` is `keysToSign`, a byte
string holding a CBOR *array* of [COSE_Key](https://www.rfc-editor.org/rfc/rfc9052#section-7)s. The
response is `{61: bstr(AuthenticatedRequest)}` and must be unwrapped. The key is the standard P-256
form `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.

Exactly two fields; a third yields an error return. `Duck-ToolBox` validates all of this before
anything is sent — two entries with labels exactly 4 and 57, a challenge of 1 to 64 bytes, exactly
one key, that key a five-field COSE_Key with the right type/algorithm/curve triple, 32-byte affine
coordinates, and a curve-equation check on the point — and re-validates in the worker subprocess
immediately before the syscall. *[MEASURED]*

The wire format agrees exactly between the two sources. The post derives request `LE32 cmd ‖ payload`
and response `LE32 retcode ‖ LE32 len ‖ payload` from TA entry-point disassembly; the Rust
implementation encodes the same thing. Neither cites the other.

### 3.6 The pipeline, and its three pitfalls

```
[host]   generate a P-256 key pair, keep the private key
[host]   fetchEekChain -> Google issues a challenge (replay protection)
[host]   assemble {4: challenge, 57: bstr([our COSE_Key])}
[device] send_cmd 0x3122 -> the TA does not verify the MAC, encodes our public key into the
         CsrPayload, signs SignedData with the real CDI_Leaf, returns the full request
[host]   unwrap {61: bstr} -> POST signCertificates?challenge=...
[host]   Google returns a four-level chain -> assemble keybox.xml(private key, chain)
```

Three pitfalls, each forced out by an HTTP 400 *[REPORTED]*. First, `keysToSign` must be an array,
not a bare map; the error is "expected an array, got MAP". Second, the wrapping error: the TA returns
a single-entry map, and posting that whole map to Google produces the same message, while unwrapping
first makes it pass immediately. Third, version 2 has no `ProtectedData` field — the second element
of `AuthenticatedRequest` is `UdsCerts`, a possibly empty map, and there is no endpoint encryption
key to wrap anything to. That third pitfall settles a question about tooling provenance, and §7.3
returns to it.

### 3.7 The result

Google's production endpoint returned HTTP 200 and a four-level chain *[REPORTED]*:

```
CN=<public key hash>, O=TEE  ->  CN=Droid CA3  ->  CN=Droid CA2  ->  Key Attestation CA1
```

Acceptance: the leaf's public key equals the host private key's public key; every chain signature
verifies in turn; the assembled keybox pairs with the private key. Repeated runs all succeeded.

That shape matches the two leaked samples of [`4-measurements.md`](4-measurements.md) §2 exactly:
four certificates, leaf `O=TEE` with a common name equal to the certificate's own serial, then two
Droid intermediates and the EC root. An independent source producing the same shape is evidence that
the measurement generalises to RKP issuance rather than describing one producer's output.

Two further observations confirm conclusions reached elsewhere from the other direction. The chain
carries no device-model fields: the leaf's common name is just a public-key hash. And substituting an
unrelated handset's build fingerprint in the EEK fetch still gets the request signed, because
`DeviceInfo` is decided by the TA's internal provisioning and never reaches the final certificate. At
this layer, "changing the device model" is a pseudo-requirement; what controls the attested model is
the interposition layer above — a keystore interception module, or TEESimulator's own profile system.

### 3.8 A second reachable secret on the same surface

Once the channel is open, two further commands were probed *[REPORTED]*, and one of them is a
separate defect.

A `GENERATE_FRS_AND_UDS` command returned a 32-byte hardware-secret-derived value directly, with the
provisioning gate not stopping it. The static audit expected a production device to reject this; in
practice it was wide open. This is not load-bearing for the oracle, but it is a second reachable
secret on the same surface, and the kind of result that should be checked before concluding a command
surface is uninteresting.

The other probe returned a negative: a nearby command is not an arbitrary MAC oracle but a P-256
key-pair generation and MAC backend.

### 3.9 Prerequisites

`Duck-ToolBox` [gates the
route](https://github.com/eltavine/Duck-ToolBox/blob/main/crates/duck-rkp-device/src/status.rs) on
five checks, of which exactly one is root: root, `android_arm64`, a Qualcomm system-on-chip, the
device node present, and the vendor library present. Its vendor test accepts an empty manufacturer
string or one containing "qualcomm", and its own tests assert that *Google* and
*[MediaTek](https://www.mediatek.com/)* are rejected. The crate advertises its limits as partial
device support and RKP-only. *[MEASURED]*

No bootloader unlock, no TEE patch, no seed, and no change to device state: request generation is
read-only, touching neither the lock state nor the download mode. The route stops working if the TA
wires its MAC parser into the version-2 path, or if the backend changes policy.

---

## 4. Route B — plaintext observation inside a Kinibi trustlet

A key does leave the device: a factory keybox, and separately a 32-byte output of the RKP
key-derivation call. The mechanism is trusted-application *replacement* rather than exploitation.
Source: [kanxue 293246](https://bbs.kanxue.com/thread-293246.htm) chapter 1, with the artifact layer
read from
[`tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction).

### 4.1 Environment

A Nothing Phone (2a), model A142, device `Pacman`, on MediaTek MT6886, Android 14, build
`Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys`. The TEE is Trustonic
Kinibi, with `tee-1-1`, `keystore2` and `vendor.keymint-trustonic` all running. Boot state
`ro.boot.verifiedbootstate = orange`, i.e. unlocked. The KeyMint trustlet lives in the
[MobiCore](https://github.com/Trustonic/trustonic-tee-user-space) registry under
`/vendor/app/mcRegistry/`. *[PRIMARY]* The tutorial gates every step on exact
[SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) values for its three input
binaries and refuses to proceed on a mismatch.

### 4.2 The chain, and where the defect sits

The report is emphatic that the vulnerability is not one bug but a sequence:

```
unlocked bootloader
  -> boot-chain verification policy defect
  -> controlled load of a modified little kernel / TEE
  -> Trustonic MCLF trustlet load boundary relaxed
  -> modified KeyMint trustlet enters the secure world
  -> the TA reads and decrypts the factory keybox secure object normally
  -> plaintext exists briefly in TA stack and heap
  -> saved before the parser runs
  -> copied into the mapped buffer before the handler returns
  -> normal-world direct client reads the buffer back
  -> host parses DER, private keys, certificate chain
```

What is exploited is not the secure object's encryption. The researcher obtained the ability to load
a modified trustlet in the same TEE environment, and the modified TA added a normal-world-observable
output path for plaintext the genuine code had already decrypted. That is what makes the route
transferable in principle and untransferable in practice (§8.4).

### 4.3 The interface, and the shape of the hooks

Reverse engineering located three [TCI
commands](https://github.com/Trustonic/trustonic-tee-user-space) on the KeyMint trustlet: one that
loads and processes the attestation keybox object, one for attestation identifiers, and one that
closes the session. *[PRIMARY]*

The patch changes exactly two branch targets, and the shape is the finding rather than the addresses.
The first hook fires after the decrypt has completed and before the parser is called, and saves the
plaintext pointer and length. The second fires after the parser has completed and before the handler
returns, and copies the saved plaintext into the mapped buffer. Both hooks are additive: the original
decrypt runs, the original parser runs, and the original success or failure return value is
preserved.

Preserving the return value is what lets the operator exclude the "returned success but the content
is wrong" case, the most common false positive in this area
([`3-detection.md`](3-detection.md) §1.1).

The normal-world side is a direct MobiCore client, not the Java Keystore API: it opens the device and
the trustlet by UUID, maps a buffer, notifies and waits. In its RKP variant it issues the trustlet's
P-256 key-generation command followed by close. *[PRIMARY]*

### 4.4 The plaintext layout, and the tail trap

The decrypted keybox is not XML. It is a length-prefixed sequence, and the expected output for this
device is exact *[PRIMARY]*: a version or keybox-number field of 1; an EC private key in
[DER](https://www.itu.int/rec/T-REC-X.690) of 138 bytes with three certificates; an RSA private key
in DER of 1794 bytes with three certificates; a total plaintext length of 8624 bytes; and 92 bytes of
tail that the copy did not overwrite.

That last number matters. The copy is shorter than the buffer, so 92 bytes of the original input
survive at the end. Treating the whole mapped buffer as plaintext yields a trailing fragment of
unrelated input that can still parse as plausible DER. Parse by the length prefix, confirm each
length against the DER object's own internal length, and never by fixed offset — a rule
[`3-detection.md`](3-detection.md) §1.5 generalises.

### 4.5 The separate RKP derivation path, and the per-vendor KDF label

A second, independent patch variant targets a key-derivation call site rather than the keybox parser,
and records the production call's own arguments at the hook. *[PRIMARY]* The captured arguments are
`label = "rkp_bcc_km"`, `label_len = 10`, `output_len = 32`, `mode = 1`, with the evidence recorded
as the label, a KDF status of zero, a 32-byte output length, a pointer marker, and the seed's SHA-256
only.

Two cross-checks make this more than one record's word. `label_len = 10` equals the length of
`rkp_bcc_km`, so the label is the string itself and not a placeholder. And `Duck-ToolBox`, an
unrelated implementation, ships exactly that label as [its
default](https://github.com/eltavine/Duck-ToolBox/blob/main/ui/src/features/rkp/draft.ts)
(`DEFAULT_KDF_LABEL` in its RKP draft module) and derives with an
[AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493) [counter-mode
KDF](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) over `BE32(counter) ‖ label`. *[MEASURED]*
Two independent codebases converging on one ten-character label is good evidence that the label is
real for this TA family.

Route A records a different label on Qualcomm (§3.2). The label is per-platform and must be
established on the target, never assumed; §9.3 is what that costs a previously published measurement.

### 4.6 The negative control

Run the same direct client against the stock trustlet and diff the mapped buffer before and after. It
does not change.

That is what proves the stock path does not emit plaintext, and therefore that the plaintext later
observed came from the patch rather than from the buffer's prior contents. A result without this
control is not interpretable; [`3-detection.md`](3-detection.md) §1 is built around the point.

---

## 5. Route C — caller-gate relaxation on a Beanpod/L4Re keybox TA

A key leaves the device: a factory keybox with both EC and RSA keys and full chains. Source: [kanxue
293246](https://bbs.kanxue.com/thread-293246.htm) chapter 2 and the matching corpus chapter. This is
the best-evidenced of the three extraction routes: the acceptance record is complete and every stage
carries a digest.

### 5.1 Environment

A Redmi Note 11T Pro, vendor device `xaga`, on MIUI `V13.0.5.0.SLOMIXM`, kernel
`5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928`. Slot `_b` only; slot `_a` was kept stock
throughout. The TEE is Beanpod on L4Re: the service stopped before extraction is
`vendor.keymint-beanpod`, the loader is an L4Re module, and the build gate includes an L4Re module
digest check. The keybox trusted application and the loader are both pinned by SHA-256. *[PRIMARY]*

The published HexHive [FIASCO](https://nebelwelt.net/blog/2025/1227-fiasco.html) chain targets the
same TEE family on a sibling handset, reaches EL3 and leaks a DRM key, and its [65
slides](https://hexhive.epfl.ch/publications/files/25CCC-presentation.pdf) contain zero occurrences
of *attestation*, *keymaster*, *keymint*, *RKP*, *DICE*, *CDI*, *UDS* or
*[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox)*. Route C is
the same TEE family, the same vendor, a sibling handset, and its target is the Android attestation
keybox. The two results are independent and complementary: HexHive published the privilege escalation
and did not touch attestation; this route touches attestation without needing the escalation.

### 5.2 The container, and what was and was not broken

The keybox TA is not a bare ELF. Container metadata read locally *[PRIMARY]*: an `ENC-TA` magic, a
payload size of 14760 bytes with a 473-byte trailer at that offset, a header
[CRC-32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check), an encrypted image of 15233 bytes,
and a decrypted ELF of 14760 bytes whose ELF magic was verified. Both the stock and patched TA
digests are recorded.

The loader's job is to parse the container, unwrap the symmetric material with an internal RSA key,
recover an [AES-CTR](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
key and initialisation vector, decrypt the ELF, verify the payload digest, and hand the TA to the
secure world.

The RSA key that unwraps the container is embedded in the loader and recoverable. The metadata
records a 1024-bit RSA key at a known loader file offset, with `e = 65537` and all Chinese-remainder
parameters present and self-checked — `P·Q = N`, `QINV·Q ≡ 1 (mod P)`, `DP = D mod (P-1)`, `DQ = D mod
(Q-1)`. The private factors are not reproduced here; the finding is their presence, location and bit
length. The unwrapped symmetric material is 60 bytes following a PKCS#1 v1.5 separator, carrying an
encryption flag, a protocol version, a 16-byte AES key, and a 16-byte IV whose low 8 bytes are zero:
AES-CTR with a 64-bit nonce and a 64-bit counter.

The signing key was not obtained, and the record says so. The research had no original TA signing
private key, so the modified TA's OEM signature cannot genuinely become valid. The patched TA is
re-encrypted but not re-signed, and the loader has to be made to continue past the failure.

### 5.3 Two decisions neutralised

A two-instruction patch set, each instruction replaced by a no-op. *[PRIMARY]* In the loader, the
branch that acts on the signature-verification result no longer aborts the load. In the keybox TA,
the comparison feeding the caller-mode gate on the read handler no longer rejects a plain TEE client.

Neither instruction removes a cryptographic check. Each neutralises one decision made on the result
of a check that still runs: the container is still parsed, the key still unwrapped, the ELF still
decrypted, the digest still computed. The command-type and parameter-type checks were deliberately
left intact, because deleting the whole dispatcher gate would have produced an unbounded TA
invocation surface rather than a bounded read experiment.

The builder refuses to run unless the stock digests, the original instruction bytes, the sizes, an
AES-CTR round-trip read-back and the L4Re module digest all match, which is §8.4 in practice.

### 5.4 The read, and the one-instruction scope of "read-only"

Deployment writes only the little-kernel and TEE partitions of the [inactive
slot](https://source.android.com/docs/core/ota/ab), after verifying serial, product, kernel, slot,
partition sizes and all four partitions' stock digests, with pre-write backups, full read-back
verification and automatic restore on any mid-flight failure. The patched TA is then
[bind-mounted](https://man7.org/linux/man-pages/man8/mount.8.html) over the stock path at runtime
rather than written to the vendor partition, so a reboot restores the factory TA.

Extraction then invokes one existing read command only. The write commands on the same dispatcher are
never opened. *[PRIMARY]* The success output records a zero status from context initialisation,
session open and command invocation, a payload length, a descriptor length, and an explicit
verification marker.

### 5.5 The descriptor and payload format

```
descriptor (168 B)                       payload (8578 B)
  magic 0x12345678                         length prefix
  payload length                           EC private DER
  two key/certificate entries              EC certificate chain
  per-entry offset / size / count          length prefix
  payload digest (MD5)                     RSA private DER
                                           RSA certificate chain
```

Measured for this round *[PRIMARY]*: a payload SHA-256 and
[MD5](https://www.rfc-editor.org/rfc/rfc1321) are recorded, and the descriptor's embedded digest
equals the computed payload MD5.

168 and 8578 describe this round's sample, not the format. They are a structural gate, not a success
proof, and a parser must not trust the descriptor's offsets alone: the payload carries its own length
prefixes, which must then be confirmed against each DER object's internal length.

### 5.6 The acceptance record

For both algorithms the public key recovered from the private DER equals the leaf certificate's public
key; each chain has three certificates; [`openssl
verify`](https://docs.openssl.org/master/man1/openssl-verify/) returns OK. The EC private DER is 121
bytes here versus 138 on Route B — the same [SEC1](https://www.secg.org/sec1-v2.pdf) object with and
without its optional parameters and public-key fields, which is why fixed-offset parsing fails across
devices.

Both chains terminate in one self-signed root whose serial number is `f92009e853b6b045`, the same RSA
Google root serial that 551 factory keyboxes in [`4-measurements.md`](4-measurements.md) §4.1 chain
to, which independently places this material in the factory population rather than the RKP one.

The leaf certificates carry a ten-year validity, categorically unlike the roughly two-week RKP leaves
of [`4-measurements.md`](4-measurements.md) §2.1, and that is why
[`3-detection.md`](3-detection.md) §4.3 can use leaf lifetime as a class discriminator.

---

## 6. Route D — same-boot `CDI_Leaf` capture under proper DICE

A key leaves the device: the final `CDI_Leaf` identity scalar, the one object in §2 that constitutes
a renewable provisioning identity. Source: [kanxue
293246](https://bbs.kanxue.com/thread-293246.htm) chapter 3 and the matching corpus chapter.

The handset is a Redmi K70E, codename `duchamp`, on MediaTek MT6897; every step in the corpus gates
on `ro.product.device == duchamp`. *[PRIMARY]* Its TEE is MiTEE, which
[`4-measurements.md`](4-measurements.md) §6 establishes independently to be a
[Zircon](https://fuchsia.dev/reference/syscalls)/[Fuchsia](https://fuchsia.dev/) secure operating
system rather than an [OP-TEE](https://optee.readthedocs.io/) core, a determination that decides
which published vulnerabilities can apply at all.

That is also the device model named inside one of the two leaked keyboxes' own provisioning extension
([`4-measurements.md`](4-measurements.md) §3.2). §10.3 works through what that convergence does and
does not establish.

### 6.1 Why the goal changed

The round began aiming at an early UDS or root seed, and six findings forced a different objective:
raw CDI, final `CDI_Leaf` and the native per-key scalar are different objects (§2); the final leaf is
measurement-dependent; patching the TEE or a boot component changes the downstream DICE chain; a
32-byte value that derives a public key is not thereby the UDS; the earlier the stage, the more it
contaminates later measurements; and holding one identity value does not by itself let you build a
request the backend will accept.

The replacement objective is a seven-step sequence: establish a stock RKP baseline; separate raw CDI
from final `CDI_Leaf`; capture the final leaf within one secure-world boot; build the software request
from that same round's DICE chain and `DeviceInfo`; generate a new software P-256 key; obtain the
backend's chain over that key; restore the device.

### 6.2 Exact-frame patching, and the correction that unblocked it

What was actually patched: the OEM RSA signature bytes were not forged and the verifier still runs;
body and header digests are preserved. What changed is the secure-boot provider's handling of the
verification return value — a non-zero result no longer immediately blocks the subsequent load, while
container parsing, decompression and the length contract all still have to hold. Writing this up as
"TA signature forged" would misstate both the defect's location and the capability obtained. It is a
loader error-handling boundary, the same class as Route C's loader branch.

Why early attempts bricked: full-image recompression candidates destroyed the
[LZ4](https://github.com/lz4/lz4) frame tail, the certificate window or the device tree, and the
handset hung at the boot logo. The conclusion drawn at the time, that all TEE patches hang at the
logo, was wrong. The real constraint is the compressed-frame and loader contract, and the route that
works is exact-frame: preserve the original frame structure, change only the minimum bytes near the
target instruction, keep the decompressed length identical, leave every other compressed block
byte-identical, leave the frame tail, certificates and device tree untouched, and re-verify image
structure and digests.

### 6.3 One-shot early bind

The dynamic experiment does not leave a patched TEE on disk. It stages a stock restore image;
triggers only when target device, slot and digest all match; boots the candidate TEE for this boot
only; captures the same-round leaf and certificate request; and restores the on-disk TEE to stock once
the system is up, without restarting the current secure world. The next boot is stock.

After boot completes the on-disk TEE is stock, and that does not mean the candidate TEE did not run.
Automatic restore exists to return the disk to a safe state while preserving the current secure-world
boot's results. What must be checked jointly instead of the disk image is boot markers, runtime
namespace, TA digest, restore record and boot identifier.

### 6.4 Same-round capture, and the gate that makes it a result

Capture order is mandatory, and it follows from §2.3:

```
stock / approved research environment
  -> native zero-key certificate request
  -> verify that round's DICE chain, outer signature and DeviceInfo
  -> capture the final CDI_Leaf scalar
  -> derive its SubjectPublicKeyInfo
  -> constant-time compare against the leaf SPKI in the same round's native request
  -> save the identity only on a match
```

The anti-pattern is to capture a 32-byte value, find a certificate request days later, staple them
together and hope the server accepts. It cannot work, because the leaf is measurement-bound: request,
DICE chain, `DeviceInfo`, challenge and identity scalar must all come from one round.

The baseline the corpus records for this device is the gate *[PRIMARY]*: a SHA-256 of the UDS
`SubjectPublicKeyInfo`, and a SHA-256 of the `CDI_Leaf` `SubjectPublicKeyInfo`. A candidate offline
seed is accepted only if it reproduces those public keys, independently verifies a request under a
fresh challenge, and yields a returned leaf matching the saved private key.

### 6.5 Two keys that must not be equal

```
CDI_Leaf identity private              software P-256 private
  -> signs the device-identity request    -> its public key enters keysToSign
  -> backend validates DICE + DeviceInfo  -> backend signs that public key
                                          -> returned leaf pubkey == software private's pubkey
```

Requiring these two to be equal judges a correct outcome as a failure. The identity key proves the
request came from this device; the software key is the one that will carry subsequent Android key
attestation. `Duck-ToolBox` implements exactly this split: the request identity comes from the
configured seed or hardware key, while `keysToSign` carries freshly generated P-256 keys with
[rejection sampling](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf). *[MEASURED]*

### 6.6 The `NOT_APPROVED` causal correction

An early round returned `NOT_APPROVED` and was attributed to "the DICE was modified". But that round
changed several variables together: modified DICE, plus a historical or mismatched `DeviceInfo`, plus
a new challenge, request and server state. It therefore shows only that that combination failed.

A later control kept the same exact modified DICE and substituted a clean `DeviceInfo` matching the
target device profile, and recorded `APPROVED`. What that licenses: "DICE was modified" is not a
sufficient rejection condition; the full `DeviceInfo` tuple and the server-side registered profile are
plausibly load-bearing gates; the control is evidence from decomposing a combination, not a
single-field proof; and without a single-field A/B comparison, no individual field can be named as the
root cause.

The second half is a verifier bug rather than a protocol fact. An early acceptance parser dropped
unknown fields of the [provisioning-information
extension](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension),
and so marked a certificate carrying `NOT_APPROVED` as a pass. The root cause was not a signature
error; the signatures were fine. The verifier lost the server's status field. Hence the rule this
series adopts verbatim:

```
X.509 / DICE signatures mathematically valid
          !=
server-side provisioning status acceptable
```

Preserve unknown fields; gate explicitly on provisioning status; never let a digest match or a chain
verification override a `NOT_APPROVED`.

---

## 7. Off-device minting: why the backend signs a software request

The routes supply a signing capability. This section is what is done with one, and unlike the
acquisition half it is fully reconstructed, with every gate in it either inapplicable or free. It is
reconstructed from two independent normal-world implementations,
[`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw) and
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), and from the two leaked keyboxes
whose bytes [`5-sources.md`](5-sources.md) §5 traces to one of them.

### 7.1 The gate-by-gate account

*Step 1 — hold a 32-byte DICE seed for a registry-recognised identity.* This is the acquisition
problem of §3–§6. Everything after it is cheap.

*Step 2 — build a degenerate DICE chain:* a bare UDS
[COSE](https://www.rfc-editor.org/rfc/rfc9052)_Key plus one self-signed
[COSE_Sign1](https://www.rfc-editor.org/rfc/rfc9052#section-4), with `UdsCerts` empty. The gate that
should stop this is the [VTS](https://source.android.com/docs/core/tests/vts) requirement for a
multi-stage chain, and it is inapplicable: that requirement is hard only when StrongBox is declared
at vendor API level 202404 or later, and the measured handset declares no StrongBox at all
([`4-measurements.md`](4-measurements.md) §6.1). Phase-1 degenerate DICE is an [officially supported
deployment
phase](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/README.md)
([`1-protocol.md`](1-protocol.md) §4.5), so this is a conforming request, not a malformed one.

*Step 3 — generate P-256 key pairs in software and put bare COSE_Keys in `keysToSign`.* The gate is
the `MacedPublicKey` [HMAC](https://www.rfc-editor.org/rfc/rfc2104), and it is structurally
inapplicable rather than merely weak. The
[CDDL](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl)
types the field as `KeysToSign = [ * PublicKey ]`, bare COSE_Keys. The TA verifies each MAC and then
strips it; the reference implementation pushes only the encoded public key into the payload. The MAC
never leaves the device, so the backend receives no cryptographic evidence that any submitted key was
TA-generated. Forging a MAC is unnecessary: whoever signs the request bypasses the check entirely.

*Step 4 — POST to the EEK endpoint with an unsigned, operator-typed fingerprint, then POST the
request.* The gate is the registry match on `UDS_pub`, and it passes, because the seed belongs to a
registered device. The only failure mode is HTTP 444 `DEVICE_NOT_REGISTERED`. And there is nothing
else to pass: `rkpd`'s own HTTP layer sets no API key, no client certificate and no TLS pinning
([`1-protocol.md`](1-protocol.md) §5.2), so the endpoint is reachable by any client that can produce
a valid signature.

*Step 5 — the backend stamps the provisioning extension and signs.* Two gates exist here on paper and
both were inert in the measured cases. [The
CDDL](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/DeviceInfoV3.cddl)
makes `vbmeta_digest` mandatory and one leaked sample's request omitted it and was signed anyway. And
the documented abuse counter, `certs_issued`, read 512 against a measured stock baseline of 8:
Google's own abuse signal was saturated inside the signed certificate and issuance proceeded
regardless ([`4-measurements.md`](4-measurements.md) §3.3).

*Step 6 — emit keybox XML; a module manager copies it over the consumer's keybox path.* No gate; this
is the ordinary install flow on an already-rooted consumer device.

*Yield:* unbounded Google-signed P-256 leaves under a live Droid intermediate, roughly fourteen days
each, from one identity, indefinitely — with the donor handset destroyed, resold, or never touched
again.

### 7.2 Why a seed is a supply and not a sample

*[INFERRED, strong]* The registry holds the `UDS_pub` the OEM extracted at manufacture. If the seed
were random-and-stored in wipe-visible storage, a factory reset would change `UDS_pub` and
permanently 444 the handset, behaviour no shipping fleet exhibits. So the object survives a wipe.

The honest boundary is that survives-a-wipe is all this forces, not derived-from-fuses. The measured
KeyMint TA on `duchamp` carries a
secure-file-system-to-[RPMB](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#rpmb-secure-storage)
migration for exactly this object ([`4-measurements.md`](4-measurements.md) §6.3), and RPMB survives
a userdata wipe, so random-once-then-persisted-in-RPMB is consistent with everything observed.

The consequence is the §2.4 distinction. A seed has no expiry, is never rotated, and appears in no
certificate that could be revoked. The fourteen-day leaf lifetime is the operator's refresh cadence,
not a decay function.

### 7.3 What the pipeline does not need, and one withdrawn inference

It does not need a hardware key ladder. The Python implementation once carried a `--hw-key` path with
an AES-CMAC counter-mode derivation, documenting itself as the KDF observed in TEE
`CryptoHmacKdf(mode=1)` calls, and its own README stated that on real devices the AES key resides in
a system-on-chip internal key ladder and is not software-accessible. *[MEASURED]* Current upstream has
removed `HardwareKdf` and the `--hw-key` path entirely, leaving only a bare seed input, and has added
a P-256 curve option. So the operative input is one 32-byte seed of unstated provenance, and the only
party known to have held a working one asserted no extraction capability.

It also does not need `ProtectedData`, and this retires an inference the earlier record carried.
Finding `protected_data` computed then discarded in a tool was listed among the signs that the tool
had never actually been run. §3.6's third pitfall gives the benign explanation: version 2 has no
`ProtectedData` field, and both independent implementations build the structure anyway. That
indicator is withdrawn; the others in the same adjudication — a hardcoded empty `UdsCerts`, the
repository hygiene, the unanswered issue — are unaffected ([`5-sources.md`](5-sources.md) §5.4).

---

## 8. The structural pattern

### 8.1 The defect is a decision, not a broken primitive

Route A: a MAC-tag parser that is not called on one path. Route B: a load boundary relaxed enough to
admit a modified trustlet. Route C: one branch on a signature-verification result, and one
caller-mode comparison. Route D: one error branch on a loader's verification return.

In no route is a cipher broken, a key factored or a digest forged. Every cryptographic check still
runs; what changed is what the code does with the answer.

The defensive consequence is direct. Auditing cryptography finds none of these. What finds them is
asking, for every check, what happens on failure, and whether any path reaches the protected
operation without the check having been consulted at all.

### 8.2 The secret is observed where authentic code already placed it in cleartext

Route B copies plaintext the authentic decrypt produced. Route C invokes the authentic read handler.
Route D captures the authentic derivation's output. Route A never sees the secret and still gets the
signature.

This generalises an older observation about trusted-world key handling, the one [Quarkslab's relay
work](https://blog.quarkslab.com/bypassing-android-hardware-attestation.html) rests on: inside the
TEE, at the right instant, the secret is plaintext in a buffer, and the whole problem reduces to
getting code to run there at that instant. Encrypting a secret at rest protects it against a cold
lift and against nothing else, which is why §9.1's cold-lift lane collapses into the lane above it.

### 8.3 Entry and exit are independent problems

*Entry* is: the boot chain admits a component; a container mishandles a failure; a caller gate is
loosely bound to a command; plaintext has an observable lifetime; a request path omits key-provenance
binding. *Exit* is: a mapped buffer; a descriptor plus payload; a certificate request; a `SignedData`;
a returned certificate chain.

Proving entry does not prove exit. Route B's negative control (§4.6) is the discipline this implies,
and the five look-alike states of [`3-detection.md`](3-detection.md) §1.1 are what happens without it.

### 8.4 Binary pinning is a precondition, not paperwork

Every route's patch is bound to exact binaries. Route C's builder gates on the stock TA, loader and
L4Re module digests and refuses to run otherwise. Route B gates on three input digests. Route D gates
on device, slot and digest before the early bind fires.

The consequence: an [OTA](https://source.android.com/docs/core/ota), a downgrade, a kernel change, a
slot change, or another handset of the same model means re-disassembly. These are routes rather than
tools. It also bounds the threat usefully — an operator can reuse a route on a fleet of identical
units only by redoing the analysis per unit, which is why the economics favour §7's single captured
seed over repeated extraction.

### 8.5 Boot-bound identity

§2.3 as an operational constraint: because `CDI_Leaf` folds in every measured component, a captured
identity belongs to the boot that produced it. That is what forces Route D's one-shot same-boot design
(§6.3), what makes the capture order of §6.4 mandatory, and what makes
capture-now-mint-later structurally impossible rather than merely unreliable.

A successful capture is therefore self-limiting for the attacker in a way a factory keybox is not: the
identity stops working when the device's measured state changes. Against that, §7.2's observation that
the seed survives a wipe is the counterweight — the seed is stable even though a leaf derived under a
patched boot is not.

### 8.6 The unlock asymmetry

Three of four routes require an unlocked bootloader and a controlled boot-chain load. Route A requires
root only.

This inverts an expectation. The designed candidate lane that looked most attractive — normal-world
root into a sibling-TA compromise, §9.1 — was attractive precisely because it passes without
unlocking, and the routes that actually produced results are the unlock-requiring ones. The one route
that needs no unlock got there by not taking a secret at all.

### 8.7 The four routes compared

| | A (Qualcomm) | B (Kinibi) | C (Beanpod/L4Re) | D (MiTEE) |
|---|---|---|---|---|
| Handset | any Qualcomm, reported | Nothing 2a / `Pacman` | Redmi Note 11T Pro / `xaga` | Redmi K70E / `duchamp` |
| Unlock required | *no* | yes | yes | yes |
| Root required | yes | yes | yes | yes |
| TEE modified | no | yes, trustlet | yes, loader and TA | yes, TEE, exact-frame |
| Brick risk | none | boot chain | boot chain, slot-isolated | boot chain, auto-restore |
| Object obtained | *nothing* — a signature | factory keybox, and a 32-byte KDF output | factory keybox, EC and RSA | final `CDI_Leaf` |
| Reusable offline | no — the handset must be present | yes | yes | yes |
| Result lifetime | per invocation | leaf `notAfter` | *ten years* | until a measurement changes |
| Transfers to a sibling unit | plausibly, same SoC family | *no* — re-disassembly | *no* — re-disassembly | *no* — re-disassembly |

---

## 9. The routes that were designed and killed

Before the four routes were published, the acquisition problem was attacked by design: seven
end-to-end schemes, each reviewed by three adversarial lenses — stage-to-stage entailment, citation
audit, and parsimony. *[MEASURED]* Twenty of twenty-one verdicts refuted the scheme under review or
downgraded it to speculative.

The kills are measurements, several of them transfer to other platforms, and the one lane that
survived turned out to be the one the published routes avoid.

### 9.1 The candidate field

*Non-technical custody* needs zero unpublished primitives: insider or provisioning-line access where
`UDS_pub` is extracted and uploaded, an authorised service or repair channel, a pre-production or
unfused unit registered in the same bulk step, or a purchased seed with no upstream knowledge. Each
produces a byte-identical artifact, and the leaked samples carry positive evidence pointing this way
([`5-sources.md`](5-sources.md) §5.3).

*Normal-world root into a sibling-TA compromise* was the strongest technical lane, and its first three
stages all pass. Stage 1 reaches arbitrary kernel physical read/write and disables SELinux on a
locked stock handset: the [public one-click
tool](https://github.com/Colorful-glassblock/duchamp-root) for that handset chains a
[KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) leak through a
[futex](https://man7.org/linux/man-pages/man2/futex.2.html) requeue race
([CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499)) to a forged pipe-operations
table, and its own prerequisites note that the delivery mechanism works whether or not the bootloader
is unlocked ([`4-measurements.md`](4-measurements.md) §6.5). Stage 2 copies the normal-world files
backing the TEE's [secure file
system](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html) — SELinux is off and
they are ordinary files. Stage 3 drives one of five device-reproduced
[TÄMU](https://arxiv.org/abs/2601.20507) bugs that ship on this handset, two of them arbitrary-read,
into code execution inside the secure world ([`4-measurements.md`](4-measurements.md) §6.4). Stage 4
is the problem: crossing from that TA to the KeyMint TA's own secret. No published primitive bridges
it.

*Cold lift of the sealed storage object* collapses into the lane above. The object's ciphertext sits
in normal-world storage and root copies it trivially; nothing in the normal world advances past that,
because the sealing key is derived from a [hardware unique
key](https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html#hardware-unique-key)
inside the TEE. Conditional on TA-identity code execution the lift is unnecessary — open the object
through the ordinary API; absent it, the lift is useless. No encrypted trusted-storage blob has ever
appeared in circulation, while seeds and finished keyboxes have.

*A boot-stage or preloader route* is *[SPECULATIVE]*. A [MediaTek
advisory](https://corp.mediatek.com/product-security-bulletin) in the right stage, with the right
primitive class and access model, listing the right chipset among its affected parts, predates the
mints by six months. Three things stop it being the answer: it speaks of *identifiers*, and a chip
identifier is by design a public value used in secure boot; its affected list spans 35 chipsets, so
the presence of any one is near-uninformative; and no source ties it to DICE material.

### 9.2 What the kills established

*A UUID-squat* — serve an older signed KeyMint TA for the same UUID and inherit its storage namespace
— needs two unpublished primitives in series, and the second does not substitute for the third: an
older genuine signed TA is an older genuine TA faithfully doing KeyMint, not attacker code reading a
secret. Its upstream-transfer premise also fails, because the container magic is not OP-TEE's
([`4-measurements.md`](4-measurements.md) §6.6).

*Deleting a TA version floor* to replay any signed TA fails on measurement: *[MEASURED]* no version
field exists anywhere in the signed container header across 38 images, so there is no floor in the
header to reset; the platform's version store lives in a secure-world loader service rather than a
normal-world file root can delete; and the four TAs worth downgrading to were never rebuilt at all,
so there is nothing to roll back to ([`4-measurements.md`](4-measurements.md) §6.6).

*A deprivilege-window capture* on the normal-world side of a hardware-backed certificate service was
refuted by the device's own binaries: *[MEASURED]* no
[Trusty](https://source.android.com/docs/security/features/trusty) port name and no Trusty IPC device
node appears in any of the handset's 17 TAs; the KeyMint HAL's link against the Trusty client library
is an unused dependency with zero corresponding undefined symbols, its only transport symbols being
the five [GlobalPlatform
client](https://globalplatform.org/specs-library/tee-client-api-specification/) calls; and the device
speaks an older command API than the AOSP service being reasoned about. The oracle under analysis was
not the code this device runs.

*A signed-custody ladder read*, where secure debug drives the chip's key-derivation service, is
stage-incoherent: a download agent displaces the boot chain, so in download mode there is no TEE and
no secret in any memory to read. Its arithmetic also fails — the tool computes `CMAC(K, BE32(i) ‖
label)` with no separator byte, no context and no length encoding, which is not [NIST SP
800-108r1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) §4.1 and cannot be what a validated
derivation service computes.

### 9.3 The kill that needed a scope note, and the lane nobody designed

Every scheme resting on the KDF label `rkp_bcc_km` was killed by measurement: *[MEASURED]* the label
is absent from all 17 TAs on `duchamp`, from its TEE kernel module and from its KeyMint HAL, along
with `CryptoHmacKdf` and a fallback label.

The measurement stands; its scope did not. §4.5 records that same label as the live production KDF
argument on Trustonic Kinibi, confirmed twice over, and §3.2 records a third, different label on
Qualcomm. The label is per-TEE-vendor. The kill of MiTEE-specific schemes resting on it remains
correct; what must not be carried forward is the generalisation that no shipped device uses it. A
*[MEASURED]* fact about one platform became wrong only when read as a fact about all of them.

The larger correction is that the published routes sit outside the entire designed field. None of
them crosses from a sibling TA. They relax one decision in the component that decides whether to load
a TA, run a minimally modified genuine TA, and observe the secret the genuine code path has already
decrypted. Call the lane *boot-chain and container error-branch substitution*. Its cost is an unlocked
bootloader, exact-version binding, and a bricking risk the sibling-TA lane does not carry.

This changes the standing conclusion in one direction only. The statement that no published route
goes from a sibling-TA bug to KeyMint's own secret remains true as stated: nobody published that
crossing. But the inference it was supporting, that device-side acquisition is unreconstructed, no
longer follows, because the crossing turns out to be avoidable. Becoming the TA makes crossing to it
unnecessary.

### 9.4 The standing grade this changes

The broader threat model this series inherited graded device-side extraction of a DICE identity as
*not demonstrated, confidence very high*, on a structural argument: the downstream minting tooling
takes the seed as a command-line argument it cannot obtain, and the tool's only open issue — how to
export a leaf seed from a handset — was unanswered.

That structural argument is answered, and the four routes are the answer. The grade belongs at
*[REPORTED], not independently reproduced*, with confidence *moderate* that no verified public
demonstration exists and *low* that the capability does not exist. The distinction the old grade was
built on survives — no peer-reviewed result shows this, and nothing in this series was reproduced on
hardware — but "the tooling cannot obtain its input" can no longer be carried as the reason, because
four named mechanisms for obtaining it have been published.

Route A changes the question rather than answering it. It reaches a Google-signed chain without
extracting any seed, so the proposition as phrased — extract a `CDI_Leaf` — can be false while its
consequence, minting Google-rooted chains over attacker keys, is achieved. A proposition about key
extraction is the wrong thing to grade; the thing to grade is whether an adversary can obtain
Google-signed chains over keys of their choosing, and the answer is yes, by at least two independent
mechanism classes.

In the custody terms of §2.1: routes B, C and D are the first published cases of class H by
trusted-application *replacement* rather than exploitation, and Route A is class G with the oracle
inside the target handset — the same architecture previously published across two handsets, collapsed
onto one, with a named missing check in place of an instrumentation hook.

---

## 10. What is not established

### 10.1 The load-bearing claims and their grades

*[MEASURED]*: that `Duck-ToolBox`'s wire format matches the independently disassembled one (§3.5);
that the five `Duck-ToolBox` gating checks and the vendor exclusions are as stated (§3.9); that the
Kinibi KDF label is defaulted to by an unrelated implementation (§4.5); that `rkp_bcc_km`,
`CryptoHmacKdf` and a fallback label are absent from every MiTEE binary searched (§9.3); that no
version field exists in the TA container header across 38 images (§9.2); that `Duck-ToolBox` has
neither a provisioning-status gate nor
[X.509](https://www.rfc-editor.org/rfc/rfc5280) signature verification
([`3-detection.md`](3-detection.md) §1.4); and that a Pixel 7 fails three of the five gates (§10.4).

*[PRIMARY]*, read from an artifact rather than narrated: Route C's container metadata, embedded
unwrapping key location and bit length, and its stock and patched digests (§5.2); Route C's
acceptance record (§5.6); Route D's device gate and its baseline public-key digests (§6, §6.4); the
stock issuance baseline ([`3-detection.md`](3-detection.md) §4.2); and the per-stage digest gates in
every builder (§8.4).

*[REPORTED]*, and the ones to treat with most caution: that Route A's request handler omits the MAC
verification and that the MAC parser is referenced only from two other commands (§3.4); that Route A
yields a Google-signed chain in practice (§3.7); that a hardware-secret-derived value is returned
with no provisioning gate (§3.8); that an arbitrary build fingerprint is accepted (§3.7); and that
routes B, C and D were executed as recorded (§4–§6).

*[INFERRED]*: that the issuance count is a logarithmic bucket, now from five observations including a
non-512 value ([`3-detection.md`](3-detection.md) §4.2); and that a seed survives a factory reset
(§7.2).

What would settle each *[REPORTED]* claim: an independent disassembly showing the same
cross-references; a returned chain whose leaf public key matches a host-generated private key, with
the invocation trace; one invocation on any production handset of that platform; a rejected request
differing only in the fingerprint; and independent re-execution from the stock inputs through each
builder's gates.

### 10.2 The unbridged step, and the limits of opportunity

Reaching another TA's secret from a compromised sibling TA requires either a secure-kernel compromise
or a flaw in the shared storage service. Neither is published, and the architecture of the measured
platform narrows the question: MiTEE relocated the secure-storage stack out
of the secure kernel and into a userspace service that holds the device's hardware unique key and
handles every TA's plaintext objects ([`4-measurements.md`](4-measurements.md) §6.3). So the target is
a named userspace process rather than an unpublished kernel exploit — but cross-TA naming is closed,
since the storage call's UUID parameter was replaced by a selector and the service identifies its
caller by an unforgeable channel.

§9.1's lane therefore establishes opportunity and access, not a completed chain: the vulnerable code
was never rebuilt and reaching it needs only a public root, and the crossing is still unpublished.
And §9.3's correction applies — the objective that crossing would serve is reachable without it.

### 10.3 Conjectures explicitly not advanced

*That the leaked samples came from the measured research handset.* The convergence is real: same
device model, same tool family, same week — the research effort's stock baseline, its submission
package and both samples all fall inside a nine-day window. But two signed fields argue against it.
The research device read an issuance count of 8; both samples read 512, which would require hundreds
of mints inside the same 30-day window from a deliberately rationed, gated, one-shot issuance
posture. And that effort's earlier submission was rejected for carrying `NOT_APPROVED`, whereas
sample A carries `APPROVED` in both verdict positions. The grade stays *[SPECULATIVE]*, and the
improvement over the earlier "nothing binds it" is that the reason is now measured. The test that
would close it is a comparison of leaf public keys or serials.

*That the two samples are one identity.* Unsupported. The `DeviceID` attribute is random
([`3-detection.md`](3-detection.md) §5.1) and the leaf common name equals the certificate's own
serial. Neither file carries a device identifier at all.

*That an issuance count of 512 implies a particular mint rate or a subscription service.* Requires
bucket semantics and a single-key batch size simultaneously, and neither is measured. What survives
is that 512 is extreme against `rkpd`'s own [default extra-key
target](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/Settings.java)
of 6, and that Google's abuse signal was saturated while issuance proceeded.

*That a preloader advisory reaches DICE or key-ladder material.* *[SPECULATIVE]*, for the three
reasons in §9.1.

*That the seed is derived from an immutable hardware root* rather than random-then-persisted.
*[SPECULATIVE]*, and the migration strings of [`4-measurements.md`](4-measurements.md) §6.3 lean
against derivation.

### 10.4 A worked negative: why a Pixel 7 is out

`panther`, a Pixel 7 on Google Tensor GS201, fails three of the five `Duck-ToolBox` gates: the
Qualcomm system-on-chip test, the device-node presence test, and the vendor-library presence test,
while passing root and the architecture check. The crate's own test asserts that a Google
manufacturer string is rejected. *[MEASURED]*

Root buys nothing here. With no command device node and no Qualcomm vendor library, the only
reachable entry is the binder HAL, which hands back a MAC'd public key and keeps the private half
inside the TEE. There is no command channel below it to misuse, so Route A has no surface. Routes B
through D are each bound to a specific TEE and a specific loader defect, and Tensor runs Trusty with
a [Titan M2](https://security.googleblog.com/2021/10/pixel-6-setting-new-standard-for-mobile.html)
[secure element](https://source.android.com/docs/security/best-practices/hardware), which none of the
four addresses.

The standing caution applies: Trusty's clean record reflects absent analysis, not demonstrated
robustness. "No route" is a statement about the published corpus, not about difficulty.

---
