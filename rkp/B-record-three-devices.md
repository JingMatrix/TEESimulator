# Appendix B. Record: keybox and certificate extraction across three handsets

Published at <https://bbs.kanxue.com/thread-293246.htm>, with a matching engineering corpus at
[`gungnir-sanye/tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction).
The content of that post is set down here for the reason given in [appendix
A](A-record-signing-oracle.md): only the opening post exists in the page's static HTML, the author's
own repository link is wrapped in the forum's encrypted-text markup and is unreadable without a
logged-in session, and the thread may be edited or removed. The substance is organised rather than
translated, and the technical analysis of the three routes is [part 2
§4](2-mechanisms.md#4-route-b-plaintext-observation-in-a-kinibi-trustlet), [part 2
§5](2-mechanisms.md#5-route-c-caller-gate-relaxation-on-a-beanpod-keybox-application) and [part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret), with the appraisal of the
record as a source in [part 5 §3.2](5-sources.md#32-the-three-device-retrospective).

The record states its own terms. It is a retrospective on three research devices rather than a
reproducible tutorial; its public version contains no private keys, no real seed, no device-unique
identifiers, no patch bytes and no executable flashing commands; and its front matter states that
the corpus was organised with the assistance of a language model, *which does not mean that every
historical command has been re-executed by a human*. The closing notice restricts the work to
authorised research, competition, security analysis and defensive retrospectives.

Each chapter of the original answers five questions: where the weak point in the security boundary
lies; how a request from the normal world enters the trusted environment; which datum inside that
environment is observed or exported; how the host turns the result into certificate material; and
which pitfalls the experiments hit, including where earlier judgements were wrong.

## B.1 Summary of the three results

The three devices produced three different results, and the record is explicit that they do not
reduce to "the seed was extracted".

On the Nothing Phone (2a), controlled observation of the decrypted plaintext of a local factory
keybox, plus a separate path to RKP derivation material. On the Redmi Note 11T Pro, passage through
the caller gate and container boundary of a MediaTek-platform keybox application's read-only
command, plus complete acceptance of descriptor, payload and certificate chain. On the Redmi K70E,
identity confirmation of the final `CDI_Leaf` under proper DICE, closing a loop over a same-round
certificate request, device information and the returned Google chain.

The record names the three errors it considers most common: treating keybox, RKP seed, raw compound
identifier, device secret and `CDI_Leaf` as one secret; treating one successful boot, one 32-byte
output or one HTTP 200 as a final result; and carrying one device's conclusions about its
application, environment, slot and DICE across to another device.

## B.2 Nothing Phone (2a): keybox plaintext leaving a Kinibi trustlet

### B.2.1 Objective

Two routes opened on this handset at once. The factory-keybox route sought a parseable EC and RSA
attestation keybox with its certificate chains. The provisioning route sought to establish whether a
32-byte value derived by a key-derivation call inside the KeyMint trustlet can serve as part of the
device's current software RKP identity. The two share the same underlying KeyMint and Trustonic
environment, but their results mean different things.

### B.2.2 The defect is a sequence

```
bootloader unlocked
  -> boot-chain verification policy defect
  -> controlled load of a modified little kernel and trusted-environment image
  -> the Trustonic trustlet load boundary is relaxed
  -> a modified KeyMint trustlet enters the secure world
  -> the application reads and decrypts the factory keybox secure object normally
  -> plaintext exists briefly in the application's stack and heap
  -> the plaintext is saved before the parser runs
  -> it is copied into the mapped buffer before the handler returns
  -> a normal-world client reads the buffer back
  -> the host parses the DER, private keys and certificate chains
```

What is exploited is not the encryption of the keybox object. The researcher obtained the ability to
load a modified trustlet in the same environment, and that trustlet added a normal-world-observable
output path for plaintext which the genuine code had already decrypted.

### B.2.3 The communication path and the direct client

The normal path runs from the KeyMint HAL through the Trustonic client, which opens a trustlet
session, maps a normal-world buffer, fills in a request structure, notifies the secure world and
waits for the application to return. The request structure carries the command type, the return
status, the mapped buffer's virtual address and length, and the current request context. The HAL
expects the application only to process the encrypted object in that buffer, and the stock
application does not write secure-world plaintext back into it.

The research client reimplements this protocol instead of calling the Java keystore API. It
establishes a session, maps the input object, sends the same class of request the HAL sends, waits
for completion, and compares the buffer before and after the call. Against an unmodified application
the buffer is unchanged, which is what establishes that the stock path emits no plaintext.

### B.2.4 Behaviour inside the application

```
handler
  |- read the mapped buffer's address and length
  |- validate the input range
  |- copy the encrypted object into the application heap
  |- call the secure-object decryption function
  |- obtain the plaintext buffer
  |- call the keybox parser
  |- free the plaintext
  \- return status
```

The patch neither reimplements the decryption nor infers the keybox format from outside. It adds two
observation points: once decryption is complete and before the parser is called, the plaintext
pointer and length are saved; once the parser is complete and before the handler returns, the saved
plaintext is copied into the mapped buffer.

The record gives the reasons for that shape. The original decryption still runs, the original parser
still runs, the original success or failure return value is preserved, a read-only request needs no
added write capability, and the case of a successful return with incorrect content can be excluded.

### B.2.5 Layout of the plaintext

The plaintext is not XML but a length-prefixed sequence:

```
version or keybox number
EC private DER length / EC private DER / EC certificate count / EC certificates 0..2
RSA private DER length / RSA private DER / RSA certificate count / RSA certificates 0..2
```

Fixed-offset slicing fails, because certificate lengths change with the version, the chain length
can change, the tail of the buffer may retain input that the copy did not overwrite, and a wrong
length interpretation produces DER fragments that look legitimate. The parse order the record
prescribes is: read the length prefix; check that enough buffer remains; check the DER leading byte
and its internal length; check that the descriptor agrees with the payload; export a public key for
each private key; compare it against the corresponding leaf certificate; and verify the complete
chain.

### B.2.6 Three layers of proof

Obtaining EC and RSA private keys is not sufficient. The record requires three layers: the public
key derived from each private key equals the public key of the corresponding leaf certificate; each
chain verifies from leaf through intermediate to a self-signed root with valid constraints; and a
fresh attestation triggered through the Android keystore yields a leaf consistent with the exported
certificates. Only all three together exclude a random key pair, a keybox for another purpose, a
misaligned parse, a test authority, and material that is well-formed but belongs to another device.

### B.2.7 The provisioning derivation path

The provisioning route takes its value from a key-derivation path inside the trustlet associated
with the label `rkp_bcc_km`, rather than from the keybox plaintext:

```
device-bound secret -> labelled key derivation -> 32-byte derived material
  -> RKP and compound-identifier handling -> request and challenge signing
```

The record's formulation of the result is deliberately bounded: in this handset's current
application path, the 32 bytes output by that derivation, after verification against the same
round's public key, certificate request and signature relations, can serve as an input to the
device's current software RKP identity. It is not asserted to be a device secret common to all
platforms, a raw compound identifier common to all devices, a `CDI_Leaf` in a format shared across
vendors, or a root seed reusable across devices.

### B.2.8 Pitfalls

A filename and a path prove only that the input object exists, not that readable plaintext sits
inside it. A successful return from the application means the decryption and parse paths did not
error, not that the output buffer holds a correct keybox. When the copy is shorter than the buffer,
the tail retains residue from the original input, so the result must be parsed by length prefix, DER
structure and certificate relations rather than treated whole. A device may prefer RKP and still
fall back to a local factory keybox when the network or service is unavailable, so the presence of
RKP does not imply the absence of a keybox. And certificate lengths and container fields change
between versions, so length prefixes and internal DER lengths must govern, with the version and
input digests treated as hard gates.

## B.3 Redmi Note 11T Pro: container and caller gate on a MediaTek platform

### B.3.1 Objective and environment

The objective is narrower: to establish whether the keybox read-only path already present in the
platform's trusted environment can, on a specific firmware version and in an authorised research
environment, be invoked from the normal world, and whether the returned payload parses into EC and
RSA private keys with their chains.

The route differs from the Nothing Phone's in every component. That one runs over a Trustonic
trustlet interface; this one over the platform's own secure management module. The container and
caller checks of the keybox application are entirely different, and the earlier patch logic does not
transfer. The corpus for this device stops the service `vendor.keymint-beanpod` before extraction
and gates its patch builder on an L4Re module digest, which places the environment in the Beanpod on
L4Re stack rather than the platform's hypervisor-based one.

### B.3.2 From boot chain to application

```
a boot-chain research environment in the unlocked state
  -> a matching-version environment image is allowed to load
  -> the environment starts L4Re and the secure management module
  -> the management module loads the keybox application
  -> a normal-world client opens a session
  -> it sends a read-only keybox request
  -> the application validates command, parameter types and caller mode
  -> it reads the keybox secure object
  -> it returns a descriptor and a payload
  -> the host parses the DER and the certificate chains
```

Two problems have to be separated: whether a modified image or application can be loaded at all,
which is a boot-chain and container problem; and whether, once loaded, the keybox application admits
the current caller to the read handler, which is the application's own caller-gate problem.

### B.3.3 The container

The application is not a bare ELF object but an encrypted payload inside a signature-verification
wrapper:

```
application file
  |- encrypted ELF payload
  |- container description
  |- wrapped symmetric key and initialisation vector
  \- signature or digest material
```

The management module reads the container, processes the wrapper with internal RSA material,
recovers an AES-CTR key and initialisation vector, decrypts the ELF, verifies the payload digest,
and places the application into secure-world execution.

The research held no original signing private key, so the modified application's vendor signature
cannot genuinely become valid. The boundary the record therefore adopts is not to delete the
verification flow but to keep container parsing, keep the unwrapping of symmetric material, keep the
AES-CTR decryption, handle only the error branch taken after verification fails, require the payload
to match the exact version, and refuse an application of an arbitrary version. This is also why the
management module, the application, the environment image and the target slot must all be pinned to
one set of version material: the route holds only for the exact build in the records, and an
over-the-air update on the same model, a different slot or a different handset each require fresh
collection and disassembly.

### B.3.4 The caller gate

The read-only path checks the command type, then the parameter types, then whether the caller mode
meets the application's expectation, before entering the keybox read handler. An ordinary Linux
client can satisfy the command and parameter formats without satisfying the expected caller mode.

The patch accordingly keeps the command-type check, keeps the parameter-type check, relaxes the
caller gate only on the read-only path, modifies neither the keybox write path nor the secure
objects, and is applied as a runtime overlay with the factory application restored on reboot.
Removing the dispatcher's checking logic wholesale would convert a bounded read experiment into an
arbitrary invocation surface whose boundary cannot be assessed.

### B.3.5 Runtime overlay

```
factory application -> a temporary overlay is established after boot
  -> the research client opens the patched application
  -> the read-only request completes
  -> the overlay disappears on reboot
```

The advantages recorded are that the vendor partition is not rewritten, the factory file is
retained, a failure is cleaned up by rebooting, factory and modified digests can be compared, and
the before and after states are easy to record. The limitations are that a service may already hold
a session on the old application, that the KeyMint service restart has to be handled, that the mount
state cannot be judged from the file path alone, that the application being read is not necessarily
the one the current process uses, and that secure-world state differs across a reboot. Establishing
that the path has been overlaid therefore does not establish that the request reached the patched
application.

### B.3.6 Descriptor and payload

```
descriptor                               payload
  |- magic                                 |- length prefix
  |- payload length                        |- EC private DER
  |- two key and certificate entries       |- EC certificate chain
  |- per-entry offset, size, count         |- length prefix
  \- payload digest                        |- RSA private DER
                                           \- RSA certificate chain
```

In the successful round the descriptor is 168 bytes and the payload 8578 bytes, cross-checked by one
integrity relation. The record states explicitly that these numbers describe that round's sample and
not every version, and that they are not themselves proof of success: they can serve as part of a
structural gate, after which DER, public-key and chain verification must still follow.

A parser must not rely on the descriptor's offsets alone, because the payload carries its own length
prefixes. The prescribed method is to parse the descriptor; verify the magic and reserved fields;
verify the payload length; verify the digest held in the descriptor; read the payload's internal
length prefixes; confirm each against the internal length of each DER object; check certificate
counts and boundaries item by item; and verify each chain cryptographically.

### B.3.7 Acceptance

The result must satisfy, at minimum, a correct descriptor magic; agreement between the descriptor's
digest and the payload; no entry out of bounds; EC and RSA private keys that parse; equality between
each private key's public half and the corresponding leaf certificate's public key; and valid
signatures at every level from leaf to root. A client return value, a payload length or a PEM file
is not sufficient.

Where a private key and a certificate's public key disagree, the record lists the common causes: a
misaligned parse offset, the wrong version's descriptor, a truncated payload, results from another
round mixed into the working directory, an incorrect certificate order, test data having been read,
or the application not having been replaced by the patched version at all.

### B.3.8 Pitfalls

The same model is not the same version: every patch is bound to the exact system version, little
kernel, environment image, keybox application and management-module digest, and an update,
downgrade, kernel change, slot change or sibling handset requires fresh disassembly. Modifying the
application without handling the loader fails, since the vendor signature mismatch causes rejection
before the payload is decrypted. Handling the verification without preserving container parsing,
AES-CTR decryption and the digest check fails too, since the application will not reach its normal
handler even once loaded. Deleting the caller-mode gate entirely overshoots the research goal. A
runtime overlay is not a permanent install, and the converse also holds, in that a service holding
an old session means the code in use cannot be judged from the path. And experiments should write
only the designated candidate slot, retaining the factory slot and a complete backup, with partition
digests verified after a rollback, since a successful boot is not a consistency check.

### B.3.9 The closed loop

```
exact version baseline -> static analysis of the container -> decryption and parsing preserved
  -> only the read-only caller gate relaxed -> temporary runtime overlay -> a real session opened
  -> descriptor and payload read -> EC and RSA DER parsed
  -> private keys matched against leaf certificates -> chains verified
  -> reboot restores the factory application -> partition and service state accepted
```

The object of study is therefore not a keybox file but the combination of boot chain, container,
caller gate, payload format and restore boundary.

## B.4 Redmi K70E: proper DICE, the leaf identifier, and issued certificates

### B.4.1 Revision of the objective

The initial objective was to find an earlier provisioning seed or device-secret root material. The
research established progressively that the raw compound identifier, the final `CDI_Leaf` and the
native per-key scalar are not the same object; that the final leaf is affected by boot measurements;
that modifying the environment or a boot component changes the subsequent chain; that a 32-byte
value from which a public key can be derived is not necessarily the device secret; that the earlier
the stage, the more likely it is to contaminate later measurements; and that holding one identity
value does not by itself permit construction of a request the backend will accept.

The objective was therefore replaced by a seven-step sequence: establish a stock baseline;
distinguish the raw identifier from the final leaf; capture the final leaf within a single
secure-world boot; construct a software request using that same round's chain and device
information; generate a new software P-256 private key; obtain the certificate chain for it; and
restore the device to a secure baseline.

### B.4.2 The chain shape and its consequence

```
device-secret root -> stage-one measurement -> stage-two measurement
  -> environment and KeyMint measurement -> final CDI_Leaf -> version-3 certificate request
```

The abstract relation is `CDI_next = KDF(CDI_current, measurement, code_id, configuration)`, so the
final leaf is not a per-model seed. It changes if the preloader, the little kernel, the environment
image, `init_boot`, the active slot, the measurement configuration or the secure-world load state
changes. A historical leaf therefore cannot be hardcoded into a new round, and one device's identity
cannot be copied to another unit of the same model.

### B.4.3 Three classes of 32-byte material

The *raw compound identifier* is an input to the subsequent derivation path. It is not the final
private key, not the identity the request uses directly, not the device secret, and not a seed that
can be handed to a software provisioning tool.

The *final `CDI_Leaf`* is the leaf private scalar that participates in signing the current identity
once derivation has completed. This is the layer the software route uses.

The *native per-key scalar* is the private scalar KeyMint generated for one specific attestation
key. It closes against its own authenticated public key, leaf certificate and signature, but it is
not the identity.

### B.4.4 Exact-frame patching

Modifying the environment image is not the same as being able to repackage it. The record is precise
about what was done: the vendor RSA signature bytes were not forged, the verifier still runs, and
body and header digests are preserved. What was modified is the secure-boot provider's error branch
on the verification return value, so that a non-zero result no longer immediately blocks the
subsequent load, while container parsing, decompression and the length contract must all still hold.
Describing this as a forged signature would misstate both the location of the defect and the
capability obtained; it is a loader error-handling boundary.

Early full-recompression candidates destroyed the certificates, the device tree or the
compressed-block boundaries at the LZ4 frame tail, and the handset hung at the boot logo. The
approach that works preserves the original frame structure, changes only the minimum bytes near the
target instruction, keeps the decompressed length unchanged, keeps every other compressed block
byte-identical, keeps the frame tail, certificates and device tree untouched, and re-verifies image
structure and digests. This is also why the earlier conclusion that every patch hangs at the logo
was wrong: the compressed frame and load contract were being destroyed, not every minimal patch
being infeasible.

### B.4.5 One-shot binding and automatic restore

```
a stock restore image is staged in advance
  -> it triggers only when target device, slot and digest all match
  -> the current boot uses the candidate image
  -> the same-round leaf and certificate request are captured
  -> once the system has booted, the on-disk image is restored to stock
  -> the current secure world is not restarted
  -> the next boot uses the stock image
```

This design invites one misjudgement: after boot completes the on-disk image is stock, and that does
not establish that the candidate image did not run. The purpose of the restore is to return the disk
to a safe state while preserving the results of the current secure-world boot. What must be examined
jointly instead are the boot markers, the runtime namespace, the application digest, the restore
record and the boot identifier.

### B.4.6 Same-round capture

```
stock or approved research environment
  -> native zero-key certificate request
  -> verify that round's chain, outer signature and device information
  -> capture the final CDI_Leaf scalar
  -> derive its public-key information
  -> constant-time comparison against the leaf public key of the same round's native request
  -> save the identity only on a match
```

The anti-pattern, stated as such, is to capture a 32-byte value, find a certificate request some
days later, staple the two together and submit them. Because the leaf is measurement-bound, request,
chain, device information, challenge and identity scalar must all come from one round.

### B.4.7 Two keys that must differ

The *device-identity private key* signs a fresh challenge and the request's identity data, and
proves that the request comes from the device's own identity. The *software-generated P-256 private
key* supplies the public key inside `keysToSign`, receives the returned leaf certificate, and
carries subsequent Android key attestation.

```
CDI_Leaf identity private -> signs the identity request -> the backend validates chain and device info
software P-256 private -> its public key enters keysToSign -> the backend signs that public key
                       -> returned leaf public key == software private key's public key
```

Requiring the two to be equal judges a correct result a failure.

### B.4.8 Request object relations

```
AuthenticatedRequest          CsrPayload
  |- outer signed data          |- request version
  |- DICE certificate chain     |- keymint profile
  |- device information         |- keysToSign
  |- challenge                  \- canonically encoded fields
  \- request payload
```

The verification relations are that the same-round leaf public key equals the signing identity of
the request; that the software private key's public half equals the `keysToSign` public key; that it
also equals the public key in the returned leaf certificate; and that the chain runs from leaf
through intermediate to root. The record adds six further checks: whether the CBOR is canonical;
whether fields foreign to the version have been mixed into the payload; whether the device
information matches the target profile; whether the endpoint key and challenge are fresh; whether
the returned certificates are fully consumed; and whether there is a duplicate leaf, a broken link,
a cycle or a stray extra certificate.

### B.4.9 Pitfalls

Treating the native per-key scalar as the identity scalar; handing a raw compound identifier
straight to a software tool, which has not been through the device's derivation; requiring the
identity key and the key awaiting issuance to be the same; mixing fields from older versions into a
version-3 request, where a field that looks reasonable at the wrong level is enough to produce HTTP
400; saving only a bare chain and thereby losing the signing context between device information and
the outer signed data; concluding that modified DICE is necessarily the cause of a rejection; an old
parser dropping unknown fields of the provisioning-information extension; treating a restored stock
image as proof the candidate image never ran; and recompressing the environment image in full.

### B.4.10 The causal correction on provisioning status

The route is most easily written up wrongly by attributing a `NOT_APPROVED` verdict directly to the
modified chain. The earlier round changed several variables at once: modified chain, plus a
historical or mismatched set of device information, plus a new challenge, request and server state.
That round can therefore show only that the combination did not pass.

A later control kept the same modified chain and substituted clean device information consistent
with the target device profile, and recorded `APPROVED`. The record states what this licenses: that
a modified chain is not a sufficient rejection condition; that the complete device-information tuple
and the server-side registered profile may be important gates; that the control is evidence from
decomposing a combination of factors; and that without a single-field comparison no individual field
can be claimed as the root cause.

Separately, an early acceptance parser dropped unknown fields of the provisioning-information
extension and once treated a certificate carrying `NOT_APPROVED` as a pass. The root cause was not a
verification error but the loss of the server's status field. Hence the rule the record states, and
which this report adopts:

```
X.509 and DICE signatures mathematically valid
          !=
server-side provisioning status acceptable
```

Unknown fields must be preserved, the status gated on explicitly, and never overridden by a digest
match or a chain verification.

### B.4.11 The closed loop

```
a same-round stock or approved research environment -> capture the final CDI_Leaf
  -> derive the identity public key and compare against the native zero-key request
  -> the host generates a new software P-256 private key
  -> reuse the same round's complete chain and device information
  -> obtain a fresh challenge and endpoint key -> construct a canonical version-3 request
  -> fetch and sign remotely -> obtain a complete certificate chain
  -> returned leaf public key == software private key's public key
  -> verify level by level to a single self-signed root
  -> retain request, response, private key and chain -> restore the device to the stock baseline
```

The product is not an exported native KeyMint private key. It is a same-round device identity, a
newly generated software private key, the complete chain issued for that public key, and a
reviewable set of request, response, certificate and restore evidence.

## B.5 Conclusions the record draws across the three devices

*Entry and exit are separate problems.* The entry may be the boot chain admitting a research
component, the container mishandling a verification failure, the caller mode being loosely bound to
command permissions, an observable point in the lifetime of plaintext, or a request path that omits
key-provenance binding. The exit is the mapped buffer, the descriptor and payload, the certificate
request, the signed data, or the returned chain. Each must be established separately; the exit
cannot be assumed from the entry.

*Static analysis does not substitute for dynamic evidence.* Observing a derivation, a parser or a
copy function statically does not establish that the path was taken at runtime. A dynamic result
additionally requires the current version and digests, the current slot, the current application and
environment, the current service state, the request input, the return status, the actual output and
the restore state.

*Acceptance verifies relations, not signatures alone.* A chain that verifies shows only that its
signature relations hold. Also required: private key against leaf certificate public key; request
identity against the same round's leaf; device information against the current device profile;
request against the current challenge; and result against the current run.

*Failure records are not superseded by eventual success.* All three devices passed through states
that resembled success: output that was not the target material; a private key that was not the
device identity; an HTTP 200 whose certificate status was unacceptable; a boot whose measurement
state was wrong; and a chain that verified while the private-key correspondence did not hold. These
intermediate results are to be retained and marked as corroborating, failed, or pending
re-verification.

The record's closing summary is that the output across the three devices is the joining of layers —
boot-chain load boundary, invocation path, secure-object decryption or identity derivation, the
observation point, structured parsing, key and certificate relations, remote issuance status, and
rollback evidence — and that without these relations what has been obtained is a sequence of bytes.
