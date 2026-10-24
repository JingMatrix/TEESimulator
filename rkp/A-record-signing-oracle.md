# Appendix A. Record: a signing oracle on a Qualcomm KeyMint trusted application

Published at <https://bbs.kanxue.com/thread-293244.htm>. The content of that post is set down here
because the medium is unstable: only the opening post exists in the page's static HTML, replies load
over JavaScript, a plain text conversion of the page yields nothing, and a forum thread can be
edited, deleted or placed behind a login. This appendix preserves the record's technical substance —
measurements, structures, negative results and the author's own qualifications — organised rather
than translated. The analysis of what it does and does not establish is [part 2
§3](2-mechanisms.md#3-route-a-a-signing-oracle-on-qualcomm-keymint); its appraisal as a source is
[part 5 §3.1](5-sources.md#31-the-signing-oracle-post).

Four classes of constant present in the original are withheld here, per the scope rule of [part 1
§1.3](1-protocol.md#13-scope-and-conventions): the runtime address of the derived secret inside the
trusted application, the internal addresses of the functions on the request path, the address of a
bounds check, and the command number of the call reported to return a hardware-derived secret.
Command number `0x3122` is retained, since open-source client code publishes it independently ([part
5 §2.2](5-sources.md#22-primary-research-records)). The author's own notice states that the material
is for study and not for unlawful use.

## A.1 Objective

A device with KeyMint 2.0 or later ships with no attestation keybox installed and obtains
certificates at runtime over RKP: the trusted application generates a key pair, places the public
key in a certificate-signing request, signs that request with `CDI_Leaf` so that the DICE chain
endorses it back to the fuses, and Google returns an X.509 chain.

Two approaches to abusing this were already known to the author. *Harvesting* extracts the device's
`CDI_Leaf` seed from the trusted execution environment and then signs certificates offline without
limit. *Proxy signing* lets the device perform a normal certificate request on an attacker's behalf.
The first is permanent but requires extraction; the second requires the handset to be present for
each use.

The record describes a third approach: take no seed, bypass the system provisioning flow, and use
the KeyMint trusted application directly as a signing oracle, so that it signs a request over an
attacker-supplied software public key using the genuine `CDI_Leaf`. That request is submitted to
Google, which returns a complete attestation chain, from which a usable keybox file is assembled.

On the handset examined, `CDI_Leaf` is a 32-byte Ed25519 seed derived as `KDF(SHK, "RKP PRIVATE KEY
SEED")`, where `SHK` is the hardware secret key of the system-on-chip key ladder. It is resident at
a fixed address in the trusted application's global area at runtime, with its public key adjacent.
The derivation label is specific to this vendor; [part 2
§4.5](2-mechanisms.md#45-the-derivation-call-site-and-its-label) records a different label in
production on Trustonic Kinibi.

In the normal flow, every public key in `keysToSign` must have been generated inside the trusted
execution environment, and the mechanism that guarantees this is the authentication tag each key
carries, computed with a device-unique provisioning key that the normal world does not hold. That
tag is the only checkpoint in the trust chain that prevents a software-held private key from
entering the signing queue.

## A.2 Antecedent failures

The research began as a harvesting attempt. The record presents the failure map as a measurement in
its own right, because it establishes the cost of the alternative. The conclusion drawn is that the
primary bootloader of this handset already fixes the loader defect that CVE-2026-25262 depends on,
so the download-mode route does not hold there. The measured surface, under Sahara version 3, COM10,
and the authorised programmer `xbl_s_devprg_ns.melf`:

| Attack surface | Measured result |
|---|---|
| First-stage RV32 stub, data-segment modification | accepted with status 0, but that stub never executes; an entry-hang patch had no effect |
| First-stage stub, header or program-header modification | rejected (`0x30`): verified before the data is pulled |
| Four later ELF images, data-segment modification | rejected (`0x22`): verified after the pull |
| The same four images, program-header redirection | rejected (`0x21`, `0x25`): verified up front |
| Sahara memory-debug greeting | rejected (`0x1b`) |
| Firehose `peek` and `poke` | rejected: "Peek is disabled on secure boot devices" |
| Firehose `configure`, `read`, `getstorageinfo` | accepted, leaving partition reads available |

All 33 fastboot commands were exhausted without yielding a memory read or write primitive. The
vendor unlock path is a 32-byte challenge plus an RSA-2048 server token and cannot be forged
offline. A nonce-reuse probe against the Ed25519 implementation — ten certificate requests over ten
distinct challenges — found zero repeated `R` values, so the implementation is conformant in that
respect.

Two by-products survived the negative result: a complete set of partition backups, and the device's
genuine `CDI_Leaf` public key, recovered from a certificate request by verifying the signer of its
signed data.

## A.3 The trusted application as the object of study

If the secret has to leave only once, in the form of a signature, then the object of study is the
command-handling logic of the trusted application rather than memory isolation.

Full linear disassembly of the KeyMint image, reported byte-identical to the live partition and an
ELF64 AArch64 object, recovered a dispatch table of 96 commands and the request path:

```
GENERATE_CSR_V2 (0x3122)
  -> generateCsrHandlerV2
  -> generateBcc
  -> derive_device_private_key        ; the CDI_Leaf derivation point
```

The audit found the surrounding input validation strict rather than weak: the challenge carries a
hard 64-byte bound enforced by an explicit compare-and-branch, every memory copy is clamped to a
minimum, the CBOR cursor is tracked, and no out-of-bounds read was found anywhere on the surface.

The defect is one omission. The authentication-tag verification routine, `parseMacTags`, is
cross-referenced only from the version-1 request path (`0x311e`) and from a `CSR_V2_FIXED` command
(`0x3125`). The ordinary `0x3122` path never calls it, so on that path the requirement that a key
must have been generated inside the trusted execution environment is not checked at all.

## A.4 Reaching the command surface

The handset had root through KernelSU, with SELinux still enforcing and the process in the KernelSU
domain. Android's own client does not address the trusted application directly but goes through the
binder HAL, whose interface is shaped so that private keys cannot escape.

The record documents which approaches to the lower interface fail. There is no `/dev/qseecom` on
this platform; `/dev/smcinvoke` is present. The library `libQSEEComAPI.so` is a compatibility shim
over MINK inter-process communication, in which `start_app` works but `send_cmd` is refused by the
object model.

What works is to replicate what the HAL does: load `libkeymasterdeviceutils.so` dynamically,
construct its `KeymasterUtils` object for the trusted-environment security level, and call
`send_cmd`. That is a MINK invocation with operation 0 and a descriptor count of `0x11`, carried
over ordinary heap buffers, against the trusted application name `keymaster64`. The wire format,
established from disassembly of the application's entry point, is `LE32 command ‖ payload` for the
request and `LE32 return-code ‖ LE32 length ‖ payload` for the response.

The client written for this, `kmcli`, uses no NDK: it links with clang directly against the bionic
`libc.so` and `libdl.so` pulled from the device, and supports single and batch invocation with
responses written to disk. Baseline invocations of `0x200 GET_VERSION` and `0x311f
GET_ROOT_OF_TRUST` both succeeded.

Two incidental findings were measured on the same surface. A `GENERATE_FRS_AND_UDS` command returns
a 32-byte secret derived from the hardware key directly, and the provisioning gate does not prevent
it; the static audit had expected a production device to reject the call with `-0x2711`, and in
practice it was open. A neighbouring command is not an arbitrary authentication oracle, as had been
hoped, but a P-256 key-pair generation and authentication backend.

## A.5 Request format

A `0x3122` request is a CBOR map with exactly two entries; a third causes the call to return `-1`.

| Label | Content |
|---|---|
| `4` | `challenge`: byte string, at most 64 bytes |
| `57` | `keysToSign`: byte string containing a CBOR array of COSE_Key structures |

The response is the single-entry map `{61: bstr(AuthenticatedRequest)}`, which must be unwrapped.
The key uses the standard P-256 form `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.

## A.6 Procedure and failure modes

```
[host]   generate a P-256 key pair and retain the private key
[host]   fetchEekChain -> Google issues a challenge
[host]   assemble {4: challenge, 57: bstr([our COSE_Key])}
[device] send command 0x3122 -> the application does not verify the tag, encodes the supplied
         public key into the payload, signs the request with the genuine CDI_Leaf, and returns it
[host]   unwrap {61: bstr} -> POST signCertificates?challenge=...
[host]   Google returns a four-level chain -> assemble keybox.xml from the private key and chain
```

Three failure modes were forced out by HTTP 400 responses. The field `keysToSign` must be an array
of COSE_Key structures and not a bare map, the error text being "Expected an array, got MAP". The
substantive error, which produces the same message, is submitting the application's single-entry
response map instead of its contents; unwrapping first makes the request pass immediately. And
version 2 of the schema has no `ProtectedData` field at all — the second element of
`AuthenticatedRequest` is a possibly empty `UdsCerts` map — so no endpoint encryption key need be
constructed.

## A.7 Result

The production endpoint `remoteprovisioning.googleapis.com` returned HTTP 200 and a four-level
chain:

```
CN=<public key hash>, O=TEE  ->  CN=Droid CA3  ->  CN=Droid CA2  ->  Key Attestation CA1
```

Acceptance was established as follows: the public key of the leaf certificate equals the public half
of the host-held private key; every signature in the chain verifies in turn; and the assembled
keybox file pairs with the private key. Repeated runs all succeeded.

Two further observations are recorded. The chain carries no device-model fields of any kind, the
leaf's common name being a hash of the public key. And substituting an unrelated handset's build
fingerprint in the endpoint-key fetch still results in a signed request, because `DeviceInfo` is
determined by the application's internal provisioning state and never reaches the final certificate.
At this layer, changing the device model is therefore a pseudo-requirement; what controls the
attested model is the interposition layer above, which in the author's deployment is a keystore
interception module.

## A.8 Why the backend cannot distinguish the request

The certificate semantics establish exactly one proposition: at signing time, this public key
appeared in a request signed by a genuine device's `CDI_Leaf`.

The DICE chain signature establishes that the request came from a real device's trusted execution
environment, and it was neither forged nor forgeable here. Whether the public key inside that
signature was generated inside that environment can be guaranteed only by the application's
authentication-tag verification. This version does not perform that verification on the version-2
path, so any key from the normal world can enter the signing queue, and the requirement that an
attestation key be generated inside the trusted environment degenerates into an empty statement. No
memory isolation is broken; a gap in command semantics is used.

## A.9 Preconditions and boundaries

The preconditions are a direct connection to the command surface of the trusted application, which
on this handset means root; this version of the vendor KeyMint firmware; and a DICE chain the
backend accepts. Non-Qualcomm platforms use a different command format and would require separate
reverse engineering.

Request generation is read-only: it does not alter device state, does not affect the bootloader lock
state, and does not require download mode.

The route stops working if the trusted application wires authentication-tag verification into the
version-2 path, which is a firmware fix, or if the backend changes policy. The author's assessment
is that seed harvesting remains the more thorough capability and that the oracle is the better
value-for-effort answer when every extraction channel on a given handset is closed.

The tooling the author reports producing consists of `kmcli`; a one-shot pipeline script joining
endpoint-key fetch, invocation, certificate request and keybox assembly; a static-analysis corpus
for the trusted application comprising the 96-command table, the full request-path disassembly and
the localisation of the seed in the global area; and the download-mode signature-verification map
together with the Sahara and firehose probe set.
