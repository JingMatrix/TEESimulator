# Appendix D. Working record: the MiTEE loader bench

Index: [the index](README.md). Subject parts: [part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret), [appendix
B](B-record-three-devices.md), [part 4 §6](4-measurements.md#6-the-measured-platform).

[Part 4 §6](4-measurements.md#6-the-measured-platform) characterises this platform from public
vendor trees and firmware dumps; [part 2 §6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret)
reconstructs Route D from the field record of [appendix B](B-record-three-devices.md). Neither used
a handset. This appendix is the first section of the report written from one: a unit of the measured
model, reachable over [`adb`](https://developer.android.com/tools/adb), with its bootloader locked,
[verified boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot)
reporting green, and transient root through the chain of [part 4
§6.5](4-measurements.md#65-normal-world-root).

It records four things: what the unit measures, what an operator account recommends and what that
recommendation rests on, which component actually holds the loader decision Route D turned on, and
what has not been attempted. *No partition was written.* Every quantity below comes from a read of
this unit or of a file carved from it, and [§D.11](#d11-what-this-does-not-establish) states what a
read cannot settle.

The scope rule of [part 1 §1.3](1-protocol.md#13-scope-and-conventions) applies unchanged. Symbol
and service names the images carry are given, because they identify the mechanism; patch patterns,
instruction offsets and the operative bytes of either bypass are withheld, because they are the
route rather than evidence of it.

## D.1 The unit

The handset is the global variant of the device of [part 4
§6.1](4-measurements.md#61-handset-and-environment-census) — the same model, one market removed from
the build string that sample A's provisioning extension names ([part 4
§3.1](4-measurements.md#31-published-schema-and-observed-encodings)), which is the China variant of
the same platform release:

```
ro.build.fingerprint   POCO/duchamp_global/duchamp:16/BP2A.250605.031.A3/OS3.0.9.0.WNLMIXM:user/release-keys
ro.hardware            mt6897
ro.boot.slot_suffix    _b
ro.boot.verifiedbootstate   green
ro.boot.vbmeta.device_state locked      ro.boot.flash.locked   1
ro.secureboot.lockstate     locked      ro.build.version.sdk  36
uname -r               6.1.138-android14-11-g44bda9e8f6e9-ab13792638
```

The kernel string is the one [part 4 §6.5](4-measurements.md#65-normal-world-root) reads off the
public root tool's own target declaration, so that tool's stated target and this unit agree exactly
— which that section could not establish without a device. Root was obtained and is real: the shell
reports user zero in the manager's own
[SELinux](https://source.android.com/docs/security/features/selinux) domain rather than in a shell
domain. It is also transient, as that section describes: after a reboot `su` is absent from the
search path again, because the chain of [CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499)
delivers privilege into a running kernel and leaves nothing on disk. Every write proposed in
[§D.3](#d3-the-operator-advice-decoded) therefore has to happen inside one root session, and a
session ends at the next boot.

*Partition geometry.* Names come from the by-name directory, nodes from resolving each symbolic
link, sizes from the block layer in 512-byte sectors:

| Name | Node | Sectors | Size |
|---|---|---|---|
| `preloader_raw_a` / `preloader_raw_b` | `dm-63` / `dm-64` | 8,184 | 3.996 MiB each |
| `lk_a` / `lk_b` | `sdc37` / `sdc69` | 32,768 | 16 MiB each |
| `tee_a` | `sdc42` | 10,240 | 5 MiB |
| `tee_b` | `sdc79` | 24,576 | 12 MiB |
| `seccfg` | `sdc19` | 16,384 | 8 MiB |
| `boot_a` / `boot_b` | `sdc38` / `sdc70` | 131,072 | 64 MiB |

Two rows carry consequences. The preloader slots are
[device-mapper](https://docs.kernel.org/admin-guide/device-mapper/index.html) targets rather than
[UFS](https://www.jedec.org/standards-documents/focus/flash/universal-flash-storage-ufs) partitions
of the main logical unit, which is why they are absent from the
[fastboot](https://source.android.com/docs/setup/test/running#fastboot) target set and why writing
one is a privileged block write rather than a flash command. And *the two environment slots are not
the same size* — five mebibytes against twelve. Any procedure that repacks the environment image
has a slot-dependent budget, and the active slot here is the larger one.

*The environment's normal-world surface.* The driver exposes three nodes, all owned by the system
user and group with mode `0660`: the client device, the privileged device, and a vendor-specific
performance device absent from upstream. The log interface of the vendor's memory-log driver is
present as two
[procfs](https://man7.org/linux/man-pages/man5/proc.5.html) entries under their own SELinux type,
both mode `0444`. On this unit the log entry reads empty and the key entry returns thirty-two bytes
of `0xff`, so the published concern that a world-readable entry discloses a live log key does not
bite here: the key is unprogrammed. The log itself is not lost, though — a privileged directory
under the vendor data tree holds a current log of about 1.4 MB and a previous-boot log of
10,487,000 bytes, written by a vendor userspace reader. That pair is the instrumentation channel
into the secure world, and it is readable with the access this unit already has.

*The client-path allowlist is satisfied by construction.* The forked driver's session-open path
takes the caller's executable path from its memory descriptor through
[`d_path`](https://www.kernel.org/doc/html/latest/filesystems/path-lookup.html) and admits only
three prefixes: the vendor binary directory, the ODM binary directory, and one
[APEX](https://source.android.com/docs/core/ota/apex) hardware directory belonging to the
[Widevine](https://developers.google.com/widevine/drm/overview) module. Everything else is refused
before a session exists. Measured against the unit, every client already sits inside it: the
supplicant, three vendor command-line tools — an information tool, a shell and a log reader — and
the environment's KeyMint [HAL](https://source.android.com/docs/core/architecture/hal) service,
declared at [AIDL](https://source.android.com/docs/core/architecture/aidl) version 3. The practical
consequence for any instrumentation is therefore a placement constraint, not a cryptographic one:
a new client must *be* at one of those paths. One trap worth recording, because it looks like a find
and is not: the vendor binary named `tee` is a symbolic link to the vendor
[toybox](https://landley.net/toybox/), the ordinary stream-duplicating utility, and has nothing to
do with the environment.

*The application store.* Nineteen application containers sit in a vendor directory, named by
[UUID](https://www.rfc-editor.org/rfc/rfc9562). This is two more than the seventeen that [part 4
§6.6](4-measurements.md#66-the-application-container) counts across two vendor-tree imports, so the
census there under-counts the current generation rather than over-counting it. The container header
decodes on the live files exactly as that section derives it from dumps — a four-byte magic followed
by the environment name, a format tag, then a big-endian payload length equal to the file size less
336:

```
dba51a17-0563-11e7-93b16fa7b0071a51.ta   1,401,936 bytes
  magic  fd 89 ee 6d        name "mitee"      tag 01 81 00 00
  payload length (BE) 0x156300 = 1,401,600 = 1,401,936 - 336
```

That identifier is the one [OP-TEE](https://optee.readthedocs.io/)'s reference keymaster application
carries upstream, which independently corroborates the build-path finding of [part 4
§6.1](4-measurements.md#61-handset-and-environment-census). The store also holds two containers far
larger than the rest, of 19,428,040 and 12,129,408 bytes, against a median near 450 KiB.

## D.2 The secure world, read off the handset

Both environment partitions were read whole. The active one decomposes with the third-party tool of
[§D.4](#d4-the-three-artifacts) into a
[Fuchsia](https://fuchsia.dev/) boot filesystem of 4,505,600 bytes holding thirty-one entries: a
directory of `0x3b8` bytes, a data section beginning at `0x3c8`, and every payload offset aligned to
4,096 bytes. The entries are seven executables, one in-image application, eleven drivers and twelve
shared libraries — among them the dynamic loader, the asynchronous dispatch library, the
input-output library and an unwinder, which is the dependency set [part 4
§6.2](4-measurements.md#62-identification-of-the-secure-operating-system) reports from the
applications' dynamic segments. Each is an ELF64 AArch64 object with no section headers and an
[xxHash](https://github.com/Cyan4973/xxHash) build identifier.

*The partition around it is a nine-record MediaTek container, and it is certificate-bearing.* Both
slots walk identically: a record header carrying the family magic, a 32-byte name, a declared data
size and a declared header size of `0x200`, with the next record at the following 16-byte boundary.
The records are `atf` (953,976 bytes), `cert1`, `cert2`, `tee` (3,106,816 — the boot image above),
`cert1`, `cert2`, `spmc_dtb` (1,024), `cert1`, `cert2`; the container occupies 4,074,640 bytes, so
the active 12 MiB slot carries 8.5 MiB of slack and the 5 MiB slot 1.1 MiB. *The repack budget is
therefore not the partition size* but the extent of the compressed frame inside the `tee` record,
which is the contract [§D.4.3](#d43-the-boot-filesystem-tool-and-one-correction-to-it) describes.

The certificates were checked against the images rather than assumed. For `tee` and `spmc_dtb`, the
SHA-256 of the record's data appears inside its own `cert2`, with the SHA-256 of the record's whole
512-byte header 56 bytes later. For `atf` the data digest matched only after the data was padded to
a 16-byte boundary — and `atf` is the one record of the three whose length is not already a multiple
of 16, so one rule is confirmed on the only record that can distinguish it. `cert2` itself decodes
as an [X.509](https://www.rfc-editor.org/rfc/rfc5280)-shaped `SEQUENCE` of 982 bytes that no
general-purpose parser will accept: after a version tag, serial, signature algorithm, an issuer and
subject of `C=AU, ST=Some-State, O=Mediatek`, a twenty-year validity and a public key, it carries a
flat list of object-identifier and value pairs under the vendor arc `2.16.886.2454`, with the image
digest and the header digest at inner-sequence members 10 and 14 — the two indices the public
library that parses this format hard-codes. The outer signature is RSASSA-PSS with SHA-256. The
three `cert1` records are byte-identical between slots, as a fixed signer should be; all six `cert2`
records differ, and `spmc_dtb`'s data is byte-identical between slots while its `cert2` is not,
which is the random-salt behaviour [part 4 §6.6](4-measurements.md#66-the-application-container)
reports for the application containers.

That settles, in the direction the locked choice of [§D.5](#d5-two-ways-past-image-verification)
needs, a question that section could otherwise only assume: *the format of the re-certification
applies to this image.* What does not follow is that a given loader build accepts a non-conforming
re-encoding of those records, and that remains the single open point on which the locked route
turns.

Two of the seven executables matter here, and both are new measurements rather than restatements:

*`bin/svchost` serves the fetch.* The storage service that [part 4
§6.3](4-measurements.md#63-storage-of-the-dice-secret) identifies as holding the hardware unique key
also *serves* the loader interface. It carries the service name `fuchsia.intsvc.SProvider` together
with the generated request and response type names of a method that loads an application from the
normal world, that interface's own identifier type, a service thread and an argument-object
allocator — the furniture of the server side.

*`bin/ta-mgr` fetches, verifies and decides.* The application manager, of 315,024 bytes, is the
*client*: it opens the service path under the private service directory and calls that method.
Alongside it holds the whole loading path — an attempt-to-load message, normal-world and
secure-filesystem load failures, an already-loaded case, and the memory-object creation calls — and
OP-TEE's cryptographic interface symbols verbatim: the
[RSA](https://www.rfc-editor.org/rfc/rfc8017) public-key allocation, the four hash-context calls,
the big-number import of a quantity named for the application public-key modulus, a
digest-comparison failure, and both branches of the signature verification.

*Which of the two actually verifies was read wrongly at first, and the resolution is the
distribution of those strings.* Both binaries carry the cryptographic interface, because it is
statically linked into each — svchost needs it for the secure-storage stack. But only the
application manager logs a verification *success*; only it carries the container format's own name;
only it carries the loader diagnostics and the version store; and only the storage service carries
the generated server-side type names. The reading that fits all of it is that the service call is a
*fetch* — its name says so — and that the manager parses, verifies, version-checks and maps the
container itself, with the bytes already in its own address space. [Section
D.10](#d10-corrections-made-in-the-course-of-this-record) records the earlier reading and why it
could not stand.

It also holds something [part 4 §6.6](4-measurements.md#66-the-application-container) inferred but
could not locate. That section established that no version field exists in the container header, and
reasoned that anti-rollback must therefore be tracked in a secure-world service rather than in a
normal-world file. The version store is here, in this binary: a version-check routine by name, an
old-version error carrying both compared values, a software-development-kit version comparison, and
read, write, update and load diagnostics for a *persistent object* holding the version — that is, a
[GlobalPlatform](https://globalplatform.org/specs-library/tee-internal-core-api-specification/)
object in the secure storage of [part 4 §6.3](4-measurements.md#63-storage-of-the-dice-secret),
reached through that same storage service. One message reads, verbatim and with its original
spelling, *"zero version dose not need storage"*, which states the exemption: an application
declaring version zero is not recorded, so it cannot be rolled back and cannot be pinned.

The division of labour is therefore exact, and it resolves a terminological difference between this
report's two sources. The field record of [appendix B](B-record-three-devices.md) says the research
changed *the secure-boot provider's error branch*; the operator account of
[§D.3](#d3-the-operator-advice-decoded) says *patch the application manager*. Both name the same
thing: the branch taken on the result of the provider's fetch, inside the manager. Both
operator-reachable decisions — that branch and the version check — therefore sit on the same side of
the channel as the bytes, which is what makes a change confined to the manager sufficient rather
than merely necessary. A change confined to the manager's handling of that status is
what [part 2 §6.2](2-mechanisms.md#62-exact-frame-patching) describes — the verifier still runs,
digests are still computed, no signature is forged — and it is the same defect class as Route C's
loader branch ([part 2 §5.3](2-mechanisms.md#53-two-neutralised-decisions)) and as the omitted
verification of [part 2 §3.4](2-mechanisms.md#34-the-omitted-verification). *What changes is what
the code does with a verification result*, which is the common structure [part 2
§8.1](2-mechanisms.md#81-decisions-rather-than-primitives) names.

## D.3 The operator advice, decoded

An operator account recommends a four-step order. Each step is given here with what it asserts, what
it rests on, and what this record verified. The account is a third-party claim in the sense of [part
5 §3](5-sources.md#3-appraisal): it is not reproduced, and where it was checked the check is stated.

*One: install a recovery floor before touching anything else.* Write an engineering first-stage
loader to both preloader slots, using the transient root as the write primitive, because a locked
device will not flash those slots and because without that floor a broken environment or bootloader
image cannot be recovered. The first-stage loader is what implements the
[USB](https://en.wikipedia.org/wiki/USB) download protocol by which a host pushes a *download agent*
— a RAM-resident flashing program — and then writes partitions through it. A retail loader verifies
that agent's signature; an engineering one does not, so download mode will accept any agent and the
device stays recoverable from any later mistake. The claim is structurally sound and the
candidate artifact is characterised in [§D.4](#d4-the-three-artifacts). Two costs belong in the same
breath: this write is simultaneously the recovery floor and the single most dangerous operation in
the sequence, because a wrong image in both slots leaves nothing to recover *through*; and it
permanently removes download-mode authentication from the unit.

*Two: unlocking is optional, because a certificate bypass exists.* Two interchangeable routes get a
modified environment image past verification, and [§D.5](#d5-two-ways-past-image-verification)
treats them. The account points at an archived public exploit that supports this exact device, and
notes that its own tooling makes unlocking unnecessary. Verified: that exploit's device table does
carry this codename with a named patch set, and the certificate bypass is implemented in two public
libraries, one of which the third artifact calls.

*Three: patch the application manager and the application.* Verified, and refined, in
[§D.2](#d2-the-secure-world-read-off-the-handset): the manager decides, a sibling service verifies,
and the manager additionally holds the rollback version store. The account adds two normal-world
cautions, both confirmed against the driver source and against this unit — the session-open path
restricts callers by executable path, and the driver maintains a log under the vendor data tree.
[Section D.1](#d1-the-unit) measures both.

*Four: the download agent is not the obstacle.* Any agent will do; the vendor's maintenance of this
model is poor enough that two published agent exploits still apply to current firmware; and from the
engineering package no exploit is needed at all, because the loader of step one does not check. The
last clause is the load-bearing one and it is consistent with the single discriminating marker
measured in [§D.4](#d4-the-three-artifacts). The two named exploits are not evidence here and were
not run; they matter only as the fallback that step one removes the need for.

The account's relation to [appendix B](B-record-three-devices.md) is worth stating plainly, because
it is why both are needed. That record is deliberately sanitised: its own publication boundary says
the public copy distributes no original files, patch bytes or executable extraction scripts, and its
practice log excludes raw commands and device-specific components. It therefore establishes *what*
was done and *why*, with its failures and its causal corrections intact, which is what [part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret) extracts. The operator
account supplies the operative layer that the record withholds. Neither corroborates the other;
they are complementary, and a claim resting on only one of them says so.

## D.4 The three artifacts

Held in this directory beside this file, and cited by digest in the manner of [part 1
§1.3](1-protocol.md#13-scope-and-conventions):

| Artifact | Size | SHA-256, first 16 hex | What it is |
|---|---|---|---|
| `preloader_duchamp.bin` | 768,316 | `b434c26cbed9de78` | candidate engineering first-stage loader |
| `DA_BR.bin` | 1,194,924 | `3c7a182edd4e32a6` | vendor download agent, version 6 |
| `mitee_bootfs.py` | 16,543 | `1f6634a1e3147264` | third-party boot-filesystem unpacker |

### D.4.1 The candidate loader, against the two the unit is running

MediaTek first-stage loaders carry a chain of generic file headers, defined publicly in
[U-Boot](https://u-boot.readthedocs.io/)'s [MediaTek image
tool](https://android.googlesource.com/platform/external/u-boot/+/refs/tags/android-mainline-11.0.0_r4/tools/mtk_image.h).
The candidate and both on-device loaders parse identically: five records in the same order — file
information, loader information, boot-ROM configuration, anti-clone and boot-ROM security
configuration — with byte-identical configuration bodies, the same load address, the same 240-byte
header, the same 1-mebibyte partition budget and the same 1,644-byte trailing signature block under
the same signature type. Same chip, same build family, same signing scheme.

They differ in exactly one way that bears on the claim:

```
                       size      "usbdl_vfy_da"     "platform/mt6897"
preloader_raw_a      746,700          0                   35
preloader_raw_b      746,700          0                   35
candidate            768,316          1 (":disabled")     38
```

Neither retail loader contains the download-agent verification marker in *any* form — not the
disabled variant, not an enabled one. The candidate is 21,616 bytes larger and carries one
occurrence, reading `usbdl_vfy_da:disabled`, plus three further source paths. So the difference is
not a flag flipped in a shared build: the candidate is a different build carrying code the retail
builds do not contain.

That is the whole measured case, and it is weaker than a proof. It establishes that the candidate is
a distinct build of this device's loader which logs that agent verification is disabled. It does not
establish that the string describes an unconditional policy rather than one branch of a conditional,
and it does not establish provenance — nothing here shows the file came from the vendor's
engineering package rather than from a modification of a retail one. The decisive test is dynamic
and is named in [§D.12](#d12-refutation-conditions).

Two incidental readings came out of the same comparison. *The two slots hold different builds*: both
are exactly 746,700 bytes, yet they differ in 8,090 bytes beginning at offset `0x2a51`, so this is
two builds of equal length rather than one build signed twice — unlike the application containers of
[part 4 §6.6](4-measurements.md#66-the-application-container), whose random salt makes identical
payloads differ. And the loader image's own 1-mebibyte budget leaves the candidate 280 KiB of
headroom in a 3.996 MiB slot, so size is not a constraint on this write.

### D.4.2 The download agent

A genuine vendor agent, not a patched one:

```
magic      "MTK_DOWNLOAD_AGENT"
identifier "MTK_DA_v6_2023-07-26 21:13:38"
entries    1       record magic 0xDADA      hardware code 0x1203
regions    3       0x02000000  0xbd260 + 256-byte signature
                   0x40000000  0x66890 + 256-byte signature, ending at the last byte of the file
```

The hardware code is the identifier this system-on-chip carries in
[`mtkclient`](https://github.com/bkerler/mtkclient)'s own chip table, whose comment names this
device among the three that share it — an independent cross-check that the agent matches the
platform. Both signature blocks are present and the second ends exactly at end of file, so nothing
has been stripped. Version 6 is the generation the two published agent exploits target, which is the
fallback of step four.

### D.4.3 The boot-filesystem tool, and one correction to it

The third artifact unpacks and repacks the boot filesystem inside an environment image: it finds the
[LZ4](https://github.com/lz4/lz4) frame, decompresses it with a self-contained decoder, replaces
file payloads, recompresses, and can then call the certificate bypass of
[§D.5](#d5-two-ways-past-image-verification) on the result. It ran correctly against this unit's
active environment partition, which is how [§D.2](#d2-the-secure-world-read-off-the-handset) was
measured.

*The format is upstream Fuchsia's, and the tool's field names are transposed.* The container is a
[Zircon boot-image](https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/sdk/lib/zbi-format/include/lib/zbi-format/zbi.h) boot filesystem: a
16-byte header carrying the magic and the directory size, then entries of a name length, a *payload
length*, a *payload offset* and a padded name. The tool reads the second and third of those in the
opposite order, so the field it calls the length is the offset and the field it calls the offset is
the length. Its author worked around this rather than fixing it, computing each file's size as the
difference between consecutive entries' offsets — which is why the listing in
[§D.2](#d2-the-secure-world-read-off-the-handset) reports sizes rounded up to the 4,096-byte
alignment, 315,392 where the application manager's true length is 315,024. Harmless for reading and
for same-size replacement; wrong if a reported size is used as a length.

*Two traps follow, and both matter before the tool is used in anger.* Its from-scratch builder
writes lengths into the offset field and so would emit an unparseable image; it is never called,
because both pack paths work by in-place replacement against a reference image, so *replacement at
the same size or smaller is the only supported operation*. A larger replacement prints a warning and
is then silently truncated, which on a signed container means the next boot fails a digest check for
a reason that has nothing to do with the patch under test. The repack path is otherwise exactly
right: it recomputes the original frame's extent and refuses to exceed it, preserving the device
tree and certificate material that follow the frame. That is not a stylistic choice. It is the
constraint [part 2 §6.2](2-mechanisms.md#62-exact-frame-patching) records as the lesson of a round
that bricked a device at the boot logo — *a modified environment cannot be treated as an arbitrarily
repacked one* — expressed as a tool contract.

### D.4.4 Publication boundary

The two vendor binaries are held locally and excluded from version control. They are vendor
firmware, and the engineering loader is additionally the operative content of step one rather than
evidence about it, so both fall under the rule of [part 1
§1.3](1-protocol.md#13-scope-and-conventions) and under the convention that sources are linked or
fingerprinted rather than mirrored ([part 5 §1.3](5-sources.md#13-archival-state)). Their digests
above are the citation. The unpacker is tracked, because it is a format reader whose behaviour this
appendix corrects and whose correction is worthless without the file it corrects. The source record
of [appendix B](B-record-three-devices.md) draws the same line for the same reasons, and states that
a filename, a hash or a research-only label is not redistribution permission.

## D.5 Two ways past image verification

*Through the second-stage loader.* The archived public exploit abuses an ordering flaw in the
MediaTek chain: when the security-configuration partition reads unlocked, the first-stage loader
stops verifying the extended second-stage loader — the very component responsible for verifying
everything after it, and one that runs at
[exception level 3](https://developer.arm.com/documentation/102412/latest/). Patching that
component's verification-policy accessor to succeed unconditionally collapses the chain of trust
from there down. Its device table carries this codename with a named patch set covering the
verification policy, the reported boot state, the lock state and the verification-error allowance,
and the matching stock image for this device ships in the repository. *It requires the bootloader
unlocked*, which is its entire premise.

*Through the certificate.* Each partition in these images carries a certificate holding
[SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) digests of the partition header
and of the partition data, signed by the vendor. The bypass forges no signature. It exploits how the
verifier walks the
[DER](https://www.itu.int/rec/T-REC-X.690) structure: one mode prepends a context-specific block
carrying the operator's digests ahead of the untouched original, the other wraps the signed
certificate in a bit string and appends a copy carrying new digests. The parser takes the digests it
reaches first; the signature it checks remains genuinely valid over the original bytes. Modified
partitions are re-certified and unmodified ones keep their original certificate untouched. This is
again a parse-order decision rather than a cryptographic break, and it belongs to the same family as
everything in [part 2 §8.1](2-mechanisms.md#81-decisions-rather-than-primitives).

*This bench takes the second route, and stays locked.* The reason is not convenience — the first
route is in fact better supplied here. It is that the locked, verified-boot-intact state is the
state the report's own detection argument turns on. [Part 4
§6.5](4-measurements.md#65-normal-world-root) makes the point that this platform reaches privileged
code with verified-boot metadata untouched, and therefore that *access is not the obstacle*; an
unlocked unit would no longer demonstrate that, and the boot-state fields a presenter cannot author
([part 3 §5](3-detection.md#5-forgeability)) would stop describing the device under test. Keeping
the unit locked also keeps the security-configuration partition out of the experiment entirely,
which removes one irreversible write.

## D.6 Measurement binding, and a tension with part 4 §6.3

[Appendix B](B-record-three-devices.md)'s principles chapter states the derivation as
`CDI_next = KDF(CDI_current, measurement, code identity, configuration)` and lists what can change
the leaf: the first-stage loader, the second-stage loader, the environment image, the initial boot
image, the active slot, the measurement configuration and the secure-world loading state. On that
statement the final leaf is not a model-wide constant, which is the reason [part 2
§6.4](2-mechanisms.md#64-same-round-capture) insists on same-round capture and why a historical leaf
cannot be spliced into a new request.

*If that is unrestricted, step one is expensive rather than cheap.* Writing a different first-stage
loader to both slots is permanent, so every subsequent boot would carry a non-stock measurement, and
the device's registered public key would never again match what the backend holds.

*But [part 4 §6.3](4-measurements.md#63-storage-of-the-dice-secret) measured the opposite shape.*
The environment's KeyMint application carries strings for checking whether a chain-key secret
exists, creating it, an already-created path, and a migration of that secret from the secure
filesystem into [replay-protected
memory](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#rpmb-secure-storage).
A secret created once and persisted is not re-derived from a boot measurement, and the inference
that section draws is explicitly that it is persisted rather than derived per boot.

These cannot both hold without qualification, and the report should not pretend otherwise. Three
readings survive, and they are distinguishable by experiment rather than by argument: the leaf is
derived per boot and the persisted object is a different secret; the leaf is persisted and the
record's list describes what *would* change a derived chain on platforms that derive one; or the
chain is persisted but re-created when a measurement changes, in which case step one destroys the
registered identity exactly once and silently. The cheap discriminator is to read the device's
native certificate request before and after a boot whose measurement differs, and compare the leaf
public keys — and the version-store exemption found in
[§D.2](#d2-the-secure-world-read-off-the-handset) suggests where the bookkeeping lives if there is
any. *Until that is measured, step one is a write with an unquantified cost to the thing the
experiment is about*, which is a reason to sequence it after the measurement rather than before, and
to weigh it against the recovery it buys.

Whichever reading holds, the one-shot design of [part 2
§6.3](2-mechanisms.md#63-one-shot-binding-at-boot) follows anyway: stage a stock restore image, arm
only on an exact device, slot, size and digest match, boot the candidate once, capture within that
boot, restore the disk while the current secure world keeps running. And the distinction of [part 2
§6.5](2-mechanisms.md#65-two-keys-that-must-differ) still decides whether a result is read as a
success: the identity key authenticates the request, a freshly generated software key is the one the
backend certifies, and requiring them to be equal judges a correct outcome a failure.

## D.7 What consumes a capture

Nothing in this appendix produces a certificate, and the minting half of the problem is already
implemented. The normal-world toolbox that [part 2
§6.5](2-mechanisms.md#65-two-keys-that-must-differ) cites for the two-key division accepts exactly
what a same-round capture yields: a complete original
[CBOR](https://www.rfc-editor.org/rfc/rfc8949) chain plus explicitly typed signing material. It
validates the chain's
[COSE](https://www.rfc-editor.org/rfc/rfc9052) signatures and the leaf-key match locally, requires
device and issuance configuration to be stated rather than guessed, obtains a fresh challenge,
generates a new [P-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) key per
invocation, signs a
[version-3 request](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl),
and exports a keybox only after the returned certificates match that new private key and pass local
checks. Its typed material kinds cover a signing seed, a final private scalar on three curves, and a
chain-attestation value with the
[open-dice](https://android.googlesource.com/platform/external/open-dice/+/refs/heads/main/docs/specification.md)
default derivation — and it refuses to guess a kind from byte length or vendor name, which is the
conflation [part 2 §2.3](2-mechanisms.md#23-consequences-of-conflation) warns about, enforced in
code.

That the scalar kinds include P-256 settles a contradiction [part 4
§6.3](4-measurements.md#63-storage-of-the-dice-secret) records: the earlier implementation built an
Ed25519 degenerate chain, which would have failed a registry match if this handset's registered key
is P-256, and the curve option removes that mismatch as a blocker. Which curve this device actually
registers remains unmeasured.

Two boundaries keep the division honest. The toolbox collects nothing from a device and patches no
firmware, so it cannot substitute for the capture half; and its own documentation records that
server acceptance of real imported material has not been verified. So a capture is necessary and the
minting path is not yet demonstrated end to end on real material by either source.

## D.8 The cheaper question first

One question on this platform needs no environment patch, no write and no unlock, and [part 4
§6.7](4-measurements.md#67-a-normal-world-keybox-installer) names it as the main unanswered one: a
system-identity boot service in the keystore group runs at every boot, linked against a vendor
library whose symbols install a keybox from a normal-world path into the environment, and whether
the application-side command it reaches is gated — by caller identity, by a provisioning lock, or by
memory state — could not be established from binaries alone. That library also carries the string
*"This device support rkp , but not upload public key"*, which records precisely the registration
state on which [part 1 §6.1](1-protocol.md#61-validation-order-at-the-backend) shows everything to
depend.

With the access this unit already has, that is a read: the daemon, its library, its command path and
the log channel of [§D.1](#d1-the-unit) are all in the normal world, and the clients that may open a
session are enumerated. It costs nothing irreversible, it does not consume the one-shot window of
[part 2 §6.3](2-mechanisms.md#63-one-shot-binding-at-boot), and either outcome is publishable:
an ungated installer is a material finding about the platform, and a gated one closes the question
[part 4 §6.7](4-measurements.md#67-a-normal-world-keybox-installer) leaves open. Sequencing it ahead
of any write also leaves the unit in the state [§D.5](#d5-two-ways-past-image-verification) argues
is worth preserving.

## D.9 Reproduction

Everything in [§D.1](#d1-the-unit), [§D.2](#d2-the-secure-world-read-off-the-handset) and
[§D.4](#d4-the-three-artifacts) comes from this sequence. It writes nothing to the device and needs
the root session of [part 4 §6.5](4-measurements.md#65-normal-world-root):

```
# 1. state and geometry: build fingerprint, slot, lock and verified-boot properties;
#    resolve every by-name link and read its sector count from the block layer.
# 2. surfaces: list the driver nodes, the two procfs log entries with their SELinux
#    types, the vendor log directory, and every client binary under the allowlisted
#    prefixes; read the first bytes of each application container.
# 3. loaders: read one mebibyte from each preloader slot; walk the generic file-header
#    chain to recover the declared total length; truncate to it; compare the two slots
#    byte for byte and count the discriminating marker in all three images.
# 4. environment: read both environment partitions whole; on the active one, locate the
#    compressed frame, decompress it, and walk the boot-filesystem directory, taking each
#    entry's true length from the field the tool mislabels.
# 5. components: for the application manager and the storage service, extract the string
#    pool and look for the service name, the generated call symbol, the cryptographic
#    interface symbols and the version-store diagnostics.
```

Step 3's truncation matters: a slot read returns the whole slot, and only the declared length is the
image. Step 4's parenthesis is the correction of
[§D.4.3](#d43-the-boot-filesystem-tool-and-one-correction-to-it).

## D.10 Corrections made in the course of this record

*Two markers were read as engineering indicators and are not.* An earlier reading of the candidate
loader offered a boot-ROM warning about bypassing a loader security check, and a security-bit
assignment, as supporting evidence. Both appear in both retail loaders on this unit at the same
counts. They carry no discriminating weight, and the case in
[§D.4.1](#d41-the-candidate-loader-against-the-two-the-unit-is-running) rests on the one marker that
does.

*The application manager was described as the verifier.* It is the client; the storage service
verifies. The distinction is what makes the terminological difference between this report's two
sources resolvable rather than contradictory
([§D.2](#d2-the-secure-world-read-off-the-handset)), and it changes where a patch would have to go.

*A vendor binary named for the environment was taken for an environment tool.* It is a link to the
vendor toybox's stream-duplicating utility.

*The application manager's length was misconverted.* Its directory entry reads `0x4ce90`, which is
315,024 and not the 314,512 first stated. The hexadecimal reading was right and the decimal
conversion was wrong; the padded slot of 315,392 and therefore the argument of
[§D.4.3](#d43-the-boot-filesystem-tool-and-one-correction-to-it) are unaffected. The field order of
that entry is now confirmed against
[Fuchsia's own `bootfs.h`](https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/sdk/lib/zbi-format/include/lib/zbi-format/internal/bootfs.h),
which defines `ZBI_BOOTFS_MAGIC` as `0xa56d3ff9`, orders the entry words `name_len`, `data_len`,
`data_off`, requires the payload offset to be a multiple of a 4,096-byte page, and pads each entry
to a four-byte boundary — every one of the 31 payload offsets measured here satisfies that
alignment, and the directory ends exactly at its declared size.

*The verification was assigned to the wrong process.* This record first stated that the storage
service verifies an application container and that the application manager only decides what its
verdict means. That reading cannot stand, and the reason is structural rather than evidential: if
verification ran on the far side of the channel, a failure would return a status and no payload, and
a change confined to the client would have nothing left to map — which would make the field record's
own account of what it changed insufficient. Re-reading the two binaries settles it the other way.
Both carry the cryptographic interface, because it is statically linked into each, but only the
manager logs a verification *success*, names the container format, and holds the loader diagnostics
and the version store, while only the storage service holds the generated server-side type names.
The service call is a fetch; the manager verifies. [Section D.2](#d2-the-secure-world-read-off-the-handset)
now reads that way, and the consequence is the one that matters: both operator-reachable decisions
sit on the same side of the channel as the bytes.

## D.11 What this does not establish

*Nothing here was executed in the secure world.* No image was repacked and installed, no patch was
applied, no application was replaced, no session was opened. The loader decision of
[§D.2](#d2-the-secure-world-read-off-the-handset) is located by its own strings and by its call to a
named service; that it behaves as the field record describes is not shown here.

*The candidate loader's provenance is unestablished*, and its single marker is a log string rather
than an observed policy ([§D.4.1](#d41-the-candidate-loader-against-the-two-the-unit-is-running)).

*String evidence bounds the search, not the universe.* These images are stripped — no section
headers and no exported function symbols — so every component claim in
[§D.2](#d2-the-secure-world-read-off-the-handset) rests on strings and on dynamic-segment entries.
The absence of a string is not the absence of code, as [part 4
§7](4-measurements.md#7-threats-to-validity) states for the same reason.

*One unit, one build.* The census difference against [part 4
§6.6](4-measurements.md#66-the-application-container), the slot-size asymmetry and the unprogrammed
log key are properties of this handset on this build, not of the model.

*The tension of [§D.6](#d6-measurement-binding-and-a-tension-with-part-4-63) is unresolved*, and
with it the cost of step one.

## D.12 Refutation conditions

*That the candidate loader does not verify a download agent*
([§D.4.1](#d41-the-candidate-loader-against-the-two-the-unit-is-running)): an unsigned agent refused
by a device running it. This is the decisive test and it is dynamic; the static reading cannot
substitute.

*That the application manager verifies the container it fetched, and the storage service only
serves the fetch* ([§D.2](#d2-the-secure-world-read-off-the-handset)): a load that fails with the
manager's verification code never entered, or a verification-success record emitted by the storage
service. Note that the earlier, opposite reading was refuted by argument rather than by this test,
so the test is still worth running.

*That the secure-OS partition's `cert2` records carry the digests of the images they follow*
([§D.2](#d2-the-secure-world-read-off-the-handset)): a record whose recomputed data digest does not
appear in its certificate under either the padded or the unpadded rule, or a member index other
than 10 and 14 carrying them on another build.

*That the image digest is taken over the data padded to the container's 16-byte alignment*
([§D.2](#d2-the-secure-world-read-off-the-handset)): a second record of non-aligned length whose
digest matches the unpadded data instead. Only one such record exists in this image, so the rule
rests on a single discriminating observation.

*That anti-rollback is tracked in a persistent object by the application manager* ([part 4
§6.6](4-measurements.md#66-the-application-container) left this open): a version comparison in any
other component, or a downgrade accepted with that object intact.

*That the client allowlist gates every session* ([§D.1](#d1-the-unit)): a session opened by a binary
outside the three prefixes.

*That the two environment slots differ in size* ([§D.1](#d1-the-unit)): equal sector counts on
another unit of the model, which would make this one's table an artifact of its update history
rather than a property of the layout.

*That the leaf is measurement-bound on this platform*
([§D.6](#d6-measurement-binding-and-a-tension-with-part-4-63)): an unchanged leaf public key across
two boots whose measured components differ — which would also refute the premise that makes
same-round capture necessary.
