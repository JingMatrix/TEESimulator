# Appendix C. Screening record: the omitted verification, measured across three vendors

Index: [the index](README.md). Subject parts: [part 2
§3](2-mechanisms.md#3-route-a-a-signing-oracle-on-qualcomm-keymint), [appendix
A](A-record-signing-oracle.md), [part 5 §3.1](5-sources.md#31-the-signing-oracle-post).

[Part 2 §3](2-mechanisms.md#3-route-a-a-signing-oracle-on-qualcomm-keymint) rests on one field
record and one independent client implementation, neither of which was re-run. This appendix
re-measures that record's central claim — that the authenticated-public-key verification is not
wired into the ordinary certificate-request path — on a *different handset, a different
system-on-chip and a different vendor*, from vendor firmware alone. No device was used, no command
was sent, and the backend was not contacted. The claim of [part 2
§3.4](2-mechanisms.md#34-the-omitted-verification) therefore now rests on two independent readings
of unrelated firmware rather than on one account.

The scope rule of [part 1 §1.3](1-protocol.md#13-scope-and-conventions) applies unchanged: the
internal addresses of the functions on the request path are withheld, as is the command number of
the call that returns a hardware-derived secret. Functions are named by the symbols the image itself
carries. Command numbers `0x3122` and `0x3125` are retained on the same ground as in [appendix
A](A-record-signing-oracle.md): open-source client code publishes the first and the record publishes
the second.

## C.1 Artifacts

The handset is a mid-range Motorola on a Qualcomm Snapdragon 6 Gen 3, vendor platform `SM6475`,
device codename `paros`, model `XT2437-3` — two system-on-chip generations and one vendor removed
from the device of [appendix A](A-record-signing-oracle.md), which is a Lenovo tablet on `SM8750`.
Three retail [European-channel](https://mirrors.lolinet.com/firmware/lenomola/2024/paros/official/)
images were read, one per [Android](https://source.android.com/docs/setup/about/build-numbers)
generation:

| Build | Android | KeyMint trusted application, SHA-256 (first 16 hex) |
|---|---|---|
| `U4UQS34.50-43-2-1` | 14 | `8a5f1d4165e736dd` |
| `V1UQS35H.103-16-9` | 15 | `432e1ff2a6b6b935` |
| `W1UQS36H.73-38-3` | 16 | `977d79cab5096c58` |

*The trusted application is not a partition of its own on this platform.* It is `keymaster.mbn`
inside `bootloader.img`, which is a Motorola single-image container: a sequence of `0x100`-byte
record headers carrying a name and a payload length, each followed by its payload padded to the
header stride. That container also holds the [UEFI](https://uefi.org/specifications) application
bootloader, the trusted-execution-environment image and the device configuration, which is why a
device whose flashfile shows no `keymaster` partition may still ship one.

The wider screen of [§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix) reads fifty-eight
images across thirty-two Qualcomm firmware lines of three unrelated handset makers: thirty-eight
across twenty-three lines of this vendor, from the same mirror; sixteen across six lines of a second
maker, from that maker's own update payloads; and four across three lines of a third, from the
factory archives it publishes itself. This section's three builds are the line examined in detail,
and the hashes above are a second carve of them, made for this revision from the archives afresh —
the pipeline of [§C.7](#c7-reproduction) reproduces all three byte for byte.

Carved out, the application is an
[ELF64](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)
[AArch64](https://developer.arm.com/documentation/ddi0487/latest/) shared object with no section
headers, an executable segment of about 394 KiB, and a read-only-after-relocation data segment that
holds the command table.

## C.2 Method

*Only the needed members were transferred.* The flashfile is about 5.4 GiB; the mirror honours
[HTTP range requests](https://www.rfc-editor.org/rfc/rfc9110#field.range), so the archive's central
directory was read first and three members pulled individually — the bootloader container, the
kernel image and the vendor ramdisk — for about 230 MiB in total.

*The implementation family is decided before anything else.* Two unrelated trusted applications
ship under the same partition name and the same application name on this chip vendor's platforms:
the long-standing one written in C, which is what every step below reads, and a port of
[AOSP](https://android.googlesource.com/platform/system/keymint/)'s reference application to
[Rust](https://doc.rust-lang.org/reference/), which vendors the reference crates and carries their
source paths inside the image. The second has neither the logging convention of the next paragraph
but one nor the dispatch table of the next, so any verdict this method produced for it would be an
artefact of the tool rather than a reading of the image. The test is a string test and costs
nothing. [§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix) records what happened on the
pass that omitted it.

*The command table was recovered structurally.* Each record is a 32-bit command number, a 32-bit
flag word and a 64-bit handler address; 93 plausible records were found, against the 96 commands
[appendix A](A-record-signing-oracle.md) reports on the other platform. The record layout is pinned
by the result rather than assumed: under this layout *every* command number resolves to a handler
whose own symbol matches it — the version query to `getVersion`, the root-of-trust query to
`get_root_of_trust`, the freshness-and-device-secret call to `generate_frs`, key generation to its
own handler — and under the two neighbouring alignments it does not.

*The image names its own functions.* The application logs through a helper taking a `"%s:%u:%d"`
format together with the name of the calling function, so address-page-plus-offset pairs resolving
into the string pool recover a symbol for each function. This is what makes the result below
checkable by name instead of by offset, and it is the reason no address needs to be published here.

*Reachability was computed over direct branches.* Function starts were taken as the union of
branch-with-link targets and table handlers, extents as the interval to the next start, and edges as
the calls and tail branches inside each extent. For each command, the question asked was whether
`parseMacTags` or `verifyPublicKeyMacTags` is reachable from its handler.

## C.3 Result

| Command | Handler symbol | Verifies the authentication tags |
|---|---|---|
| certificate request, version 1 | `generateCsrHandler` | no |
| `0x3122` certificate request, version 2 | `generateCertificateRequestV2` | *no* |
| certificate request, version 1, fixed variant | `generateCsrHandler_FIXED` | yes |
| `0x3125` certificate request, version 2, fixed variant | `generateCertificateRequestV2_FIXED` | yes |
| request-key authentication | `generateRkpKeyMac` | — (it is the producer) |

*The two version-2 handlers differ by exactly one call.* Both allocate the request envelope, build
the certificate-signing payload, select the hardware or software
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/) path, build the
signed data, encode and serialise. The fixed variant also calls `parseMacTags`. Nothing else in
their call lists differs.

`parseMacTags` has two callers in the whole image: `verifyPublicKeyMacTags`, reached only from
`generateCsrHandler_FIXED`, and `generateCertificateRequestV2_FIXED`. Of 778 recovered functions,
four can reach it at all. Within it the image parses a
[COSE_Mac0](https://www.rfc-editor.org/rfc/rfc9052#section-6) structure, recomputes the tag through
`calculateCosePublicKeyMac` — the same routine the tag *producer* uses — validates the payload, and
carries the two test-mode mismatch strings that AOSP's grammar implies. The verification is
therefore present, correct in construction, and simply not called on the ordinary path, which is
precisely the shape [part 2 §3.4](2-mechanisms.md#34-the-omitted-verification) describes.

*Neither version-2 handler contains an indirect branch.* The image uses 118 register-indirect calls
elsewhere, so a reachability result over direct branches alone would ordinarily be a weak negative;
inside these two handlers there are none, so no edge can be hidden from the method.

One difference from [appendix A](A-record-signing-oracle.md) is worth recording as a difference
rather than a confirmation: there, the verification is cross-referenced from the version-1 path and
from the fixed variant. *Here the version-1 path does not verify either.* On this firmware only the
two fixed variants do, which makes it the more permissive of the two readings.

## C.4 The verification and the gap arrived together

The Android 14 and Android 15 trusted applications of the same handset contain *no* version-2
request command, *no* fixed variants and *no* `parseMacTags` at all; they implement version 1 only.
Two consequences follow, and they cut in opposite directions.

The first is operational: on this device the route is a property of the Android 16 application.
Reverting to an earlier build removes the command rather than restoring an unverified one, so the
usual instinct — downgrade to escape a fix — is inverted here.

*That first consequence was re-measured, and its stated premise was wrong.* The two earlier
applications were carved again and their symbol sets compared directly against the third. Android 14
and Android 15 are identical in every request-related name; what Android 16 adds is a single block
holding both halves of the mechanism at once — the version-2 commands with their fixed variants, the
verification (`parseMacTags`, `verifyPublicKeyMacTags`, `validateCoseMacPayload`), the tag
*producer* (`generateRkpKeyMac`, `generateEphemeralCoseMac0`, `calculateCosePublicKeyMac`) and the
hardware and software [DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/)
paths. The earlier builds are therefore not a state in which the check exists and is unwired: they
carry a complete version-1 request path — `generateCsrHandler`, `generateCsr`, their serialisation
pair, the [COSE_Encrypt](https://www.rfc-editor.org/rfc/rfc9052#section-5) machinery and both
derivation labels of [§C.6](#c6-platform-agreement-and-a-second-reading-of-the-derivation-label) —
and no authenticated-public-key machinery of any kind, neither the check nor the thing it checks.
Downgrading does not reach a build where the request's input is authenticated. It reaches one where
nothing in the trusted application authenticates it, and where whatever authentication the protocol
of [part 1 §2.4](1-protocol.md#24-key-generation-and-the-authenticated-public-key) requires can only
have been performed outside it. The same shape was then measured on six further builds across four
other lines of this vendor, so it is the class and not one image.

*What holds that older path shut is a different gate.* Every version-1-only image read carries
`validateAndExtractEekPubAndId`: the version-1 request takes an endpoint encryption key and
validates its chain, and the version-2 request takes none at all — the difference [part 1
§2.1](1-protocol.md#21-three-version-axes) tabulates as "required" against "absent". The
alternative the protocol leaves open on that path is test mode, and [part 1
§5.6](1-protocol.md#56-test-mode) sets out the four independent mechanisms that make its output
worthless as evidence. Whether this vendor's validation is pinned to a fixed key was not determined
and is left as an open reading. The advice above therefore stands, on corrected grounds: not because
the route disappears under a downgrade, but because the route that survives reintroduces exactly the
dependency the version-2 route removes.

The second is a standing caution, and
[§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix) shows it is not
hypothetical. The verification routine and its mis-wiring entered the image in the same release, and
a later build on the same line can close the path without any other visible change; seven of the
lines screened have already done so. Nothing in the public record announces it, because as [part 5
§3.1](5-sources.md#31-the-signing-oracle-post) notes this defect carries no vulnerability
identifier, so there is no advisory to watch and no patch note to read. The screening is therefore
per build, not per model, and [§C.7](#c7-reproduction) is written so that it can be repeated against
any later one.

## C.5 The same reading across three vendors, and the fix

The [§C.4](#c4-the-verification-and-the-gap-arrived-together) result invites the wrong conclusion —
that the ordinary version-2 path is an Android 16 artifact. It is not. Fifty-eight images were
screened by the same method: thirty-eight across twenty-three Qualcomm firmware lines of the
handset's own vendor, sixteen across six lines of an unrelated one, and four across three lines of a
third, each reached through a different distribution format ([§C.7](#c7-reproduction)). Six classes
appear.

*First vendor,* two or three generations per line:

| Line | Platform | Android 15 | Android 16 |
|---|---|---|---|
| `malmo` | `SM6375` | *the gap* | *the gap* |
| `mona`, `monai` | `SM6475` | *the gap* | stubbed |
| `portov` | `SM7435` | *the gap* | stubbed |
| `paros` | `SM6475` | *version-1 only* | *the gap* |
| `cuscoi`, `cuscoi25` | `SM6450` | *version-1 only* | *the gap* |
| `eqe`, `tank` | `SM7550`, `SM7450` | *version-1 only* | *version-1 only* |
| `mumba`, `lamy`, `marvel` | `SM6435`, `SM6475`, `SM7635` | — | stubbed |

*Second vendor,* a different handset maker on the same chip vendor's platforms:

| Line | Android 15 | Android 16 | Android 17 |
|---|---|---|---|
| `zorn` | *no verification code at all* | *the gap* | — |
| `miro` | *no verification code at all* | stubbed | — |
| `annibale` | — | *the gap* | stubbed |
| `warsaw` | — | *the gap* | stubbed |
| `onyx`, `dada` | — | stubbed | — |
| `myron` | — | *reference Rust application* | *reference Rust application* |

*Third vendor,* a maker that publishes complete factory archives itself:

| Line | Android 15 | Android 16 |
|---|---|---|
| `FP6` | *the gap* | stubbed |
| `FP5`, `FP4` | *no request path at all* | — |

*The gap* is what [§C.3](#c3-result) reports. *Version-1 only* images carry no version-2 request
command, no fixed variants and no `parseMacTags`; what they do carry is the version-1 request path
with nothing in the trusted application that authenticates its input, which is the subject of
[§C.4](#c4-the-verification-and-the-gap-arrived-together). *No verification code at all* is the
sharpest state of all: those images implement the version-2 command and contain no tag-verification
routine anywhere — no `parseMacTags`, no `verifyPublicKeyMacTags`, no tag recomputation, and no
fixed variants to compare against — while carrying the other symbols of the request path, so this is
an absence in the image rather than a stripped symbol table. There the requirement of [part 1
§2.4](1-protocol.md#24-key-generation-and-the-authenticated-public-key) is not mis-wired but simply
unimplemented. *No request path at all* is the commonest state among the cheapest models of all
three makers: their application is a [Keymaster
4.x](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/keymaster/4.1/)
image, carrying scores of `KM_NEW_` commands and not one `KEYMINT_` command, with no
certificate-request command of either family, no COSE machinery and no derivation label. Seven of
the thirty-two lines are in it, and the reading below confirms one of them from the other side. *The
reference Rust application* is the sixth state and the one this screen nearly missed.

*The fix is the substantive finding of this screen, and it belongs to the chip vendor rather than to
either handset maker.* Where the defect has been addressed, the verification was *not* wired into
the ordinary path. The unverified commands were removed: their dispatch entries point at
two-instruction stubs — a move-immediate and a return, in some builds behind a branch-target landing
pad — answering `-100`, the
[KeyMint](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/ErrorCode.aidl)
code for an unimplemented operation, with only the fixed variants retaining an implementation. *Both
vendors ship byte-identical stub shapes*, which is what makes the attribution to the shared platform
source rather than to either integrator the natural reading, and it is the same inference the
derivation label supports in
[§C.6](#c6-platform-agreement-and-a-second-reading-of-the-derivation-label). The fix is trivially
detectable, needs no call-graph analysis, and is unambiguous: a command answering the unimplemented
code before touching its argument cannot be an oracle.

*A second and stronger fix appears on the newest lines read, and finding it cost this screen a
mistake.* Two lines, one of the first vendor and one of the second and on platforms two tiers apart,
answer neither description: their application is not the C one at all but the chip vendor's port of
[AOSP](https://android.googlesource.com/platform/system/keymint/)'s reference trusted application to
Rust, built around the reference `kmr-ta` and `kmr-common` crates — the image carries their source
paths, their error set (`InvalidMac`, `TestKeyInProductionRequest`, `ProductionKeyInTestRequest`,
`InvalidEek`) and their request entry points, inside the chip vendor's own object layer, and it is
six to twenty times the size of the C application. That implementation authenticates *every* public
key on *every* request path by construction: the version-2 entry decodes the
[COSE_Mac0](https://www.rfc-editor.org/rfc/rfc9052#section-6) structure, rejects a test-key marker
in a production request, recomputes the tag and compares it in constant time, returning the
invalid-tag error — and it does all of this before the request payload is assembled, for each key in
turn, with no branch around it. Replacing the application therefore closes the route more thoroughly
than stubbing a command does, and it closes the version-1 path of
[§C.4](#c4-the-verification-and-the-gap-arrived-together) at the same time.

*The mistake is worth recording in full, because it was the method's and not the image's.* On the
earlier pass this line was reported as *pre-version-2* — as carrying no version-2 command at all.
That verdict was an artefact: the analyser looks for the C application's `{command, flags, handler}`
dispatch table and for function names recovered from its logging convention, and the Rust
application has neither, so the table scan found nothing and the absence was read as a missing
command rather than as a missing *table*. The image in fact implements the version-2 request and
verifies it. A tool that recognises one implementation will describe a second one as a deficient
first one, and the only defence is to establish the family before running the analysis, which
[§C.2](#c2-method) now does and [§C.7](#c7-reproduction) now lists as its first step. Every
version-1-only and every stubbed verdict in the tables above was re-read under that test; those two
lines are the only images of the fifty-eight that change class. That the same replacement now
appears on two makers, as the stub already did, is the same argument for the same conclusion: this
is the chip vendor's change and not an integrator's.

*The third vendor's two older lines were confirmed from the normal world as well as from the
application,* which is the one place in this screen where the two sides could be compared. Its
`vendor` partition was extracted from the logical-partition image in the factory archive and read
directly: the [VINTF](https://source.android.com/docs/core/architecture/vintf) manifest declares no
`android.hardware.security` interface of any version — no
[KeyMint](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/)
and therefore no `IRemotelyProvisionedComponent` — only the HIDL Keymaster 4.1 service, and the
partition's own properties put its interface level four releases behind the system image it runs
under, which is the vendor-freeze arrangement the chip vendor supports. So the request path is
absent from the device and not merely from the application, the device provisions attestation keys
the older way, and the screen's reading of its trusted application was right without the partition
having been read. Two consequences for the method: a frozen vendor interface level is a cheap
predictor of this class, readable without carving anything; and on a device in it there is nothing
for the route of [part 2 §3](2-mechanisms.md#3-route-a-a-signing-oracle-on-qualcomm-keymint) to
address at all.

Its rollout is visible and ongoing. Three lines of the first vendor acquired it between their
Android 15 and Android 16 builds; the newest models of that vendor ship with it. On the second
vendor two lines carry the gap on Android 16 and the stub on Android 17, one of them the handset on
which the field record's route was publicly reported reproduced, so the published reproduction and
its closure are both visible in firmware; a third line of that vendor has gone further and replaced
the application. The third vendor's current line carries the gap on its Android 15 build and the
stub on its Android 16 build. The consequence inverts the usual instinct twice over: *a newer build
is now more likely to be fixed than an older one, and a newer model more likely still.*

*A reading corrected during this screen.* The first pass over the fixed images reported them as
unresolved, and the reachability step reported the stubbed command as not verifying — formally true
and substantively backwards, since a two-instruction stub reaches nothing. The check now tests for
the stub before it tests reachability, and the tabulated verdicts are the corrected ones. The lesson
generalises past this screen: a negative reachability result means nothing until the handler is
confirmed to be an implementation.

*One pair of lines sharpens that conclusion past the point the earlier text put it.* Two lines of
the first vendor carry the same model name in their archives' own build-information member, the same
platform and the same operating-system release, and they differ in class: one implements the
version-2 command and does not verify it, the other has no version-2 command at all. What separates
them is distribution — their channel lists do not intersect, one being that maker's European set and
the other its Americas set. So two units a buyer would both call by one name, bought in two regions,
are not the same device for this purpose. The decisive identifier is the model-number suffix, which
selects the firmware line, and through it the platform-source vintage the line was built from.

The conclusion is operational. *The screening key is the firmware line and the build — not the
operating-system release, not the model number, and not the vendor.* Two lines lack the version-2
command on the newest release they ship and seven more have no request path at all; thirteen have
had the command stubbed and two have had the whole application replaced; one carries the gap on two
consecutive releases. No version string in a settings menu answers the question, and
[§C.7](#c7-reproduction) is the only thing that does.

Two notes on the screen itself. Platform identification is cheap: the first vendor's archives carry
a modem firmware version that names the platform, and its bootloader container opens with an index
record that names the platform and the codename outright; the second vendor's update payloads either
contain a `keymaster` partition or do not, so devices on other trusted execution environments —
[MediaTek](https://corp.mediatek.com/product-security-bulletin) in every case met here — separate
out before any image is transferred. And each build exists per region and per carrier channel; the
images read are retail channels, and no two channels of one build were compared.

## C.6 Platform agreement, and a second reading of the derivation label

Four platform facts agree with [appendix A](A-record-signing-oracle.md) across the two
system-on-chip generations: the trusted application answers to the same application name and
carries the same loader metadata; its entry point is the same container-invoke symbol; the vendor
ramdisk declares both the [MINK](https://github.com/qualcomm/minkipc) invoke device and a
compatibility shim for the older trusted-application interface, which is the protocol stack [part 2
§3.3](2-mechanisms.md#33-the-command-channel-below-the-hal) describes; and the request-key
authentication key is derived from the system-on-chip secret, as the image's own derivation strings
state.

The derivation label is the substantive addition. [Part 2
§4.5](2-mechanisms.md#45-the-derivation-call-site-and-its-label) measured one label on this vendor's
platform and a different one on [Trustonic](https://www.trustonic.com/) Kinibi, and [part 2
§9.3](2-mechanisms.md#93-scope-of-the-label-measurement) cautions against assuming a label
transfers. This reading extends that caution's other half: *the same label appears on both Qualcomm
platforms*, two system-on-chip generations and two vendors apart, alongside a separate labelled seed
for the [Curve25519](https://www.rfc-editor.org/rfc/rfc7748) variant. The label travels with the
chip vendor's source, not with the handset maker — which is also why a defect found on one
Qualcomm device is worth screening for on an unrelated one.

*One reading cuts against the simple version of that claim, and sharpens it.* The line that ships
the reference Rust application ([§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix))
carries neither of this chip vendor's two labels. In their place it carries the reference
implementation's own label for the key that authenticates public keys, `Key to MAC public keys`,
together with DICE material and no marker of a software-only context. So the label identifies the
*implementation*, not the silicon: it travels with whichever source the application was built from.
That is the same conclusion as above in a stricter and more useful form, since it makes the label a
family test in its own right — and this is the third distinct label the report has now measured,
against the chip vendor's on the C application ([part 2
§3.2](2-mechanisms.md#32-derivation-and-storage-of-the-leaf-secret)) and
[Trustonic](https://www.trustonic.com/) Kinibi's on a third ([part 2
§4.5](2-mechanisms.md#45-the-derivation-call-site-and-its-label)). The caution of [part 2
§9.3](2-mechanisms.md#93-scope-of-the-label-measurement) is the right one, and it now has a reason
as well as a rule: a label is a property of a codebase, and one firmware line can change codebase
between two releases.

## C.7 Reproduction

No device and no credentials are required. The archive is public and the analysis is static.

```
# 0. decide the implementation family.  If the image carries the reference
#    crates' source paths or their request entry points, it is the Rust
#    application: it verifies by construction and steps 5 to 8 do not apply.
# 1. locate the build.  Vendor mirror, by device codename and release channel;
#    the archive member *.info.txt names the model and the Android version.
# 2. pull members over HTTP range requests rather than the whole flashfile:
#    read the zip central directory, then fetch bootloader.img (~28 MiB),
#    vendor_boot.img and boot.img.
# 3. carve the trusted application: scan bootloader.img for 0x100-byte record
#    headers -- name at the start, payload length as a 64-bit word at the end
#    of the header, payload padded up to the stride, zero blocks skipped as
#    padding; the record named keymaster.mbn is the KeyMint application.
# 4. confirm it is an ELF64 AArch64 object and take its executable segment.
# 5. recover the command table: scan for {u32 command, u32 flags, u64 handler}
#    records whose handler lies inside that segment.
# 6. symbolise: for every function, resolve address-page-plus-offset pairs into
#    the string pool; the name the function logs is its own.
# 7. build the direct-branch call graph and ask, per command, whether
#    parseMacTags or verifyPublicKeyMacTags is reachable from its handler.
# 8. assert the layout: every command number must resolve to a handler whose
#    symbol matches its name.  If it does not, the record stride is wrong.
```

The second vendor distributes no such container: its firmware arrives as an [A/B update
payload](https://source.android.com/docs/core/ota/ab) inside a multi-gigabyte archive. That is
equally seekable. The archive stores `payload.bin` uncompressed, so its header and protocol-buffer
manifest can be read with a few range requests, the manifest names every partition with the file
offsets of its install operations, and the `keymaster` partition is a few hundred kilobytes with a
single operation — about half a megabyte transferred from an archive of nine gigabytes. A device
whose payload carries no such partition is on another trusted execution environment and needs no
further reading. From there, steps 3 to 8 are unchanged.

The third vendor needs no container parsing and no payload parsing: it publishes the factory archive
with every image in it as a separate member, so step 2 fetches the application directly and step 3
does not arise. Its `vendor` partition costs more and was read once
([§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix)). The archive holds one
[dynamic-partition image](https://source.android.com/docs/core/ota/dynamic_partitions), itself
wrapped in the [Android
sparse
format](https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsparse/sparse_format.h);
its [metadata](https://source.android.com/docs/core/ota/dynamic_partitions/implement) at a fixed
offset gives each partition's extents in 512-byte sectors, so the compressed member can be decoded
as it streams and only the wanted byte ranges written out, stopping at the last one needed.
Partition names there carry the slot suffix, so the name asked for is `vendor_a`.

Steps 5 to 8 are about 120 lines of Python over the carved image and need no disassembler. The
scripts used here are session scratch rather than part of [the toolkit](tools/README.md), which
deliberately requires neither network nor device.

Two further readings came free from the same members and are recorded for completeness. The
application bootloader is a [LZMA](https://www.7-zip.org/sdk.html)-compressed UEFI payload inside
`abl.elf`; decompressed, it carries the vendor's complete official unlock flow — the unlock-data
query, the ability query, the portal URL and the developer-options precondition — unlike the handset
of [appendix A](A-record-signing-oracle.md), where the unlock verb is disabled outright and only a
signed-token path remains. And the kernel is a
[generic-kernel-image](https://source.android.com/docs/core/architecture/kernel/generic-kernel-image)
build of the 6.6 line.

## C.8 What this does not establish

*Nothing here was executed.* No command was sent to a trusted application, no certificate-signing
request was produced, and the provisioning backend was not contacted. The measurement is of a
binary's call structure, not of a device's behaviour; the step from "the verification is not called"
to "a software-held public key is certified" is exactly the step [appendix
A](A-record-signing-oracle.md) reports and this appendix does not re-run.

*The normal-world side is unread on the device examined in detail.* The vendor convenience library
that [part 2 §3.3](2-mechanisms.md#33-the-command-channel-below-the-hal) names as one of the two
artifacts gating the channel sits in the vendor partition, which was not retrieved for this handset;
only the kernel-side invoke device and the compatibility shim were confirmed. Its absence would not
close the channel — the HAL's own path remains — but it would raise the work. One vendor partition
was read in this screen, on a different maker's device and for a different question
([§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix)); it is the only normal-world reading
here, and it says nothing about this handset.

*Backend acceptance is unknown.* Whether this model's device identity is registered with the
provisioning backend, and whether a request bearing it would be signed, cannot be read from
firmware at all.

*One channel of one region was read per generation, with one exception.* Two channels of a single
build of one line — a carrier image and the general retail image of the same release — were carved
and compared, and their trusted applications are byte-identical, so for that build the channel does
not select the application. One pair is not a general result, and it says nothing across *regions*,
where [§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix) finds two lines of one model
name in different classes. The unlock path's *eligibility* remains a per-unit property that firmware
cannot answer at all.

## C.9 Refutation conditions

A call to `parseMacTags` reachable from the ordinary version-2 handler in any build of this line
refutes the result for that build. An on-device invocation of `0x3122` over a normal-world public
key that returns a rejection refutes the operative claim regardless of the call graph, and would
indicate either a check this method cannot see or a gate above the trusted application. A command
table whose records do not satisfy the symbol-agreement assertion of step 8 refutes the layout and
with it the command-to-handler mapping of [§C.3](#c3-result).

Three conditions bear on the readings added in this revision. A tag-verification routine, or a tag
*producer*, found anywhere in an Android 14 or Android 15 image of the detailed line refutes
[§C.4](#c4-the-verification-and-the-gap-arrived-together)'s claim that neither side of the mechanism
is present there; the claim is a claim of absence and a single symbol settles it. An
endpoint-encryption-key validation that accepts a self-made chain in production mode would remove
the gate that section relies on and make the version-1 path the easier of the two, inverting its
conclusion. And a `vendor` partition of either of the third vendor's two older lines that does
declare a provisioning interface would refute the agreement claimed in
[§C.5](#c5-the-same-reading-across-three-vendors-and-the-fix) between the two sides of that device,
and would mean the trusted application is not the whole story there.
