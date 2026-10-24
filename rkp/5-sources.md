# 5. Sources and their limits

Index: [the index](README.md). Companion parts: [part 1](1-protocol.md), [part 2](2-mechanisms.md),
[part 3](3-detection.md), [part 4](4-measurements.md).

## Abstract

The report rests on four kinds of record, which do not carry equal weight. *Normative sources*,
meaning [AOSP](https://source.android.com/) code and Google's own documentation, are read directly
and settle every question of what the protocol requires. *Two public field records* and *one
engineering corpus* supply the acquisition mechanisms, three of the four routes deriving from a
single author's effort whose own front matter declines to assert that every historical command was
re-executed by a human. *Two independent normal-world implementations* of the provisioning client
serve as protocol references, because code that must interoperate encodes the wire rules more
reliably than prose about them. And *two leaked keybox samples* are the primary artifacts, whose
origin is established here to the byte: both are reproduced exactly by one named open-source keybox
writer, distinguished from its sibling implementation by a single indentation constant, which
establishes that their private keys were generated in normal-world software and never existed inside
a [trusted execution
environment](https://globalplatform.org/technical-committees/trusted-execution-environment-tee-committee/).
The appraisal concludes that the mechanism class of [part 2
§8](2-mechanisms.md#8-common-structure-of-the-four-routes) is well evidenced while the individual
constants are single-sourced; [§3.5](#35-the-common-limit) states what would break that
single-sourcing, and [§4](#4-material-that-could-not-be-read) lists what could not be read at all.

---

## 1. Conventions

### 1.1 Attribution

A reader who needs to know whether a claim is safe to act on needs three things this part supplies:
where the claim came from, what kind of source that is — a signed certificate, a vendor binary, a
forum post, a code comment — and what single observation would overturn it.

Two conventions govern attribution. A claim does not gain strength by being repeated: a value
measured once remains a measurement of that instance and does not become a general fact by being
cited elsewhere, and a claim resting on a record whose execution was not re-run remains so
attributed however many parts repeat it. Where this report states something more strongly than its
source did, the strengthening is argued at the point of use or it does not occur.

The underlying records use labels this report does not adopt. The earlier dossiers maintained their
own ledgers of established claims, including claims established as an absence, and dispositions of
unsupported, withdrawn, argued against, not reconstructed and unmeasured. Where this report carries
such a claim it restates the status in prose rather than importing the label. A claim previously
marked as established-as-an-absence becomes, here, a claim reported as an absence: nobody published
the thing, which is a statement about the published corpus rather than about reality.

### 1.2 Checks against primary sources

The following checks were performed beyond reading each record, and each is the reason a claim
elsewhere is stated as it is.

*Five AOSP sources were re-read directly* rather than through the summaries that cited them,
producing four exact confirmations and two substantive contributions. Both contributions are in
[part 1](1-protocol.md): the layer-identifier derivation masks the high bit of its first output
byte, an operation the prior record's formula omitted and whose omission breaks chain linkage while
presenting as a signature fault ([part 1 §4.3](1-protocol.md#43-layer-keys-and-identifiers)); and
the recommendation to report a null endpoint curve requires a test-suite qualification it previously
lacked ([part 1 §2.3](1-protocol.md#23-hardware-information)).

*The two independent implementations were read and cross-checked*: the wire format of one field
route against the Rust client's encoder, the derivation label against that client's default, the
verifier's pinned protocol constants against AOSP's grammar, and the absence of a
provisioning-status gate and of [X.509](https://www.rfc-editor.org/rfc/rfc5280) signature
verification in that client. These are reported in [part 2 §3.5](2-mechanisms.md#35-request-format),
[part 2 §4.5](2-mechanisms.md#45-the-derivation-call-site-and-its-label), [part 3
§1.3](3-detection.md#13-relations-for-a-minted-certificate-chain) and [part 3
§1.4](3-detection.md#14-gates-the-chain-does-not-supply).

*The engineering corpus's artifact layer was read directly* rather than through its narrative:
container metadata, patch-script constants, recorded digests, and the acceptance records. That is
what separates claims read from an artifact from claims only narrated, throughout [part 2
§4](2-mechanisms.md#4-route-b-plaintext-observation-in-a-kinibi-trustlet) to [part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret).

*This project's own source was checked* where a part makes a claim about it: the keybox parser's
constraints, the inspector's object-identifier coverage, and the revocation matcher's serial
handling. One documentation error was found and corrected in the project's own README, which stated
that a keybox must contain both an RSA and an
[EC](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) key, where
[`rust/teesim-km/src/attest.rs`](../rust/teesim-km/src/attest.rs) requires at least one, which is
what allows a provisioning-shaped keybox to load.

*The arithmetic of every cross-part claim was recomputed*, which is why the ratio statements of
[part 4 §3.3](4-measurements.md#33-issuance-counts) are given as measured multiples.

### 1.3 Archival state

The primary sources below are cited by address, with digests or commit identifiers where they exist.
Three categories are mirrored in this repository and the rest are not. The two field records are set
down in [appendix A](A-record-signing-oracle.md) and [appendix B](B-record-three-devices.md),
because forum threads can be edited, deleted or placed behind a login. The two keybox samples are
not carried, because they contain live private keys that [part 1
§1.3](1-protocol.md#13-scope-and-conventions) excludes. The engineering corpus and the firmware
dumps are not carried either, because this repository holds analysis rather than an archive.

That remains a weakness in the evidence base. A repository can be force-pushed or taken down and a
firmware dump site can lapse. Where that occurs, the record of what a source said survives only in
these parts. Two mitigations are in place. Every claim traceable to such a source is quoted or
restated in enough detail to be checkable against a copy obtained elsewhere, which is why the
lengths, digests, labels, command words and field values appear in [part 4](4-measurements.md) and
[part 2](2-mechanisms.md). And every record is pinned where pinning is possible: commit identifiers
for the two implementations, digests for every binary in [part 4
§1.2](4-measurements.md#12-artifacts), and [Wayback Machine](https://web.archive.org/) snapshots for
the revocation list in [part 4 §4.2](4-measurements.md#42-revocation-list-snapshots).

Drift was already observed during this work, which is why the point is not hypothetical. The
upstream Python minting tool removed its hardware-key-derivation path and added a
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) curve option
after the measurement that described it; one measured firmware generation has no public dump at all,
so the newest available stock dump predates the build the leaked sample names by roughly seven
months; and the public vendor tree receives whole-tree re-imports that make diff status unreadable
and force comparison by blob identifier ([part 4
§6.6](4-measurements.md#66-the-application-container)).

---

## 2. The sources

### 2.1 Normative sources

[AOSP](https://cs.android.com/android/platform/superproject/main) and
[source.android.com](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning),
read directly, are dispositive for every question of what the protocol requires. The full list of
paths is [part 1 §9](1-protocol.md#9-references); the standing caution is that AOSP is a moving
target and that every version-dependent claim carries the re-verification requirement of [part 1
§8.1](1-protocol.md#81-version-dependent-claims), against [Code
Search](https://cs.android.com/android/platform/superproject/main) or
[Gitiles](https://android.googlesource.com/) raw output rather than the GitHub mirror.

The one place AOSP is not dispositive is the provisioning-information extension. Google publishes
[two labels of that
map](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension)
and states explicitly that it is unversioned and may gain fields. Two of the four labels observed in
the field are therefore undocumented, and nothing normative constrains them ([part 4
§3.2](4-measurements.md#32-label-dictionary)).

### 2.2 Primary research records

*The signing-oracle post*, [kanxue thread 293244](https://bbs.kanxue.com/thread-293244.htm),
recorded in [appendix A](A-record-signing-oracle.md). A public technical post, single author, on a
Qualcomm handset. It names the missing check by symbol and gives the command number, the wire format
and the failed alternatives. Its execution was not re-run here, and it is unusually well supported
for a single-source record because its wire format is independently confirmed
([§3.1](#31-the-signing-oracle-post)).

*The three-device retrospective*, [kanxue thread 293246](https://bbs.kanxue.com/thread-293246.htm),
recorded in [appendix B](B-record-three-devices.md). A public retrospective covering three
extraction routes, matching the engineering corpus chapter for chapter. It declares itself not a
reproducible tutorial and states that the public version omits private keys, real seeds, device
identifiers, patch bytes and flashable commands. Its value is the causal corrections and the pitfall
catalogue, which is why it is the most-cited record in [part 2
§10](2-mechanisms.md#10-limits-of-the-evidence).

*The engineering corpus*,
[`gungnir-sanye/tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction),
read at commit `87f07b3`. Per-device tutorials, practice logs, patch scripts, patched binaries,
container-decryption metadata and acceptance reports. Artifacts read directly from it are reported
as such; anything only narrated is attributed to the narrative.

*An independent implementation used as a protocol reference*,
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), read at commit `85807c0`. A
normal-world Rust implementation of the provisioning client, the request builder, a verifier, and
the Qualcomm device path, read and cross-checked locally. It matters more than its size suggests:
its validator encodes the wire rules, so a claim about the protocol can be checked against code that
has to interoperate rather than against prose that does not.

*The minting tool*, [`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw). A Python
implementation of the same pipeline, cited throughout for protocol behaviour because its source is
legible. Note the drift of [§1.3](#13-archival-state): the revision that carried the hardware-key
path no longer exists upstream.

### 2.3 Background records

Each supports a bounded claim and none carries a route.

[TÄMU](https://arxiv.org/abs/2601.20507), with [tooling](https://github.com/HexHive/taemu), for its
reported vulnerability table and its public platform support; the basis of [part 4
§6.4](4-measurements.md#64-published-application-vulnerabilities). Its results carry no
vulnerability identifiers, so patch status cannot be checked against any bulletin.

[FIASCO](https://nebelwelt.net/blog/2025/1227-fiasco.html), with
[slides](https://hexhive.epfl.ch/publications/files/25CCC-presentation.pdf) and
[tooling](https://github.com/HexHive/beanpod_fiasco), for the escalation it published on a sibling
handset, and relevant chiefly as a negative: its 65 slides contain no occurrence of *attestation*,
*keymaster*, *keymint*, *RKP*,
*[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/)*, *CDI*, *UDS* or
*[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox)*, which is
what makes the route of [part 2 §5.1](2-mechanisms.md#51-environment) independent of it.

[Quarkslab on bypassing Android hardware
attestation](https://blog.quarkslab.com/bypassing-android-hardware-attestation.html), with a
[demonstration](https://github.com/quarkslab/android-hardware-attestation-demo), for the two-handset
relay architecture that [part 2 §3](2-mechanisms.md#3-route-a-a-signing-oracle-on-qualcomm-keymint)
collapses onto one device.

[`Colorful-glassblock/duchamp-root`](https://github.com/Colorful-glassblock/duchamp-root), for its
documentation read rather than run; the basis of [part 4
§6.5](4-measurements.md#65-normal-world-root), corroborated from an unrelated direction by the
[registry record](https://cveawg.mitre.org/api/cve/CVE-2026-43499) for
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), which describes an upstream Linux
defect rather than a vendor one.

[`mt6897-devs/vendor_xiaomi_duchamp`](https://github.com/mt6897-devs/vendor_xiaomi_duchamp) and
[`dumps.tadiphone.dev`](https://dumps.tadiphone.dev/dumps/redmi/duchamp), the two independent
provenance chains whose agreement establishes correspondence between tree and firmware by hash in
[part 4 §6.1](4-measurements.md#61-handset-and-environment-census).

[`android.googleapis.com/attestation/status`](https://android.googleapis.com/attestation/status) and
[`key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl), live endpoints measured on
dated fetches, with historical snapshots through the Wayback Machine.

[MediaTek product security bulletins](https://corp.mediatek.com/product-security-bulletin), for
advisory text, and the basis of a claim deliberately not advanced ([part 2
§9.1](2-mechanisms.md#91-the-candidate-field)): an advisory in the right stage with the right
primitive class is not evidence about DICE material.

Downstream consumers of leaked keyboxes — a widely distributed integrity module shipping a directory
of them, several keybox managers, and an alternative
[KeyMint](https://source.android.com/docs/security/features/keystore) implementation that rejects
EC-only provisioned keyboxes — are relevant only as ecosystem context, and the last of them as a
datapoint that the provisioned shape is recognised in the wild.

---

## 3. Appraisal

### 3.1 The signing-oracle post

*Its wire format is confirmed by unrelated code.* The post derives request and response framing from
entry-point disassembly; the Rust implementation encodes the same command word, the same two
[CBOR](https://www.rfc-editor.org/rfc/rfc8949) labels, and the same single-entry response map.
Neither source cites the other, and that is the strongest single corroboration anywhere in this
report ([part 2 §3.5](2-mechanisms.md#35-request-format)).

*It records its failures.* The post is largely an account of what did not work: the whole
download-mode surface, a nonce-reuse probe that found the implementation conformant, and a command
that proved not to be the authentication oracle it was hoped to be. A record that publishes its
negative results is easier to weigh than one that publishes only its successes.

*It names the defect precisely enough to be refuted.* A claim that one specific function is
referenced only from two specific commands is checkable by anyone holding the same image, which is
why [part 4 §8](4-measurements.md#8-refutation-conditions) can state the refutation condition in one
line.

What it lacks is independent execution. Whether the described invocation yields a Google-signed
chain in practice rests on the post's own report of a repeated success.

### 3.2 The three-device retrospective

Its value is not the routes but the methodology: the five states resembling success, the three-layer
acceptance structure, the negative control, the parsing discipline, the two-keys-must-differ
correction, and above all the causal correction of [part 2
§6.6](2-mechanisms.md#66-a-causal-correction), where the research corrects its own earlier
attribution by decomposing a multi-variable change. Those transfer to any platform and would survive
every route narrative being wrong.

Its weakness is that it is one author's effort reporting three of this report's four routes, and its
own front matter states that the material was organised with the assistance of a language model and
that not every historical command has been re-executed by a human. Read against that, two readings
are available and this report takes the conservative one: the mechanism class is well evidenced
while the individual constants are single-sourced.

### 3.3 The engineering corpus

The corpus is where claims read from an artifact and claims merely narrated diverge within one
source.

*Settled by reading an artifact:* container metadata, with its own self-consistency checks on the
unwrapping key's parameters; recorded digests for every stock and patched binary; the patch scripts'
constants, including a derivation call site's own captured arguments; the acceptance records, with
public-key correspondence and chain verification results; and the device gates that every builder
enforces before running.

*Only narrated:* that the routes were executed as recorded, that the patches were sufficient and
minimal, and that any given capture reproduced the same round's identity. The artifacts are
consistent with the narrative throughout, which is weaker than confirming it.

One structural observation is evidence of care rather than of result: the corpus publishes a seed's
digest fingerprint and never the seed. A record that withholds the one element that would make it a
key-distribution vector, while publishing enough to be checked, behaves as the scope rule of [part 1
§1.3](1-protocol.md#13-scope-and-conventions) describes.

### 3.4 Two independent implementations

Both normal-world implementations construct an entire
[COSE_Encrypt](https://www.rfc-editor.org/rfc/rfc9052#section-5) structure that the protocol version
they target does not have ([part 2
§7.3](2-mechanisms.md#73-components-the-procedure-does-not-need)). Read alone, either looks like
evidence that the code was never exercised. Read together, it is a shared inheritance from the older
protocol version, and the inference drawn from it was withdrawn.

That is why the implementations serve as references at all. Where a specification is ambiguous — map
ordering, which fields are mandatory in practice, what a validator actually rejects — code that must
interoperate resolves the ambiguity, and two independent codebases agreeing resolve it reliably. The
two places this proved decisive are the derivation label of [part 2
§4.5](2-mechanisms.md#45-the-derivation-call-site-and-its-label) and the wire format of [part 2
§3.5](2-mechanisms.md#35-request-format).

It cuts the other way too, as [part 3 §1.4](3-detection.md#14-gates-the-chain-does-not-supply)
records: both implementations are missing gates the protocol needs, having no provisioning-status
check and linking chains by name rather than by signature. A reference implementation establishes
what the wire looks like, not what a careful verifier should do.

### 3.5 The common limit

Three of four routes from one corpus is the structural weakness of the whole evidence base, and it
is not remediable by reading more of the same corpus. What would break it, in approximate order of
cost:

An *independent disassembly* of the same Qualcomm image showing the same cross-references for the
authentication-tag parser. A *single invocation* on any production handset of that platform of the
command reported to return a hardware-derived value with no provisioning gate, which would either
confirm a second defect or refute it outright. An *independent stock-handset reading* of the
issuance count, which [part 4 §5.2](4-measurements.md#52-on-device-measurements) shows to cost one
command and to settle the baseline on which the detection argument of [part 3
§4.2](3-detection.md#42-the-provisioning-information-extension) rests. A *re-run from the stock
inputs* through any builder's digest gates. And, for the one claim that is both weight-bearing and
weakly supported, a *factory-reset experiment* on any Android handset ([part 4
§5.4](4-measurements.md#54-experiments-that-would-settle-a-claim)).

What is not on that list is re-executing a route end to end. No conclusion in this report requires
it, because every conclusion that matters defensively is either a protocol fact, a measurement on an
artifact ([§3.3](#33-the-engineering-corpus)), or the structure of [part 2
§8](2-mechanisms.md#8-common-structure-of-the-four-routes), which is strengthened rather than
weakened by the routes being on four different platforms.

---

## 4. Material that could not be read

*An English-language forum thread* on [boot-ROM](https://en.wikipedia.org/wiki/Boot_ROM)-level
techniques for the chipset in question returns HTTP 403 to automated fetch. It is known only from
search snippets and could not be confirmed; no claim in this report rests on it.

*A conference slide deck's spoken content.* A quotation to the effect that one vendor environment is
being phased out in favour of another is second-hand and marked as such where it appears.

*No public firmware dump exists for the current generation of the measured handset.* This is the
sample edge of the never-rebuilt finding of [part 4
§6.6](4-measurements.md#66-the-application-container), and the one gap that cannot be closed by
effort, only by someone publishing a dump.

*The 17 vulnerabilities reported by the emulation paper carry no identifiers*, so their patch status
cannot be checked against any bulletin. The paper states that they were responsibly disclosed, and
nothing further is knowable from the public record.

*The forum pages hide more than they show, and the limits are mechanical.* Only the opening post of
each thread appears in the static HTML; replies load over JavaScript and were never captured. In the
retrospective, the author's own repository link is wrapped in the forum's encrypted-text markup and
is unreadable without a logged-in session. A plain HTML-to-text conversion yields nothing on these
pages, because the post body sits in a container requiring a document-model parse, and each page
embeds the author's source once and the rendered text again, so a naive extraction produces every
paragraph twice. Re-fetching requires a browser user agent and a Chinese language header, or the
server returns a stub. These are the reasons the records in [appendix A](A-record-signing-oracle.md)
and [appendix B](B-record-three-devices.md) were prepared by hand rather than by a converter, and
the reason a future reader should expect to repeat that work.

*An earlier internal dossier is not carried forward as a file.* The general account of
attestation-key compromise from which this report grew — the custody classes now in [part 2
§2.1](2-mechanisms.md#21-custody-classes), the control-plane measurements now in [part 3
§2](3-detection.md#2-the-control-plane), the coverage matrix now in [part 3
§9](3-detection.md#9-coverage-of-mechanisms-by-control) — is not part of this report and is not
mirrored. Its substance was extracted rather than referenced, and the one assessment it carried that
these routes overturn is restated in [part 2
§9.4](2-mechanisms.md#94-revision-of-an-inherited-assessment). Claims traceable to it carry the
status they had there, and its live fetches are dated only as single fetches, since the values have
certainly moved since.

*Authorship of the signing-oracle post relative to the retrospective* could not be determined from
the archived pages. Section [part 2 §1.2](2-mechanisms.md#12-the-evidence-base) states the
consequence: treating it as independent is generous in one direction and risky in the other, and the
risk is disclosed rather than resolved.

---

## 5. Provenance of the keybox samples

The samples are the report's primary artifacts and the only place where origin could be established
to the byte. This section is what licenses [part 4
§2](4-measurements.md#2-two-leaked-provisioned-keyboxes) to treat them as a known quantity.

### 5.1 Identity

Sample A is 5,993 bytes with [SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
`4c1fd429…5b26c3`; sample B is 5,690 bytes with SHA-256 `f87306c3…925aa5`. Each is a keybox file
holding one EC key and no RSA key, with a four-certificate chain, and each file's private key
matches its leaf. Their original filenames differ from the names used here, which is noted so that a
reader holding a copy under another name can match by digest. The private scalars are not
reproduced, although a cited source published them in full; the digests suffice for correlation work
and the scalars do not.

### 5.2 Byte-exact attribution

Both files are reproduced byte-exactly — 89 of 89 lines and 5,993 of 5,993 bytes for sample A, 86 of
86 lines and 5,690 of 5,690 bytes for sample B — by a keybox writer whose indentation constants are
four spaces for the count and keybox elements, eight for the key element, twelve for the private-key
and chain elements, sixteen for the certificate-count and certificate elements, sixteen for the
private-key [PEM](https://www.rfc-editor.org/rfc/rfc7468) body, and twenty for the certificate
bodies.

Those last two constants are emitted natively by
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), in its keybox writer at the
revision measured, since reorganised, where the two indentation calls pass literal 16-space and
20-space prefixes, with every element string character-identical to the artifacts line for line.

[`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw), the Python sibling, emits twelve
and sixteen for those two constants and matches only 21 of 89 lines. Adding four spaces to its
indenter yields sixteen and twenty and reproduces both files exactly. The two tools therefore differ
by precisely that one constant, and the Rust project's own module metadata lists the Python tool's
author as a co-author, so the relationship is a fork rather than a coincidence.

The native, unmodified emitter of these bytes is the Rust tool. The Python one is the legible
reference implementation of the same pipeline, which is why it is cited for protocol behaviour
throughout [part 2 §7](2-mechanisms.md#7-off-device-certificate-minting).

Four consequences follow, each measured rather than inferred.

*The device-identifier attribute is packaging metadata.* It is the manufacturer string, a hyphen,
and six random bytes, produced by the writer's own formatting call. It is not a hardware address and
carries no device identity; the manufacturer comes from the operator's configuration file.

*One EC key and no RSA key is the writer's fixed shape*, rather than a fact about provisioning,
although it is also what a genuine provisioned keybox looks like, which is why the shape works as a
class signal ([part 3 §5.1](3-detection.md#51-fields-a-keybox-holder-authors)).

*A single-keybox file is the writer's shape.* Factory-keybox leaks are bulk files; these are
singletons.

*The private keys were generated in normal-world software and never existed inside a trusted
execution environment.* Nothing was unsealed, decrypted or lifted from a key blob. No attestation
private key was extracted from any secure world to produce these artifacts: they were minted against
Google's unauthenticated production endpoint by ordinary software ([part 2
§7](2-mechanisms.md#7-off-device-certificate-minting)).

An independent confirmation that does not rely on the byte match: the producing tool's default
device information omits the verified-boot metadata digest, which the grammar makes mandatory and
which a genuine KeyMint application cannot omit, so sample B's request was demonstrably not produced
by one ([part 4 §3.4](4-measurements.md#34-corrections-to-earlier-readings)).

### 5.3 Claims not established

*That the seed behind them came from the handset named in sample A's extension.* The fingerprint in
label 5.4 is operator-authored configuration sent unsigned to the endpoint-key endpoint. It shows
only that a real, certified build string was entered and that the backend resolved it and marked it
approved. It is not cryptographically bound to the seed's device, and sample B names no device at
all. A seed from any registered device, paired with a typed fingerprint, would produce a
byte-identical artifact. The conjecture is not advanced, and [part 2
§10.3](2-mechanisms.md#103-conjectures-not-advanced) records the two signed fields that argue
against a specific candidate origin.

*That the two samples are one identity.* Unsupported. The device-identifier attribute is random and
the leaf common name equals the certificate's own serial; neither file carries a device identifier.

*Which curve the donor identity registers.* Section [part 4
§6.3](4-measurements.md#63-storage-of-the-dice-secret) leans toward P-256 from named routines in a
stripped binary, and the Python tool built [Ed25519](https://www.rfc-editor.org/rfc/rfc8032) chains
until it gained a P-256 option. Unmeasured.

*Whether the shared intermediates establish anything.* They do not: the backend hands the same
shared portion to every requester in an epoch ([part 4
§2.2](4-measurements.md#22-shared-chain-positions)), so agreement between two samples on positions 2
through 4 is not evidence of common origin. The byte-exact reproduction of
[§5.2](#52-byte-exact-attribution) establishes a common producer rather than a common device.

### 5.4 Corrections of record

Six corrections, each recorded rather than silently applied. The first four are stated in detail in
[part 4 §3.4](4-measurements.md#34-corrections-to-earlier-readings): the inverted direction of
resolution for label 5.2, the device-identifier attribute as packaging metadata, the distinction
between anonymous and bound keyboxes as a property of the operator's configuration, and the
withdrawal of the pool-cap reading of the issuance count. Two further corrections concern provenance
and belong here.

*The donor handset's environment was misidentified in an earlier dossier.* It was recorded as one
vendor's environment and is in fact another's, on a
[Zircon](https://fuchsia.dev/fuchsia-src/concepts/kernel)
[microkernel](https://en.wikipedia.org/wiki/Microkernel), which retired a standing assumption that a
published escalation chain applied to it ([part 4
§6.2](4-measurements.md#62-identification-of-the-secure-operating-system)). The correction is not
cosmetic: it removes an entire vulnerability inventory from the analysis.

*One indicator of tool non-exercise is withdrawn.* Finding an unused encryption structure was listed
among the signs that the Python tool had never been run. Both implementations construct it, because
the targeted protocol version does not have the field ([part 2
§7.3](2-mechanisms.md#73-components-the-procedure-does-not-need)). The other indicators in that
adjudication — a hardcoded empty certification map, the repository hygiene, an unanswered issue —
are unaffected.

A seventh correction concerns a citation rather than a claim, and the error class is instructive:
one refuted scheme rested on a reading of AOSP
[Trusty](https://source.android.com/docs/security/features/trusty) in which a hardware-key
derivation routine produces the device certificate chain. It does not: it derives the authentication
key, under its own explicit label, while the certificate chain and device key come from a separate
service. A scheme resting on a misread function name is refuted by reading the function.

### 5.5 Scope

Every source cited in this report states a research, competition or defensive scope and withholds
private keys, real seeds, device identifiers and flashable commands. This report holds the same
line, and in one case holds it where a source did not: the samples' private scalars were published
by a cited record and are not reproduced here, because they add nothing analytically while being the
one element that would make this a key-distribution vector. The same reasoning applies to the
container-unwrapping private factors of [part 2 §5.2](2-mechanisms.md#52-the-application-container),
where the finding is that an unwrapping key sits in a loader at a recorded offset.

One request was declined in the course of this work, and the declination is recorded: selecting a
handset to purchase for the purpose of extracting a live provisioning identity. A seed is a
permanent capability to mint Google-signed attestations belonging to a real registered device, its
downstream use is forging [hardware
attestation](https://source.android.com/docs/security/features/keystore/attestation) to banking,
payment and identity applications, and at the time no acquisition route had been published, so the
request was target selection for novel offensive work. Everything adjacent remained in scope and is
what this report contains: analysis, measurement, acceptance relations, the discriminating
experiments of [part 4 §5.4](4-measurements.md#54-experiments-that-would-settle-a-claim), and the
detection signals of [part 3 §7](3-detection.md#7-statistical-and-behavioural-signals).

---

## 6. Additional locators

Section [part 1 §9](1-protocol.md#9-references) carries every normative and academic address this
report uses. The remainder, listed once:

The leaf revocation endpoint and the provisioning hierarchy's revocation list —
[`attestation/status`](https://android.googleapis.com/attestation/status),
[`key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl) — with historical snapshots
of the former through the Wayback Machine, whose addresses are in [part 4
§4.2](4-measurements.md#42-revocation-list-snapshots).

Device and firmware provenance: vendor blobs at
[`mt6897-devs/vendor_xiaomi_duchamp`](https://github.com/mt6897-devs/vendor_xiaomi_duchamp), the
device tree at
[`mt6897-devs/device_xiaomi_duchamp`](https://github.com/mt6897-devs/device_xiaomi_duchamp), kernel
sources at
[`MiCode/Xiaomi_Kernel_OpenSource`](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/tree/bsp-duchamp-u-oss),
stock dumps at [`dumps.tadiphone.dev`](https://dumps.tadiphone.dev/dumps/redmi/duchamp), a firmware
tracker at [`mirom.ezbox.idv.tw`](https://mirom.ezbox.idv.tw/en/phone/duchamp/), and handset
specifications from [GSMArena](https://www.gsmarena.com/redmi_k70e-12716.php).

Advisories and vulnerability records: [MediaTek product security
bulletins](https://corp.mediatek.com/product-security-bulletin), the [CVE
Program](https://www.cve.org/), and the [registry
interface](https://cveawg.mitre.org/api/cve/CVE-2026-43499) for records whose assigner text is worth
reading verbatim.

The system-call reference used in [part 4
§6.2](4-measurements.md#62-identification-of-the-secure-operating-system):
[fuchsia.dev](https://fuchsia.dev/reference/syscalls).

Field records, corpora and implementations: all five in the final section of [part 1
§9](1-protocol.md#9-references), with commit identifiers in [§2.2](#22-primary-research-records)
above.
