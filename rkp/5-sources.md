# 5 · Evidence base — provenance, appraisal, and the limits of each record

*Where each claim in this series comes from, how much weight the underlying record can carry, and
what would break it. [`1-protocol.md`](1-protocol.md) specifies the protocol, §1.4 of it defines the
grades used throughout and §1.5 the scope rule; [`2-mechanisms.md`](2-mechanisms.md) reconstructs the
field routes; [`4-measurements.md`](4-measurements.md) reports the numbers. Read this part before
quoting any of it.*

## Abstract

The series rests on four kinds of record and they do not carry equal weight. *Normative sources* —
[AOSP](https://source.android.com/) code and Google's own documentation — are read directly and
settle every question of what the protocol requires. *Two public field reports* and *one engineering
corpus* supply the acquisition mechanisms, and three of the four routes come from a single author's
effort whose own front matter declines to assert that every historical command was re-executed by a
human. *Two independent normal-world implementations* of the RKP client are used as protocol oracles,
because code that must interoperate encodes the wire rules more reliably than prose about them. And
*two leaked keybox samples* are the primary artifacts, whose origin is established here to the byte:
both are reproduced exactly by one named open-source keybox writer, distinguished from its sibling
implementation by a single indentation constant, which proves their private keys were generated in
normal-world software and never existed inside a [trusted execution
environment](https://globalplatform.org/technical-committees/trusted-execution-environment-tee-committee/).
The appraisal concludes that the mechanism class of [`2-mechanisms.md`](2-mechanisms.md) §8 is
established with high confidence while the individual numbers are single-sourced; §3.5 states what
would break that single-sourcing, and §4 lists what could not be read at all.

---

## 1. Purpose and method

### 1.1 Purpose

A reader who wants to know whether a claim is safe to act on needs three things this part supplies:
where the claim came from, what that source is — a signed certificate, a vendor binary, a forum post,
a code comment — and what single observation would overturn it.

The grades are defined once, in [`1-protocol.md`](1-protocol.md) §1.4. Two rules about their use
belong here.

*No grade is promoted when a claim moves between documents.* A value measured once stays *[MEASURED]*
for that measurement and does not become a general fact by being cited. A route narrative stays
*[REPORTED]* however many documents repeat it. Where this series states something more strongly than
a source did, the upgrade is argued at the point of use or it does not happen.

*Several labels appear in the underlying records that the six-grade scheme does not define.* The
earlier dossiers used *ESTABLISHED* and *ESTABLISHED (as an absence)* in their own ledgers, and the
dispositions *unsupported*, *withdrawn*, *argued against*, *not reconstructed* and *unmeasured* for
claims that are disposed of rather than graded. Where this series carries such a claim it maps the
label onto the six-grade scheme explicitly rather than inventing a seventh grade: *ESTABLISHED (as an
absence)* becomes *[REPORTED]*, as an absence, which is the honest reading — nobody published the
thing, and that is a statement about the published corpus rather than about reality.

### 1.2 Verification performed for this appraisal

Beyond reading each record, the following were checked independently, and each check is the reason a
claim elsewhere carries the grade it does.

*Five AOSP sources were re-read against `cs.android.com`* rather than against the summaries that
cited them, producing four exact confirmations and two substantive contributions. Both contributions
are in [`1-protocol.md`](1-protocol.md): the open-dice layer-identifier derivation masks the high bit
of its first output byte, an operation the prior record's formula omitted and whose omission breaks
chain linkage while presenting as a signature bug (§4.3); and the recommendation to report
`CURVE_NONE` for `supportedEekCurve` needs a [VTS](https://source.android.com/docs/core/tests/vts)
caveat it previously lacked (§2.3).

*The two independent implementations were read and cross-checked*: the wire format of one field route
against the Rust client's encoder, the key-derivation label against that client's default, the
verifier's pinned protocol constants against AOSP's [CDDL](https://www.rfc-editor.org/rfc/rfc8610),
and the absence of a provisioning-status gate and of [X.509](https://www.rfc-editor.org/rfc/rfc5280)
signature verification in that client — reported in [`2-mechanisms.md`](2-mechanisms.md) §3.5 and
§4.5 and in [`3-detection.md`](3-detection.md) §1.3 and §1.4.

*The engineering corpus's artifact layer was read directly* rather than through its narrative:
container metadata JSON, patch-script constants, recorded digests, and the acceptance records. That
is what distinguishes *[PRIMARY]* from *[REPORTED]* throughout [`2-mechanisms.md`](2-mechanisms.md)
§4–§6.

*The module's own source was checked* where a document made a claim about it: the keybox parser's
actual constraints, the inspector's [OID](https://www.itu.int/rec/T-REC-X.660) coverage, the
revocation matcher's serial handling. One documentation error was found and corrected in the module's
own README, which claimed a keybox must contain both an RSA and an
[ECDSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) key, where
[`rust/teesim-km/src/attest.rs`](../rust/teesim-km/src/attest.rs) requires at least one — which is
what lets an RKP-shaped keybox load.

*The arithmetic of every cross-document claim was recomputed*, which is how the "orders of magnitude"
and ratio statements in [`4-measurements.md`](4-measurements.md) §3.3 came to be stated as the
measured multiple.

### 1.3 Archival state

The primary sources below are cited by URL, with digests or commit identifiers where they exist. They
are not mirrored in this repository: the verbatim HTML of the two forum threads, their English
renditions, the engineering corpus, and the two keybox samples are all outside it — the samples
because they contain live private keys that [`1-protocol.md`](1-protocol.md) §1.5 excludes, and the
rest because this repository carries analysis rather than an archive.

That is a real weakness in the evidence base. A forum thread can be edited or deleted; a GitHub
repository can be force-pushed or taken down; a firmware dump site can lapse. Where that happens, the
record of what a source said survives only in these five documents. Two mitigations are in place.
Every claim traceable to one of those sources is quoted or restated here in enough detail to be
checkable against a copy obtained elsewhere — the lengths, digests, labels, command words and field
values in [`4-measurements.md`](4-measurements.md) and [`2-mechanisms.md`](2-mechanisms.md) are there
for exactly this reason. And every record is pinned where pinning is possible: commit identifiers for
the two implementations, digests for every binary in [`4-measurements.md`](4-measurements.md) §1.2,
and [Wayback Machine](https://web.archive.org/) snapshots for the revocation list in §4.2 of that
document.

Drift already observed during this work, which is why the point is not hypothetical: the upstream
Python minting tool removed its hardware-key-derivation path and added a
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) curve option after
the measurement that described it; one measured firmware generation has no public dump at all, so the
newest available stock dump predates the build the leaked sample names by roughly seven months; and
the public vendor tree receives whole-tree re-imports that make diff status unreadable and force
comparison by blob identifier ([`4-measurements.md`](4-measurements.md) §6.6).

---

## 2. The sources

### 2.1 Normative

[AOSP](https://cs.android.com/android/platform/superproject/main) and
[source.android.com](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning),
read directly. *[PRIMARY]*, and dispositive for every question of what the protocol requires. The full
list of paths is [`1-protocol.md`](1-protocol.md) §9; the standing caution is that AOSP is a moving
target and every version-dependent claim carries [`1-protocol.md`](1-protocol.md) §8.1's
re-verification requirement, against [Code
Search](https://cs.android.com/android/platform/superproject/main) or
[Gitiles](https://android.googlesource.com/) raw rather than the GitHub mirror.

The one place AOSP is not dispositive is the provisioning-information extension. Google publishes [two
keys of that
map](https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension)
and states explicitly that it is unversioned and may gain fields. Two of the four tags observed in the
field are therefore undocumented, and nothing normative constrains them
([`4-measurements.md`](4-measurements.md) §3.2).

### 2.2 Records carrying argumentative weight

*The signing-oracle post* — [kanxue thread 293244](https://bbs.kanxue.com/thread-293244.htm). A public
technical post, single author, on a Qualcomm handset. It names the missing check by symbol, gives the
command number, the wire format and the failed alternatives. *[REPORTED]*, and uniquely well-supported
for a single-source record because its wire format is independently confirmed (§3.1).

*The three-device retrospective* — [kanxue thread 293246](https://bbs.kanxue.com/thread-293246.htm). A
public retrospective covering three extraction routes, matching the engineering corpus chapter for
chapter. It declares itself not a copy-paste tutorial and states that the public version omits private
keys, real seeds, device identifiers, patch bytes and flashable commands. *[REPORTED]*. Its value is
the causal corrections and the pitfall catalogue, which is why it is the most-cited record in
[`2-mechanisms.md`](2-mechanisms.md) §10.

*The engineering corpus* —
[`gungnir-sanye/tee-attestation-extraction`](https://github.com/gungnir-sanye/tee-attestation-extraction),
read at commit `87f07b3`. Per-device tutorials, practice logs, patch scripts, patched binaries,
container-decryption metadata and acceptance reports. *[PRIMARY]* for artifacts read directly;
*[REPORTED]* for anything only narrated.

*An independent implementation used as a protocol oracle* —
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), read at commit `85807c0`. A
normal-world Rust implementation of the RKP client, the CSR builder, a verifier, and the Qualcomm
device path. *[MEASURED]* — read and cross-checked locally. It matters more than its size suggests:
its validator encodes the wire rules, so a claim about the protocol can be checked against code that
has to interoperate rather than against prose that does not.

*The minting tool* — [`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw). The readable
Python implementation of the same pipeline, used throughout to cite protocol behaviour because its
source is straightforwardly legible. *[PRIMARY]* for code read; note §1.3's drift — the revision that
carried the hardware-key path no longer exists upstream.

### 2.3 Records carried as background

Each supports a bounded claim and none carries a route.

[TÄMU](https://arxiv.org/abs/2601.20507), with [tooling](https://github.com/HexHive/taemu) —
*[PRIMARY]* for its reported vulnerability table and its public platform support; the basis of
[`4-measurements.md`](4-measurements.md) §6.4. Its results carry no CVE numbers, so patch status
cannot be checked against any bulletin.

[FIASCO](https://nebelwelt.net/blog/2025/1227-fiasco.html), with
[slides](https://hexhive.epfl.ch/publications/files/25CCC-presentation.pdf) and
[tooling](https://github.com/HexHive/beanpod_fiasco) — *[PRIMARY]* for the escalation it published on
a sibling handset, and relevant chiefly as a negative: its 65 slides contain no occurrence of
*attestation*, *keymaster*, *keymint*, *RKP*,
*[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/)*, *CDI*, *UDS* or
*[StrongBox](https://source.android.com/docs/security/best-practices/hardware#strongbox)*, which is
what makes [`2-mechanisms.md`](2-mechanisms.md) §5.1's route independent of it.

[Quarkslab on bypassing Android hardware
attestation](https://blog.quarkslab.com/bypassing-android-hardware-attestation.html), with a
[demo](https://github.com/quarkslab/android-hardware-attestation-demo) — *[PRIMARY]* for the
two-handset relay architecture that [`2-mechanisms.md`](2-mechanisms.md) §3 collapses into one device.

[`Colorful-glassblock/duchamp-root`](https://github.com/Colorful-glassblock/duchamp-root) —
*[PRIMARY]* for its README read, not run; the basis of [`4-measurements.md`](4-measurements.md) §6.5,
corroborated from an unrelated direction by the [MITRE
record](https://cveawg.mitre.org/api/cve/CVE-2026-43499) for
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), which is an upstream Linux bug
rather than a vendor one.

[`mt6897-devs/vendor_xiaomi_duchamp`](https://github.com/mt6897-devs/vendor_xiaomi_duchamp) and
[`dumps.tadiphone.dev`](https://dumps.tadiphone.dev/dumps/redmi/duchamp) — the two independent
provenance chains whose agreement establishes tree ↔ real firmware by hash in
[`4-measurements.md`](4-measurements.md) §6.1.

[`android.googleapis.com/attestation/status`](https://android.googleapis.com/attestation/status) and
[`key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl) — live endpoints, *[MEASURED]*
on dated fetches, with historical snapshots through the Wayback Machine.

[MediaTek product security bulletins](https://corp.mediatek.com/product-security-bulletin) —
*[PRIMARY]* for advisory text, and the basis of a claim that is deliberately not advanced
([`2-mechanisms.md`](2-mechanisms.md) §9.1): an advisory in the right stage with the right primitive
class is not evidence about DICE material.

Downstream consumers of leaked keyboxes — a widely distributed integrity-fix module shipping a leaked-
keybox directory, several keybox managers, and an alternative
[KeyMint](https://source.android.com/docs/security/features/keystore) implementation that rejects
EC-only RKP keyboxes — are relevant only as ecosystem context, and the last of them as a datapoint
that the RKP shape is recognised in the wild.

---

## 3. Appraisal of the records that carry weight

### 3.1 What makes the signing-oracle post unusually checkable

*Its wire format is confirmed by unrelated code.* The post derives request and response framing from
trusted-application entry-point disassembly; the Rust implementation encodes the same command word,
the same two [CBOR](https://www.rfc-editor.org/rfc/rfc8949) labels, and the same single-entry response
map. Neither source cites the other. That is the strongest single piece of corroboration anywhere in
this series ([`2-mechanisms.md`](2-mechanisms.md) §3.5).

*It records its failures.* The post is largely an account of what did not work: the whole
download-mode surface, a nonce-reuse probe that found the implementation conformant, and a command
that turned out not to be the MAC oracle it was hoped to be. A record that publishes its negative
results is easier to weigh than one that publishes only its successes.

*It names the defect precisely enough to be refuted.* A claim that one specific function is referenced
only from two specific commands is checkable by anyone with the same image, which is why
[`4-measurements.md`](4-measurements.md) §8 can state the refutation condition in one line.

What it does not have is independent execution. Whether the described invocation yields a
Google-signed chain in practice rests on the post's own report of a repeated success.

### 3.2 What makes the retrospective valuable, and where it is weakest

Its value is not the routes. It is the methodology: the five look-alike success states, the three-layer
acceptance structure, the negative control, the parsing discipline, the two-keys-must-differ
correction, and the causal correction of [`2-mechanisms.md`](2-mechanisms.md) §6.6, where the research
corrects its own earlier attribution by decomposing a multi-variable change. Those transfer to any
platform and would survive every route narrative being wrong.

Its weakness is that it is one author's effort reporting three of this series' four routes, and its own
front matter says the material was organised by AI from existing project records and that not every
historical command has been re-executed by a human. Read against that, two readings are available and
this series takes the conservative one: the mechanism class is well evidenced, the individual constants
are single-sourced.

### 3.3 What the corpus settles, and what it only narrates

The corpus is where *[PRIMARY]* and *[REPORTED]* diverge within one source.

*Settled by reading an artifact:* container metadata, with its own self-consistency checks on the
unwrapping key's parameters; recorded digests for every stock and patched binary; the patch scripts'
constants, including a key-derivation call site's own captured arguments; the acceptance records, with
public-key correspondence and chain verification results; and the device gates that every builder
enforces before running.

*Only narrated:* that the routes were executed as recorded, that the patches were sufficient and
minimal, and that any given capture reproduced the same round's identity. The artifacts are consistent
with the narrative throughout, which is weaker than confirming it.

One structural observation is evidence of care rather than of result: the corpus publishes a seed's
digest fingerprint and never the seed. A record that withholds the one thing that would make it a
key-distribution vector, while publishing enough to be checked, is behaving the way the scope rule of
[`1-protocol.md`](1-protocol.md) §1.5 describes.

### 3.4 Why two implementations are better than one specification

Both normal-world implementations build an entire `ProtectedData`
[COSE_Encrypt](https://www.rfc-editor.org/rfc/rfc9052#section-5) structure that the protocol version
they target does not have ([`2-mechanisms.md`](2-mechanisms.md) §7.3). Reading either alone, that looks
like evidence the code was never exercised. Reading both, it is a shared inheritance from the older
protocol version — and the inference drawn from it was withdrawn.

That is why the implementations are used as oracles at all. Where a specification is ambiguous — map
ordering, which fields are mandatory in practice, what a validator actually rejects — code that must
interoperate resolves the ambiguity, and two independent codebases agreeing resolves it reliably. The
two places this paid off are the key-derivation label of [`2-mechanisms.md`](2-mechanisms.md) §4.5 and
the wire format of §3.5.

It cuts the other way too, and [`3-detection.md`](3-detection.md) §1.4 records it: both implementations
are missing gates the protocol needs — no provisioning-status check, and chain linkage by name rather
than by signature. An oracle tells you what the wire looks like, not what a careful verifier should do.

### 3.5 The common limit, and what would break the single-sourcing

Three of four routes from one corpus is the structural weakness of the whole evidence base, and it is
not remediable by reading more of the same corpus. What would break it, in rough order of cost:

An *independent disassembly* of the same Qualcomm image showing the same cross-references for the MAC
parser. A *single invocation* on any production handset of that platform of the command reported to
return a hardware-secret-derived value with no provisioning gate — one invocation either confirms a
second defect or refutes it outright. An *independent stock-handset reading* of the provisioning
extension's issuance count, which [`4-measurements.md`](4-measurements.md) §5.2 shows costs one `adb`
command and settles the baseline that [`3-detection.md`](3-detection.md) §4.2's entire detection
argument rests on. A *re-run from the stock inputs* through any builder's digest gates. And, for the
one claim in the series that is both load-bearing and weakly graded, a *factory-reset experiment* on
any Android handset ([`4-measurements.md`](4-measurements.md) §5.4).

What is not on that list is re-executing a route end to end. None of this series' conclusions requires
it, because every conclusion that matters defensively is either a protocol fact (normative), a
measurement on an artifact (§3.3), or the structural pattern of [`2-mechanisms.md`](2-mechanisms.md)
§8 — which is strengthened rather than weakened by the routes being on four different platforms.

---

## 4. What could not be read

*An English-language forum's thread* on [boot-ROM](https://en.wikipedia.org/wiki/Boot_ROM)-level
techniques for the chipset in question returns HTTP 403 to automated fetch. It is known only from
search snippets and is *[UNVERIFIED]* throughout; no claim in this series rests on it.

*A conference slide deck's spoken content.* A quotation to the effect that one vendor TEE is being
phased out in favour of another is second-hand and marked as such.

*No public firmware dump exists for the current generation of the measured handset.* This is the
sample-edge of [`4-measurements.md`](4-measurements.md) §6.6's never-rebuilt finding, and the one gap
that cannot be closed by effort — only by someone publishing a dump.

*The 17 vulnerabilities reported by the emulation paper carry no CVE numbers*, so their patch status
cannot be checked against any bulletin. The paper states they were responsibly disclosed; nothing more
is knowable from the public record.

*The forum pages hide more than they show, and the limits are mechanical.* Only the opening post of
each thread is in the static HTML; replies load over JavaScript and were never captured. In the
retrospective the author's own repository link is wrapped in the forum's encrypted-text markup and is
unreadable without a logged-in session. A plain HTML-to-text conversion yields nothing on these pages,
because the post body sits in a container that needs a DOM parse; and each page embeds the author's
markdown source once and the rendered text again, so a naive extraction produces every paragraph
twice. Re-fetching needs a browser user agent and a Chinese `Accept-Language`, or the server returns a
stub. These are the reasons the renditions this series worked from were made by hand rather than by a
converter, and the reason a future reader should expect to redo that work.

*An earlier internal dossier is not carried forward as a file.* The general account of
attestation-key compromise that this series grew out of — the custody taxonomy now in
[`2-mechanisms.md`](2-mechanisms.md) §2.1, the control-plane measurements now in
[`3-detection.md`](3-detection.md) §2, the coverage matrix now in §9 of that document — is not part of
this series and is not mirrored here. Its substance was extracted rather than referenced, and the one
grade it carried that these routes overturn is restated as [`2-mechanisms.md`](2-mechanisms.md) §9.4.
Claims traceable to it are marked with the grade they carried there, and its live fetches are dated
only as "on one live fetch", since the values have certainly moved since.

*Authorship of the signing-oracle post relative to the retrospective* could not be determined from the
archived pages. [`2-mechanisms.md`](2-mechanisms.md) §1.2 states the consequence: treating it as
independent is generous in one direction and risky in the other, and the risk is disclosed rather than
resolved.

---

## 5. Provenance of the two keybox samples

The samples are the series' primary artifacts and the only place where origin could be established to
the byte. This section is what licenses [`4-measurements.md`](4-measurements.md) §2 to treat them as a
known quantity.

### 5.1 Identity

Sample A is 5993 bytes, [SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
`4c1fd429…5b26c3`; sample B is 5690 bytes, SHA-256 `f87306c3…925aa5`. Each is a keybox XML wrapper
holding one `ecdsa` key and no RSA key, with a four-certificate chain, and each file's private key
matches its leaf. Their original filenames differ from the names used in this series, which is noted so
that a reader holding a copy under another name can match by digest. The private scalars are not
reproduced, although a cited source published them in full; the digests are sufficient for correlation
work and the scalars are not.

### 5.2 What is proven, and how

*[MEASURED]* Both files are reproduced byte-exactly — 89 of 89 lines and 5993 of 5993 bytes for sample
A, 86 of 86 lines and 5690 of 5690 bytes for sample B — by a keybox writer whose indentation constants
are: four spaces for the keybox-count and keybox elements, eight for the key element, twelve for the
private-key and certificate-chain elements, sixteen for the certificate-count and certificate
elements, sixteen for the private-key [PEM](https://www.rfc-editor.org/rfc/rfc7468) body, and twenty
for the certificate PEM bodies.

*[PRIMARY]* Those last two constants are emitted natively by
[`eltavine/Duck-ToolBox`](https://github.com/eltavine/Duck-ToolBox), in its keybox-XML writer
(`duckd/src/features/rkp/keybox_xml.rs` at the revision measured; the tree has since been
reorganised), where the two `indent_block` calls pass literal 16-space and 20-space prefixes, with
every element string character-identical to the artifacts line for line.

*[MEASURED]* [`MhmRdd/google-rkp-sw`](https://github.com/MhmRdd/google-rkp-sw), the Python sibling,
emits twelve and sixteen for those two constants and matches only 21 of 89 lines. Adding four spaces to
its PEM indenter yields sixteen and twenty and reproduces both files exactly. The two tools therefore
differ by precisely that one constant — and the Rust project's own module metadata lists the Python
tool's author as a co-author, so the relationship is a fork rather than a coincidence.

The native, unmodified emitter of these bytes is the Rust tool. The Python one is the readable
reference implementation of the same pipeline, which is why it is cited for protocol behaviour
throughout [`2-mechanisms.md`](2-mechanisms.md) §7.

Four consequences follow, each measured rather than inferred.

*The `DeviceID` attribute is packaging metadata.* It is the manufacturer string, a hyphen, and six
random bytes, produced by the writer's own `f'{manufacturer}-{os.urandom(6).hex()}'`. It is not a MAC
address and carries no device identity; the manufacturer comes from the operator's configuration file.

*One EC key and no RSA key is the writer's fixed shape*, not a fact about RKP — although it is also
what a genuine RKP keybox looks like, which is why the shape works as a class signal
([`3-detection.md`](3-detection.md) §5.1).

*A single-keybox file is the writer's shape.* Factory-keybox leaks are bulk files; these are
singletons.

*The P-256 private keys were generated in normal-world software and never existed inside a TEE.*
Nothing was unsealed, decrypted or lifted from a key blob. No attestation private key was extracted
from any secure world to produce these artifacts: they were minted against Google's unauthenticated
production endpoint by ordinary software ([`2-mechanisms.md`](2-mechanisms.md) §7).

An independent confirmation that does not rely on the byte match at all: the producing tool's default
device information omits `vbmeta_digest`, which the CDDL makes mandatory and which a genuine KeyMint
trusted application cannot omit, so sample B's request was demonstrably not TA-produced
([`4-measurements.md`](4-measurements.md) §3.4).

### 5.3 What is explicitly not proven

*That the seed behind them came from the handset named in sample A's extension.* Tag 5.4's fingerprint
is operator-authored configuration sent unsigned to the EEK endpoint. It shows only that a real,
certified build string was entered and that the backend resolved it and marked it approved. It is not
cryptographically bound to the seed's device, and sample B names no device at all. A seed from any
registered device, paired with a typed fingerprint, would produce a byte-identical artifact. The grade
stays *[SPECULATIVE]*, and [`2-mechanisms.md`](2-mechanisms.md) §10.3 records the two signed fields
that argue against a specific candidate origin.

*That the two samples are one identity.* Unsupported. The `DeviceID` is random and the leaf common name
equals the certificate's own serial; neither file carries a device identifier.

*Which curve the donor identity registers.* [`4-measurements.md`](4-measurements.md) §6.3 leans P-256
from named routines in a stripped binary, and the Python tool built
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032) chains until it gained a P-256 option. Unmeasured.

*Whether the shared intermediates say anything.* They do not: the backend hands the same shared portion
to every requester in an epoch ([`4-measurements.md`](4-measurements.md) §2.2), so two samples agreeing
on positions 2 through 4 is not evidence of common origin. The byte-exact XML reproduction of §5.2
establishes common *producer*, not common *device*.

### 5.4 Corrections of record

Six, each recorded rather than silently applied. The first four are stated in detail in
[`4-measurements.md`](4-measurements.md) §3.4 — the inverted direction of tag 5.2's resolution,
`DeviceID` as packaging metadata, "anonymous versus bound" as a property of the operator's
configuration, and the withdrawal of the pool-cap reading of the issuance count. Two more are
provenance corrections and belong here.

*The donor-handset TEE was misidentified in an earlier dossier.* It was recorded as one vendor's TEE
and is in fact another's, on a [Zircon](https://fuchsia.dev/fuchsia-src/concepts/kernel)
[microkernel](https://en.wikipedia.org/wiki/Microkernel), which retired a standing assumption that a
published EL3 chain applied to it ([`4-measurements.md`](4-measurements.md) §6.2). The correction is
not cosmetic: it removes an entire CVE inventory from the analysis.

*One indicator of tool non-exercise is withdrawn.* Finding an unused `ProtectedData` construction was
listed among the signs that the Python tool had never been run. Both implementations build it, because
the targeted protocol version does not have the field ([`2-mechanisms.md`](2-mechanisms.md) §7.3). The
other indicators in that adjudication — a hardcoded empty `UdsCerts`, the repository hygiene, an
unanswered issue — are unaffected.

A seventh correction concerns a citation rather than a claim, and the error class is instructive: one
killed scheme rested on a reading of AOSP
[Trusty](https://source.android.com/docs/security/features/trusty) in which a hardware-key derivation
routine produces the device certificate chain. It does not — it derives the MAC key, under its own
explicit label, while the certificate chain and device key come from a separate service. A scheme
resting on a misread function name is refuted by reading the function.

### 5.5 Scope observed in this section

Every source cited in this series states a research, competition or defensive scope and withholds
private keys, real seeds, device identifiers and flashable commands. This document holds the same line,
and in one case holds it where a source did not: the samples' private scalars were published by a cited
record and are not reproduced here, because they add nothing analytically while being the one thing
that would make this a key-distribution vector. The same reasoning applies to the container-unwrapping
private factors of [`2-mechanisms.md`](2-mechanisms.md) §5.2, where the finding is that an unwrapping
key sits in a loader at a recorded offset.

One request was declined in the course of this work and the declination is recorded: selecting a
handset to purchase for the purpose of extracting a live provisioning identity. A seed is a permanent
Google-signed-attestation minting capability belonging to a real registered device, its downstream use
is forging [hardware
attestation](https://source.android.com/docs/security/features/keystore/attestation) to banking,
payment and identity applications, and at the time no acquisition route was published — so the request
was target selection for novel offensive work. Everything adjacent remained in scope and is what this
series contains: analysis, measurement, acceptance relations, the discriminating experiments of
[`4-measurements.md`](4-measurements.md) §5.4, and the detection signals of
[`3-detection.md`](3-detection.md) §7.

---

## 6. Locators not carried in the reference list

[`1-protocol.md`](1-protocol.md) §9 carries every normative and academic address this series uses. The
remainder, listed once:

The leaf revocation endpoint and the RKP hierarchy's
[CRL](https://www.rfc-editor.org/rfc/rfc5280#section-5) —
[`attestation/status`](https://android.googleapis.com/attestation/status),
[`key_ca1.crl`](https://android.googleapis.com/attestation/key_ca1.crl). Historical snapshots of the
former through the Wayback Machine, with the snapshot URLs in
[`4-measurements.md`](4-measurements.md) §4.2.

Device and firmware provenance — vendor blobs at
[`mt6897-devs/vendor_xiaomi_duchamp`](https://github.com/mt6897-devs/vendor_xiaomi_duchamp), the device
tree at
[`mt6897-devs/device_xiaomi_duchamp`](https://github.com/mt6897-devs/device_xiaomi_duchamp), kernel
sources at
[`MiCode/Xiaomi_Kernel_OpenSource`](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/tree/bsp-duchamp-u-oss),
stock dumps at [`dumps.tadiphone.dev`](https://dumps.tadiphone.dev/dumps/redmi/duchamp), and a
firmware tracker at [`mirom.ezbox.idv.tw`](https://mirom.ezbox.idv.tw/en/phone/duchamp/). Handset
specifications from [GSMArena](https://www.gsmarena.com/redmi_k70e-12716.php).

Advisories and vulnerability records — [MediaTek product security
bulletins](https://corp.mediatek.com/product-security-bulletin), the [CVE
Program](https://www.cve.org/), and the [MITRE CVE
API](https://cveawg.mitre.org/api/cve/CVE-2026-43499) for records whose assigner text is worth reading
verbatim.

The Zircon syscall reference used in [`4-measurements.md`](4-measurements.md) §6.2 —
[fuchsia.dev](https://fuchsia.dev/reference/syscalls).

Field reports, corpora and implementations — all five in [`1-protocol.md`](1-protocol.md) §9's final
section, with commit identifiers in §2.2 above.
