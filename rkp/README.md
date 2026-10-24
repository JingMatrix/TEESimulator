# Android [Remote Key Provisioning](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning) — a technical report in five parts

Read in order, or jump to the part that matches the question. Each part is exclusive in its subject
and self-contained in its sources: *every external claim is linked, and nothing here depends on
material outside this directory.*

### [1 · Protocol, trust model, and the limits of simulation](1-protocol.md)

*Start here.* The device-side protocol specified byte for byte — three interleaved version axes, the
`AuthenticatedRequest<CsrPayload>` envelope, the deterministic-encoding rules that decide byte
equality — then the [DICE](https://source.android.com/docs/security/features/dice) key hierarchy
derived from [`open-dice`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c),
the path keys travel through `rkpd` and `keystore2`, and an analysis of why a chain that is
internally perfect still confers nothing. Closes with where this module sits against all of it and
what a *serving* implementation would need.

It also carries the series' only copy of the apparatus: the six-grade scheme (§1.4), the scope rule
(§1.5) and the reference list (§9).

### [2 · Mechanisms of compromise](2-mechanisms.md)

What has actually been done to real handsets. The custody taxonomy first — *who holds the key and
who signs with it*, which decides whether revocation is even the right remedy — then five objects
routinely confused for one another, then four published acquisition routes across four different
[trusted execution
environments](https://globalplatform.org/technical-committees/trusted-execution-environment-tee-committee/),
the off-device minting pipeline they feed, and the structural pattern all of them share: *no cipher
is broken, no key factored, no digest forged; what changes is what the code does with the answer.*

### [3 · Detection and defence](3-detection.md)

The other half. Acceptance relations that separate a result from a plausible byte string; Google's
control plane as measured, including a root re-issued four times under one public key and a
[revocation list](https://android.googleapis.com/attestation/status) whose entries arrive in two
different serial encodings; the signals a presenter can and cannot suppress; and mitigation by
actor. Its coverage matrix (§9) is the summary result, and its two empty columns are the point.

### [4 · The measured record](4-measurements.md)

Every quantity the other four rely on, each with the command that reproduces it: two leaked keyboxes
decoded, the provisioning-information extension byte for byte, population censuses, revocation-list
state, and the measured platform characterised directly from vendor binaries.

### [5 · Evidence base](5-sources.md)

Where each claim comes from, how much weight the underlying record can carry, and what single
observation would overturn it. Also the byte-exact provenance of the two keybox samples, and an
honest account of what could not be read at all.

---

### [`tools/`](tools/) — the checks, runnable

`teesim-attest` implements the acceptance relations of part 3 §1 and the thresholds of part 4, with
34 tests that need neither network nor device:

```bash
cd tools && python3 -m unittest discover -s tests -q
./teesim-attest baseline            # every constant, with its provenance
./teesim-attest inspect keybox.xml  # decodes the provisioning extension
./teesim-attest verify  keybox.xml  # exits 1 if the keybox would not be accepted
```

### Conventions

*Every substantive claim is graded*, on the six-grade scheme of part 1 §1.4, and *no grade is
promoted* when a claim moves between documents.

*Corrections are recorded, not silently applied.* Where a later measurement overturns earlier text,
the document says what was withdrawn and why — part 4 §3.4 and part 5 §5.4 are the lists. A
document's own corrections outrank anything remembered about it.

*Each part states what is not established*, and names the single observation that would refute each
load-bearing claim. Where a claim is an absence of evidence rather than evidence of absence, it says
so.

*Secret extraction is out of scope as a procedure*, per part 1 §1.5. These documents reconstruct
mechanisms, formats and acceptance relations so that the simulation is faithful and the detection
advice is correct; they reproduce no private key material and no route-operative constant.

*Absolute dates are avoided.* Durations, spans and intervals carry the meaning and stay stable; a
calendar date goes stale and was rarely the point. Where precision matters, the linked artifact
carries its own timestamp.

*Sources are linked, not mirrored.* Part 5 §1.3 states the consequence — a thread can be deleted and
a repository force-pushed — and why every claim traceable to one is restated here in enough detail
to be checked against a copy obtained elsewhere.
