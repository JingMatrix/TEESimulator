# Android [Remote Key Provisioning](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning) — a technical report in five parts

The parts are exclusive in subject and self-contained in sources: every external claim is linked,
and nothing here depends on material outside this directory.

### [1 · Protocol, trust model, and the limits of simulation](1-protocol.md)

The device-side protocol byte for byte: three interleaved version axes, the
`AuthenticatedRequest<CsrPayload>` envelope, and the deterministic-encoding rules that decide byte
equality. Then the [DICE](https://source.android.com/docs/security/features/dice) key hierarchy as
[`open-dice`](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c) derives it,
the path keys travel through `rkpd` and `keystore2`, why an internally perfect chain confers
nothing, and where this module stands against all of it. Carries the series' apparatus: the
six-grade scheme (§1.4), the scope rule (§1.5) and the reference list (§9).

### [2 · Mechanisms of compromise](2-mechanisms.md)

What has been done to real handsets. The custody taxonomy — who holds the key and who signs with it,
which decides whether revocation is the right remedy — then five objects routinely confused for one
another, four published acquisition routes across four [trusted execution
environment](https://globalplatform.org/technical-committees/trusted-execution-environment-tee-committee/)s,
the off-device minting pipeline they feed, and the pattern they share: no cipher is broken and no
key factored; what changes is what the code does with a verification result.

### [3 · Detection and defence](3-detection.md)

Acceptance relations that separate a result from a plausible byte string; Google's control plane as
measured, including a root re-issued four times under one public key and a [revocation
list](https://android.googleapis.com/attestation/status) carrying two different serial encodings;
the signals a presenter can and cannot suppress; and mitigation by actor. The coverage matrix is §9.

### [4 · The measured record](4-measurements.md)

Every quantity the other parts rely on, with the command that reproduces it: two leaked keyboxes
decoded, the provisioning-information extension byte for byte, population censuses, revocation-list
state, and the measured platform characterised from vendor binaries.

### [5 · Evidence base](5-sources.md)

Where each claim comes from, how much weight the record can carry, and what would overturn it. Also
the byte-exact provenance of the two keybox samples, and what could not be read at all.

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

Every substantive claim is graded on the six-grade scheme of part 1 §1.4, and no grade is promoted
when a claim moves between documents.

Corrections are recorded, not silently applied. Part 4 §3.4 and part 5 §5.4 are the lists; a
document's own corrections outrank anything remembered about it.

Each part states what is not established, and names the single observation that would refute each
load-bearing claim. Where a claim is an absence of evidence rather than evidence of absence, it says
so.

Secret extraction is out of scope as a procedure, per part 1 §1.5. These documents reconstruct
mechanisms, formats and acceptance relations so that the simulation is faithful and the detection
advice correct; they reproduce no private key material and no route-operative constant.

Absolute dates are avoided: durations, spans and intervals carry the meaning and stay stable. Where
precision matters, the linked artifact carries its own timestamp.

Sources are linked, not mirrored. Part 5 §1.3 states the consequence — a thread can be deleted and a
repository force-pushed — and why every claim traceable to one is restated here in enough detail to
be checked against a copy obtained elsewhere.
