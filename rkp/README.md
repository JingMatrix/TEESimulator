# Android Remote Key Provisioning

A technical report on the protocol
[Android](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning) uses to
issue attestation certificates, on how attestation material has been compromised in the field, and
on what distinguishes a genuine result from a plausible one. The five parts are exclusive in subject
and self-contained in sources: every external claim is linked, and nothing here depends on material
outside this directory.

### [1. The Remote Key Provisioning protocol and its trust model](1-protocol.md)

The device-side protocol byte for byte: three interleaved version axes, the request envelope, and
the deterministic-encoding rules that decide byte equality ([part 1
§3](1-protocol.md#3-deterministic-encoding)). Then the
[DICE](https://source.android.com/docs/security/features/dice) key hierarchy as
[open-dice](https://pigweed.googlesource.com/open-dice/+/refs/heads/main/src/dice.c) derives it
([part 1 §4](1-protocol.md#4-the-dice-key-hierarchy)), the path keys travel through the provisioning
daemon and the keystore ([part 1 §5](1-protocol.md#5-the-provisioning-path-on-the-device)), why an
internally perfect chain confers nothing ([part 1
§6](1-protocol.md#6-analysis-of-the-trust-relation)), and where this project stands against all of
it ([part 1 §7](1-protocol.md#7-application-to-teesimulator)). Carries the scope rule ([part 1
§1.3](1-protocol.md#13-scope-and-conventions)) and the reference list ([part 1
§9](1-protocol.md#9-references)).

### [2. Mechanisms of attestation-material compromise](2-mechanisms.md)

What has been done to real handsets. The custody classes ([part 2
§2.1](2-mechanisms.md#21-custody-classes)) — who holds the key and who signs with it, which decides
whether revocation is the right remedy — then five objects routinely confused for one another, four
published acquisition routes across four trusted execution environments ([part 2
§3](2-mechanisms.md#3-route-a-a-signing-oracle-on-qualcomm-keymint) to [part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret)), the off-device minting
procedure they feed ([part 2 §7](2-mechanisms.md#7-off-device-certificate-minting)), and the
structure they share ([part 2 §8](2-mechanisms.md#8-common-structure-of-the-four-routes)): no cipher
is broken and no key factored, and what changes is what the code does with a verification result.

### [3. Detection and defence](3-detection.md)

Acceptance relations that separate a result from a plausible byte string ([part 3
§1](3-detection.md#1-acceptance-criteria)); the control plane as measured ([part 3
§2](3-detection.md#2-the-control-plane)), including a root re-issued four times under one public key
and a [revocation list](https://android.googleapis.com/attestation/status) carrying two serial
encodings; the signals a presenter can and cannot suppress ([part 3
§5](3-detection.md#5-forgeability), [part 3
§7](3-detection.md#7-statistical-and-behavioural-signals)); the coverage of mechanisms by control
([part 3 §9](3-detection.md#9-coverage-of-mechanisms-by-control)); and recommendations by actor
([part 3 §10](3-detection.md#10-recommendations-by-actor)).

### [4. Measurements](4-measurements.md)

Every quantity the other parts rely on, with the command that reproduces it ([part 4
§5](4-measurements.md#5-reproduction)): two leaked keyboxes decoded ([part 4
§2](4-measurements.md#2-two-leaked-provisioned-keyboxes)), the provisioning-information extension
byte for byte ([part 4 §3](4-measurements.md#3-the-provisioning-information-extension)), population
censuses ([part 4 §4](4-measurements.md#4-populations)), and the measured platform characterised
from vendor binaries ([part 4 §6](4-measurements.md#6-the-measured-platform)).

### [5. Sources and their limits](5-sources.md)

Where each claim comes from, how much weight the record can carry, and what would overturn it. Also
the byte-exact provenance of the two keybox samples ([part 5
§5](5-sources.md#5-provenance-of-the-keybox-samples)), and what could not be read at all ([part 5
§4](5-sources.md#4-material-that-could-not-be-read)).

### Appendices

[appendix A](A-record-signing-oracle.md) and [appendix B](B-record-three-devices.md) record the
content of the two field sources on which [part 2
§3](2-mechanisms.md#3-route-a-a-signing-oracle-on-qualcomm-keymint) to [part 2
§6](2-mechanisms.md#6-route-d-same-boot-capture-of-the-dice-leaf-secret) rest. Both originals are
forum threads, a medium that can be edited, deleted or placed behind a login, and whose replies are
absent from the static HTML. The appendices set down their technical substance — measurements,
structures, negative results and the authors' own qualifications — so that the claims remain
checkable if the sources become unavailable.

---

### Toolkit: [the toolkit](tools/README.md)

`teesim-attest` implements the acceptance relations of [part 3
§1](3-detection.md#1-acceptance-criteria) and the thresholds of [part 4](4-measurements.md), with 34
tests that require neither network nor device:

```bash
cd tools && python3 -m unittest discover -s tests -q
./teesim-attest baseline            # every constant, with its provenance
./teesim-attest inspect keybox.xml  # decodes the provisioning extension
./teesim-attest verify  keybox.xml  # exits 1 if the keybox would not be accepted
```

### Conventions

*Claims are attributed where they are made.* A measurement states what was measured and gives the
command that reproduces it; a claim resting on a third-party account not reproduced here says so at
the point of use, and [part 5 §3](5-sources.md#3-appraisal) appraises how much weight each such
account carries. No claim gains strength by being repeated in another part.

*Corrections are recorded rather than silently applied.* Sections [part 4
§3.4](4-measurements.md#34-corrections-to-earlier-readings) and [part 5
§5.4](5-sources.md#54-corrections-of-record) are those lists, and a part's own corrections outrank
anything remembered about it.

*Each part states what is not established*, and names the single observation that would refute each
weight-bearing claim. Where a claim is an absence of evidence rather than evidence of absence, it
says so.

*Secret extraction is out of scope as a procedure*, per [part 1
§1.3](1-protocol.md#13-scope-and-conventions). These parts reconstruct mechanisms, formats and
acceptance relations so that the simulation is faithful and the detection advice correct; they
reproduce no private key material and no route-operative constant.

*Absolute dates are avoided.* Durations, spans and intervals carry the meaning and remain stable;
where precision matters, the linked artifact carries its own timestamp.

*Sources are linked rather than mirrored*, with the exception of the two field records in the
appendices. Section [part 5 §1.3](5-sources.md#13-archival-state) states the consequence and the
drift already observed.
