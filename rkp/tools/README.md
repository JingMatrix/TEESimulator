# `teesim-attest` — attestation material toolkit

Inspect, verify and unpack the material TEESimulator signs with: `keybox.xml` files, the
secure-world containers a keybox is extracted from, and RKP certificate requests.

Every check here implements an acceptance relation from [`../3-detection.md`](../3-detection.md) §1,
and every threshold is a number measured in [`../4-measurements.md`](../4-measurements.md) §2–§4 or
in the control-plane measurements of [`../3-detection.md`](../3-detection.md) §2. The tools exist so
those documents' conclusions can be run rather than read: `teesim-attest baseline` prints each
constant with its provenance.

```
tools/
  teesim-attest            the CLI; all subcommands
  teesim_attest/
    cbor.py                strict CBOR reader + canonical encoder, order-violation checker
    provisioning.py        OID 1.3.6.1.4.1.11129.2.1.30, with the measured stock baseline
    keybox.py              keybox.xml parsing and the three-layer acceptance proof
    plaintext.py           the two secure-world container formats
    csr.py                 RKP v3 AuthenticatedRequest verification, DICE chain walk
    revocation.py          Google's status list, with both serial encodings
  tests/
    make_fixtures.py       regenerates the synthetic fixtures
    test_toolkit.py        34 tests, no network, no device
    fixtures/              synthetic keyboxes, containers and CSRs
```

## Requirements

Python 3.11+ and [`cryptography`](https://pypi.org/project/cryptography/). Nothing else — the
[CBOR](https://www.rfc-editor.org/rfc/rfc8949) reader is deliberately in-tree, both to avoid a
dependency and because checking canonical map order needs each key's *encoded* bytes, which a
general-purpose decoder discards.

## Commands

### `inspect` — describe a keybox

```console
$ ./tools/teesim-attest inspect rkp-keybox-sample-b.xml
rkp-keybox-sample-b.xml
  shape      rkp-provisioned (EC only)
  DeviceID   Xiaomi-d5918872d745
  key ecdsa (256-bit), 4 certificate(s)
    fact private key SPKI == leaf certificate SPKI
    FAIL certificate 0 expired 33 day(s) ago (2026-09-14)
    [0] leaf         sig ok        expired 33d ago      CN=344dc9148ccb0cc561b4983543e9678b, O=TEE
      provisioning extension 1.3.6.1.4.1.11129.2.1.30  oem=Xiaomi
        info no provisioning verdict in this certificate (no key 5 record)
        warn certs_issued = 512, 64x the stock baseline of 8 (stock Redmi K70E (duchamp),
             measured before any patching) — Google's own abuse signal, readable by any relying party
    [1] intermediate sig ok        11d left             CN=Droid CA3, O=Google LLC
    [2] intermediate sig ok        845d left            CN=Droid CA2, O=Google LLC
    [3] root         sig ok        3193d left           CN=Key Attestation CA1, O=Google LLC, OU=Android, C=US
```

`shape` is read from the keybox itself: RKP issuance is
[P-256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) only, so an
EC-only keybox is RKP-provisioned and one carrying both algorithms is a factory keybox. Leaf
lifetime corroborates — about two weeks for RKP, about ten years for a factory batch key.

`-v` adds each certificate's serial, basic constraints and
[SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

### `verify` — acceptance, with an exit status

Exits 1 if the keybox would not be accepted, so it can gate a build or a config change.

```console
$ ./tools/teesim-attest verify tools/tests/fixtures/keybox-rkp-not-approved.xml
  ...
    FAIL certificate 0 carries provisioning status NOT_APPROVED, NOT_APPROVED
  => NOT ACCEPTED (layers 1 and 2; layer 3 needs a device, see below)
$ echo $?
1
```

What it checks, and why each one is separate:

| Check | What it catches | What it does not |
|---|---|---|
| private key SPKI == leaf SPKI | a random key pair, a misaligned parse, the wrong file | nothing about the chain |
| each certificate verified against its parent's public key | a substituted certificate | a chain that stops before a root |
| subject/issuer name linkage and duplicate detection | a misordered or reversed chain | a *substituted* chain — name linkage is not a signature check, which is why both run |
| expiry, per certificate | a keybox that is simply dead | — |
| provisioning status, with unknown extension fields preserved | a `NOT_APPROVED` keybox that passes every cryptographic check | — |
| declared counts vs. actual | hand-edited files that some parsers trust over their own content | — |

*Layer 3 is not implemented and cannot be.* The third layer of the acceptance proof is: trigger a
fresh attestation through Android KeyStore on the device and compare the resulting leaf against the
keybox's own certificates. It is the only layer that binds the material to the handset in front of
you, and it is the one usually skipped. On a device with the module installed, the WebUI's keybox
inspector and stored-key view cover it.

### `unpack` — parse a secure-world container

Two formats, both length-prefixed binary rather than XML:

```console
$ ./tools/teesim-attest unpack payload.bin --descriptor descriptor.bin -o out/
  fact descriptor 168 B, payload 8578 B (both describe this sample, not the format)
  fact magic 0x12345678 OK
  fact descriptor trailing MD5 matches the payload (635c04aa3590d2cbe7ce3dfa79c3e3c7)
  fact length prefixes are 4-byte little-endian
  fact version/keybox number = 1
  fact entry 0 (ecdsa): private DER 121 B, 3 certificate(s)
  fact entry 1 (rsa): private DER 1769 B, 3 certificate(s)
```

Omit `--descriptor` for a bare plaintext buffer.

The reason this is a tool rather than a few lines of slicing: *fixed offsets appear to work and
produce [DER](https://www.itu.int/rec/T-REC-X.690) fragments that look legitimate.* Certificate
lengths change between versions, chain lengths change, and the tail of the buffer can hold uncopied
input — one recorded sample leaves exactly 92 bytes of it. So a length prefix is accepted only when
the bytes it points at parse as a DER SEQUENCE *whose own internal length agrees with the prefix*. A
wrong interpretation is rejected instead of yielding plausible garbage, and the prefix width and
endianness are detected once and then held fixed.

Leftover bytes are classified rather than ignored: a small tail is reported as copy residue, while a
large one — or one that itself starts with a DER SEQUENCE — is reported as a parse that stopped
early, which is what a truncated buffer looks like. The two documented sample sizes (a 168-byte
descriptor, an 8578-byte payload) are *reported and not required*: they describe one round, not the
format.

### `verify-csr` — acceptance on an RKP v3 request

```console
$ ./tools/teesim-attest verify-csr --unwrap response.cbor
  fact unwrapped the TA response envelope {61: bstr}
  => OK
```

Verifies `AuthenticatedRequest = [1, UdsCerts, DiceCertChain, SignedData]`: walks the
[DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/) chain from the UDS
public key, verifying each entry's [COSE_Sign1](https://www.rfc-editor.org/rfc/rfc9052#section-4)
with the key the previous entry carried, then checks that `SignedData` verifies under the key the
last entry carried. That final link is what ties the request to the device's measured boot, and it
is the only reason a backend trusts anything in the request. Then `CsrPayload = [3, "keymint",
DeviceInfo, keysToSign]`, the 14 permitted `DeviceInfo` fields with their value domains and
field-count rules, and every `keysToSign` entry as an ES256 P-256
[COSE_Key](https://www.rfc-editor.org/rfc/rfc9052#section-7).

Four of its findings exist because of recorded field failures rather than because the
[CDDL](https://www.rfc-editor.org/rfc/rfc8610) demands them, and each says so in its message:

- *non-[canonical CBOR](https://www.rfc-editor.org/rfc/rfc8949#section-4.2), anywhere.* A map whose
  keys are out of RFC 8949 §4.2.1 order, or a
field at the wrong level, is enough for the backend to answer 400.
- *`keysToSign` as a bare map* rather than an array — the recorded cause of the backend
answering *"Expected an array, got MAP"*.
- *a degenerate DICE chain*: exactly two elements where the UDS public key equals the
leaf's subject public key, so the chain is self-signed and carries no boot measurements. It
satisfies the structural minimum and is a recorded first-line cause of 444 DeviceNotRegistered.
Reported as a warning, not a failure — it is valid, just not registrable.
- *the identity key appearing in `keysToSign`.* The identity key proves the request came
from the device; the key being certified must be a different, freshly generated one. Requiring them
to be equal judges a correct result a failure.

`--unwrap` handles the `{61: bstr}` envelope a TA returns. Posting that envelope to the backend
instead of its contents produces the same 400 as the bare-map mistake above, which is why the error
message for a map input names it explicitly.

### `revocation` — look up serials, in both encodings

```console
$ ./tools/teesim-attest revocation rkp-keybox-sample-a.xml rkp-keybox-sample-b.xml
  fact 1761 entries from https://android.googleapis.com/attestation/status
  fact 780 contain a-f (unambiguously hex)
  fact 981 are digits only (hex-valid, but read as decimal by Google's own tooling ...)
  0 of 8 serial(s) revoked
    matched as hex: 0
    matched as decimal: 0
```

*Every lookup tests both `format(serial, 'x')` and `str(serial)`.* The schema says the key is the
serial in lowercase hex, and Google's own reference verifier does
`revokedSerials.contains(cert.serialNumber.toString(16))` — but a measured majority of live entries
contain no `a`–`f` digit and read as decimal. They are *syntactically* valid lowercase hex, which is
why nothing rejects them and why the failure is silent. A verifier using hex only misses roughly
half the revoked population, most likely including the older factory-keybox entries that matter
most. The per-form counts are printed for the reason [`../3-detection.md`](../3-detection.md) §2.3
gives: a decimal-match counter stuck at zero over a large sample means that population is not being
checked at all.

Exits 1 if anything is revoked. `--offline` uses only the cache at
`~/.cache/teesim-attest/attestation-status.json`; a live fetch refreshes it.

### `baseline` — the constants, with provenance

Prints every measured threshold the tools gate on and where each came from. Run it before quoting a
number from the tools' output.

## Tests

```console
$ python3 tools/tests/test_toolkit.py
Ran 34 tests in 0.046s
OK
```

No network, no device. Everything runs against the synthetic fixtures in `tests/fixtures/` — freshly
generated keys, self-signed roots and containers built to the recorded shapes, so no real keybox or
device material is involved and the fixtures are safe to commit. The two real sample keyboxes of
[`../4-measurements.md`](../4-measurements.md) §1.2 are checked too when a copy is available — they
are not carried in this repository, because they hold live private keys — and then only for facts
that are stable: shape, chain length, private-key correspondence and the extension's contents, never
their expiry. Point `TEESIM_ATTEST_SAMPLES` at a directory holding `rkp-keybox-sample-a.xml` and
`rkp-keybox-sample-b.xml` to enable those checks; without it they skip and the suite still reports
success.

Regenerate the fixtures with `python3 tools/tests/make_fixtures.py` after changing a format.

## What is deliberately not here

The field routes reconstructed in [`../2-mechanisms.md`](../2-mechanisms.md) §3–§6 come with tooling
of their own: TA and TEE-image patch builders, caller-gate and verify-branch binary patchers,
secure-world seed-capture probes, a client that sends raw commands to a
[KeyMint](https://source.android.com/docs/security/features/keystore) TA, and a pipeline that mints
Google-signed chains from a captured identity. *None of that is ported here, and it is a deliberate
line, not an oversight.*

Those tools modify a boot chain, relax a loader's security decision, or produce attestation material
for a device identity — they are device-exploitation and key-minting tools, and their value does not
depend on this repository. The documents keep the mechanisms, offsets, container formats and
acceptance relations, because that is what makes a simulation faithful and a detection rule correct;
the toolkit keeps the half that parses and verifies. That split matches the series' standing scope
note: the simulator manufactures its own keys and never needs a real one.

What *is* ported is every tool whose job is to read, parse, check or classify — which is also, in
practice, most of what the field records spend their time on. The acceptance discipline in those
records is the transferable part: three independent layers for an extracted keybox, a same-round
identity binding for a minted chain, length-prefix-plus-DER parsing for a container, and an explicit
provisioning-status gate that no amount of valid signatures can override.
