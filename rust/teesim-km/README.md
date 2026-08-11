# teesim-km

The crypto engine. This is the trusted application — the Rust static library that
actually generates keys, runs cryptographic operations, and signs attestation
certificates. Both C++ interceptors (`keymint/` on Android 12+, `keystore/` on
Android 10/11) are plumbing around it: they decode an intercepted KeyMint call,
hand the pieces to this library, and encode whatever it returns back into the reply.
There is one engine and two front ends.

What makes the certificates hold up is that this is not a hand-rolled attestation
faker. It embeds AOSP's own reference KeyMint TA, [`kmr-ta`](https://cs.android.com/android/platform/superproject/main/+/main:system/keymint/ta/src/lib.rs) — the software KeyMint the emulator itself runs — and drives the real KeyMint state machine:
generateKey, begin/update/finish, key characteristics, the works. The attestation
extension, the key-usage authorizations, the tag ordering in the record — all of it
is produced by the same code a real TEE runs, so it is internally consistent by
construction rather than by our getting a hundred fields right by hand. What we change is
narrow: the crypto backend underneath it, where the attestation signature comes from, the
per-request security level and version, and — in patch mode — re-signing a real hardware leaf
rather than minting one.

## `kmr-ta` wiring

`KeyMintTa::new` (see `lib.rs::Ta::new_ex`) takes four things: `HardwareInfo`, an
`RpcInfo`, a `crypto::Implementation`, and a device `Implementation`. The daemon resolves
a profile — keybox, patch/OS levels, and optional device IDs — together with the harvested
security level and device-wide boot info into a `TaConfig`, and the interceptor hands it to `Ta::new_ex`;
`Ta::new` is a thin wrapper that supplies historical defaults for the pre-configuration
state. The device `Implementation` is a bag of trait objects — `kmr-ta` calls back into
these for anything that a real TA would get from its secure environment. We supply:

- `keys: device::Keys` — `RetrieveKeyMaterial`. The root key material (below).
- `sign_info: attest::CertSignInfo` — [`RetrieveCertSigningInfo`](https://cs.android.com/android/platform/superproject/main/+/main:system/keymint/ta/src/device.rs;l=112). The attestation
  signing keys, loaded from the profile's keybox.
- `attest_ids` — `RetrieveAttestationIds`. `Some(device::AttestIds(...))` when the
  profile carries device-identity values, so ID attestation vouches for them; `None`
  otherwise, which declines ID attestation.
- `rpc: device::NoRpc` — `RetrieveRpcArtifacts`. Stubbed; RKP is never routed here.
- `bootloader: BootloaderDone`, `tup: TrustedPresenceUnsupported` — stock kmr-ta
  markers meaning "bootloader has finished" and "no trusted user presence."
- `sdd_mgr: None`, `sk_wrapper: None`, `legacy_key: None` — no secure-deletion store
  (so rollback-resistant keys are declined), no secure key wrapper, no legacy blob format.

The crypto `Implementation` (`lib.rs::crypto_impls`) is every primitive wired to the
BoringSSL backend — `BoringAes`, `BoringRsa`, `BoringEc`, `BoringHmac`, and so on —
plus `device::Clock`, a `MonotonicClock` backed by `CLOCK_BOOTTIME`.

## Stable key-encryption keys

KeyMint does not store key blobs in the clear. It wraps each one under a
key-encryption key that it [*derives*](https://cs.android.com/android/platform/superproject/main/+/main:system/keymint/common/src/keyblob.rs), and the derivation inputs are the root key
material and the verified-boot root of trust. keystore2 persists those wrapped blobs
in its SQLite database and hands them back on later boots for begin/finish.

If a KEK-derivation input changes between the boot that created a blob and the boot
that uses it, the derived KEK is different and the blob **fails to decrypt** — every
key a targeted app made in a previous session becomes permanently unusable, with no
error that points at the cause. So both inputs are held stable:

- The root key material is constant: `device::Keys::root_kek` returns a fixed all-zero
  HMAC key, `kak` a fixed all-zero AES-256 key, and `unique_id_hbk` a fixed literal.
  They are the same on every device and must never be made random or device-derived.
- The verified-boot root of trust is device-wide and **frozen**. `Ta::new_ex` passes the
  `verified_boot_key`, `verified_boot_hash`, `device_boot_locked`, and
  `verified_boot_state` from the `TaConfig` to `set_boot_info`; the daemon harvests these
  from the device's real attestation once and never rewrites them. They are therefore the
  same across reboots and identical for every profile, which is what makes a blob
  cross-decryptable no matter which profile's TA created it.

Because the root of trust is authentic and frozen rather than zeroed, the attested value
matches a real locked, verified device *and* the KEK stays put. The remaining record
fields — `boot_patchlevel` on `set_boot_info`, and the OS and patch levels on
`set_hal_info` — also come from the `TaConfig` but do not feed the KEK, so a profile can
carry its own patch levels without orphaning stored blobs. Before the daemon pushes a
profile, `Ta::new`'s defaults stand in a zeroed root of trust as a placeholder.

## Keybox

[`attest.rs`](src/attest.rs) parses the `keybox.xml` (via `roxmltree`) into two `AlgoInfo`s: the
`<Key algorithm="rsa">` and `<Key algorithm="ecdsa">` batch signing keys, each a
PEM-decoded private key plus its full certificate chain. `CertSignInfo` implements
`RetrieveCertSigningInfo`, so when `kmr-ta` needs to sign an attestation it asks for
the RSA or EC key by `algo_hint` and gets the batch key and chain back. There is no
built-in fallback key: if the keybox is missing, malformed, lacks either algorithm,
or a chain has fewer than two certs, `Ta::new` returns `Err` and the interceptor
declines to install its hook (a misconfigured module becomes a no-op, not a hazard).
Two field facts baked in: the EC batch key is assumed NIST **P-256** (what real
keyboxes ship), and each key must carry at least a leaf plus a root.

## Patch-mode re-signing

Generation mints a key and its attestation entirely here. **Patch mode** instead keeps a real
hardware key and only re-roots its attestation: the interceptor forwards `generateKey` to the
real HAL, then hands the real leaf to [`resign.rs`](src/resign.rs)
(`teesim_km_patch_attestation`), which re-signs it under the keybox with the root of trust
patched to the profile's locked/Verified value and returns `[patched leaf, keybox chain]`. The
real key blob is kept untouched, so the key stays hardware-backed and its authentic KeyMint
attestation content (challenge, versions, tee-enforced authorizations) survives — only the root
of trust and the signing root change.

`kmr-ta`'s certificate assembly is private, so this re-implements just the surgery it needs:
`x509-cert` parses and rebuilds the leaf (new issuer, keybox signature algorithm, patched
extension), a small hand-written DER splice replaces the `RootOfTrust` (which sits under a
high-number `[704]` context tag `x509-cert` can't address), and the signature is produced by the
same `BoringEc`/`BoringRsa` backend and keybox key generation uses. The target root of trust is
built once in `Ta::new_ex` from the same boot info generation feeds `kmr-ta`, so both modes
report an identical one. `Ta` therefore retains a clone of `CertSignInfo` (the batch key
`kmr-ta` also owns but doesn't expose) alongside the precomputed `patch_rot`.

## Per-request attestation identity

One `Ta` serves both the TEE and StrongBox proxies, so the record's security level and version are
set per request rather than at construction. Each creation passes the requesting HAL's level;
`ops.rs::override_attestation_identity` sets `hw_info.security_level` and a raw `attestation_version`
for that one call and restores them after. The version is stored raw (2/3/4/100/…) so a pre-KeyMint
device's Keymaster versions survive, and `cert.rs` derives the matching `keyMintVersion` from it
(Keymaster 4.0 is attestation 3 / keymaster 4, 4.1 is 4 / 41; KeyMint versions are equal). The level
and version come from the harvest, or are fabricated (TrustedEnvironment and the OS-appropriate
version) when the device produced no working hardware attestation. The `security_level` /
`attestation_version` getters and setters this needs are added to `kmr-ta` by
[`patches/kmr-ta-seclevel.patch`](../patches/kmr-ta-seclevel.patch), applied the same idempotent way
as the BoringSSL patch below.

## BoringSSL backend

The crypto backend is `kmr-crypto-boring`, the reference backend, but it normally
builds under Soong against `bssl-sys`. We build under Cargo against `openssl-sys`,
so [`build.sh`](../build.sh) applies [`patches/kmr-crypto-boring.patch`](../patches/kmr-crypto-boring.patch) to the submodule working
tree (idempotently — it reverse-checks before applying) to drop the `#[cfg(soong)]`
paths and the `i32` key-length narrowing that BoringSSL's `openssl-sys` binding
doesn't need. `openssl-sys` with the `bindgen` feature generates the FFI straight
from BoringSSL's headers at build time, which is why the build needs only
`$BORINGSSL/include`, no `libcrypto` of any ABI.

The output is `libteesim_km.a` — a **staticlib**, nothing more. It records a link
directive for `libcrypto` but never links one. Resolving `libcrypto` is the
interceptor's job, and it differs by platform:

- **keystore2 (Android 12+):** `libcrypto.so` already lives in the host process, so
  the interceptor links only a stub `.so` with the right SONAME and lets the host's
  real BoringSSL satisfy the symbols at load time.
- **Android 10/11:** the platform's `libcrypto` is too old to have the functions
  this backend calls, so the interceptor bundles a modern **static** BoringSSL into
  its own `.so` instead.

Build one ABI with [`rust/build.sh`](../build.sh) (`ABI=arm64-v8a API=34 ./build.sh` by default);
it drives `cargo ndk`.

## C ABI

The interceptors are C++; the TA is Rust; CBOR lives only on the Rust side. The
boundary ([`include/teesim_km.h`](include/teesim_km.h), implemented in [`ffi.rs`](src/ffi.rs) + [`capi.rs`](src/capi.rs)) is therefore
flat C with opaque handles, so the C++ never has to understand a `kmr_wire`
encoding:

- Handles it holds but can't inspect: `Ta` (the boxed TA), `TsCreationResult`
  (generate/import output), `TsBeginResult`, `TsCharacteristics`.
- `KmParam` — a KeyMint `KeyParameter` flattened to `{ tag, int_value, blob,
  blob_len }`. `teesim_km_tag_value_kind(tag)` returns a `KmValueKind` saying how
  `int_value` is represented (bool / bytes / signed or unsigned 32- or 64-bit), so
  C++ copies one union arm without knowing the tag catalog and both sides share one
  signed/unsigned/width table (it mirrors `kmr_wire`'s per-tag decoder — the source
  of the `USER_SECURE_ID` sign bug this replaced).
- Per-method entry points (`teesim_km_generate_key`, `teesim_km_begin`,
  `teesim_km_update`, `teesim_km_finish`, …), each returning `0` or a negative
  KeyMint error code, plus accessor functions to walk the result handles field by
  field. Output handles/buffers are written only on success and must be freed with
  their matching `teesim_km_free_*`.
- [`ffi.rs`](src/ffi.rs) also exposes `teesim_km_process`: feed it a raw serialized `kmr_wire`
  request and get the raw response, for any method without a dedicated shim.

**Every** entry point wraps its body in `catch_unwind`. Unwinding a Rust panic
across an `extern "C"` boundary is undefined behavior, and this code runs *inside*
keystore — a panic that escaped would take the daemon down. `catch_unwind` turns a
panic into a null handle or an error code instead. `teesim_km_init` also installs a
panic hook that logs to logcat under the `TEESimulator` tag.

## Wire format and tag numbers

`kmr_wire` is the CBOR request/response schema `kmr-ta` speaks. `Ta::process`
([`lib.rs`](src/lib.rs)) takes a serialized request and returns a serialized response;
`ops.rs::perform` builds those messages the way kmr-hal frames its channel — request
is `[opcode, req]`, reply is `[error_code, [[op_type, rsp]]]` — so any new
method must mirror that framing exactly or the response decode fails.

Translation between `KmParam` and `kmr_wire::KeyParam` (`capi.rs::to_keyparam` and
`owned_param`) is done through `kmr_wire`'s own `AsCborValue` codec, not by hand.
`to_keyparam` builds the CBOR `[tag, value]` pair and lets `KeyParam::from_cbor_value`
key off the tag to pick the value type; `owned_param` runs it back the other way.
That's the reason the numeric tag values in `KmParam` must equal KeyMint's — the
decoder dispatches on the tag, and a wrong number is silently the wrong type.

Key blobs get a routing marker so the interceptor can tell ours apart from the real
TEE's. `BLOB_MARKER` is `b"TEESIMkm\x00"`. [`ops.rs`](src/ops.rs) applies it to every blob the TA
hands out (`marked_result`, `upgrade_key`) and strips it before every blob goes back
in (`begin`, `delete_key`, `get_key_characteristics`, the attestation key). The
marker must not collide with km_compat's reserved prefixes (`pKMblob\0`,
`pKMblob\1`, `SoftKeyMintForV1Blob`); the interceptor checks a blob's prefix to
decide simulate-vs-forward, so a stored key made by us is still served by us on the
next boot.

## Files

- [`src/lib.rs`](src/lib.rs) — builds the `Ta`: crypto backend, device traits, fixed boot/HAL info;
  the blob marker and CBOR helpers.
- [`src/device.rs`](src/device.rs) — `RetrieveKeyMaterial` (fixed roots), the `CLOCK_BOOTTIME` clock,
  stubbed `RetrieveRpcArtifacts`.
- [`src/attest.rs`](src/attest.rs) — keybox parsing and `RetrieveCertSigningInfo`.
- [`src/ops.rs`](src/ops.rs) — one function per KeyMint method: build the `kmr_wire` request, run
  it, decode the typed response, apply/strip the marker; the per-request level/version override.
- [`src/resign.rs`](src/resign.rs) — patch mode: re-sign a real hardware attestation leaf under
  the keybox with a patched root of trust (`teesim_km_patch_attestation`).
- [`src/capi.rs`](src/capi.rs) — the per-method C ABI and the result handles/accessors.
- [`src/ffi.rs`](src/ffi.rs) — lifecycle (`init`/`destroy`), raw `process`, buffer free, marker
  check.
- [`include/teesim_km.h`](include/teesim_km.h) — the C header the interceptors compile against.
- [`../build.sh`](../build.sh) — `cargo ndk` build for one ABI, plus the BoringSSL patch.
