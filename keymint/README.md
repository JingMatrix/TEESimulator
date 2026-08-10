# keymint

The Android 12+ interceptor. It runs as a shared library injected into `keystore2`
and steers KeyMint transactions to an in-process software KeyMint backed by the
keybox, while leaving every other key on the real hardware.

On Android 12 and newer, `keystore2` doesn't hold KeyMint in-process — it talks to a
KeyMint HAL over Binder. That's the seam we splice into.

## Interception point

The obvious move would be to hand `keystore2` a different binder when it resolves
KeyMint. Too late: `keystore2` resolves the KeyMint HAL once at boot and caches the
binder for the life of the process (see [`get_keymint_device` in keystore2's `globals.rs`](https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/globals.rs),
which memoizes each connection in a `LazyLock` device map), and it does that *before* we're injected. There
is no resolution call left to intercept.

So we intercept the traffic instead. [`keymint_hook.cpp`](keymint_hook.cpp) PLT-hooks
`AIBinder_transact` — the one NDK function every outbound Binder call funnels
through. `HookedTransact` inspects each call and, when it's a KeyMint request we care
about, re-dispatches it to a local binder we own. Everything else calls
`real_transact` (the saved original) and is none the wiser.

Two tests gate a call. `IsHandled(code)` matches the transaction codes we simulate —
`3` generateKey, `4` importKey, `5` importWrappedKey, `6` upgradeKey, `7` deleteKey,
`10` begin, `13` convertStorageKeyToEphemeral, `14` getKeyCharacteristics. (These are
the [AIDL method ordinals](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/IKeyMintDevice.aidl),
matching the method declaration order in `IKeyMintDevice.aidl`; the AIDL compiler numbers methods from `1` after the
reserved metadata slots.) `IsKeyMintProxy(binder)` confirms the target is actually
the KeyMint proxy and not some other service sharing the `AIBinder_transact` call
site: it checks `AIBinder_isRemote` and compares the binder's class descriptor
against `IKeyMintDevice::descriptor`. The descriptor is the interface's fully-qualified
name string, stamped on every binder of that type, so it's a reliable identity check.

## Re-dispatching the transaction

We cannot take `keystore2`'s parcel and feed it to our own local binder.
`AIBinder_transact` rejects a parcel that wasn't created by `AIBinder_prepareTransaction`
for *that specific* target binder — the parcel carries a header bound to its intended
recipient.

That header is the interface token. Every AIDL transaction parcel begins with a fixed
preamble (a strict-mode policy word, then the interface descriptor string) that the
receiving stub reads back and validates before touching the payload (written by
[`Parcel::writeInterfaceToken`, checked by `Parcel::enforceInterface`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/libs/binder/Parcel.cpp)). `prepareTransaction`
writes this preamble; the arguments are marshalled after it. Two parcels prepared for
two binders of the *same* interface get byte-identical headers, only the payload
differs.

`Redirect` exploits that. It calls `AIBinder_prepareTransaction(local, &my_in)` to get
a fresh parcel already carrying the correct header for our local device, then measures
that header's length with `AParcel_getDataSize(my_in)` before writing anything else —
call it `hdr`. It reads the incoming parcel's full length as `total`, and copies the
payload across with [`AParcel_appendFrom`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/libs/binder/ndk/parcel.cpp):

```
AParcel_appendFrom(*in, my_in, hdr, total - hdr)
```

That copies `keystore2`'s request bytes starting at offset `hdr` (skipping its header,
which is identical to ours) for the remaining `total - hdr` bytes, appending them right
after our header. The result is a valid parcel for `local` holding the original
arguments. We dispatch it with `real_transact(local, code, &my_in, out, flags)`.

One ownership detail: `AIBinder_transact` takes ownership of the input parcel and frees
it (see [ibinder.cpp](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/libs/binder/ndk/ibinder.cpp),
where the input parcel is wrapped in an `AutoParcelDestroyer`). Our hook stands in for that call, so callers still expect their `*in` to be consumed.
`real_transact` frees `my_in`; we then `AParcel_delete(*in)` and null it ourselves to
honor the same contract. Skip that and a parcel leaks per KeyMint call.

If anything in the setup fails — `prepareTransaction`, a short parcel, `appendFrom` — we
fall back to `real_transact(proxy, …)` on the original binder, so a redirect that can't
be built degrades to normal behavior rather than breaking the call.

## Simulate or forward

[`keymint_router.cpp`](keymint_router.cpp) defines the local binder, `TeesimKeyMintDevice`, a
`BnKeyMintDevice` that also holds a `shared_ptr<IKeyMintDevice>` to the *real* HAL
(reconstructed from the cached proxy binder via `IKeyMintDevice::fromBinder`). It's
created lazily per proxy and cached in `g_local_for_proxy`.

Being a `Bn…` server means the generated AIDL stub unmarshals the parcel we handed it
into typed C++ arguments and calls the matching method — `generateKey`, `begin`, and so
on. We never parse raw parcels here; we work with `KeyParameter`, `KeyCreationResult`,
`BeginResult`. That's the whole reason we build the AIDL: the `Bn` base classes do the
marshalling, so the router is ordinary typed C++.

Each method decides for itself whether to simulate or forward:

- **Creation** (`generateKey`, `importKey`) acts only for an app assigned to a profile.
  `ProfileForRequest` scans the key parameters for `ATTESTATION_APPLICATION_ID` and matches
  its value against each profile's package names; a request with no attestation app id is
  never a target — an app not asking for attestation has no reason to be handled — and
  non-targets forward to the real HAL untouched. For a target, the profile's mode decides
  *how* (see [Patch and generation modes](#patch-and-generation-modes)).
- **Operations on an existing key** (`begin`, `deleteKey`, `upgradeKey`,
  `getKeyCharacteristics`) route by the blob. `IsOurs(keyBlob)` calls
  `teesim_km_is_marked`: keys the TA mints carry a blob prefix, so later operations on
  them come back to us, while real TEE blobs fail the check and forward. This is what
  keeps a simulated key working end-to-end (generate → begin → update → finish) without
  us having to track handles across calls.
- **Everything else** (`addRngEntropy`, `deviceLocked`, root-of-trust calls,
  `importWrappedKey`, `convertStorageKeyToEphemeral`, …) forwards. Note that a few of
  these are in `IsHandled` and so pass through the local device, but the local device
  just relays them to the real HAL; they're intercepted for uniformity, not simulated.

The method bodies translate between the AIDL types and the TA's flat C ABI
([`teesim_km.h`](../rust/teesim-km/include/teesim_km.h)): `ToKm`/`FromKm` convert a `KeyParameter` to/from a `KmParam`, using the
tag's top nibble (`kTagBool`, `kTagBytes`, `kTagUlong`, …) to pick the active union
member. `TeesimKeyMintOperation` wraps a TA operation handle and aborts it in the
destructor if `finish` never ran, so a dropped operation doesn't leak state in the TA.

### Patch and generation modes

A target key is created one of two ways, chosen per profile:

- **Generation** mints the whole key in the TA and keybox-signs a fresh attestation. The
  key never touches the real hardware; `IsOurs` later routes its operations back to us. This
  is the fallback whenever the real hardware can't be used.
- **Patch** (the default, fewer detection points) forwards `generateKey` to the real HAL, so
  the key is genuinely hardware-backed and its attestation carries authentic KeyMint content
  (real version, real tee-enforced authorizations). We keep that **real key blob** unchanged
  — later operations forward to the real HAL — and only **re-sign the attestation leaf** under
  the keybox with the root of trust patched to locked/Verified (`teesim_km_patch_attestation`,
  implemented in [`resign.rs`](../rust/teesim-km/src/resign.rs)). Patch needs working hardware
  at the request's level; a level whose hardware can't attest falls back to generation.

`PatchAttest` is the forward-plus-re-sign path; if the real HAL declines or returns no
attestation, it falls back to `Simulate` (generation) so a target key is always produced.

The same re-sign is exposed to the daemon as `teesim_cfg_resign` (see [control.h](../common/control.h)):
after a config push commits, the daemon re-attests keys that already existed before their app was
covered by handing each one's real leaf back over the `@teesim` channel and writing the returned,
keybox-rooted chain into the keystore. The re-sign is identical to a fresh patch — it keeps the real
key blob and only re-roots the certificate.

Attestation keys need special handling — a spoofed leaf is only convincing if the key that signed
it is also ours — as does StrongBox:

- **Creating an attestation key** (`ATTEST_KEY` purpose) is always minted in the TA
  (`IsAttestKeyRequest` → `Simulate`, ignoring any attest key keystore2 injected), so we hold its
  private key and can patch the root of trust of every leaf it later signs. An app usually creates
  its attest key *unattested* (no challenge, no app id), so it is routed to its profile by caller
  uid (`ProfileForRequest`'s uid fallback) rather than by name.
- **Denying remote provisioning.** On TrustedEnvironment, keystore2 resolves a real,
  remote-provisioned (RKP) key to attest a target app's new attest key and appends that key's
  Google-rooted chain — which the app can read straight off the `generateKey` reply, too late for
  any later fix. The hook fails keystore2's own outbound `IRemoteProvisioning.getRegistration`
  transact for a target uid, so on a hybrid device keystore2 falls back to *no* attest key and
  appends nothing, leaving the TA's keybox-rooted chain intact. It is scoped to target uids
  (`teesim_is_target_uid`, and the resolution runs on the app's binder thread so `getCallingUid`
  is the app's) and gated on `remote_provisioning.tee.rkp_only`, which is only *read*, never
  written — a global property change would be an obvious detection point.
- **A foreign attest key on a leaf** — one an app made before we covered it — is forwarded to the
  real HAL (its leaf keeps the real root of trust). The durable fix is that attest keys are now
  ours, so once regenerated the app takes the "ours" path; the startup purge deletes any
  pre-existing foreign attest key to force that regeneration.
- **StrongBox.** keystore2 resolves separate TEE (`/default`) and StrongBox (`/strongbox`)
  KeyMint proxies; both are hooked, each wrapped by a local device reporting its real level.
  A device with a real TrustedEnvironment always *offers* StrongBox, but an unlocked dev unit
  may have a broken StrongBox that can't attest — `g_strongbox_ok` (harvested) gates patch at
  the StrongBox level, forcing generation there when it's broken.

### Per-level attestation identity

The record's security level and version must match the HAL the request came through: a StrongBox
key claims StrongBox and that HAL's version, a TEE key the TEE's. One TA serves both proxies, so
before each creation the router passes the proxy's level to the TA, which overrides
`hw_info.security_level` and the raw `attestation_version` for that one request
(`override_attestation_identity`) and restores them after. The versions are harvested from throwaway
attested keys at each level and carried in the config — or fabricated (TrustedEnvironment and the
OS-appropriate version) when the device has no working hardware attestation; the `keyMintVersion` is
then derived from `attestationVersion` in the TA (Keymaster 4.0 is attestation 3 / keymaster 4, 4.1 is
4 / 41; KeyMint versions are equal). A broken StrongBox reuses the TEE version. Patch mode gets this
for free — it re-signs the real leaf, whose version fields are
already the hardware's.

### Recursion guard

Forwarding to the real HAL calls `real_->generateKey(…)` etc., which issues an outbound
Binder call — back through `AIBinder_transact`, back into our hook. Left alone that's
infinite recursion. A `thread_local bool tls_forwarding` breaks it: `ForwardGuard` sets
it (via `teesim_hook_set_forwarding`) around every call into the real HAL, and
`HookedTransact` bails to `real_transact` immediately when it's set. Thread-local, not
global, because unrelated KeyMint traffic on other threads must still be intercepted
while one thread is mid-forward.

## Files

- [`keymint_hook.cpp`](keymint_hook.cpp) — the `AIBinder_transact` hook, the KeyMint redirect, the
  remote-provisioning denial for target apps (`IsRkpProvisioning` / `RkpOnlyTee`), and
  `teesim_hook_install`,
  which uses LSPlt to patch the caller's PLT slot for the symbol. It scans `/proc/self/maps`
  and probes only the main executable first — the binder client that issues the KeyMint call
  is linked into it, so that is where `AIBinder_transact` is imported — which avoids LSPlt
  logging a "symbol not found" for every unrelated library. Only if the executable turns out
  not to import it does it widen to a full ELF scan, so coverage is never lost. Either way it
  registers on ELF mappings only (the main executable and `.so` files); feed LSPlt a non-ELF
  mapping (dex, oat, font, apk) and its ELF parser faults.
- [`keymint_router.cpp`](keymint_router.cpp) — `TeesimKeyMintDevice` / `TeesimKeyMintOperation`, the
  patch/generation/forward logic (`PatchAttest`, `Simulate`, `IsAttestKeyRequest`), the
  parcel↔TA translation, per-profile routing (`ProfileForRequest`, by app id then caller uid,
  carrying each profile's mode), `teesim_is_target_uid` for the RKP denial, and the
  config-staging C entry points (`teesim_cfg_begin`, `teesim_cfg_add_profile`,
  `teesim_cfg_commit`) that build a new profile set and swap it in atomically, plus
  `teesim_router_new_device`.
- [`keymint_entry.cpp`](keymint_entry.cpp) — `entry()`, what the injector calls. It reads no
  files: it starts the `@teesim` control server and installs the hook in a no-op state, and
  the daemon then connects and pushes the resolved profiles (keyboxes included). Until a
  profile is pushed nothing is simulated — a keystore without configuration is a no-op,
  not a hazard.
- [`exports.map`](exports.map) — exposes only `entry`; everything else is hidden so our symbols can't
  collide with `keystore2`'s.
- [`libcrypto.syms`](libcrypto.syms) — the BoringSSL symbols the TA needs. In the default build there's no
  bundled crypto: CMake generates a stub `libcrypto.so` (empty functions with the right
  SONAME) from this list purely to satisfy the linker, and at runtime `keystore2`'s own
  `libcrypto` provides the real implementations. The list must stay in sync with what the
  Rust TA actually calls.

## Integration

The injector (`../injector`) loads this library into `keystore2` and calls `entry()`.
The device methods call the Rust TA in `../rust/teesim-km` over the [`teesim_km.h`](../rust/teesim-km/include/teesim_km.h) C ABI;
the TA does the crypto and signs attestations with the keybox. The KeyMint AIDL and the
`frameworks/native` binder headers are built from the `third_party` submodules at build
time (see the top-level `CMakeLists.txt`). The Android 10/11 sibling, `../keystore`,
does the same job for the legacy `keystore` daemon, which apps reach over a different
Binder path.
