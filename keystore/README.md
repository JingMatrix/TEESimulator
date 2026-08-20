# keystore

The Android 10/11 interceptor. It runs as a shared library injected into the legacy
`keystore` daemon and answers a target app's key operations from an in-process software
Keymaster backed by the keybox, while forwarding every other caller to the real service.

Android 10 and 11 predate `keystore2`/KeyMint. Apps talk to the `keystore` daemon over its
`android.security.keystore` (`IKeystoreService`) Binder, and the daemon reaches a Keymaster
HAL beneath it. That app-facing service is the seam we splice into — not the HAL below it.

## Interception point

On this platform we intercept on the **server side**, inside the `keystore` daemon itself,
rather than swapping a binder the way the keymint interceptor does. Injected into `keystore`,
we PLT-hook `ioctl` on `libbinder.so` and watch the incoming `BR_TRANSACTION`s the driver
delivers. For a transaction whose target is the registered `keystore` binder we rewrite the
target handle to a local stub (transaction code `0xdeadbeef`); the stub hands the parcel to an
in-process handler that either answers it or reports "not mine", in which case the call is
replayed to the real service untouched. Hooking `ioctl` (not a service method) means we see
every transaction the daemon receives regardless of which `IKeystoreService` method it is.

Only ELF mappings are hooked, and only the one whose path ends in `/libbinder.so` — the driver
calls funnel through that single library, so there is nothing to gain from scanning the rest.

## Simulation

For a target app the key never touches the real Keymaster. The handler
([`keystore_router.cpp`](keystore_router.cpp)) generates the key pair itself and hands back its
public key; at `attestKey` it imports that key into the reference TA with the app's challenge, so
the TA issues a **keybox-signed** attestation over it. The same imported key backs the crypto
lifecycle — `begin`/`update`/`finish`/`abort` run against the TA operation — so the key is usable
for signing, not merely for attestation. Non-target callers are forwarded, so unrelated apps keep
using the real hardware.

Because the legacy `IKeystoreService` methods deliver their results by transacting **back** on a
callback binder passed in the request (the transaction's own reply is just a status), the handler
produces each result by calling that callback binder, mirroring what the real daemon would do.

The profile set (which apps to simulate, which keybox signs) is pushed from the control daemon
over the control socket; nothing here is read from disk.

## Files

- [`keystore_entry.cpp`](keystore_entry.cpp) — `entry()`, what the injector calls. It starts the
  control server, installs the `libbinder` `ioctl` hook, and registers the app-facing
  `android.security.keystore` service so its transactions reach `teesim_ks_handle`. Awaits the
  config push before simulating anything.
- [`binder_interceptor.cpp`](binder_interceptor.cpp) — the server-side machinery: the `ioctl`
  PLT hook, the `BR_TRANSACTION` watch, the target-to-stub rewrite, and the fall-through that
  replays a declined transaction to the real service.
- [`keystore_router.cpp`](keystore_router.cpp) — `teesim_ks_handle`, the per-method simulation
  (key generation, `attestKey`, the begin/update/finish/abort operation lifecycle) against the
  reference TA, plus the callback-binder result delivery and per-app routing.
- [`aosp/`](aosp) — the minimal vendored AOSP `libbinder`/`libbase`/`libutils` headers and stubs
  the interceptor compiles against; the device's real libraries resolve at runtime.

## Building

Built as part of the top-level Gradle graph into `libteesim_keystore.so`, shipped in the module
and injected by the daemon on Android 10/11. The keymint interceptor
([`../keymint`](../keymint)) is its Android 12+ counterpart, and both share the reference TA in
[`../rust/teesim-km`](../rust/teesim-km) and the control channel in `control.*`.
