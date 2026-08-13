# app

The privileged **control daemon** — the brain of the module. Everything that needs a real
Android framework (an attested key to harvest from, `PackageManager` to resolve uids, a
`Context` to reach keystore) lives here, in a Kotlin process launched by the module's
`service.sh` via `app_process`. The injected native interceptors stay pure crypto-and-routing
engines; this daemon owns the configuration, resolves it against the live device, injects the
interceptor, and pushes the resolved profiles over the `@teesim` control socket. It never sits
in the keystore hot path.

It builds to a single `classes.dex` (AGP), shipped in the module and run as:

```
app_process -Djava.class.path=$MODDIR/classes.dex $MODDIR --nice-name=teesim org.matrix.teesim.App $MODDIR
```

## Bootstrap

A bare `app_process` has no `Application`, no bound `Context`, no `AndroidKeyStore` provider —
so `App` builds just enough of the framework by hand, in the order the platform requires. It
waits for a core system service (`ServiceManager
.waitForService("package")`) so it doesn't race `system_server` at boot, then
`Looper.prepareMainLooper()`, `ActivityThread.systemMain()`, `getSystemContext()`, wraps that in
an `Application`, and sets `ActivityThread.mInitialApplication` so `KeyStore
.getApplicationContext()` works. It installs the R/S+ `AndroidKeyStore` provider and swaps
Android's stripped `BC` for the bundled full BouncyCastle (ASN.1 parsing). Only then does the
real work start.

The framework classes it calls are hidden or `@SystemApi`, so they can't be compiled against
the SDK directly. The sibling **`stub/`** module supplies compile-only stand-ins
(`ActivityThread`, `ContextImpl`, `ServiceManager`, `SystemProperties`, `IPackageManager`, the
two `AndroidKeyStoreProvider`s) with the right signatures; at runtime the device's real classes
resolve instead. `stub/` is `compileOnly` and never shipped.

## The pipeline

Once the framework is up, `App.main` wires the daemon and enters `Looper.loop()`:

1. **`Harvester`** generates a throwaway attested key and reads the leaf's KeyDescription
   extension (OID `1.3.6.1.4.1.11129.2.1.17`) to capture the device's real attestation
   parameters — verified-boot key/hash, patch levels, OS version, security levels, and (via
   `setDevicePropertiesAttestationIncluded`) the device-identity ids. It tries a
   device-properties attestation first, falls back to a plain one, and only reports a broken TEE
   if both fail. `verifiedBoot*` are frozen on first success (they seed KeyMint's
   key-encryption-key derivation, so a changed value would orphan stored keys). IMEI/MEID/serial,
   which device-properties attestation omits, are read straight from the platform — IMEI/MEID from the
   `IPhoneSubInfo` binder's legacy `getDeviceIdForPhone`/`getMeidForSubscriber` calls, and the serial
   from the `ro.serialno` property. The public `TelephonyManager.getImei()`/`Build.getSerial()` paths
   are deliberately avoided: they enforce a "calling package belongs to caller uid" check the root
   daemon (uid 0, no package) can never satisfy, whereas the legacy binder calls return the real values
   regardless of package. The record is cached to `harvested.json`, and each parsed field is logged.
2. **`ConfigStore`** parses, validates, and `FileObserver`-watches `config.json`; **`Resolver`**
   turns a validated config plus the frozen harvest, system properties, and the clock into the
   full-replace `config` message the native lib applies — resolving the profile's targets via
   **`Scope`**, the patch mini-language, and the harvested device ids and security level.

   **`Scope`** is the one place a profile's `apps[]` becomes the two wire arrays the native router
   matches on — `packages[]` (attestation package-name match, kept verbatim so a not-yet-installed
   name still matches once the app lands) and `uids[]` (caller-uid match, the effective set with no
   `-1`). An `apps[]` entry is a package name or an advanced `uid:N` token that targets a caller uid
   directly (for a shared-uid app or one whose package is unknown). Every
   entry is logged as it resolves (`Scope[<id>]: 'com.foo' -> uid 10123`, `-> NOT INSTALLED (dropped)`),
   and a uid below the app range (a `shell`/`system_server`-style uid) is flagged with a warning — the
   instrumentation that makes "which app is actually intercepted" answerable from the log.
3. **`Injector`** finds the keystore daemon's pid (`keystore2` on API ≥ 31, `keystore` on 10/11),
   runs the packaged `inject` binary to load the right interceptor, and re-injects whenever the
   pid changes; it confirms the library actually checked in over `@teesim` and warns otherwise
   (usually an SELinux denial on the abstract socket).
4. **`Control`** connects the `@teesim` abstract unix socket, checks peer credentials, and pushes
   the resolved config on start and on every change.
5. **`ReAttest`** runs after each push commits (on the lib's `ack`) to re-root keys that already
   existed before their app was covered — a key made earlier carries the real hardware attestation
   (an unlocked root of trust). For each target app it reads that uid's stored attestation leaves
   from the keystore2 database (**`KeystoreDb.attestedKeys`**, skipping our own keys and any leaf
   already rooted in the live keybox), asks the lib to re-sign each under the profile's keybox over
   a `resign` request on the same socket (the same patch the router applies to a fresh key), and
   writes the patched chain back with **`Keystore2Service.updateSubcomponent`** — the key blob is
   never touched, so the real hardware key keeps signing; only the certificate the app reads changes.
   Record-less and idempotent: it re-scans each run, so a keybox swap or a newly installed app
   self-heals on the next push.

   On the **first** commit only (daemon start), `ReAttest.purgeTargetAttestKeys` additionally
   **deletes** each target app's *foreign* attestation key — one with `ATTEST_KEY` purpose that is not
   ours (**`KeystoreDb.deleteTargetAttestKeys`**, scoped hard to the target uid, `PURPOSE=ATTEST_KEY`,
   and *not* carrying our marker). This exists because of how attest-key delegation works: an
   attestation key signs the leaves of the keys it attests, and keystore2 appends *that key's own*
   stored certificate chain (snapshotted at generation, before the HAL call). So a delegated key is
   only fully spoofable — keybox-rooted chain **and** a patched, locked root of trust *inside the
   leaf* — when we hold the attest key's private key and sign that leaf ourselves. A real hardware
   attest key we don't control can only ever sign a leaf carrying the device's genuine, unlocked root
   of trust, which we cannot re-sign. Deleting the foreign key forces the app to regenerate it, and
   the router always mints an `ATTEST_KEY`-purpose key in the TA (generation mode, never patched), so
   the replacement is ours. Our own marked attest keys are left untouched, and the purge runs exactly
   once at start (an `AtomicBoolean` one-shot), so it never disturbs a key mid-session.

## The WebUI back end

The root-manager WebUI talks to the daemon over a tiny loopback HTTP endpoint, since the daemon
has a real `Context` and root that the webview alone does not:

- **`KeyAdmin`** — HTTP/1.1 on `127.0.0.1:8790`, gated by a random token in a root-only file
  (`admin.token`). It serves the WebUI's status, key, keybox, logs, and canary routes, plus the
  **Scope** app-picker's routes: **`GET /packages`** (the installed-app list collapsed by uid — label,
  packages, system / launchable / enabled, install time, plus per-app request frequency, last-used, and
  a since-boot "recent" flag), **`GET /icon`** (a rendered app icon PNG, token-in-query so an `<img>`
  can load it, cached in memory), and **`POST /usage/clear`** (wipe the frequency memory). So a
  profile's targets are chosen from the live device — searchable, sortable by real usage, with icons —
  rather than typed as raw package names.
- **`UsageStore`** — the per-package frequency/recency memory behind the picker's "Recent" group and
  its frequency/recently-used sorts. The injected interceptor tallies each `generateKey` caller uid in
  memory (a short locked bump, never any I/O on the crypto path); the daemon polls that snapshot over
  the control socket (`getUsage`, ~15s), resolves each uid to a package, and folds the per-uid delta
  into `usage.json` keyed by package — a persisted per-uid cursor keeps the accumulation exact across
  daemon restarts, and "recent" is the in-memory set seen since this boot.
- **`KeystoreDb`** — on API ≥ 31, snapshots keystore2's SQLite database and reads the `keyentry`
  table so the WebUI can list the keys targeted apps actually created (they live in each app's
  own namespace, which the daemon's `AndroidKeyStore` can't enumerate).
- **`KeyboxInspector`** — parses a `keybox.xml` and its certificate chains for the WebUI's keybox
  inspector (subject/issuer/validity/key type/chain linkage).
- **`Updater`** — canary self-update: checks the rolling `canary-<code>` GitHub prereleases,
  reports the installed version, and downloads-and-flashes a chosen build through the root
  manager on request.
- **`LogTail`** — tails logcat (our `TEESimulator` tag, SELinux `avc` denials, and the injected
  keystore pid) into a bounded ring buffer the WebUI polls and filters.

## Support

- **`DeviceProps`** — read-only system properties and the integer encodings KeyMint expects
  (osVersion, patch levels), plus the config patch mini-language resolution.
- **`Const`** — paths, the control port, and the security-level encodings shared with the native
  side.
- **`SystemLogger`** — logcat under the single `TEESimulator` tag the whole module logs to.

## Building

The daemon is one node in the top-level Gradle graph; `./gradlew zipRelease` (or `zipDebug`)
compiles it to `classes.dex` and assembles it into the flashable module alongside the native
interceptors and the WebUI. It needs only the Android SDK.
