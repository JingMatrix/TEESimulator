# TEESimulator

*TEESimulator* defeats hardware-backed [Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) by serving selected apps from a software KeyMint that runs *inside* the real keystore daemon, while every other key stays on the device's real hardware.

Rather than patch certificates after the fact, it embeds AOSP's own reference KeyMint trusted application ([`kmr-ta`](https://cs.android.com/android/platform/superproject/main/+/main:system/keymint/)) and signs attestations with a user-provided keybox. The certificates are generated the same way a real TEE generates them, so they are internally consistent by construction.

## How it works

A privileged control daemon owns the configuration and the real device identity; the injected native library is a pure crypto-and-routing engine. The daemon launches at boot, harvests the device's real attestation parameters (verified-boot state, patch levels, OS version) from a throwaway hardware key, resolves the configured profiles against the live device, injects the interceptor into the keystore daemon, and pushes the resolved configuration over a local socket. Editing the configuration re-pushes without a reboot.

The daemon that guards keys — and the way apps reach it — changed across Android versions, so the module hooks each generation at the point that suits it, and both paths lead to the same reference TA and keybox:

* *Android 12 and newer* use `keystore2`, which reaches the KeyMint HAL over Binder. The module injects a native library into `keystore2` and PLT-hooks `AIBinder_transact`; a KeyMint transaction for a *targeted app* (or a key the module created) is redirected to a *local, in-process `IKeyMintDevice`* that wraps the TA, and everything else is forwarded to the real hardware.
* *Android 10 and 11* use the legacy `keystore` daemon, which apps reach over `IKeystoreService`. The module injects into `keystore`, hooks `ioctl` on libbinder, and redirects that service to a local stub handled in-process. For a targeted app it generates the key itself, hands back its public key, and at attestation time imports that key into the TA with the app's challenge, so the TA issues a keybox-signed chain over it. Other callers pass through.

Keys the simulator creates are tagged (Android 12+) or tracked by caller (Android 10/11) so only they are served; real hardware keys are never intercepted. If no keybox is loaded the interceptor stays a no-op, so a misconfigured module is inert rather than a hazard.

### Profiles and device identity

Configuration is organised into **profiles**: a named bundle of a keybox, an operation mode, patch and OS levels, and optional device-identity values (brand, model, IMEI, …), assigned to a set of apps. Each targeted app belongs to exactly one profile, and its attestations are signed and shaped by that profile.

The root of trust — verified-boot key, verified-boot state, device-locked flag — is deliberately *not* configurable. The daemon harvests the device's real values once and freezes them: they make the attested root of trust authentic, and because those fields also seed KeyMint's key-encryption-key derivation, freezing them gives a stable per-device key that keeps stored keys decryptable across reboots.

## Requirements

* *Android 10 or newer*
* A *64-bit* device — *arm64-v8a* or *x86_64* (the keystore daemon is 64-bit)
* Root (Magisk, KernelSU, or APatch)

## Installation

1. Flash the module with the root manager and reboot.
2. Place a hardware-backed `keybox.xml` at `/data/adb/teesim/keybox.xml`.
3. List the apps to simulate under a profile in `/data/adb/teesim/config.json`, or edit the profile in the WebUI.
4. Save. The daemon watches the configuration and applies changes live; no reboot is needed.

The module ships a default `config.json` that targets Google Play services and the Play Store. The keybox is private and is never shipped with the module, so until one is placed the interceptor does nothing.

Killing the keystore daemon (`su -c 'kill $(pidof keystore2)'` on Android 12+, `keystore` on 10/11) is the recovery path: a fresh daemon starts clean, with no interception, until the module re-injects it.

## Configuration

Everything lives in `/data/adb/teesim/`, owned and validated by the daemon. The keybox files carry private keys and are never shipped with the module.

### `config.json`

A schema version and a map of named profiles. Each targeted package must appear in exactly one profile:

```jsonc
{
  "version": 1,
  "profiles": {
    "default": {
      "keybox": "keybox.xml",                // relative to /data/adb/teesim; must parse (rsa + ecdsa, chains >= 2)
      "patchLevel": { "system": "today", "vendor": "YYYY-MM-05", "boot": "YYYY-MM-05" },
      "osVersion": "",                       // empty = harvested | system_property | "16" | "16.0.0" | 160000
      "brand": "", "device": "", "product": "",
      "manufacturer": "", "model": "",
      "serial": "", "imei": "", "meid": "", "imei2": "",
      "apps": ["com.google.android.gms", "com.android.vending"]
    }
  }
}
```

Patch and OS levels accept a small mini-language the daemon resolves against the device. `harvested` reuses the value captured from the real TEE at harvest time; `system_property` reads the matching build property from `getprop` and nothing else. Both report *nothing* when their source has no value — the tag is omitted rather than sent as a made-up default. `today` is the current month; `YYYY-MM-DD` / `YYYY-MM` an explicit date; `no` suppresses the level. A date may also use the tokens `YYYY` / `MM` / `DD`, resolved to today, so `YYYY-MM-05` means the 5th of the current month (the shipped default for the vendor and boot patch levels, which tracks the calendar). Device-identity fields fall back to the values captured from the real TEE at harvest, so an app that asks the keystore to attest the device's real ids gets a matching answer; a non-empty field overrides that, and both are omitted only when neither is set. The root of trust is never listed here — it comes from the harvest.

### `keybox.xml`

A keybox carries the private keys and certificate chains the simulator signs with. It must contain *both* an RSA and an ECDSA key (the EC key on NIST P-256), each with a PEM `PrivateKey` and its `CertificateChain`:

```xml
<?xml version="1.0"?>
<AndroidAttestation>
  <Keybox DeviceID="...">
    <Key algorithm="rsa">
      <PrivateKey format="pem">-----BEGIN PRIVATE KEY-----...</PrivateKey>
      <CertificateChain>
        <Certificate format="pem">-----BEGIN CERTIFICATE-----...</Certificate>
        <!-- ...intermediate and root... -->
      </CertificateChain>
    </Key>
    <Key algorithm="ecdsa">
      <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY-----...</PrivateKey>
      <CertificateChain>
        <Certificate format="pem">-----BEGIN CERTIFICATE-----...</Certificate>
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>
```

A profile names its keybox by relative path, so several profiles can sign with different keyboxes. An app that is in no profile is transparent to the module — its keys go straight to the real hardware.

### WebUI

Where the root manager supports it (KernelSU, APatch), the module ships a WebUI that edits profiles without a text editor: create and assign profiles, import and rename keyboxes, choose the operation mode, and set the patch/OS levels and device identity. It also manages the keys the simulator has stored — list, inspect the attestation record, and delete — surfaces the harvest and injection status and live daemon logs, and can download and flash a newer canary build in place.

## Building from source

The build depends on no device: `libbinder_ndk` and `liblog` come from the NDK, and BoringSSL is either resolved at runtime (Android 12+) or built as a static library from the submodule (Android 10/11). It needs only the SDK (for `aidl`) and the NDK.

```sh
git clone --recurse-submodules <repo> TEESimulator
cd TEESimulator

export ANDROID_HOME=/path/to/android/sdk        # SDK: aidl, cmake, the daemon's AGP build
export ANDROID_NDK_HOME=/path/to/android/ndk    # or the newest NDK under $ANDROID_HOME/ndk

./gradlew zipRelease                            # -> out/TEESimulator-<version>-<count>-<hash>-Release.zip
```

The whole build is one Gradle graph. `zipRelease` (or `zipDebug`, which bundles extra logging) builds the Rust TA, both native interceptors for `arm64-v8a` and `x86_64` (via CMake `externalNativeBuild`), and the control daemon's dex, then assembles the flashable module. With a device attached, `./gradlew installMagisk` (or `installKsu` / `installApatch`) pushes and installs it; append `AndReboot` to reboot after, and set `ANDROID_SERIAL=<serial>` to pick a device when several are connected.

## Project layout

| Path | What it is |
| --- | --- |
| `app/` | The Kotlin control daemon: harvests the real device parameters, resolves profiles, injects the interceptor, serves the WebUI, and pushes configuration over the control socket. |
| `injector/` | A `ptrace`-based tool that loads an interceptor into a running process. |
| `keymint/` | The Android 12+ interceptor: the `AIBinder_transact` hook and the router that decides, per request, whether to simulate or forward. |
| `keystore/` | The Android 10/11 interceptor: the libbinder `ioctl` hook and the `IKeystoreService` handler that serves a target's key lifecycle from the TA. |
| `rust/teesim-km/` | The in-process TA — the reference KeyMint TA wired to BoringSSL and keybox-based attestation, behind a small C ABI. |
| `module/` | The flashable module: boot service, installer, `sepolicy.rule`, the default configuration, and the WebUI. |
| `third_party/` | Submodules: the reference KeyMint, the AIDL interfaces, `frameworks/native`, BoringSSL, and LSPlt. |
