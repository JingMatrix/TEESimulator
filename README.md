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

### Without a reboot

Nothing the module installs waits for a boot stage — it mounts no partition and ships no `system.prop`, and the daemon injects whatever keystore process it finds — so an install can take effect on the system that is already running. Which path a device has depends on its root manager:

* *KernelSU* installs it in place. The installer asks for a hot install, `ksud` swaps the module directory and runs `hotinstall.sh`, and the daemon takes over from there.
* *Magisk, APatch,* and a KernelSU too old for that path need one command:

  ```sh
  su -c /data/adb/modules/teesim/late-load.sh
  ```

  `ksud late-load` runs the same script by itself. `--stop` is the reverse: it stops the daemon and restarts the keystore service, leaving the system carrying no interceptor at all.

Both arm the running system, and both have one thing a reboot does not: the keystore process in front of them may already carry an interceptor, which no library is ever unloaded from or injected over. When that one is *this* build's — a daemon that crashed and respawned, or a second `late-load.sh` — the daemon adopts it and nothing restarts. When it is an older build's, as after an update, the daemon restarts the keystore service and injects the new one into the fresh process, and apps may see a transient keystore error as it goes down. The stage prints which of the two happened — and when `ksud` runs it for you, at boot or on a hot install, there is no shell for it to print to, so the same lines go to the device log and show up in the daemon's log and the WebUI's Logs panel.

A reboot is still needed for one case the installer reports: a *TrickyStore* that was active on this boot keeps its own keystore hook until the keystore daemon restarts, so the installer disables it and asks for the reboot rather than hot-installing over it.

## Configuration

Everything lives in `/data/adb/teesim/`, owned and validated by the daemon. The keybox files carry private keys and are never shipped with the module.

### `config.json`

A schema version and a map of named profiles. Each targeted package must appear in exactly one profile:

```jsonc
{
  "version": 1,
  "profiles": {
    "default": {
      "keybox": "keybox.xml",                // relative to /data/adb/teesim; must parse (rsa and/or ecdsa, chains >= 2)
      "patchLevel": { "system": "today", "vendor": "YYYY-MM-05", "boot": "YYYY-MM-05" },
      "osVersion": "",                       // empty = harvested | system_property | "16" | "16.0.0" | 160000
      "brand": "", "device": "", "product": "",
      "manufacturer": "", "model": "",
      "serial": "", "imei": "", "meid": "", "imei2": "",
      "verifiedBootHash": "",                // empty = the keybox's, else this device's; or 64 hex characters
      "applyProperties": true,               // also write what this profile attests into the matching system properties
      "apps": ["com.google.android.gms", "com.android.vending"]
    }
  }
}
```

Patch and OS levels accept a small mini-language the daemon resolves against the device. `harvested` reuses the value captured from the real TEE at harvest time; `system_property` reads the matching build property from `getprop` and nothing else. Both report *nothing* when their source has no value — the tag is omitted rather than sent as a made-up default. `today` is the current month; `YYYY-MM-DD` / `YYYY-MM` an explicit date; `no` suppresses the level. A date may also use the tokens `YYYY` / `MM` / `DD`, resolved to today, so `YYYY-MM-05` means the 5th of the current month (the shipped default for the vendor and boot patch levels, which tracks the calendar). Every other field states what this profile attests, and what it leaves empty takes a default from one of two places. An RKP keybox records the device it was *provisioned* for — its verified boot hash, its manufacturer, and a build fingerprint, which spells out the brand, product and device names — and that comes first, because attesting this device's own values under such a keybox contradicts the keybox signing the chain. Everything it does not state falls back to the harvest: the value captured from the real TEE, or the one read from the OS when the attested leaf carried none, so an app asking the keystore to attest the device's real ids gets a matching answer. A field with neither is omitted rather than sent as a made-up default, and the editor's hint under each empty field names the value and which of the two sources it came from.

`verifiedBootHash` is the profile's root of trust. It is also an input to the key-encryption key the simulator's TA derives, so a profile that changes it cannot read back the generation-mode keys minted under the previous hash — they return when it does, and patch mode keeps the real hardware key and is unaffected.

`applyProperties` decides whether what a profile attests is also what the device *says*. Attestation and the system properties are read by different code — an app can ask the keystore to attest the device ids and then read `ro.product.model` for itself — so a profile whose values differ from this device's own leaves the two disagreeing. With the flag set, every id, patch level and OS version the profile presents that differs from the harvest is written into the properties it is read from, and `ro.boot.vbmeta.digest` follows the hash the profile attests. Only a property this device already carries is written: a name it does not have is one nothing on it reads, and inventing one would change the build's shape rather than what it says. There is a single set of properties, so at most one profile may claim them (the daemon rejects a second); an absent flag means the profile named `default`, or the only one a single-profile configuration has, which is what the daemon did before the flag existed.

Nothing written this way is permanent. `resetprop` lives in memory, so a reboot restores every property on its own, and the daemon records what each one read before it first wrote it (`props.json`, scoped to one boot) so it can put them back — when a profile stops claiming a value, and before it harvests, which is what keeps the capture a reading of *this* device even when the daemon is restarted into a system it has already spoofed.

### `keybox.xml`

A keybox carries the private keys and certificate chains the simulator signs with. It must contain *at least one* of an RSA and an ECDSA key (the EC key on NIST P-256), each with a PEM `PrivateKey` and a `CertificateChain` of two certificates or more — a factory keybox carries both, while one extracted from RKP carries only the EC key. An attested key is signed by the batch key of its own algorithm where the keybox has it, and by the other one where it does not:

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
| `module/` | The flashable module: the stage scripts (`service.sh` at boot, `late-load.sh` and `hotinstall.sh` on a running system, all forwarding to `stage.sh`), installer, `sepolicy.rule`, the default configuration, and the WebUI. |
| `third_party/` | Submodules: the reference KeyMint, the AIDL interfaces, `frameworks/native`, BoringSSL, and LSPlt. |

## License

TEESimulator is free software, licensed under the [GNU General Public License v3.0](LICENSE) or
any later version. The third-party code it builds on — the AOSP submodules, BoringSSL, LSPlt and
the vendored platform headers — is listed with its own terms in [NOTICE](NOTICE).
