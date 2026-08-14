// The daemon <-> lib control channel, and the config-staging API the routers
// implement. The daemon resolves configuration against the live device and
// pushes it here over an abstract unix socket; the lib is a pure engine that
// never reads files, a clock, or package data.
//
// A push is applied as: teesim_cfg_begin(boot); add_profile() x N; commit(epoch).
// commit atomically swaps the live profile set and routing tables, so the
// AIBinder_transact / ioctl hooks keep serving the previous config until the
// instant the new one is ready.
#ifndef TEESIM_CONTROL_H
#define TEESIM_CONTROL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "teesim_km.h"  // TsDeviceIds

#ifdef __cplusplus
extern "C" {
#endif

// Device-wide verified-boot info. Same for every profile and frozen by the
// daemon (it feeds the KEK derivation), so blobs stay decryptable across reboots.
// verified_boot_state: 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed.
typedef struct {
  const uint8_t *verified_boot_key;
  size_t verified_boot_key_len;
  const uint8_t *verified_boot_hash;
  size_t verified_boot_hash_len;
  // SHA-256 the daemon computed over the device's active APEX/module set, to attach as
  // Tag::MODULE_HASH on keys we mint. NULL/0 when unavailable; the TA emits the tag only for
  // KeyMint v4+ attestations regardless, so an older-version profile never carries it.
  const uint8_t *module_hash;
  size_t module_hash_len;
  bool device_locked;
  int32_t verified_boot_state;
  bool strongbox_available;  // device can produce a real StrongBox-backed key; gates patch at that level
  int32_t attest_version_tee;        // harvested KeyMint HAL version at TEE (attestationVersion)
  int32_t attest_version_strongbox;  // harvested KeyMint HAL version at StrongBox (TEE value if broken)
} TsBootInfo;

// One fully-resolved profile from a config push. All strings/bytes are borrowed
// for the duration of the teesim_cfg_add_profile call only.
typedef struct {
  const char *id;
  const uint8_t *keybox;
  size_t keybox_len;
  const char *mode;  // "patch" | "generation"; NULL defaults to generation
  int32_t security_level;  // 0 Software, 1 TEE, 2 StrongBox
  uint32_t os_version;
  uint32_t os_patchlevel;
  uint32_t vendor_patchlevel;
  uint32_t boot_patchlevel;
  const TsDeviceIds *ids;  // NULL if the profile provisions no device IDs
  const char *const *packages;  // for keystore2 name-match
  int n_packages;
  const int32_t *uids;  // for keystore1 uid-match (may be shorter than packages)
  int n_uids;
} TsProfile;

// --- staging API, implemented by each router ---------------------------------

// Start a new staging generation with the device-wide boot info (copied).
void teesim_cfg_begin(const TsBootInfo *boot);
// Build one profile's TA and stage its routing. Returns false if the profile
// failed to build (e.g. a bad keybox); such a profile is skipped, its apps fall
// through to real hardware, and the rest of the push still applies.
bool teesim_cfg_add_profile(const TsProfile *p);
// Atomically swap the staged profile set live. Returns the number of profiles
// applied, or -1 on a hard failure. `err` receives a short message on failure.
int teesim_cfg_commit(uint64_t epoch, char *err, size_t err_len);

// Re-sign an existing key's real attestation leaf under profile `profile_id`'s keybox with its
// patched (locked/Verified) root of trust — patch mode applied to a key already stored in the
// keystore. `leaf`/`leaf_len` is the DER leaf. `sink` is invoked once per certificate of the
// resulting chain [patched leaf, keybox chain] with its DER bytes. Returns false if the profile is
// unknown or the re-sign fails (the keystore1 interceptor, which has no patch mode, always returns
// false). Runs on the control thread, against the live profile set.
typedef void (*TsCertSink)(void *ctx, const uint8_t *der, size_t der_len);
bool teesim_cfg_resign(const char *profile_id, const uint8_t *leaf, size_t leaf_len,
                       TsCertSink sink, void *ctx);
// Which hook this lib is, for the hello message: "keymint" or "keystore1".
const char *teesim_hook_name(void);

// Snapshot the per-caller key-usage stats this lib has recorded since it loaded,
// as a malloc'd, NUL-terminated JSON ARRAY the caller must free(). Each element
// is one uid that has requested a key this boot:
//   [{"uid":N,"count":N,"lastBootMs":N,"pkg":"..."}]
// count is the cumulative generateKey requests from that uid, lastBootMs is the
// CLOCK_BOOTTIME (ms) of its most recent request, and pkg is a best-effort
// package hint (usually "" — the daemon resolves uid->package itself). The
// keymint router fills this in; the keystore1 router returns "[]" (out of scope).
// The daemon polls it via the control channel's getUsage request.
char *teesim_usage_json_alloc(void);

// The device Android API level (ro.build.version.sdk), or 0 if unknown. Shared so
// hooks can select release-specific wire formats — the legacy keystore1 interface
// shifted its transaction ordinals and grew finish()'s signature between 10 and 11.
int teesim_android_api(void);

// --- control server, implemented in common/control.cpp -----------------------

// Bind the abstract socket @teesim, listen, and serve config pushes on a
// detached thread. Idempotent; safe to call once from entry().
void teesim_control_start(void);

#ifdef __cplusplus
}
#endif

#endif  // TEESIM_CONTROL_H
