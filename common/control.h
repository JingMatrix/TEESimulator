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
  bool device_locked;
  int32_t verified_boot_state;
} TsBootInfo;

// One fully-resolved profile from a config push. All strings/bytes are borrowed
// for the duration of the teesim_cfg_add_profile call only.
typedef struct {
  const char *id;
  const uint8_t *keybox;
  size_t keybox_len;
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
// Which hook this lib is, for the hello message: "keymint" or "keystore1".
const char *teesim_hook_name(void);

// --- control server, implemented in common/control.cpp -----------------------

// Bind the abstract socket @teesim, listen, and serve config pushes on a
// detached thread. Idempotent; safe to call once from entry().
void teesim_control_start(void);

#ifdef __cplusplus
}
#endif

#endif  // TEESIM_CONTROL_H
