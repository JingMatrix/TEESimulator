// Local IKeyMintDevice / IKeyMintOperation backed by the in-process Rust TA.
//
// The interceptor re-dispatches keystore2's KeyMint transactions to these local
// binders. The generated Bn base classes handle all parcel marshalling, so here
// we only convert between the AIDL types and the flat C ABI (teesim_km.h).
//
// Each device also wraps the real KeyMint HAL. It decides per request whether to
// simulate (target app, or one of our own key blobs) or to forward to the real
// HAL, so non-target apps and real hardware keys are never disturbed.

#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/BnKeyMintOperation.h>
#include <android/binder_ibinder.h>  // AIBinder_getCallingUid / AIBinder_getCallingPid
#include <unistd.h>                       // getuid / getpid

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <condition_variable>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "control.h"
#include "keymint_hook.h"
#include "km_names.h"
// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "km"
#include "logging.hpp"
#include "teesim_km.h"

using namespace aidl::android::hardware::security::keymint;
namespace secureclock = aidl::android::hardware::security::secureclock;

namespace {

// A TA is reference-counted so an in-flight operation keeps its profile's TA
// alive even if a config reload swaps or drops that profile underneath it.
using TaPtr = std::shared_ptr<::Ta>;
TaPtr WrapTa(::Ta* ta) {
  return TaPtr(ta, [](::Ta* t) {
    if (t) teesim_km_destroy(t);
  });
}

// The stride between two Android users' uids for the same app (android.os.UserHandle.PER_USER_RANGE).
// A caller uid is userId * 100000 + appId, so this is what turns one into the other.
constexpr int32_t kPerUserRange = 100000;

// One package name routed to a profile, and the Android user it is routed in. An attestation
// application id carries the package but not the user, so without `user_id` a work profile's clone of
// an app would answer to the primary user's entry and vice versa.
struct TargetPackage {
  std::string name;
  int32_t user_id = 0;
};

// A configured profile: its per-level TAs, the package names routed to it, and whether it patches the
// real hardware attestation (patch mode) or mints the whole key in the TA (generation mode).
struct Profile {
  std::string id;
  // A separate fixed-level TA per security level, mirroring how a real device runs an independent
  // KeyMint instance per level. Every op routes to the instance for the level it arrived on, so a
  // key's characteristics are always read at the level the key was minted at.
  TaPtr ta_tee;
  TaPtr ta_strongbox;
  std::vector<TargetPackage> packages;
  std::vector<int32_t> uids;  // resolved caller uids, for requests that carry no app-id to match
  // Parallel to uids[]: the package the daemon resolved each uid from, or "" for a raw uid:N or an
  // auto-included one. Only used to name the caller in the log — routing never reads it.
  std::vector<std::string> uid_names;
  bool patch_mode = false;

  // The TA that serves requests arriving at `level`. Software-level KeyMint is never wrapped, so any
  // non-StrongBox level maps to the TrustedEnvironment instance.
  const TaPtr& TaFor(SecurityLevel level) const {
    return level == SecurityLevel::STRONGBOX ? ta_strongbox : ta_tee;
  }
};

// Live routing, swapped atomically by teesim_cfg_commit under g_cfg_mu.
std::mutex g_cfg_mu;
std::vector<Profile> g_profiles;
// Signalled by teesim_cfg_commit. Operations on one of our own key blobs wait on this rather than
// failing while the daemon has not pushed a config yet; see WaitForDefaultTa.
std::condition_variable g_cfg_cv;
bool g_strongbox_ok = false;  // device can patch real StrongBox keys; else StrongBox forces generation
// The device-wide MODULE_HASH to seed a freshly built TA with, so a generation-mode key carries the
// tag keystore2 only sends once per boot (and never resends to a TA built afterwards). Preference:
// the exact bytes keystore2 pushed via setAdditionalAttestationInfo, captured below; the daemon's own
// computed value (g_stage_module_hash) is only a fallback for when we never saw that one-shot call.
// Guarded by g_cfg_mu. Empty until either source provides one.
std::vector<uint8_t> g_module_hash;

// Staging state built up by teesim_cfg_begin/add_profile before the swap.
std::vector<Profile> g_staging;
std::vector<uint8_t> g_stage_vb_key;
std::vector<uint8_t> g_stage_vb_hash;
std::vector<uint8_t> g_stage_module_hash;  // MODULE_HASH to seed each TA with at creation (may be empty)
bool g_stage_locked = true;
int32_t g_stage_vb_state = 0;
bool g_stage_strongbox_ok = false;
int32_t g_stage_attest_version_tee = 400;
int32_t g_stage_attest_version_strongbox = 300;

// --- Per-caller usage stats --------------------------------------------------
// Every app that asks us for a key this boot is recorded here from generateKey,
// so the daemon can surface a "Recent" group and a frequency ordering in the
// scope picker. Keyed by caller uid because a uid outlives a single request; the
// daemon maps uid->package (uids get reassigned across installs, packages are
// stable). This is a hot path, so the record is a short locked map update with
// no I/O — never touch the crypto path's latency.
struct UsageEntry {
  uint64_t count = 0;         // cumulative generateKey requests from this uid since load
  uint64_t last_boot_ms = 0;  // CLOCK_BOOTTIME (ms) of the most recent request
  std::string pkg;            // best-effort package hint, usually empty (daemon resolves uid->pkg)
};
std::mutex g_usage_mu;
std::map<int32_t, UsageEntry> g_usage;

// Milliseconds on CLOCK_BOOTTIME: a monotonic clock that keeps counting across
// suspend, matching the daemon's SystemClock.elapsedRealtime so it can convert
// our lastBootMs back to a wall-clock instant.
uint64_t NowBootMs() {
  struct timespec ts{};
  clock_gettime(CLOCK_BOOTTIME, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000u + static_cast<uint64_t>(ts.tv_nsec) / 1000000u;
}

// Milliseconds on CLOCK_MONOTONIC, for the "how long did this take" fields. Deliberately not
// NowBootMs: the usage stats need a clock that keeps counting across suspend, a duration needs one
// that does not.
uint64_t NowMonoMs() {
  struct timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000u + static_cast<uint64_t>(ts.tv_nsec) / 1000000u;
}

// A stopwatch for one span, so the log can say whether a hooked call added latency even below the
// ~500ms threshold where libbinder's own slow-transaction warning fires.
struct Elapsed {
  uint64_t t0 = NowMonoMs();
  unsigned long long Ms() const { return NowMonoMs() - t0; }
};

// The security level as the name a reader knows it by, rather than the AIDL's ordinal.
const char* LevelName(SecurityLevel level) {
  switch (level) {
    case SecurityLevel::SOFTWARE: return "SW";
    case SecurityLevel::TRUSTED_ENVIRONMENT: return "TEE";
    case SecurityLevel::STRONGBOX: return "StrongBox";
    case SecurityLevel::KEYSTORE: return "keystore";
    default: return "?";
  }
}

// Record one key request from `caller_uid` (target or not). Cheap by design: the
// daemon does the uid->package resolution, so we only bump the count and stamp
// the time. A caller with no valid uid (-1) is skipped.
void RecordUsage(int32_t caller_uid) {
  if (caller_uid < 0) return;
  std::lock_guard<std::mutex> lk(g_usage_mu);
  UsageEntry& e = g_usage[caller_uid];
  ++e.count;
  e.last_boot_ms = NowBootMs();
}

// RAII guard: mark the current thread as forwarding to the real HAL.
struct ForwardGuard {
  ForwardGuard() { teesim_hook_set_forwarding(true); }
  ~ForwardGuard() { teesim_hook_set_forwarding(false); }
};

// The profile matched to this request by its ATTESTATION_APPLICATION_ID: the TA to serve it with and
// whether that profile is in patch mode. `ta` is null when the request is not for any target app.
struct RequestTarget {
  TaPtr ta;
  bool patch_mode = false;
  // The profile's id, for the log: on a device with more than one profile it says which keybox
  // signed a chain.
  std::string id;
};

RequestTarget ProfileForRequest(const std::vector<KeyParameter>& params, uid_t caller_uid,
                                SecurityLevel level) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  if (g_profiles.empty()) return {};
  // The Android user the request came from, or -1 when the caller is unknown (no binder transaction
  // in flight). An unknown user cannot contradict a name match, so it accepts any entry's user.
  const int32_t caller_user =
      caller_uid == static_cast<uid_t>(-1) ? -1 : static_cast<int32_t>(caller_uid) / kPerUserRange;
  // Primary match: the ATTESTATION_APPLICATION_ID the app embeds in the request names its package.
  // The blob names only the package, so the caller's user is what separates two users' copies of one
  // app — a work profile's Play Store must not pick up the entry written for the primary user's.
  for (const auto& p : params) {
    if (p.tag != Tag::ATTESTATION_APPLICATION_ID) continue;
    if (p.value.getTag() != KeyParameterValue::blob) continue;
    const auto& id = p.value.get<KeyParameterValue::blob>();
    std::string hay(id.begin(), id.end());
    for (const auto& prof : g_profiles) {
      for (const auto& pkg : prof.packages) {
        if (hay.find(pkg.name) == std::string::npos) continue;
        if (caller_user >= 0 && pkg.user_id != caller_user) {
          // A seam, not an outcome: it fires per candidate package on every request that carries an
          // attestation application id, and says nothing a reader wants unless routing is the thing
          // under investigation.
          LOGD("ProfileForRequest: '%s' matches profile '%s' for user %d, not the caller's user "
               "%d; skipped",
               pkg.name.c_str(), prof.id.c_str(), pkg.user_id, caller_user);
          continue;
        }
        return {prof.TaFor(level), prof.patch_mode, prof.id};
      }
    }
  }
  // Fallback match: the caller's uid. An app creating an attestation KEY does so unattested — no
  // challenge, no app-id — so there is nothing to name-match, yet we must still route it to the app's
  // profile (and mint it in the TA) or the key it later attests is signed by a key we do not hold.
  if (caller_uid != static_cast<uid_t>(-1)) {
    for (const auto& prof : g_profiles) {
      for (int32_t uid : prof.uids) {
        if (static_cast<uid_t>(uid) == caller_uid) return {prof.TaFor(level), prof.patch_mode, prof.id};
      }
    }
  }
  return {};
}

// The log prefix naming the request a hooked call is serving: "[10316 com.snapchat.android r3c81] ",
// or "[10316 r3c81] " when no configured package resolved to that uid. Stamped once per entry point;
// every line the call logs then carries it, which is what makes an operation attributable to an app
// instead of having to be inferred from what was logged next to it on an interleaved thread.
//
// AIBinder_getCallingUid returns getuid() when no transaction is in flight, never -1, so a uid alone
// cannot tell keystore2's own work (its key garbage collection, say) from an app running as
// AID_KEYSTORE. Pairing the uid with the pid says which it is.
std::string PackageNameFor(int32_t uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  for (const auto& prof : g_profiles) {
    for (size_t i = 0; i < prof.uids.size(); ++i) {
      if (prof.uids[i] != uid) continue;
      if (i < prof.uid_names.size()) return prof.uid_names[i];
      return std::string();
    }
  }
  // No exact match: a secondary-user caller carries uid = user * 100000 + app_id and shares its
  // package with the primary-user entry of the same app id, so match on app id to name it rather
  // than log a bare uid (a Private-space app forwards here as e.g. 1010156 for app id 10156). The
  // name carries the user as "pkg@<user>" to mark it a cross-user instance, not a configured
  // target. Log line only; routing keys off the exact uid, so it never widens a profile's scope.
  const int32_t app_id = uid % 100000;
  for (const auto& prof : g_profiles) {
    for (size_t i = 0; i < prof.uids.size() && i < prof.uid_names.size(); ++i) {
      if (prof.uids[i] % 100000 == app_id && !prof.uid_names[i].empty()) {
        return prof.uid_names[i] + "@" + std::to_string(uid / 100000);
      }
    }
  }
  return std::string();
}

// A fresh context for the request now entering. `rid` joins this request's lines across the router,
// the TA and both languages; it is minted here because this is the one place every hooked call
// passes through.
std::string RequestCtx() {
  char rid[16];
  snprintf(rid, sizeof(rid), "r%04x", teesim_log_new_rid());
  const uid_t caller_uid = AIBinder_getCallingUid();
  // AIBinder_getCallingPid is __INTRODUCED_IN(29), the same floor as getCallingUid — unlike
  // AIBinder_isHandlingTransaction, which is 33 and would be a null weak symbol on Android 12.
  if (caller_uid == getuid() && AIBinder_getCallingPid() == getpid()) {
    return std::string("[self ") + rid + "] ";
  }
  const int32_t uid = static_cast<int32_t>(caller_uid);
  std::string tag = "[" + std::to_string(uid);
  const std::string name = PackageNameFor(uid);
  if (!name.empty()) tag += " " + name;
  return tag + " " + rid + "] ";
}

// How long an operation on one of our own key blobs waits for the daemon's first config push.
constexpr auto kConfigWait = std::chrono::seconds(8);

// ErrorCode::HARDWARE_NOT_YET_AVAILABLE. Returned when a key of ours outlives the wait below: it says
// "come back later", where the UNIMPLEMENTED we used to return says "this key is unusable" and pushes
// the app into deleting and regenerating it.
constexpr int32_t kNotYetAvailable = -85;

// The TA used for operations on an existing blob of ours (begin/upgrade/etc.), at the level the op
// arrived on. Any profile's TA can decrypt any of our blobs (the KEK is level- and profile-
// independent), but the level must match so the reference TA finds the key's characteristics at its
// own level; the front profile's instance for `level` serves as that default.
//
// It waits out the window between this library taking over keystore2's KeyMint and the daemon
// pushing the config that builds those TAs. keystore2 resolves KeyMint — and apps start using their
// keys — within a second of boot, while the daemon still has to harvest and validate before it can
// push. A key of OURS touched in that window has no TA to serve it, and the hard error we used to
// return reads to keystore2 (and to the app) as "this key is broken": the app's recovery is to delete
// the alias and generate a fresh key, which silently destroys everything the old key had encrypted.
// Blocking the caller for a moment instead costs a stall at boot and keeps the key.
TaPtr WaitForDefaultTa(SecurityLevel level) {
  // Latched once the wait has run out, so a daemon that never pushes (no keybox, say) costs one
  // stall rather than one per call: every app touching a key of ours would otherwise park a
  // keystore2 binder thread for the full timeout and could starve the pool at boot.
  static bool gave_up = false;
  std::unique_lock<std::mutex> lk(g_cfg_mu);
  if (g_profiles.empty()) {
    if (gave_up) return {};
    LOGW("WaitForDefaultTa: no profile configured yet; holding an operation on one of our keys for up "
         "to %llds rather than failing it",
         static_cast<long long>(kConfigWait.count()));
    g_cfg_cv.wait_for(lk, kConfigWait, [] { return !g_profiles.empty(); });
    if (g_profiles.empty()) {
      gave_up = true;
      LOGE("WaitForDefaultTa: still no profile after waiting; the daemon never pushed a config (missing "
           "or invalid keybox?); reporting the hardware as not yet available, and an app that gives "
           "up here may regenerate its key and lose whatever it had encrypted");
      return {};
    }
    LOGI("WaitForDefaultTa: config arrived while waiting; serving the operation");
  }
  gave_up = false;
  return g_profiles.front().TaFor(level);
}

// A snapshot of every configured profile's TA, for device-state transitions (earlyBootEnded /
// setAdditionalAttestationInfo) that must reach all our keys, not just the default profile. The list
// is copied under the config lock so the calls themselves run unlocked.
std::vector<TaPtr> AllProfileTas() {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  std::vector<TaPtr> tas;
  tas.reserve(g_profiles.size() * 2);
  for (const auto& p : g_profiles) {
    if (p.ta_tee) tas.push_back(p.ta_tee);
    if (p.ta_strongbox) tas.push_back(p.ta_strongbox);
  }
  return tas;
}

// Record `hash` on `ta` as Tag::MODULE_HASH so a generation-mode key it mints carries the module
// hash. No-op for an empty hash. Setting the value a TA already holds is idempotent in the reference
// TA (a repeat of the same bytes is ignored), so the later keystore2 forward over the same value is
// harmless; only a genuinely different value is rejected, which this logs.
void SeedModuleHash(const TaPtr& ta, const std::vector<uint8_t>& hash) {
  if (hash.empty() || !ta) return;
  KmParam p{};
  p.tag = static_cast<uint32_t>(Tag::MODULE_HASH);
  p.blob = hash.data();
  p.blob_len = hash.size();
  int32_t rc = teesim_km_set_additional_attestation_info(ta.get(), &p, 1);
  if (rc != 0) LOGW("SeedModuleHash: TA rejected rc=%d(%s)", rc, teesim_km_err_name(rc));
}

// --- AIDL KeyParameter <-> flat KmParam --------------------------------------

KmParam ToKm(const KeyParameter& kp) {
  KmParam k{};
  k.tag = static_cast<uint32_t>(kp.tag);
  switch (kp.value.getTag()) {
    case KeyParameterValue::algorithm:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::algorithm>());
      break;
    case KeyParameterValue::blockMode:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::blockMode>());
      break;
    case KeyParameterValue::paddingMode:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::paddingMode>());
      break;
    case KeyParameterValue::digest:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::digest>());
      break;
    case KeyParameterValue::ecCurve:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::ecCurve>());
      break;
    case KeyParameterValue::origin:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::origin>());
      break;
    case KeyParameterValue::keyPurpose:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::keyPurpose>());
      break;
    case KeyParameterValue::hardwareAuthenticatorType:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::hardwareAuthenticatorType>());
      break;
    case KeyParameterValue::securityLevel:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::securityLevel>());
      break;
    case KeyParameterValue::boolValue:
      k.int_value = kp.value.get<KeyParameterValue::boolValue>() ? 1 : 0;
      break;
    case KeyParameterValue::integer:
      k.int_value = kp.value.get<KeyParameterValue::integer>();
      break;
    case KeyParameterValue::longInteger:
      k.int_value = kp.value.get<KeyParameterValue::longInteger>();
      break;
    case KeyParameterValue::dateTime:
      k.int_value = kp.value.get<KeyParameterValue::dateTime>();
      break;
    case KeyParameterValue::blob: {
      const auto& b = kp.value.get<KeyParameterValue::blob>();
      k.blob = b.data();
      k.blob_len = b.size();
      break;
    }
    default:
      break;
  }
  return k;
}

std::vector<KmParam> ToKmVec(const std::vector<KeyParameter>& params) {
  std::vector<KmParam> out;
  out.reserve(params.size());
  for (const auto& p : params) out.push_back(ToKm(p));
  return out;
}

KeyParameter FromKm(const KmParam& k) {
  KeyParameter kp;
  kp.tag = static_cast<Tag>(k.tag);
  switch (kp.tag) {
    case Tag::ALGORITHM:
      kp.value.set<KeyParameterValue::algorithm>(static_cast<Algorithm>(k.int_value));
      return kp;
    case Tag::BLOCK_MODE:
      kp.value.set<KeyParameterValue::blockMode>(static_cast<BlockMode>(k.int_value));
      return kp;
    case Tag::PADDING:
      kp.value.set<KeyParameterValue::paddingMode>(static_cast<PaddingMode>(k.int_value));
      return kp;
    case Tag::DIGEST:
    case Tag::RSA_OAEP_MGF_DIGEST:
      kp.value.set<KeyParameterValue::digest>(static_cast<Digest>(k.int_value));
      return kp;
    case Tag::EC_CURVE:
      kp.value.set<KeyParameterValue::ecCurve>(static_cast<EcCurve>(k.int_value));
      return kp;
    case Tag::ORIGIN:
      kp.value.set<KeyParameterValue::origin>(static_cast<KeyOrigin>(k.int_value));
      return kp;
    case Tag::PURPOSE:
      kp.value.set<KeyParameterValue::keyPurpose>(static_cast<KeyPurpose>(k.int_value));
      return kp;
    case Tag::USER_AUTH_TYPE:
      kp.value.set<KeyParameterValue::hardwareAuthenticatorType>(
          static_cast<HardwareAuthenticatorType>(k.int_value));
      return kp;
    default:
      break;
  }
  // The remaining tags map by their flat value kind (the classifier the Rust TA
  // owns), so the width/signedness table lives in one place. The specific ENUM
  // tags handled above keep their dedicated union fields; everything else is a
  // bool, a byte array, a date, a long, or a plain 32-bit integer.
  switch (teesim_km_tag_value_kind(k.tag)) {
    case KM_VALUE_BOOL:
      kp.value.set<KeyParameterValue::boolValue>(true);
      break;
    case KM_VALUE_BYTES:
      kp.value.set<KeyParameterValue::blob>(std::vector<uint8_t>(k.blob, k.blob + k.blob_len));
      break;
    case KM_VALUE_INT64:  // DATE
      kp.value.set<KeyParameterValue::dateTime>(k.int_value);
      break;
    case KM_VALUE_UINT64:  // ULONG/ULONG_REP
      kp.value.set<KeyParameterValue::longInteger>(k.int_value);
      break;
    default:  // INT32/UINT32 enums and integers
      kp.value.set<KeyParameterValue::integer>(static_cast<int32_t>(k.int_value));
      break;
  }
  return kp;
}

ndk::ScopedAStatus Status(int32_t code) {
  return code == 0 ? ndk::ScopedAStatus::ok()
                   : ndk::ScopedAStatus::fromServiceSpecificError(code);
}

// A forwarded call's outcome, in the form the log wants it: the KeyMint status by number and by
// name. A transaction that died before reaching the HAL carries no service-specific error at all — its
// getServiceSpecificError() is 0, which reads as success — so that case is reported as the binder
// exception it actually is.
std::string StatusDesc(const ndk::ScopedAStatus& st) {
  if (st.isOk()) return "rc=0";
  char buf[96];
  if (st.getExceptionCode() == EX_SERVICE_SPECIFIC) {
    const int32_t rc = st.getServiceSpecificError();
    snprintf(buf, sizeof(buf), "rc=%d(%s)", rc, teesim_km_err_name(rc));
  } else {
    snprintf(buf, sizeof(buf), "binder_exc=%d transaction=%d", st.getExceptionCode(),
             st.getStatus());
  }
  return std::string(buf);
}

// A call we can neither serve nor forward. UNIMPLEMENTED is what the caller sees; saying so is what
// distinguishes "the module declined" from "the module was never asked".
ndk::ScopedAStatus NoRealHal(const char* what) {
  LOGW("%s: FAILED, not ours to serve and no real HAL to forward to; reporting rc=-100(%s)", what,
       teesim_km_err_name(-100));
  return Status(-100);
}

// The reply to an operation on one of our keys that arrives with no TA to serve it.
//
// WaitForDefaultTa latches `gave_up` after its first timeout, so on a device where the daemon never
// pushes a config this is not one stall but the permanent answer for every operation on every key of
// ours. An app that concludes its key is broken may regenerate it, so every occurrence is logged.
ndk::ScopedAStatus NoTa(const char* what) {
  LOGW("%s: FAILED, no TA for this level yet; reporting rc=%d(%s); an app that gives up here may "
       "regenerate its key and lose whatever it had encrypted",
       what, kNotYetAvailable, teesim_km_err_name(kNotYetAvailable));
  return Status(kNotYetAvailable);
}

void FillCreationResult(TsCreationResult* res, KeyCreationResult* out) {
  const uint8_t* blob = nullptr;
  size_t blob_len = 0;
  teesim_km_result_key_blob(res, &blob, &blob_len);
  out->keyBlob.assign(blob, blob + blob_len);

  size_t n_certs = teesim_km_result_num_certs(res);
  out->certificateChain.resize(n_certs);
  for (size_t i = 0; i < n_certs; ++i) {
    const uint8_t* c = nullptr;
    size_t clen = 0;
    teesim_km_result_cert(res, i, &c, &clen);
    out->certificateChain[i].encodedCertificate.assign(c, c + clen);
  }

  size_t n_chars = teesim_km_result_num_chars(res);
  out->keyCharacteristics.resize(n_chars);
  for (size_t ci = 0; ci < n_chars; ++ci) {
    int32_t level = 0;
    size_t n_params = teesim_km_result_char(res, ci, &level);
    out->keyCharacteristics[ci].securityLevel = static_cast<SecurityLevel>(level);
    out->keyCharacteristics[ci].authorizations.reserve(n_params);
    for (size_t pi = 0; pi < n_params; ++pi) {
      KmParam km{};
      teesim_km_result_char_param(res, ci, pi, &km);
      out->keyCharacteristics[ci].authorizations.push_back(FromKm(km));
    }
  }
}

// True if `blob` is one of our key blobs.
bool IsOurs(const std::vector<uint8_t>& blob) {
  return teesim_km_is_marked(blob.data(), blob.size());
}

// True when the request creates an asymmetric key (RSA or EC) — the only algorithms KeyMint
// attests, and the only kind worth simulating. A symmetric key (AES/3DES/HMAC) is never attested,
// so simulating one would move the app's key off the real hardware for no gain, and an auth-bound
// one would then verify against a TA holding no device HMAC key. Those are forwarded to the real
// HAL, exactly as the keystore1 path does (#291). A request with no algorithm tag cannot be one of
// ours, so it forwards too.
bool IsAsymmetricKeyRequest(const std::vector<KeyParameter>& params) {
  for (const auto& p : params) {
    if (p.tag == Tag::ALGORITHM && p.value.getTag() == KeyParameterValue::algorithm) {
      const Algorithm a = p.value.get<KeyParameterValue::algorithm>();
      return a == Algorithm::RSA || a == Algorithm::EC;
    }
  }
  return false;
}

// True if the request creates a key with ATTEST_KEY purpose (an attestation key). Such a key MUST be
// minted in the TA (generation), never patched: only if we hold its private key can our TA later sign
// — and root-of-trust-patch — the leaves this key attests. A patched real-hardware attest key can only
// ever produce a real, unlocked delegated leaf (we cannot re-sign under a key we don't hold).
bool IsAttestKeyRequest(const std::vector<KeyParameter>& params) {
  for (const auto& p : params) {
    if (p.tag == Tag::PURPOSE && p.value.getTag() == KeyParameterValue::keyPurpose &&
        p.value.get<KeyParameterValue::keyPurpose>() == KeyPurpose::ATTEST_KEY) {
      return true;
    }
  }
  return false;
}

// --- auth / timestamp token marshalling --------------------------------------

// Flatten an optional AIDL HardwareAuthToken into the flat C ABI struct. Returns a pointer to
// `storage` (filled in) when the token is present, or nullptr when absent — exactly the nullability
// the TA expects. The mac pointer borrows the token's vector, which outlives the FFI call.
const TsAuthToken* FlattenAuth(const std::optional<HardwareAuthToken>& tok, TsAuthToken* storage) {
  if (!tok) return nullptr;
  storage->challenge = tok->challenge;
  storage->user_id = tok->userId;
  storage->authenticator_id = tok->authenticatorId;
  storage->authenticator_type = static_cast<int32_t>(tok->authenticatorType);
  storage->timestamp_ms = tok->timestamp.milliSeconds;
  storage->mac = tok->mac.empty() ? nullptr : tok->mac.data();
  storage->mac_len = tok->mac.size();
  return storage;
}

// Flatten an optional secureclock TimeStampToken into the flat C ABI struct (nullptr when absent).
const TsTimestampToken* FlattenTimestamp(const std::optional<secureclock::TimeStampToken>& tok,
                                         TsTimestampToken* storage) {
  if (!tok) return nullptr;
  storage->challenge = tok->challenge;
  storage->timestamp_ms = tok->timestamp.milliSeconds;
  storage->mac = tok->mac.empty() ? nullptr : tok->mac.data();
  storage->mac_len = tok->mac.size();
  return storage;
}

// --- Operation tracing -------------------------------------------------------
//
// A capture that records only blob_len cannot answer the question these failures
// pose: whether a decrypt that fails its tag is being asked to decrypt ciphertext
// that belongs to a different key, or whether the operation itself was mishandled.
// Length is not identity -- two keys of the same size are indistinguishable, and a
// blob that changed under an upgrade keeps its length. So tag every blob, and
// record what an AEAD verdict actually depends on: the nonce, the tag length, and
// the byte counts on the way through.

// 64-bit FNV-1a over the blob, printed as 16 hex digits. A digest, not the bytes:
// enough to say "the same blob as before" or "a different one", and no key material
// reaches the log.
std::string BlobTag(const std::vector<uint8_t>& blob) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (uint8_t b : blob) {
    h ^= b;
    h *= 0x100000001b3ULL;
  }
  char buf[17];
  snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
  return std::string(buf);
}

std::string HexOf(const std::vector<uint8_t>& v) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(v.size() * 2);
  for (uint8_t b : v) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0xf]);
  }
  return out;
}

// The begin parameters an AEAD or RSA verdict turns on. A wrong nonce and stale
// ciphertext both surface as VERIFICATION_FAILED, and nothing in the old capture
// told them apart.
// The shape of a key being created: algorithm, size or curve, and purposes, by name. The parameter
// count alone cannot tell an attested EC signing key from an AES key an app keeps a secret under.
std::string KeyShape(const std::vector<KeyParameter>& params) {
  std::string algorithm = "?", size, curve, purposes;
  for (const auto& p : params) {
    if (p.tag == Tag::ALGORITHM && p.value.getTag() == KeyParameterValue::algorithm) {
      algorithm = toString(p.value.get<KeyParameterValue::algorithm>());
    } else if (p.tag == Tag::KEY_SIZE && p.value.getTag() == KeyParameterValue::integer) {
      size = std::to_string(p.value.get<KeyParameterValue::integer>());
    } else if (p.tag == Tag::EC_CURVE && p.value.getTag() == KeyParameterValue::ecCurve) {
      curve = toString(p.value.get<KeyParameterValue::ecCurve>());
    } else if (p.tag == Tag::PURPOSE && p.value.getTag() == KeyParameterValue::keyPurpose) {
      if (!purposes.empty()) purposes += "|";
      purposes += toString(p.value.get<KeyParameterValue::keyPurpose>());
    }
  }
  std::string out = algorithm;
  if (!curve.empty()) {
    out += "/" + curve;
  } else if (!size.empty()) {
    out += "-" + size;
  }
  return out + " purpose=" + (purposes.empty() ? "-" : purposes);
}

// The full parameter list of a request, decoded (see KmDescribeParams).
std::string ParamsDesc(const std::vector<KeyParameter>& params) {
  const auto km = ToKmVec(params);
  return KmDescribeParams(km.data(), km.size());
}

// A short id naming ONE operation, not the key it runs on. Two concurrent operations on the same
// blob are otherwise indistinguishable, which is exactly the case a failing AEAD tag poses: the
// question is whether this decrypt was handed the nonce belonging to its own ciphertext, and with
// only op[<blob>] to go on, the begin that carried that nonce cannot be identified. Our own
// operations print the TA's real handle, so a line here and a line from the TA name the same thing;
// a forwarded one has no handle we can see, so it gets a process-local serial.
std::string OpId(int64_t op_handle) {
  char buf[24];
  snprintf(buf, sizeof(buf), "h%llx", static_cast<unsigned long long>(op_handle));
  return std::string(buf);
}

std::string NextForwardedOpId() {
  static std::atomic<uint32_t> next{0};
  char buf[16];
  snprintf(buf, sizeof(buf), "f%x", next.fetch_add(1, std::memory_order_relaxed));
  return std::string(buf);
}

// --- IKeyMintOperation -------------------------------------------------------

class TeesimKeyMintOperation : public BnKeyMintOperation {
 public:
  // `ctx` is the caller tag captured at begin(): keystore2 drives update/finish/abort on whatever
  // binder thread the app's later calls land on, and getCallingUid there is the app's, but an
  // operation outliving its begin is exactly where an anonymous line would leave us guessing. Carry
  // it with the operation instead of re-deriving it.
  TeesimKeyMintOperation(TaPtr ta, int64_t op_handle, std::string blob_tag, std::string ctx)
      : ta_(std::move(ta)),
        op_handle_(op_handle),
        op_id_(OpId(op_handle)),
        blob_tag_(std::move(blob_tag)),
        ctx_(std::move(ctx)) {}
  ~TeesimKeyMintOperation() override {
    LogContext lc_(ctx_);
    // An operation destroyed without a finish or an abort is keystore2 dropping it — a pruned
    // operation slot, or an app that went away mid-decrypt. Logged so the operation's end is
    // visible, as its forwarded twin's abort is.
    if (!finished_) {
      int32_t rc = teesim_km_abort(ta_.get(), op_handle_);
      LOGD("op[%s/%s] ours dropped without finish: abandoned by keystore2, aborted in the TA rc=%d(%s)",
           blob_tag_.c_str(), op_id_.c_str(), rc, teesim_km_err_name(rc));
    }
  }

  ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& input,
                               const std::optional<HardwareAuthToken>& authToken,
                               const std::optional<secureclock::TimeStampToken>& tst) override {
    LogContext lc_(ctx_);
    TsAuthToken at;
    TsTimestampToken tt;
    int32_t rc = teesim_km_update_aad(ta_.get(), op_handle_, input.data(), input.size(),
                                      FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt));
    LogOp("ours update_aad", rc, "aad=%zu", input.size());
    return Status(rc);
  }

  ndk::ScopedAStatus update(const std::vector<uint8_t>& input,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    TsAuthToken at;
    TsTimestampToken tt;
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_update(ta_.get(), op_handle_, input.data(), input.size(),
                                  FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt), &buf, &len);
    in_total_ += input.size();
    LogOp("ours update", rc, "in=%zu out=%zu in_total=%zu", input.size(), len, in_total_);
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& input,
                            const std::optional<std::vector<uint8_t>>& signature,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            const std::optional<std::vector<uint8_t>>& confirmationToken,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    const uint8_t* in_ptr = input ? input->data() : nullptr;
    size_t in_len = input ? input->size() : 0;
    const uint8_t* sig_ptr = signature ? signature->data() : nullptr;
    size_t sig_len = signature ? signature->size() : 0;
    const uint8_t* conf_ptr = confirmationToken ? confirmationToken->data() : nullptr;
    size_t conf_len = confirmationToken ? confirmationToken->size() : 0;
    TsAuthToken at;
    TsTimestampToken tt;
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_finish(ta_.get(), op_handle_, in_ptr, in_len, sig_ptr, sig_len,
                                  FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt), conf_ptr,
                                  conf_len, &buf, &len);
    finished_ = true;
    // in_total is what the tag check actually consumed: for GCM the reference TA
    // holds the trailing tag back from update() and verifies it here, so a finish
    // with no input is normal and the interesting number is everything before it.
    LogOp("ours finish", rc, "in=%zu sig=%zu in_total=%zu out=%zu", in_len, sig_len,
          in_total_ + in_len, len);
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus abort() override {
    LogContext lc_(ctx_);
    finished_ = true;
    int32_t rc = teesim_km_abort(ta_.get(), op_handle_);
    LogOp("ours abort", rc, "in_total=%zu", in_total_);
    return Status(rc);
  }

 private:
  // One line per call, at the level the outcome earns: a non-zero rc is a failure the app sees, so it
  // logs at WARN while successes stay at DEBUG. The error is named rather than left as a bare number.
  __attribute__((format(printf, 4, 5)))
  void LogOp(const char* what, int32_t rc, const char* fmt, ...) {
    char detail[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    if (rc == 0) {
      LOGD("op[%s/%s] %s: %s rc=0", blob_tag_.c_str(), op_id_.c_str(), what, detail);
    } else {
      LOGW("op[%s/%s] %s FAILED: rc=%d(%s) %s", blob_tag_.c_str(), op_id_.c_str(), what, rc,
           teesim_km_err_name(rc), detail);
    }
  }

  TaPtr ta_;
  int64_t op_handle_;
  std::string op_id_;
  std::string blob_tag_;
  std::string ctx_;
  size_t in_total_ = 0;
  bool finished_ = false;
};

// --- IKeyMintOperation, forwarded --------------------------------------------
//
// A forwarded begin used to hand keystore2 the real HAL's operation object, after
// which update/finish went straight there and nothing about them was observable
// here. That is precisely the case that needs watching -- a non-target app whose
// decrypt fails its tag in the real TA -- so wrap the operation and delegate. Every
// call is passed through untouched; only the counts are recorded.
class ForwardedKeyMintOperation : public BnKeyMintOperation {
 public:
  ForwardedKeyMintOperation(std::shared_ptr<IKeyMintOperation> real, std::string blob_tag,
                            std::string op_id, std::string ctx)
      : real_(std::move(real)),
        blob_tag_(std::move(blob_tag)),
        op_id_(std::move(op_id)),
        ctx_(std::move(ctx)) {}

  ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& input,
                               const std::optional<HardwareAuthToken>& authToken,
                               const std::optional<secureclock::TimeStampToken>& tst) override {
    LogContext lc_(ctx_);
    ForwardGuard g;
    auto st = real_->updateAad(input, authToken, tst);
    LogOp("real update_aad", st, "aad=%zu", input.size());
    return st;
  }

  ndk::ScopedAStatus update(const std::vector<uint8_t>& input,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    ForwardGuard g;
    auto st = real_->update(input, authToken, tst, out);
    in_total_ += input.size();
    LogOp("real update", st, "in=%zu out=%zu in_total=%zu", input.size(),
          out ? out->size() : 0, in_total_);
    return st;
  }

  ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& input,
                            const std::optional<std::vector<uint8_t>>& signature,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            const std::optional<std::vector<uint8_t>>& confirmationToken,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    ForwardGuard g;
    auto st = real_->finish(input, signature, authToken, tst, confirmationToken, out);
    const size_t in_len = input ? input->size() : 0;
    // from=real-hal is the fact that decides whether a failure here is ours: the module forwarded
    // the call untouched and the real hardware is what rejected it.
    LogOp("real finish", st, "in=%zu sig=%zu in_total=%zu out=%zu from=real-hal", in_len,
          signature ? signature->size() : 0, in_total_ + in_len, out ? out->size() : 0);
    return st;
  }

  ndk::ScopedAStatus abort() override {
    LogContext lc_(ctx_);
    ForwardGuard g;
    auto st = real_->abort();
    LogOp("real abort", st, "in_total=%zu", in_total_);
    return st;
  }

 private:
  // The forwarded twin of TeesimKeyMintOperation::LogOp: a real-hardware rejection logs at WARN with
  // its status named, so it never reads like a success.
  __attribute__((format(printf, 4, 5)))
  void LogOp(const char* what, const ndk::ScopedAStatus& st, const char* fmt, ...) {
    char detail[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    if (st.isOk()) {
      LOGD("op[%s/%s] %s: %s rc=0", blob_tag_.c_str(), op_id_.c_str(), what, detail);
    } else {
      LOGW("op[%s/%s] %s FAILED: %s %s", blob_tag_.c_str(), op_id_.c_str(), what,
           StatusDesc(st).c_str(), detail);
    }
  }

  std::shared_ptr<IKeyMintOperation> real_;
  std::string blob_tag_;
  std::string op_id_;
  std::string ctx_;
  size_t in_total_ = 0;
};

// --- IKeyMintDevice ----------------------------------------------------------

class TeesimKeyMintDevice : public BnKeyMintDevice {
 public:
  TeesimKeyMintDevice(SecurityLevel level, std::shared_ptr<IKeyMintDevice> real)
      : level_(level), real_(std::move(real)) {}

  ndk::ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info) override {
    LogContext lc_(RequestCtx());
    if (real_) {
      ForwardGuard g;
      return real_->getHardwareInfo(info);
    }
    info->versionNumber = 400;
    info->securityLevel = level_;
    info->keyMintName = "TEESimulator";
    info->keyMintAuthorName = "TEESimulator";
    info->timestampTokenRequired = false;
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus generateKey(const std::vector<KeyParameter>& keyParams,
                                 const std::optional<AttestationKey>& attestationKey,
                                 KeyCreationResult* out) override {
    LogContext lc_(RequestCtx());
    const uid_t caller_uid = AIBinder_getCallingUid();
    RecordUsage(static_cast<int32_t>(caller_uid));  // every app that asks for a key, for the daemon's usage view
    RequestTarget t = ProfileForRequest(keyParams, caller_uid, level_);
    TsRkpVerdict rkp{};
    teesim_hook_take_rkp_verdict(&rkp);
    // A verdict recorded more than this long ago cannot belong to the request in hand: keystore2
    // resolves the attest key immediately before calling generateKey on the same thread. An older
    // one was armed for a request it then abandoned, and reporting it here would attribute another
    // app's gate decision to this key.
    constexpr uint32_t kRkpFreshMs = 2000;
    const bool rkp_none = std::strcmp(rkp.verdict, "none") == 0;
    const bool rkp_stale = !rkp_none && rkp.age_ms > kRkpFreshMs;
    // "none" has no uid, no rid and no age to report, and it is the common case — most requests
    // never reach the gate at all. Printing three placeholder fields for it would put noise on
    // every line to say nothing happened.
    char rkp_gate[96];
    if (rkp_none) {
      snprintf(rkp_gate, sizeof(rkp_gate), "none");
    } else {
      snprintf(rkp_gate, sizeof(rkp_gate), "%s(uid=%d,r%04x,%ums%s)", rkp.verdict, rkp.uid, rkp.rid,
               rkp.age_ms, rkp_stale ? ",STALE" : "");
    }
    // Only a target app's own call earns INFO: every OTHER app on the device calling generateKey
    // (the overwhelming majority of calls this router ever sees) is not our concern, and at INFO its
    // parameters would drown the target-app lines this exists for.
    if (t.ta) {
      LOGI("generateKey: level=%s, profile=%s, %s, caller_attest_key=%d, patch_mode=%d, "
           "strongbox_ok=%d, rkp_gate=%s",
           LevelName(level_), t.id.empty() ? "-" : t.id.c_str(), KeyShape(keyParams).c_str(),
           attestationKey.has_value(), t.patch_mode, g_strongbox_ok, rkp_gate);
      LOGI("generateKey: params=%s", ParamsDesc(keyParams).c_str());
    } else {
      LOGD("generateKey: level=%s, %s, caller_attest_key=%d, not a target, rkp_gate=%s",
           LevelName(level_), KeyShape(keyParams).c_str(), attestationKey.has_value(), rkp_gate);
      LOGD("generateKey: params=%s", ParamsDesc(keyParams).c_str());
    }
    // An attest key decides everything that follows — a foreign one can only ever be forwarded, and
    // the leaf it signs keeps the real root of trust — so name it here, next to the gate verdict that
    // let it through. "rkp_gate=none" with an attest key present means keystore2 obtained it without
    // ever calling the getRegistration we hook: the key came from somewhere our gate cannot see.
    if (attestationKey) {
      const bool ours = IsOurs(attestationKey->keyBlob);
      LOGI("generateKey: attest key=%s, blob_len=%zu, ours=%d, issuer_len=%zu (%s)",
           BlobTag(attestationKey->keyBlob).c_str(), attestationKey->keyBlob.size(), ours,
           attestationKey->issuerSubjectName.size(),
           ours ? "ours: its leaves stay keybox-rooted"
                : "foreign: we hold no private half, so this leaf keeps the REAL root of trust");
      // On an RKP-only level the gate cannot force keystore2 to fall back to an unattested key:
      // denying getRegistration makes key generation fail instead.  If the key that consequently
      // arrives here is foreign, neither patch mode nor harvested root-of-trust values can affect
      // the leaf that the real hardware signs, or the remotely provisioned chain keystore2 appends.
      // Call this case out separately; the ordinary "foreign" message can otherwise suggest that
      // purging an app-created attest key will fix a freshly injected RKP key.
      if (!ours && !rkp_stale &&
          std::strcmp(rkp.verdict, "allowed-rkp-only-level") == 0) {
        LOGW("generateKey: RKP-only level supplied a foreign attest key; this target's leaf and "
             "appended RKP chain expose the REAL device state (patch mode and harvested "
             "RootOfTrust values do not apply)");
      }
    }
    if (!t.ta) {
      if (real_) {
        LOGD("generateKey: forwarding to real HAL (not a target)");
        ForwardGuard g;
        auto st = real_->generateKey(keyParams, attestationKey, out);
        if (!st.isOk()) LOGW("generateKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    // A target's symmetric key is forwarded, not simulated (see IsAsymmetricKeyRequest). An attest
    // key is always asymmetric, so this never diverts one.
    if (!IsAsymmetricKeyRequest(keyParams)) {
      if (real_) {
        LOGI("generateKey: symmetric key; forwarding to the real HAL (never attested, kept in the "
             "real TEE)");
        ForwardGuard g;
        auto st = real_->generateKey(keyParams, attestationKey, out);
        if (!st.isOk())
          LOGW("generateKey: FAILED in the real HAL (symmetric): %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    // Creating an ATTESTATION KEY (ATTEST_KEY purpose) always mints it in the TA (ours). Unless the
    // caller named one of our keys as its attest key (the "ours" case just below), we ignore any
    // injected attest key and self-attest the new key under the keybox. This MUST come before the
    // attestationKey branch below: on TrustedEnvironment, attesting a new attest key that carries a
    // challenge makes keystore2 inject an RKP-provisioned (real hardware) key — which that branch would
    // forward, leaving us a foreign attest key we can never re-root. We must hold this key's private key
    // so the leaves it later signs get a patched root of trust. (StrongBox has no RKP, so its attest-key
    // creation already arrived with no injected key — exactly why StrongBox worked and TE did not.)
    if (IsAttestKeyRequest(keyParams)) {
      // An attest key created via setAttestKeyAlias(A) arrives with A's blob injected: the app is
      // building a key graph A -> B and expects B's leaf to be SIGNED BY A (so verifying B under A's
      // public key succeeds). If A is ours we must honor that — sign B's leaf with A in the TA — or the
      // graph breaks and B's leaf verifies under neither A nor the keybox, a signature no real KeyMint
      // could produce and a reliable "leaf re-rooted" tell. Only self-attest under the keybox when there
      // is no injected key, or a FOREIGN one (an RKP key keystore2 injected for a bare challenge) we
      // cannot re-root anyway.
      if (attestationKey && IsOurs(attestationKey->keyBlob)) {
        LOGI("generateKey: attest-key creation attested by our attest key; signing its leaf with it (preserving the A->B chain)");
        return Simulate(t.ta.get(), keyParams, attestationKey, out);
      }
      LOGI("generateKey: attest-key creation -> forced generation in the TA (no usable injected attest key)");
      return Simulate(t.ta.get(), keyParams, std::nullopt, out);
    }
    // A leaf that carries an attest key: keystore2 appends that attest key's OWN stored certificate chain
    // to the leaf we return, so we emit ONLY the leaf, never extra certificates.
    if (attestationKey) {
      if (IsOurs(attestationKey->keyBlob)) {
        // Our attest key: sign the leaf with it in the TA (RoT patched, keybox-rooted). keystore2
        // appends the attest key's own keybox chain. This is the path an app hits once its attest key
        // was generated by us above.
        LOGI("generateKey: attest key is ours; signing the leaf with it (no extra certs)");
        return Simulate(t.ta.get(), keyParams, attestationKey, out);
      }
      // Foreign attest key on a leaf — an RKP key keystore2 injected for a bare challenge, or one made
      // before we covered the app. Forward so the real hardware signs the leaf and keystore2 appends the
      // key's chain. This leaf keeps the real root of trust; the durable fix is that attest keys are now
      // ours (above), so an app that uses its own attest key takes the "ours" path.
      LOGI("generateKey: foreign attest key (blob_len=%zu); forwarding to real HAL, no extra certs",
           attestationKey->keyBlob.size());
      if (!real_) {
        // No real HAL to forward to (a device built without one). We cannot mint under a foreign
        // attest key ourselves, so fail rather than dereference a null proxy.
        LOGW("generateKey: foreign attest key but no real HAL; failing");
        return NoRealHal(__func__);
      }
      ForwardGuard g;
      auto st = real_->generateKey(keyParams, attestationKey, out);
      if (!st.isOk()) {
        LOGW("generateKey: FAILED in the real HAL under a foreign attest key: %s",
             StatusDesc(st).c_str());
      }
      return st;
    }
    // No attest key. Patch mode re-roots the real hardware leaf under the keybox; a StrongBox that cannot
    // attest (g_strongbox_ok=false), or no real HAL, generates instead.
    if (t.patch_mode && real_ && (level_ != SecurityLevel::STRONGBOX || g_strongbox_ok)) {
      return PatchAttest(t.ta.get(), keyParams, out);
    }
    return Simulate(t.ta.get(), keyParams, attestationKey, out);
  }

  ndk::ScopedAStatus importKey(const std::vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                               const std::vector<uint8_t>& keyData,
                               const std::optional<AttestationKey>& attestationKey,
                               KeyCreationResult* out) override {
    LogContext lc_(RequestCtx());
    RequestTarget t = ProfileForRequest(keyParams, AIBinder_getCallingUid(), level_);
    TaPtr ta = t.ta;
    // importKey creates a key exactly as generateKey does, so it is logged the same way: only a
    // target's own call earns INFO; every other app importing a key of its own is not our concern.
    if (ta) {
      LOGI("importKey: level=%s, profile=%s, %s, format=%s, key_data_len=%zu, "
           "caller_attest_key=%d, patch_mode=%d",
           LevelName(level_), t.id.empty() ? "-" : t.id.c_str(), KeyShape(keyParams).c_str(),
           toString(keyFormat).c_str(), keyData.size(), attestationKey.has_value(),
           t.patch_mode);
      LOGI("importKey: params=%s", ParamsDesc(keyParams).c_str());
    } else {
      LOGD("importKey: level=%s, %s, format=%s, key_data_len=%zu, not a target",
           LevelName(level_), KeyShape(keyParams).c_str(), toString(keyFormat).c_str(),
           keyData.size());
      LOGD("importKey: params=%s", ParamsDesc(keyParams).c_str());
    }
    if (!ta) {
      if (real_) {
        LOGD("importKey: forwarding to real HAL (not a target)");
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, attestationKey, out);
        if (!st.isOk()) LOGW("importKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    // As in generateKey, a symmetric key is forwarded rather than simulated.
    if (!IsAsymmetricKeyRequest(keyParams)) {
      if (real_) {
        LOGI("importKey: symmetric key; forwarding to the real HAL (never attested, kept in the "
             "real TEE)");
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, attestationKey, out);
        if (!st.isOk())
          LOGW("importKey: FAILED in the real HAL (symmetric): %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    // As in generateKey: a foreign attest key can't be used by our TA — forward instead.
    if (attestationKey && !IsOurs(attestationKey->keyBlob)) {
      if (real_) {
        LOGI("importKey: attest key is not ours; forwarding to real HAL");
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, attestationKey, out);
        if (!st.isOk()) LOGW("importKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    int32_t rc = teesim_km_import_key(ta.get(), km.data(), km.size(),
                                      static_cast<int32_t>(keyFormat), keyData.data(), keyData.size(),
                                      ak.blob, ak.blob_len, ak.params.data(), ak.params.size(),
                                      ak.issuer, ak.issuer_len, &res);
    if (rc != 0) {
      LOGW("importKey: FAILED in the TA: rc=%d(%s)", rc, teesim_km_err_name(rc));
      return Status(rc);
    }
    FillCreationResult(res, out);
    teesim_km_free_result(res);
    LOGI("importKey: emitted %zu-cert chain (imported into the TA) key=%s blob_len=%zu",
         out->certificateChain.size(), BlobTag(out->keyBlob).c_str(), out->keyBlob.size());
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                           const std::vector<KeyParameter>& params,
                           const std::optional<HardwareAuthToken>& authToken,
                           BeginResult* out) override {
    LogContext lc_(RequestCtx());
    const std::string blob_tag = BlobTag(keyBlob);
    // One line per begin, written once the outcome is known: it names the operation every later
    // line of it carries. A failure carries the same description.
    const std::string what = "purpose=" + toString(purpose) + ", key=" + blob_tag +
                             ", blob_len=" + std::to_string(keyBlob.size()) +
                             ", params=" + ParamsDesc(params);
    if (!IsOurs(keyBlob)) {
      if (real_) {
        ForwardGuard g;
        auto st = real_->begin(purpose, keyBlob, params, authToken, out);
        if (!st.isOk()) {
          LOGW("begin: FAILED in the real HAL: %s; %s", StatusDesc(st).c_str(), what.c_str());
          return st;
        }
        if (out->operation) {
          // The id is minted here and printed on both this line and every later line of the
          // operation, so a finish that fails names the begin that carried its nonce.
          std::string op_id = NextForwardedOpId();
          LOGD("begin: %s -> real HAL op[%s/%s]", what.c_str(), blob_tag.c_str(), op_id.c_str());
          out->operation = ndk::SharedRefBase::make<ForwardedKeyMintOperation>(
              out->operation, blob_tag, std::move(op_id), teesim_log_context());
        }
        return st;
      }
      return NoRealHal(__func__);
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);
    auto km = ToKmVec(params);
    TsAuthToken at;
    TsBeginResult* res = nullptr;
    int32_t rc = teesim_km_begin(ta.get(), static_cast<int32_t>(purpose), keyBlob.data(),
                                 keyBlob.size(), km.data(), km.size(), FlattenAuth(authToken, &at),
                                 &res);
    if (rc != 0) {
      LOGW("begin: FAILED in the TA: rc=%d(%s); %s", rc, teesim_km_err_name(rc), what.c_str());
      return Status(rc);
    }
    out->challenge = teesim_km_begin_challenge(res);
    size_t n = teesim_km_begin_num_params(res);
    out->params.reserve(n);
    for (size_t i = 0; i < n; ++i) {
      KmParam p{};
      teesim_km_begin_param(res, i, &p);
      out->params.push_back(FromKm(p));
    }
    int64_t op_handle = teesim_km_begin_op_handle(res);
    teesim_km_free_begin(res);
    LOGD("begin: %s -> TA op[%s/%s]", what.c_str(), blob_tag.c_str(), OpId(op_handle).c_str());
    out->operation =
        ndk::SharedRefBase::make<TeesimKeyMintOperation>(ta, op_handle, blob_tag,
                                                        teesim_log_context());
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus deleteKey(const std::vector<uint8_t>& keyBlob) override {
    LogContext lc_(RequestCtx());
    // keystore2 garbage-collects superseded real blobs on its own thread; only a delete of one of
    // our keys is an event worth INFO.
    if (IsOurs(keyBlob)) {
      LOGI("deleteKey: key=%s, blob_len=%zu, ours=1", BlobTag(keyBlob).c_str(), keyBlob.size());
    } else {
      LOGD("deleteKey: key=%s, blob_len=%zu, ours=0", BlobTag(keyBlob).c_str(), keyBlob.size());
    }
    if (!IsOurs(keyBlob)) {
      if (real_) {
        ForwardGuard g;
        return real_->deleteKey(keyBlob);
      }
      return ndk::ScopedAStatus::ok();
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);
    return Status(teesim_km_delete_key(ta.get(), keyBlob.data(), keyBlob.size()));
  }

  ndk::ScopedAStatus upgradeKey(const std::vector<uint8_t>& keyBlobToUpgrade,
                                const std::vector<KeyParameter>& upgradeParams,
                                std::vector<uint8_t>* out) override {
    LogContext lc_(RequestCtx());
    // An upgrade is the one operation that legitimately replaces a blob, so it is
    // the one place a key can quietly stop being the key that encrypted an app's
    // data. Log what went in and what came back out.
    LOGI("upgradeKey: key=%s, blob_len=%zu, ours=%d, params=%s", BlobTag(keyBlobToUpgrade).c_str(),
         keyBlobToUpgrade.size(), IsOurs(keyBlobToUpgrade), ParamsDesc(upgradeParams).c_str());
    if (!IsOurs(keyBlobToUpgrade)) {
      if (real_) {
        ForwardGuard g;
        auto st = real_->upgradeKey(keyBlobToUpgrade, upgradeParams, out);
        if (!st.isOk()) {
          LOGW("upgradeKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
          return st;
        }
        LOGI("upgradeKey: real HAL returned key=%s, blob_len=%zu",
             out ? BlobTag(*out).c_str() : "-", out ? out->size() : 0);
        return st;
      }
      return NoRealHal(__func__);
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);
    auto km = ToKmVec(upgradeParams);
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_upgrade_key(ta.get(), keyBlobToUpgrade.data(), keyBlobToUpgrade.size(),
                                       km.data(), km.size(), &buf, &len);
    if (rc != 0) {
      LOGW("upgradeKey: FAILED in the TA: rc=%d(%s)", rc, teesim_km_err_name(rc));
      return Status(rc);
    }
    out->assign(buf, buf + len);
    LOGI("upgradeKey: TA returned key=%s, blob_len=%zu", BlobTag(*out).c_str(), out->size());
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& keyBlob,
                                           const std::vector<uint8_t>& appId,
                                           const std::vector<uint8_t>& appData,
                                           std::vector<KeyCharacteristics>* out) override {
    LogContext lc_(RequestCtx());
    LOGD("getKeyCharacteristics: key=%s, blob_len=%zu, ours=%d", BlobTag(keyBlob).c_str(),
         keyBlob.size(), IsOurs(keyBlob));
    if (!IsOurs(keyBlob)) {
      if (real_) {
        ForwardGuard g;
        return real_->getKeyCharacteristics(keyBlob, appId, appData, out);
      }
      return NoRealHal(__func__);
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);
    TsCharacteristics* res = nullptr;
    int32_t rc = teesim_km_get_key_characteristics(ta.get(), keyBlob.data(), keyBlob.size(),
                                                   appId.data(), appId.size(), appData.data(),
                                                   appData.size(), &res);
    if (rc != 0) return Status(rc);
    size_t n_chars = teesim_km_chars_num(res);
    out->resize(n_chars);
    for (size_t ci = 0; ci < n_chars; ++ci) {
      int32_t level = 0;
      size_t n_params = teesim_km_chars_entry(res, ci, &level);
      (*out)[ci].securityLevel = static_cast<SecurityLevel>(level);
      (*out)[ci].authorizations.reserve(n_params);
      for (size_t pi = 0; pi < n_params; ++pi) {
        KmParam km{};
        teesim_km_chars_param(res, ci, pi, &km);
        (*out)[ci].authorizations.push_back(FromKm(km));
      }
    }
    teesim_km_free_chars(res);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& storageKeyBlob,
                                                  std::vector<uint8_t>* out) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->convertStorageKeyToEphemeral(storageKeyBlob, out) : NoRealHal(__func__);
  }

  // Everything below is not simulated; forward to the real HAL when present.
  ndk::ScopedAStatus addRngEntropy(const std::vector<uint8_t>& data) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->addRngEntropy(data) : ndk::ScopedAStatus::ok();
  }
  // Wrapped-key import is always forwarded to the real HAL, even for a target app: the result is a
  // real, unmarked blob whose later operations forward to real hardware, so it is never re-rooted
  // under the keybox. Simulating it would mean unwrapping with the wrapping key inside our TA, which
  // we only hold if that wrapping key was itself minted by us — a rare case not worth the surface.
  ndk::ScopedAStatus importWrappedKey(const std::vector<uint8_t>& wrappedKeyData,
                                      const std::vector<uint8_t>& wrappingKeyBlob,
                                      const std::vector<uint8_t>& maskingKey,
                                      const std::vector<KeyParameter>& unwrappingParams,
                                      int64_t passwordSid, int64_t biometricSid,
                                      KeyCreationResult* out) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey,
                                           unwrappingParams, passwordSid, biometricSid, out)
                 : NoRealHal(__func__);
  }
  ndk::ScopedAStatus deleteAllKeys() override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->deleteAllKeys() : ndk::ScopedAStatus::ok();
  }
  ndk::ScopedAStatus destroyAttestationIds() override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->destroyAttestationIds() : ndk::ScopedAStatus::ok();
  }
  // deviceLocked notifies the HAL that the screen locked, so AUTH_TIMEOUT keys require fresh auth
  // before the timeout would otherwise expire. Our TA (an Android-14 kmr-ta) models device lock only
  // at boot (SetBootInfo), not at runtime, so there is nothing to route here: our auth-timeout keys
  // instead expire on the auth token's own timestamp, checked at begin. We relay to the real HAL for
  // its own (real hardware) keys.
  ndk::ScopedAStatus deviceLocked(bool passwordOnly,
                                  const std::optional<secureclock::TimeStampToken>& tst) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    // deviceLocked is deprecated in the AIDL but still part of the interface we implement, so we
    // relay it verbatim; suppress the deprecation warning for the one forwarding call.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return real_ ? real_->deviceLocked(passwordOnly, tst) : ndk::ScopedAStatus::ok();
#pragma clang diagnostic pop
  }
  ndk::ScopedAStatus earlyBootEnded() override {
    LogContext lc_(RequestCtx());
    // Latch end-of-early-boot on our keys too, so an EARLY_BOOT_ONLY key we minted stops working at
    // the same point keystore2 signals the real HAL. Best-effort: a TA that rejects is only logged.
    for (const auto& ta : AllProfileTas()) {
      int32_t rc = teesim_km_early_boot_ended(ta.get());
      if (rc != 0) LOGW("earlyBootEnded: TA rejected rc=%d(%s)", rc, teesim_km_err_name(rc));
    }
    ForwardGuard g;
    return real_ ? real_->earlyBootEnded() : ndk::ScopedAStatus::ok();
  }
  ndk::ScopedAStatus getRootOfTrustChallenge(std::array<uint8_t, 16>* out) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->getRootOfTrustChallenge(out) : NoRealHal(__func__);
  }
  ndk::ScopedAStatus getRootOfTrust(const std::array<uint8_t, 16>& challenge,
                                    std::vector<uint8_t>* out) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->getRootOfTrust(challenge, out) : NoRealHal(__func__);
  }
  ndk::ScopedAStatus sendRootOfTrust(const std::vector<uint8_t>& rootOfTrust) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->sendRootOfTrust(rootOfTrust) : ndk::ScopedAStatus::ok();
  }
  // Record the additional attestation info (e.g. MODULE_HASH on Android 16) on our TAs as well, so a
  // key we attest carries the same value keystore2 pushes to the real HAL and still matches a genuine
  // device. Applied to every profile since the info is device-wide; best-effort per TA.
  ndk::ScopedAStatus setAdditionalAttestationInfo(const std::vector<KeyParameter>& info) override {
    LogContext lc_(RequestCtx());
    // Latch keystore2's MODULE_HASH as the authoritative value to seed TAs built later this boot: it
    // is the exact bytes the real HAL got, so it matches a genuine device byte-for-byte.
    for (const auto& p : info) {
      if (p.tag == Tag::MODULE_HASH && p.value.getTag() == KeyParameterValue::blob) {
        std::lock_guard<std::mutex> lk(g_cfg_mu);
        g_module_hash = p.value.get<KeyParameterValue::blob>();
      }
    }
    auto km = ToKmVec(info);
    for (const auto& ta : AllProfileTas()) {
      int32_t rc = teesim_km_set_additional_attestation_info(ta.get(), km.data(), km.size());
      if (rc != 0)
        LOGW("setAdditionalAttestationInfo: TA rejected rc=%d(%s)", rc, teesim_km_err_name(rc));
    }
    ForwardGuard g;
    return real_ ? real_->setAdditionalAttestationInfo(info) : ndk::ScopedAStatus::ok();
  }

 private:
  struct AttestKeyArgs {
    const uint8_t* blob = nullptr;
    size_t blob_len = 0;
    std::vector<KmParam> params;
    const uint8_t* issuer = nullptr;
    size_t issuer_len = 0;
  };

  static AttestKeyArgs MakeAttestKey(const std::optional<AttestationKey>& ak) {
    AttestKeyArgs a;
    if (ak) {
      a.blob = ak->keyBlob.data();
      a.blob_len = ak->keyBlob.size();
      a.params = ToKmVec(ak->attestKeyParams);
      a.issuer = ak->issuerSubjectName.data();
      a.issuer_len = ak->issuerSubjectName.size();
    }
    return a;
  }

  // Patch mode: the real hardware generates and attests the key; we keep its genuine, hardware-backed
  // key blob and re-sign only the attestation chain under the keybox, with the root of trust patched
  // to locked/Verified. The kept blob is unmarked, so later operations on the key forward to the real
  // HAL. Falls back to generation only if the real HAL declines outright or the re-signing fails.
  ndk::ScopedAStatus PatchAttest(::Ta* ta, const std::vector<KeyParameter>& keyParams,
                                 KeyCreationResult* out) {
    KeyCreationResult real;
    Elapsed real_el;
    {
      ForwardGuard g;
      // No attest key here — a request that carries one is handled before we reach patch mode (ours is
      // signed in the TA, a foreign one is forwarded whole). Let the real hardware attest with its own
      // batch key; we keep only the leaf and re-sign it under the keybox.
      auto st = real_->generateKey(keyParams, std::nullopt, &real);
      if (!st.isOk()) {
        LOGW("PatchAttest: real generateKey failed (%s) after %llums; generating instead",
             StatusDesc(st).c_str(), real_el.Ms());
        return Simulate(ta, keyParams, std::nullopt, out);
      }
    }
    const unsigned long long real_ms = real_el.Ms();
    if (real.certificateChain.empty()) {
      // A symmetric key (AES/HMAC/3DES) never has a certificate, so an empty chain is the real HAL
      // saying there is nothing to attest — not a failure. Keep the hardware key exactly as it came
      // back: minting our own would move the app's key material into the software TA for no gain in
      // attestation, and an auth-bound key would then be checked against a TA that holds no device
      // HMAC key ("no device HMAC key; accepting auth_token on presence"), which is how fingerprint-
      // bound keys start failing with KEY_USER_NOT_AUTHENTICATED.
      *out = std::move(real);
      LOGI("PatchAttest: real HAL returned no certificates (nothing to attest); keeping the real key "
           "key=%s blob_len=%zu real=%llums",
           BlobTag(out->keyBlob).c_str(), out->keyBlob.size(), real_ms);
      return ndk::ScopedAStatus::ok();
    }
    LOGD("PatchAttest: real HAL returned %zu cert(s) in %llums; re-signing only the leaf under the "
         "keybox",
         real.certificateChain.size(), real_ms);
    const auto& leaf = real.certificateChain.front().encodedCertificate;
    TsCreationResult* res = nullptr;
    Elapsed ta_el;
    int32_t rc = teesim_km_patch_attestation(ta, leaf.data(), leaf.size(), &res);
    const unsigned long long ta_ms = ta_el.Ms();
    if (rc != 0) {
      LOGW("PatchAttest: re-signing the real attestation failed rc=%d(%s); generating instead", rc,
           teesim_km_err_name(rc));
      return Simulate(ta, keyParams, std::nullopt, out);
    }
    // Keep the real hardware key blob and characteristics; swap in the keybox-rooted, RoT-patched
    // chain we just built.
    out->keyBlob = real.keyBlob;
    out->keyCharacteristics = std::move(real.keyCharacteristics);
    size_t n = teesim_km_result_num_certs(res);
    out->certificateChain.resize(n);
    for (size_t i = 0; i < n; ++i) {
      const uint8_t* c = nullptr;
      size_t clen = 0;
      teesim_km_result_cert(res, i, &c, &clen);
      out->certificateChain[i].encodedCertificate.assign(c, c + clen);
    }
    teesim_km_free_result(res);
    // The key tag ties this creation to every later begin, upgrade and delete on the key, so a blob
    // seen at a begin can be traced back to the profile that signed it and whether it was patched or
    // minted.
    LOGI("PatchAttest: emitted %zu-cert chain (real key blob kept, leaf re-rooted at keybox) key=%s "
         "blob_len=%zu real=%llums ta=%llums",
         out->certificateChain.size(), BlobTag(out->keyBlob).c_str(), out->keyBlob.size(), real_ms,
         ta_ms);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus Simulate(::Ta* ta, const std::vector<KeyParameter>& keyParams,
                              const std::optional<AttestationKey>& attestationKey,
                              KeyCreationResult* out) {
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    Elapsed ta_el;
    int32_t rc = teesim_km_generate_key(ta, km.data(), km.size(),
                                        ak.blob, ak.blob_len, ak.params.data(), ak.params.size(),
                                        ak.issuer, ak.issuer_len, &res);
    const unsigned long long ta_ms = ta_el.Ms();
    if (rc != 0) {
      LOGW("Simulate: FAILED in the TA: rc=%d(%s)", rc, teesim_km_err_name(rc));
      return Status(rc);
    }
    FillCreationResult(res, out);
    teesim_km_free_result(res);
    LOGI("Simulate: emitted %zu-cert chain (whole key minted in the TA) key=%s blob_len=%zu "
         "ta=%llums",
         out->certificateChain.size(), BlobTag(out->keyBlob).c_str(), out->keyBlob.size(), ta_ms);
    return ndk::ScopedAStatus::ok();
  }

  SecurityLevel level_;
  std::shared_ptr<IKeyMintDevice> real_;
};

}  // namespace

// --- C entry points ----------------------------------------------------------

extern "C" const char* teesim_hook_name(void) { return "keymint"; }

// Snapshot the usage map as a JSON array (see control.h). Built under the usage
// lock only; no crypto state is touched, so the daemon can poll this freely.
extern "C" char* teesim_usage_json_alloc(void) {
  std::string out = "[";
  {
    std::lock_guard<std::mutex> lk(g_usage_mu);
    bool first = true;
    for (const auto& kv : g_usage) {
      if (!first) out += ",";
      first = false;
      out += "{\"uid\":";
      out += std::to_string(kv.first);
      out += ",\"count\":";
      out += std::to_string(kv.second.count);
      out += ",\"lastBootMs\":";
      out += std::to_string(kv.second.last_boot_ms);
      out += ",\"pkg\":\"";
      // pkg is a plain package name or empty, but escape the JSON-significant bytes defensively.
      for (char c : kv.second.pkg) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
      }
      out += "\"}";
    }
  }
  out += "]";
  char* buf = static_cast<char*>(malloc(out.size() + 1));
  if (buf) memcpy(buf, out.c_str(), out.size() + 1);
  return buf;
}

// Config-staging API (see common/control.h). teesim_cfg_begin/add_profile run on
// the control thread before the swap; only teesim_cfg_commit touches live tables.
extern "C" void teesim_cfg_begin(const TsBootInfo* boot) {
  g_staging.clear();
  g_stage_vb_key.assign(boot->verified_boot_key,
                        boot->verified_boot_key + boot->verified_boot_key_len);
  g_stage_vb_hash.assign(boot->verified_boot_hash,
                         boot->verified_boot_hash + boot->verified_boot_hash_len);
  g_stage_module_hash.assign(boot->module_hash, boot->module_hash + boot->module_hash_len);
  g_stage_locked = boot->device_locked;
  g_stage_vb_state = boot->verified_boot_state;
  g_stage_strongbox_ok = boot->strongbox_available;
  g_stage_attest_version_tee = boot->attest_version_tee;
  g_stage_attest_version_strongbox = boot->attest_version_strongbox;
}

extern "C" bool teesim_cfg_add_profile(const TsProfile* p) {
  // A real device runs a separate KeyMint instance per security level; we mirror that with one fixed-
  // level TA per level. Both are built from the same keybox and boot state, so their key-encryption
  // keys match and any of our blobs decrypts under either — but each stamps its own level into the
  // keys it mints, so operations read a key's characteristics at the level it was minted at with no
  // per-request override. `p->security_level` is retained only for the staged-profile log line.
  auto buildTa = [&](int32_t level) -> ::Ta* {
    return teesim_km_init_ex(p->keybox, p->keybox_len, level, p->os_version, p->os_patchlevel,
                             p->vendor_patchlevel, p->boot_patchlevel, g_stage_vb_key.data(),
                             g_stage_vb_key.size(), g_stage_vb_hash.data(), g_stage_vb_hash.size(),
                             g_stage_locked, g_stage_vb_state, g_stage_attest_version_tee,
                             g_stage_attest_version_strongbox, p->ids);
  };
  ::Ta* ta_tee = buildTa(static_cast<int32_t>(SecurityLevel::TRUSTED_ENVIRONMENT));
  ::Ta* ta_sb = buildTa(static_cast<int32_t>(SecurityLevel::STRONGBOX));
  if (!ta_tee || !ta_sb) {
    LOGE("teesim_cfg_add_profile: profile %s failed to build (bad keybox?)", p->id ? p->id : "?");
    if (ta_tee) teesim_km_destroy(ta_tee);
    if (ta_sb) teesim_km_destroy(ta_sb);
    return false;
  }
  Profile prof;
  prof.id = p->id ? p->id : "";
  prof.ta_tee = WrapTa(ta_tee);
  prof.ta_strongbox = WrapTa(ta_sb);
  prof.patch_mode = p->mode && std::string(p->mode) == "patch";
  // Seed both instances with the device-wide MODULE_HASH so a generation-mode key either mints carries
  // the tag, independent of keystore2's one-shot delivery. Prefer keystore2's captured bytes; fall
  // back to the daemon's computed value when we never saw that call. The reference TA emits the tag
  // only for KeyMint v4+ attestations, so seeding an older-version profile is harmless.
  {
    std::vector<uint8_t> seed;
    {
      std::lock_guard<std::mutex> lk(g_cfg_mu);
      seed = g_module_hash.empty() ? g_stage_module_hash : g_module_hash;
    }
    SeedModuleHash(prof.ta_tee, seed);
    SeedModuleHash(prof.ta_strongbox, seed);
  }
  for (int i = 0; i < p->n_packages && p->packages; ++i) {
    if (!p->packages[i]) continue;
    // No package_users[] at all means an older daemon that only ever targeted the primary user.
    prof.packages.push_back({p->packages[i], p->package_users ? p->package_users[i] : 0});
  }
  for (int i = 0; i < p->n_uids && p->uids; ++i) {
    prof.uids.push_back(p->uids[i]);
    // uid_packages[] is aligned 1:1 with uids[]; a NULL array (older daemon) or a NULL/"" entry (a
    // raw uid:N target) just means the log will carry the bare uid.
    const char* name = (p->uid_packages && p->uid_packages[i]) ? p->uid_packages[i] : "";
    prof.uid_names.emplace_back(name);
  }
  LOGI("teesim_cfg_add_profile: staged profile '%s' (mode=%s, security_level=%s, %zu package(s), "
       "%zu uid(s))",
       prof.id.c_str(), prof.patch_mode ? "patch" : "generation",
       LevelName(static_cast<SecurityLevel>(p->security_level)),
       prof.packages.size(), prof.uids.size());
  for (const auto& pkg : prof.packages)
    LOGD("teesim_cfg_add_profile:   package '%s' in user %d", pkg.name.c_str(), pkg.user_id);
  g_staging.push_back(std::move(prof));
  return true;
}

extern "C" int teesim_cfg_commit(uint64_t /*epoch*/, char* /*err*/, size_t /*err_len*/) {
  int n = 0;
  {
    std::lock_guard<std::mutex> lk(g_cfg_mu);
    g_profiles = std::move(g_staging);
    g_staging.clear();
    g_strongbox_ok = g_stage_strongbox_ok;
    n = static_cast<int>(g_profiles.size());
  }
  // Release anything parked in WaitForDefaultTa now that there is a TA to serve it.
  g_cfg_cv.notify_all();
  return n;
}

// True if `uid` belongs to a live target profile. The transact hook uses this to scope the RKP
// denial to our apps: when a target app's generateKey resolves a remote-provisioned attest key, we
// fail that lookup so keystore2 appends no real-hardware chain and our forced generation stays clean.
extern "C" bool teesim_is_target_uid(int32_t uid) {
  if (uid < 0) return false;
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  for (const auto& prof : g_profiles) {
    for (int32_t u : prof.uids) {
      if (u == uid) return true;
    }
  }
  return false;
}

extern "C" bool teesim_cfg_resign(const char* profile_id, const uint8_t* leaf, size_t leaf_len,
                                  TsCertSink sink, void* ctx) {
  if (!profile_id || !leaf || leaf_len == 0 || !sink) return false;
  LOGI("teesim_cfg_resign: request for profile '%s' (leaf %zu bytes)", profile_id, leaf_len);
  TaPtr ta;
  {
    std::lock_guard<std::mutex> lk(g_cfg_mu);
    for (const auto& prof : g_profiles) {
      if (prof.id == profile_id) {
        // Re-signing is level-independent (same keybox and patched root of trust at either level).
        ta = prof.ta_tee;
        break;
      }
    }
  }
  if (!ta) {
    LOGW("teesim_cfg_resign: unknown profile '%s'", profile_id);
    return false;
  }
  // Re-sign the existing leaf exactly as patch mode does for a fresh key: keep its public key and
  // attestation content, re-root under the keybox with a patched root of trust.
  TsCreationResult* res = nullptr;
  int32_t rc = teesim_km_patch_attestation(ta.get(), leaf, leaf_len, &res);
  if (rc != 0) {
    LOGW("teesim_cfg_resign: patch_attestation failed rc=%d(%s) for profile '%s'", rc,
         teesim_km_err_name(rc), profile_id);
    return false;
  }
  size_t n = teesim_km_result_num_certs(res);
  for (size_t i = 0; i < n; ++i) {
    const uint8_t* c = nullptr;
    size_t clen = 0;
    teesim_km_result_cert(res, i, &c, &clen);
    sink(ctx, c, clen);
  }
  teesim_km_free_result(res);
  return true;
}

// Create a local device wrapping the real HAL binder (may be null). Returns an
// AIBinder* whose ownership passes to the caller (release with AIBinder_decStrong).
//
// `security_level` is only a fallback: the device's real level is derived here
// from the wrapped HAL's own getHardwareInfo(), so we report StrongBox only when a
// real StrongBox HAL exists. This runs once per proxy (the caller caches the
// result), and the ForwardGuard keeps this getHardwareInfo from looping back
// through the interceptor. Any failure leaves the passed fallback in place.
extern "C" AIBinder* teesim_router_new_device(int32_t security_level, AIBinder* real_binder) {
  std::shared_ptr<IKeyMintDevice> real;
  if (real_binder) {
    ndk::SpAIBinder sp(real_binder);
    AIBinder_incStrong(real_binder);  // keep our own reference
    real = IKeyMintDevice::fromBinder(sp);
  }
  if (real) {
    ForwardGuard g;
    KeyMintHardwareInfo hw;
    if (real->getHardwareInfo(&hw).isOk()) {
      security_level = static_cast<int32_t>(hw.securityLevel);
    } else {
      // The level probe failed, so we keep the passed fallback (TEE). This is the one path that could
      // mis-level a SOFTWARE km_compat leg as TEE and wrap it — the SOFTWARE exclusion below keys off
      // this value. getHardwareInfo is an in-process call returning static info, so a failure is not
      // expected; log it so a mis-levelled leg is visible rather than silently assumed TEE.
      LOGW("teesim_router_new_device: getHardwareInfo failed; keeping fallback security_level=%s "
           "(real=%p, remote=%d)", LevelName(static_cast<SecurityLevel>(security_level)), real_binder,
           real_binder ? AIBinder_isRemote(real_binder) : -1);
    }
  }
  // Never wrap a SOFTWARE-level KeyMint. keystore2 serves SecurityLevel::SOFTWARE from an in-process
  // km_compat device on every device — native TEE devices included (only TrustedEnvironment and
  // StrongBox resolve to a native HAL; SOFTWARE always takes the compat fallback). We only simulate the
  // hardware levels; wrapping the software leg would route a target uid's ordinary software keys (via
  // ProfileForRequest's uid fallback) into the TA, so we bail here: LocalFor caches this nullptr and
  // HookedTransact falls through to real_transact, leaving the software path untouched. The early
  // return is ref-balanced — `real` releases its fromBinder reference as it goes out of scope,
  // restoring real_binder to exactly the count keystore2 holds; adding a decStrong here would
  // under-reference it.
  if (static_cast<SecurityLevel>(security_level) == SecurityLevel::SOFTWARE) {
    LOGI("teesim_router_new_device: SOFTWARE-level KeyMint (real=%p, remote=%d); NOT wrapping",
         real_binder, real_binder ? AIBinder_isRemote(real_binder) : -1);
    return nullptr;
  }
  // keystore2 resolves a distinct IKeyMintDevice for TrustedEnvironment (level 1) and, when present,
  // StrongBox (level 2); each is wrapped by its own local device at its real level. remote=0 marks a
  // legacy km_compat leg, remote=1 a native HAL.
  LOGI("teesim_router_new_device: local KeyMint device at security_level=%s (real=%p, remote=%d)",
       LevelName(static_cast<SecurityLevel>(security_level)), real_binder, real_binder ? AIBinder_isRemote(real_binder) : -1);
  auto dev = ndk::SharedRefBase::make<TeesimKeyMintDevice>(
      static_cast<SecurityLevel>(security_level), std::move(real));
  ndk::SpAIBinder b = dev->asBinder();
  AIBinder* raw = b.get();
  AIBinder_incStrong(raw);
  return raw;
}
