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
#include <android/binder_ibinder.h>  // AIBinder_getCallingUid

#include <ctime>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "control.h"
#include "logging.hpp"
#include "teesim_km.h"

using namespace aidl::android::hardware::security::keymint;
namespace secureclock = aidl::android::hardware::security::secureclock;

// Set by the router around calls into the real HAL so the interceptor lets those
// transactions through instead of looping back to us. Defined in keymint_hook.cpp.
extern "C" void teesim_hook_set_forwarding(bool forwarding);

namespace {

// A TA is reference-counted so an in-flight operation keeps its profile's TA
// alive even if a config reload swaps or drops that profile underneath it.
using TaPtr = std::shared_ptr<::Ta>;
TaPtr WrapTa(::Ta* ta) {
  return TaPtr(ta, [](::Ta* t) {
    if (t) teesim_km_destroy(t);
  });
}

// A configured profile: its TA, the package names routed to it, and whether it patches the real
// hardware attestation (patch mode) or mints the whole key in the TA (generation mode).
struct Profile {
  std::string id;
  TaPtr ta;
  std::vector<std::string> packages;
  std::vector<int32_t> uids;  // resolved caller uids, for requests that carry no app-id to match
  bool patch_mode = false;
};

// Live routing, swapped atomically by teesim_cfg_commit under g_cfg_mu.
std::mutex g_cfg_mu;
std::vector<Profile> g_profiles;
TaPtr g_default_ta;  // serves ops on our blobs; any profile's TA decrypts them
bool g_strongbox_ok = false;  // device can patch real StrongBox keys; else StrongBox forces generation

// Staging state built up by teesim_cfg_begin/add_profile before the swap.
std::vector<Profile> g_staging;
std::vector<uint8_t> g_stage_vb_key;
std::vector<uint8_t> g_stage_vb_hash;
bool g_stage_locked = true;
int32_t g_stage_vb_state = 0;
bool g_stage_strongbox_ok = false;
int32_t g_stage_attest_version_tee = 400;
int32_t g_stage_attest_version_strongbox = 400;

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
};

RequestTarget ProfileForRequest(const std::vector<KeyParameter>& params, uid_t caller_uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  if (g_profiles.empty()) return {};
  // Primary match: the ATTESTATION_APPLICATION_ID the app embeds in the request names its package.
  for (const auto& p : params) {
    if (p.tag != Tag::ATTESTATION_APPLICATION_ID) continue;
    if (p.value.getTag() != KeyParameterValue::blob) continue;
    const auto& id = p.value.get<KeyParameterValue::blob>();
    std::string hay(id.begin(), id.end());
    for (const auto& prof : g_profiles) {
      for (const auto& pkg : prof.packages) {
        if (hay.find(pkg) != std::string::npos) return {prof.ta, prof.patch_mode};
      }
    }
  }
  // Fallback match: the caller's uid. An app creating an attestation KEY does so unattested — no
  // challenge, no app-id — so there is nothing to name-match, yet we must still route it to the app's
  // profile (and mint it in the TA) or the key it later attests is signed by a key we do not hold.
  if (caller_uid != static_cast<uid_t>(-1)) {
    for (const auto& prof : g_profiles) {
      for (int32_t uid : prof.uids) {
        if (static_cast<uid_t>(uid) == caller_uid) return {prof.ta, prof.patch_mode};
      }
    }
  }
  return {};
}

// The TA used for operations on an existing blob of ours (begin/upgrade/etc.).
TaPtr DefaultTa() {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  return g_default_ta;
}

// A snapshot of every configured profile's TA, for device-state transitions (earlyBootEnded /
// setAdditionalAttestationInfo) that must reach all our keys, not just the default profile. The list
// is copied under the config lock so the calls themselves run unlocked.
std::vector<TaPtr> AllProfileTas() {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  std::vector<TaPtr> tas;
  tas.reserve(g_profiles.size());
  for (const auto& p : g_profiles) tas.push_back(p.ta);
  return tas;
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

// --- IKeyMintOperation -------------------------------------------------------

class TeesimKeyMintOperation : public BnKeyMintOperation {
 public:
  TeesimKeyMintOperation(TaPtr ta, int64_t op_handle)
      : ta_(std::move(ta)), op_handle_(op_handle) {}
  ~TeesimKeyMintOperation() override {
    if (!finished_) teesim_km_abort(ta_.get(), op_handle_);
  }

  ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& input,
                               const std::optional<HardwareAuthToken>& authToken,
                               const std::optional<secureclock::TimeStampToken>& tst) override {
    TsAuthToken at;
    TsTimestampToken tt;
    return Status(teesim_km_update_aad(ta_.get(), op_handle_, input.data(), input.size(),
                                       FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt)));
  }

  ndk::ScopedAStatus update(const std::vector<uint8_t>& input,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            std::vector<uint8_t>* out) override {
    TsAuthToken at;
    TsTimestampToken tt;
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_update(ta_.get(), op_handle_, input.data(), input.size(),
                                  FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt), &buf, &len);
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
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus abort() override {
    finished_ = true;
    return Status(teesim_km_abort(ta_.get(), op_handle_));
  }

 private:
  TaPtr ta_;
  int64_t op_handle_;
  bool finished_ = false;
};

// --- IKeyMintDevice ----------------------------------------------------------

class TeesimKeyMintDevice : public BnKeyMintDevice {
 public:
  TeesimKeyMintDevice(SecurityLevel level, std::shared_ptr<IKeyMintDevice> real)
      : level_(level), real_(std::move(real)) {}

  ndk::ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info) override {
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
    const uid_t caller_uid = AIBinder_getCallingUid();
    RecordUsage(static_cast<int32_t>(caller_uid));  // every app that asks for a key, for the daemon's usage view
    RequestTarget t = ProfileForRequest(keyParams, caller_uid);
    LOGI("generateKey: level=%d, %zu param(s), caller_uid=%d, caller_attest_key=%d, target=%d, "
         "patch_mode=%d, strongbox_ok=%d",
         static_cast<int>(level_), keyParams.size(), static_cast<int>(caller_uid),
         attestationKey.has_value(), t.ta != nullptr, t.patch_mode, g_strongbox_ok);
    if (!t.ta) {
      if (real_) {
        LOGI("generateKey: forwarding to real HAL (not a target)");
        ForwardGuard g;
        return real_->generateKey(keyParams, attestationKey, out);
      }
      return Status(-100);
    }
    // Creating an ATTESTATION KEY (ATTEST_KEY purpose) always mints it in the TA (ours) and IGNORES any
    // attest key keystore2 injected to attest it. This MUST come before the attestationKey branch below:
    // on TrustedEnvironment, attesting a new attest key that carries a challenge makes keystore2 inject
    // an RKP-provisioned (real hardware) key — which would otherwise be seen here as a "foreign attest
    // key" and forwarded, leaving us a foreign attest key we can never re-root. We must hold this key's
    // private key so the leaves it later signs get a patched root of trust. (StrongBox has no RKP, so its
    // attest-key creation already arrived with no injected key — exactly why StrongBox worked and TE did
    // not.) Forward std::nullopt: the TA self-attests the new key under the keybox.
    if (IsAttestKeyRequest(keyParams)) {
      LOGI("generateKey: attest-key creation -> forced generation in the TA (ignoring any injected attest key)");
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
        return Status(-100);
      }
      ForwardGuard g;
      return real_->generateKey(keyParams, attestationKey, out);
    }
    // No attest key. Patch mode re-roots the real hardware leaf under the keybox; a StrongBox that cannot
    // attest (g_strongbox_ok=false), or no real HAL, generates instead.
    if (t.patch_mode && real_ && (level_ != SecurityLevel::STRONGBOX || g_strongbox_ok)) {
      LOGI("generateKey: patch mode (re-signing real hardware attestation) for target app");
      return PatchAttest(t.ta.get(), keyParams, out);
    }
    LOGI("generateKey: generation mode for target app");
    return Simulate(t.ta.get(), keyParams, attestationKey, out);
  }

  ndk::ScopedAStatus importKey(const std::vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                               const std::vector<uint8_t>& keyData,
                               const std::optional<AttestationKey>& attestationKey,
                               KeyCreationResult* out) override {
    RequestTarget t = ProfileForRequest(keyParams, AIBinder_getCallingUid());
    TaPtr ta = t.ta;
    if (!ta) {
      if (real_) {
        ForwardGuard g;
        return real_->importKey(keyParams, keyFormat, keyData, attestationKey, out);
      }
      return Status(-100);
    }
    // As in generateKey: a foreign attest key can't be used by our TA — forward instead.
    if (attestationKey && !IsOurs(attestationKey->keyBlob)) {
      if (real_) {
        LOGI("importKey: attest key is not ours; forwarding to real HAL");
        ForwardGuard g;
        return real_->importKey(keyParams, keyFormat, keyData, attestationKey, out);
      }
      return Status(-100);
    }
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    int32_t rc = teesim_km_import_key(ta.get(), km.data(), km.size(), static_cast<int32_t>(level_),
                                      static_cast<int32_t>(keyFormat), keyData.data(), keyData.size(),
                                      ak.blob, ak.blob_len, ak.params.data(), ak.params.size(),
                                      ak.issuer, ak.issuer_len, &res);
    if (rc != 0) return Status(rc);
    FillCreationResult(res, out);
    teesim_km_free_result(res);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                           const std::vector<KeyParameter>& params,
                           const std::optional<HardwareAuthToken>& authToken,
                           BeginResult* out) override {
    LOGI("begin: purpose=%d, blob_len=%zu, ours=%d", static_cast<int>(purpose), keyBlob.size(),
         IsOurs(keyBlob));
    if (!IsOurs(keyBlob)) {
      if (real_) {
        ForwardGuard g;
        return real_->begin(purpose, keyBlob, params, authToken, out);
      }
      return Status(-100);
    }
    TaPtr ta = DefaultTa();
    if (!ta) return Status(-100);
    auto km = ToKmVec(params);
    TsAuthToken at;
    TsBeginResult* res = nullptr;
    int32_t rc = teesim_km_begin(ta.get(), static_cast<int32_t>(purpose), keyBlob.data(),
                                 keyBlob.size(), km.data(), km.size(), FlattenAuth(authToken, &at),
                                 &res);
    if (rc != 0) return Status(rc);
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
    out->operation = ndk::SharedRefBase::make<TeesimKeyMintOperation>(ta, op_handle);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus deleteKey(const std::vector<uint8_t>& keyBlob) override {
    LOGI("deleteKey: blob_len=%zu, ours=%d", keyBlob.size(), IsOurs(keyBlob));
    if (!IsOurs(keyBlob)) {
      if (real_) {
        ForwardGuard g;
        return real_->deleteKey(keyBlob);
      }
      return ndk::ScopedAStatus::ok();
    }
    TaPtr ta = DefaultTa();
    if (!ta) return ndk::ScopedAStatus::ok();
    return Status(teesim_km_delete_key(ta.get(), keyBlob.data(), keyBlob.size()));
  }

  ndk::ScopedAStatus upgradeKey(const std::vector<uint8_t>& keyBlobToUpgrade,
                                const std::vector<KeyParameter>& upgradeParams,
                                std::vector<uint8_t>* out) override {
    LOGI("upgradeKey: blob_len=%zu, ours=%d", keyBlobToUpgrade.size(), IsOurs(keyBlobToUpgrade));
    if (!IsOurs(keyBlobToUpgrade)) {
      if (real_) {
        ForwardGuard g;
        return real_->upgradeKey(keyBlobToUpgrade, upgradeParams, out);
      }
      return Status(-100);
    }
    TaPtr ta = DefaultTa();
    if (!ta) return Status(-100);
    auto km = ToKmVec(upgradeParams);
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_upgrade_key(ta.get(), keyBlobToUpgrade.data(), keyBlobToUpgrade.size(),
                                       km.data(), km.size(), &buf, &len);
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& keyBlob,
                                           const std::vector<uint8_t>& appId,
                                           const std::vector<uint8_t>& appData,
                                           std::vector<KeyCharacteristics>* out) override {
    LOGI("getKeyCharacteristics: blob_len=%zu, ours=%d", keyBlob.size(), IsOurs(keyBlob));
    if (!IsOurs(keyBlob)) {
      if (real_) {
        ForwardGuard g;
        return real_->getKeyCharacteristics(keyBlob, appId, appData, out);
      }
      return Status(-100);
    }
    TaPtr ta = DefaultTa();
    if (!ta) return Status(-100);
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
    ForwardGuard g;
    return real_ ? real_->convertStorageKeyToEphemeral(storageKeyBlob, out) : Status(-100);
  }

  // Everything below is not simulated; forward to the real HAL when present.
  ndk::ScopedAStatus addRngEntropy(const std::vector<uint8_t>& data) override {
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
    ForwardGuard g;
    return real_ ? real_->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey,
                                           unwrappingParams, passwordSid, biometricSid, out)
                 : Status(-100);
  }
  ndk::ScopedAStatus deleteAllKeys() override {
    ForwardGuard g;
    return real_ ? real_->deleteAllKeys() : ndk::ScopedAStatus::ok();
  }
  ndk::ScopedAStatus destroyAttestationIds() override {
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
    ForwardGuard g;
    // deviceLocked is deprecated in the AIDL but still part of the interface we implement, so we
    // relay it verbatim; suppress the deprecation warning for the one forwarding call.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return real_ ? real_->deviceLocked(passwordOnly, tst) : ndk::ScopedAStatus::ok();
#pragma clang diagnostic pop
  }
  ndk::ScopedAStatus earlyBootEnded() override {
    // Latch end-of-early-boot on our keys too, so an EARLY_BOOT_ONLY key we minted stops working at
    // the same point keystore2 signals the real HAL. Best-effort: a TA that rejects is only logged.
    for (const auto& ta : AllProfileTas()) {
      int32_t rc = teesim_km_early_boot_ended(ta.get());
      if (rc != 0) LOGW("earlyBootEnded: TA rejected (%d)", rc);
    }
    ForwardGuard g;
    return real_ ? real_->earlyBootEnded() : ndk::ScopedAStatus::ok();
  }
  ndk::ScopedAStatus getRootOfTrustChallenge(std::array<uint8_t, 16>* out) override {
    ForwardGuard g;
    return real_ ? real_->getRootOfTrustChallenge(out) : Status(-100);
  }
  ndk::ScopedAStatus getRootOfTrust(const std::array<uint8_t, 16>& challenge,
                                    std::vector<uint8_t>* out) override {
    ForwardGuard g;
    return real_ ? real_->getRootOfTrust(challenge, out) : Status(-100);
  }
  ndk::ScopedAStatus sendRootOfTrust(const std::vector<uint8_t>& rootOfTrust) override {
    ForwardGuard g;
    return real_ ? real_->sendRootOfTrust(rootOfTrust) : ndk::ScopedAStatus::ok();
  }
  // Record the additional attestation info (e.g. MODULE_HASH on Android 16) on our TAs as well, so a
  // key we attest carries the same value keystore2 pushes to the real HAL and a verifier that checks
  // it still validates. Applied to every profile since the info is device-wide; best-effort per TA.
  ndk::ScopedAStatus setAdditionalAttestationInfo(const std::vector<KeyParameter>& info) override {
    auto km = ToKmVec(info);
    for (const auto& ta : AllProfileTas()) {
      int32_t rc = teesim_km_set_additional_attestation_info(ta.get(), km.data(), km.size());
      if (rc != 0) LOGW("setAdditionalAttestationInfo: TA rejected (%d)", rc);
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
  // HAL. Falls back to generation if the real HAL declines or returns no attestation to re-sign.
  ndk::ScopedAStatus PatchAttest(::Ta* ta, const std::vector<KeyParameter>& keyParams,
                                 KeyCreationResult* out) {
    KeyCreationResult real;
    {
      ForwardGuard g;
      // No attest key here — a request that carries one is handled before we reach patch mode (ours is
      // signed in the TA, a foreign one is forwarded whole). Let the real hardware attest with its own
      // batch key; we keep only the leaf and re-sign it under the keybox.
      auto st = real_->generateKey(keyParams, std::nullopt, &real);
      if (!st.isOk()) {
        LOGW("patch: real generateKey failed (%d); generating instead", st.getServiceSpecificError());
        return Simulate(ta, keyParams, std::nullopt, out);
      }
    }
    if (real.certificateChain.empty()) {
      LOGW("patch: real attestation returned no certificates; generating instead");
      return Simulate(ta, keyParams, std::nullopt, out);
    }
    LOGI("patch: real HAL returned %zu cert(s); re-signing only the leaf under the keybox",
         real.certificateChain.size());
    const auto& leaf = real.certificateChain.front().encodedCertificate;
    TsCreationResult* res = nullptr;
    int32_t rc = teesim_km_patch_attestation(ta, leaf.data(), leaf.size(), &res);
    if (rc != 0) {
      LOGW("patch: re-signing the real attestation failed (%d); generating instead", rc);
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
    LOGI("patch: emitted %zu-cert chain (real key blob kept, leaf re-rooted at keybox)",
         out->certificateChain.size());
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus Simulate(::Ta* ta, const std::vector<KeyParameter>& keyParams,
                              const std::optional<AttestationKey>& attestationKey,
                              KeyCreationResult* out) {
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    int32_t rc = teesim_km_generate_key(ta, km.data(), km.size(), static_cast<int32_t>(level_),
                                        ak.blob, ak.blob_len, ak.params.data(), ak.params.size(),
                                        ak.issuer, ak.issuer_len, &res);
    if (rc != 0) return Status(rc);
    FillCreationResult(res, out);
    teesim_km_free_result(res);
    LOGI("generate: emitted %zu-cert chain (whole key minted in the TA)",
         out->certificateChain.size());
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
  g_stage_locked = boot->device_locked;
  g_stage_vb_state = boot->verified_boot_state;
  g_stage_strongbox_ok = boot->strongbox_available;
  g_stage_attest_version_tee = boot->attest_version_tee;
  g_stage_attest_version_strongbox = boot->attest_version_strongbox;
}

extern "C" bool teesim_cfg_add_profile(const TsProfile* p) {
  ::Ta* ta = teesim_km_init_ex(p->keybox, p->keybox_len, p->security_level, p->os_version,
                               p->os_patchlevel, p->vendor_patchlevel, p->boot_patchlevel,
                               g_stage_vb_key.data(), g_stage_vb_key.size(), g_stage_vb_hash.data(),
                               g_stage_vb_hash.size(), g_stage_locked, g_stage_vb_state,
                               g_stage_attest_version_tee, g_stage_attest_version_strongbox, p->ids);
  if (!ta) {
    LOGE("keymint: profile %s failed to build (bad keybox?)", p->id ? p->id : "?");
    return false;
  }
  Profile prof;
  prof.id = p->id ? p->id : "";
  prof.ta = WrapTa(ta);
  prof.patch_mode = p->mode && std::string(p->mode) == "patch";
  for (int i = 0; i < p->n_packages && p->packages; ++i) {
    if (p->packages[i]) prof.packages.emplace_back(p->packages[i]);
  }
  for (int i = 0; i < p->n_uids && p->uids; ++i) prof.uids.push_back(p->uids[i]);
  LOGI("cfg: staged profile '%s' (mode=%s, security_level=%d, %zu package(s), %zu uid(s))",
       prof.id.c_str(), prof.patch_mode ? "patch" : "generation", p->security_level,
       prof.packages.size(), prof.uids.size());
  g_staging.push_back(std::move(prof));
  return true;
}

extern "C" int teesim_cfg_commit(uint64_t /*epoch*/, char* /*err*/, size_t /*err_len*/) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  g_profiles = std::move(g_staging);
  g_staging.clear();
  g_default_ta = g_profiles.empty() ? nullptr : g_profiles.front().ta;
  g_strongbox_ok = g_stage_strongbox_ok;
  return static_cast<int>(g_profiles.size());
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
  LOGI("resign: request for profile '%s' (leaf %zu bytes)", profile_id, leaf_len);
  TaPtr ta;
  {
    std::lock_guard<std::mutex> lk(g_cfg_mu);
    for (const auto& prof : g_profiles) {
      if (prof.id == profile_id) {
        ta = prof.ta;
        break;
      }
    }
  }
  if (!ta) {
    LOGW("resign: unknown profile '%s'", profile_id);
    return false;
  }
  // Re-sign the existing leaf exactly as patch mode does for a fresh key: keep its public key and
  // attestation content, re-root under the keybox with a patched root of trust.
  TsCreationResult* res = nullptr;
  int32_t rc = teesim_km_patch_attestation(ta.get(), leaf, leaf_len, &res);
  if (rc != 0) {
    LOGW("resign: patch_attestation failed (%d) for profile '%s'", rc, profile_id);
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
      LOGW("teesim_router_new_device: getHardwareInfo failed; keeping fallback security_level=%d "
           "(real=%p, remote=%d)", security_level, real_binder,
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
  LOGI("teesim_router_new_device: local KeyMint device at security_level=%d (real=%p, remote=%d)",
       security_level, real_binder, real_binder ? AIBinder_isRemote(real_binder) : -1);
  auto dev = ndk::SharedRefBase::make<TeesimKeyMintDevice>(
      static_cast<SecurityLevel>(security_level), std::move(real));
  ndk::SpAIBinder b = dev->asBinder();
  AIBinder* raw = b.get();
  AIBinder_incStrong(raw);
  return raw;
}
