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

#include <cstring>
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

constexpr uint32_t kTagTypeMask = 0xF0000000u;
constexpr uint32_t kTagUlong = 0x50000000u;
constexpr uint32_t kTagDate = 0x60000000u;
constexpr uint32_t kTagBool = 0x70000000u;
constexpr uint32_t kTagBignum = 0x80000000u;
constexpr uint32_t kTagBytes = 0x90000000u;
constexpr uint32_t kTagUlongRep = 0xA0000000u;

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

RequestTarget ProfileForRequest(const std::vector<KeyParameter>& params) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  if (g_profiles.empty()) return {};
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
  return {};
}

// The TA used for operations on an existing blob of ours (begin/upgrade/etc.).
TaPtr DefaultTa() {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  return g_default_ta;
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
  switch (k.tag & kTagTypeMask) {
    case kTagBool:
      kp.value.set<KeyParameterValue::boolValue>(true);
      break;
    case kTagBytes:
    case kTagBignum:
      kp.value.set<KeyParameterValue::blob>(std::vector<uint8_t>(k.blob, k.blob + k.blob_len));
      break;
    case kTagDate:
      kp.value.set<KeyParameterValue::dateTime>(k.int_value);
      break;
    case kTagUlong:
    case kTagUlongRep:
      kp.value.set<KeyParameterValue::longInteger>(k.int_value);
      break;
    default:
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

// --- IKeyMintOperation -------------------------------------------------------

class TeesimKeyMintOperation : public BnKeyMintOperation {
 public:
  TeesimKeyMintOperation(TaPtr ta, int64_t op_handle)
      : ta_(std::move(ta)), op_handle_(op_handle) {}
  ~TeesimKeyMintOperation() override {
    if (!finished_) teesim_km_abort(ta_.get(), op_handle_);
  }

  ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& input,
                               const std::optional<HardwareAuthToken>&,
                               const std::optional<secureclock::TimeStampToken>&) override {
    return Status(teesim_km_update_aad(ta_.get(), op_handle_, input.data(), input.size()));
  }

  ndk::ScopedAStatus update(const std::vector<uint8_t>& input,
                            const std::optional<HardwareAuthToken>&,
                            const std::optional<secureclock::TimeStampToken>&,
                            std::vector<uint8_t>* out) override {
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_update(ta_.get(), op_handle_, input.data(), input.size(), &buf, &len);
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& input,
                            const std::optional<std::vector<uint8_t>>& signature,
                            const std::optional<HardwareAuthToken>&,
                            const std::optional<secureclock::TimeStampToken>&,
                            const std::optional<std::vector<uint8_t>>&,
                            std::vector<uint8_t>* out) override {
    const uint8_t* in_ptr = input ? input->data() : nullptr;
    size_t in_len = input ? input->size() : 0;
    const uint8_t* sig_ptr = signature ? signature->data() : nullptr;
    size_t sig_len = signature ? signature->size() : 0;
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc =
        teesim_km_finish(ta_.get(), op_handle_, in_ptr, in_len, sig_ptr, sig_len, &buf, &len);
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
    RequestTarget t = ProfileForRequest(keyParams);
    if (!t.ta) {
      if (real_) {
        LOGI("generateKey: forwarding to real HAL (not a target)");
        ForwardGuard g;
        return real_->generateKey(keyParams, attestationKey, out);
      }
      return Status(-100);
    }
    // A supplied attest key we did not mint is a real-hardware blob our TA cannot parse;
    // forward the whole request so the real HAL attests it, rather than feeding a foreign
    // blob to the TA (which fails as InvalidKeyBlob).
    if (attestationKey && !IsOurs(attestationKey->keyBlob)) {
      if (real_) {
        LOGI("generateKey: attest key is not ours; forwarding to real HAL");
        ForwardGuard g;
        return real_->generateKey(keyParams, attestationKey, out);
      }
      return Status(-100);
    }
    // Patch mode: let the real hardware generate the key and attest it, then keep its blob and only
    // re-sign the attestation under the keybox with a patched root of trust. It needs working hardware
    // at this level to forward to — a StrongBox that cannot attest (g_strongbox_ok=false), or no real
    // HAL at all, falls back to generation.
    if (t.patch_mode && real_ && (level_ != SecurityLevel::STRONGBOX || g_strongbox_ok)) {
      LOGI("generateKey: patch mode (re-signing real hardware attestation) for target app");
      return PatchAttest(t.ta.get(), keyParams, out);
    }
    LOGI("generateKey: simulating for target app");
    return Simulate(t.ta.get(), keyParams, attestationKey, out);
  }

  ndk::ScopedAStatus importKey(const std::vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                               const std::vector<uint8_t>& keyData,
                               const std::optional<AttestationKey>& attestationKey,
                               KeyCreationResult* out) override {
    RequestTarget t = ProfileForRequest(keyParams);
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
    TsBeginResult* res = nullptr;
    int32_t rc = teesim_km_begin(ta.get(), static_cast<int32_t>(purpose), keyBlob.data(),
                                 keyBlob.size(), km.data(), km.size(), &res);
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
  ndk::ScopedAStatus setAdditionalAttestationInfo(const std::vector<KeyParameter>& info) override {
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
    return ndk::ScopedAStatus::ok();
  }

  SecurityLevel level_;
  std::shared_ptr<IKeyMintDevice> real_;
};

}  // namespace

// --- C entry points ----------------------------------------------------------

extern "C" const char* teesim_hook_name(void) { return "keymint"; }

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

extern "C" bool teesim_cfg_resign(const char* profile_id, const uint8_t* leaf, size_t leaf_len,
                                  TsCertSink sink, void* ctx) {
  if (!profile_id || !leaf || leaf_len == 0 || !sink) return false;
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
    }
  }
  // Confirms which KeyMint HALs we intercept: keystore2 resolves a distinct IKeyMintDevice for
  // TrustedEnvironment (level 1) and, when present, StrongBox (level 2) — both are hooked, each
  // wrapped by its own local device at its real level.
  LOGI("teesim_router_new_device: local KeyMint device at security_level=%d (real=%p)",
       security_level, real_binder);
  auto dev = ndk::SharedRefBase::make<TeesimKeyMintDevice>(
      static_cast<SecurityLevel>(security_level), std::move(real));
  ndk::SpAIBinder b = dev->asBinder();
  AIBinder* raw = b.get();
  AIBinder_incStrong(raw);
  return raw;
}
