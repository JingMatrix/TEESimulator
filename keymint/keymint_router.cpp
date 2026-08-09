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

::Ta* g_ta = nullptr;

// Targeting configuration.
std::mutex g_cfg_mu;
bool g_target_all = false;
std::vector<std::string> g_targets;

// RAII guard: mark the current thread as forwarding to the real HAL.
struct ForwardGuard {
  ForwardGuard() { teesim_hook_set_forwarding(true); }
  ~ForwardGuard() { teesim_hook_set_forwarding(false); }
};

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

// Decide whether a generate/import request is for a target app, by matching the
// configured package names inside the ATTESTATION_APPLICATION_ID value. A request
// with no attestation application id (i.e. no attestation) is never a target.
bool IsTargetRequest(const std::vector<KeyParameter>& params) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  if (g_target_all) return true;
  if (g_targets.empty()) return false;
  for (const auto& p : params) {
    if (p.tag != Tag::ATTESTATION_APPLICATION_ID) continue;
    if (p.value.getTag() != KeyParameterValue::blob) continue;
    const auto& id = p.value.get<KeyParameterValue::blob>();
    std::string hay(id.begin(), id.end());
    for (const auto& t : g_targets) {
      if (hay.find(t) != std::string::npos) return true;
    }
  }
  return false;
}

// --- IKeyMintOperation -------------------------------------------------------

class TeesimKeyMintOperation : public BnKeyMintOperation {
 public:
  explicit TeesimKeyMintOperation(int64_t op_handle) : op_handle_(op_handle) {}
  ~TeesimKeyMintOperation() override {
    if (!finished_) teesim_km_abort(g_ta, op_handle_);
  }

  ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& input,
                               const std::optional<HardwareAuthToken>&,
                               const std::optional<secureclock::TimeStampToken>&) override {
    return Status(teesim_km_update_aad(g_ta, op_handle_, input.data(), input.size()));
  }

  ndk::ScopedAStatus update(const std::vector<uint8_t>& input,
                            const std::optional<HardwareAuthToken>&,
                            const std::optional<secureclock::TimeStampToken>&,
                            std::vector<uint8_t>* out) override {
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_update(g_ta, op_handle_, input.data(), input.size(), &buf, &len);
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
    int32_t rc = teesim_km_finish(g_ta, op_handle_, in_ptr, in_len, sig_ptr, sig_len, &buf, &len);
    finished_ = true;
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus abort() override {
    finished_ = true;
    return Status(teesim_km_abort(g_ta, op_handle_));
  }

 private:
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
    if (real_ && !IsTargetRequest(keyParams)) {
      LOGI("generateKey: forwarding to real HAL (not a target)");
      ForwardGuard g;
      return real_->generateKey(keyParams, attestationKey, out);
    }
    LOGI("generateKey: simulating for target app");
    return Simulate(keyParams, attestationKey, out);
  }

  ndk::ScopedAStatus importKey(const std::vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                               const std::vector<uint8_t>& keyData,
                               const std::optional<AttestationKey>& attestationKey,
                               KeyCreationResult* out) override {
    if (real_ && !IsTargetRequest(keyParams)) {
      ForwardGuard g;
      return real_->importKey(keyParams, keyFormat, keyData, attestationKey, out);
    }
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    int32_t rc = teesim_km_import_key(g_ta, km.data(), km.size(), static_cast<int32_t>(keyFormat),
                                      keyData.data(), keyData.size(), ak.blob, ak.blob_len,
                                      ak.params.data(), ak.params.size(), ak.issuer, ak.issuer_len,
                                      &res);
    if (rc != 0) return Status(rc);
    FillCreationResult(res, out);
    teesim_km_free_result(res);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                           const std::vector<KeyParameter>& params,
                           const std::optional<HardwareAuthToken>& authToken,
                           BeginResult* out) override {
    if (real_ && !IsOurs(keyBlob)) {
      ForwardGuard g;
      return real_->begin(purpose, keyBlob, params, authToken, out);
    }
    auto km = ToKmVec(params);
    TsBeginResult* res = nullptr;
    int32_t rc = teesim_km_begin(g_ta, static_cast<int32_t>(purpose), keyBlob.data(),
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
    out->operation = ndk::SharedRefBase::make<TeesimKeyMintOperation>(op_handle);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus deleteKey(const std::vector<uint8_t>& keyBlob) override {
    if (real_ && !IsOurs(keyBlob)) {
      ForwardGuard g;
      return real_->deleteKey(keyBlob);
    }
    return Status(teesim_km_delete_key(g_ta, keyBlob.data(), keyBlob.size()));
  }

  ndk::ScopedAStatus upgradeKey(const std::vector<uint8_t>& keyBlobToUpgrade,
                                const std::vector<KeyParameter>& upgradeParams,
                                std::vector<uint8_t>* out) override {
    if (real_ && !IsOurs(keyBlobToUpgrade)) {
      ForwardGuard g;
      return real_->upgradeKey(keyBlobToUpgrade, upgradeParams, out);
    }
    auto km = ToKmVec(upgradeParams);
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_upgrade_key(g_ta, keyBlobToUpgrade.data(), keyBlobToUpgrade.size(),
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
    if (real_ && !IsOurs(keyBlob)) {
      ForwardGuard g;
      return real_->getKeyCharacteristics(keyBlob, appId, appData, out);
    }
    TsCharacteristics* res = nullptr;
    int32_t rc = teesim_km_get_key_characteristics(g_ta, keyBlob.data(), keyBlob.size(),
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
    return real_ ? real_->deviceLocked(passwordOnly, tst) : ndk::ScopedAStatus::ok();
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

  ndk::ScopedAStatus Simulate(const std::vector<KeyParameter>& keyParams,
                              const std::optional<AttestationKey>& attestationKey,
                              KeyCreationResult* out) {
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    int32_t rc = teesim_km_generate_key(g_ta, km.data(), km.size(), ak.blob, ak.blob_len,
                                        ak.params.data(), ak.params.size(), ak.issuer,
                                        ak.issuer_len, &res);
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

extern "C" bool teesim_router_init(const char* keybox_xml, size_t len) {
  if (g_ta) return true;
  g_ta = teesim_km_init(reinterpret_cast<const uint8_t*>(keybox_xml), len);
  return g_ta != nullptr;
}

extern "C" void teesim_router_configure(bool target_all, const char* const* pkgs, int n) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  g_target_all = target_all;
  g_targets.clear();
  for (int i = 0; i < n && pkgs; ++i) {
    if (pkgs[i]) g_targets.emplace_back(pkgs[i]);
  }
}

// Create a local device wrapping the real HAL binder (may be null). Returns an
// AIBinder* whose ownership passes to the caller (release with AIBinder_decStrong).
extern "C" AIBinder* teesim_router_new_device(int32_t security_level, AIBinder* real_binder) {
  std::shared_ptr<IKeyMintDevice> real;
  if (real_binder) {
    ndk::SpAIBinder sp(real_binder);
    AIBinder_incStrong(real_binder);  // keep our own reference
    real = IKeyMintDevice::fromBinder(sp);
  }
  auto dev = ndk::SharedRefBase::make<TeesimKeyMintDevice>(
      static_cast<SecurityLevel>(security_level), std::move(real));
  ndk::SpAIBinder b = dev->asBinder();
  AIBinder* raw = b.get();
  AIBinder_incStrong(raw);
  return raw;
}
