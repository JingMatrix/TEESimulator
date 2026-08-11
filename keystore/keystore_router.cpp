// Handler for intercepted IKeystoreService transactions (Android 10/11).
//
// Full simulation via the reference TA: a target app's key never touches the real
// keymaster. We generate the key pair ourselves, hand back its public key, and at
// attestKey time import that key into the TA with the app's challenge so the TA
// issues a keybox-signed attestation over it. The same imported key backs the
// crypto lifecycle — begin/update/finish/abort run against the TA operation, so the
// key is usable for signing, not just attestation. Non-target callers are forwarded.
//
// The service methods deliver their results by transacting back on a callback
// binder passed in the request; the transaction's own reply is just a status.

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>

#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <ctime>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include "control.h"
#include "logging.hpp"
#include "teesim_km.h"

using namespace android;

// IKeystoreService transaction codes (Android 10/11).
enum {
  TX_generateKey = 18,
  TX_getKeyCharacteristics = 19,
  TX_begin = 22,
  TX_update = 23,
  TX_finish = 24,
  TX_abort = 25,
  TX_exportKey = 21,
  TX_attestKey = 29,
};

// KeyMint/Keymaster tag values (shared) and enum constants we need.
enum {
  TAG_PURPOSE = 0x20000001,
  TAG_ALGORITHM = 0x10000002,
  TAG_KEY_SIZE = 0x30000003,
  TAG_DIGEST = 0x20000005,
  TAG_EC_CURVE = 0x1000000a,
  TAG_CREATION_DATETIME = 0x600002bd,            // 0x60000000 | 701
  TAG_ATTESTATION_CHALLENGE = 0x900002c4,        // 0x90000000 | 708
  TAG_ATTESTATION_APPLICATION_ID = 0x900002c5,   // 0x90000000 | 709
  TAG_CERTIFICATE_NOT_BEFORE = 0x600003f0,       // 0x60000000 | 1008
  TAG_CERTIFICATE_NOT_AFTER = 0x600003f1,        // 0x60000000 | 1009
  ALGORITHM_RSA = 1,
  ALGORITHM_EC = 3,
  KEY_FORMAT_PKCS8 = 1,
  KS_NO_ERROR = 1,
  KS_SYSTEM_ERROR = 4,
};

namespace {

const String16 kServiceDescriptor("android.security.keystore.IKeystoreService");

// A simulated key, keyed by (uid, alias).
struct PendingKey {
  std::vector<uint8_t> pkcs8;   // private key, PKCS#8 DER
  std::vector<uint8_t> spki;    // public key, SubjectPublicKeyInfo DER
  std::vector<uint8_t> ta_blob; // key imported into the TA, for signing operations
  std::vector<KmParam> params;  // key parameters from generateKey
  // Owns the bytes of every byte-array (BYTES/BIGNUM) parameter, in the order those parameters
  // appear in `params`. A KmParam only holds a raw `blob` pointer, so this storage must outlive the
  // key and the pointers must be rebound into it after any copy or move (RebindParamBlobs) — otherwise
  // they dangle into the caller's transient read buffer or into the source object.
  std::vector<std::vector<uint8_t>> param_blobs;

  // Point each byte-array parameter's `blob` at this object's own `param_blobs`. `params` and
  // `param_blobs` were built in lockstep, so the k-th byte-array parameter uses param_blobs[k].
  void RebindParamBlobs() {
    size_t k = 0;
    for (auto& kp : params) {
      const uint32_t type = kp.tag & 0xf0000000u;
      if (type != 0x80000000u && type != 0x90000000u) continue;  // not a BIGNUM/BYTES param
      if (k >= param_blobs.size()) {
        kp.blob = nullptr;
        kp.blob_len = 0;
        continue;
      }
      kp.blob = param_blobs[k].data();
      kp.blob_len = param_blobs[k].size();
      ++k;
    }
  }
};

// A TA is reference-counted so an in-flight operation keeps its profile's TA
// alive even if a config reload swaps or drops that profile underneath it.
using TaPtr = std::shared_ptr<Ta>;
TaPtr WrapTa(Ta* ta) {
  return TaPtr(ta, [](Ta* t) {
    if (t) teesim_km_destroy(t);
  });
}

// A configured profile: its TA and the target uids, each mapped to its package
// name (needed to synthesise the attestation application id).
struct Profile {
  std::string id;
  TaPtr ta;
  std::map<int, std::string> uids;  // uid -> package name
};

// Live routing, swapped atomically by teesim_cfg_commit under g_cfg_mutex.
std::mutex g_cfg_mutex;
std::vector<Profile> g_profiles;
TaPtr g_default_ta;  // serves ops on our blobs; any profile's TA decrypts them

// Staging state built up by teesim_cfg_begin/add_profile before the swap.
std::vector<Profile> g_staging;
std::vector<uint8_t> g_stage_vb_key;
std::vector<uint8_t> g_stage_vb_hash;
bool g_stage_locked = true;
int32_t g_stage_vb_state = 0;
int32_t g_stage_attest_version_tee = 400;
int32_t g_stage_attest_version_strongbox = 400;

std::mutex g_keys_mutex;
std::map<std::string, PendingKey> g_keys;

// An in-flight crypto operation. The token returned to the caller identifies the
// TA operation handle and the TA it runs on, for follow-up update/finish/abort.
class OpToken : public BBinder {};
struct Operation {
  sp<IBinder> token;  // keeps the token binder alive while the operation runs
  int64_t op_handle;
  TaPtr ta;
};
std::mutex g_ops_mutex;
std::map<IBinder*, Operation> g_ops;

// The profile TA serving this uid, or null if the uid is not a target.
TaPtr ProfileForUid(int uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  for (const auto& prof : g_profiles) {
    if (prof.uids.count(uid)) return prof.ta;
  }
  return nullptr;
}

// The TA used for operations on an existing blob of ours.
TaPtr DefaultTa() {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  return g_default_ta;
}

bool IsTarget(int uid) { return ProfileForUid(uid) != nullptr; }

std::string PackageForUid(int uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  for (const auto& prof : g_profiles) {
    auto it = prof.uids.find(uid);
    if (it != prof.uids.end()) return it->second;
  }
  return std::string();
}

// AttestationApplicationId ::= SEQUENCE { packages SET OF SEQUENCE { name
// OCTET_STRING, version INTEGER }, signatures SET OF OCTET_STRING }. keystore
// normally builds this from the caller's package; downstream of our hook it is
// absent, so we synthesise it for the target package.
std::vector<uint8_t> BuildAttestationApplicationId(const std::string& pkg) {
  bssl::ScopedCBB cbb;
  CBB seq, pkg_set, pkg_seq, name, version, sig_set;
  CBB_init(cbb.get(), 128);
  CBB_add_asn1(cbb.get(), &seq, CBS_ASN1_SEQUENCE);
  CBB_add_asn1(&seq, &pkg_set, CBS_ASN1_SET);
  CBB_add_asn1(&pkg_set, &pkg_seq, CBS_ASN1_SEQUENCE);
  CBB_add_asn1(&pkg_seq, &name, CBS_ASN1_OCTETSTRING);
  CBB_add_bytes(&name, reinterpret_cast<const uint8_t*>(pkg.data()), pkg.size());
  CBB_add_asn1(&pkg_seq, &version, CBS_ASN1_INTEGER);
  CBB_add_u8(&version, 1);
  CBB_add_asn1(&seq, &sig_set, CBS_ASN1_SET);  // no signature digests
  uint8_t* out = nullptr;
  size_t len = 0;
  std::vector<uint8_t> v;
  if (CBB_finish(cbb.get(), &out, &len)) {
    v.assign(out, out + len);
    OPENSSL_free(out);
  }
  return v;
}

// Keystore prefixes each stored entry (USRPKEY_/USRCERT_/CACERT_/...); strip it so
// every operation on a key maps to the same identity.
std::string ExtractAlias(const String16& alias16) {
  std::string a = String8(alias16).c_str();
  for (const char* pfx : {"USRPKEY_", "USRCERT_", "CACERT_", "USRSKEY_"}) {
    size_t n = strlen(pfx);
    if (a.compare(0, n, pfx) == 0) return a.substr(n);
  }
  return a;
}

std::string KeyId(int uid, const String16& alias) {
  return std::to_string(uid) + ":" + ExtractAlias(alias);
}

// The strict-mode/work-source header written before the interface descriptor
// varies; enforceInterface consumes it. We read our own copy so the forwarded
// parcel keeps its position.
struct Reader {
  Parcel p;
  explicit Reader(const Parcel& src) {
    p.appendFrom(&src, 0, src.dataSize());
    p.setDataPosition(0);
  }
};

std::vector<uint8_t> ReadByteArray(Parcel& p) {
  int32_t len = p.readInt32();
  std::vector<uint8_t> v;
  if (len > 0) {
    v.resize(len);
    p.read(v.data(), len);
  }
  return v;
}

// Read a KeymasterArguments blob into KmParam values. Layout: int32 count, then
// per entry int32 tag followed by a value whose width is set by the tag's type.
std::vector<KmParam> ReadKeymasterArguments(Parcel& p,
                                            std::vector<std::vector<uint8_t>>& blob_store) {
  std::vector<KmParam> out;
  int32_t count = p.readInt32();
  // `count` is attacker-controlled and independent of the parcel size; clamp it so a bogus value can
  // neither drive a huge loop nor (below) a huge reservation. Real keymaster arg lists are tiny.
  if (count < 0 || count > 4096) count = 0;
  for (int32_t i = 0; i < count; ++i) {
    if (p.readInt32() == 0) continue;  // typed-list element presence marker
    KmParam kp{};
    kp.tag = static_cast<uint32_t>(p.readInt32());
    switch (kp.tag & 0xf0000000u) {
      case 0x10000000:  // ENUM
      case 0x20000000:  // ENUM_REP
      case 0x30000000:  // UINT
      case 0x40000000:  // UINT_REP
        kp.int_value = p.readInt32();
        break;
      case 0x50000000:  // ULONG
      case 0x60000000:  // DATE
      case 0xa0000000:  // ULONG_REP
        kp.int_value = p.readInt64();
        break;
      case 0x70000000:  // BOOL
        kp.int_value = 1;
        break;
      case 0x80000000:  // BIGNUM
      case 0x90000000:  // BYTES
        blob_store.push_back(ReadByteArray(p));
        kp.blob = blob_store.back().data();
        kp.blob_len = blob_store.back().size();
        break;
      default:
        break;
    }
    out.push_back(kp);
  }
  return out;
}

int64_t ParamInt(const std::vector<KmParam>& params, uint32_t tag, int64_t dflt) {
  for (const auto& p : params)
    if (p.tag == tag) return p.int_value;
  return dflt;
}

// writeTypedObject(obj != null): a leading 1 then the object's body.
void BeginTypedObject(Parcel& p) { p.writeInt32(1); }

// KeystoreResponse: (int errorCode, String errorMessage).
void WriteKeystoreResponse(Parcel& p, int32_t code) {
  BeginTypedObject(p);
  p.writeInt32(code);
  p.writeString16(nullptr, 0);  // null errorMessage
}

// KeymasterArguments: int32 count then the entries (we emit none).
void WriteEmptyArguments(Parcel& p) { p.writeInt32(0); }

// KeymasterArguments carrying the given parameters (reverse of the reader).
void WriteKeymasterArguments(Parcel& p, const std::vector<KmParam>& params) {
  p.writeInt32(static_cast<int32_t>(params.size()));
  for (const auto& kp : params) {
    p.writeInt32(1);  // typed-list element presence marker
    p.writeInt32(static_cast<int32_t>(kp.tag));
    switch (kp.tag & 0xf0000000u) {
      case 0x10000000:
      case 0x20000000:
      case 0x30000000:
      case 0x40000000:
        p.writeInt32(static_cast<int32_t>(kp.int_value));
        break;
      case 0x50000000:
      case 0x60000000:
      case 0xa0000000:
        p.writeInt64(kp.int_value);
        break;
      case 0x70000000:
        break;  // bool: presence only
      case 0x80000000:
      case 0x90000000:
        p.writeByteArray(kp.blob_len, kp.blob);
        break;
    }
  }
}

// Marshal an EC key as PKCS#8 with the curve kept inside the inner ECPrivateKey.
// BoringSSL's own PKCS#8 marshaling drops the curve from the inner key (it travels
// in the outer AlgorithmIdentifier), but the reference TA stores that inner key
// verbatim and, on its stock openssl backend, parses it for signing without the
// algorithm context — so a curveless inner key cannot be loaded. Build the wrapper
// by hand around a SEC1 body that retains its parameters.
bool MarshalEcPkcs8(const EC_KEY* ec, std::vector<uint8_t>& out) {
  static const uint8_t kEcPublicKeyOid[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
  bssl::ScopedCBB cbb;
  CBB info, algorithm, oid, private_key;
  if (!CBB_init(cbb.get(), 128) ||
      !CBB_add_asn1(cbb.get(), &info, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&info, 0) ||  // version
      !CBB_add_asn1(&info, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBB_add_bytes(&oid, kEcPublicKeyOid, sizeof(kEcPublicKeyOid)) ||
      !EC_KEY_marshal_curve_name(&algorithm, EC_KEY_get0_group(ec)) ||
      !CBB_add_asn1(&info, &private_key, CBS_ASN1_OCTETSTRING) ||
      !EC_KEY_marshal_private_key(&private_key, ec, 0))  // 0: keep curve and public key
    return false;
  uint8_t* der = nullptr;
  size_t dlen = 0;
  if (!CBB_finish(cbb.get(), &der, &dlen)) return false;
  out.assign(der, der + dlen);
  OPENSSL_free(der);
  return true;
}

// Generate an EC or RSA key pair for the requested parameters, returning its
// PKCS#8 private key and SubjectPublicKeyInfo public key.
bool GenerateKeyPair(const std::vector<KmParam>& params, PendingKey& out) {
  int64_t algorithm = ParamInt(params, TAG_ALGORITHM, ALGORITHM_EC);
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
  if (algorithm == ALGORITHM_EC) {
    int64_t curve = ParamInt(params, TAG_EC_CURVE, 1 /*P-256*/);
    int nid = NID_X9_62_prime256v1;
    if (curve == 0) nid = NID_secp224r1;
    else if (curve == 2) nid = NID_secp384r1;
    else if (curve == 3) nid = NID_secp521r1;
    bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(nid));
    if (!ec || !EC_KEY_generate_key(ec.get())) return false;
    if (!EVP_PKEY_assign_EC_KEY(pkey.get(), ec.release())) return false;
  } else {
    int64_t bits = ParamInt(params, TAG_KEY_SIZE, 2048);
    bssl::UniquePtr<RSA> rsa(RSA_new());
    bssl::UniquePtr<BIGNUM> e(BN_new());
    BN_set_word(e.get(), RSA_F4);
    if (!RSA_generate_key_ex(rsa.get(), static_cast<int>(bits), e.get(), nullptr)) return false;
    if (!EVP_PKEY_assign_RSA(pkey.get(), rsa.release())) return false;
  }

  if (algorithm == ALGORITHM_EC) {
    if (!MarshalEcPkcs8(EVP_PKEY_get0_EC_KEY(pkey.get()), out.pkcs8)) return false;
  } else {
    bssl::ScopedCBB cbb;
    uint8_t* der = nullptr;
    size_t dlen = 0;
    CBB_init(cbb.get(), 0);
    if (!EVP_marshal_private_key(cbb.get(), pkey.get()) ||  // PKCS#8 PrivateKeyInfo
        !CBB_finish(cbb.get(), &der, &dlen))
      return false;
    out.pkcs8.assign(der, der + dlen);
    OPENSSL_free(der);
  }

  uint8_t* der = nullptr;
  int len = i2d_PUBKEY(pkey.get(), &der);  // SubjectPublicKeyInfo
  if (len <= 0) return false;
  out.spki.assign(der, der + len);
  OPENSSL_free(der);
  return true;
}

// Send a result back on the callback binder. onFinished is transaction code 1.
void InvokeCallback(const sp<IBinder>& cb, const String16& cb_descriptor,
                    const std::function<void(Parcel&)>& write_body) {
  if (!cb) return;
  Parcel data, reply;
  data.writeInterfaceToken(cb_descriptor);
  write_body(data);
  cb->transact(1 /*onFinished*/, data, &reply);
}

void ReplyStatus(Parcel* reply, int32_t status) {
  if (!reply) return;
  reply->writeNoException();
  reply->writeInt32(status);
}

// Add the tags the TA needs to build a certificate that Android 10 leaves for
// keystore to fill in. app_id_store keeps a synthesised attestation application id
// alive for the duration of the import call.
void AddRequiredTags(std::vector<KmParam>& params, int uid,
                     std::vector<uint8_t>& app_id_store, bool with_attestation) {
  auto has = [&](uint32_t tag) {
    for (const auto& p : params)
      if (p.tag == tag) return true;
    return false;
  };
  int64_t now_ms = static_cast<int64_t>(time(nullptr)) * 1000;
  if (!has(TAG_CREATION_DATETIME))
    params.push_back({TAG_CREATION_DATETIME, now_ms, nullptr, 0});
  if (!has(TAG_CERTIFICATE_NOT_BEFORE))
    params.push_back({TAG_CERTIFICATE_NOT_BEFORE, now_ms, nullptr, 0});
  if (!has(TAG_CERTIFICATE_NOT_AFTER))
    params.push_back({TAG_CERTIFICATE_NOT_AFTER, 4102444800000LL, nullptr, 0});  // ~year 2100
  if (ParamInt(params, TAG_ALGORITHM, ALGORITHM_EC) == ALGORITHM_EC && !has(TAG_EC_CURVE)) {
    int64_t sz = ParamInt(params, TAG_KEY_SIZE, 256);
    params.push_back({TAG_EC_CURVE, sz == 384 ? 2 : sz == 521 ? 3 : sz == 224 ? 0 : 1, nullptr, 0});
  }
  if (with_attestation && !has(TAG_ATTESTATION_APPLICATION_ID)) {
    app_id_store = BuildAttestationApplicationId(PackageForUid(uid));
    if (!app_id_store.empty())
      params.push_back({TAG_ATTESTATION_APPLICATION_ID, 0, app_id_store.data(), app_id_store.size()});
  }
}

// Import the key's PKCS#8 into the TA. `extra` carries any attestation tags the
// caller supplies (the challenge). Returns a result the caller must free, or null.
TsCreationResult* ImportKey(const PendingKey& k, int uid, const std::vector<KmParam>& extra,
                            bool with_attestation) {
  TaPtr ta = ProfileForUid(uid);
  if (!ta) ta = DefaultTa();
  if (!ta) return nullptr;
  std::vector<KmParam> params = k.params;
  params.insert(params.end(), extra.begin(), extra.end());
  std::vector<uint8_t> app_id;
  AddRequiredTags(params, uid, app_id, with_attestation);
  TsCreationResult* res = nullptr;
  // The legacy Keystore HAL path has no wrapped KeyMint HAL to derive a level
  // from, so -1 keeps the TA's configured default security level.
  int32_t rc = teesim_km_import_key(ta.get(), params.data(), params.size(), /*security_level=*/-1,
                                    KEY_FORMAT_PKCS8, k.pkcs8.data(), k.pkcs8.size(), nullptr, 0,
                                    nullptr, 0, nullptr, 0, &res);
  if (rc != 0 || !res) {
    LOGE("keystore: TA import_key failed rc=%d", rc);
    return nullptr;
  }
  return res;
}

// Make sure the key exists in the TA (generating the key pair first if needed) so
// crypto operations can run against it. Call with g_keys_mutex held.
bool EnsureTaKey(PendingKey& k, int uid) {
  if (!k.ta_blob.empty()) return true;
  if (k.pkcs8.empty() && !GenerateKeyPair(k.params, k)) return false;
  // Import through the regular attestation path with a fixed challenge; only the
  // resulting key blob matters here, and that path is well exercised.
  static const uint8_t kChallenge[16] = {0};
  std::vector<KmParam> extra = {{TAG_ATTESTATION_CHALLENGE, 0, kChallenge, sizeof(kChallenge)}};
  TsCreationResult* res = ImportKey(k, uid, extra, true);
  if (!res) return false;
  const uint8_t* ptr = nullptr;
  size_t len = 0;
  teesim_km_result_key_blob(res, &ptr, &len);
  k.ta_blob.assign(ptr, ptr + len);
  teesim_km_free_result(res);
  return true;
}

// OperationResult { int resultCode, IBinder token, long operationHandle, int
// inputConsumed, byte[] output, KeymasterArguments outParams }, as the non-null
// callback argument. Note the output array precedes outParams in this version.
void WriteOperationResult(Parcel& p, int32_t code, const sp<IBinder>& token, int64_t op_handle,
                          int32_t input_consumed, const std::vector<uint8_t>& output) {
  BeginTypedObject(p);
  p.writeInt32(code);
  p.writeStrongBinder(token);
  p.writeInt64(op_handle);
  p.writeInt32(input_consumed);
  p.writeByteArray(output.size(), output.data());
  WriteEmptyArguments(p);  // outParams
}

// --- Per-method handlers ----------------------------------------------------

bool HandleGenerateKey(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();
  std::vector<std::vector<uint8_t>> blobs;
  std::vector<KmParam> params;
  if (in.readInt32() == 1) params = ReadKeymasterArguments(in, blobs);

  PendingKey key;
  key.params = std::move(params);
  key.param_blobs = std::move(blobs);  // take ownership so the params' blob pointers stay valid
  key.RebindParamBlobs();              // and repoint them into our own storage, not the read buffer
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    g_keys[KeyId(uid, alias)] = std::move(key);
  }
  LOGI("keystore: generateKey simulated alias=%s", String8(alias).c_str());

  static const String16 kCb("android.security.keystore.IKeystoreKeyCharacteristicsCallback");
  InvokeCallback(cb, kCb, [](Parcel& p) {
    WriteKeystoreResponse(p, KS_NO_ERROR);
    BeginTypedObject(p);        // KeyCharacteristics
    WriteEmptyArguments(p);     // swEnforced
    WriteEmptyArguments(p);     // hwEnforced
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleGetKeyCharacteristics(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();
  std::vector<KmParam> params;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) return false;  // not ours; forward
    params = it->second.params;
  }
  static const String16 kCb("android.security.keystore.IKeystoreKeyCharacteristicsCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteKeystoreResponse(p, KS_NO_ERROR);
    BeginTypedObject(p);                 // KeyCharacteristics
    WriteEmptyArguments(p);              // swEnforced
    WriteKeymasterArguments(p, params);  // hwEnforced
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleExportKey(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();

  std::vector<uint8_t> spki;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) return false;  // not ours; forward
    if (!EnsureTaKey(it->second, uid)) {
      LOGE("keystore: key setup failed");
      return false;
    }
    spki = it->second.spki;
  }

  static const String16 kCb("android.security.keystore.IKeystoreExportKeyCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    BeginTypedObject(p);  // ExportResult
    p.writeInt32(KS_NO_ERROR);
    p.writeByteArray(spki.size(), spki.data());
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleAttestKey(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();
  std::vector<std::vector<uint8_t>> blobs;
  std::vector<KmParam> attest_params;
  if (in.readInt32() == 1) attest_params = ReadKeymasterArguments(in, blobs);

  PendingKey key;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) return false;  // not ours; forward
    if (it->second.pkcs8.empty() && !GenerateKeyPair(it->second.params, it->second)) return false;
    key = it->second;        // deep-copies param_blobs, but the params still point into the source...
    key.RebindParamBlobs();  // ...so repoint them into this copy's own storage
  }

  // The caller supplies the attestation challenge; the application id is synthesised.
  std::vector<KmParam> extra;
  for (const auto& p : attest_params)
    if (p.tag == TAG_ATTESTATION_CHALLENGE) extra.push_back(p);
  TsCreationResult* res = ImportKey(key, uid, extra, /*with_attestation=*/true);
  if (!res) return false;

  // Reuse the imported key blob for later signing operations.
  {
    const uint8_t* bp = nullptr;
    size_t bl = 0;
    teesim_km_result_key_blob(res, &bp, &bl);
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it != g_keys.end() && it->second.ta_blob.empty()) it->second.ta_blob.assign(bp, bp + bl);
  }

  std::vector<std::vector<uint8_t>> chain;
  size_t n = teesim_km_result_num_certs(res);
  for (size_t i = 0; i < n; ++i) {
    const uint8_t* ptr = nullptr;
    size_t len = 0;
    teesim_km_result_cert(res, i, &ptr, &len);
    chain.emplace_back(ptr, ptr + len);
  }
  teesim_km_free_result(res);
  LOGI("keystore: attestKey simulated alias=%s certs=%zu", String8(alias).c_str(), chain.size());

  static const String16 kCb("android.security.keystore.IKeystoreCertificateChainCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteKeystoreResponse(p, KS_NO_ERROR);
    BeginTypedObject(p);  // KeymasterCertificateChain
    p.writeInt32(static_cast<int32_t>(chain.size()));
    for (const auto& c : chain) p.writeByteArray(c.size(), c.data());
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleBegin(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  in.readStrongBinder();  // appToken (unused)
  String16 alias = in.readString16();
  int32_t purpose = in.readInt32();
  in.readInt32();  // pruneable (unused)
  std::vector<std::vector<uint8_t>> blobs;
  std::vector<KmParam> op_params;
  if (in.readInt32() == 1) {
    for (const auto& p : ReadKeymasterArguments(in, blobs)) {
      // Pass only operation parameters; key characteristics come from the blob.
      if (p.tag == TAG_ALGORITHM || p.tag == TAG_KEY_SIZE || p.tag == TAG_EC_CURVE) continue;
      op_params.push_back(p);
    }
  }

  std::vector<uint8_t> blob;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) return false;  // not ours; forward
    if (!EnsureTaKey(it->second, uid)) return false;
    blob = it->second.ta_blob;
  }

  TaPtr ta = ProfileForUid(uid);
  if (!ta) ta = DefaultTa();
  if (!ta) return false;
  TsBeginResult* res = nullptr;
  // The legacy keystore1 HAL carries auth tokens through its own mechanism, not the flat token structs
  // the keystore2 path uses, so no auth token is forwarded here yet (unchanged behavior). Auth-bound
  // keys on Android 10/11 are a separate follow-up; pass nullptr to mean "no token".
  int32_t rc = teesim_km_begin(ta.get(), purpose, blob.data(), blob.size(), op_params.data(),
                               op_params.size(), /*auth_token=*/nullptr, &res);
  if (rc != 0 || !res) {
    LOGE("keystore: TA begin failed rc=%d", rc);
    return false;
  }
  int64_t op_handle = teesim_km_begin_op_handle(res);
  teesim_km_free_begin(res);

  sp<IBinder> token = sp<OpToken>::make();
  {
    std::lock_guard<std::mutex> lk(g_ops_mutex);
    g_ops[token.get()] = {token, op_handle, ta};
  }
  LOGI("keystore: begin purpose=%d alias=%s", purpose, String8(alias).c_str());

  static const String16 kCb("android.security.keystore.IKeystoreOperationResultCallback");
  InvokeCallback(cb, kCb,
                 [&](Parcel& p) { WriteOperationResult(p, KS_NO_ERROR, token, op_handle, 0, {}); });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

// Look up the TA operation handle and its TA for a token the caller passes back.
bool OpFor(const sp<IBinder>& token, int64_t* op_handle, TaPtr* ta, bool erase) {
  std::lock_guard<std::mutex> lk(g_ops_mutex);
  auto it = g_ops.find(token.get());
  if (it == g_ops.end()) return false;
  *op_handle = it->second.op_handle;
  *ta = it->second.ta;
  if (erase) g_ops.erase(it);
  return true;
}

void DeliverOperationResult(const sp<IBinder>& cb, int32_t rc, const sp<IBinder>& token,
                            int32_t input_consumed, const std::vector<uint8_t>& output) {
  static const String16 kCb("android.security.keystore.IKeystoreOperationResultCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteOperationResult(p, rc == 0 ? KS_NO_ERROR : KS_SYSTEM_ERROR, token, 0, input_consumed,
                         output);
  });
}

bool HandleUpdate(int /*uid*/, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  sp<IBinder> token = in.readStrongBinder();
  std::vector<std::vector<uint8_t>> blobs;
  if (in.readInt32() == 1) ReadKeymasterArguments(in, blobs);  // op params (unused)
  std::vector<uint8_t> input = ReadByteArray(in);

  int64_t op_handle = 0;
  TaPtr ta;
  if (!OpFor(token, &op_handle, &ta, /*erase=*/false)) return false;  // not ours; forward

  uint8_t* out = nullptr;
  size_t out_len = 0;
  int32_t rc = teesim_km_update(ta.get(), op_handle, input.data(), input.size(),
                                /*auth_token=*/nullptr, /*timestamp_token=*/nullptr, &out, &out_len);
  std::vector<uint8_t> output;
  if (rc == 0 && out) {
    output.assign(out, out + out_len);
    teesim_km_free_buf(out, out_len);
  } else if (rc != 0) {
    LOGE("keystore: TA update failed rc=%d", rc);
  }

  DeliverOperationResult(cb, rc, token, static_cast<int32_t>(input.size()), output);
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleFinish(int /*uid*/, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  sp<IBinder> token = in.readStrongBinder();
  std::vector<std::vector<uint8_t>> blobs;
  if (in.readInt32() == 1) ReadKeymasterArguments(in, blobs);  // op params (unused)
  std::vector<uint8_t> signature = ReadByteArray(in);          // supplied for verify

  int64_t op_handle = 0;
  TaPtr ta;
  if (!OpFor(token, &op_handle, &ta, /*erase=*/true)) return false;  // not ours; forward

  uint8_t* out = nullptr;
  size_t out_len = 0;
  int32_t rc = teesim_km_finish(ta.get(), op_handle, nullptr, 0, signature.data(), signature.size(),
                                /*auth_token=*/nullptr, /*timestamp_token=*/nullptr,
                                /*confirmation_token=*/nullptr, 0, &out, &out_len);
  std::vector<uint8_t> output;
  if (rc == 0 && out) {
    output.assign(out, out + out_len);
    teesim_km_free_buf(out, out_len);
  } else if (rc != 0) {
    LOGE("keystore: TA finish failed rc=%d", rc);
  }
  LOGI("keystore: finish output=%zu", output.size());

  DeliverOperationResult(cb, rc, token, 0, output);
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleAbort(int /*uid*/, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  sp<IBinder> token = in.readStrongBinder();
  int64_t op_handle = 0;
  TaPtr ta;
  if (!OpFor(token, &op_handle, &ta, /*erase=*/true)) return false;  // not ours; forward
  teesim_km_abort(ta.get(), op_handle);

  static const String16 kCb("android.security.keystore.IKeystoreResponseCallback");
  InvokeCallback(cb, kCb, [](Parcel& p) { WriteKeystoreResponse(p, KS_NO_ERROR); });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

}  // namespace

extern "C" const char* teesim_hook_name(void) { return "keystore1"; }

// Config-staging API (see common/control.h). teesim_cfg_begin/add_profile run on
// the control thread; only teesim_cfg_commit touches the live routing tables.
extern "C" void teesim_cfg_begin(const TsBootInfo* boot) {
  g_staging.clear();
  g_stage_vb_key.assign(boot->verified_boot_key,
                        boot->verified_boot_key + boot->verified_boot_key_len);
  g_stage_vb_hash.assign(boot->verified_boot_hash,
                         boot->verified_boot_hash + boot->verified_boot_hash_len);
  g_stage_locked = boot->device_locked;
  g_stage_vb_state = boot->verified_boot_state;
  g_stage_attest_version_tee = boot->attest_version_tee;
  g_stage_attest_version_strongbox = boot->attest_version_strongbox;
}

extern "C" bool teesim_cfg_add_profile(const TsProfile* p) {
  Ta* ta = teesim_km_init_ex(p->keybox, p->keybox_len, p->security_level, p->os_version,
                             p->os_patchlevel, p->vendor_patchlevel, p->boot_patchlevel,
                             g_stage_vb_key.data(), g_stage_vb_key.size(), g_stage_vb_hash.data(),
                             g_stage_vb_hash.size(), g_stage_locked, g_stage_vb_state,
                             g_stage_attest_version_tee, g_stage_attest_version_strongbox, p->ids);
  if (!ta) {
    LOGE("keystore: profile %s failed to build (bad keybox?)", p->id ? p->id : "?");
    return false;
  }
  Profile prof;
  prof.id = p->id ? p->id : "";
  prof.ta = WrapTa(ta);
  // uids[] is aligned 1:1 with packages[]; -1 marks a package that is not installed.
  for (int i = 0; i < p->n_uids && p->uids; ++i) {
    if (p->uids[i] < 0) continue;
    const char* pkg =
        (i < p->n_packages && p->packages && p->packages[i]) ? p->packages[i] : "";
    prof.uids[p->uids[i]] = pkg;
  }
  g_staging.push_back(std::move(prof));
  return true;
}

extern "C" int teesim_cfg_commit(uint64_t /*epoch*/, char* /*err*/, size_t /*err_len*/) {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  g_profiles = std::move(g_staging);
  g_staging.clear();
  g_default_ta = g_profiles.empty() ? nullptr : g_profiles.front().ta;
  return static_cast<int>(g_profiles.size());
}

// The legacy keystore interceptor has no patch mode, so it re-signs nothing.
extern "C" bool teesim_cfg_resign(const char* /*profile_id*/, const uint8_t* /*leaf*/,
                                  size_t /*leaf_len*/, TsCertSink /*sink*/, void* /*ctx*/) {
  return false;
}

// The interception handler installed for the keystore service binder.
extern "C" bool teesim_ks_handle(uint32_t code, const Parcel& data, Parcel* reply,
                                  status_t& result) {
  switch (code) {
    case TX_generateKey:
    case TX_getKeyCharacteristics:
    case TX_exportKey:
    case TX_attestKey:
    case TX_begin:
    case TX_update:
    case TX_finish:
    case TX_abort:
      break;
    default:
      return false;
  }
  int uid = IPCThreadState::self()->getCallingUid();
  if (!IsTarget(uid)) return false;
  Reader r(data);
  if (!r.p.enforceInterface(kServiceDescriptor)) return false;

  bool done = false;
  switch (code) {
    case TX_generateKey:           done = HandleGenerateKey(uid, r.p, reply); break;
    case TX_getKeyCharacteristics: done = HandleGetKeyCharacteristics(uid, r.p, reply); break;
    case TX_exportKey:             done = HandleExportKey(uid, r.p, reply); break;
    case TX_attestKey:             done = HandleAttestKey(uid, r.p, reply); break;
    case TX_begin:                 done = HandleBegin(uid, r.p, reply); break;
    case TX_update:                done = HandleUpdate(uid, r.p, reply); break;
    case TX_finish:                done = HandleFinish(uid, r.p, reply); break;
    case TX_abort:                 done = HandleAbort(uid, r.p, reply); break;
  }
  if (done) result = OK;
  return done;
}
