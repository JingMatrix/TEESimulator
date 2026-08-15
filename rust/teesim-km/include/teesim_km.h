// C ABI for the in-process KeyMint TA (see src/ffi.rs and src/capi.rs).
//
// Lifecycle: teesim_km_init -> per-method calls -> teesim_km_destroy.
// Every per-method call returns 0 on success or a KeyMint error code (negative);
// output handles/buffers are written only on success and must be freed.
#ifndef TEESIM_KM_H
#define TEESIM_KM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles.
typedef struct Ta Ta;
typedef struct TsCreationResult TsCreationResult;
typedef struct TsBeginResult TsBeginResult;
typedef struct TsCharacteristics TsCharacteristics;

// A flattened KeyMint KeyParameter. int_value holds bool/enum/int/long/date
// values; blob holds byte-array values (else NULL). The tag's type bits decide
// which is active.
typedef struct {
  uint32_t tag;
  int64_t int_value;
  const uint8_t *blob;
  size_t blob_len;
} KmParam;

// How a KeyMint tag's scalar value is represented in KmParam::int_value. Returned by
// teesim_km_tag_value_kind so the native marshallers share one signed/unsigned/width table with the
// Rust side (which mirrors kmr_wire's per-tag decoder). Never derive this from the tag's type nibble
// directly: USER_AUTH_TYPE is ENUM-typed but decoded as an unsigned 32-bit value.
typedef enum {
  KM_VALUE_INVALID = 0,  // no scalar value / unknown tag
  KM_VALUE_BOOL = 1,     // BOOL: presence means true
  KM_VALUE_BYTES = 2,    // BYTES/BIGNUM: a byte array
  KM_VALUE_INT32 = 3,    // signed 32-bit: ENUM/ENUM_REP
  KM_VALUE_UINT32 = 4,   // unsigned 32-bit: UINT/UINT_REP and USER_AUTH_TYPE
  KM_VALUE_INT64 = 5,    // signed 64-bit: DATE
  KM_VALUE_UINT64 = 6,   // unsigned 64-bit: ULONG/ULONG_REP
} KmValueKind;

// Classify a tag's flat value representation (see KmValueKind). Pure function of `tag`.
KmValueKind teesim_km_tag_value_kind(uint32_t tag);

// Device-ID values a profile vouches for; each is a byte span (NULL/0 = unset).
// Passed to teesim_km_init_ex. If every field is unset, device-ID attestation is
// declined, exactly as on a device that was never provisioned with IDs.
typedef struct {
  const uint8_t *brand;        size_t brand_len;
  const uint8_t *device;       size_t device_len;
  const uint8_t *product;      size_t product_len;
  const uint8_t *serial;       size_t serial_len;
  const uint8_t *imei;         size_t imei_len;
  const uint8_t *imei2;        size_t imei2_len;
  const uint8_t *meid;         size_t meid_len;
  const uint8_t *manufacturer; size_t manufacturer_len;
  const uint8_t *model;        size_t model_len;
} TsDeviceIds;

// A KeyMint HardwareAuthToken flattened for the C ABI, passed (nullable) to begin/update/finish so the
// TA can honour auth-bound keys. `mac` is the Gatekeeper/biometric HMAC tag (NULL/0 when absent).
typedef struct {
  int64_t challenge;
  int64_t user_id;
  int64_t authenticator_id;
  int32_t authenticator_type;  // HardwareAuthenticatorType: 0 None, 1 Password, 2 Fingerprint, -1 Any
  int64_t timestamp_ms;        // milliseconds since epoch
  const uint8_t *mac;
  size_t mac_len;
} TsAuthToken;

// A secureclock TimeStampToken flattened for the C ABI (nullable), carried alongside update/finish for
// auth-timeout keys checked on a clockless TA. Our TA has its own clock, but the token is forwarded
// verbatim so the reference TA behaves exactly as it would on real hardware.
typedef struct {
  int64_t challenge;
  int64_t timestamp_ms;
  const uint8_t *mac;
  size_t mac_len;
} TsTimestampToken;

// --- lifecycle ---------------------------------------------------------------

// Build a TA with the historical default identity (used before any daemon push).
Ta *teesim_km_init(const uint8_t *keybox_ptr, size_t keybox_len);

// Build a TA from a fully resolved profile: keybox + security level + patch/OS
// levels + device-wide verified-boot fields + optional device IDs. Integer
// encodings match KeyMint: os_version = major*10000+minor*100+sub; os_patchlevel
// = YYYYMM; vendor/boot patchlevel = YYYYMMDD. security_level: 0 Software, 1 TEE,
// 2 StrongBox. verified_boot_state: 0 Verified, 1 SelfSigned, 2 Unverified,
// 3 Failed. attest_version_tee/strongbox are the harvested KeyMint HAL versions
// (attestationVersion; 100/200/300/400) reported by keys attested at each level.
// `ids` may be NULL. Returns null on failure (e.g. a bad keybox).
Ta *teesim_km_init_ex(const uint8_t *keybox_ptr, size_t keybox_len,
                      int32_t security_level, uint32_t os_version,
                      uint32_t os_patchlevel, uint32_t vendor_patchlevel,
                      uint32_t boot_patchlevel, const uint8_t *vb_key,
                      size_t vb_key_len, const uint8_t *vb_hash, size_t vb_hash_len,
                      bool device_locked, int32_t verified_boot_state,
                      int32_t attest_version_tee, int32_t attest_version_strongbox,
                      const TsDeviceIds *ids);
void teesim_km_destroy(Ta *handle);
bool teesim_km_is_marked(const uint8_t *blob_ptr, size_t blob_len);

// Raw kmr_wire request/response (used for methods without a dedicated shim).
int32_t teesim_km_process(Ta *handle, const uint8_t *req_ptr, size_t req_len,
                          uint8_t **out_ptr, size_t *out_len);
void teesim_km_free_buf(uint8_t *ptr, size_t len);

// --- generateKey / importKey -------------------------------------------------

// The attestation record and key characteristics are emitted at this TA instance's fixed security
// level. Route the request to the TA for the level the request came through (each level has its own
// instance); there is no per-request override.
int32_t teesim_km_generate_key(Ta *ta, const KmParam *params, size_t n_params,
                               const uint8_t *ak_blob,
                               size_t ak_blob_len, const KmParam *ak_params,
                               size_t ak_n_params, const uint8_t *ak_issuer,
                               size_t ak_issuer_len, TsCreationResult **out);

// Patch mode: re-sign a real hardware attestation leaf under this profile's keybox with the
// profile's locked/Verified root of trust. `leaf` is the DER leaf from the real HAL's chain; its
// public key and attestation content are preserved. On success *out holds the new certificate chain
// [patched leaf, keybox chain] (empty key blob / characteristics), read via the result accessors.
int32_t teesim_km_patch_attestation(Ta *ta, const uint8_t *leaf, size_t leaf_len,
                                    TsCreationResult **out);

int32_t teesim_km_import_key(Ta *ta, const KmParam *params, size_t n_params,
                             int32_t key_format,
                             const uint8_t *key_data, size_t key_data_len,
                             const uint8_t *ak_blob, size_t ak_blob_len,
                             const KmParam *ak_params, size_t ak_n_params,
                             const uint8_t *ak_issuer, size_t ak_issuer_len,
                             TsCreationResult **out);

void teesim_km_result_key_blob(const TsCreationResult *res, const uint8_t **ptr, size_t *len);
size_t teesim_km_result_num_certs(const TsCreationResult *res);
void teesim_km_result_cert(const TsCreationResult *res, size_t i, const uint8_t **ptr, size_t *len);
size_t teesim_km_result_num_chars(const TsCreationResult *res);
// Returns the parameter count for entry ci and writes its security level.
size_t teesim_km_result_char(const TsCreationResult *res, size_t ci, int32_t *security_level);
void teesim_km_result_char_param(const TsCreationResult *res, size_t ci, size_t pi, KmParam *out);
void teesim_km_free_result(TsCreationResult *res);

// --- begin / operation -------------------------------------------------------

// `auth_token` is nullable: keystore2 attaches it when the key is auth-bound (fingerprint/PIN). The TA
// checks it at begin for AUTH_TIMEOUT keys and defers to update/finish for auth-per-operation keys.
int32_t teesim_km_begin(Ta *ta, int32_t purpose, const uint8_t *key_blob,
                        size_t key_blob_len, const KmParam *params,
                        size_t n_params, const TsAuthToken *auth_token,
                        TsBeginResult **out);
int64_t teesim_km_begin_challenge(const TsBeginResult *res);
int64_t teesim_km_begin_op_handle(const TsBeginResult *res);
size_t teesim_km_begin_num_params(const TsBeginResult *res);
void teesim_km_begin_param(const TsBeginResult *res, size_t i, KmParam *out);
void teesim_km_free_begin(TsBeginResult *res);

// update / updateAad / finish take the same nullable auth + timestamp tokens keystore2 passes, so an
// auth-per-operation key is re-checked on every invocation. finish also carries the (nullable)
// confirmation token for TRUSTED_CONFIRMATION_REQUIRED keys.
int32_t teesim_km_update(Ta *ta, int64_t op_handle, const uint8_t *input,
                        size_t input_len, const TsAuthToken *auth_token,
                        const TsTimestampToken *timestamp_token, uint8_t **out, size_t *out_len);
int32_t teesim_km_update_aad(Ta *ta, int64_t op_handle, const uint8_t *input, size_t input_len,
                            const TsAuthToken *auth_token, const TsTimestampToken *timestamp_token);
int32_t teesim_km_finish(Ta *ta, int64_t op_handle, const uint8_t *input,
                        size_t input_len, const uint8_t *signature,
                        size_t signature_len, const TsAuthToken *auth_token,
                        const TsTimestampToken *timestamp_token,
                        const uint8_t *confirmation_token, size_t confirmation_token_len,
                        uint8_t **out, size_t *out_len);
int32_t teesim_km_abort(Ta *ta, int64_t op_handle);

// --- deleteKey / upgradeKey / getKeyCharacteristics --------------------------

int32_t teesim_km_delete_key(Ta *ta, const uint8_t *key_blob, size_t key_blob_len);
int32_t teesim_km_upgrade_key(Ta *ta, const uint8_t *key_blob, size_t key_blob_len,
                             const KmParam *params, size_t n_params,
                             uint8_t **out, size_t *out_len);

int32_t teesim_km_get_key_characteristics(Ta *ta, const uint8_t *key_blob,
                                          size_t key_blob_len, const uint8_t *app_id,
                                          size_t app_id_len, const uint8_t *app_data,
                                          size_t app_data_len, TsCharacteristics **out);
size_t teesim_km_chars_num(const TsCharacteristics *res);
size_t teesim_km_chars_entry(const TsCharacteristics *res, size_t ci, int32_t *security_level);
void teesim_km_chars_param(const TsCharacteristics *res, size_t ci, size_t pi, KmParam *out);
void teesim_km_free_chars(TsCharacteristics *res);

// --- device state (routed to our TA for our keys) ----------------------------

// Mark early boot as ended: EARLY_BOOT_ONLY keys become unusable afterwards. Applied to each profile
// TA so our keys observe the same transition keystore2 signals to the real HAL.
int32_t teesim_km_early_boot_ended(Ta *ta);

// Record additional attestation info (e.g. MODULE_HASH on Android 16) so keys attested by this TA
// carry it, matching what keystore2 pushes to the real HAL. `info` is a KeyParameter array.
int32_t teesim_km_set_additional_attestation_info(Ta *ta, const KmParam *info, size_t n_info);

#ifdef __cplusplus
}
#endif

#endif // TEESIM_KM_H
