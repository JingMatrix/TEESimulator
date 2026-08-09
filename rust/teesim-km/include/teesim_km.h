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

// --- lifecycle ---------------------------------------------------------------

// Build a TA with the historical default identity (used before any daemon push).
Ta *teesim_km_init(const uint8_t *keybox_ptr, size_t keybox_len);

// Build a TA from a fully resolved profile: keybox + security level + patch/OS
// levels + device-wide verified-boot fields + optional device IDs. Integer
// encodings match KeyMint: os_version = major*10000+minor*100+sub; os_patchlevel
// = YYYYMM; vendor/boot patchlevel = YYYYMMDD. security_level: 0 Software, 1 TEE,
// 2 StrongBox. verified_boot_state: 0 Verified, 1 SelfSigned, 2 Unverified,
// 3 Failed. `ids` may be NULL. Returns null on failure (e.g. a bad keybox).
Ta *teesim_km_init_ex(const uint8_t *keybox_ptr, size_t keybox_len,
                      int32_t security_level, uint32_t os_version,
                      uint32_t os_patchlevel, uint32_t vendor_patchlevel,
                      uint32_t boot_patchlevel, const uint8_t *vb_key,
                      size_t vb_key_len, const uint8_t *vb_hash, size_t vb_hash_len,
                      bool device_locked, int32_t verified_boot_state,
                      const TsDeviceIds *ids);
void teesim_km_destroy(Ta *handle);
bool teesim_km_is_marked(const uint8_t *blob_ptr, size_t blob_len);

// Raw kmr_wire request/response (used for methods without a dedicated shim).
int32_t teesim_km_process(Ta *handle, const uint8_t *req_ptr, size_t req_len,
                          uint8_t **out_ptr, size_t *out_len);
void teesim_km_free_buf(uint8_t *ptr, size_t len);

// --- generateKey / importKey -------------------------------------------------

// `security_level` is the level of the real HAL the request came through (0
// Software, 1 TrustedEnvironment, 2 StrongBox); the attestation record and key
// characteristics are emitted at that level, overriding the TA's default. A value
// outside that set keeps the TA's configured default.
int32_t teesim_km_generate_key(Ta *ta, const KmParam *params, size_t n_params,
                               int32_t security_level, const uint8_t *ak_blob,
                               size_t ak_blob_len, const KmParam *ak_params,
                               size_t ak_n_params, const uint8_t *ak_issuer,
                               size_t ak_issuer_len, TsCreationResult **out);

int32_t teesim_km_import_key(Ta *ta, const KmParam *params, size_t n_params,
                             int32_t security_level, int32_t key_format,
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

int32_t teesim_km_begin(Ta *ta, int32_t purpose, const uint8_t *key_blob,
                        size_t key_blob_len, const KmParam *params,
                        size_t n_params, TsBeginResult **out);
int64_t teesim_km_begin_challenge(const TsBeginResult *res);
int64_t teesim_km_begin_op_handle(const TsBeginResult *res);
size_t teesim_km_begin_num_params(const TsBeginResult *res);
void teesim_km_begin_param(const TsBeginResult *res, size_t i, KmParam *out);
void teesim_km_free_begin(TsBeginResult *res);

int32_t teesim_km_update(Ta *ta, int64_t op_handle, const uint8_t *input,
                        size_t input_len, uint8_t **out, size_t *out_len);
int32_t teesim_km_update_aad(Ta *ta, int64_t op_handle, const uint8_t *input, size_t input_len);
int32_t teesim_km_finish(Ta *ta, int64_t op_handle, const uint8_t *input,
                        size_t input_len, const uint8_t *signature,
                        size_t signature_len, uint8_t **out, size_t *out_len);
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

#ifdef __cplusplus
}
#endif

#endif // TEESIM_KM_H
