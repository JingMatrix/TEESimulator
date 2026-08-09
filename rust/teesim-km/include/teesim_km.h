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

// --- lifecycle ---------------------------------------------------------------

Ta *teesim_km_init(const uint8_t *keybox_ptr, size_t keybox_len);
void teesim_km_destroy(Ta *handle);
bool teesim_km_is_marked(const uint8_t *blob_ptr, size_t blob_len);

// Raw kmr_wire request/response (used for methods without a dedicated shim).
int32_t teesim_km_process(Ta *handle, const uint8_t *req_ptr, size_t req_len,
                          uint8_t **out_ptr, size_t *out_len);
void teesim_km_free_buf(uint8_t *ptr, size_t len);

// --- generateKey / importKey -------------------------------------------------

int32_t teesim_km_generate_key(Ta *ta, const KmParam *params, size_t n_params,
                               const uint8_t *ak_blob, size_t ak_blob_len,
                               const KmParam *ak_params, size_t ak_n_params,
                               const uint8_t *ak_issuer, size_t ak_issuer_len,
                               TsCreationResult **out);

int32_t teesim_km_import_key(Ta *ta, const KmParam *params, size_t n_params,
                             int32_t key_format, const uint8_t *key_data,
                             size_t key_data_len, const uint8_t *ak_blob,
                             size_t ak_blob_len, const KmParam *ak_params,
                             size_t ak_n_params, const uint8_t *ak_issuer,
                             size_t ak_issuer_len, TsCreationResult **out);

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
