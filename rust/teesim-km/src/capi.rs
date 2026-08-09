// C ABI for the per-method operations.
//
// The native interceptor decodes an IKeyMintDevice transaction into these flat
// arguments, calls the matching function here, and encodes the result back into
// the reply parcel. Key parameters cross the boundary as `KmParam` (a flattened
// KeyParameter); structured results are returned as opaque handles with
// accessors so the C++ side never has to know the kmr_wire encoding.
//
// Every function returns 0 on success or a KeyMint error code (negative) on
// failure. Output handles are only written on success and must be freed with the
// matching free function.

use crate::{Ta, OpError};
use kmr_wire::cbor::value::{Integer, Value};
use kmr_wire::keymint::{
    AttestationKey, KeyCharacteristics, KeyCreationResult, KeyFormat, KeyParam, KeyPurpose,
};
use kmr_wire::AsCborValue;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

const ERR_UNKNOWN: i32 = -1000;

/// A flattened KeyMint `KeyParameter`. The interpretation of `int_value` vs
/// `blob` follows the tag's type bits, so the C++ side only has to copy the
/// active union field.
#[repr(C)]
pub struct KmParam {
    pub tag: u32,
    pub int_value: i64,
    pub blob: *const u8,
    pub blob_len: usize,
}

// KeyMint TagType bits (top nibble of a tag).
const TAG_TYPE_MASK: u32 = 0xF000_0000;
const TAG_BOOL: u32 = 0x7000_0000;
const TAG_BIGNUM: u32 = 0x8000_0000;
const TAG_BYTES: u32 = 0x9000_0000;

fn call<T>(f: impl FnOnce() -> Result<T, OpError>) -> Result<T, i32> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => {
            log::error!("teesim_km op failed: code={} {}", e.code, e.msg);
            Err(e.code)
        }
        Err(_) => Err(ERR_UNKNOWN),
    }
}

/// Convert a flat `KmParam` into a kmr_wire `KeyParam`, reusing kmr_wire's own
/// tag-keyed decoding.
fn to_keyparam(p: &KmParam) -> Result<KeyParam, OpError> {
    let value = match p.tag & TAG_TYPE_MASK {
        TAG_BOOL => Value::Bool(true),
        TAG_BYTES | TAG_BIGNUM => {
            let bytes = if p.blob.is_null() || p.blob_len == 0 {
                Vec::new()
            } else {
                // Safety: the caller guarantees blob/blob_len are valid for the call.
                unsafe { slice::from_raw_parts(p.blob, p.blob_len) }.to_vec()
            };
            Value::Bytes(bytes)
        }
        _ => Value::Integer(Integer::from(p.int_value)),
    };
    let tag = Value::Integer(Integer::from((p.tag as i32) as i64));
    KeyParam::from_cbor_value(Value::Array(vec![tag, value])).map_err(|e| OpError {
        code: ERR_UNKNOWN,
        msg: format!("bad key param tag {:#x}: {e:?}", p.tag),
    })
}

/// # Safety
/// `params`/`n` must describe a valid array (or be null/0).
unsafe fn to_keyparams(params: *const KmParam, n: usize) -> Result<Vec<KeyParam>, OpError> {
    if params.is_null() || n == 0 {
        return Ok(Vec::new());
    }
    slice::from_raw_parts(params, n).iter().map(to_keyparam).collect()
}

/// An owned, C-friendly key parameter (blob lives in the handle).
struct OwnedParam {
    tag: u32,
    int_value: i64,
    blob: Vec<u8>,
}

fn owned_param(kp: &KeyParam) -> OwnedParam {
    let mut o = OwnedParam { tag: kp.tag() as u32, int_value: 0, blob: Vec::new() };
    if let Ok(Value::Array(mut a)) = kp.clone().to_cbor_value() {
        if a.len() == 2 {
            match a.remove(1) {
                Value::Integer(i) => o.int_value = i128::from(i) as i64,
                Value::Bytes(b) => o.blob = b,
                Value::Bool(b) => o.int_value = b as i64,
                _ => {}
            }
        }
    }
    o
}

fn view(p: &OwnedParam) -> KmParam {
    KmParam {
        tag: p.tag,
        int_value: p.int_value,
        blob: if p.blob.is_empty() { std::ptr::null() } else { p.blob.as_ptr() },
        blob_len: p.blob.len(),
    }
}

struct OwnedChar {
    security_level: i32,
    params: Vec<OwnedParam>,
}

fn owned_chars(chars: &[KeyCharacteristics]) -> Vec<OwnedChar> {
    chars
        .iter()
        .map(|c| OwnedChar {
            security_level: c.security_level as i32,
            params: c.authorizations.iter().map(owned_param).collect(),
        })
        .collect()
}

/// Result of generateKey / importKey, owned across the FFI boundary.
pub struct TsCreationResult {
    key_blob: Vec<u8>,
    certs: Vec<Vec<u8>>,
    chars: Vec<OwnedChar>,
}

impl TsCreationResult {
    fn new(r: KeyCreationResult) -> Self {
        TsCreationResult {
            key_blob: r.key_blob,
            certs: r.certificate_chain.into_iter().map(|c| c.encoded_certificate).collect(),
            chars: owned_chars(&r.key_characteristics),
        }
    }
}

fn build_attestation_key(
    ak_blob: *const u8,
    ak_blob_len: usize,
    ak_params: *const KmParam,
    ak_n_params: usize,
    ak_issuer: *const u8,
    ak_issuer_len: usize,
) -> Result<Option<AttestationKey>, OpError> {
    if ak_blob.is_null() {
        return Ok(None);
    }
    // Safety: caller guarantees the pointers describe valid buffers for the call.
    let key_blob = unsafe { slice::from_raw_parts(ak_blob, ak_blob_len) };
    let attest_key_params = unsafe { to_keyparams(ak_params, ak_n_params)? };
    let issuer_subject_name = if ak_issuer.is_null() {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(ak_issuer, ak_issuer_len) }.to_vec()
    };
    Ok(Some(AttestationKey {
        key_blob: crate::strip_marker(key_blob).to_vec(),
        attest_key_params,
        issuer_subject_name,
    }))
}

// --- generateKey / importKey -------------------------------------------------

/// # Safety
/// See module docs; all pointer/length pairs must be valid for the call.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_generate_key(
    ta: *mut Ta,
    params: *const KmParam,
    n_params: usize,
    security_level: i32,
    ak_blob: *const u8,
    ak_blob_len: usize,
    ak_params: *const KmParam,
    ak_n_params: usize,
    ak_issuer: *const u8,
    ak_issuer_len: usize,
    out: *mut *mut TsCreationResult,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        let key_params = to_keyparams(params, n_params)?;
        let attestation_key =
            build_attestation_key(ak_blob, ak_blob_len, ak_params, ak_n_params, ak_issuer, ak_issuer_len)?;
        let result = ta.generate_key(key_params, attestation_key, security_level)?;
        Ok(TsCreationResult::new(result))
    }) {
        Ok(r) => {
            *out = Box::into_raw(Box::new(r));
            0
        }
        Err(code) => code,
    }
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_import_key(
    ta: *mut Ta,
    params: *const KmParam,
    n_params: usize,
    security_level: i32,
    key_format: i32,
    key_data: *const u8,
    key_data_len: usize,
    ak_blob: *const u8,
    ak_blob_len: usize,
    ak_params: *const KmParam,
    ak_n_params: usize,
    ak_issuer: *const u8,
    ak_issuer_len: usize,
    out: *mut *mut TsCreationResult,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        let key_params = to_keyparams(params, n_params)?;
        let format = KeyFormat::n(key_format)
            .ok_or(OpError { code: ERR_UNKNOWN, msg: format!("bad key format {key_format}") })?;
        let data = if key_data.is_null() { Vec::new() } else { slice::from_raw_parts(key_data, key_data_len).to_vec() };
        let attestation_key =
            build_attestation_key(ak_blob, ak_blob_len, ak_params, ak_n_params, ak_issuer, ak_issuer_len)?;
        let result = ta.import_key(key_params, format, data, attestation_key, security_level)?;
        Ok(TsCreationResult::new(result))
    }) {
        Ok(r) => {
            *out = Box::into_raw(Box::new(r));
            0
        }
        Err(code) => code,
    }
}

// Accessors for TsCreationResult.

/// # Safety
/// `res` must come from generateKey/importKey and outlive this call.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_result_key_blob(res: *const TsCreationResult, ptr: *mut *const u8, len: *mut usize) {
    let r = &*res;
    *ptr = r.key_blob.as_ptr();
    *len = r.key_blob.len();
}

/// # Safety
/// `res` must come from generateKey/importKey.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_result_num_certs(res: *const TsCreationResult) -> usize {
    (&*res).certs.len()
}

/// # Safety
/// `i` must be < num_certs.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_result_cert(res: *const TsCreationResult, i: usize, ptr: *mut *const u8, len: *mut usize) {
    let c = &(&*res).certs[i];
    *ptr = c.as_ptr();
    *len = c.len();
}

/// # Safety
/// `res` must come from generateKey/importKey.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_result_num_chars(res: *const TsCreationResult) -> usize {
    (&*res).chars.len()
}

/// Number of parameters in characteristics entry `ci`.
/// # Safety
/// `ci` must be < num_chars.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_result_char(res: *const TsCreationResult, ci: usize, security_level: *mut i32) -> usize {
    let c = &(&*res).chars[ci];
    *security_level = c.security_level;
    c.params.len()
}

/// Fill `out` with parameter `pi` of characteristics entry `ci`.
/// # Safety
/// `ci`/`pi` must be in range; the blob pointer stays valid until free.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_result_char_param(res: *const TsCreationResult, ci: usize, pi: usize, out: *mut KmParam) {
    *out = view(&(&*res).chars[ci].params[pi]);
}

/// # Safety
/// `res` must come from generateKey/importKey and not be freed already.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_free_result(res: *mut TsCreationResult) {
    if !res.is_null() {
        drop(Box::from_raw(res));
    }
}

// --- begin / operation -------------------------------------------------------

/// Result of begin(): the challenge, our operation handle, and returned params.
pub struct TsBeginResult {
    challenge: i64,
    op_handle: i64,
    params: Vec<OwnedParam>,
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_begin(
    ta: *mut Ta,
    purpose: i32,
    key_blob: *const u8,
    key_blob_len: usize,
    params: *const KmParam,
    n_params: usize,
    out: *mut *mut TsBeginResult,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        let purpose = KeyPurpose::n(purpose)
            .ok_or(OpError { code: ERR_UNKNOWN, msg: format!("bad purpose {purpose}") })?;
        let blob = if key_blob.is_null() { &[][..] } else { slice::from_raw_parts(key_blob, key_blob_len) };
        let key_params = to_keyparams(params, n_params)?;
        // Auth-bound keys are not supported until ISharedSecret is handled.
        let r = ta.begin(purpose, blob, key_params, None)?;
        Ok(TsBeginResult {
            challenge: r.challenge,
            op_handle: r.op_handle,
            params: r.params.iter().map(owned_param).collect(),
        })
    }) {
        Ok(r) => {
            *out = Box::into_raw(Box::new(r));
            0
        }
        Err(code) => code,
    }
}

/// # Safety
/// `res` from begin().
#[no_mangle]
pub unsafe extern "C" fn teesim_km_begin_challenge(res: *const TsBeginResult) -> i64 {
    (&*res).challenge
}

/// The opaque operation handle to pass to update/finish/abort.
/// # Safety
/// `res` from begin().
#[no_mangle]
pub unsafe extern "C" fn teesim_km_begin_op_handle(res: *const TsBeginResult) -> i64 {
    (&*res).op_handle
}

/// # Safety
/// `res` from begin().
#[no_mangle]
pub unsafe extern "C" fn teesim_km_begin_num_params(res: *const TsBeginResult) -> usize {
    (&*res).params.len()
}

/// # Safety
/// `i` < num_params.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_begin_param(res: *const TsBeginResult, i: usize, out: *mut KmParam) {
    *out = view(&(&*res).params[i]);
}

/// # Safety
/// `res` from begin(), not already freed.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_free_begin(res: *mut TsBeginResult) {
    if !res.is_null() {
        drop(Box::from_raw(res));
    }
}

// --- update / updateAad / finish / abort -------------------------------------

unsafe fn opt_bytes(ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(ptr, len).to_vec())
    }
}

fn emit(bytes: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    unsafe {
        *out = Box::into_raw(boxed) as *mut u8;
        *out_len = len;
    }
}

/// # Safety
/// See module docs. Output (free with teesim_km_free_buf) is written on success.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_update(
    ta: *mut Ta,
    op_handle: i64,
    input: *const u8,
    input_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        let data = if input.is_null() { Vec::new() } else { slice::from_raw_parts(input, input_len).to_vec() };
        ta.update(op_handle, data, None, None)
    }) {
        Ok(bytes) => {
            emit(bytes, out, out_len);
            0
        }
        Err(code) => code,
    }
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_update_aad(
    ta: *mut Ta,
    op_handle: i64,
    input: *const u8,
    input_len: usize,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        let data = if input.is_null() { Vec::new() } else { slice::from_raw_parts(input, input_len).to_vec() };
        ta.update_aad(op_handle, data, None, None)
    }) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

/// # Safety
/// See module docs. Output (free with teesim_km_free_buf) is written on success.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_finish(
    ta: *mut Ta,
    op_handle: i64,
    input: *const u8,
    input_len: usize,
    signature: *const u8,
    signature_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        ta.finish(op_handle, opt_bytes(input, input_len), opt_bytes(signature, signature_len), None, None, None)
    }) {
        Ok(bytes) => {
            emit(bytes, out, out_len);
            0
        }
        Err(code) => code,
    }
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_abort(ta: *mut Ta, op_handle: i64) -> i32 {
    match call(|| (&mut *ta).abort(op_handle)) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

// --- deleteKey / upgradeKey / getKeyCharacteristics --------------------------

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_delete_key(ta: *mut Ta, key_blob: *const u8, key_blob_len: usize) -> i32 {
    match call(|| {
        let blob = if key_blob.is_null() { &[][..] } else { slice::from_raw_parts(key_blob, key_blob_len) };
        (&mut *ta).delete_key(blob)
    }) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

/// # Safety
/// See module docs. Output (free with teesim_km_free_buf) is the upgraded, marked blob.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_upgrade_key(
    ta: *mut Ta,
    key_blob: *const u8,
    key_blob_len: usize,
    params: *const KmParam,
    n_params: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        let blob = if key_blob.is_null() { &[][..] } else { slice::from_raw_parts(key_blob, key_blob_len) };
        let upgrade_params = to_keyparams(params, n_params)?;
        ta.upgrade_key(blob, upgrade_params)
    }) {
        Ok(bytes) => {
            emit(bytes, out, out_len);
            0
        }
        Err(code) => code,
    }
}

/// TsCharacteristics-only result of getKeyCharacteristics.
pub struct TsCharacteristics {
    chars: Vec<OwnedChar>,
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_get_key_characteristics(
    ta: *mut Ta,
    key_blob: *const u8,
    key_blob_len: usize,
    app_id: *const u8,
    app_id_len: usize,
    app_data: *const u8,
    app_data_len: usize,
    out: *mut *mut TsCharacteristics,
) -> i32 {
    match call(|| {
        let ta = &mut *ta;
        let blob = if key_blob.is_null() { &[][..] } else { slice::from_raw_parts(key_blob, key_blob_len) };
        let id = if app_id.is_null() { Vec::new() } else { slice::from_raw_parts(app_id, app_id_len).to_vec() };
        let data = if app_data.is_null() { Vec::new() } else { slice::from_raw_parts(app_data, app_data_len).to_vec() };
        let chars = ta.get_key_characteristics(blob, id, data)?;
        Ok(TsCharacteristics { chars: owned_chars(&chars) })
    }) {
        Ok(c) => {
            *out = Box::into_raw(Box::new(c));
            0
        }
        Err(code) => code,
    }
}

/// # Safety
/// `res` from getKeyCharacteristics.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_chars_num(res: *const TsCharacteristics) -> usize {
    (&*res).chars.len()
}

/// # Safety
/// `ci` < chars_num.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_chars_entry(res: *const TsCharacteristics, ci: usize, security_level: *mut i32) -> usize {
    let c = &(&*res).chars[ci];
    *security_level = c.security_level;
    c.params.len()
}

/// # Safety
/// `ci`/`pi` in range.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_chars_param(res: *const TsCharacteristics, ci: usize, pi: usize, out: *mut KmParam) {
    *out = view(&(&*res).chars[ci].params[pi]);
}

/// # Safety
/// `res` from getKeyCharacteristics, not already freed.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_free_chars(res: *mut TsCharacteristics) {
    if !res.is_null() {
        drop(Box::from_raw(res));
    }
}
