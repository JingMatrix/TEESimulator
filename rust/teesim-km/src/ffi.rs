// C ABI for the native interceptor.
//
// The handle returned by `teesim_km_init` is an opaque pointer to a boxed `Ta`.
// Every entry point is wrapped in `catch_unwind` so a fault in the TA can never
// unwind across the FFI boundary into keystore2.

use crate::Ta;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

/// Create a TA from a keybox.xml byte buffer (UTF-8). Returns an opaque handle,
/// or null on failure.
///
/// # Safety
/// `keybox_ptr` must point to `keybox_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_init(keybox_ptr: *const u8, keybox_len: usize) -> *mut Ta {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("TEESimulator"),
    );
    std::panic::set_hook(Box::new(|info| log::error!("teesim_km panic: {info}")));
    let result = catch_unwind(AssertUnwindSafe(|| {
        if keybox_ptr.is_null() {
            return None;
        }
        let bytes = slice::from_raw_parts(keybox_ptr, keybox_len);
        let xml = std::str::from_utf8(bytes).ok()?;
        match Ta::new(xml) {
            Ok(ta) => Some(Box::into_raw(Box::new(ta))),
            Err(e) => {
                log::error!("teesim_km_init: {e}");
                None
            }
        }
    }));
    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

/// Process one serialized kmr_wire request. On success writes a freshly allocated
/// buffer to `*out_ptr` / `*out_len` (free it with `teesim_km_free_buf`) and
/// returns 0; returns -1 on failure.
///
/// # Safety
/// `handle` must come from `teesim_km_init`; `req_ptr` must point to `req_len`
/// readable bytes; `out_ptr` and `out_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_process(
    handle: *mut Ta,
    req_ptr: *const u8,
    req_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || req_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let ta = &mut *handle;
        let req = slice::from_raw_parts(req_ptr, req_len);
        let rsp = ta.process(req);

        // into_boxed_slice gives capacity == len, so the matching free can
        // reconstruct the allocation exactly.
        let boxed = rsp.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        *out_ptr = ptr;
        *out_len = len;
        0
    }));
    result.unwrap_or(-1)
}

/// Free a buffer returned by `teesim_km_process`.
///
/// # Safety
/// `ptr`/`len` must be a buffer returned by `teesim_km_process` and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_free_buf(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Vec::from_raw_parts(ptr, len, len));
    }));
}

/// Destroy a TA handle.
///
/// # Safety
/// `handle` must come from `teesim_km_init` and not have been destroyed already.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_destroy(handle: *mut Ta) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(handle));
    }));
}

/// True if `blob` was produced by this TA (has our routing marker).
///
/// # Safety
/// `blob_ptr` must point to `blob_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_is_marked(blob_ptr: *const u8, blob_len: usize) -> bool {
    if blob_ptr.is_null() {
        return false;
    }
    let blob = slice::from_raw_parts(blob_ptr, blob_len);
    crate::is_marked(blob)
}
