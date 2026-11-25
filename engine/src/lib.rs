//! Palisec policy engine.
//!
//! The production evaluator for policy schema 1.0 to 1.5, compiled to WebAssembly and run by the API
//! alongside the TypeScript reference evaluator. Both must agree on every field of every result;
//! if they ever differ, or this engine cannot run, the API denies (fails closed).
//!
//! WebAssembly interface (no bindings generator, so the surface stays tiny and auditable):
//!   ps_alloc(len) -> ptr            reserve `len` bytes for the request
//!   ps_evaluate(ptr, len) -> u64    request: {"policy","intent","state","env"}
//!   ps_validate(ptr, len) -> u64    request: a policy document
//!   ps_free(ptr, len)               release a request or response buffer
//! Responses are UTF-8 JSON `{"ok": ...}` or `{"error": "..."}`, returned as (ptr << 32) | len.

pub mod asset;
pub mod evaluate;
pub mod loss;
pub mod proven;
pub mod recovery;
pub mod spend;
pub mod js;
pub mod validate;

use serde_json::{json, Value};

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Evaluates `{"policy","intent","state","env"}` and returns `{"ok": result}` or `{"error": msg}`.
pub fn evaluate_request(request: &str) -> String {
    let out = serde_json::from_str::<Value>(request)
        .map_err(|e| format!("invalid JSON: {e}"))
        .and_then(|v| {
            let get = |k: &str| v.get(k).ok_or_else(|| format!("missing {k}"));
            evaluate::evaluate(get("policy")?, get("intent")?, get("state")?, get("env")?)
        });
    wrap(out)
}

/// Validates a policy document and returns `{"ok": [{path, message}, ...]}`.
pub fn validate_request(request: &str) -> String {
    wrap(serde_json::from_str::<Value>(request).map_err(|e| format!("invalid JSON: {e}")).map(|doc| validate::validate_json(&doc)))
}

fn wrap(r: Result<Value, String>) -> String {
    match r {
        Ok(v) => json!({ "ok": v, "engine": ENGINE_VERSION }).to_string(),
        Err(e) => json!({ "error": e }).to_string(),
    }
}

// ---- WebAssembly ABI -------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn ps_alloc(len: usize) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `len` must come from `ps_alloc(len)` or from a response this module returned.
#[no_mangle]
pub unsafe extern "C" fn ps_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
    }
}

unsafe fn call(ptr: *const u8, len: usize, f: fn(&str) -> String) -> u64 {
    let input = std::slice::from_raw_parts(ptr, len);
    let out = match std::str::from_utf8(input) {
        Ok(s) => f(s),
        Err(_) => json!({ "error": "request is not UTF-8" }).to_string(),
    };
    let mut bytes = out.into_bytes();
    bytes.shrink_to_fit();
    let (p, l) = (bytes.as_mut_ptr(), bytes.len());
    std::mem::forget(bytes);
    ((p as u64) << 32) | l as u64
}

/// # Safety
/// `ptr` must point to `len` readable bytes written after `ps_alloc(len)`.
#[no_mangle]
pub unsafe extern "C" fn ps_evaluate(ptr: *const u8, len: usize) -> u64 {
    call(ptr, len, evaluate_request)
}

/// # Safety
/// `ptr` must point to `len` readable bytes written after `ps_alloc(len)`.
#[no_mangle]
pub unsafe extern "C" fn ps_validate(ptr: *const u8, len: usize) -> u64 {
    call(ptr, len, validate_request)
}
