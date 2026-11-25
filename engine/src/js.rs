//! The small parts of JavaScript semantics the reference evaluator relies on, reproduced exactly.

use num_bigint::BigUint;
use serde_json::{Map, Value};

/// `/^(0|[1-9][0-9]{0,77})$/`
pub fn is_uint(s: &str) -> bool {
    let b = s.as_bytes();
    match b.len() {
        0 => false,
        1 => b[0].is_ascii_digit(),
        n if n <= 78 => b[0] != b'0' && b.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// `/^0x[0-9a-fA-F]{40}$/`
pub fn is_address(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 42 && b.starts_with(b"0x") && b[2..].iter().copied().all(is_hex_digit)
}

/// `/^0x([0-9a-fA-F]{2})*$/`
pub fn is_hex(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b.starts_with(b"0x") && (b.len() - 2) % 2 == 0 && b[2..].iter().copied().all(is_hex_digit)
}

/// `/^0x[0-9a-fA-F]{8}$/`
pub fn is_selector(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10 && b.starts_with(b"0x") && b[2..].iter().copied().all(is_hex_digit)
}

/// `/^[a-z0-9_]{3,64}$/`
pub fn is_policy_id(s: &str) -> bool {
    let b = s.as_bytes();
    (3..=64).contains(&b.len()) && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// A decimal string the caller has already checked with `is_uint`.
pub fn big(s: &str) -> BigUint {
    s.parse().unwrap_or_default()
}

/// `BigInt(s)` for inputs that come from outside the policy (prices, reservations). Only plain
/// decimal is accepted; anything else is an engine error, so the dual check fails closed.
pub fn big_strict(s: &str) -> Result<BigUint, String> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("not a decimal integer: {s:?}"));
    }
    s.parse().map_err(|_| format!("not a decimal integer: {s:?}"))
}

/// A JavaScript number that must hold an integer (times, ids). `3.0` counts, as in JavaScript.
pub fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| {
            let f = n.as_f64()?;
            (f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15).then_some(f as i64)
        }),
        _ => None,
    }
}

/// `typeof v === "number" && Number.isInteger(v) && min <= v <= max`
pub fn int_in(v: Option<&Value>, min: i64, max: i64) -> bool {
    match v {
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) => f.is_finite() && f.fract() == 0.0 && f >= min as f64 && f <= max as f64,
            None => false,
        },
        _ => false,
    }
}

/// 64-bit FNV-1a over UTF-16 code units, as `fingerprint()` does with `charCodeAt`.
pub fn fingerprint(input: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for unit in input.encode_utf16() {
        h ^= unit as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("0x{h:016x}")
}

/// `data.slice(0, 10).toLowerCase()` when at least 10 UTF-16 units long.
pub fn selector_of(data: &str) -> Option<String> {
    let units: Vec<u16> = data.encode_utf16().collect();
    if units.len() < 10 {
        return None;
    }
    Some(String::from_utf16_lossy(&units[..10]).to_lowercase())
}

/// USD micros for an amount of wei, rounded up.
pub fn wei_to_usd_micros(wei: &BigUint, price_micros: &BigUint) -> BigUint {
    let n = wei * price_micros;
    if n == BigUint::default() {
        return n;
    }
    let wei_per_eth = BigUint::from(10u32).pow(18);
    (n + &wei_per_eth - 1u32) / wei_per_eth
}

/// `formatUsd`: `$1,234.56`, dollars grouped as `toLocaleString("en-US")` does, cents truncated.
pub fn format_usd(micros: &BigUint) -> String {
    let million = BigUint::from(1_000_000u32);
    let dollars = (micros / &million).to_string();
    let cents = (micros % &million) / BigUint::from(10_000u32);
    let mut grouped = String::with_capacity(dollars.len() + dollars.len() / 3);
    for (i, c) in dollars.chars().enumerate() {
        if i > 0 && (dollars.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    format!("${grouped}.{:0>2}", cents.to_string())
}

/// `Object.keys` order: canonical array-index keys ascending first, then the rest in insertion order.
pub fn js_keys(o: &Map<String, Value>) -> Vec<&String> {
    fn index(k: &str) -> Option<u32> {
        let n: u32 = k.parse().ok()?;
        (n != u32::MAX && n.to_string() == k).then_some(n)
    }
    let mut idx: Vec<(u32, &String)> = o.keys().filter_map(|k| index(k).map(|n| (n, k))).collect();
    idx.sort_by_key(|(n, _)| *n);
    let mut out: Vec<&String> = idx.into_iter().map(|(_, k)| k).collect();
    out.extend(o.keys().filter(|k| index(k).is_none()));
    out
}

/// Lowercases ASCII and everything else the way `String.prototype.toLowerCase` does for the inputs
/// that matter here (addresses and hex). Non-ASCII uses Rust's Unicode mapping.
pub fn lower(s: &str) -> String {
    s.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_the_reference() {
        // fingerprint("") in TypeScript is the FNV offset basis.
        assert_eq!(fingerprint(""), "0xcbf29ce484222325");
        assert_eq!(fingerprint("a"), "0xaf63dc4c8601ec8c");
    }

    #[test]
    fn usd_formatting() {
        assert_eq!(format_usd(&BigUint::from(0u32)), "$0.00");
        assert_eq!(format_usd(&BigUint::from(1_234_567_891u64)), "$1,234.56");
        assert_eq!(format_usd(&BigUint::from(999_999u32)), "$0.99");
        assert_eq!(format_usd(&big("1000000000000000")), "$1,000,000,000.00");
    }

    #[test]
    fn patterns() {
        assert!(is_uint("0") && is_uint("10") && !is_uint("01") && !is_uint("") && !is_uint("-1"));
        assert!(is_uint(&"9".repeat(78)) && !is_uint(&"9".repeat(79)));
        assert!(is_hex("0x") && is_hex("0xAb") && !is_hex("0xa") && !is_hex("ab"));
    }
}
