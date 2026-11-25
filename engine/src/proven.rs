//! Proven on Zolva (schema 1.4). Mirrors `provenUnlocked` in packages/policy-schema/src/simulator.ts:
//! the unlocked limits apply only with the section on, a link verified from both sides, Zolva's replay
//! check "match", enough verified hours, a fresh read, and an unlock that has already waited out the
//! loosening delay. Anything else keeps the policy's own limits. Malformed input is an engine error.

use crate::js::int;
use serde_json::{Map, Value};

type Res<T> = Result<T, String>;

pub const NOTE: &str = " Unlocked limit: verified Zolva record (paper trading).";

fn bad<T>(why: &str) -> Res<T> {
    Err(format!("asset simulation input: {why}"))
}
fn int_of(o: &Map<String, Value>, k: &str) -> Res<i64> {
    match o.get(k).and_then(int) {
        Some(n) => Ok(n),
        None => bad(&format!("proven_record.{k} must be an integer")),
    }
}

pub fn unlocked(policy: &Value, env: &Value, now: i64) -> Res<bool> {
    let rules = match policy.get("proven_record") {
        Some(Value::Object(r)) => r,
        _ => return Ok(false),
    };
    if rules.get("enabled") != Some(&Value::Bool(true)) {
        return Ok(false);
    }
    let r = match env.get("proven_record") {
        None | Some(Value::Null) => return Ok(false),
        Some(Value::Object(m)) => m,
        Some(_) => return bad("proven_record must be an object"),
    };
    let observed = int_of(r, "observed_at")?;
    let linked = match r.get("link_verified") {
        Some(Value::Bool(b)) => *b,
        _ => return bad("proven_record.link_verified must be a boolean"),
    };
    let status = match r.get("replay_status") {
        Some(Value::String(s)) => s.as_str(),
        _ => return bad("proven_record.replay_status must be a string"),
    };
    let hours = int_of(r, "hours_verified")?;
    let at = match r.get("unlocked_at") {
        Some(Value::Null) => None,
        _ => Some(int_of(r, "unlocked_at")?),
    };
    let min_hours = rules.get("min_verified_hours").and_then(int).ok_or("policy.proven_record.min_verified_hours must be an integer")?;
    let max_age = rules.get("max_record_age_seconds").and_then(int).ok_or("policy.proven_record.max_record_age_seconds must be an integer")?;
    if !linked || status != "match" || hours < min_hours {
        return Ok(false);
    }
    if observed > now || now - observed > max_age {
        return Ok(false);
    }
    Ok(matches!(at, Some(t) if t <= now))
}

/// The limit at `limits.<key>`, or `proven_record.unlocked_limits.<key>` when unlocked.
pub fn limit(policy: &Value, unlocked: bool, key: &str) -> Res<String> {
    let v = if unlocked {
        policy.get("proven_record").and_then(|p| p.get("unlocked_limits")).and_then(|u| u.get(key))
    } else {
        policy.get("limits").and_then(|l| l.get(key))
    };
    v.and_then(Value::as_str).map(str::to_owned).ok_or_else(|| format!("policy limit {key} must be a string"))
}
