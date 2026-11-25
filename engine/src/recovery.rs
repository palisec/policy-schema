//! Upoch recovery (schema 1.2). Mirrors `recoveryCheck` in packages/policy-schema/src/simulator.ts:
//! same order, codes and wording. The Upoch workflow is read before evaluation and passed in as
//! `env.upoch`; malformed input is an engine error (the dual evaluator then fails closed).

use crate::asset::Asset::{self, *};
use crate::js::int;
use serde_json::{Map, Value};

const UPOCH_READ_MAX_AGE: i64 = 60;

type Res<T> = Result<T, String>;

fn bad<T>(why: &str) -> Res<T> {
    Err(format!("asset simulation input: {why}"))
}
fn str_of<'a>(o: &'a Map<String, Value>, k: &str) -> Res<&'a str> {
    match o.get(k) {
        Some(Value::String(s)) => Ok(s),
        _ => bad(&format!("{k} must be a string")),
    }
}
fn int_of(v: Option<&Value>, k: &str) -> Res<i64> {
    match v.and_then(int) {
        Some(n) => Ok(n),
        None => bad(&format!("{k} must be an integer")),
    }
}
fn bool_of(o: &Map<String, Value>, k: &str) -> Res<bool> {
    match o.get(k) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => bad(&format!("{k} must be a boolean")),
    }
}

pub fn check(policy: &Value, env: &Value, now: i64) -> Res<Asset> {
    let rules = match policy.get("upoch_recovery") {
        Some(Value::Object(r)) => r,
        _ => return Ok(Pass("Upoch recovery is not required by this policy.".into())),
    };
    if rules.get("require_upoch_recoverable") != Some(&Value::Bool(true)) {
        return Ok(Pass("Upoch recovery is not required by this policy.".into()));
    }
    let review = rules.get("on_unavailable").and_then(Value::as_str) == Some("review");
    let unavailable = |why: String| -> Asset {
        if review {
            Review("PS_RECOVERY_003", format!("{why} The policy holds this for a human instead of allowing it."))
        } else {
            Fail("PS_RECOVERY_003", format!("{why} Without Upoch data the request fails closed."))
        }
    };
    let u = match env.get("upoch") {
        None | Some(Value::Null) => return Ok(unavailable("Upoch data unavailable.".into())),
        Some(Value::Object(m)) => m,
        Some(_) => return bad("upoch must be an object"),
    };
    let wf = str_of(u, "workflow_id")?;
    let observed = int_of(u.get("observed_at"), "observed_at")?;
    let linked = bool_of(u, "linked")?;
    let active = bool_of(u, "active")?;
    let count = int_of(u.get("checkpoint_count"), "checkpoint_count")?;
    let last = match u.get("last_checkpoint_at") {
        Some(Value::Null) => None,
        v => Some(int_of(v, "last_checkpoint_at")?),
    };
    let guardians = int_of(u.get("guardians"), "guardians")?;
    let read_age = now - observed;
    if read_age > UPOCH_READ_MAX_AGE {
        return Ok(unavailable(format!("Upoch data is {read_age}s old; maximum is {UPOCH_READ_MAX_AGE}s.")));
    }
    if wf.is_empty() {
        return Ok(Fail("PS_RECOVERY_001", "No Upoch workflow is set for this agent.".into()));
    }
    if !linked {
        return Ok(Fail(
            "PS_RECOVERY_001",
            format!("Upoch workflow {wf} is not linked to this account: neither its owner nor a guardian is an owner of the account."),
        ));
    }
    if !active {
        return Ok(Fail("PS_RECOVERY_001", format!("Upoch workflow {wf} is paused.")));
    }
    let Some(last) = last.filter(|_| count != 0) else {
        return Ok(Fail("PS_RECOVERY_001", format!("Upoch workflow {wf} has no checkpoint.")));
    };
    if rules.get("require_guardian") == Some(&Value::Bool(true)) && guardians == 0 {
        return Ok(Fail("PS_RECOVERY_001", format!("Upoch workflow {wf} has no guardian.")));
    }
    let max = rules.get("max_checkpoint_age_seconds").and_then(int).ok_or("upoch_recovery.max_checkpoint_age_seconds must be an integer")?;
    let age = now - last;
    if age > max {
        return Ok(Fail("PS_RECOVERY_002", format!("The last Upoch checkpoint is {age}s old; maximum is {max}s.")));
    }
    Ok(Pass(format!("Upoch workflow {wf}: {count} checkpoint(s), last {age}s ago, {guardians} guardian(s).")))
}
