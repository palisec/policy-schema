//! The evaluator. Mirrors `evaluate` in packages/policy-schema/src/simulator.ts check for check:
//! same order, same reason codes, same wording, same next-state snapshot. Shared fixtures and a
//! seeded fuzz suite prove the two agree; the API runs both and fails closed if they ever differ.

use crate::js::{big, big_strict, fingerprint, format_usd, int, is_address, is_hex, is_uint, lower, selector_of, wei_to_usd_micros};
use crate::validate::validate;
use num_bigint::BigUint;
use serde_json::{json, Map, Value};

const WINDOW_SECONDS: i64 = 3600;
const RESERVATION_TTL_SECONDS: i64 = 300;
const MAX_CALLDATA_BYTES: usize = 65536;

pub fn retryable(code: &str) -> bool {
    matches!(code, "PS_BUDGET_001" | "PS_RATE_001" | "PS_ATTEST_001" | "PS_FEE_001" | "PS_PAUSED_001" | "PS_STATE_001" | "PS_CHAIN_001" | "PS_RECOVERY_003" | "PS_LOSS_003" | "PS_PRICE_001" | "PS_SIM_002")
}

const LIVE_CHECKS: [(&str, &str); 5] = [
    ("simulate", "Execution simulation against chain state"),
    ("bind", "Authorization bound to operation hash, chain, policy version, expiry"),
    ("sign", "Signature from the protected signing path"),
    ("validate_onchain", "Smart-account validation of the Palisec signature"),
    ("submit", "Bundler submission and receipt reconciliation"),
];

type Res<T> = Result<T, String>;

fn field<'a>(o: &'a Value, k: &str) -> Res<&'a Value> {
    o.get(k).ok_or_else(|| format!("missing field {k}"))
}
fn s<'a>(o: &'a Value, k: &str) -> Res<&'a str> {
    field(o, k)?.as_str().ok_or_else(|| format!("{k} must be a string"))
}
fn n(o: &Value, k: &str) -> Res<i64> {
    int(field(o, k)?).ok_or_else(|| format!("{k} must be an integer"))
}
fn b(o: &Value, k: &str) -> Res<bool> {
    field(o, k)?.as_bool().ok_or_else(|| format!("{k} must be a boolean"))
}
fn arr<'a>(o: &'a Value, k: &str) -> Res<&'a Vec<Value>> {
    field(o, k)?.as_array().ok_or_else(|| format!("{k} must be an array"))
}
fn obj<'a>(o: &'a Value, k: &str) -> Res<&'a Map<String, Value>> {
    field(o, k)?.as_object().ok_or_else(|| format!("{k} must be an object"))
}
fn strings(o: &Value, k: &str) -> Res<Vec<String>> {
    arr(o, k)?.iter().map(|v| v.as_str().map(str::to_owned).ok_or_else(|| format!("{k} must hold strings"))).collect()
}

/// `policy?.contracts.allowlist.find((e) => e.address.toLowerCase() === to)`, including the cases
/// where JavaScript would throw (reported as an engine error).
fn find_entry<'a>(policy: &'a Value, to_lower: &str) -> Res<Option<&'a Map<String, Value>>> {
    if policy.is_null() {
        return Ok(None);
    }
    let contracts = match policy {
        Value::Object(m) => m.get("contracts"),
        _ => None,
    };
    let list = match contracts {
        Some(Value::Object(c)) => match c.get("allowlist") {
            Some(Value::Array(a)) => a,
            _ => return Err("policy.contracts.allowlist is not an array".into()),
        },
        _ => return Err("policy.contracts is not an object".into()),
    };
    for e in list {
        match e {
            Value::Object(m) => match m.get("address") {
                Some(Value::String(a)) => {
                    if lower(a) == to_lower {
                        return Ok(Some(m));
                    }
                }
                _ => return Err("allowlist entry without a string address".into()),
            },
            _ => return Err("allowlist entry is not an object".into()),
        }
    }
    Ok(None)
}

struct Run {
    checks: Vec<Value>,
    failed: Option<(String, String)>,
    review: Option<(String, String)>,
}

enum Outcome {
    Pass(String),
    Fail(&'static str, String),
    Review(&'static str, String),
}
use Outcome::*;

impl Run {
    fn run(&mut self, id: &str, label: &str, f: impl FnOnce() -> Res<Outcome>) -> Res<()> {
        if self.failed.is_some() {
            self.checks.push(check(id, label, "skipped", "Not evaluated: an earlier check denied the request.", "local"));
            return Ok(());
        }
        let (status, detail, code) = match f()? {
            Pass(d) => ("pass", d, None),
            Fail(c, d) => ("fail", d, Some(c)),
            Review(c, d) => ("review", d, Some(c)),
        };
        self.checks.push(check(id, label, status, &detail, "local"));
        match (status, code) {
            ("fail", Some(c)) => self.failed = Some((c.into(), detail)),
            ("review", Some(c)) if self.review.is_none() => self.review = Some((c.into(), detail)),
            _ => {}
        }
        Ok(())
    }
}

fn check(id: &str, label: &str, status: &str, detail: &str, enforcement: &str) -> Value {
    json!({ "id": id, "label": label, "status": status, "detail": detail, "enforcement": enforcement })
}

pub fn evaluate(policy: &Value, intent: &Value, state: &Value, env: &Value) -> Res<Value> {
    // Typed inputs. The server builds these; anything malformed is an engine error (fails closed).
    let request_id = s(intent, "request_id")?;
    let agent_id = s(intent, "agent_id")?;
    let chain_id = int(field(intent, "chain_id")?).ok_or("chain_id must be an integer")?;
    let from = s(intent, "from")?;
    let to = s(intent, "to")?;
    let value_wei = s(intent, "value_wei")?;
    let data = s(intent, "data")?;
    let deadline = n(intent, "deadline")?;

    let now = n(env, "now")?;
    let fee_estimate = match field(env, "fee_estimate_wei")? {
        Value::Null => None,
        Value::String(v) => Some(v.as_str()),
        _ => return Err("fee_estimate_wei must be a string or null".into()),
    };
    let eth_usd = match field(env, "eth_usd")? {
        Value::Null => None,
        v @ Value::Object(_) => Some((s(v, "price_micros")?, n(v, "observed_at")?)),
        _ => return Err("eth_usd must be an object or null".into()),
    };
    let verified_code = obj(env, "verified_code")?;
    let emergency_stop = b(env, "emergency_stop")?;
    let paused_agents = strings(env, "paused_agents")?;

    let seen_ids = strings(state, "seen_request_ids")?;
    let calldata_seen = obj(state, "calldata_seen")?;
    let intent_seen = obj(state, "intent_seen")?;

    // Expire stale reservations before reading budget state.
    let mut reservations: Vec<Value> = Vec::new();
    for r in arr(state, "reservations")? {
        let st = s(r, "state")?;
        let expires = n(r, "expires_at")?;
        let mut r = r.clone();
        if st == "reserved" && expires <= now {
            r.as_object_mut().ok_or("reservation must be an object")?.insert("state".into(), json!("released"));
        }
        reservations.push(r);
    }

    let mut usd = BigUint::default();
    let mut fee = BigUint::default();
    let value = if is_uint(value_wei) { big(value_wei) } else { BigUint::default() };
    let selector = selector_of(data);
    let to_lower = lower(to);

    let mut r = Run { checks: Vec::new(), failed: None, review: None };

    // Field accessors on the policy; only reached once the policy has validated.
    let p = policy;
    let pint = |path: &[&str]| -> Res<i64> {
        let mut v = p;
        for k in path {
            v = field(v, k)?;
        }
        int(v).ok_or_else(|| format!("policy.{} must be an integer", path.join(".")))
    };
    let pstr = |path: &[&str]| -> Res<String> {
        let mut v = p;
        for k in path {
            v = field(v, k)?;
        }
        v.as_str().map(str::to_owned).ok_or_else(|| format!("policy.{} must be a string", path.join(".")))
    };

    r.run("policy", "Active, valid policy", || {
        let truthy = match p {
            Value::Null | Value::Bool(false) => false,
            Value::Number(x) => x.as_f64() != Some(0.0),
            Value::String(x) => !x.is_empty(),
            _ => true,
        };
        if !truthy {
            return Ok(Fail("PS_POLICY_001", "No policy is configured. A missing policy is never treated as allow-all.".into()));
        }
        let errs = validate(p);
        if let Some((path, msg)) = errs.first() {
            return Ok(Fail("PS_POLICY_001", format!("Policy failed schema validation: {path} {msg}.")));
        }
        let status = pstr(&["status"])?;
        if status != "active" {
            return Ok(Fail("PS_POLICY_001", format!("Policy status is \"{status}\", not active.")));
        }
        Ok(Pass(format!("{} v{} is active.", pstr(&["policy_id"])?, pint(&["version"])?)))
    })?;

    r.run("schema", "Request schema", || {
        let bad = if !is_address(from) {
            Some("from")
        } else if !is_address(to) {
            Some("to")
        } else if !is_uint(value_wei) {
            Some("value_wei")
        } else if !is_hex(data) {
            Some("data")
        } else if (data.len() - 2) / 2 > MAX_CALLDATA_BYTES {
            Some("data (too long)")
        } else if request_id.is_empty() {
            Some("request_id")
        } else {
            None
        };
        Ok(match bad {
            Some(f) => Fail("PS_REQUEST_001", format!("Invalid field: {f}.")),
            None => Pass("All fields well-formed and within size bounds.".into()),
        })
    })?;

    r.run("replay", "Request identity, deadline, replay", || {
        if seen_ids.iter().any(|x| x == request_id) {
            return Ok(Fail("PS_REPLAY_001", format!("request_id {request_id} was already evaluated.")));
        }
        if deadline <= now {
            return Ok(Fail("PS_REPLAY_001", format!("Deadline {deadline} has passed (now {now}).")));
        }
        Ok(Pass(format!("New request; {}s until deadline.", deadline - now)))
    })?;

    r.run("active", "Emergency stop and agent status", || {
        if emergency_stop {
            return Ok(Fail("PS_PAUSED_001", "Global emergency stop is active. All new protected executions are denied.".into()));
        }
        if paused_agents.iter().any(|a| a == agent_id) {
            return Ok(Fail("PS_PAUSED_001", format!("Agent {agent_id} is paused.")));
        }
        Ok(Pass("No emergency stop; agent is active.".into()))
    })?;

    r.run("account_stop", "Emergency stop engaged by the account on the registry", || {
        use crate::asset::{bool_of, int_of, record_of};
        let raw = match env.get("registry_stop") {
            None => return Ok(Pass("The account does not publish to a policy registry.".into())),
            Some(Value::Null) => return Ok(Fail("PS_STATE_001", "The account's stop on the policy registry could not be read, so the request fails closed.".into())),
            v => record_of(v, "registry_stop")?,
        };
        let held = bool_of(raw.get("held_by_account"), "registry_stop.held_by_account")?;
        let age = now - int_of(raw.get("observed_at"), "registry_stop.observed_at")?;
        const MAX: i64 = 60;
        if age > MAX {
            return Ok(Fail("PS_STATE_001", format!("The registry read is {age}s old; maximum is {MAX}s.")));
        }
        if !held {
            return Ok(Pass("No stop engaged by the account on the registry.".into()));
        }
        let exits: Vec<String> = match p.get("loss_limit").and_then(|l| l.get("exit_addresses")) {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(lower).collect(),
            _ => Vec::new(),
        };
        let recipient = match selector.as_deref() {
            None => Some(to_lower.clone()),
            Some("0xa9059cbb") if value == BigUint::default() => crate::loss::transfer_recipient(data),
            _ => None,
        };
        if let Some(rcp) = recipient.filter(|r| exits.contains(r)) {
            return Ok(Pass(format!("The account engaged its stop; a withdrawal to exit address {rcp} stays allowed.")));
        }
        Ok(Fail("PS_PAUSED_001", "The account engaged its emergency stop on the registry. Nothing that adds risk is co-signed until the account lifts it.".into()))
    })?;

    r.run("chain", "Chain and account binding", || {
        let pc = pint(&["account", "chain_id"])?;
        if chain_id != pc {
            return Ok(Fail("PS_TARGET_001", format!("Chain {chain_id} does not match policy chain {pc}.")));
        }
        if lower(from) != lower(&pstr(&["account", "address"])?) {
            return Ok(Fail("PS_POLICY_001", "Sender is not the account this policy protects.".into()));
        }
        Ok(Pass(format!("Chain {chain_id}; account matches.")))
    })?;

    r.run("denylist", "Explicit deny rules", || {
        let deny = p["contracts"]["denylist"].as_array().ok_or("denylist must be an array")?;
        if deny.iter().any(|a| a.as_str().map(lower).as_deref() == Some(to_lower.as_str())) {
            return Ok(Fail("PS_POLICY_002", "Target is on the explicit denylist. Deny overrides allow.".into()));
        }
        Ok(Pass("No deny rule matched.".into()))
    })?;

    let entry = find_entry(policy, &to_lower)?;
    let require_code = entry.and_then(|e| e.get("require_verified_code")).and_then(Value::as_bool).unwrap_or(false);

    r.run("target", "Target contract allowlist", || {
        if entry.is_none() {
            return Ok(Fail("PS_TARGET_001", "Target is not on the allowlist; default is deny.".into()));
        }
        if require_code && verified_code.get(&to_lower) != Some(&Value::Bool(true)) {
            return Ok(Fail("PS_TARGET_001", "Target requires verified code, and verification is missing or failed.".into()));
        }
        Ok(Pass(if require_code { "Allowlisted; code verified per the chain environment's report." } else { "Allowlisted." }.into()))
    })?;

    r.run("method", "Function selector", || {
        let Some(sel) = &selector else {
            return Ok(Pass("Native transfer (no calldata).".into()));
        };
        let sels = entry.and_then(|e| e.get("selectors")).and_then(Value::as_array).ok_or("selectors must be an array")?;
        if sels.iter().any(|x| x.as_str() == Some(sel.as_str())) {
            return Ok(Pass(format!("Selector {sel} is allowed.")));
        }
        if p["human_approval"]["require_for_unknown_methods"] == Value::Bool(true) {
            return Ok(Review("PS_HUMAN_001", format!("Selector {sel} is not allowlisted; policy routes unknown methods to human review.")));
        }
        Ok(Fail("PS_METHOD_001", format!("Selector {sel} is not allowed.")))
    })?;

    // Proven on Zolva: read once, after the policy has validated. Malformed input is an engine error.
    let proven: std::cell::Cell<Option<bool>> = std::cell::Cell::new(None);
    let unlocked = || -> Res<bool> {
        if let Some(u) = proven.get() {
            return Ok(u);
        }
        let u = crate::proven::unlocked(p, env, now)?;
        proven.set(Some(u));
        Ok(u)
    };

    r.run("value", "Per-transaction value limit", || {
        let un = unlocked()?;
        let max = big(&crate::proven::limit(p, un, "max_transaction_value_wei")?);
        let note = if un { crate::proven::NOTE } else { "" };
        if value > max {
            return Ok(Fail("PS_BUDGET_001", format!("Value {value} wei exceeds the per-transaction limit of {max} wei.{note}")));
        }
        Ok(Pass(format!("{value} wei \u{2264} {max} wei.{note}")))
    })?;

    r.run("fee", "Fee estimate", || {
        let Some(f) = fee_estimate.filter(|f| is_uint(f)) else {
            return Ok(Fail("PS_FEE_001", "Fee estimate unavailable. An unknown fee is never treated as zero.".into()));
        };
        fee = big(f);
        let max = big(&pstr(&["limits", "max_gas_cost_wei"])?);
        if fee > max {
            return Ok(Fail("PS_BUDGET_001", format!("Estimated fee {fee} wei exceeds the gas limit of {max} wei.")));
        }
        Ok(Pass(format!("Estimated fee {fee} wei \u{2264} {max} wei.")))
    })?;

    r.run("price", "Price freshness", || {
        let Some((price, observed_at)) = eth_usd else {
            return Ok(Fail("PS_STATE_001", "No price available. USD limits cannot be enforced, so the request fails closed.".into()));
        };
        let age = now - observed_at;
        let max_age = pint(&["limits", "max_price_age_seconds"])?;
        if age > max_age {
            return Ok(Fail("PS_STATE_001", format!("Price is {age}s old; maximum is {max_age}s.")));
        }
        usd = wei_to_usd_micros(&(&value + &fee), &big_strict(price)?);
        Ok(Pass(format!("Price is {age}s old. Exposure: {} (value + fee).", format_usd(&usd))))
    })?;

    r.run("spend", "Token spend (simulated outflows and open allowances, in USD)", || {
        let (outcome, add) = crate::spend::check(policy, env, now, selector.as_deref(), &value, &usd)?;
        usd += add;
        Ok(match outcome {
            crate::asset::Asset::Pass(d) => Pass(d),
            crate::asset::Asset::Fail(c, d) => Fail(c, d),
            crate::asset::Asset::Review(c, d) => Review(c, d),
        })
    })?;

    r.run("budget", "Rolling hourly budget (atomic reservation)", || {
        let since = now - WINDOW_SECONDS;
        let mut used = BigUint::default();
        for x in &reservations {
            if s(x, "state")? != "released" && n(x, "created_at")? > since {
                used += big_strict(s(x, "amount_usd_micros")?)?;
            }
        }
        let un = unlocked()?;
        let max = big(&crate::proven::limit(p, un, "hourly_budget_usd_micros")?);
        let note = if un { crate::proven::NOTE } else { "" };
        let total = &used + &usd;
        if total > max {
            return Ok(Fail(
                "PS_BUDGET_001",
                format!("{} used + {} requested exceeds the {} hourly budget.{note}", format_usd(&used), format_usd(&usd), format_usd(&max)),
            ));
        }
        Ok(Pass(format!("{} of {} after this reservation.{note}", format_usd(&total), format_usd(&max))))
    })?;

    r.run("pending", "Pending operation limit", || {
        let mut open = 0i64;
        for x in &reservations {
            let st = s(x, "state")?;
            if st == "reserved" || st == "pending_approval" {
                open += 1;
            }
        }
        let max = pint(&["limits", "max_pending_operations"])?;
        if open >= max {
            return Ok(Fail("PS_RATE_001", format!("{open} operations pending; limit is {max}.")));
        }
        Ok(Pass(format!("{open} of {max} pending slots in use.")))
    })?;

    let calldata_key = fingerprint(&format!("{}|{}", to_lower, lower(data)));
    let intent_key = fingerprint(&format!("{}|{}|{}|{}", agent_id, to_lower, selector.as_deref().unwrap_or("native"), value_wei));

    r.run("loop", "Repeated calldata and intent", || {
        if let Some(c) = calldata_seen.get(&calldata_key) {
            let c = int(c).ok_or("calldata_seen values must be integers")?;
            let cd = pint(&["cooldowns", "identical_calldata_seconds"])?;
            if now - c < cd {
                return Ok(Fail("PS_LOOP_001", format!("Identical calldata seen {}s ago; cooldown is {cd}s.", now - c)));
            }
        }
        if let Some(i) = intent_seen.get(&intent_key) {
            let i = int(i).ok_or("intent_seen values must be integers")?;
            let id = pint(&["cooldowns", "identical_intent_seconds"])?;
            if now - i < id {
                return Ok(Fail("PS_LOOP_001", format!("Equivalent intent seen {}s ago; cooldown is {id}s.", now - i)));
            }
        }
        Ok(Pass("No repeat within the cooldown windows.".into()))
    })?;

    r.run("asset", "Asset safety (simulated balance changes, sell leg, tax, approvals)", || {
        Ok(match crate::asset::check(policy, intent, env, now, selector.as_deref())? {
            crate::asset::Asset::Pass(d) => Pass(d),
            crate::asset::Asset::Fail(c, d) => Fail(c, d),
            crate::asset::Asset::Review(c, d) => Review(c, d),
        })
    })?;

    r.run("recovery", "Recoverable on Upoch (checkpoint, guardian)", || {
        Ok(match crate::recovery::check(policy, env, now)? {
            crate::asset::Asset::Pass(d) => Pass(d),
            crate::asset::Asset::Fail(c, d) => Fail(c, d),
            crate::asset::Asset::Review(c, d) => Review(c, d),
        })
    })?;

    r.run("loss", "Loss limit (account value against the window's peak)", || {
        Ok(match crate::loss::check(policy, intent, env, now, selector.as_deref(), &value)? {
            crate::asset::Asset::Pass(d) => Pass(d),
            crate::asset::Asset::Fail(c, d) => Fail(c, d),
            crate::asset::Asset::Review(c, d) => Review(c, d),
        })
    })?;

    r.run("human", "Human approval threshold", || {
        let t = big(&pstr(&["human_approval", "usd_threshold_micros"])?);
        if usd >= t {
            return Ok(Review("PS_HUMAN_001", format!("{} meets the {} approval threshold.", format_usd(&usd), format_usd(&t))));
        }
        Ok(Pass(format!("{} is below the {} approval threshold.", format_usd(&usd), format_usd(&t))))
    })?;

    let Run { mut checks, failed, review } = r;
    for (id, label) in LIVE_CHECKS {
        checks.push(check(id, label, "skipped", "Requires a live protected account. The simulator never signs or broadcasts.", "live"));
    }

    // Request IDs are consumed once the request is well-formed, whatever the decision.
    let schema_ok = checks.iter().any(|c| c["id"] == "schema" && c["status"] == "pass");
    let mut seen: Vec<Value> = seen_ids.iter().map(|x| json!(x)).collect();
    if schema_ok && !seen_ids.iter().any(|x| x == request_id) {
        seen.push(json!(request_id));
    }

    let policy_field = |k: &str| match policy {
        Value::Object(m) => m.get(k).cloned().unwrap_or(Value::Null),
        _ => Value::Null,
    };

    if let Some((code, message)) = failed {
        let mut next = state.as_object().ok_or("state must be an object")?.clone();
        next.insert("reservations".into(), Value::Array(reservations));
        next.insert("seen_request_ids".into(), Value::Array(seen));
        return Ok(json!({
            "request_id": request_id,
            "decision": "DENY",
            "reason_code": code,
            "policy_id": policy_field("policy_id"),
            "policy_version": policy_field("version"),
            "authorization_id": null,
            "transaction_hash": null,
            "retryable": retryable(&code),
            "message": message,
            "checks": checks,
            "next_state": next,
        }));
    }

    let policy_id = pstr(&["policy_id"])?;
    let version = pint(&["version"])?;
    let pending = review.is_some();
    let reservation = json!({
        "reservation_id": format!("ps_res_{}", &fingerprint(&format!("{request_id}|{version}"))[2..]),
        "request_id": request_id,
        "agent_id": agent_id,
        "policy_version": version,
        "amount_usd_micros": usd.to_string(),
        "created_at": now,
        "expires_at": now + RESERVATION_TTL_SECONDS,
        "state": if pending { "pending_approval" } else { "reserved" },
    });
    reservations.push(reservation);
    let mut cd = calldata_seen.clone();
    cd.insert(calldata_key, json!(now));
    let mut is = intent_seen.clone();
    is.insert(intent_key, json!(now));

    Ok(json!({
        "request_id": request_id,
        "decision": if pending { "REQUIRES_HUMAN_SIGNATURE" } else { "ALLOW" },
        "reason_code": review.as_ref().map(|r| r.0.clone()),
        "policy_id": policy_field("policy_id"),
        "policy_version": policy_field("version"),
        "authorization_id": if pending { Value::Null } else { json!(format!("ps_auth_{}", &fingerprint(&format!("{request_id}|{policy_id}|{version}"))[2..])) },
        "transaction_hash": null,
        "retryable": false,
        "message": match &review {
            Some((_, m)) => format!("{m} Nothing is signed until an approver signs this exact operation."),
            None => "Authorized. Budget reserved; signing and submission happen only on the protected path.".into(),
        },
        "checks": checks,
        "next_state": {
            "reservations": reservations,
            "seen_request_ids": seen,
            "calldata_seen": cd,
            "intent_seen": is,
        },
    }))
}
