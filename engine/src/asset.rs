//! Asset safety (schema 1.1). Mirrors `assetCheck` in packages/policy-schema/src/simulator.ts:
//! same order, same reason codes, same wording. The simulation is an input; nothing here reads
//! the chain, so the result is deterministic. Malformed simulation input is an engine error
//! (the dual evaluator then fails closed), raised at the same points the reference throws.

use crate::js::{int, is_uint, lower};
use num_bigint::BigUint;
use serde_json::{Map, Value};

pub const NATIVE_TOKEN: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

pub enum Asset {
    Pass(String),
    Fail(&'static str, String),
    Review(&'static str, String),
}
use Asset::*;

type Res<T> = Result<T, String>;

pub(crate) fn bad<T>(why: &str) -> Res<T> {
    Err(format!("asset simulation input: {why}"))
}
pub(crate) fn str_of<'a>(v: Option<&'a Value>, what: &str) -> Res<&'a str> {
    match v {
        Some(Value::String(s)) => Ok(s),
        _ => bad(&format!("{what} must be a string")),
    }
}
pub(crate) fn amount_of(v: Option<&Value>, what: &str) -> Res<BigUint> {
    let s = str_of(v, what)?;
    if is_uint(s) {
        Ok(s.parse().unwrap_or_default())
    } else {
        bad(&format!("{what} must be a decimal integer"))
    }
}
pub(crate) fn int_of(v: Option<&Value>, what: &str) -> Res<i64> {
    match v.and_then(int) {
        Some(n) => Ok(n),
        None => bad(&format!("{what} must be an integer")),
    }
}
pub(crate) fn list_of<'a>(v: Option<&'a Value>, what: &str) -> Res<&'a Vec<Value>> {
    match v {
        Some(Value::Array(a)) => Ok(a),
        _ => bad(&format!("{what} must be an array")),
    }
}
pub(crate) fn record_of<'a>(v: Option<&'a Value>, what: &str) -> Res<&'a Map<String, Value>> {
    match v {
        Some(Value::Object(m)) => Ok(m),
        _ => bad(&format!("{what} must be an object")),
    }
}
pub(crate) fn bool_of(v: Option<&Value>, what: &str) -> Res<bool> {
    match v {
        Some(Value::Bool(b)) => Ok(*b),
        _ => bad(&format!("{what} must be a boolean")),
    }
}

/// token (lowercase) -> amount, summed, in first-seen order (a JavaScript Map).
pub(crate) fn amounts(v: Option<&Value>, what: &str) -> Res<Vec<(String, BigUint)>> {
    let mut out: Vec<(String, BigUint)> = Vec::new();
    for x in list_of(v, what)? {
        let o = record_of(Some(x), what)?;
        let t = lower(str_of(o.get("token"), &format!("{what}.token"))?);
        let a = amount_of(o.get("amount"), &format!("{what}.amount"))?;
        match out.iter_mut().find(|(k, _)| *k == t) {
            Some((_, sum)) => *sum += a,
            None => out.push((t, a)),
        }
    }
    Ok(out)
}
fn get<'a>(m: &'a [(String, BigUint)], k: &str) -> Option<&'a BigUint> {
    m.iter().find(|(t, _)| t == k).map(|(_, a)| a)
}

/// `formatBps`: 2000 -> "20.00%".
pub fn format_bps(bps: i64) -> String {
    format!("{}.{:0>2}%", bps.div_euclid(100), bps.rem_euclid(100))
}

pub fn check(policy: &Value, intent: &Value, env: &Value, now: i64, selector: Option<&str>) -> Res<Asset> {
    let rules = match policy.get("asset_safety") {
        Some(Value::Object(r)) => r,
        _ => return Ok(Pass("Asset safety is off for this policy.".into())),
    };
    if rules.get("enabled") != Some(&Value::Bool(true)) {
        return Ok(Pass("Asset safety is off for this policy.".into()));
    }
    if selector.is_none() {
        return Ok(Pass("Native transfer: no contract call to simulate.".into()));
    }
    let review = rules.get("on_simulation_unavailable").and_then(Value::as_str) == Some("review");
    let unavailable = |why: String| -> Asset {
        if review {
            Review("PS_SIM_001", format!("{why} The policy holds this for a human instead of allowing it."))
        } else {
            Fail("PS_SIM_001", format!("{why} Without a simulation the request fails closed."))
        }
    };
    let rule_int = |k: &str| rules.get(k).and_then(int).ok_or_else(|| format!("asset_safety.{k} must be an integer"));

    let sim = match env.get("asset_simulation") {
        None | Some(Value::Null) => return Ok(unavailable("Simulation unavailable.".into())),
        v => record_of(v, "asset_simulation")?,
    };
    let block = int_of(sim.get("block_number"), "block_number")?;
    let age = now - int_of(sim.get("observed_at"), "observed_at")?;
    let max_age = rule_int("max_simulation_age_seconds")?;
    if age > max_age {
        return Ok(unavailable(format!("Simulation is {age}s old; maximum is {max_age}s.")));
    }
    if bool_of(sim.get("reverted"), "reverted")? {
        return Ok(Fail("PS_SIM_001", format!("The transaction reverts in simulation at block {block}.")));
    }

    let declared = match intent.get("asset_intent") {
        None => None,
        v => Some(record_of(v, "asset_intent")?),
    };
    let empty = Value::Array(Vec::new());
    let spend = amounts(Some(declared.and_then(|d| d.get("spend")).unwrap_or(if declared.is_some() { &Value::Null } else { &empty })), "asset_intent.spend")?;
    let receive = amounts(Some(declared.and_then(|d| d.get("receive")).unwrap_or(if declared.is_some() { &Value::Null } else { &empty })), "asset_intent.receive")?;
    let outflows = amounts(sim.get("outflows"), "outflows")?;
    let inflows = amounts(sim.get("inflows"), "inflows")?;
    let mut approvals: Vec<(String, String, BigUint)> = Vec::new();
    for x in list_of(sim.get("approvals"), "approvals")? {
        let o = record_of(Some(x), "approvals")?;
        approvals.push((
            lower(str_of(o.get("token"), "approvals.token")?),
            lower(str_of(o.get("spender"), "approvals.spender")?),
            amount_of(o.get("amount"), "approvals.amount")?,
        ));
    }
    let sell_reverted = match sim.get("sell") {
        Some(Value::Null) => None,
        v => Some(bool_of(record_of(v, "sell")?.get("reverted"), "sell.reverted")?),
    };
    let tax = match sim.get("tax_bps") {
        Some(Value::Null) => None,
        v => Some(int_of(v, "tax_bps")?),
    };
    let loss = match sim.get("round_trip_loss_bps") {
        Some(Value::Null) => None,
        v => Some(int_of(v, "round_trip_loss_bps")?),
    };

    if rules.get("block_unlimited_approvals") == Some(&Value::Bool(true)) {
        let contracts = &policy["contracts"];
        let deny: Vec<String> = contracts["denylist"].as_array().ok_or("denylist must be an array")?.iter().filter_map(Value::as_str).map(lower).collect();
        let allow: Vec<String> = contracts["allowlist"]
            .as_array()
            .ok_or("allowlist must be an array")?
            .iter()
            .filter_map(|e| e.get("address").and_then(Value::as_str))
            .map(lower)
            .collect();
        let unlimited = BigUint::from(1u32) << 128u32;
        for (token, spender, amount) in &approvals {
            let trusted = !deny.contains(spender) && allow.contains(spender);
            if *amount == BigUint::default() || trusted {
                continue;
            }
            let allowed = get(&spend, token);
            // An exact declared amount is fine; an unlimited one never is, declared or not.
            if allowed == Some(amount) && *amount < unlimited {
                continue;
            }
            let what = if *amount >= unlimited { "an unlimited amount".to_string() } else { amount.to_string() };
            let of = allowed.map(|a| format!(" of {a}")).unwrap_or_default();
            return Ok(Fail(
                "PS_APPROVAL_001",
                format!("Approves {what} of {token} to {spender}, which is not an allowlisted contract, and the amount is not the declared spend{of}."),
            ));
        }
    }

    let received: Vec<&String> = inflows.iter().map(|(t, _)| t).filter(|t| t.as_str() != NATIVE_TOKEN).collect();
    if !received.is_empty() && rules.get("require_sell_simulation") == Some(&Value::Bool(true)) {
        match sell_reverted {
            None => return Ok(unavailable(format!("No sell leg could be simulated for {}.", received[0]))),
            Some(true) => {
                return Ok(Fail("PS_ASSET_001", format!("Selling {} back reverts in simulation at block {block}: likely a honeypot.", received[0])));
            }
            Some(false) => {}
        }
    }
    let max_tax = rule_int("max_transfer_tax_bps")?;
    if let Some(t) = tax {
        if t > max_tax {
            return Ok(Fail("PS_ASSET_002", format!("Transfer tax {} exceeds the policy maximum of {}.", format_bps(t), format_bps(max_tax))));
        }
    }

    for (token, out) in &outflows {
        match get(&spend, token) {
            None => return Ok(Fail("PS_ASSET_003", format!("{out} of {token} leaves the account, but the request declares no spend of it."))),
            Some(allowed) if out > allowed => {
                return Ok(Fail("PS_ASSET_003", format!("{out} of {token} leaves the account, more than the declared {allowed}.")));
            }
            _ => {}
        }
    }
    let slippage = rule_int("max_slippage_bps")?;
    for (token, quoted) in &receive {
        let got = get(&inflows, token).cloned().unwrap_or_default();
        let min = quoted * BigUint::from((10000 - slippage) as u64) / BigUint::from(10000u32);
        if got < min {
            return Ok(Fail(
                "PS_ASSET_003",
                format!("Receives {got} of {token}, below the quoted {quoted} less {} slippage.", format_bps(slippage)),
            ));
        }
    }

    let mut parts = vec![
        format!("Simulated at block {block} ({age}s old)"),
        format!("tax {}", tax.map(format_bps).unwrap_or_else(|| "n/a".into())),
        format!("round-trip loss {}", loss.map(format_bps).unwrap_or_else(|| "n/a".into())),
        format!("approvals {}", approvals.len()),
        format!("{} token(s) out, {} in", outflows.len(), inflows.len()),
    ];
    if !received.is_empty() {
        parts.push(if sell_reverted == Some(false) { "sell leg ok" } else { "sell leg not required" }.into());
    }
    Ok(Pass(format!("{}.", parts.join("; "))))
}

#[cfg(test)]
mod tests {
    use super::format_bps;

    #[test]
    fn bps() {
        assert_eq!(format_bps(2000), "20.00%");
        assert_eq!(format_bps(5), "0.05%");
        assert_eq!(format_bps(10000), "100.00%");
    }
}
