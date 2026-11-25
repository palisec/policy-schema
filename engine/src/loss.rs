//! Loss limit (schema 1.3). Mirrors `lossCheck` in packages/policy-schema/src/simulator.ts: same
//! order, codes and wording. The account's value and the window's peak are measured before
//! evaluation and passed in as `env.loss_snapshot`; malformed input is an engine error (the dual
//! evaluator then fails closed), raised at the same points the reference throws.

use crate::asset::Asset::{self, *};
use crate::asset::{amount_of, amounts, bad, format_bps, int_of, list_of, record_of, str_of, NATIVE_TOKEN};
use crate::js::{big, format_usd, int, lower};
use num_bigint::BigUint;
use serde_json::{Map, Value};

pub const LOSS_SNAPSHOT_MAX_AGE: i64 = 60;
const TRANSFER_SELECTOR: &str = "0xa9059cbb";

type Res<T> = Result<T, String>;

/// `tokenUsdMicros`: USD micros for `amount` base units at `price` micros per whole token.
pub(crate) fn token_usd(amount: &BigUint, price: &BigUint, decimals: u32, up: bool) -> BigUint {
    let scale = BigUint::from(10u32).pow(decimals);
    let n = amount * price;
    if up {
        (n + &scale - 1u32) / scale
    } else {
        n / scale
    }
}

/// `drawdownBps`.
fn drawdown_bps(peak: &BigUint, value: &BigUint) -> BigUint {
    let zero = BigUint::default();
    let loss = if peak > value { peak - value } else { zero.clone() };
    if *peak == zero {
        zero
    } else {
        loss * 10000u32 / peak
    }
}

/// `lossBreach`: USD first.
fn loss_breach(usd_max: &BigUint, bps_max: i64, peak: &BigUint, value: &BigUint) -> Option<&'static str> {
    let zero = BigUint::default();
    let loss = if peak > value { peak - value } else { zero.clone() };
    if *usd_max > zero && loss >= *usd_max {
        return Some("PS_LOSS_002");
    }
    if bps_max > 0 && drawdown_bps(peak, value) >= BigUint::from(bps_max as u64) {
        return Some("PS_LOSS_001");
    }
    None
}

pub(crate) fn transfer_recipient(data: &str) -> Option<String> {
    if data.len() < 138 || lower(&data[..10]) != TRANSFER_SELECTOR {
        return None;
    }
    if !data[10..34].bytes().all(|c| c == b'0') {
        return None;
    }
    Some(format!("0x{}", lower(&data[34..74])))
}

fn addresses(rules: &Map<String, Value>, k: &str) -> Res<Vec<String>> {
    match rules.get(k) {
        Some(Value::Array(a)) => a.iter().map(|v| v.as_str().map(lower).ok_or_else(|| format!("loss_limit.{k} must hold strings"))).collect(),
        _ => Err(format!("loss_limit.{k} must be an array")),
    }
}

/// Value of a set of amounts; None when one of them has no reliable price right now.
fn worth(m: &[(String, BigUint)], prices: &[(String, BigUint, u32)], missing: &[String], up: bool) -> Option<BigUint> {
    let mut sum = BigUint::default();
    for (t, a) in m {
        if missing.contains(t) {
            return None;
        }
        if let Some((_, p, d)) = prices.iter().find(|(k, _, _)| k == t) {
            sum += token_usd(a, p, *d, up);
        }
    }
    Some(sum)
}

pub fn check(policy: &Value, intent: &Value, env: &Value, now: i64, selector: Option<&str>, value: &BigUint) -> Res<Asset> {
    let rules = match policy.get("loss_limit") {
        Some(Value::Object(r)) => r,
        _ => return Ok(Pass("Loss limit is off for this policy.".into())),
    };
    if rules.get("enabled") != Some(&Value::Bool(true)) {
        return Ok(Pass("Loss limit is off for this policy.".into()));
    }
    let exits = addresses(rules, "exit_addresses")?;
    let stables = addresses(rules, "stablecoins")?;
    let review_unavailable = rules.get("on_valuation_unavailable").and_then(Value::as_str) == Some("review");
    let review_breach = rules.get("on_breach").and_then(Value::as_str) == Some("review");
    let unavailable = |why: String| -> Asset {
        if review_unavailable {
            Review("PS_LOSS_003", format!("{why} The policy holds this for a human instead of allowing it."))
        } else {
            Fail("PS_LOSS_003", format!("{why} Without a reliable account value, nothing that adds risk is allowed."))
        }
    };
    let breach = |code: &'static str, why: String| -> Asset {
        if review_breach {
            Review(code, format!("{why} The policy holds this for a human."))
        } else {
            Fail(code, format!("{why} Only risk-reducing actions are allowed until the owner resets the limit."))
        }
    };
    let rule_int = |k: &str| rules.get(k).and_then(int).ok_or_else(|| format!("loss_limit.{k} must be an integer"));
    let to = lower(intent.get("to").and_then(Value::as_str).ok_or("to must be a string")?);
    let data = intent.get("data").and_then(Value::as_str).ok_or("data must be a string")?;
    let raw_sim = match env.get("asset_simulation") {
        None | Some(Value::Null) => None,
        v => Some(v),
    };
    let zero = BigUint::default();

    // A withdrawal to the owner or recovery wallet is never a loss, and needs no price.
    if selector.is_none() && exits.contains(&to) {
        return Ok(Pass(format!("Transfer to exit address {to}: a withdrawal, not a loss.")));
    }
    let recipient = if selector == Some(TRANSFER_SELECTOR) && *value == zero { transfer_recipient(data) } else { None };
    if let Some(recipient) = recipient.filter(|r| exits.contains(r)) {
        let mut pure = true;
        if let Some(v) = raw_sim {
            let sim = record_of(v, "asset_simulation")?;
            let out = amounts(sim.get("outflows"), "outflows")?;
            let inn = amounts(sim.get("inflows"), "inflows")?;
            pure = inn.is_empty() && out.iter().all(|(t, _)| *t == to);
        } else {
            // Without a simulation, only a transfer of one of the policy's stablecoins is taken at its word.
            pure = stables.contains(&to);
        }
        if pure {
            return Ok(Pass(format!("Token transfer to exit address {recipient}: a withdrawal, not a loss.")));
        }
    }

    let snap = match env.get("loss_snapshot") {
        None | Some(Value::Null) => return Ok(unavailable("Account value unavailable.".into())),
        v => record_of(v, "loss_snapshot")?,
    };
    let age = now - int_of(snap.get("observed_at"), "loss_snapshot.observed_at")?;
    if age > LOSS_SNAPSHOT_MAX_AGE {
        return Ok(unavailable(format!("Account value is {age}s old; maximum is {LOSS_SNAPSHOT_MAX_AGE}s.")));
    }
    let mut paused: Option<&'static str> = match snap.get("paused") {
        Some(Value::Null) => None,
        v => match str_of(v, "loss_snapshot.paused")? {
            "PS_LOSS_001" => Some("PS_LOSS_001"),
            "PS_LOSS_002" => Some("PS_LOSS_002"),
            _ => return bad("loss_snapshot.paused must be PS_LOSS_001, PS_LOSS_002 or null"),
        },
    };
    let mut prices: Vec<(String, BigUint, u32)> = Vec::new();
    for x in list_of(snap.get("prices"), "loss_snapshot.prices")? {
        let o = record_of(Some(x), "loss_snapshot.prices")?;
        let t = lower(str_of(o.get("token"), "prices.token")?);
        let price = amount_of(o.get("price_micros"), "prices.price_micros")?;
        let decimals = int_of(o.get("decimals"), "prices.decimals")?;
        if !(0..=36).contains(&decimals) {
            return bad("prices.decimals must be between 0 and 36");
        }
        if !prices.iter().any(|(k, _, _)| *k == t) {
            prices.push((t, price, decimals as u32));
        }
    }
    let mut missing: Vec<String> = Vec::new();
    for t in list_of(snap.get("unavailable"), "loss_snapshot.unavailable")? {
        missing.push(lower(str_of(Some(t), "unavailable")?));
    }
    let value_now = match snap.get("value_usd_micros") {
        Some(Value::Null) => None,
        v => Some(amount_of(v, "loss_snapshot.value_usd_micros")?),
    };
    let peak = match snap.get("baseline_usd_micros") {
        Some(Value::Null) => None,
        v => Some(amount_of(v, "loss_snapshot.baseline_usd_micros")?),
    };

    // What this operation does to the account's assets.
    let mut out: Vec<(String, BigUint)> = Vec::new();
    let mut inn: Vec<(String, BigUint)> = Vec::new();
    let mut approvals: Vec<(String, BigUint)> = Vec::new();
    if selector.is_none() {
        if *value > zero {
            out.push((NATIVE_TOKEN.to_string(), value.clone()));
        }
    } else {
        let Some(v) = raw_sim else {
            return Ok(unavailable("No simulation of this operation, so its effect on the account's value is unknown.".into()));
        };
        let sim = record_of(v, "asset_simulation")?;
        let sim_age = now - int_of(sim.get("observed_at"), "observed_at")?;
        if sim_age > LOSS_SNAPSHOT_MAX_AGE {
            return Ok(unavailable(format!("Simulation is {sim_age}s old; maximum is {LOSS_SNAPSHOT_MAX_AGE}s.")));
        }
        out = amounts(sim.get("outflows"), "outflows")?;
        inn = amounts(sim.get("inflows"), "inflows")?;
        for x in list_of(sim.get("approvals"), "approvals")? {
            let o = record_of(Some(x), "approvals")?;
            approvals.push((lower(str_of(o.get("spender"), "approvals.spender")?), amount_of(o.get("amount"), "approvals.amount")?));
        }
    }

    let usd_max = big(rules.get("max_loss_usd_micros").and_then(Value::as_str).ok_or("loss_limit.max_loss_usd_micros must be a string")?);
    let bps_max = rule_int("max_drawdown_bps")?;
    if paused.is_none() {
        if let (Some(v), Some(p)) = (&value_now, &peak) {
            paused = loss_breach(&usd_max, bps_max, p, v);
        }
    }

    // While paused, every approval must be bounded and to an allowlisted contract (no later drain).
    let safe_approvals = {
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
        approvals.iter().all(|(s, a)| *a < unlimited && !deny.contains(s) && allow.contains(s))
    };
    let approval_breach = |code: &'static str| {
        breach(code, format!("The loss limit was reached ({code}) and this operation grants an approval that is not bounded or not to an allowlisted contract."))
    };

    if out.is_empty() && inn.is_empty() {
        let Some(code) = paused else {
            return Ok(Pass("No value moves in this operation.".into()));
        };
        if safe_approvals {
            return Ok(Pass("No value moves (bounded approvals to allowlisted contracts only): allowed while paused.".into()));
        }
        return Ok(approval_breach(code));
    }

    if let Some(code) = paused {
        let reducing = !inn.is_empty() && inn.iter().all(|(t, _)| stables.contains(t));
        if !reducing {
            return Ok(breach(code, format!("The loss limit was reached ({code}) and this operation adds risk.")));
        }
        if !safe_approvals {
            return Ok(approval_breach(code));
        }
        let (Some(sold), Some(got)) = (worth(&out, &prices, &missing, true), worth(&inn, &prices, &missing, false)) else {
            return Ok(unavailable("A price needed to check this exit swap is unavailable.".into()));
        };
        let slip = rule_int("max_exit_slippage_bps")?;
        let min = &sold * BigUint::from((10000 - slip) as u64) / 10000u32;
        if got < min {
            return Ok(breach(
                code,
                format!(
                    "Exit swap returns {} for {}, more than the {} exit slippage allowed while paused.",
                    format_usd(&got),
                    format_usd(&sold),
                    format_bps(slip)
                ),
            ));
        }
        return Ok(Pass(format!("Risk-reducing swap into a stablecoin ({} for {}): allowed while paused.", format_usd(&got), format_usd(&sold))));
    }

    let (Some(value_now), Some(peak)) = (value_now, peak) else {
        return Ok(unavailable("A price for an asset the account holds is unavailable.".into()));
    };
    let (Some(sold), Some(got)) = (worth(&out, &prices, &missing, true), worth(&inn, &prices, &missing, false)) else {
        return Ok(unavailable("A price for an asset this operation moves is unavailable.".into()));
    };
    let gross = &value_now + &got;
    let after = if gross > sold { gross - &sold } else { zero.clone() };
    let loss = if peak > after { &peak - &after } else { zero.clone() };
    let dd = drawdown_bps(&peak, &after);
    let dd = i64::try_from(&dd).unwrap_or(10000);
    match loss_breach(&usd_max, bps_max, &peak, &after) {
        Some(code @ "PS_LOSS_002") => Ok(breach(
            code,
            format!(
                "This operation would bring the loss to {}, at or above the {} limit (peak {}, value after {}).",
                format_usd(&loss),
                format_usd(&usd_max),
                format_usd(&peak),
                format_usd(&after)
            ),
        )),
        Some(code) => Ok(breach(
            code,
            format!(
                "This operation would bring the drawdown to {}, at or above the {} limit (peak {}, value after {}).",
                format_bps(dd),
                format_bps(bps_max),
                format_usd(&peak),
                format_usd(&after)
            ),
        )),
        None => Ok(Pass(format!(
            "Loss after this operation {}, drawdown {} (peak {}, value after {}).",
            format_usd(&loss),
            format_bps(dd),
            format_usd(&peak),
            format_usd(&after)
        ))),
    }
}
