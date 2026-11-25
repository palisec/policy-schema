//! Token spend limits (schema 1.5). Mirrors `spendCheck` in packages/policy-schema/src/simulator.ts:
//! same order, codes and wording. The simulation and the spent tokens' prices are inputs made before
//! evaluation; malformed input is an engine error (the dual evaluator then fails closed), raised at the
//! same points the reference throws.

use crate::asset::Asset::{self, *};
use crate::asset::{amount_of, amounts, bad, bool_of, int_of, list_of, record_of, str_of, NATIVE_TOKEN};
use crate::js::{big, big_strict, format_usd, lower, wei_to_usd_micros};
use crate::loss::token_usd;
use num_bigint::BigUint;
use serde_json::Value;

pub const SPEND_INPUT_MAX_AGE: i64 = 60;
const TRANSFER_SELECTOR: &str = "0xa9059cbb";
const APPROVE_SELECTOR: &str = "0x095ea7b3";

type Res<T> = Result<T, String>;

struct Allowance {
    token: String,
    spender: String,
    amount: BigUint,
}

fn allowance_list(v: Option<&Value>, what: &str) -> Res<Vec<Allowance>> {
    let mut out = Vec::new();
    for x in list_of(v, what)? {
        let o = record_of(Some(x), what)?;
        out.push(Allowance {
            token: lower(str_of(o.get("token"), &format!("{what}.token"))?),
            spender: lower(str_of(o.get("spender"), &format!("{what}.spender"))?),
            amount: amount_of(o.get("amount"), &format!("{what}.amount"))?,
        });
    }
    Ok(out)
}

/// Returns the outcome and the USD micros this check adds to the exposure. `base` is value + fee.
pub fn check(policy: &Value, env: &Value, now: i64, selector: Option<&str>, value: &BigUint, base: &BigUint) -> Res<(Asset, BigUint)> {
    let zero = BigUint::default();
    let rules = match policy.get("token_spend") {
        Some(Value::Object(r)) if r.get("enabled") == Some(&Value::Bool(true)) => r,
        _ => return Ok((Pass("Token spend is not counted by this policy: the limits count ETH value and fee only.".into()), zero)),
    };
    let cap = big(rules.get("max_transaction_usd_micros").and_then(Value::as_str).ok_or("token_spend.max_transaction_usd_micros must be a string")?);
    let capped = |total: &BigUint, what: &str| -> Asset {
        if *total > cap {
            Fail("PS_BUDGET_001", format!("Exposure {} ({what}) exceeds the per-transaction limit of {}.", format_usd(total), format_usd(&cap)))
        } else {
            Pass(format!("Exposure {} ({what}) \u{2264} {}.", format_usd(total), format_usd(&cap)))
        }
    };
    let unknown = |why: String| -> (Asset, BigUint) {
        (Fail("PS_SIM_002", format!("{why} The tokens this transaction spends are unknown, so it fails closed.")), BigUint::default())
    };
    let sim = match env.get("asset_simulation") {
        None | Some(Value::Null) => return Ok(unknown("Simulation unavailable.".into())),
        v => record_of(v, "asset_simulation")?,
    };
    let block = int_of(sim.get("block_number"), "block_number")?;
    let age = now - int_of(sim.get("observed_at"), "observed_at")?;
    if age > SPEND_INPUT_MAX_AGE {
        return Ok(unknown(format!("Simulation is {age}s old; maximum is {SPEND_INPUT_MAX_AGE}s.")));
    }
    if bool_of(sim.get("reverted"), "reverted")? {
        return Ok((Fail("PS_SIM_001", format!("The transaction reverts in simulation at block {block}.")), zero));
    }
    let outflows = amounts(sim.get("outflows"), "outflows")?;
    let inflows = amounts(sim.get("inflows"), "inflows")?;
    let approvals = allowance_list(sim.get("approvals"), "approvals")?;
    // Allowance left open per (token, spender), in first-seen order (a JavaScript Map).
    let source = match sim.get("allowances_after") {
        None => approvals,
        v => allowance_list(v, "allowances_after")?,
    };
    let mut open: Vec<Allowance> = Vec::new();
    for a in source {
        match open.iter_mut().find(|x| x.token == a.token && x.spender == a.spender) {
            Some(x) => x.amount = a.amount,
            None => open.push(a),
        }
    }

    let spent: Vec<&(String, BigUint)> = outflows.iter().filter(|(t, _)| t != NATIVE_TOKEN).collect();
    let require_output = rules.get("require_output_to_account") == Some(&Value::Bool(true));
    if require_output && selector != Some(TRANSFER_SELECTOR) && selector != Some(APPROVE_SELECTOR) && !spent.is_empty() && inflows.is_empty() {
        let (t, a) = spent[0];
        return Ok((
            Fail("PS_ASSET_003", format!("{a} of {t} leaves the account and nothing comes back into it: a swap's output must return to the account.")),
            zero,
        ));
    }
    let unlimited = BigUint::from(1u32) << 128u32;
    if let Some(a) = open.iter().find(|a| a.amount >= unlimited) {
        return Ok((
            Fail("PS_BUDGET_001", format!("Leaves an unlimited allowance of {} to {}, which no spending limit can cover.", a.token, a.spender)),
            zero,
        ));
    }

    // What is counted, per token: what leaves now plus what stays approved.
    let mut counted: Vec<(String, BigUint)> = spent.iter().map(|(t, a)| (t.clone(), a.clone())).collect();
    for a in open.iter().filter(|a| a.amount > zero) {
        match counted.iter_mut().find(|(t, _)| *t == a.token) {
            Some((_, sum)) => *sum += &a.amount,
            None => counted.push((a.token.clone(), a.amount.clone())),
        }
    }
    let native_out = outflows.iter().find(|(t, _)| t == NATIVE_TOKEN).map(|(_, a)| a.clone()).unwrap_or_default();
    let extra_wei = if native_out > *value { &native_out - value } else { zero.clone() };
    let mut add = if extra_wei > zero {
        let price = env.get("eth_usd").and_then(|p| p.get("price_micros")).and_then(Value::as_str).ok_or("eth_usd.price_micros must be a string")?;
        wei_to_usd_micros(&extra_wei, &big_strict(price)?)
    } else {
        zero.clone()
    };
    if counted.is_empty() {
        let total = base + &add;
        return Ok((capped(&total, "value + fee; no tokens leave the account"), add));
    }

    let review = rules.get("on_price_unavailable").and_then(Value::as_str) == Some("review");
    let no_price = |why: String, add: BigUint| -> (Asset, BigUint) {
        let total = base + &add;
        if total > cap {
            return (capped(&total, "value + fee + priced tokens"), add);
        }
        if review {
            (Review("PS_PRICE_001", format!("{why} The policy holds this for a human instead of allowing it.")), add)
        } else {
            (Fail("PS_PRICE_001", format!("{why} A spent token is never counted as $0, so the request fails closed.")), add)
        }
    };
    let sp = match env.get("spend_prices") {
        None | Some(Value::Null) => return Ok(no_price("Token prices unavailable.".into(), add)),
        v => record_of(v, "spend_prices")?,
    };
    let price_age = now - int_of(sp.get("observed_at"), "spend_prices.observed_at")?;
    if price_age > SPEND_INPUT_MAX_AGE {
        return Ok(no_price(format!("Token prices are {price_age}s old; maximum is {SPEND_INPUT_MAX_AGE}s."), add));
    }
    let mut prices: Vec<(String, BigUint, u32)> = Vec::new();
    for x in list_of(sp.get("prices"), "spend_prices.prices")? {
        let o = record_of(Some(x), "spend_prices.prices")?;
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
    for t in list_of(sp.get("unavailable"), "spend_prices.unavailable")? {
        missing.push(lower(str_of(Some(t), "unavailable")?));
    }
    let mut tokens = BigUint::default();
    let mut unpriced: Option<&str> = None;
    for (t, a) in &counted {
        match prices.iter().find(|(k, _, _)| k == t) {
            Some((_, p, d)) if !missing.contains(t) => tokens += token_usd(a, p, *d, true),
            _ => {
                if unpriced.is_none() {
                    unpriced = Some(t);
                }
            }
        }
    }
    add += &tokens;
    if let Some(t) = unpriced {
        return Ok(no_price(format!("No reliable price for {t}, which this transaction spends or leaves approved."), add));
    }
    let allowances = open.iter().filter(|a| a.amount > zero).count();
    let note = if allowances > 0 { format!(", {allowances} open allowance(s)") } else { String::new() };
    let total = base + &add;
    Ok((capped(&total, &format!("value + fee + {} in {} token(s){note}", format_usd(&tokens), counted.len())), add))
}
