//! Policy schema 1.0 to 1.5 validation. Mirrors `validatePolicy` in packages/policy-schema: same rules,
//! same paths, same messages, same order. Unknown fields are rejected so a typo cannot disable a rule.

use crate::js::{int_in, is_address, is_policy_id, is_selector, is_uint, js_keys};
use serde_json::{json, Map, Value};

pub const SCHEMA_VERSIONS: [&str; 6] = ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5"];
const MAX_ALLOWLIST: usize = 256;
const MAX_SELECTORS: usize = 64;
const MAX_LOSS_ADDRESSES: usize = 16;
const I31: i64 = 2_147_483_647;

pub struct Validator {
    pub errors: Vec<(String, String)>,
}

impl Validator {
    fn err(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.errors.push((path.into(), message.into()));
    }

    fn fields(&mut self, o: &Map<String, Value>, path: &str, allowed: &[&str]) {
        for k in js_keys(o) {
            if !allowed.contains(&k.as_str()) {
                self.err(format!("{path}.{k}"), "unknown field");
            }
        }
    }

    fn obj<'a>(&mut self, o: &'a Map<String, Value>, key: &str, path: &str) -> Option<&'a Map<String, Value>> {
        match o.get(key) {
            Some(Value::Object(m)) => Some(m),
            _ => {
                self.err(format!("{path}.{key}"), "required object");
                None
            }
        }
    }

    fn uint(&mut self, o: &Map<String, Value>, key: &str, path: &str) {
        let ok = matches!(o.get(key), Some(Value::String(s)) if is_uint(s));
        if !ok {
            self.err(format!("{path}.{key}"), "must be a non-negative integer string");
        }
    }

    fn int(&mut self, o: &Map<String, Value>, key: &str, path: &str, min: i64, max: i64) {
        if !int_in(o.get(key), min, max) {
            self.err(format!("{path}.{key}"), format!("must be an integer between {min} and {max}"));
        }
    }

    fn bool(&mut self, o: &Map<String, Value>, key: &str, path: &str) {
        if !matches!(o.get(key), Some(Value::Bool(_))) {
            self.err(format!("{path}.{key}"), "must be a boolean");
        }
    }

    fn address(&mut self, v: Option<&Value>, path: String) {
        if !matches!(v, Some(Value::String(s)) if is_address(s)) {
            self.err(path, "must be a 20-byte hex address");
        }
    }
}

/// Returns `(path, message)` pairs; empty when the policy is valid.
pub fn validate(doc: &Value) -> Vec<(String, String)> {
    let Value::Object(doc) = doc else {
        return vec![("$".into(), "policy must be an object".into())];
    };
    let mut v = Validator { errors: Vec::new() };
    v.fields(
        doc,
        "$",
        &["schema_version", "policy_id", "version", "account", "status", "limits", "cooldowns", "contracts", "human_approval", "failure_mode", "asset_safety", "upoch_recovery", "loss_limit", "proven_record", "token_spend"],
    );

    if !matches!(doc.get("schema_version"), Some(Value::String(s)) if SCHEMA_VERSIONS.contains(&s.as_str())) {
        v.err("$.schema_version", "must be \"1.0\", \"1.1\", \"1.2\", \"1.3\", \"1.4\" or \"1.5\"");
    }
    if !matches!(doc.get("policy_id"), Some(Value::String(s)) if is_policy_id(s)) {
        v.err("$.policy_id", "must be 3-64 chars of a-z, 0-9, _");
    }
    v.int(doc, "version", "$", 1, I31);
    if !matches!(doc.get("status"), Some(Value::String(s)) if s == "draft" || s == "active" || s == "disabled") {
        v.err("$.status", "must be \"draft\", \"active\" or \"disabled\"");
    }
    if doc.get("failure_mode") != Some(&Value::String("closed".into())) {
        v.err("$.failure_mode", "must be \"closed\"; fail-open is not supported");
    }

    if let Some(account) = v.obj(doc, "account", "$") {
        v.fields(account, "$.account", &["chain_id", "address"]);
        v.int(account, "chain_id", "$.account", 1, I31);
        v.address(account.get("address"), "$.account.address".into());
    }

    if let Some(limits) = v.obj(doc, "limits", "$") {
        v.fields(
            limits,
            "$.limits",
            &["max_transaction_value_wei", "max_gas_cost_wei", "hourly_budget_usd_micros", "max_pending_operations", "max_price_age_seconds"],
        );
        v.uint(limits, "max_transaction_value_wei", "$.limits");
        v.uint(limits, "max_gas_cost_wei", "$.limits");
        v.uint(limits, "hourly_budget_usd_micros", "$.limits");
        v.int(limits, "max_pending_operations", "$.limits", 0, 1000);
        v.int(limits, "max_price_age_seconds", "$.limits", 1, 3600);
    }

    if let Some(cooldowns) = v.obj(doc, "cooldowns", "$") {
        v.fields(cooldowns, "$.cooldowns", &["identical_calldata_seconds", "identical_intent_seconds"]);
        v.int(cooldowns, "identical_calldata_seconds", "$.cooldowns", 0, 86400);
        v.int(cooldowns, "identical_intent_seconds", "$.cooldowns", 0, 86400);
    }

    if let Some(contracts) = v.obj(doc, "contracts", "$") {
        v.fields(contracts, "$.contracts", &["default", "allowlist", "denylist"]);
        if contracts.get("default") != Some(&Value::String("deny".into())) {
            v.err("$.contracts.default", "must be \"deny\"");
        }
        match contracts.get("allowlist") {
            Some(Value::Array(list)) => {
                if list.len() > MAX_ALLOWLIST {
                    v.err("$.contracts.allowlist", format!("at most {MAX_ALLOWLIST} entries"));
                }
                for (i, entry) in list.iter().enumerate() {
                    let p = format!("$.contracts.allowlist[{i}]");
                    let Value::Object(entry) = entry else {
                        v.err(p, "must be an object");
                        continue;
                    };
                    v.fields(entry, &p, &["address", "selectors", "require_verified_code"]);
                    v.address(entry.get("address"), format!("{p}.address"));
                    v.bool(entry, "require_verified_code", &p);
                    match entry.get("selectors") {
                        Some(Value::Array(sels)) => {
                            if sels.len() > MAX_SELECTORS {
                                v.err(format!("{p}.selectors"), format!("at most {MAX_SELECTORS} selectors"));
                            }
                            for (j, s) in sels.iter().enumerate() {
                                if !matches!(s, Value::String(s) if is_selector(s)) {
                                    v.err(format!("{p}.selectors[{j}]"), "must be a 4-byte hex selector");
                                }
                            }
                        }
                        _ => v.err(format!("{p}.selectors"), "required array"),
                    }
                }
            }
            _ => v.err("$.contracts.allowlist", "required array"),
        }
        match contracts.get("denylist") {
            Some(Value::Array(deny)) => {
                for (i, a) in deny.iter().enumerate() {
                    v.address(Some(a), format!("$.contracts.denylist[{i}]"));
                }
            }
            _ => v.err("$.contracts.denylist", "required array"),
        }
    }

    if let Some(human) = v.obj(doc, "human_approval", "$") {
        v.fields(human, "$.human_approval", &["usd_threshold_micros", "require_for_unknown_methods"]);
        v.uint(human, "usd_threshold_micros", "$.human_approval");
        v.bool(human, "require_for_unknown_methods", "$.human_approval");
    }

    if doc.contains_key("asset_safety") {
        if !matches!(doc.get("schema_version"), Some(Value::String(s)) if s == "1.1" || s == "1.2" || s == "1.3" || s == "1.4" || s == "1.5") {
            v.err("$.asset_safety", "requires schema_version \"1.1\" or later");
        }
        if let Some(safety) = v.obj(doc, "asset_safety", "$") {
            let p = "$.asset_safety";
            v.fields(
                safety,
                p,
                &[
                    "enabled",
                    "max_transfer_tax_bps",
                    "max_slippage_bps",
                    "require_sell_simulation",
                    "block_unlimited_approvals",
                    "on_simulation_unavailable",
                    "max_simulation_age_seconds",
                ],
            );
            v.bool(safety, "enabled", p);
            v.int(safety, "max_transfer_tax_bps", p, 0, 10000);
            v.int(safety, "max_slippage_bps", p, 0, 10000);
            v.bool(safety, "require_sell_simulation", p);
            v.bool(safety, "block_unlimited_approvals", p);
            if !matches!(safety.get("on_simulation_unavailable"), Some(Value::String(s)) if s == "deny" || s == "review") {
                v.err(format!("{p}.on_simulation_unavailable"), "must be \"deny\" or \"review\"");
            }
            v.int(safety, "max_simulation_age_seconds", p, 1, 300);
        }
    }

    if doc.contains_key("upoch_recovery") {
        if !matches!(doc.get("schema_version"), Some(Value::String(s)) if s == "1.2" || s == "1.3" || s == "1.4" || s == "1.5") {
            v.err("$.upoch_recovery", "requires schema_version \"1.2\" or later");
        }
        if let Some(up) = v.obj(doc, "upoch_recovery", "$") {
            let p = "$.upoch_recovery";
            v.fields(up, p, &["require_upoch_recoverable", "max_checkpoint_age_seconds", "require_guardian", "on_unavailable"]);
            v.bool(up, "require_upoch_recoverable", p);
            v.int(up, "max_checkpoint_age_seconds", p, 60, 31536000);
            v.bool(up, "require_guardian", p);
            if !matches!(up.get("on_unavailable"), Some(Value::String(s)) if s == "deny" || s == "review") {
                v.err(format!("{p}.on_unavailable"), "must be \"deny\" or \"review\"");
            }
        }
    }

    if doc.contains_key("loss_limit") {
        if !matches!(doc.get("schema_version"), Some(Value::String(s)) if s == "1.3" || s == "1.4" || s == "1.5") {
            v.err("$.loss_limit", "requires schema_version \"1.3\" or later");
        }
        if let Some(loss) = v.obj(doc, "loss_limit", "$") {
            let p = "$.loss_limit";
            v.fields(
                loss,
                p,
                &[
                    "enabled",
                    "max_drawdown_bps",
                    "max_loss_usd_micros",
                    "window_seconds",
                    "on_breach",
                    "on_valuation_unavailable",
                    "stablecoins",
                    "exit_addresses",
                    "max_exit_slippage_bps",
                    "max_closed_market_price_age_seconds",
                    "reset_epoch",
                ],
            );
            v.bool(loss, "enabled", p);
            v.int(loss, "max_drawdown_bps", p, 0, 10000);
            v.uint(loss, "max_loss_usd_micros", p);
            let zero_bps = matches!(loss.get("max_drawdown_bps"), Some(Value::Number(n)) if n.as_f64() == Some(0.0));
            let zero_usd = matches!(loss.get("max_loss_usd_micros"), Some(Value::String(s)) if s == "0");
            if zero_bps && zero_usd {
                v.err(p, "needs max_drawdown_bps or max_loss_usd_micros above zero");
            }
            v.int(loss, "window_seconds", p, 3600, 604800);
            if !matches!(loss.get("on_breach"), Some(Value::String(s)) if s == "pause_risk" || s == "review") {
                v.err(format!("{p}.on_breach"), "must be \"pause_risk\" or \"review\"");
            }
            if !matches!(loss.get("on_valuation_unavailable"), Some(Value::String(s)) if s == "deny" || s == "review") {
                v.err(format!("{p}.on_valuation_unavailable"), "must be \"deny\" or \"review\"");
            }
            for key in ["stablecoins", "exit_addresses"] {
                match loss.get(key) {
                    Some(Value::Array(list)) => {
                        if list.len() > MAX_LOSS_ADDRESSES {
                            v.err(format!("{p}.{key}"), format!("at most {MAX_LOSS_ADDRESSES} entries"));
                        }
                        for (i, a) in list.iter().enumerate() {
                            v.address(Some(a), format!("{p}.{key}[{i}]"));
                        }
                    }
                    _ => v.err(format!("{p}.{key}"), "required array"),
                }
            }
            v.int(loss, "max_exit_slippage_bps", p, 0, 10000);
            v.int(loss, "max_closed_market_price_age_seconds", p, 0, 604800);
            v.int(loss, "reset_epoch", p, 0, I31);
        }
    }

    if doc.contains_key("proven_record") {
        if !matches!(doc.get("schema_version"), Some(Value::String(s)) if s == "1.4" || s == "1.5") {
            v.err("$.proven_record", "requires schema_version \"1.4\" or later");
        }
        if let Some(pr) = v.obj(doc, "proven_record", "$") {
            let p = "$.proven_record";
            v.fields(pr, p, &["enabled", "source", "min_verified_hours", "max_record_age_seconds", "unlocked_limits"]);
            v.bool(pr, "enabled", p);
            if pr.get("source") != Some(&Value::String("zolva".into())) {
                v.err(format!("{p}.source"), "must be \"zolva\"");
            }
            v.int(pr, "min_verified_hours", p, 24, 8760);
            v.int(pr, "max_record_age_seconds", p, 600, 86400);
            if let Some(un) = v.obj(pr, "unlocked_limits", p) {
                let q = format!("{p}.unlocked_limits");
                v.fields(un, &q, &["max_transaction_value_wei", "hourly_budget_usd_micros"]);
                let limits = doc.get("limits").and_then(Value::as_object);
                for k in ["max_transaction_value_wei", "hourly_budget_usd_micros"] {
                    v.uint(un, k, &q);
                    let base = limits.and_then(|l| l.get(k)).and_then(Value::as_str);
                    if let (Some(Value::String(x)), Some(b)) = (un.get(k), base) {
                        if crate::js::is_uint(x) && crate::js::is_uint(b) && uint_lt(x, b) {
                            v.err(format!("{q}.{k}"), format!("must be at least limits.{k}"));
                        }
                    }
                }
            }
        }
    }

    if doc.contains_key("token_spend") {
        if doc.get("schema_version") != Some(&Value::String("1.5".into())) {
            v.err("$.token_spend", "requires schema_version \"1.5\"");
        }
        if let Some(ts) = v.obj(doc, "token_spend", "$") {
            let p = "$.token_spend";
            v.fields(ts, p, &["enabled", "max_transaction_usd_micros", "on_price_unavailable", "max_closed_market_price_age_seconds", "require_output_to_account"]);
            v.bool(ts, "enabled", p);
            v.uint(ts, "max_transaction_usd_micros", p);
            if !matches!(ts.get("on_price_unavailable"), Some(Value::String(s)) if s == "deny" || s == "review") {
                v.err(format!("{p}.on_price_unavailable"), "must be \"deny\" or \"review\"");
            }
            v.int(ts, "max_closed_market_price_age_seconds", p, 0, 604800);
            v.bool(ts, "require_output_to_account", p);
        }
    }

    v.errors
}

/// `a < b` for canonical decimal integer strings (no leading zeros).
fn uint_lt(a: &str, b: &str) -> bool {
    a.len() < b.len() || (a.len() == b.len() && a < b)
}

/// The `ValidationError[]` shape the TypeScript validator returns.
pub fn validate_json(doc: &Value) -> Value {
    Value::Array(validate(doc).into_iter().map(|(path, message)| json!({ "path": path, "message": message })).collect())
}
