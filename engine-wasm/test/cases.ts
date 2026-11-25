/**
 * Seeded generators for parity testing. The same seed always yields the same case, so fixtures
 * can be regenerated and checked, and a failing fuzz case can be reproduced from its seed.
 */
import { EXAMPLE_POLICY, fingerprint, selectorOf, validatePolicy } from "@palisec/policy-schema";

export type Rng = () => number;

/** mulberry32 */
export function rng(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(r: Rng, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
const chance = (r: Rng, p: number) => r() < p;
const int = (r: Rng, lo: number, hi: number) => lo + Math.floor(r() * (hi - lo + 1));
const digits = (r: Rng, n: number) => String(int(r, 1, 9)) + Array.from({ length: n - 1 }, () => int(r, 0, 9)).join("");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const POOL = [
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
  "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01",
  "0xabcdef0123456789abcdef0123456789abcdef01",
  "0x5555555555555555555555555555555555555555",
];
const SELECTORS = ["0xa9059cbb", "0x095ea7b3", "0x38ed1739", "0xA9059CBB", "0xdeadbeef"];
const AGENTS = ["agent-a", "agent-b", "ägent-ü-😀", "agent with spaces"];
const REQUESTS = ["req-1", "req-2", "req-3", "req-😀", "r"];
const NOW = 1_800_000_000;
const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const TOKENS = [NATIVE, "0x7777777777777777777777777777777777777777", "0x8888888888888888888888888888888888888888", "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"];

/** Schema 1.1 asset-safety rules, mostly valid and enabled. */
function assetSafety(r: Rng): Record<string, unknown> {
  return {
    enabled: chance(r, 0.85),
    max_transfer_tax_bps: pick(r, [0, 100, 500, 500, 2000, 10000]),
    max_slippage_bps: pick(r, [0, 50, 300, 300, 10000]),
    require_sell_simulation: chance(r, 0.8),
    block_unlimited_approvals: chance(r, 0.8),
    on_simulation_unavailable: pick(r, ["deny", "deny", "review"]),
    max_simulation_age_seconds: pick(r, [1, 10, 10, 60, 300]),
  };
}

/** Schema 1.2 Upoch recovery rules. */
function upochRecovery(r: Rng): Record<string, unknown> {
  return {
    require_upoch_recoverable: chance(r, 0.85),
    max_checkpoint_age_seconds: pick(r, [60, 3600, 604800, 31536000]),
    require_guardian: chance(r, 0.5),
    on_unavailable: pick(r, ["deny", "deny", "review"]),
  };
}

/** An Upoch workflow read, mostly well-formed and recoverable. */
function upochStatus(r: Rng, now: number): Record<string, unknown> {
  const count = pick(r, [0, 1, 5, 22]);
  return {
    workflow_id: pick(r, ["", "9", "12", "12"]),
    observed_at: now - pick(r, [0, 0, 1, 30, 61, -1]),
    linked: chance(r, 0.85),
    active: chance(r, 0.9),
    checkpoint_count: count,
    last_checkpoint_at: count === 0 && chance(r, 0.7) ? null : now - pick(r, [0, 59, 3601, 86400, 700000, 40000000]),
    guardians: pick(r, [0, 1, 1, 2]),
  };
}

/** Schema 1.4 proven record, mostly valid; unlocked limits at or above the base (sometimes below). */
function provenRecord(r: Rng, limits: Record<string, any>): Record<string, unknown> {
  const up = (base: unknown) =>
    typeof base === "string" && /^(0|[1-9][0-9]*)$/.test(base)
      ? pick(r, [base, (BigInt(base) * 10n).toString(), (BigInt(base) + 1n).toString(), "9".repeat(60), base === "0" ? "0" : (BigInt(base) - 1n).toString()])
      : uintish(r);
  return {
    enabled: chance(r, 0.85),
    source: chance(r, 0.97) ? "zolva" : "other",
    min_verified_hours: chance(r, 0.95) ? pick(r, [24, 72, 168, 720]) : pick(r, [0, 23, 9000]),
    max_record_age_seconds: chance(r, 0.95) ? pick(r, [600, 3600, 7200, 86400]) : pick(r, [599, 86401]),
    unlocked_limits: { max_transaction_value_wei: up(limits.max_transaction_value_wei), hourly_budget_usd_micros: up(limits.hourly_budget_usd_micros) },
  };
}

function provenStatus(r: Rng, now: number): Record<string, unknown> {
  if (chance(r, 0.04)) return { observed_at: "x", link_verified: true, replay_status: "match", hours_verified: 200, unlocked_at: null };
  return {
    observed_at: now - pick(r, [0, 60, 900, 7000, 90000, -5]),
    link_verified: chance(r, 0.8),
    replay_status: pick(r, ["match", "match", "match", "differs", "no_history", "MATCH"]),
    hours_verified: pick(r, [0, 23, 24, 72, 168, 500, 2000]),
    unlocked_at: chance(r, 0.25) ? null : now - pick(r, [0, 1, 3600, -10]),
  };
}

/** Schema 1.3 loss limit, mostly valid and enabled. */
function lossLimit(r: Rng): Record<string, unknown> {
  const bps = pick(r, [0, 100, 500, 500, 10000]);
  return {
    enabled: chance(r, 0.85),
    max_drawdown_bps: bps,
    max_loss_usd_micros: bps === 0 ? pick(r, ["1", "5000", "50000000"]) : pick(r, ["0", "0", "5000", "50000000", digits(r, int(r, 1, 12))]),
    window_seconds: pick(r, [3600, 86400, 604800]),
    on_breach: pick(r, ["pause_risk", "pause_risk", "review"]),
    on_valuation_unavailable: pick(r, ["deny", "deny", "review"]),
    stablecoins: TOKENS.slice(1).filter(() => chance(r, 0.4)),
    exit_addresses: POOL.filter(() => chance(r, 0.25)),
    max_exit_slippage_bps: pick(r, [0, 100, 300, 10000]),
    max_closed_market_price_age_seconds: pick(r, [0, 259200]),
    reset_epoch: int(r, 0, 3),
  };
}

/** Schema 1.5 token spend rule, mostly valid and enabled. */
function tokenSpend(r: Rng): Record<string, unknown> {
  return {
    enabled: chance(r, 0.85),
    max_transaction_usd_micros: pick(r, ["0", "1000", "5000000", digits(r, int(r, 1, 14)), "9".repeat(40)]),
    on_price_unavailable: pick(r, ["deny", "deny", "review"]),
    max_closed_market_price_age_seconds: pick(r, [0, 259200]),
    require_output_to_account: chance(r, 0.6),
  };
}

/** Prices for spent tokens, mostly well-formed and fresh. */
function spendPrices(r: Rng, now: number): Record<string, unknown> {
  return {
    observed_at: now - pick(r, [0, 0, 1, 30, 61, -1]),
    prices: TOKENS.filter(() => chance(r, 0.8)).map((token) => ({
      token: chance(r, 0.2) ? token.toUpperCase().replace("0X", "0x") : token,
      price_micros: pick(r, ["0", "1000000", "3200000000", digits(r, int(r, 1, 12))]),
      decimals: pick(r, [0, 6, 18, 18]),
    })),
    unavailable: TOKENS.filter(() => chance(r, 0.1)),
  };
}

/** An account-value snapshot, mostly well-formed and fresh. */
function lossSnapshot(r: Rng, now: number): Record<string, unknown> {
  const priced = chance(r, 0.85);
  const value = pick(r, ["0", "1000", "1000000000", digits(r, int(r, 1, 14))]);
  const peak = chance(r, 0.5) ? value : (BigInt(value) + BigInt(pick(r, ["1", "4000", "60000000", digits(r, int(r, 1, 12))]))).toString();
  return {
    observed_at: now - pick(r, [0, 1, 5, 30, 61, -1]),
    value_usd_micros: priced ? value : null,
    baseline_usd_micros: priced ? peak : null,
    paused: pick(r, [null, null, null, "PS_LOSS_001", "PS_LOSS_002"]),
    prices: TOKENS.filter(() => chance(r, 0.75)).map((token) => ({
      token: chance(r, 0.2) ? token.toUpperCase().replace("0X", "0x") : token,
      price_micros: pick(r, ["0", "1000000", "3200000000", digits(r, int(r, 1, 12))]),
      decimals: pick(r, [0, 6, 18, 18]),
    })),
    unavailable: TOKENS.filter(() => chance(r, 0.1)),
  };
}

const amountList = (r: Rng, n: number) =>
  Array.from({ length: n }, () => ({
    token: pick(r, TOKENS),
    amount: pick(r, ["0", "1", "1000", digits(r, int(r, 1, 20)), "340282366920938463463374607431768211456"]),
  }));

function assetIntent(r: Rng): Record<string, unknown> {
  return { spend: amountList(r, int(r, 0, 2)), receive: amountList(r, int(r, 0, 2)) };
}

/** A well-formed simulation result; the generator never produces malformed shapes (the server cannot). */
function assetSimulation(r: Rng, now: number): Record<string, unknown> {
  return {
    block_number: int(r, 1, 10_000_000),
    observed_at: now - pick(r, [0, 0, 1, 3, 9, 11, 61, 400, -2]),
    reverted: chance(r, 0.1),
    outflows: amountList(r, int(r, 0, 2)),
    inflows: amountList(r, int(r, 0, 2)),
    approvals: Array.from({ length: pick(r, [0, 0, 0, 1, 2]) }, () => ({
      token: pick(r, TOKENS.slice(1)),
      spender: pick(r, [...POOL, "0x9999999999999999999999999999999999999999"]),
      amount: pick(r, ["0", "1000", digits(r, int(r, 1, 30)), "115792089237316195423570985008687907853269984665640564039457584007913129639935"]),
    })),
    sell: chance(r, 0.2) ? null : { reverted: chance(r, 0.2) },
    tax_bps: chance(r, 0.3) ? null : pick(r, [0, 30, 500, 501, 2000, 9999]),
    round_trip_loss_bps: chance(r, 0.4) ? null : int(r, 0, 10000),
  };
}

/** Make the declared intent match the simulation, so the later asset rules are reached. */
function coherentAsset(r: Rng, intent: Record<string, unknown>, sim: Record<string, unknown>) {
  const spend = (sim.outflows as { token: string; amount: string }[]).map((o) => ({ ...o }));
  const receive = (sim.inflows as { token: string; amount: string }[]).map((o) => ({ ...o }));
  intent.asset_intent = { spend: chance(r, 0.9) ? spend : [], receive: chance(r, 0.8) ? receive : [] };
  if (chance(r, 0.7)) sim.approvals = [];
  if (chance(r, 0.6)) sim.reverted = false;
}

const uintish = (r: Rng) =>
  pick(r, [
    "0",
    "1",
    digits(r, int(r, 1, 6)),
    digits(r, int(r, 12, 20)),
    "1000000000000000000",
    digits(r, 78),
  ]);

function calldata(r: Rng): string {
  const sel = pick(r, SELECTORS);
  return pick(r, [
    "0x",
    "0x",
    sel + "00".repeat(int(r, 0, 64)),
    sel.toLowerCase() + "ab".repeat(32),
    "0xabc",
    "0x12",
    "0x" + "ff".repeat(int(r, 4, 9)),
    "nothex",
  ]);
}

export interface EvalCase {
  policy: unknown;
  intent: Record<string, unknown>;
  state: Record<string, unknown>;
  env: Record<string, unknown>;
}

function policyFor(r: Rng): unknown {
  if (chance(r, 0.04)) return null;
  const p = clone(EXAMPLE_POLICY) as unknown as Record<string, any>;
  p.account.chain_id = pick(r, [46630, 46630, 4663]);
  p.account.address = pick(r, [ACCOUNT, ACCOUNT.toUpperCase().replace("0X", "0x"), POOL[0]!]);
  p.status = pick(r, ["active", "active", "active", "active", "draft", "disabled"]);
  p.version = int(r, 1, 50);
  p.limits = {
    max_transaction_value_wei: uintish(r),
    max_gas_cost_wei: uintish(r),
    hourly_budget_usd_micros: uintish(r),
    max_pending_operations: int(r, 0, 5),
    max_price_age_seconds: int(r, 1, 600),
  };
  p.cooldowns = { identical_calldata_seconds: pick(r, [0, 30, 600]), identical_intent_seconds: pick(r, [0, 15, 900]) };
  p.contracts.allowlist = Array.from({ length: int(r, 0, 4) }, () => ({
    address: pick(r, POOL),
    selectors: Array.from({ length: int(r, 0, 3) }, () => pick(r, SELECTORS)),
    require_verified_code: chance(r, 0.4),
  }));
  p.contracts.denylist = POOL.filter(() => chance(r, 0.15));
  p.human_approval = { usd_threshold_micros: uintish(r), require_for_unknown_methods: chance(r, 0.5) };
  if (chance(r, 0.5)) {
    p.schema_version = chance(r, 0.97) ? pick(r, ["1.1", "1.2"]) : "1.0";
    p.asset_safety = assetSafety(r);
  }
  if (chance(r, 0.35)) {
    p.schema_version = chance(r, 0.96) ? "1.2" : "1.1";
    p.upoch_recovery = upochRecovery(r);
  }
  if (chance(r, 0.3)) {
    p.schema_version = chance(r, 0.96) ? "1.3" : "1.2";
    p.loss_limit = lossLimit(r);
  }
  if (chance(r, 0.3)) {
    p.schema_version = chance(r, 0.96) ? "1.4" : "1.3";
    p.proven_record = provenRecord(r, p.limits);
  }
  if (chance(r, 0.35)) {
    p.schema_version = chance(r, 0.96) ? "1.5" : "1.4";
    p.token_spend = tokenSpend(r);
  }
  if (chance(r, 0.06)) return mutatePolicy(r, p, int(r, 1, 3));
  return p;
}

export function evalCase(seed: number): EvalCase {
  const r = rng(seed);
  const policy = policyFor(r);
  const now = NOW + int(r, 0, 10_000);
  const to = chance(r, 0.95) ? pick(r, POOL) : pick(r, ["0x12", "0xZZ22222222222222222222222222222222222222"]);
  const data = calldata(r);
  const agent = pick(r, AGENTS);
  const value = chance(r, 0.9) ? uintish(r) : pick(r, ["01", "-1", "1.5", ""]);
  const intent: Record<string, unknown> = {
    request_id: chance(r, 0.03) ? "" : pick(r, REQUESTS),
    agent_id: agent,
    chain_id: pick(r, [46630, 46630, 46630, 4663]),
    from: chance(r, 0.9) ? pick(r, [ACCOUNT, "0x1111111111111111111111111111111111111111"]) : pick(r, [POOL[1]!, "0x11"]),
    to,
    value_wei: value,
    data,
    deadline: now + int(r, -30, 400),
  };
  if (chance(r, 0.4)) intent.asset_intent = assetIntent(r);
  const verified: Record<string, boolean> = {};
  for (const a of POOL) if (chance(r, 0.6)) verified[a.toLowerCase()] = chance(r, 0.85);
  const env: Record<string, unknown> = {
    now,
    fee_estimate_wei: chance(r, 0.08) ? null : chance(r, 0.03) ? "abc" : uintish(r),
    eth_usd: chance(r, 0.08) ? null : { price_micros: pick(r, ["0", "3200000000", digits(r, int(r, 7, 12))]), observed_at: now - int(r, 0, 900) },
    verified_code: verified,
    emergency_stop: chance(r, 0.04),
    paused_agents: chance(r, 0.05) ? [agent] : chance(r, 0.1) ? ["someone-else"] : [],
  };
  const sim = chance(r, 0.15) ? null : assetSimulation(r, now);
  if (sim !== null || chance(r, 0.5)) env.asset_simulation = sim;
  const up = chance(r, 0.12) ? null : upochStatus(r, now);
  if (up !== null || chance(r, 0.5)) env.upoch = up;
  const snap = chance(r, 0.1) ? null : lossSnapshot(r, now);
  if (snap !== null || chance(r, 0.5)) env.loss_snapshot = snap;
  const proven = chance(r, 0.15) ? null : provenStatus(r, now);
  if (proven !== null || chance(r, 0.5)) env.proven_record = proven;
  if (chance(r, 0.3)) env.registry_stop = chance(r, 0.1) ? null : { held_by_account: chance(r, 0.4), observed_at: now - pick(r, [0, 5, 60, 61, -1]) };
  const prices = chance(r, 0.12) ? null : spendPrices(r, now);
  if (prices !== null || chance(r, 0.5)) env.spend_prices = prices;
  if (sim && chance(r, 0.4)) {
    // What is left approved at the end: sometimes everything was pulled, sometimes not.
    sim.allowances_after = (sim.approvals as { token: string; spender: string; amount: string }[]).map((a) => ({
      ...a,
      amount: pick(r, ["0", "0", a.amount, "1000", digits(r, int(r, 1, 24))]),
    }));
    if (chance(r, 0.1)) (sim.allowances_after as unknown[]).push({ token: pick(r, TOKENS.slice(1)), spender: pick(r, POOL), amount: pick(r, ["0", "5000"]) });
  }
  // Four in ten cases start coherent (everything lines up for ALLOW or review), then take at most
  // one perturbation, so every check is reached and every outcome occurs.
  if (policy && typeof policy === "object" && !Array.isArray(policy) && chance(r, 0.4)) {
    const p = policy as Record<string, any>;
    if (validatePolicy(p).length === 0) {
      p.status = "active";
      p.account = { chain_id: 46630, address: ACCOUNT };
      intent.chain_id = 46630;
      intent.from = ACCOUNT;
      if (!/^0x[0-9a-fA-F]{40}$/.test(intent.to as string)) intent.to = POOL[0]!;
      if (!/^(0|[1-9][0-9]{0,77})$/.test(intent.value_wei as string)) intent.value_wei = "1000";
      if (!/^0x([0-9a-fA-F]{2})*$/.test(intent.data as string)) intent.data = "0x";
      if (!intent.request_id) intent.request_id = "req-ok";
      intent.deadline = now + 120;
      const sel = selectorOf(intent.data as string);
      const target = (intent.to as string).toLowerCase();
      p.contracts.denylist = p.contracts.denylist.filter((a: string) => a.toLowerCase() !== target);
      p.contracts.allowlist = p.contracts.allowlist.filter((e: { address: string }) => e.address.toLowerCase() !== target);
      p.contracts.allowlist.push({ address: intent.to, selectors: sel && chance(r, 0.8) ? [sel] : [], require_verified_code: chance(r, 0.5) });
      p.limits.max_transaction_value_wei = "9".repeat(78);
      p.limits.max_gas_cost_wei = "9".repeat(30);
      p.limits.hourly_budget_usd_micros = chance(r, 0.8) ? "9".repeat(40) : p.limits.hourly_budget_usd_micros;
      p.limits.max_pending_operations = int(r, 3, 8);
      p.limits.max_price_age_seconds = 600;
      p.cooldowns = { identical_calldata_seconds: chance(r, 0.8) ? 0 : 600, identical_intent_seconds: chance(r, 0.8) ? 0 : 900 };
      p.human_approval.usd_threshold_micros = chance(r, 0.7) ? "9".repeat(60) : pick(r, ["0", "1", "5000000"]);
      if (p.proven_record && chance(r, 0.5)) {
        // Tight base limits, generous unlocked ones: whether the unlock applies decides the outcome.
        p.limits.max_transaction_value_wei = pick(r, ["0", "1000", "100000"]);
        p.limits.hourly_budget_usd_micros = pick(r, ["0", "1000"]);
        p.proven_record.unlocked_limits = { max_transaction_value_wei: "9".repeat(78), hourly_budget_usd_micros: "9".repeat(40) };
        if (validatePolicy(p).length === 0 && chance(r, 0.6)) {
          p.proven_record.enabled = true;
          env.proven_record = {
            observed_at: now - int(r, 0, 500),
            link_verified: chance(r, 0.9),
            replay_status: chance(r, 0.9) ? "match" : "differs",
            hours_verified: chance(r, 0.9) ? 10_000 : 1,
            unlocked_at: chance(r, 0.85) ? now - int(r, 0, 100) : pick(r, [null, now + 60]),
          };
        }
      }
      Object.assign(env, {
        fee_estimate_wei: chance(r, 0.9) ? String(int(r, 0, 10 ** 9)) : env.fee_estimate_wei,
        eth_usd: chance(r, 0.9) ? { price_micros: "3200000000", observed_at: now - int(r, 0, 300) } : env.eth_usd,
        emergency_stop: chance(r, 0.03),
        paused_agents: [],
      });
      (env.verified_code as Record<string, boolean>)[target] = chance(r, 0.9);
      if (p.upoch_recovery && up && chance(r, 0.6)) Object.assign(up, { workflow_id: "12", linked: true, active: true, checkpoint_count: 3, last_checkpoint_at: now - 10, observed_at: now });
      if (p.loss_limit && snap && chance(r, 0.6)) {
        Object.assign(snap, { observed_at: now, paused: chance(r, 0.7) ? null : snap.paused });
        if (chance(r, 0.3)) p.loss_limit.exit_addresses = [intent.to];
        if (chance(r, 0.5) && sim) Object.assign(sim, { observed_at: now, reverted: false });
      }
      if (p.token_spend && chance(r, 0.6)) {
        // Fresh prices for every token and a usable simulation, so the cap and the budget decide.
        p.token_spend.max_transaction_usd_micros = chance(r, 0.6) ? "9".repeat(40) : pick(r, ["1000", "5000000", "40000000000"]);
        env.spend_prices = {
          observed_at: now - int(r, 0, 60),
          prices: TOKENS.map((token) => ({ token, price_micros: pick(r, ["1000000", "3200000000", "180000000"]), decimals: pick(r, [6, 18]) })),
          unavailable: chance(r, 0.85) ? [] : [pick(r, TOKENS)],
        };
        if (sim && chance(r, 0.8)) Object.assign(sim, { observed_at: now - int(r, 0, 60), reverted: false });
      }
      if (p.asset_safety && sim && chance(r, 0.7)) {
        coherentAsset(r, intent, sim);
        if (!sel && chance(r, 0.6)) {
          intent.data = "0xa9059cbb" + "00".repeat(int(r, 0, 8));
          p.contracts.allowlist[p.contracts.allowlist.length - 1].selectors = ["0xa9059cbb"];
        }
      }
    }
  }
  const calldataKey = fingerprint(`${(intent.to as string).toLowerCase()}|${(intent.data as string).toLowerCase()}`);
  const intentKey = fingerprint(`${agent}|${(intent.to as string).toLowerCase()}|${selectorOf(intent.data as string) ?? "native"}|${intent.value_wei as string}`);
  const state = {
    reservations: Array.from({ length: int(r, 0, 7) }, (_, i) => {
      const created = now - int(r, 0, 5000);
      return {
        reservation_id: `res_${i}`,
        request_id: `old-${i}`,
        agent_id: pick(r, AGENTS),
        policy_version: int(r, 1, 50),
        amount_usd_micros: pick(r, ["0", digits(r, int(r, 1, 10))]),
        created_at: created,
        expires_at: created + pick(r, [300, 60, 3600]),
        state: pick(r, ["reserved", "reserved", "pending_approval", "released", "finalized"]),
      };
    }),
    seen_request_ids: REQUESTS.filter(() => chance(r, 0.12)),
    calldata_seen: chance(r, 0.3) ? { [calldataKey]: now - int(r, 0, 700), "0xffffffffffffffff": now } : {},
    intent_seen: chance(r, 0.3) ? { [intentKey]: now - int(r, 0, 1000) } : {},
  };
  return { policy, intent, state, env };
}

/** Random structural damage to a policy document, for validation parity. */
export function mutatePolicy(r: Rng, doc: unknown, times: number): unknown {
  const d = clone(doc) as any;
  const junk = () =>
    pick(r, [
      null,
      true,
      0,
      -1,
      2.5,
      2147483648,
      "",
      "x",
      "01",
      "1.0",
      [],
      [1],
      {},
      { a: 1 },
      "0x1234",
      "0xa9059cbb",
      "1000000000000000000",
      "9".repeat(79),
      3600,
      86401,
      1001,
    ]);
  for (let n = 0; n < times; n++) {
    // Walk to a random container.
    let parent: any = d;
    let key: string | number | null = null;
    for (let depth = 0; depth < 4; depth++) {
      const v: any = key === null ? parent : parent?.[key];
      if (v === null || typeof v !== "object") break;
      const keys: (string | number)[] = Array.isArray(v) ? v.map((_, i) => i) : Object.keys(v);
      if (!keys.length || chance(r, 0.25)) break;
      if (key !== null) parent = v;
      key = pick(r, keys as (string | number)[]);
    }
    if (key === null || parent === null || typeof parent !== "object") continue;
    const action = int(r, 0, 3);
    if (action === 0 && !Array.isArray(parent)) delete parent[key];
    else if (action === 1 && !Array.isArray(parent)) parent[pick(r, ["extra", "10", "2", "01", "__proto_x", "Status"])] = junk();
    else parent[key] = junk();
  }
  return d;
}

export function validateCase(seed: number): unknown {
  const r = rng(seed ^ 0x5bd1e995);
  if (chance(r, 0.03)) return pick(r, [null, 5, "policy", [], [EXAMPLE_POLICY]]);
  if (chance(r, 0.12)) return mutatePolicy(r, { ...clone(EXAMPLE_POLICY), schema_version: "1.5", token_spend: tokenSpend(r) }, int(r, 0, 5));
  if (chance(r, 0.15)) {
    const base = clone(EXAMPLE_POLICY) as unknown as Record<string, any>;
    return mutatePolicy(r, { ...base, schema_version: "1.4", proven_record: provenRecord(r, base.limits) }, int(r, 0, 5));
  }
  if (chance(r, 0.2)) return mutatePolicy(r, { ...clone(EXAMPLE_POLICY), schema_version: "1.3", loss_limit: lossLimit(r) }, int(r, 0, 5));
  if (chance(r, 0.25)) return mutatePolicy(r, { ...clone(EXAMPLE_POLICY), schema_version: "1.2", upoch_recovery: upochRecovery(r) }, int(r, 0, 5));
  if (chance(r, 0.5)) return mutatePolicy(r, { ...clone(EXAMPLE_POLICY), schema_version: "1.1", asset_safety: assetSafety(r) }, int(r, 0, 5));
  return mutatePolicy(r, EXAMPLE_POLICY, int(r, 0, 5));
}
