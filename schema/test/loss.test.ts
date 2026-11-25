import { describe, expect, it } from "vitest";
import {
  classifyPolicyChange, drawdownBps, EMPTY_STATE, evaluate, EXAMPLE_POLICY, lossBreach, NATIVE_TOKEN, tokenUsdMicros, validatePolicy,
  type AssetSimulation, type Environment, type Intent, type LossLimit, type LossSnapshot, type Policy,
} from "../src";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const ROUTER = "0x2222222222222222222222222222222222222222";
const USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168";
const STOCK = "0x7777777777777777777777777777777777777777";
const JUNK = "0x8888888888888888888888888888888888888888";
const EXIT = "0x9999999999999999999999999999999999999999";
const STRANGER = "0x3333333333333333333333333333333333333333";
const NOW = 1_800_000_000;
const ETH = 10n ** 18n;
const ETH_PRICE = 3_000_000_000n; // $3,000.00 in micros

const LIMIT: LossLimit = {
  enabled: true,
  max_drawdown_bps: 500,
  max_loss_usd_micros: "50000000",
  window_seconds: 86400,
  on_breach: "pause_risk",
  on_valuation_unavailable: "deny",
  stablecoins: [USDG],
  exit_addresses: [EXIT],
  max_exit_slippage_bps: 300,
  max_closed_market_price_age_seconds: 259200,
  reset_epoch: 0,
};

function policy(loss: Partial<LossLimit> = {}): Policy {
  const p = JSON.parse(JSON.stringify(EXAMPLE_POLICY)) as Policy;
  return {
    ...p,
    schema_version: "1.3",
    account: { chain_id: 4663, address: ACCOUNT },
    limits: { ...p.limits, max_transaction_value_wei: (10n ** 30n).toString(), max_gas_cost_wei: "999999999999999", hourly_budget_usd_micros: "9".repeat(30), max_pending_operations: 10 },
    cooldowns: { identical_calldata_seconds: 0, identical_intent_seconds: 0 },
    contracts: {
      default: "deny",
      allowlist: [
        { address: ROUTER, selectors: ["0x04e45aaf", "0x095ea7b3"], require_verified_code: false },
        { address: USDG, selectors: ["0xa9059cbb", "0x095ea7b3"], require_verified_code: false },
        { address: EXIT, selectors: [], require_verified_code: false },
        { address: STRANGER, selectors: [], require_verified_code: false },
      ],
      denylist: [],
    },
    human_approval: { usd_threshold_micros: "9".repeat(30), require_for_unknown_methods: false },
    loss_limit: { ...LIMIT, ...loss },
  };
}

/** $1,000 account: 0.2 ETH ($600) and 400 USDG; the peak is given per test. */
function snapshot(over: Partial<LossSnapshot> = {}): LossSnapshot {
  return {
    observed_at: NOW - 2,
    value_usd_micros: "1000000000",
    baseline_usd_micros: "1000000000",
    paused: null,
    prices: [
      { token: NATIVE_TOKEN, price_micros: ETH_PRICE.toString(), decimals: 18 },
      { token: USDG, price_micros: "1000000", decimals: 6 },
      { token: STOCK, price_micros: "180000000", decimals: 18 },
    ],
    unavailable: [],
    ...over,
  };
}

const sim = (outflows: [string, bigint][], inflows: [string, bigint][], approvals: AssetSimulation["approvals"] = []): AssetSimulation => ({
  block_number: 1,
  observed_at: NOW - 1,
  reverted: false,
  outflows: outflows.map(([token, a]) => ({ token: token as `0x${string}`, amount: a.toString() })),
  inflows: inflows.map(([token, a]) => ({ token: token as `0x${string}`, amount: a.toString() })),
  approvals,
  sell: null,
  tax_bps: null,
  round_trip_loss_bps: null,
});

let n = 0;
const intent = (to: string, data: string, value = "0"): Intent =>
  ({ request_id: `r${++n}`, agent_id: "agent", chain_id: 4663, from: ACCOUNT, to, value_wei: value, data, deadline: NOW + 100 }) as Intent;
const env = (snap: LossSnapshot | null | undefined, simulation?: AssetSimulation | null): Environment => {
  const e: Environment = { now: NOW, fee_estimate_wei: "1000", eth_usd: { price_micros: ETH_PRICE.toString(), observed_at: NOW }, verified_code: {}, emergency_stop: false, paused_agents: [] };
  if (snap !== undefined) e.loss_snapshot = snap;
  if (simulation !== undefined) e.asset_simulation = simulation;
  return e;
};
const swap = "0x04e45aaf" + "00".repeat(32);
const transferTo = (to: string, amount: bigint) => "0xa9059cbb" + to.slice(2).padStart(64, "0") + amount.toString(16).padStart(64, "0");
const decide = (p: Policy, i: Intent, e: Environment) => evaluate(p, i, EMPTY_STATE, e);
const lossCheck = (r: ReturnType<typeof decide>) => r.checks.find((c) => c.id === "loss")!;

describe("loss limit: helpers", () => {
  it("prices round against the account and drawdown rounds down", () => {
    expect(tokenUsdMicros(ETH, ETH_PRICE, 18, false)).toBe(ETH_PRICE);
    expect(tokenUsdMicros(1n, 1_000_000n, 18, true)).toBe(1n);
    expect(tokenUsdMicros(1n, 1_000_000n, 18, false)).toBe(0n);
    expect(drawdownBps(1000n, 951n)).toBe(490n);
    expect(drawdownBps(0n, 0n)).toBe(0n);
    expect(drawdownBps(100n, 200n)).toBe(0n);
  });
  it("the USD limit is reported first when both are hit", () => {
    expect(lossBreach(LIMIT, 1_000_000_000n, 900_000_000n)).toBe("PS_LOSS_002");
    expect(lossBreach({ ...LIMIT, max_loss_usd_micros: "0" }, 1_000_000_000n, 949_000_000n)).toBe("PS_LOSS_001");
    expect(lossBreach(LIMIT, 1_000_000_000n, 960_000_000n)).toBeNull();
  });
});

describe("loss limit: evaluation", () => {
  it("off unless enabled; no change for policies without the section", () => {
    const p = policy({ enabled: false });
    expect(lossCheck(decide(p, intent(STRANGER, "0x", "1"), env(undefined))).detail).toBe("Loss limit is off for this policy.");
    const old = { ...p, schema_version: "1.2" as const };
    delete old.loss_limit;
    expect(decide(old, intent(STRANGER, "0x", "1"), env(undefined)).decision).toBe("ALLOW");
  });

  it("a trade within the limit is allowed and reports the loss after it", () => {
    // Swap $100 of USDG for ETH worth $99: $1 lost.
    const s = sim([[USDG, 100_000_000n]], [[NATIVE_TOKEN, 33_000_000_000_000_000n]]);
    const r = decide(policy(), intent(ROUTER, swap), env(snapshot(), s));
    expect(r.decision).toBe("ALLOW");
    expect(lossCheck(r).detail).toBe("Loss after this operation $1.00, drawdown 0.10% (peak $1,000.00, value after $999.00).");
  });

  it("the trade that would cross the USD limit is itself denied (PS_LOSS_002)", () => {
    // Already $45 down; this swap loses another $6.
    const s = sim([[USDG, 100_000_000n]], [[NATIVE_TOKEN, 31_333_333_333_333_334n]]);
    const r = decide(policy(), intent(ROUTER, swap), env(snapshot({ value_usd_micros: "955000000" }), s));
    expect(r.decision).toBe("DENY");
    expect(r.reason_code).toBe("PS_LOSS_002");
    expect(r.retryable).toBe(false);
    expect(r.message).toContain("Only risk-reducing actions are allowed until the owner resets the limit.");
  });

  it("the percentage limit alone gives PS_LOSS_001", () => {
    const s = sim([[USDG, 60_000_000n]], []);
    const r = decide(policy({ max_loss_usd_micros: "0" }), intent(ROUTER, swap), env(snapshot(), s));
    expect(r.reason_code).toBe("PS_LOSS_001");
    expect(r.message).toContain("drawdown to 6.00%, at or above the 5.00% limit");
  });

  it("a payment to a third party is a loss; a withdrawal to the exit address is not", () => {
    const pay = decide(policy(), intent(STRANGER, "0x", (ETH / 50n).toString()), env(snapshot()));
    expect(pay.reason_code).toBe("PS_LOSS_002"); // $60 to someone else
    const out = decide(policy(), intent(EXIT, "0x", (ETH / 5n).toString()), env(snapshot()));
    expect(out.decision).toBe("ALLOW");
    expect(lossCheck(out).detail).toContain("a withdrawal, not a loss");
  });

  it("while paused: risk-adding denied, swap into a stablecoin and withdrawals allowed", () => {
    const paused = snapshot({ paused: "PS_LOSS_002", value_usd_micros: "940000000" });
    const buy = decide(policy(), intent(ROUTER, swap), env(paused, sim([[USDG, 1_000_000n]], [[NATIVE_TOKEN, 330_000_000_000_000n]])));
    expect(buy.reason_code).toBe("PS_LOSS_002");
    expect(buy.message).toContain("adds risk");
    const exit = decide(policy(), intent(ROUTER, swap), env(paused, sim([[NATIVE_TOKEN, ETH / 10n]], [[USDG, 298_000_000n]])));
    expect(exit.decision).toBe("ALLOW");
    expect(lossCheck(exit).detail).toBe("Risk-reducing swap into a stablecoin ($298.00 for $300.00): allowed while paused.");
    const usdgHome = decide(policy(), intent(USDG, transferTo(EXIT, 5_000_000n)), env(paused, sim([[USDG, 5_000_000n]], [])));
    expect(usdgHome.decision).toBe("ALLOW");
    const ethHome = decide(policy(), intent(EXIT, "0x", "1000"), env(null));
    expect(ethHome.decision).toBe("ALLOW");
  });

  it("while paused, an exit swap at a terrible price is not allowed", () => {
    const paused = snapshot({ paused: "PS_LOSS_001" });
    const r = decide(policy(), intent(ROUTER, swap), env(paused, sim([[NATIVE_TOKEN, ETH / 10n]], [[USDG, 200_000_000n]])));
    expect(r.reason_code).toBe("PS_LOSS_001");
    expect(r.message).toContain("more than the 3.00% exit slippage");
  });

  it("over the limit but not yet latched counts as paused (exit still possible)", () => {
    const over = snapshot({ value_usd_micros: "900000000" });
    expect(decide(policy(), intent(ROUTER, swap), env(over, sim([[USDG, 1_000_000n]], [[NATIVE_TOKEN, 1n]]))).reason_code).toBe("PS_LOSS_002");
    expect(decide(policy(), intent(ROUTER, swap), env(over, sim([[NATIVE_TOKEN, ETH / 100n]], [[USDG, 30_000_000n]]))).decision).toBe("ALLOW");
  });

  it("approvals: bounded to an allowlisted contract is fine while paused, unlimited is not", () => {
    const paused = snapshot({ paused: "PS_LOSS_002" });
    const ok = decide(policy(), intent(USDG, "0x095ea7b3" + "00".repeat(64)), env(paused, sim([], [], [{ token: USDG, spender: ROUTER, amount: "5000000" }])));
    expect(ok.decision).toBe("ALLOW");
    const bad = decide(policy(), intent(USDG, "0x095ea7b3" + "00".repeat(64)), env(paused, sim([], [], [{ token: USDG, spender: ROUTER, amount: (2n ** 200n).toString() }])));
    expect(bad.reason_code).toBe("PS_LOSS_002");
  });

  it("while paused, an exit swap that also grants an unlimited approval is not allowed", () => {
    const paused = snapshot({ paused: "PS_LOSS_002" });
    const s = sim([[NATIVE_TOKEN, ETH / 10n]], [[USDG, 299_000_000n]], [{ token: USDG, spender: STRANGER, amount: (2n ** 200n).toString() }]);
    const r = decide(policy(), intent(ROUTER, swap), env(paused, s));
    expect(r.reason_code).toBe("PS_LOSS_002");
    expect(r.message).toContain("grants an approval");
  });

  it("without a simulation, only a stablecoin transfer to an exit address is taken at its word", () => {
    const p = policy();
    p.contracts.allowlist.push({ address: STOCK, selectors: ["0xa9059cbb"], require_verified_code: false });
    const stable = decide(p, intent(USDG, transferTo(EXIT, 5_000_000n)), env(snapshot({ paused: "PS_LOSS_002" }), null));
    expect(stable.decision).toBe("ALLOW");
    const other = decide(p, intent(STOCK, transferTo(EXIT, 5n)), env(snapshot({ paused: "PS_LOSS_002" }), null));
    expect(other.reason_code).toBe("PS_LOSS_003");
  });

  it("missing or stale value: PS_LOSS_003, deny or review, never allow", () => {
    const trade = sim([[USDG, 1_000_000n]], [[NATIVE_TOKEN, 330_000_000_000_000n]]);
    for (const e of [env(null, trade), env(undefined, trade), env(snapshot({ observed_at: NOW - 61 }), trade), env(snapshot({ value_usd_micros: null, baseline_usd_micros: null }), trade), env(snapshot({ unavailable: [USDG] }), trade), env(snapshot(), null)]) {
      const r = decide(policy(), intent(ROUTER, swap), e);
      expect(r.decision).toBe("DENY");
      expect(r.reason_code).toBe("PS_LOSS_003");
      expect(r.retryable).toBe(true);
    }
    const held = decide(policy({ on_valuation_unavailable: "review" }), intent(ROUTER, swap), env(null, trade));
    expect(held.decision).toBe("REQUIRES_HUMAN_SIGNATURE");
    expect(held.reason_code).toBe("PS_LOSS_003");
  });

  it("an unpriced token is worth $0: buying it counts the whole spend as a loss", () => {
    const r = decide(policy(), intent(ROUTER, swap), env(snapshot(), sim([[USDG, 60_000_000n]], [[JUNK, 10n ** 30n]])));
    expect(r.reason_code).toBe("PS_LOSS_002");
  });

  it("on_breach review holds instead of denying", () => {
    const r = decide(policy({ on_breach: "review" }), intent(ROUTER, swap), env(snapshot({ paused: "PS_LOSS_002" }), sim([[USDG, 1n]], [[STOCK, 1n]])));
    expect(r.decision).toBe("REQUIRES_HUMAN_SIGNATURE");
    expect(r.reason_code).toBe("PS_LOSS_002");
  });
});

describe("loss limit: schema and loosening", () => {
  it("validates, and needs schema 1.3 and at least one limit", () => {
    expect(validatePolicy(policy())).toEqual([]);
    expect(validatePolicy({ ...policy(), schema_version: "1.2" })).toEqual([{ path: "$.loss_limit", message: 'requires schema_version "1.3" or later' }]);
    expect(validatePolicy(policy({ max_drawdown_bps: 0, max_loss_usd_micros: "0" }))[0]!.message).toContain("needs max_drawdown_bps");
    expect(validatePolicy(policy({ window_seconds: 60 }))[0]!.path).toBe("$.loss_limit.window_seconds");
    expect(validatePolicy(policy({ exit_addresses: ["0x12" as `0x${string}`] }))[0]!.path).toBe("$.loss_limit.exit_addresses[0]");
  });

  const kind = (f: Partial<LossLimit>) => classifyPolicyChange(policy(), policy(f)).loosening;
  it("reset, raising, weaker modes and new exits are loosenings", () => {
    expect(kind({ reset_epoch: 1 })).toBe(true);
    expect(kind({ max_loss_usd_micros: "60000000" })).toBe(true);
    expect(kind({ max_loss_usd_micros: "0" })).toBe(true);
    expect(kind({ max_drawdown_bps: 0 })).toBe(true);
    expect(kind({ window_seconds: 3600 })).toBe(true);
    expect(kind({ enabled: false })).toBe(true);
    expect(kind({ on_breach: "review" })).toBe(true);
    expect(kind({ on_valuation_unavailable: "review" })).toBe(true);
    expect(kind({ exit_addresses: [EXIT, STRANGER] })).toBe(true);
    expect(kind({ stablecoins: [USDG, STOCK] })).toBe(true);
    expect(kind({ max_exit_slippage_bps: 1000 })).toBe(true);
    const off = policy();
    delete off.loss_limit;
    expect(classifyPolicyChange(policy(), off).loosening).toBe(true);
  });
  it("lowering limits, a longer window and adding the section are instant", () => {
    expect(kind({ max_loss_usd_micros: "10000000" })).toBe(false);
    expect(kind({ max_drawdown_bps: 100 })).toBe(false);
    expect(kind({ window_seconds: 172800 })).toBe(false);
    expect(kind({ exit_addresses: [] })).toBe(false);
    const before = policy();
    delete before.loss_limit;
    expect(classifyPolicyChange(before, policy()).loosening).toBe(false);
  });
});
