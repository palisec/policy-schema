/**
 * Named token spend cases (schema 1.5). The reference tests check each expected decision, and the
 * engine parity tests run the same cases through the Rust engine, which must return the same result.
 */
import { EMPTY_STATE, EXAMPLE_POLICY, NATIVE_TOKEN, type AssetSimulation, type Environment, type Intent, type LedgerState, type Policy, type SpendPrices, type TokenSpend } from "../src";

export const ACCOUNT = "0x1111111111111111111111111111111111111111";
export const ROUTER = "0x2222222222222222222222222222222222222222";
export const MULTICALL = "0x3333333333333333333333333333333333333333";
export const UNKNOWN = "0x4444444444444444444444444444444444444444";
export const USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168";
export const STOCK = "0x7777777777777777777777777777777777777777";
export const JUNK = "0x8888888888888888888888888888888888888888";
export const RECIPIENT = "0x9999999999999999999999999999999999999999";
export const NOW = 1_800_000_000;

const SWAP = "0x04e45aaf";
const MULTI = "0xac9650d8";
const APPROVE = "0x095ea7b3";
const usdg = (dollars: number) => String(BigInt(dollars) * 1_000_000n);

export const RULE: TokenSpend = {
  enabled: true,
  max_transaction_usd_micros: "30000000", // $30 per transaction, ETH and tokens
  on_price_unavailable: "deny",
  max_closed_market_price_age_seconds: 259200,
  require_output_to_account: true,
};

export function spendPolicy(rule: Partial<TokenSpend> | null = {}, limits: Partial<Policy["limits"]> = {}, threshold = "50000000"): Policy {
  const p = JSON.parse(JSON.stringify(EXAMPLE_POLICY)) as Policy;
  const out: Policy = {
    ...p,
    schema_version: "1.5",
    account: { chain_id: 4663, address: ACCOUNT },
    limits: {
      ...p.limits,
      max_transaction_value_wei: (10n ** 30n).toString(),
      max_gas_cost_wei: "999999999999999",
      hourly_budget_usd_micros: "100000000", // $100 an hour
      max_pending_operations: 10,
      ...limits,
    },
    cooldowns: { identical_calldata_seconds: 0, identical_intent_seconds: 0 },
    contracts: {
      default: "deny",
      allowlist: [
        { address: ROUTER, selectors: [SWAP], require_verified_code: false },
        { address: MULTICALL, selectors: [MULTI], require_verified_code: false },
        { address: UNKNOWN, selectors: ["0xdeadbeef"], require_verified_code: false },
        { address: USDG, selectors: [APPROVE, "0xa9059cbb"], require_verified_code: false },
        { address: RECIPIENT, selectors: [], require_verified_code: false },
      ],
      denylist: [],
    },
    human_approval: { usd_threshold_micros: threshold, require_for_unknown_methods: false },
  };
  if (rule !== null) out.token_spend = { ...RULE, ...rule };
  return out;
}

export function intent(to: string, selector: string, id = "req-1", value = "0"): Intent {
  return { request_id: id, agent_id: "agent-a", chain_id: 4663, from: ACCOUNT, to: to as Intent["to"], value_wei: value, data: (selector ? selector + "00".repeat(64) : "0x") as Intent["data"], deadline: NOW + 120 };
}

export function sim(over: Partial<AssetSimulation> = {}): AssetSimulation {
  return { block_number: 100, observed_at: NOW - 2, reverted: false, outflows: [], inflows: [], approvals: [], sell: null, tax_bps: null, round_trip_loss_bps: null, ...over };
}

/** Spends `dollars` USDG and receives some stock token back. */
export const swapSim = (dollars: number, over: Partial<AssetSimulation> = {}) =>
  sim({ outflows: [{ token: USDG, amount: usdg(dollars) }], inflows: [{ token: STOCK, amount: "100000000000000000" }], ...over });

export function prices(over: Partial<SpendPrices> = {}): SpendPrices {
  return {
    observed_at: NOW - 3,
    prices: [
      { token: NATIVE_TOKEN, price_micros: "3000000000", decimals: 18 },
      { token: USDG, price_micros: "1000000", decimals: 6 },
      { token: STOCK, price_micros: "180000000", decimals: 18 },
    ],
    unavailable: [],
    ...over,
  };
}

export function env(simulation: AssetSimulation | null, p: SpendPrices | null = prices()): Environment {
  return {
    now: NOW,
    fee_estimate_wei: "10000000000000", // 0.00001 ETH = $0.03
    eth_usd: { price_micros: "3000000000", observed_at: NOW - 5 },
    verified_code: {},
    emergency_stop: false,
    paused_agents: [],
    asset_simulation: simulation,
    spend_prices: p,
  };
}

/** $90 already reserved in the last hour. */
export const USED_90: LedgerState = {
  ...EMPTY_STATE,
  reservations: [
    { reservation_id: "r0", request_id: "old-0", agent_id: "agent-a", policy_version: 7, amount_usd_micros: "90000000", created_at: NOW - 600, expires_at: NOW - 300, state: "finalized" },
  ],
};

export interface SpendCase {
  name: string;
  policy: Policy;
  intent: Intent;
  state: LedgerState;
  env: Environment;
  decision: "ALLOW" | "DENY" | "REQUIRES_HUMAN_SIGNATURE";
  code: string | null;
  /** Exposure reserved (USD micros) when allowed or held. */
  reserved?: string;
}

const FEE = 30000n; // $0.03 in micros
const r = (dollars: number) => (BigInt(dollars) * 1_000_000n + FEE).toString();

export const SPEND_CASES: SpendCase[] = [
  { name: "router swap within the cap is allowed and its tokens are reserved", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(20)), decision: "ALLOW", code: null, reserved: r(20) },
  { name: "router swap over the per-transaction cap is denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(40)), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "multicall spending tokens is counted", policy: spendPolicy(), intent: intent(MULTICALL, MULTI), state: EMPTY_STATE, env: env(swapSim(25)), decision: "ALLOW", code: null, reserved: r(25) },
  { name: "multicall over the cap is denied", policy: spendPolicy(), intent: intent(MULTICALL, MULTI), state: EMPTY_STATE, env: env(swapSim(31)), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "unknown contract spending tokens is counted", policy: spendPolicy(), intent: intent(UNKNOWN, "0xdeadbeef"), state: EMPTY_STATE, env: env(swapSim(10)), decision: "ALLOW", code: null, reserved: r(10) },
  { name: "unknown contract over the cap is denied", policy: spendPolicy(), intent: intent(UNKNOWN, "0xdeadbeef"), state: EMPTY_STATE, env: env(swapSim(35)), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "token spend that crosses the hourly budget is denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: USED_90, env: env(swapSim(20)), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "token spend at the approval threshold is held for a human", policy: spendPolicy({}, {}, "15000000"), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(20)), decision: "REQUIRES_HUMAN_SIGNATURE", code: "PS_HUMAN_001", reserved: r(20) },
  { name: "a stock token is priced from its feed", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: STOCK, amount: "200000000000000000" }], inflows: [{ token: USDG, amount: usdg(35) }] })), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "a spent token with no feed is denied", policy: spendPolicy(), intent: intent(UNKNOWN, "0xdeadbeef"), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: JUNK, amount: "1" }], inflows: [{ token: USDG, amount: "1" }] })), decision: "DENY", code: "PS_PRICE_001" },
  { name: "a spent token with no feed is held when the policy says review", policy: spendPolicy({ on_price_unavailable: "review" }), intent: intent(UNKNOWN, "0xdeadbeef"), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: JUNK, amount: "1" }], inflows: [{ token: USDG, amount: "1" }] })), decision: "REQUIRES_HUMAN_SIGNATURE", code: "PS_PRICE_001" },
  { name: "USDG off its peg (price unavailable) is denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(5), prices({ unavailable: [USDG] })), decision: "DENY", code: "PS_PRICE_001" },
  { name: "no token prices at all is denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(5), null), decision: "DENY", code: "PS_PRICE_001" },
  { name: "stale token prices are denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(5), prices({ observed_at: NOW - 61 })), decision: "DENY", code: "PS_PRICE_001" },
  { name: "no simulation: outflows unknown, denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(null), decision: "DENY", code: "PS_SIM_002" },
  { name: "stale simulation: outflows unknown, denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(5, { observed_at: NOW - 61 })), decision: "DENY", code: "PS_SIM_002" },
  { name: "unknown outflows are denied even when the policy holds missing prices for review", policy: spendPolicy({ on_price_unavailable: "review" }), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(null), decision: "DENY", code: "PS_SIM_002" },
  { name: "an unlimited approval cannot fit a budget", policy: spendPolicy(), intent: intent(USDG, APPROVE), state: EMPTY_STATE, env: env(sim({ approvals: [{ token: USDG, spender: ROUTER, amount: (2n ** 256n - 1n).toString() }] })), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "a large approval left open counts at its amount", policy: spendPolicy(), intent: intent(USDG, APPROVE), state: EMPTY_STATE, env: env(sim({ approvals: [{ token: USDG, spender: ROUTER, amount: usdg(1000) }] })), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "a small approval left open is counted and reserved", policy: spendPolicy(), intent: intent(USDG, APPROVE), state: EMPTY_STATE, env: env(sim({ approvals: [{ token: USDG, spender: ROUTER, amount: usdg(20) }] })), decision: "ALLOW", code: null, reserved: r(20) },
  { name: "an approval left open crosses the hourly budget", policy: spendPolicy(), intent: intent(USDG, APPROVE), state: USED_90, env: env(sim({ approvals: [{ token: USDG, spender: ROUTER, amount: usdg(20) }] })), decision: "DENY", code: "PS_BUDGET_001" },
  {
    name: "approve and pull in one call: only what left is counted when nothing stays approved",
    policy: spendPolicy(), intent: intent(MULTICALL, MULTI), state: EMPTY_STATE,
    env: env(swapSim(20, { approvals: [{ token: USDG, spender: ROUTER, amount: usdg(500) }], allowances_after: [{ token: USDG, spender: ROUTER, amount: "0" }] })),
    decision: "ALLOW", code: null, reserved: r(20),
  },
  {
    name: "approve and pull in one call: what stays approved is counted too",
    policy: spendPolicy(), intent: intent(MULTICALL, MULTI), state: EMPTY_STATE,
    env: env(swapSim(20, { approvals: [{ token: USDG, spender: ROUTER, amount: usdg(500) }], allowances_after: [{ token: USDG, spender: ROUTER, amount: usdg(480) }] })),
    decision: "DENY", code: "PS_BUDGET_001",
  },
  {
    name: "approve and pull in one call: without the allowance read, the approved amount counts",
    policy: spendPolicy(), intent: intent(MULTICALL, MULTI), state: EMPTY_STATE,
    env: env(swapSim(5, { approvals: [{ token: USDG, spender: ROUTER, amount: usdg(500) }] })),
    decision: "DENY", code: "PS_BUDGET_001",
  },
  { name: "a swap whose output does not return to the account is denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: USDG, amount: usdg(5) }] })), decision: "DENY", code: "PS_ASSET_003" },
  { name: "with the output rule off, the full outflow still counts", policy: spendPolicy({ require_output_to_account: false }), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: USDG, amount: usdg(5) }] })), decision: "ALLOW", code: null, reserved: r(5) },
  { name: "a token transfer out is counted", policy: spendPolicy(), intent: intent(USDG, "0xa9059cbb"), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: USDG, amount: usdg(40) }] })), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "a reverting transaction is denied", policy: spendPolicy(), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(5, { reverted: true })), decision: "DENY", code: "PS_SIM_001" },
  { name: "native ETH over the USD cap is denied", policy: spendPolicy(), intent: intent(RECIPIENT, "", "req-1", "20000000000000000"), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: NATIVE_TOKEN, amount: "20000000000000000" }] })), decision: "DENY", code: "PS_BUDGET_001" },
  { name: "native ETH within the USD cap is allowed", policy: spendPolicy(), intent: intent(RECIPIENT, "", "req-1", "5000000000000000"), state: EMPTY_STATE, env: env(sim({ outflows: [{ token: NATIVE_TOKEN, amount: "5000000000000000" }] })), decision: "ALLOW", code: null, reserved: (15_000_000n + FEE).toString() },
  { name: "native ETH without a simulation is denied (the target could pull tokens)", policy: spendPolicy(), intent: intent(RECIPIENT, "", "req-1", "5000000000000000"), state: EMPTY_STATE, env: env(null), decision: "DENY", code: "PS_SIM_002" },
  {
    name: "native ETH to a contract that pulls tokens through an older allowance is counted",
    policy: spendPolicy({ require_output_to_account: false }), intent: intent(RECIPIENT, "", "req-1", "1000000000000000"), state: EMPTY_STATE,
    env: env(sim({ outflows: [{ token: NATIVE_TOKEN, amount: "1000000000000000" }, { token: USDG, amount: usdg(40) }] })),
    decision: "DENY", code: "PS_BUDGET_001",
  },
  { name: "rule off: a 3,000 USD token swap counts only the fee (the old behaviour)", policy: spendPolicy(null), intent: intent(ROUTER, SWAP), state: EMPTY_STATE, env: env(swapSim(3000)), decision: "ALLOW", code: null, reserved: FEE.toString() },
];
