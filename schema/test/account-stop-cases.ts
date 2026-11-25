/** Named cases for the account's own stop on the registry; both engines run them (see the engine parity test). */
import { EMPTY_STATE, type Environment, type Intent, type Policy } from "../src";
import { ACCOUNT, NOW, RECIPIENT, ROUTER, USDG, env, intent, spendPolicy, swapSim } from "./spend-cases";

const EXIT = RECIPIENT;
const withExit = (): Policy => {
  const p = spendPolicy(null);
  return { ...p, schema_version: "1.3", loss_limit: { enabled: false, max_drawdown_bps: 500, max_loss_usd_micros: "0", window_seconds: 86400, on_breach: "pause_risk", on_valuation_unavailable: "deny", stablecoins: [USDG], exit_addresses: [EXIT], max_exit_slippage_bps: 300, max_closed_market_price_age_seconds: 259200, reset_epoch: 0 } } as Policy;
};
const held = (e: Environment, h: boolean | null, age = 5): Environment => ({ ...e, registry_stop: h === null ? null : { held_by_account: h, observed_at: NOW - age } });
const transfer = (to: string): Intent => ({ ...intent(USDG, "0xa9059cbb"), data: `0xa9059cbb${to.slice(2).toLowerCase().padStart(64, "0")}${"0".repeat(63)}1` as Intent["data"] });

export interface StopCase { name: string; policy: Policy; intent: Intent; env: Environment; decision: string; code: string | null }
export const STOP_CASES: StopCase[] = [
  { name: "not published to a registry: nothing to check", policy: withExit(), intent: intent(ROUTER, "0x04e45aaf"), env: env(swapSim(5)), decision: "ALLOW", code: null },
  { name: "no stop held by the account: decides as usual", policy: withExit(), intent: intent(ROUTER, "0x04e45aaf"), env: held(env(swapSim(5)), false), decision: "ALLOW", code: null },
  { name: "the account holds its stop: a swap is denied", policy: withExit(), intent: intent(ROUTER, "0x04e45aaf"), env: held(env(swapSim(5)), true), decision: "DENY", code: "PS_PAUSED_001" },
  { name: "the account holds its stop: ETH to an exit address stays allowed", policy: withExit(), intent: intent(EXIT, "", "req-1", "1000"), env: held(env(null), true), decision: "ALLOW", code: null },
  { name: "the account holds its stop: a token transfer to an exit address stays allowed", policy: withExit(), intent: transfer(EXIT), env: held(env(null), true), decision: "ALLOW", code: null },
  { name: "the account holds its stop: a token transfer elsewhere is denied", policy: withExit(), intent: transfer(ACCOUNT.replace(/1/g, "7")), env: held(env(null), true), decision: "DENY", code: "PS_PAUSED_001" },
  { name: "registry unreadable: fails closed", policy: withExit(), intent: intent(ROUTER, "0x04e45aaf"), env: held(env(swapSim(5)), null), decision: "DENY", code: "PS_STATE_001" },
  { name: "registry read too old: fails closed", policy: withExit(), intent: intent(ROUTER, "0x04e45aaf"), env: held(env(swapSim(5)), false, 61), decision: "DENY", code: "PS_STATE_001" },
];
export const STOP_STATE = EMPTY_STATE;
