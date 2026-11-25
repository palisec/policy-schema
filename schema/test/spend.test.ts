import { describe, expect, it } from "vitest";
import { classifyPolicyChange, EMPTY_STATE, evaluate, validatePolicy, type Policy } from "../src";
import { env, intent, NOW, ROUTER, SPEND_CASES, spendPolicy, swapSim } from "./spend-cases";

describe("token spend limits (schema 1.5)", () => {
  for (const c of SPEND_CASES) {
    it(c.name, () => {
      const res = evaluate(c.policy, c.intent, c.state, c.env);
      expect({ decision: res.decision, code: res.reason_code }, res.message).toEqual({ decision: c.decision, code: c.code });
      if (c.reserved !== undefined) expect(res.next_state.reservations.at(-1)!.amount_usd_micros).toBe(c.reserved);
      expect(res.checks.find((x) => x.id === "spend")).toBeDefined();
    });
  }

  it("swaps that add up past the hourly budget: the one that crosses it is denied", () => {
    // $100 budget, $30 cap: three $30 swaps fit ($90.09), the fourth crosses.
    const p = spendPolicy();
    let state = EMPTY_STATE;
    const decisions: string[] = [];
    for (let i = 0; i < 4; i++) {
      const res = evaluate(p, intent(ROUTER, "0x04e45aaf", `swap-${i}`), state, { ...env(swapSim(29)), now: NOW + i });
      decisions.push(res.reason_code ? `${res.decision}:${res.reason_code}` : res.decision);
      state = res.next_state;
    }
    expect(decisions).toEqual(["ALLOW", "ALLOW", "ALLOW", "DENY:PS_BUDGET_001"]);
    const denied = evaluate(p, intent(ROUTER, "0x04e45aaf", "swap-x"), state, { ...env(swapSim(29)), now: NOW + 5 });
    expect(denied.checks.find((x) => x.id === "budget")!.status).toBe("fail");
  });

  it("the old limits alone let the same swaps through (rule off)", () => {
    const p = spendPolicy(null);
    let state = EMPTY_STATE;
    for (let i = 0; i < 4; i++) {
      const res = evaluate(p, intent(ROUTER, "0x04e45aaf", `swap-${i}`), state, { ...env(swapSim(3000)), now: NOW + i });
      expect(res.decision).toBe("ALLOW");
      state = res.next_state;
    }
  });

  it("validates the rule and its schema version", () => {
    expect(validatePolicy(spendPolicy())).toEqual([]);
    expect(validatePolicy({ ...spendPolicy(), schema_version: "1.4" })).toContainEqual({ path: "$.token_spend", message: 'requires schema_version "1.5"' });
    const bad = spendPolicy() as unknown as Record<string, any>;
    bad.token_spend.extra = 1;
    bad.token_spend.on_price_unavailable = "allow";
    bad.token_spend.max_transaction_usd_micros = "1.5";
    const errs = validatePolicy(bad).map((e) => e.path);
    expect(errs).toEqual(expect.arrayContaining(["$.token_spend.extra", "$.token_spend.on_price_unavailable", "$.token_spend.max_transaction_usd_micros"]));
  });

  describe("policy changes", () => {
    const kind = (a: Policy, b: Policy) => classifyPolicyChange(a, b).loosening;
    const off = spendPolicy(null);
    it("adding the rule is a tightening (applies at once)", () => expect(kind(off, spendPolicy())).toBe(false));
    it("removing an active rule is a loosening (waits the delay)", () => expect(kind(spendPolicy(), off)).toBe(true));
    it("switching it off is a loosening", () => expect(kind(spendPolicy(), spendPolicy({ enabled: false }))).toBe(true));
    it("raising the cap is a loosening", () => expect(kind(spendPolicy(), spendPolicy({ max_transaction_usd_micros: "60000000" }))).toBe(true));
    it("lowering the cap is a tightening", () => expect(kind(spendPolicy(), spendPolicy({ max_transaction_usd_micros: "10000000" }))).toBe(false));
    it("deny to review on missing prices is a loosening", () => expect(kind(spendPolicy(), spendPolicy({ on_price_unavailable: "review" }))).toBe(true));
    it("review to deny is a tightening", () => expect(kind(spendPolicy({ on_price_unavailable: "review" }), spendPolicy())).toBe(false));
    it("dropping the output rule is a loosening", () => expect(kind(spendPolicy(), spendPolicy({ require_output_to_account: false }))).toBe(true));
    it("a longer closed-market price age is a loosening", () => expect(kind(spendPolicy(), spendPolicy({ max_closed_market_price_age_seconds: 600000 }))).toBe(true));
    it("moving an existing policy to schema 1.5 alone changes nothing", () => {
      const v14 = { ...off, schema_version: "1.4" } as Policy;
      expect(classifyPolicyChange(v14, off).changes).toEqual([]);
    });
  });
});
