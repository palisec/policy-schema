import { describe, expect, it } from "vitest";
import {
  EMPTY_STATE,
  EXAMPLE_ENV,
  EXAMPLE_POLICY,
  SCENARIOS,
  evaluate,
  validatePolicy,
  type Intent,
  type Policy,
} from "../src";

/** Environment at a later time, with a fresh price observation. */
const at = (now: number) => ({ ...EXAMPLE_ENV, now, eth_usd: { price_micros: "3200000000", observed_at: now } });

const scenario = (id: string, n = 1): Intent => ({
  ...SCENARIOS.find((s) => s.id === id)!.intent,
  request_id: `req_${id}_${n}`,
  deadline: EXAMPLE_ENV.now + 120,
});

describe("validatePolicy", () => {
  it("accepts the example policy", () => {
    expect(validatePolicy(EXAMPLE_POLICY)).toEqual([]);
  });

  it("rejects unknown fields, floats, and fail-open", () => {
    const bad = {
      ...EXAMPLE_POLICY,
      extra: true,
      failure_mode: "open",
      limits: { ...EXAMPLE_POLICY.limits, max_transaction_value_wei: "0.1" },
    };
    const paths = validatePolicy(bad).map((e) => e.path);
    expect(paths).toContain("$.extra");
    expect(paths).toContain("$.failure_mode");
    expect(paths).toContain("$.limits.max_transaction_value_wei");
  });
});

describe("evaluate", () => {
  it("allows an in-policy swap and reserves budget", () => {
    const r = evaluate(EXAMPLE_POLICY, scenario("swap"), EMPTY_STATE, EXAMPLE_ENV);
    expect(r.decision).toBe("ALLOW");
    expect(r.transaction_hash).toBeNull();
    expect(r.next_state.reservations).toHaveLength(1);
    expect(r.next_state.reservations[0]!.state).toBe("reserved");
  });

  it("is deterministic and does not mutate inputs", () => {
    const state = JSON.parse(JSON.stringify(EMPTY_STATE));
    const a = evaluate(EXAMPLE_POLICY, scenario("swap"), state, EXAMPLE_ENV);
    const b = evaluate(EXAMPLE_POLICY, scenario("swap"), state, EXAMPLE_ENV);
    expect(a).toEqual(b);
    expect(state).toEqual(EMPTY_STATE);
  });

  it.each([
    ["over-limit", "PS_BUDGET_001"],
    ["unknown-target", "PS_TARGET_001"],
    ["denied-target", "PS_POLICY_002"],
  ])("denies %s with %s", (id, code) => {
    const r = evaluate(EXAMPLE_POLICY, scenario(id), EMPTY_STATE, EXAMPLE_ENV);
    expect(r.decision).toBe("DENY");
    expect(r.reason_code).toBe(code);
    expect(r.authorization_id).toBeNull();
    expect(r.next_state.reservations).toHaveLength(0);
  });

  it("routes unknown methods to review, or denies when configured", () => {
    expect(evaluate(EXAMPLE_POLICY, scenario("unknown-method"), EMPTY_STATE, EXAMPLE_ENV).decision).toBe("REQUIRES_HUMAN_SIGNATURE");
    const strict: Policy = { ...EXAMPLE_POLICY, human_approval: { ...EXAMPLE_POLICY.human_approval, require_for_unknown_methods: false } };
    expect(evaluate(strict, scenario("unknown-method"), EMPTY_STATE, EXAMPLE_ENV).reason_code).toBe("PS_METHOD_001");
  });

  it("requires a human above the USD threshold and does not authorize", () => {
    const r = evaluate(EXAMPLE_POLICY, scenario("large-swap"), EMPTY_STATE, EXAMPLE_ENV);
    expect(r.decision).toBe("REQUIRES_HUMAN_SIGNATURE");
    expect(r.authorization_id).toBeNull();
    expect(r.next_state.reservations[0]!.state).toBe("pending_approval");
  });

  it("blocks identical calldata within the cooldown, then allows after it", () => {
    const first = evaluate(EXAMPLE_POLICY, scenario("swap", 1), EMPTY_STATE, EXAMPLE_ENV);
    const again = evaluate(EXAMPLE_POLICY, scenario("swap", 2), first.next_state, { ...EXAMPLE_ENV, now: EXAMPLE_ENV.now + 30 });
    expect(again.reason_code).toBe("PS_LOOP_001");
    const later = evaluate(EXAMPLE_POLICY, { ...scenario("swap", 3), deadline: EXAMPLE_ENV.now + 600 }, again.next_state, at(EXAMPLE_ENV.now + 61));
    expect(later.decision).toBe("ALLOW");
  });

  it("rejects a replayed request id", () => {
    const first = evaluate(EXAMPLE_POLICY, scenario("swap"), EMPTY_STATE, EXAMPLE_ENV);
    const replay = evaluate(EXAMPLE_POLICY, scenario("swap"), first.next_state, EXAMPLE_ENV);
    expect(replay.reason_code).toBe("PS_REPLAY_001");
  });

  it("fails closed without a fee estimate or a fresh price", () => {
    expect(evaluate(EXAMPLE_POLICY, scenario("swap"), EMPTY_STATE, { ...EXAMPLE_ENV, fee_estimate_wei: null }).reason_code).toBe("PS_FEE_001");
    expect(evaluate(EXAMPLE_POLICY, scenario("swap"), EMPTY_STATE, { ...EXAMPLE_ENV, eth_usd: null }).reason_code).toBe("PS_STATE_001");
    const stale = { ...EXAMPLE_ENV, now: EXAMPLE_ENV.now + 61 };
    expect(evaluate(EXAMPLE_POLICY, { ...scenario("swap"), deadline: stale.now + 10 }, EMPTY_STATE, stale).reason_code).toBe("PS_STATE_001");
  });

  it("denies everything under an emergency stop, and with no policy", () => {
    expect(evaluate(EXAMPLE_POLICY, scenario("swap"), EMPTY_STATE, { ...EXAMPLE_ENV, emergency_stop: true }).reason_code).toBe("PS_PAUSED_001");
    expect(evaluate(null, scenario("swap"), EMPTY_STATE, EXAMPLE_ENV).reason_code).toBe("PS_POLICY_001");
  });

  it("enforces the hourly budget across sequential reservations", () => {
    let state = EMPTY_STATE;
    const decisions: string[] = [];
    for (let i = 0; i < 5; i++) {
      const now = EXAMPLE_ENV.now + i * 61;
      const r = evaluate(EXAMPLE_POLICY, { ...scenario("swap", i), deadline: now + 60 }, state, at(now));
      decisions.push(r.reason_code ?? r.decision);
      state = r.next_state;
    }
    // $128.38 per swap against a $500 hourly budget: three fit, the fourth does not.
    expect(decisions).toEqual(["ALLOW", "ALLOW", "ALLOW", "PS_BUDGET_001", "PS_BUDGET_001"]);
  });
});
