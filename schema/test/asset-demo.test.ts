import { describe, expect, it } from "vitest";
import { EMPTY_STATE, EXAMPLE_ASSET_SAFETY, EXAMPLE_ENV, EXAMPLE_POLICY, NATIVE_TOKEN, SCENARIOS, evaluate, exampleSimulation, type Policy } from "../src";

const policy: Policy = { ...EXAMPLE_POLICY, schema_version: "1.1", asset_safety: EXAMPLE_ASSET_SAFETY };
const run = (id: string) => {
  const s = SCENARIOS.find((x) => x.id === id)!;
  const v = s.intent.value_wei;
  return evaluate(
    policy,
    { ...s.intent, request_id: `r-${id}`, deadline: EXAMPLE_ENV.now + 120, asset_intent: { spend: v === "0" ? [] : [{ token: NATIVE_TOKEN, amount: v }], receive: [] } },
    EMPTY_STATE,
    { ...EXAMPLE_ENV, asset_simulation: exampleSimulation(s, EXAMPLE_ENV.now) },
  );
};

describe("homepage demo with asset safety", () => {
  it("the 20% sell-tax buy is PS_ASSET_002 and shows the tax", () => {
    const r = run("tax-token");
    expect(r.decision).toBe("DENY");
    expect(r.reason_code).toBe("PS_ASSET_002");
    expect(r.message).toContain("20.00%");
  });
  it("the other examples decide as before", () => {
    expect(run("swap").decision).toBe("ALLOW");
    expect(run("large-swap").decision).toBe("REQUIRES_HUMAN_SIGNATURE");
    expect(run("over-limit").reason_code).toBe("PS_BUDGET_001");
    expect(run("denied-target").reason_code).toBe("PS_POLICY_002");
  });
});
