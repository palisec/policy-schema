import { describe, expect, it } from "vitest";
import {
  EXAMPLE_POLICY,
  classifyPolicyChange,
  evaluate,
  provenUnlocked,
  validatePolicy,
  type Environment,
  type Intent,
  type LedgerState,
  type Policy,
  type ProvenRecordStatus,
} from "../src/index";

const NOW = 1_800_000_000;
const ACCOUNT = "0x1111111111111111111111111111111111111111" as const;
const TARGET = "0x2222222222222222222222222222222222222222" as const;

function policy(over: Partial<Policy["proven_record"]> = {}): Policy {
  const p = JSON.parse(JSON.stringify(EXAMPLE_POLICY)) as Policy;
  p.schema_version = "1.4";
  p.status = "active";
  p.account = { chain_id: 4663, address: ACCOUNT };
  p.contracts.allowlist = [{ address: TARGET, selectors: [], require_verified_code: false }];
  p.contracts.denylist = [];
  p.limits = { ...p.limits, max_transaction_value_wei: "1000", hourly_budget_usd_micros: "99999999999999", max_pending_operations: 5, max_price_age_seconds: 600 };
  p.human_approval = { usd_threshold_micros: "9".repeat(40), require_for_unknown_methods: false };
  p.cooldowns = { identical_calldata_seconds: 0, identical_intent_seconds: 0 };
  p.proven_record = {
    enabled: true,
    source: "zolva",
    min_verified_hours: 168,
    max_record_age_seconds: 3600,
    unlocked_limits: { max_transaction_value_wei: "5000", hourly_budget_usd_micros: "99999999999999" },
    ...over,
  };
  return p;
}

const good: ProvenRecordStatus = { observed_at: NOW - 60, link_verified: true, replay_status: "match", hours_verified: 200, unlocked_at: NOW - 10 };
const env = (proven: unknown): Environment =>
  ({
    now: NOW,
    fee_estimate_wei: "0",
    eth_usd: { price_micros: "3000000000", observed_at: NOW },
    verified_code: {},
    emergency_stop: false,
    paused_agents: [],
    proven_record: proven,
  }) as Environment;
const intent = (value: string): Intent => ({ request_id: `r-${value}`, agent_id: "a", chain_id: 4663, from: ACCOUNT, to: TARGET, value_wei: value, data: "0x", deadline: NOW + 60 });
const state: LedgerState = { reservations: [], seen_request_ids: [], calldata_seen: {}, intent_seen: {} };

describe("proven on Zolva: validation", () => {
  it("accepts a valid section in schema 1.4", () => {
    expect(validatePolicy(policy())).toEqual([]);
  });
  it("needs schema 1.4", () => {
    expect(validatePolicy({ ...policy(), schema_version: "1.3" })).toContainEqual({ path: "$.proven_record", message: 'requires schema_version "1.4" or later' });
  });
  it("only knows the zolva source and bounded settings", () => {
    const errs = validatePolicy(policy({ source: "other" as "zolva", min_verified_hours: 1, max_record_age_seconds: 100 }));
    expect(errs.map((e) => e.path)).toEqual(["$.proven_record.source", "$.proven_record.min_verified_hours", "$.proven_record.max_record_age_seconds"]);
  });
  it("unlocked limits can never be smaller than the policy's own", () => {
    const errs = validatePolicy(policy({ unlocked_limits: { max_transaction_value_wei: "999", hourly_budget_usd_micros: "99999999999999" } }));
    expect(errs).toEqual([{ path: "$.proven_record.unlocked_limits.max_transaction_value_wei", message: "must be at least limits.max_transaction_value_wei" }]);
  });
  it("rejects unknown fields", () => {
    const p = policy() as unknown as Record<string, any>;
    p.proven_record.extra = true;
    expect(validatePolicy(p)).toContainEqual({ path: "$.proven_record.extra", message: "unknown field" });
  });
});

describe("proven on Zolva: when the bigger limits apply", () => {
  it("unlocks only when every condition holds", () => {
    expect(provenUnlocked(policy(), env(good))).toBe(true);
  });
  const locked: [string, unknown, Partial<NonNullable<Policy["proven_record"]>>?][] = [
    ["no record (Zolva down or never read)", undefined],
    ["record unavailable", null],
    ["link not verified from both sides", { ...good, link_verified: false }],
    ["replay differs", { ...good, replay_status: "differs" }],
    ["no replay history", { ...good, replay_status: "no_history" }],
    ["too few verified hours", { ...good, hours_verified: 167 }],
    ["stale record", { ...good, observed_at: NOW - 3601 }],
    ["record from the future", { ...good, observed_at: NOW + 1 }],
    ["unlock still waiting out the delay", { ...good, unlocked_at: NOW + 1 }],
    ["never unlocked", { ...good, unlocked_at: null }],
    ["section switched off", good, { enabled: false }],
  ];
  for (const [name, rec, over] of locked)
    it(`keeps the policy's own limits: ${name}`, () => {
      expect(provenUnlocked(policy(over), env(rec))).toBe(false);
    });
  it("treats malformed input as an engine error (the dual evaluator fails closed)", () => {
    expect(() => provenUnlocked(policy(), env({ ...good, hours_verified: "200" }))).toThrow();
  });
});

describe("proven on Zolva: decisions", () => {
  it("a value above the base limit is denied while locked", () => {
    const r = evaluate(policy(), intent("3000"), state, env({ ...good, unlocked_at: null }));
    expect(r.decision).toBe("DENY");
    expect(r.reason_code).toBe("PS_BUDGET_001");
    expect(r.checks.find((c) => c.id === "value")!.detail).toBe("Value 3000 wei exceeds the per-transaction limit of 1000 wei.");
  });
  it("the same value is allowed once unlocked, and the check says why", () => {
    const r = evaluate(policy(), intent("3000"), state, env(good));
    expect(r.decision).toBe("ALLOW");
    expect(r.checks.find((c) => c.id === "value")!.detail).toBe("3000 wei ≤ 5000 wei. Unlocked limit: verified Zolva record (paper trading).");
  });
  it("the unlocked limit is still a limit", () => {
    const r = evaluate(policy(), intent("6000"), state, env(good));
    expect(r.decision).toBe("DENY");
    expect(r.reason_code).toBe("PS_BUDGET_001");
  });
});

describe("proven on Zolva: changes", () => {
  const base = policy({ enabled: false });
  it("adding the section switched on is a loosening; switched off it changes nothing", () => {
    const { proven_record: _, ...without } = base;
    expect(classifyPolicyChange(without as Policy, policy()).loosening).toBe(true);
    expect(classifyPolicyChange(without as Policy, base).loosening).toBe(false);
  });
  it("removing it, or switching it off, applies at once", () => {
    const { proven_record: _, ...without } = policy();
    expect(classifyPolicyChange(policy(), without as Policy).loosening).toBe(false);
    expect(classifyPolicyChange(policy(), base).loosening).toBe(false);
  });
  it("bigger unlocked limits, fewer hours or an older record loosen; the opposite tightens", () => {
    expect(classifyPolicyChange(policy(), policy({ unlocked_limits: { max_transaction_value_wei: "6000", hourly_budget_usd_micros: "99999999999999" } })).loosening).toBe(true);
    expect(classifyPolicyChange(policy(), policy({ min_verified_hours: 72 })).loosening).toBe(true);
    expect(classifyPolicyChange(policy(), policy({ max_record_age_seconds: 7200 })).loosening).toBe(true);
    expect(classifyPolicyChange(policy(), policy({ min_verified_hours: 720, max_record_age_seconds: 600 })).loosening).toBe(false);
    expect(classifyPolicyChange(policy(), policy({ unlocked_limits: { max_transaction_value_wei: "2000", hourly_budget_usd_micros: "99999999999999" } })).loosening).toBe(false);
  });
});
