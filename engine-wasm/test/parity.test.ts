/**
 * Parity between the Rust engine (WebAssembly) and the TypeScript reference evaluator.
 *
 * - fixtures/parity.jsonl holds seeded cases with the reference results. They are regenerated
 *   here and must match (so the reference cannot drift silently), and `cargo test` in
 *   services/policy-engine checks the native Rust build against the same file.
 *   Regenerate after an intended change: WRITE_FIXTURES=1 pnpm --filter @palisec/policy-engine test
 * - A larger seeded fuzz run compares WebAssembly against TypeScript case by case.
 * - The embedded WebAssembly must have been built from the current Rust sources.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { EXAMPLE_POLICY, evaluate, validatePolicy, type Environment, type Intent, type LedgerState, type Policy } from "@palisec/policy-schema";
import { describe, expect, it } from "vitest";
import { engineStatus, evaluateDual, evaluateRust, sameJson, SOURCE_HASH, validateRust } from "../src/index";
import { evalCase, validateCase, type EvalCase } from "./cases";
import { SPEND_CASES } from "../../schema/test/spend-cases";
import { STOP_CASES, STOP_STATE } from "../../schema/test/account-stop-cases";
// @ts-expect-error plain ESM helper without types
import { sourceHash } from "../../engine/source-hash.mjs";

const FIXTURES = fileURLToPath(new URL("../fixtures/parity.jsonl", import.meta.url));
const ENGINE_DIR = fileURLToPath(new URL("../../engine/", import.meta.url));
const FIXTURE_VALIDATIONS = 150;
const FUZZ = Number(process.env.PARITY_FUZZ ?? 6000);

function reference(c: EvalCase): unknown {
  try {
    return evaluate(c.policy as Policy | null, c.intent as unknown as Intent, c.state as unknown as LedgerState, c.env as unknown as Environment);
  } catch {
    return null; // the reference throws: the engine must refuse too
  }
}

function rust(c: EvalCase): unknown {
  try {
    return evaluateRust(c.policy as Policy | null, c.intent as unknown as Intent, c.state as unknown as LedgerState, c.env as unknown as Environment);
  } catch {
    return null;
  }
}

/**
 * Fixtures are chosen by outcome so a small file still covers everything: ALLOW, human review,
 * every DENY reason code, and inputs the reference refuses outright.
 */
function fixtureLines(): string[] {
  const lines: string[] = [];
  const quota: Record<string, number> = { ALLOW: 30, REQUIRES_HUMAN_SIGNATURE: 25, throws: 8 };
  const taken: Record<string, number> = {};
  for (let seed = 1; seed <= 20_000 && lines.length < 260; seed++) {
    const c = evalCase(seed);
    if (typeof c.intent.data === "string" && c.intent.data.length > 300) continue;
    const expected = reference(c) as { decision: string; reason_code: string | null } | null;
    const bucket = expected === null ? "throws" : expected.decision === "DENY" ? `DENY:${expected.reason_code}` : expected.decision;
    if ((taken[bucket] ?? 0) >= (quota[bucket] ?? 7)) continue;
    taken[bucket] = (taken[bucket] ?? 0) + 1;
    lines.push(JSON.stringify({ kind: "evaluate", seed, input: c, expected }));
  }
  for (let seed = 1; seed <= FIXTURE_VALIDATIONS; seed++) {
    const doc = validateCase(seed);
    lines.push(JSON.stringify({ kind: "validate", seed, input: doc, expected: validatePolicy(doc) }));
  }
  return lines;
}

describe("policy engine", () => {
  it("loads and reports its version", () => {
    expect(engineStatus()).toMatchObject({ ok: true });
  });

  it("was built from the current Rust sources", () => {
    expect(SOURCE_HASH, "run `pnpm --filter @palisec/policy-engine build:wasm` and commit src/wasm.ts").toBe(sourceHash(ENGINE_DIR));
  });

  it("fixtures match the reference evaluator", () => {
    const lines = fixtureLines();
    if (process.env.WRITE_FIXTURES) writeFileSync(FIXTURES, lines.join("\n") + "\n");
    const stored = readFileSync(FIXTURES, "utf8").replace(/\r\n/g, "\n").trimEnd().split("\n");
    expect(stored.length).toBe(lines.length);
    for (let i = 0; i < lines.length; i++) expect(sameJson(JSON.parse(stored[i]!), JSON.parse(lines[i]!)), `fixture line ${i + 1}`).toBeNull();
  }, 120_000);

  it("WebAssembly matches every fixture", () => {
    const stored = readFileSync(FIXTURES, "utf8").trimEnd().split(/\r?\n/).map((l) => JSON.parse(l));
    let evaluated = 0;
    for (const f of stored) {
      const got = f.kind === "evaluate" ? rust(f.input) : validateRust(f.input);
      expect(sameJson(got, f.expected), `${f.kind} seed ${f.seed}`).toBeNull();
      if (f.kind === "evaluate" && f.expected) evaluated++;
    }
    expect(evaluated).toBeGreaterThan(100);
  });

  it(`WebAssembly matches the reference on ${FUZZ} seeded random cases`, () => {
    const decisions = { ALLOW: 0, DENY: 0, REQUIRES_HUMAN_SIGNATURE: 0 } as Record<string, number>;
    const codes = new Set<string>();
    for (let seed = 100_000; seed < 100_000 + FUZZ; seed++) {
      const c = evalCase(seed);
      const ref = reference(c) as { decision: string; reason_code: string | null } | null;
      const got = rust(c);
      const diff = sameJson(got, ref);
      if (diff) throw new Error(`seed ${seed} differs at ${diff}`);
      if (ref) {
        decisions[ref.decision]!++;
        if (ref.reason_code) codes.add(ref.reason_code);
      }
      const doc = validateCase(seed);
      const vd = sameJson(validateRust(doc), validatePolicy(doc));
      if (vd) throw new Error(`validation seed ${seed} differs at ${vd}`);
    }
    // The generator must reach every outcome, or the comparison proves little.
    expect(decisions.ALLOW).toBeGreaterThan(FUZZ / 100);
    expect(decisions.REQUIRES_HUMAN_SIGNATURE).toBeGreaterThan(FUZZ / 100);
    for (const code of ["PS_POLICY_001", "PS_POLICY_002", "PS_TARGET_001", "PS_METHOD_001", "PS_BUDGET_001", "PS_RATE_001", "PS_LOOP_001", "PS_REPLAY_001", "PS_FEE_001", "PS_HUMAN_001", "PS_PAUSED_001", "PS_STATE_001", "PS_REQUEST_001", "PS_SIM_001", "PS_ASSET_001", "PS_ASSET_002", "PS_ASSET_003", "PS_APPROVAL_001", "PS_RECOVERY_001", "PS_RECOVERY_002", "PS_RECOVERY_003", "PS_LOSS_001", "PS_LOSS_002", "PS_LOSS_003", "PS_PRICE_001", "PS_SIM_002"])
      expect(codes.has(code), code).toBe(true);
  }, 600_000);

  it("long calldata is bounded identically", () => {
    const c = evalCase(7);
    c.intent.data = "0xa9059cbb" + "00".repeat(65_533);
    expect(sameJson(rust(c), reference(c))).toBeNull();
    c.intent.data = "0xa9059cbb" + "00".repeat(65_532);
    expect(sameJson(rust(c), reference(c))).toBeNull();
  }, 60_000);
});

describe("loosening delay: the version that decides is an input", () => {
  // The server passes the active version while a looser one is pending, and the new one after
  // effective_at. Both engines must reach the same decision for each, and the two must differ.
  const strict = JSON.parse(JSON.stringify(EXAMPLE_POLICY)) as Policy;
  const target = "0x2222222222222222222222222222222222222222" as const;
  Object.assign(strict, { status: "active", version: 4, account: { chain_id: 46630, address: "0x1111111111111111111111111111111111111111" } });
  strict.contracts = { default: "deny", allowlist: [{ address: target, selectors: [], require_verified_code: false }], denylist: [] };
  strict.limits = { ...strict.limits, max_transaction_value_wei: "1000", max_gas_cost_wei: "999999999999", hourly_budget_usd_micros: "999999999999", max_pending_operations: 5, max_price_age_seconds: 600 };
  strict.cooldowns = { identical_calldata_seconds: 0, identical_intent_seconds: 0 };
  strict.human_approval = { usd_threshold_micros: "999999999999", require_for_unknown_methods: false };
  const loose = { ...JSON.parse(JSON.stringify(strict)), version: 5, limits: { ...strict.limits, max_transaction_value_wei: "1000000" } } as Policy;
  const intent = { request_id: "pending-1", agent_id: "agent-a", chain_id: 46630, from: "0x1111111111111111111111111111111111111111", to: target, value_wei: "5000", data: "0x", deadline: 1_800_000_300 } as Intent;
  const state = { reservations: [], seen_request_ids: [], calldata_seen: {}, intent_seen: {} } as LedgerState;
  const env = { now: 1_800_000_000, fee_estimate_wei: "100", eth_usd: { price_micros: "3000000000", observed_at: 1_800_000_000 }, verified_code: {}, emergency_stop: false, paused_agents: [] } as Environment;

  it("before effective_at the active (stricter) version denies, on both engines", () => {
    const ref = evaluate(strict, intent, state, env);
    expect(ref.decision).toBe("DENY");
    expect(ref.policy_version).toBe(4);
    expect(sameJson(evaluateRust(strict, intent, state, env), ref)).toBeNull();
  });

  it("after effective_at the new version allows, on both engines", () => {
    const ref = evaluate(loose, intent, state, env);
    expect(ref.decision, ref.message).toBe("ALLOW");
    expect(ref.policy_version).toBe(5);
    expect(sameJson(evaluateRust(loose, intent, state, env), ref)).toBeNull();
  });
});

describe("dual evaluation", () => {
  const c = evalCase(3);
  const args = [c.policy as Policy, c.intent as unknown as Intent, c.state as unknown as LedgerState, c.env as unknown as Environment] as const;

  it("returns the shared result when both engines agree", () => {
    expect(sameJson(evaluateDual(...args, () => {}), evaluate(...args))).toBeNull();
  });

  it("fails closed when the reference throws", () => {
    const reports: unknown[] = [];
    const r = evaluateDual({ nonsense: true } as unknown as Policy, args[1], args[2], args[3], (d) => reports.push(d));
    expect(r.decision).toBe("DENY");
    expect(r.reason_code).toBe("PS_STATE_001");
    expect(r.next_state).toBe(args[2]);
    expect(reports).toHaveLength(1);
  });

  it("fails closed when the inputs cannot be evaluated by the engine", () => {
    const bad = { ...args[3], now: "soon" } as unknown as Environment;
    const r = evaluateDual(args[0], args[1], args[2], bad, () => {});
    expect(r.decision).toBe("DENY");
    expect(r.reason_code).toBe("PS_STATE_001");
  });
});

describe("token spend cases: both engines agree", () => {
  for (const c of SPEND_CASES) {
    it(c.name, () => {
      const ref = evaluate(c.policy, c.intent, c.state, c.env);
      expect(ref.decision).toBe(c.decision);
      expect(sameJson(evaluateRust(c.policy, c.intent, c.state, c.env), ref)).toBeNull();
    });
  }
});

describe("account stop cases: both engines agree", () => {
  for (const c of STOP_CASES)
    it(c.name, () => {
      const ref = evaluate(c.policy, c.intent, STOP_STATE, c.env);
      expect(ref.decision).toBe(c.decision);
      expect(sameJson(evaluateRust(c.policy, c.intent, STOP_STATE, c.env), ref)).toBeNull();
    });
});
