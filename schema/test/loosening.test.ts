import { describe, expect, it } from "vitest";
import { classifyPolicyChange, EXAMPLE_POLICY, type Policy } from "../src";

const clone = (p: Policy): Policy => JSON.parse(JSON.stringify(p));
const base = (): Policy => ({
  ...clone(EXAMPLE_POLICY),
  schema_version: "1.1",
  asset_safety: {
    enabled: true, max_transfer_tax_bps: 500, max_slippage_bps: 300, require_sell_simulation: true,
    block_unlimited_approvals: true, on_simulation_unavailable: "deny", max_simulation_age_seconds: 10,
  },
});
const kinds = (b: Policy, a: Policy) => classifyPolicyChange(b, a).changes.map((c) => c.kind);
const edit = (f: (p: Policy) => void) => {
  const p = base();
  f(p);
  return p;
};

describe("loosening classifier", () => {
  const loosening: [string, (p: Policy) => void][] = [
    ["higher per-transaction limit", (p) => (p.limits.max_transaction_value_wei = "200000000000000000")],
    ["higher gas limit", (p) => (p.limits.max_gas_cost_wei = "9000000000000000")],
    ["higher hourly budget", (p) => (p.limits.hourly_budget_usd_micros = "900000000")],
    ["higher pending limit", (p) => (p.limits.max_pending_operations = 9)],
    ["older price accepted", (p) => (p.limits.max_price_age_seconds = 600)],
    ["higher approval threshold", (p) => (p.human_approval.usd_threshold_micros = String(10n ** 12n))],
    ["new allowlisted contract", (p) => p.contracts.allowlist.push({ address: "0x9999999999999999999999999999999999999999", selectors: [], require_verified_code: true })],
    ["new allowed function", (p) => p.contracts.allowlist[0]!.selectors.push("0xdeadbeef")],
    ["verified code no longer required", (p) => (p.contracts.allowlist[0]!.require_verified_code = false)],
    ["removed deny rule", (p) => (p.contracts.denylist = [])],
    ["shorter calldata cooldown", (p) => (p.cooldowns.identical_calldata_seconds = 1)],
    ["shorter intent cooldown", (p) => (p.cooldowns.identical_intent_seconds = 1)],
    ["unknown methods from deny to review", (p) => (p.human_approval.require_for_unknown_methods = true)],
    ["asset safety off", (p) => (p.asset_safety!.enabled = false)],
    ["higher tax allowed", (p) => (p.asset_safety!.max_transfer_tax_bps = 2000)],
    ["higher slippage allowed", (p) => (p.asset_safety!.max_slippage_bps = 1000)],
    ["sell simulation off", (p) => (p.asset_safety!.require_sell_simulation = false)],
    ["unlimited approvals allowed", (p) => (p.asset_safety!.block_unlimited_approvals = false)],
    ["no simulation: deny to review", (p) => (p.asset_safety!.on_simulation_unavailable = "review")],
    ["older simulation accepted", (p) => (p.asset_safety!.max_simulation_age_seconds = 60)],
    ["asset safety removed", (p) => delete p.asset_safety],
    ["different account", (p) => (p.account.address = "0x9999999999999999999999999999999999999999")],
    ["unknown field (cannot classify)", (p) => ((p as unknown as Record<string, unknown>).extra_rule = { x: 1 })],
  ];
  for (const [name, f] of loosening)
    it(`loosening: ${name}`, () => {
      const before = base();
      if (name.includes("deny to review")) before.human_approval.require_for_unknown_methods = false;
      const after = clone(before);
      f(after);
      const r = classifyPolicyChange(before, after);
      expect(r.loosening).toBe(true);
      expect(r.changes.length).toBeGreaterThan(0);
    });

  const tightening: [string, (p: Policy) => void][] = [
    ["lower per-transaction limit", (p) => (p.limits.max_transaction_value_wei = "1")],
    ["lower hourly budget", (p) => (p.limits.hourly_budget_usd_micros = "1")],
    ["lower pending limit", (p) => (p.limits.max_pending_operations = 1)],
    ["lower approval threshold", (p) => (p.human_approval.usd_threshold_micros = "1")],
    ["removed allowlist entry", (p) => p.contracts.allowlist.pop()],
    ["removed function", (p) => (p.contracts.allowlist[0]!.selectors = [])],
    ["added deny rule", (p) => p.contracts.denylist.push("0x9999999999999999999999999999999999999999")],
    ["longer cooldown", (p) => (p.cooldowns.identical_calldata_seconds = 3600)],
    ["unknown methods from review to deny", (p) => (p.human_approval.require_for_unknown_methods = false)],
    ["lower tax allowed", (p) => (p.asset_safety!.max_transfer_tax_bps = 100)],
    ["no simulation: review to deny", (p) => (p.asset_safety!.on_simulation_unavailable = "deny")],
  ];
  for (const [name, f] of tightening)
    it(`tightening: ${name}`, () => {
      const before = name.includes("review to deny")
        ? edit((p) => {
            p.human_approval.require_for_unknown_methods = true;
            p.asset_safety!.on_simulation_unavailable = "review";
          })
        : base();
      const r = classifyPolicyChange(before, f === tightening[0]![1] ? edit(f) : (() => { const p = clone(before); f(p); return p; })());
      expect(r.changes.length).toBeGreaterThan(0);
      expect(r.loosening, JSON.stringify(r.changes)).toBe(false);
    });

  it("Upoch recovery: turning it off, a longer checkpoint age or review on no data loosen; adding it tightens", () => {
    const up = edit((p) => {
      p.schema_version = "1.2";
      p.upoch_recovery = { require_upoch_recoverable: true, max_checkpoint_age_seconds: 604800, require_guardian: true, on_unavailable: "deny" };
    });
    expect(classifyPolicyChange(base(), up).loosening).toBe(false);
    const w = (f: (p: Policy) => void) => { const p = JSON.parse(JSON.stringify(up)) as Policy; f(p); return classifyPolicyChange(up, p).loosening; };
    expect(w((p) => (p.upoch_recovery!.require_upoch_recoverable = false))).toBe(true);
    expect(w((p) => (p.upoch_recovery!.max_checkpoint_age_seconds = 2_000_000))).toBe(true);
    expect(w((p) => (p.upoch_recovery!.require_guardian = false))).toBe(true);
    expect(w((p) => (p.upoch_recovery!.on_unavailable = "review"))).toBe(true);
    expect(w((p) => delete p.upoch_recovery)).toBe(true);
    expect(w((p) => (p.upoch_recovery!.max_checkpoint_age_seconds = 3600))).toBe(false);
  });

  it("adding asset safety to a 1.0 policy tightens", () => {
    const old = clone(EXAMPLE_POLICY);
    const r = classifyPolicyChange(old, base());
    expect(r.loosening).toBe(false);
  });

  it("a mixed change is loosening as a whole, with both kinds listed", () => {
    const k = kinds(base(), edit((p) => {
      p.limits.hourly_budget_usd_micros = "1";
      p.limits.max_transaction_value_wei = "900000000000000000";
    }));
    expect(k).toContain("tightening");
    expect(k).toContain("loosening");
    expect(classifyPolicyChange(base(), edit((p) => (p.limits.max_transaction_value_wei = "900000000000000000"))).loosening).toBe(true);
  });

  it("re-enabling or first activation is loosening; version and status are ignored", () => {
    expect(classifyPolicyChange(null, base()).loosening).toBe(true);
    expect(classifyPolicyChange(base(), base(), { disabled: true }).loosening).toBe(true);
    expect(classifyPolicyChange(base(), edit((p) => { p.version = 99; p.status = "draft"; })).changes).toEqual([]);
  });

  it("a repeated allowlist address is loosening (the engines use the first entry)", () => {
    const after = edit((p) => {
      const first = p.contracts.allowlist[0]!;
      p.contracts.allowlist.unshift({ address: first.address.toUpperCase().replace("0X", "0x") as `0x${string}`, selectors: ["0xdeadbeef"], require_verified_code: false });
    });
    expect(classifyPolicyChange(base(), after).loosening).toBe(true);
  });

  it("address case does not count as a change", () => {
    expect(classifyPolicyChange(base(), edit((p) => (p.contracts.allowlist[0]!.address = p.contracts.allowlist[0]!.address.toUpperCase().replace("0X", "0x") as `0x${string}`))).changes).toEqual([]);
  });
});
