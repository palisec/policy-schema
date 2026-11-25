import {
  evaluate,
  RETRYABLE,
  type Environment,
  type EvaluationResult,
  type Intent,
  type LedgerState,
  type Policy,
  type ValidationError,
} from "@palisec/policy-schema";
import { ENGINE_VERSION, SOURCE_HASH, WASM_BASE64 } from "./wasm";

export { ENGINE_VERSION, SOURCE_HASH };

interface Exports {
  memory: WebAssembly.Memory;
  ps_alloc(len: number): number;
  ps_free(ptr: number, len: number): void;
  ps_evaluate(ptr: number, len: number): bigint;
  ps_validate(ptr: number, len: number): bigint;
}

/** The Rust engine could not run or returned an error. Callers fail closed. */
export class EngineError extends Error {
  override name = "EngineError";
}

let exportsCache: Exports | null = null;
let loadError: string | null = null;

function load(): Exports {
  if (exportsCache) return exportsCache;
  if (loadError) throw new EngineError(loadError);
  try {
    const bin = atob(WASM_BASE64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    // Synchronous compile is fine on the server (no main-thread size limit in Node).
    const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
    exportsCache = instance.exports as unknown as Exports;
    return exportsCache;
  } catch (e) {
    loadError = `policy engine failed to load: ${e instanceof Error ? e.message : String(e)}`;
    throw new EngineError(loadError);
  }
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function call(fn: "ps_evaluate" | "ps_validate", request: string): unknown {
  const x = load();
  const input = enc.encode(request);
  const ptr = x.ps_alloc(input.length);
  new Uint8Array(x.memory.buffer, ptr, input.length).set(input);
  let packed: bigint;
  try {
    packed = x[fn](ptr, input.length);
  } catch (e) {
    // A trap leaves the instance in an unknown state: drop it and reload on the next call.
    exportsCache = null;
    throw new EngineError(`policy engine trapped: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    if (exportsCache) x.ps_free(ptr, input.length);
  }
  const outPtr = Number(packed >> 32n);
  const outLen = Number(packed & 0xffffffffn);
  const text = dec.decode(new Uint8Array(x.memory.buffer, outPtr, outLen));
  x.ps_free(outPtr, outLen);
  const res = JSON.parse(text) as { ok?: unknown; error?: string };
  if (res.error !== undefined) throw new EngineError(res.error);
  return res.ok;
}

/** The Rust engine's evaluation. Throws EngineError if it cannot evaluate. */
export function evaluateRust(policy: Policy | null, intent: Intent, state: LedgerState, env: Environment): EvaluationResult {
  return call("ps_evaluate", JSON.stringify({ policy, intent, state, env })) as EvaluationResult;
}

/** The Rust engine's schema validation. */
export function validateRust(doc: unknown): ValidationError[] {
  return call("ps_validate", JSON.stringify(doc)) as ValidationError[];
}

/** Whether the engine loads and runs, for health checks. Cheap after the first call. */
export function engineStatus(): { ok: boolean; version: string; source_hash: string; error?: string } {
  try {
    validateRust({});
    return { ok: true, version: ENGINE_VERSION, source_hash: SOURCE_HASH };
  } catch (e) {
    return { ok: false, version: ENGINE_VERSION, source_hash: SOURCE_HASH, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Structural equality of JSON values: object key order is ignored, array order is not. */
export function sameJson(a: unknown, b: unknown, path = "$"): string | null {
  if (a === b) return null;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return path;
  if (Array.isArray(a) !== Array.isArray(b)) return path;
  if (Array.isArray(a)) {
    const bb = b as unknown[];
    if (a.length !== bb.length) return `${path}.length`;
    for (let i = 0; i < a.length; i++) {
      const d = sameJson(a[i], bb[i], `${path}[${i}]`);
      if (d) return d;
    }
    return null;
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const keys = new Set([...Object.keys(ao), ...Object.keys(bo)]);
  for (const k of keys) {
    if (ao[k] === undefined && bo[k] === undefined) continue;
    const d = sameJson(ao[k], bo[k], `${path}.${k}`);
    if (d) return d;
  }
  return null;
}

export type Disagreement = { request_id: string; reason: string; reference: string | null; engine: string | null };

/**
 * Evaluates with both the Rust engine and the TypeScript reference. Returns the result only when
 * they agree on every field; otherwise the request is denied with PS_STATE_001 and nothing is
 * reserved. A bug in either implementation can therefore deny, but never allow.
 */
export function evaluateDual(
  policy: Policy | null,
  intent: Intent,
  state: LedgerState,
  env: Environment,
  report: (d: Disagreement) => void = (d) => console.error("[policy-engine] fail closed", d),
): EvaluationResult {
  let reference: EvaluationResult | null = null;
  let engine: EvaluationResult | null = null;
  let reason: string | null = null;
  try {
    reference = evaluate(policy, intent, state, env);
  } catch (e) {
    reason = `reference evaluator error: ${e instanceof Error ? e.message : String(e)}`;
  }
  try {
    engine = evaluateRust(policy, intent, state, env);
  } catch (e) {
    reason ??= e instanceof Error ? e.message : String(e);
  }
  if (reference && engine) {
    const diff = sameJson(reference, engine);
    if (diff === null) return engine;
    reason = `engines disagree at ${diff}`;
  }
  report({ request_id: intent.request_id, reason: reason ?? "unknown", reference: reference?.decision ?? null, engine: engine?.decision ?? null });
  return {
    request_id: intent.request_id,
    decision: "DENY",
    reason_code: "PS_STATE_001",
    policy_id: reference?.policy_id ?? null,
    policy_version: reference?.policy_version ?? null,
    authorization_id: null,
    transaction_hash: null,
    retryable: RETRYABLE.PS_STATE_001,
    message: "The policy engine could not confirm this decision, so the request fails closed. Nothing was reserved.",
    checks: [
      { id: "engine", label: "Policy engines agree", status: "fail", detail: "The Rust engine and the reference evaluator must return the same result. They did not, or one could not run.", enforcement: "local" },
    ],
    next_state: state,
  };
}
