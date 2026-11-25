import { describe, expect, it } from "vitest";
import { evaluate } from "../src";
import { STOP_CASES, STOP_STATE } from "./account-stop-cases";

describe("a stop the account engaged on the registry stops Palisec's decisions", () => {
  for (const c of STOP_CASES)
    it(c.name, () => {
      const r = evaluate(c.policy, c.intent, STOP_STATE, c.env);
      expect({ d: r.decision, c: r.reason_code }, r.message).toEqual({ d: c.decision, c: c.code });
    });
});
