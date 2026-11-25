# Palisec policy schema and engines

[![CI](https://github.com/palisec/policy-schema/actions/workflows/ci.yml/badge.svg)](https://github.com/palisec/policy-schema/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

The rules Palisec applies before it co-signs an agent's transaction, in a form you can check yourself:

| Path | What |
|---|---|
| `schema/` | The policy JSON Schema (1.5), the reason codes (`PS_*`), validation, the policy-change classifier and the **TypeScript reference evaluator** |
| `engine/` | The **Rust policy engine**, compiled to WebAssembly; the production evaluator |
| `engine-wasm/` | The embedded WebAssembly build and the **parity suite**: shared fixtures plus a 20,000-case seeded fuzz run that the two engines must agree on, field for field |

Palisec runs both engines on every decision and denies if they ever disagree (fail closed).

## Run it

```sh
npm install
npm run typecheck
npm test                                   # reference tests + parity (PARITY_FUZZ=20000 for the full run)
cd engine && cargo test --locked           # the Rust engine against the same fixtures
```

Rebuild the WebAssembly after changing the Rust sources: `npm run build:wasm -w engine-wasm` (needs the `wasm32-unknown-unknown` target).

## Example

```ts
import { evaluate, EMPTY_STATE, EXAMPLE_POLICY, EXAMPLE_ENV } from "@palisec/policy-schema";

const result = evaluate(EXAMPLE_POLICY, {
  request_id: "req-1", agent_id: "agent-a", chain_id: 4663,
  from: EXAMPLE_POLICY.account.address, to: "0x2222222222222222222222222222222222222222",
  value_wei: "0", data: "0x", deadline: EXAMPLE_ENV.now + 60,
}, EMPTY_STATE, EXAMPLE_ENV);
console.log(result.decision, result.reason_code); // every check, with its reason
```

Docs: [policy reference](https://palisec.tech/docs/policies) · [reason codes](https://palisec.tech/docs/errors) · [palisec.tech](https://palisec.tech)

## History

Developed inside [palisec/palisec](https://github.com/palisec/palisec), where its full commit history is.
