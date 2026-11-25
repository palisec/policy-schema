//! The native engine against the shared fixtures (packages/policy-engine/fixtures/parity.jsonl),
//! which hold the TypeScript reference evaluator's results. A `null` expectation means the
//! reference refuses the input outright; the engine must refuse it too.

use palisec_policy_engine::{evaluate::evaluate, validate::validate_json};
use serde_json::Value;

#[test]
fn engine_matches_reference_fixtures() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../engine-wasm/fixtures/parity.jsonl");
    let text = std::fs::read_to_string(path).expect("fixtures present");
    let (mut evaluated, mut validated) = (0, 0);
    for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let f: Value = serde_json::from_str(line).expect("fixture line is JSON");
        let input = &f["input"];
        let expected = &f["expected"];
        match f["kind"].as_str() {
            Some("evaluate") => {
                let got = evaluate(&input["policy"], &input["intent"], &input["state"], &input["env"]);
                match (expected, got) {
                    (Value::Null, Err(_)) => {}
                    (Value::Null, Ok(v)) => panic!("line {}: reference refuses, engine returned {}", i + 1, v["decision"]),
                    (_, Err(e)) => panic!("line {}: engine error {e}", i + 1),
                    (exp, Ok(v)) => assert_eq!(&v, exp, "line {} (seed {})", i + 1, f["seed"]),
                }
                evaluated += 1;
            }
            Some("validate") => {
                assert_eq!(&validate_json(input), expected, "validation line {} (seed {})", i + 1, f["seed"]);
                validated += 1;
            }
            other => panic!("unknown fixture kind {other:?}"),
        }
    }
    assert!(evaluated > 100 && validated > 100, "fixtures too small: {evaluated} evaluations, {validated} validations");
}
