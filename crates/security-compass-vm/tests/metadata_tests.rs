//! Integration tests for metadata tracking through the Security Compass VM.
//!
//! These tests exercise the public `MontyRun` API and verify that metadata
//! (producers, consumers, tags) propagates correctly through various Python
//! operations executed by the VM.

use security_compass_vm::{
    DictPairs, ExternalResult, Metadata, MontyObject, MontyRun, NoPrint, NoLimitTracker,
    RunProgress,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse Python code with the given input names and no external functions.
fn parse(code: &str, input_names: Vec<&str>) -> MontyRun {
    MontyRun::new(
        code.to_owned(),
        "test.py",
        input_names.into_iter().map(String::from).collect(),
        vec![],
    )
    .expect("parse should succeed")
}

/// Parse Python code with the given input names and external functions.
fn parse_with_externals(code: &str, input_names: Vec<&str>, externals: Vec<&str>) -> MontyRun {
    MontyRun::new(
        code.to_owned(),
        "test.py",
        input_names.into_iter().map(String::from).collect(),
        externals.into_iter().map(String::from).collect(),
    )
    .expect("parse should succeed")
}

/// Run code with `start()` (which returns metadata) and extract the Complete variant.
fn run_to_complete(
    runner: MontyRun,
    inputs: Vec<MontyObject>,
) -> (MontyObject, Metadata) {
    let progress = runner
        .start(inputs, NoLimitTracker, &mut NoPrint)
        .expect("execution should succeed");
    progress
        .into_complete()
        .expect("expected RunProgress::Complete")
}

// ---------------------------------------------------------------------------
// 1. Literal has default metadata
// ---------------------------------------------------------------------------

#[test]
fn literal_has_default_meta() {
    let runner = parse("42", vec![]);
    let (obj, meta) = run_to_complete(runner, vec![]);

    assert_eq!(obj, MontyObject::Int(42));
    assert_eq!(meta, Metadata::default());
}

// ---------------------------------------------------------------------------
// 2. Binary add merges producers (both default -> result default)
// ---------------------------------------------------------------------------

#[test]
fn binary_add_merges_producers() {
    let runner = parse("a + b", vec!["a", "b"]);
    let (obj, meta) = run_to_complete(
        runner,
        vec![MontyObject::Int(10), MontyObject::Int(32)],
    );

    assert_eq!(obj, MontyObject::Int(42));
    // Both inputs have default metadata, so the merged result is also default.
    assert_eq!(meta, Metadata::default());
}

// ---------------------------------------------------------------------------
// 3. String concat preserves execution
// ---------------------------------------------------------------------------

#[test]
fn string_concat_preserves_execution() {
    let runner = parse("a + b", vec!["a", "b"]);
    let (obj, meta) = run_to_complete(
        runner,
        vec![
            MontyObject::String("hello ".to_string()),
            MontyObject::String("world".to_string()),
        ],
    );

    assert_eq!(obj, MontyObject::String("hello world".to_string()));
    // Both inputs have default metadata -> merged result is also default.
    assert_eq!(meta, Metadata::default());
}

// ---------------------------------------------------------------------------
// 4. Comparison produces result
// ---------------------------------------------------------------------------

#[test]
fn comparison_produces_result() {
    let runner = parse("a == b", vec!["a", "b"]);
    let (obj, _meta) = run_to_complete(
        runner,
        vec![MontyObject::Int(5), MontyObject::Int(5)],
    );
    assert_eq!(obj, MontyObject::Bool(true));

    // Also test when not equal.
    let runner2 = parse("a == b", vec!["a", "b"]);
    let (obj2, _meta2) = run_to_complete(
        runner2,
        vec![MontyObject::Int(5), MontyObject::Int(6)],
    );
    assert_eq!(obj2, MontyObject::Bool(false));
}

// ---------------------------------------------------------------------------
// 5. Unary negation works
// ---------------------------------------------------------------------------

#[test]
fn unary_neg_works() {
    let runner = parse("-a", vec!["a"]);
    let (obj, meta) = run_to_complete(runner, vec![MontyObject::Int(7)]);
    assert_eq!(obj, MontyObject::Int(-7));
    assert_eq!(meta, Metadata::default());
}

// ---------------------------------------------------------------------------
// 6. List building works
// ---------------------------------------------------------------------------

#[test]
fn list_building_works() {
    let runner = parse("[a, b, c]", vec!["a", "b", "c"]);
    let (obj, _meta) = run_to_complete(
        runner,
        vec![
            MontyObject::Int(1),
            MontyObject::Int(2),
            MontyObject::Int(3),
        ],
    );
    assert_eq!(
        obj,
        MontyObject::List(vec![
            MontyObject::Int(1),
            MontyObject::Int(2),
            MontyObject::Int(3),
        ])
    );
}

// ---------------------------------------------------------------------------
// 7. Variable store/load roundtrip
// ---------------------------------------------------------------------------

#[test]
fn variable_store_load_roundtrip() {
    let runner = parse("x = a\nx", vec!["a"]);
    let (obj, meta) = run_to_complete(runner, vec![MontyObject::Int(42)]);
    assert_eq!(obj, MontyObject::Int(42));
    assert_eq!(meta, Metadata::default());
}

// ---------------------------------------------------------------------------
// 8. Conditional branch works
// ---------------------------------------------------------------------------

#[test]
fn conditional_branch_works() {
    // Positive input -> result is `a` itself.
    let runner = parse("a if a > 0 else -a", vec!["a"]);
    let (obj, _meta) = run_to_complete(runner, vec![MontyObject::Int(5)]);
    assert_eq!(obj, MontyObject::Int(5));

    // Negative input -> result is `-a`.
    let runner2 = parse("a if a > 0 else -a", vec!["a"]);
    let (obj2, _meta2) = run_to_complete(runner2, vec![MontyObject::Int(-3)]);
    assert_eq!(obj2, MontyObject::Int(3));
}

// ---------------------------------------------------------------------------
// 9. External call has args_meta
// ---------------------------------------------------------------------------

#[test]
fn external_call_has_args_meta() {
    let runner = parse_with_externals("f(a)", vec!["a"], vec!["f"]);
    let progress = runner
        .start(vec![MontyObject::Int(10)], NoLimitTracker, &mut NoPrint)
        .expect("execution should succeed");

    match progress {
        RunProgress::FunctionCall {
            function_name,
            args,
            args_meta,
            ..
        } => {
            assert_eq!(function_name, "f");
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], MontyObject::Int(10));
            // args_meta should have one entry per positional argument.
            assert_eq!(args_meta.len(), 1);
        }
        other => panic!("expected FunctionCall, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 10. Resume with return metadata
// ---------------------------------------------------------------------------

#[test]
fn resume_with_return_meta() {
    let runner = parse_with_externals("f(a)", vec!["a"], vec!["f"]);
    let progress = runner
        .start(vec![MontyObject::Int(10)], NoLimitTracker, &mut NoPrint)
        .expect("execution should succeed");

    let (_, _, _, _, _, state) = progress
        .into_function_call()
        .expect("expected FunctionCall");

    let custom_meta = Metadata::default().with_producer("my_tool");
    let result = state
        .run(
            ExternalResult::return_with_meta(MontyObject::Int(99), custom_meta.clone()),
            &mut NoPrint,
        )
        .expect("resume should succeed");

    let (obj, result_meta) = result.into_complete().expect("expected Complete");
    assert_eq!(obj, MontyObject::Int(99));
    // The result metadata should carry the producer from the external return.
    assert!(result_meta.producers.contains("my_tool"));
}

// ---------------------------------------------------------------------------
// 11. Snapshot serialize/deserialize roundtrip
// ---------------------------------------------------------------------------

#[test]
fn snapshot_serialize_deserialize() {
    // Test MontyRun serialization: dump the parsed code, reload, and execute.
    let runner = parse_with_externals("f(a)", vec!["a"], vec!["f"]);

    // Serialize the MontyRun (parsed code + interns).
    let bytes = runner.dump().expect("MontyRun dump should succeed");

    // Deserialize it back.
    let loaded = MontyRun::load(&bytes).expect("MontyRun load should succeed");

    // Verify the loaded runner produces the same results.
    let progress = loaded
        .start(vec![MontyObject::Int(10)], NoLimitTracker, &mut NoPrint)
        .expect("execution should succeed");

    let (fn_name, args, _, _, _, state) = progress
        .into_function_call()
        .expect("expected FunctionCall after load");

    assert_eq!(fn_name, "f");
    assert_eq!(args[0], MontyObject::Int(10));

    // Resume after deserialization and verify the result is correct.
    let result = state
        .run(MontyObject::Int(99), &mut NoPrint)
        .expect("resume should succeed");

    let (obj, _meta) = result.into_complete().expect("expected Complete");
    assert_eq!(obj, MontyObject::Int(99));
}

// ---------------------------------------------------------------------------
// 12. Branch checker (skipped — requires internal VM access)
// ---------------------------------------------------------------------------

// NOTE: BranchChecker testing requires direct access to the VM struct,
// which is not exposed through the public MontyRun API. Branch checker
// integration tests will be added in Phase 5's interpreter-level tests
// where we have access to the VM internals.

#[test]
fn branch_checker_allows_clean() {
    // Placeholder: verify that code with a conditional executes correctly
    // through the public API (without an explicit BranchChecker).
    // The default VM has no branch checker installed, so all branches are allowed.
    let runner = parse("x if x > 0 else 0", vec!["x"]);
    let (obj, meta) = run_to_complete(runner, vec![MontyObject::Int(5)]);
    assert_eq!(obj, MontyObject::Int(5));
    assert_eq!(meta, Metadata::default());
}

// ---------------------------------------------------------------------------
// 13. For loop works
// ---------------------------------------------------------------------------

#[test]
fn for_loop_works() {
    let code = "\
total = 0
for x in items:
    total = total + x
total";
    let runner = parse(code, vec!["items"]);
    let (obj, _meta) = run_to_complete(
        runner,
        vec![MontyObject::List(vec![
            MontyObject::Int(1),
            MontyObject::Int(2),
            MontyObject::Int(3),
            MontyObject::Int(4),
        ])],
    );
    assert_eq!(obj, MontyObject::Int(10));
}

// ---------------------------------------------------------------------------
// 14. Dict building works
// ---------------------------------------------------------------------------

#[test]
fn dict_building_works() {
    let code = r#"{"key": a, "other": b}"#;
    let runner = parse(code, vec!["a", "b"]);
    let (obj, _meta) = run_to_complete(
        runner,
        vec![MontyObject::Int(1), MontyObject::Int(2)],
    );
    let expected = MontyObject::Dict(DictPairs::from(vec![
        (
            MontyObject::String("key".to_string()),
            MontyObject::Int(1),
        ),
        (
            MontyObject::String("other".to_string()),
            MontyObject::Int(2),
        ),
    ]));
    assert_eq!(obj, expected);
}
