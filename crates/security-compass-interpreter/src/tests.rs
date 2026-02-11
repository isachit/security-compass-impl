//! Tests for the Security Compass Interpreter.
//!
//! Test categories:
//! - Convert tests: MontyObject ↔ JSON roundtrip
//! - Branch checker tests: PolicyBranchChecker behavior
//! - Execution tests: Full interpreter execution flow
//! - Policy integration tests: SQRT policy enforcement
//! - Edge case tests: Error handling and boundary conditions

use std::collections::BTreeSet;
use std::sync::Arc;

use security_compass_meta::{ConsumerSet, Metadata, ValueWithMeta};
use security_compass_vm::{DictPairs, ExcType, MontyObject};
use sqrt_eval::{CompiledPolicy, InternalPolicyPreset};

use crate::branch_checker::PolicyBranchChecker;
use crate::convert::{json_to_monty, monty_to_json};
use crate::error::InterpreterError;
use crate::types::{ExecutionResult, Interpreter, InterpreterConfig, ToolDefinition};

// ============================================================
// Test Helpers
// ============================================================

fn str_set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn meta(producers: &[&str], consumers: ConsumerSet, tags: &[&str]) -> Metadata {
    Metadata {
        producers: str_set(producers),
        consumers,
        tags: str_set(tags),
    }
}

fn parse_and_compile(src: &str) -> CompiledPolicy {
    let program = sqrt_parser::parse(src).expect("Parse failed");
    sqrt_eval::compile(&program, InternalPolicyPreset::default()).expect("Compile failed")
}

fn parse_and_compile_with_preset(src: &str, preset: InternalPolicyPreset) -> CompiledPolicy {
    let program = sqrt_parser::parse(src).expect("Parse failed");
    sqrt_eval::compile(&program, preset).expect("Compile failed")
}

fn default_config() -> InterpreterConfig {
    InterpreterConfig::default()
}

fn simple_tool(name: &str, params: &[&str]) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        parameter_names: params.iter().map(|s| (*s).to_string()).collect(),
        deterministic: false,
    }
}

fn deterministic_tool(name: &str, params: &[&str]) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        parameter_names: params.iter().map(|s| (*s).to_string()).collect(),
        deterministic: true,
    }
}

fn input_var(name: &str, value: serde_json::Value) -> (String, ValueWithMeta<serde_json::Value>) {
    (
        name.to_string(),
        ValueWithMeta {
            value,
            meta: Metadata::default(),
        },
    )
}

fn input_var_with_meta(
    name: &str,
    value: serde_json::Value,
    meta: Metadata,
) -> (String, ValueWithMeta<serde_json::Value>) {
    (name.to_string(), ValueWithMeta { value, meta })
}

// ============================================================
// Convert Tests
// ============================================================

#[test]
fn convert_none_roundtrip() {
    let obj = MontyObject::None;
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::Value::Null);
    let back = json_to_monty(json);
    assert_eq!(back, MontyObject::None);
}

#[test]
fn convert_bool_roundtrip() {
    for b in [true, false] {
        let obj = MontyObject::Bool(b);
        let json = monty_to_json(&obj).unwrap();
        assert_eq!(json, serde_json::Value::Bool(b));
        let back = json_to_monty(json);
        assert_eq!(back, MontyObject::Bool(b));
    }
}

#[test]
fn convert_int_roundtrip() {
    for i in [0i64, 1, -1, i64::MAX, i64::MIN] {
        let obj = MontyObject::Int(i);
        let json = monty_to_json(&obj).unwrap();
        assert_eq!(json, serde_json::json!(i));
        let back = json_to_monty(json);
        assert_eq!(back, MontyObject::Int(i));
    }
}

#[test]
fn convert_float_roundtrip() {
    let obj = MontyObject::Float(3.14);
    let json = monty_to_json(&obj).unwrap();
    let back = json_to_monty(json);
    match back {
        MontyObject::Float(f) => assert!((f - 3.14).abs() < 1e-10),
        other => panic!("Expected Float, got {other:?}"),
    }
}

#[test]
fn convert_float_nan_to_null() {
    let obj = MontyObject::Float(f64::NAN);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::Value::Null);
}

#[test]
fn convert_float_infinity_to_null() {
    let obj = MontyObject::Float(f64::INFINITY);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::Value::Null);

    let obj = MontyObject::Float(f64::NEG_INFINITY);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::Value::Null);
}

#[test]
fn convert_string_roundtrip() {
    let obj = MontyObject::String("hello world".to_string());
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!("hello world"));
    let back = json_to_monty(json);
    assert_eq!(back, MontyObject::String("hello world".to_string()));
}

#[test]
fn convert_empty_string() {
    let obj = MontyObject::String(String::new());
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!(""));
}

#[test]
fn convert_list_roundtrip() {
    let obj = MontyObject::List(vec![
        MontyObject::Int(1),
        MontyObject::String("two".to_string()),
        MontyObject::Bool(true),
    ]);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!([1, "two", true]));
    let back = json_to_monty(json);
    match back {
        MontyObject::List(items) => {
            assert_eq!(items.len(), 3);
            assert_eq!(items[0], MontyObject::Int(1));
            assert_eq!(items[1], MontyObject::String("two".to_string()));
            assert_eq!(items[2], MontyObject::Bool(true));
        }
        other => panic!("Expected List, got {other:?}"),
    }
}

#[test]
fn convert_dict_roundtrip() {
    let pairs = vec![
        (MontyObject::String("a".to_string()), MontyObject::Int(1)),
        (MontyObject::String("b".to_string()), MontyObject::Int(2)),
    ];
    let obj = MontyObject::Dict(DictPairs::from(pairs));
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json["a"], serde_json::json!(1));
    assert_eq!(json["b"], serde_json::json!(2));
}

#[test]
fn convert_dict_non_string_keys() {
    let pairs = vec![
        (MontyObject::Int(42), MontyObject::String("answer".to_string())),
        (MontyObject::Bool(true), MontyObject::Int(1)),
    ];
    let obj = MontyObject::Dict(DictPairs::from(pairs));
    let json = monty_to_json(&obj).unwrap();
    // Non-string keys are converted via Display-like formatting
    assert_eq!(json["42"], serde_json::json!("answer"));
    assert_eq!(json["True"], serde_json::json!(1));
}

#[test]
fn convert_tuple_to_array() {
    let obj = MontyObject::Tuple(vec![MontyObject::Int(1), MontyObject::Int(2)]);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!([1, 2]));
}

#[test]
fn convert_set_to_array() {
    let obj = MontyObject::Set(vec![MontyObject::Int(1)]);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!([1]));
}

#[test]
fn convert_bytes_to_array() {
    let obj = MontyObject::Bytes(vec![0, 255, 128]);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!([0, 255, 128]));
}

#[test]
fn convert_bigint_to_string() {
    // BigInt is one-way: converted to string (no roundtrip to BigInt)
    use num_bigint::BigInt;
    let big = BigInt::from(i64::MAX) + BigInt::from(1);
    let obj = MontyObject::BigInt(big);
    let json = monty_to_json(&obj).unwrap();
    assert!(json.is_string());
    assert_eq!(json.as_str().unwrap(), "9223372036854775808");
}

#[test]
fn convert_nested_structure() {
    let inner_dict = MontyObject::Dict(DictPairs::from(vec![
        (MontyObject::String("x".to_string()), MontyObject::Int(10)),
    ]));
    let obj = MontyObject::List(vec![
        MontyObject::Int(1),
        inner_dict,
        MontyObject::List(vec![MontyObject::Bool(true)]),
    ]);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!([1, {"x": 10}, [true]]));
}

#[test]
fn convert_ellipsis_to_null() {
    let obj = MontyObject::Ellipsis;
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::Value::Null);
}

#[test]
fn convert_exception_to_object() {
    let obj = MontyObject::Exception {
        exc_type: ExcType::RuntimeError,
        arg: Some("something went wrong".to_string()),
    };
    let json = monty_to_json(&obj).unwrap();
    let exc = &json["$exception"];
    assert_eq!(exc["type"], "RuntimeError");
    assert_eq!(exc["message"], "something went wrong");
}

#[test]
fn convert_path_to_string() {
    let obj = MontyObject::Path("/usr/bin".to_string());
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!("/usr/bin"));
}

#[test]
fn convert_repr_to_string() {
    let obj = MontyObject::Repr("<object at 0x1234>".to_string());
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!("<object at 0x1234>"));
}

#[test]
fn convert_frozenset_to_array() {
    // FrozenSet converts to JSON array, same as Set
    let obj = MontyObject::FrozenSet(vec![MontyObject::Int(1), MontyObject::Int(2)]);
    let json = monty_to_json(&obj).unwrap();
    assert_eq!(json, serde_json::json!([1, 2]));
}

#[test]
fn convert_json_object_to_dict() {
    let json = serde_json::json!({"key": "value", "num": 42});
    let obj = json_to_monty(json);
    match obj {
        MontyObject::Dict(pairs) => {
            let map: std::collections::HashMap<String, MontyObject> = pairs
                .into_iter()
                .map(|(k, v)| {
                    if let MontyObject::String(s) = k {
                        (s, v)
                    } else {
                        panic!("Expected String key")
                    }
                })
                .collect();
            assert_eq!(map["key"], MontyObject::String("value".to_string()));
            assert_eq!(map["num"], MontyObject::Int(42));
        }
        other => panic!("Expected Dict, got {other:?}"),
    }
}

// ============================================================
// Branch Checker Tests
// ============================================================

#[test]
fn branch_checker_clean_metadata_passes() {
    // Default branching meta-policy = Deny mode with empty sets
    // Clean metadata has no producers/tags, so no overlap → passes
    let policy = parse_and_compile("");
    let checker = PolicyBranchChecker::new(Arc::new(policy));

    let clean_meta = Metadata::default();
    assert!(
        security_compass_vm::BranchChecker::check(&checker, &clean_meta).is_ok()
    );
}

#[test]
fn branch_checker_deny_mode_blocks_matching_producer() {
    // Configure deny mode with specific producers to block
    use sqrt_eval::BranchingMetaPolicy;
    use sqrt_eval::BranchingMode;

    let preset = InternalPolicyPreset {
        branching_meta_policy: BranchingMetaPolicy {
            mode: BranchingMode::Deny,
            producers: str_set(&["untrusted_tool"]),
            tags: BTreeSet::new(),
            consumers: BTreeSet::new(),
        },
        ..InternalPolicyPreset::default()
    };

    let policy = parse_and_compile_with_preset("", preset);
    let checker = PolicyBranchChecker::new(Arc::new(policy));

    // Metadata with matching producer → should be denied
    let tainted_meta = meta(&["untrusted_tool"], ConsumerSet::Universal, &[]);
    let result = security_compass_vm::BranchChecker::check(&checker, &tainted_meta);
    assert!(result.is_err());
}

#[test]
fn branch_checker_deny_mode_allows_non_matching() {
    use sqrt_eval::{BranchingMetaPolicy, BranchingMode};

    let preset = InternalPolicyPreset {
        branching_meta_policy: BranchingMetaPolicy {
            mode: BranchingMode::Deny,
            producers: str_set(&["untrusted_tool"]),
            tags: BTreeSet::new(),
            consumers: BTreeSet::new(),
        },
        ..InternalPolicyPreset::default()
    };

    let policy = parse_and_compile_with_preset("", preset);
    let checker = PolicyBranchChecker::new(Arc::new(policy));

    // Metadata with non-matching producer → allowed
    let safe_meta = meta(&["trusted_tool"], ConsumerSet::Universal, &[]);
    assert!(
        security_compass_vm::BranchChecker::check(&checker, &safe_meta).is_ok()
    );
}

#[test]
fn branch_checker_deny_mode_blocks_matching_tag() {
    use sqrt_eval::{BranchingMetaPolicy, BranchingMode};

    let preset = InternalPolicyPreset {
        branching_meta_policy: BranchingMetaPolicy {
            mode: BranchingMode::Deny,
            producers: BTreeSet::new(),
            tags: str_set(&["__non_executable"]),
            consumers: BTreeSet::new(),
        },
        ..InternalPolicyPreset::default()
    };

    let policy = parse_and_compile_with_preset("", preset);
    let checker = PolicyBranchChecker::new(Arc::new(policy));

    let tagged_meta = meta(&[], ConsumerSet::Universal, &["__non_executable"]);
    assert!(
        security_compass_vm::BranchChecker::check(&checker, &tagged_meta).is_err()
    );
}

#[test]
fn branch_checker_allow_mode_allows_subset() {
    use sqrt_eval::{BranchingMetaPolicy, BranchingMode};

    let preset = InternalPolicyPreset {
        branching_meta_policy: BranchingMetaPolicy {
            mode: BranchingMode::Allow,
            producers: str_set(&["trusted_api", "user_input"]),
            tags: BTreeSet::new(),
            consumers: BTreeSet::new(),
        },
        ..InternalPolicyPreset::default()
    };

    let policy = parse_and_compile_with_preset("", preset);
    let checker = PolicyBranchChecker::new(Arc::new(policy));

    // Producers are a subset of the allow list → passes
    let ok_meta = meta(&["trusted_api"], ConsumerSet::Universal, &[]);
    assert!(
        security_compass_vm::BranchChecker::check(&checker, &ok_meta).is_ok()
    );
}

#[test]
fn branch_checker_allow_mode_blocks_non_subset() {
    use sqrt_eval::{BranchingMetaPolicy, BranchingMode};

    let preset = InternalPolicyPreset {
        branching_meta_policy: BranchingMetaPolicy {
            mode: BranchingMode::Allow,
            producers: str_set(&["trusted_api"]),
            tags: BTreeSet::new(),
            consumers: BTreeSet::new(),
        },
        ..InternalPolicyPreset::default()
    };

    let policy = parse_and_compile_with_preset("", preset);
    let checker = PolicyBranchChecker::new(Arc::new(policy));

    // Producers NOT a subset of the allow list → blocked
    let bad_meta = meta(&["untrusted_tool"], ConsumerSet::Universal, &[]);
    assert!(
        security_compass_vm::BranchChecker::check(&checker, &bad_meta).is_err()
    );
}

#[test]
fn branch_checker_error_message_format() {
    use sqrt_eval::{BranchingMetaPolicy, BranchingMode};

    let preset = InternalPolicyPreset {
        branching_meta_policy: BranchingMetaPolicy {
            mode: BranchingMode::Deny,
            producers: str_set(&["evil_tool"]),
            tags: BTreeSet::new(),
            consumers: BTreeSet::new(),
        },
        ..InternalPolicyPreset::default()
    };

    let policy = parse_and_compile_with_preset("", preset);
    let checker = PolicyBranchChecker::new(Arc::new(policy));

    let tainted = meta(&["evil_tool"], ConsumerSet::Universal, &[]);
    let err = security_compass_vm::BranchChecker::check(&checker, &tainted).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("Branching denied"), "Error message: {msg}");
    assert!(msg.contains("evil_tool"), "Error message: {msg}");
}

// ============================================================
// Execution Tests
// ============================================================

#[test]
fn execute_simple_expression() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp
        .execute("x + 1", vec![input_var("x", serde_json::json!(41))], &[])
        .unwrap();

    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!(42));
        }
        other => panic!("Expected Complete, got {other:?}"),
    }
}

#[test]
fn execute_string_expression() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp
        .execute(
            "greeting + ' ' + name",
            vec![
                input_var("greeting", serde_json::json!("hello")),
                input_var("name", serde_json::json!("world")),
            ],
            &[],
        )
        .unwrap();

    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!("hello world"));
        }
        other => panic!("Expected Complete, got {other:?}"),
    }
}

#[test]
fn execute_tool_call_yields_needs_tool_call() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("get_data", &["query"])];
    let result = interp
        .execute(
            "result = get_data('test')\nresult",
            vec![],
            &tools,
        )
        .unwrap();

    match result {
        ExecutionResult::NeedsToolCall {
            tool_name, args, ..
        } => {
            assert_eq!(tool_name, "get_data");
            assert_eq!(args.len(), 1);
            assert_eq!(args["query"].value, serde_json::json!("test"));
        }
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    }
}

#[test]
fn execute_tool_call_and_resume() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("get_data", &["query"])];
    let result = interp
        .execute(
            "result = get_data('test')\nresult",
            vec![],
            &tools,
        )
        .unwrap();

    match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            ..
        } => {
            let tool_result = serde_json::json!({"data": "found"});
            let result_meta = Metadata::default_for_tool_result("get_data", true);

            let resumed = interp
                .resume_after_tool_call(
                    state,
                    "get_data",
                    tool_result.clone(),
                    result_meta,
                    &result_updates,
                    &session_after_updates,
                )
                .unwrap();

            match resumed {
                ExecutionResult::Complete { value, .. } => {
                    assert_eq!(value, tool_result);
                }
                other => panic!("Expected Complete after resume, got {other:?}"),
            }
        }
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    }
}

#[test]
fn execute_multiple_sequential_tool_calls() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("fetch", &["url"])];
    let code = r#"
a = fetch("url1")
b = fetch("url2")
[a, b]
"#;

    // First tool call
    let result = interp.execute(code, vec![], &tools).unwrap();
    let (state, result_updates, session_after_updates) = match result {
        ExecutionResult::NeedsToolCall {
            tool_name,
            state,
            result_updates,
            session_after_updates,
            ..
        } => {
            assert_eq!(tool_name, "fetch");
            (state, result_updates, session_after_updates)
        }
        other => panic!("Expected first NeedsToolCall, got {other:?}"),
    };

    let result_meta = Metadata::default_for_tool_result("fetch", true);
    let resumed = interp
        .resume_after_tool_call(
            state,
            "fetch",
            serde_json::json!("result1"),
            result_meta,
            &result_updates,
            &session_after_updates,
        )
        .unwrap();

    // Second tool call
    let (state2, result_updates2, session_after_updates2) = match resumed {
        ExecutionResult::NeedsToolCall {
            tool_name,
            state,
            result_updates,
            session_after_updates,
            ..
        } => {
            assert_eq!(tool_name, "fetch");
            (state, result_updates, session_after_updates)
        }
        other => panic!("Expected second NeedsToolCall, got {other:?}"),
    };

    let result_meta2 = Metadata::default_for_tool_result("fetch", true);
    let final_result = interp
        .resume_after_tool_call(
            state2,
            "fetch",
            serde_json::json!("result2"),
            result_meta2,
            &result_updates2,
            &session_after_updates2,
        )
        .unwrap();

    match final_result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!(["result1", "result2"]));
        }
        other => panic!("Expected Complete after two tool calls, got {other:?}"),
    }
}

#[test]
fn execute_parse_with_ai_yields() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let code = r#"
result = parse_with_ai(data, "extract name", {})
result
"#;
    let result = interp
        .execute(
            code,
            vec![input_var("data", serde_json::json!("John Smith is an engineer"))],
            &[],
        )
        .unwrap();

    match result {
        ExecutionResult::NeedsParseWithAi { query, data, .. } => {
            assert_eq!(query, "extract name");
            assert_eq!(data.value, serde_json::json!("John Smith is an engineer"));
        }
        other => panic!("Expected NeedsParseWithAi, got {other:?}"),
    }
}

#[test]
fn execute_parse_with_ai_resume() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let code = r#"
result = parse_with_ai(data, "extract name", {})
result
"#;
    let result = interp
        .execute(
            code,
            vec![input_var("data", serde_json::json!("John"))],
            &[],
        )
        .unwrap();

    match result {
        ExecutionResult::NeedsParseWithAi { state, data, .. } => {
            let parsed = serde_json::json!({"name": "John"});
            let resumed = interp
                .resume_after_parse_with_ai(state, &data.meta, parsed.clone())
                .unwrap();

            match resumed {
                ExecutionResult::Complete { value, meta, .. } => {
                    assert_eq!(value, parsed);
                    // Should have parse_with_ai tag
                    assert!(meta.is_parse_with_ai());
                }
                other => panic!("Expected Complete, got {other:?}"),
            }
        }
        other => panic!("Expected NeedsParseWithAi, got {other:?}"),
    }
}

#[test]
fn execute_verify_hypothesis_yields() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let code = r#"
result = verify_hypothesis("is positive", data)
result
"#;
    let result = interp
        .execute(
            code,
            vec![input_var("data", serde_json::json!(42))],
            &[],
        )
        .unwrap();

    match result {
        ExecutionResult::NeedsVerifyHypothesis { hypothesis, data, .. } => {
            assert_eq!(hypothesis, "is positive");
            assert_eq!(data.value, serde_json::json!(42));
        }
        other => panic!("Expected NeedsVerifyHypothesis, got {other:?}"),
    }
}

#[test]
fn execute_verify_hypothesis_resume() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let code = r#"
result = verify_hypothesis("is positive", data)
result
"#;
    let result = interp
        .execute(
            code,
            vec![input_var("data", serde_json::json!(42))],
            &[],
        )
        .unwrap();

    match result {
        ExecutionResult::NeedsVerifyHypothesis { state, data, .. } => {
            let resumed = interp
                .resume_after_verify_hypothesis(state, &data.meta, true)
                .unwrap();

            match resumed {
                ExecutionResult::Complete { value, .. } => {
                    assert_eq!(value, serde_json::json!(true));
                }
                other => panic!("Expected Complete, got {other:?}"),
            }
        }
        other => panic!("Expected NeedsVerifyHypothesis, got {other:?}"),
    }
}

#[test]
fn execute_print_output_captured() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp
        .execute("print('hello from vm')", vec![], &[])
        .unwrap();

    match result {
        ExecutionResult::Complete { print_output, .. } => {
            assert_eq!(print_output.trim(), "hello from vm");
        }
        other => panic!("Expected Complete, got {other:?}"),
    }
}

#[test]
fn execute_gas_limit_exceeded() {
    let policy = parse_and_compile("");
    let config = InterpreterConfig {
        gas_limit: 1,
        ..default_config()
    };
    let mut interp = Interpreter::new(policy, config);

    let tools = vec![simple_tool("fetch", &["url"])];
    let code = r#"
a = fetch("url1")
b = fetch("url2")
[a, b]
"#;

    // First tool call should succeed
    let result = interp.execute(code, vec![], &tools).unwrap();
    let (state, result_updates, session_after_updates) = match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            ..
        } => (state, result_updates, session_after_updates),
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    };

    // Resume and expect gas exhaustion on second tool call
    let result_meta = Metadata::default_for_tool_result("fetch", true);
    let err = interp
        .resume_after_tool_call(
            state,
            "fetch",
            serde_json::json!("r1"),
            result_meta,
            &result_updates,
            &session_after_updates,
        )
        .unwrap_err();

    assert!(matches!(err, InterpreterError::GasExhausted { .. }));
}

#[test]
fn execute_tool_call_limit_exceeded() {
    let policy = parse_and_compile("");
    let config = InterpreterConfig {
        max_tool_calls_per_attempt: 1,
        ..default_config()
    };
    let mut interp = Interpreter::new(policy, config);

    let tools = vec![simple_tool("fetch", &["url"])];
    let code = r#"
a = fetch("url1")
b = fetch("url2")
[a, b]
"#;

    // First tool call should succeed
    let result = interp.execute(code, vec![], &tools).unwrap();
    let (state, result_updates, session_after_updates) = match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            ..
        } => (state, result_updates, session_after_updates),
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    };

    // Resume — second tool call should hit the limit
    let result_meta = Metadata::default_for_tool_result("fetch", true);
    let err = interp
        .resume_after_tool_call(
            state,
            "fetch",
            serde_json::json!("r1"),
            result_meta,
            &result_updates,
            &session_after_updates,
        )
        .unwrap_err();

    assert!(matches!(err, InterpreterError::ToolCallLimitExceeded { .. }));
}

// ============================================================
// Policy Integration Tests
// ============================================================

#[test]
fn policy_must_deny_blocks_tool_call() {
    let src = r#"
        tool "send_email" {
            must deny always;
        }
    "#;
    let policy = parse_and_compile(src);
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("send_email", &["to", "body"])];
    // The code calls send_email but the policy denies it.
    // The VM should get a RuntimeError exception. Since it's not caught, it propagates.
    let code = "send_email('alice@example.com', 'hello')";

    let result = interp.execute(code, vec![], &tools);
    // Should be a VmError since the denied tool raises a RuntimeError
    assert!(result.is_err());
}

#[test]
fn policy_must_allow_permits_tool_call() {
    let src = r#"
        tool "get_data" {
            must allow always;
        }
    "#;
    let policy = parse_and_compile(src);
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("get_data", &["query"])];
    let result = interp
        .execute("get_data('test')", vec![], &tools)
        .unwrap();

    match result {
        ExecutionResult::NeedsToolCall { tool_name, .. } => {
            assert_eq!(tool_name, "get_data");
        }
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    }
}

#[test]
fn policy_denied_tool_caught_by_try_except() {
    let src = r#"
        tool "send_email" {
            must deny always;
        }
    "#;
    let policy = parse_and_compile(src);
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("send_email", &["to"])];
    let code = r#"
try:
    send_email("alice")
except:
    result = "denied"
result
"#;
    let result = interp.execute(code, vec![], &tools).unwrap();
    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!("denied"));
        }
        other => panic!("Expected Complete with 'denied', got {other:?}"),
    }
}

#[test]
fn policy_default_deny_blocks_unknown_tools() {
    let preset = InternalPolicyPreset {
        default_allow: false,
        ..InternalPolicyPreset::default()
    };
    let policy = parse_and_compile_with_preset("", preset);
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("unknown_tool", &["arg"])];
    let code = r#"
try:
    unknown_tool("test")
except:
    result = "blocked"
result
"#;
    let result = interp.execute(code, vec![], &tools).unwrap();
    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!("blocked"));
        }
        other => panic!("Expected Complete with 'blocked', got {other:?}"),
    }
}

#[test]
fn policy_non_executable_tag_added_to_tool_result() {
    let policy = parse_and_compile(""); // Default preset has enable_non_executable_memory = true
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("get_data", &["query"])];
    let result = interp
        .execute("get_data('test')", vec![], &tools)
        .unwrap();

    match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            ..
        } => {
            // Create result meta WITHOUT non_executable (it should be added by resume)
            let result_meta = Metadata::default_for_tool_result("get_data", false);

            let resumed = interp
                .resume_after_tool_call(
                    state,
                    "get_data",
                    serde_json::json!("result"),
                    result_meta,
                    &result_updates,
                    &session_after_updates,
                )
                .unwrap();

            match resumed {
                ExecutionResult::Complete { meta, .. } => {
                    // The non_executable tag should have been added by the interpreter
                    assert!(meta.is_non_executable());
                }
                other => panic!("Expected Complete, got {other:?}"),
            }
        }
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    }
}

#[test]
fn policy_input_metadata_propagates_to_tool_args() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("process", &["data"])];
    let input_meta = meta(&["external_api"], ConsumerSet::Universal, &["user_data"]);

    let result = interp
        .execute(
            "process(data)",
            vec![input_var_with_meta("data", serde_json::json!("sensitive"), input_meta.clone())],
            &tools,
        )
        .unwrap();

    match result {
        ExecutionResult::NeedsToolCall { args, .. } => {
            let data_arg = args.get("data").expect("missing 'data' arg");
            // The metadata from the input should propagate through
            assert_eq!(data_arg.meta.producers, input_meta.producers);
            assert_eq!(data_arg.meta.tags, input_meta.tags);
        }
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    }
}

#[test]
fn policy_session_meta_persists_across_executions() {
    let src = r#"
        tool "set_session" {
            must allow always;
            session after {
                @tags |= {"session_active"};
            }
        }
    "#;
    let policy = parse_and_compile(src);
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("set_session", &[])];

    // First execution: tool call
    let result = interp.execute("set_session()", vec![], &tools).unwrap();
    let (state, result_updates, session_after_updates) = match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            ..
        } => (state, result_updates, session_after_updates),
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    };

    let result_meta = Metadata::default_for_tool_result("set_session", true);
    interp
        .resume_after_tool_call(
            state,
            "set_session",
            serde_json::json!(null),
            result_meta,
            &result_updates,
            &session_after_updates,
        )
        .unwrap();

    // Session meta should now have the tag
    assert!(
        interp.session_meta().tags.contains("session_active"),
        "Session meta should contain 'session_active' tag"
    );
}

#[test]
fn clear_session_meta_resets_state() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    // Manually set session meta to verify clear works
    interp.session_meta.tags.insert("test_tag".to_string());
    assert!(interp.session_meta().tags.contains("test_tag"));

    interp.clear_session_meta();
    assert!(interp.session_meta().tags.is_empty());
}

// ============================================================
// Edge Case Tests
// ============================================================

#[test]
fn edge_empty_program_returns_none() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp.execute("None", vec![], &[]).unwrap();
    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::Value::Null);
        }
        other => panic!("Expected Complete(Null), got {other:?}"),
    }
}

#[test]
fn edge_division_by_zero_returns_vm_error() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp.execute("1 / 0", vec![], &[]);
    assert!(result.is_err());
    match result.unwrap_err() {
        InterpreterError::VmError(exc) => {
            let msg = format!("{exc}");
            assert!(msg.contains("ZeroDivisionError") || msg.contains("division"), "Error: {msg}");
        }
        other => panic!("Expected VmError, got {other:?}"),
    }
}

#[test]
fn edge_syntax_error_returns_vm_error() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp.execute("if if if", vec![], &[]);
    assert!(result.is_err());
}

#[test]
fn edge_unknown_tool_in_code_returns_error() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    // Tool not registered in tool definitions
    let result = interp.execute("missing_tool('x')", vec![], &[]);
    // This should fail at VM level since missing_tool isn't registered as external function
    assert!(result.is_err());
}

#[test]
fn edge_tool_call_history_recorded() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("my_tool", &["arg"])];
    let result = interp
        .execute("my_tool('test')", vec![], &tools)
        .unwrap();

    match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            ..
        } => {
            let result_meta = Metadata::default_for_tool_result("my_tool", true);
            interp
                .resume_after_tool_call(
                    state,
                    "my_tool",
                    serde_json::json!("done"),
                    result_meta,
                    &result_updates,
                    &session_after_updates,
                )
                .unwrap();

            assert_eq!(interp.tool_call_history().len(), 1);
            assert_eq!(interp.tool_call_history()[0].tool_name, "my_tool");
            assert!(matches!(
                interp.tool_call_history()[0].outcome,
                crate::types::ToolCallOutcome::Executed
            ));
        }
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    }
}

#[test]
fn edge_multiple_inputs_with_metadata() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let inputs = vec![
        input_var_with_meta("a", serde_json::json!(10), meta(&["api"], ConsumerSet::Universal, &[])),
        input_var_with_meta("b", serde_json::json!(20), meta(&["user"], ConsumerSet::Universal, &[])),
    ];

    let result = interp.execute("a + b", inputs, &[]).unwrap();
    match result {
        ExecutionResult::Complete { value, meta: result_meta, .. } => {
            assert_eq!(value, serde_json::json!(30));
            // Metadata should be merged from both inputs (producers = union)
            assert!(result_meta.producers.contains("api"));
            assert!(result_meta.producers.contains("user"));
        }
        other => panic!("Expected Complete, got {other:?}"),
    }
}

#[test]
fn edge_list_comprehension_works() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp
        .execute("[x * 2 for x in [1, 2, 3]]", vec![], &[])
        .unwrap();

    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!([2, 4, 6]));
        }
        other => panic!("Expected Complete, got {other:?}"),
    }
}

#[test]
fn edge_conditional_expression() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let result = interp
        .execute(
            "'yes' if x > 0 else 'no'",
            vec![input_var("x", serde_json::json!(5))],
            &[],
        )
        .unwrap();

    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!("yes"));
        }
        other => panic!("Expected Complete, got {other:?}"),
    }
}

#[test]
fn edge_for_loop_with_tool_call() {
    let policy = parse_and_compile("");
    let mut interp = Interpreter::new(policy, default_config());

    let tools = vec![simple_tool("process", &["item"])];
    let code = r#"
results = []
for item in items:
    r = process(item)
    results.append(r)
results
"#;
    let result = interp
        .execute(
            code,
            vec![input_var("items", serde_json::json!([1, 2]))],
            &tools,
        )
        .unwrap();

    // First iteration tool call
    let (state, updates, session_updates) = match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            args,
            ..
        } => {
            assert_eq!(args["item"].value, serde_json::json!(1));
            (state, result_updates, session_after_updates)
        }
        other => panic!("Expected NeedsToolCall for first item, got {other:?}"),
    };

    let meta1 = Metadata::default_for_tool_result("process", true);
    let result = interp
        .resume_after_tool_call(state, "process", serde_json::json!("r1"), meta1, &updates, &session_updates)
        .unwrap();

    // Second iteration tool call
    let (state2, updates2, session_updates2) = match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            args,
            ..
        } => {
            assert_eq!(args["item"].value, serde_json::json!(2));
            (state, result_updates, session_after_updates)
        }
        other => panic!("Expected NeedsToolCall for second item, got {other:?}"),
    };

    let meta2 = Metadata::default_for_tool_result("process", true);
    let result = interp
        .resume_after_tool_call(state2, "process", serde_json::json!("r2"), meta2, &updates2, &session_updates2)
        .unwrap();

    match result {
        ExecutionResult::Complete { value, .. } => {
            assert_eq!(value, serde_json::json!(["r1", "r2"]));
        }
        other => panic!("Expected Complete, got {other:?}"),
    }
}

#[test]
fn edge_deterministic_tool_cache_hit() {
    use crate::types::CacheMode;

    let policy = parse_and_compile("");
    let config = InterpreterConfig {
        cache_tool_result: CacheMode::DeterministicOnly,
        ..default_config()
    };
    let mut interp = Interpreter::new(policy, config);

    let tools = vec![deterministic_tool("lookup", &["key"])];
    // Two identical calls to the same deterministic tool
    let code = r#"
a = lookup("x")
b = lookup("x")
[a, b]
"#;

    // First call: yields NeedsToolCall
    let result = interp.execute(code, vec![], &tools).unwrap();
    let (state, result_updates, session_after_updates, args) = match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            args,
            ..
        } => (state, result_updates, session_after_updates, args),
        other => panic!("Expected NeedsToolCall, got {other:?}"),
    };

    // Resume with cache support
    let result_meta = Metadata::default_for_tool_result("lookup", true);
    let result = interp
        .resume_after_tool_call_with_cache(
            state,
            "lookup",
            serde_json::json!("cached_value"),
            result_meta,
            &result_updates,
            &session_after_updates,
            &args,
        )
        .unwrap();

    // Second call should hit cache and complete directly (no NeedsToolCall yield)
    match result {
        ExecutionResult::Complete { value, .. } => {
            // Both calls should return the cached value
            assert_eq!(value, serde_json::json!(["cached_value", "cached_value"]));
        }
        other => panic!("Expected Complete (cache hit for second call), got {other:?}"),
    }
}

#[test]
fn edge_non_deterministic_tool_not_cached() {
    use crate::types::CacheMode;

    let policy = parse_and_compile("");
    let config = InterpreterConfig {
        cache_tool_result: CacheMode::DeterministicOnly,
        ..default_config()
    };
    let mut interp = Interpreter::new(policy, config);

    // Non-deterministic tool should NOT be cached
    let tools = vec![simple_tool("random_fetch", &["key"])];
    let code = r#"
a = random_fetch("x")
b = random_fetch("x")
[a, b]
"#;

    // First call
    let result = interp.execute(code, vec![], &tools).unwrap();
    let (state, result_updates, session_after_updates, args) = match result {
        ExecutionResult::NeedsToolCall {
            state,
            result_updates,
            session_after_updates,
            args,
            ..
        } => (state, result_updates, session_after_updates, args),
        other => panic!("Expected first NeedsToolCall, got {other:?}"),
    };

    let result_meta = Metadata::default_for_tool_result("random_fetch", true);
    let result = interp
        .resume_after_tool_call_with_cache(
            state,
            "random_fetch",
            serde_json::json!("r1"),
            result_meta,
            &result_updates,
            &session_after_updates,
            &args,
        )
        .unwrap();

    // Second call: should NOT be cached (non-deterministic tool)
    match result {
        ExecutionResult::NeedsToolCall { tool_name, .. } => {
            assert_eq!(tool_name, "random_fetch");
        }
        other => panic!("Expected second NeedsToolCall (no cache), got {other:?}"),
    }
}
