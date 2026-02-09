//! Comprehensive tests for the SQRT policy evaluation engine.
//!
//! Tests are organized by module:
//! - Compiler tests
//! - Value matching tests
//! - Set evaluation tests
//! - Predicate evaluation tests
//! - Metadata update tests
//! - Evaluator tests (full integration)
//! - Branching meta-policy tests
//! - Integration tests (end-to-end from SQRT source)

use std::collections::{BTreeSet, HashMap};

use indexmap::IndexMap;
use serde_json::json;

use security_compass_meta::{ConsumerSet, Metadata, ValueWithMeta};
use sqrt_parser::{
    self, AggregationOp, Comparison, Enforcement, LiteralValue, MetaFieldKind, MetaUpdateOp,
    MetadataStmt, MetadataTarget, MetadataUpdate, NumberValue, Predicate, RangeSpec, SetElement,
    SetExpr, SetOperand, StringPattern, TypeDomain, ValueOperand,
};

use crate::compiler::compile;
use crate::context::EvalContext;
use crate::error::{CompileError, EvalError};
use crate::evaluator::{check_branch, evaluate};
use crate::metadata_update::{apply_update, apply_updates, resolve_metadata_stmts};
use crate::predicate_eval::eval_predicate;
use crate::set_eval::eval_set_expr;
use crate::types::{
    BranchingMetaPolicy, BranchingMode, CompiledPolicy, InternalPolicyPreset,
    PolicyDecision, ResolvedLetValue, ResolvedUpdate, SetExprResolved, ToolCallContext,
};
use crate::value_match::{matches_set_element, matches_type_domain};

// ============================================================
// Test Helpers
// ============================================================

fn str_set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn finite(items: &[&str]) -> ConsumerSet {
    ConsumerSet::Finite(str_set(items))
}

fn meta(p: &[&str], c: ConsumerSet, t: &[&str]) -> Metadata {
    Metadata {
        producers: str_set(p),
        consumers: c,
        tags: str_set(t),
    }
}

fn value_with_meta(val: serde_json::Value, m: Metadata) -> ValueWithMeta<serde_json::Value> {
    ValueWithMeta { value: val, meta: m }
}

/// Build a simple ToolCallContext for testing.
fn make_ctx<'a>(
    tool_name: &'a str,
    args: &'a IndexMap<String, ValueWithMeta<serde_json::Value>>,
    session_meta: &'a Metadata,
) -> ToolCallContext<'a> {
    ToolCallContext {
        tool_name,
        args,
        result_meta: None,
        session_meta,
    }
}

/// Build an EvalContext for unit testing internal functions.
fn make_eval_ctx<'a>(
    ctx: &'a ToolCallContext<'a>,
    variables: &'a HashMap<String, ResolvedLetValue>,
) -> EvalContext<'a> {
    EvalContext { ctx, variables }
}

/// Helper to parse SQRT source and compile to CompiledPolicy.
fn parse_and_compile(src: &str) -> CompiledPolicy {
    parse_and_compile_with_preset(src, InternalPolicyPreset::default())
}

fn parse_and_compile_with_preset(src: &str, preset: InternalPolicyPreset) -> CompiledPolicy {
    let program = sqrt_parser::parse(src).expect("Parse failed");
    compile(&program, preset).expect("Compile failed")
}

// ============================================================
// Compiler Tests
// ============================================================

#[test]
fn test_compile_empty_program() {
    let program = sqrt_parser::parse("").unwrap();
    let policy = compile(&program, InternalPolicyPreset::default()).unwrap();
    assert!(policy.variables.is_empty());
    assert!(policy.exact_policies.is_empty());
    assert!(policy.regex_policies.is_empty());
}

#[test]
fn test_compile_let_static_set() {
    let policy = parse_and_compile(r#"let sensitive = {"confidential", "secret"};"#);
    match policy.variables.get("sensitive").unwrap() {
        ResolvedLetValue::Set(SetExprResolved::Static(s)) => {
            assert_eq!(*s, str_set(&["confidential", "secret"]));
        }
        other => panic!("Expected static set, got {other:?}"),
    }
}

#[test]
fn test_compile_let_empty_set() {
    let policy = parse_and_compile("let empty_set = {};");
    match policy.variables.get("empty_set").unwrap() {
        ResolvedLetValue::Set(SetExprResolved::Static(s)) => {
            assert!(s.is_empty());
        }
        other => panic!("Expected static empty set, got {other:?}"),
    }
}

#[test]
fn test_compile_let_dynamic_set() {
    let src = r#"let combined = @session.tags | {"extra"};"#;
    let policy = parse_and_compile(src);
    match policy.variables.get("combined").unwrap() {
        ResolvedLetValue::Set(SetExprResolved::Dynamic(_)) => {} // Expected
        other => panic!("Expected dynamic set, got {other:?}"),
    }
}

#[test]
fn test_compile_let_predicate() {
    let src = r#"let is_safe = msg.tags overlaps {"safe"};"#;
    let policy = parse_and_compile(src);
    match policy.variables.get("is_safe").unwrap() {
        ResolvedLetValue::Predicate(_) => {} // Expected
        other => panic!("Expected predicate, got {other:?}"),
    }
}

#[test]
fn test_compile_duplicate_variable_error() {
    let src = r#"
        let x = {"a"};
        let x = {"b"};
    "#;
    let program = sqrt_parser::parse(src).unwrap();
    let result = compile(&program, InternalPolicyPreset::default());
    assert!(matches!(result, Err(CompileError::DuplicateVariable { .. })));
}

#[test]
fn test_compile_exact_tool() {
    let src = r#"
        tool "send_email" {
            must deny when msg.tags overlaps {"confidential"};
        }
    "#;
    let policy = parse_and_compile(src);
    assert!(policy.exact_policies.contains_key("send_email"));
    assert_eq!(policy.exact_policies["send_email"].len(), 1);
    assert_eq!(policy.exact_policies["send_email"][0].checks.len(), 1);
}

#[test]
fn test_compile_regex_tool() {
    let src = r#"
        tool r".*_pii$" {
            must deny always;
        }
    "#;
    let policy = parse_and_compile(src);
    assert!(policy.exact_policies.is_empty());
    assert_eq!(policy.regex_policies.len(), 1);
    assert!(policy.regex_policies[0].0.is_match("get_pii"));
    assert!(!policy.regex_policies[0].0.is_match("get_data"));
}

#[test]
fn test_compile_invalid_regex_error() {
    let src = r#"
        tool r"[invalid" {
            must deny always;
        }
    "#;
    let program = sqrt_parser::parse(src).unwrap();
    let result = compile(&program, InternalPolicyPreset::default());
    assert!(matches!(result, Err(CompileError::InvalidRegex { .. })));
}

#[test]
fn test_compile_tool_with_priority() {
    let src = r#"
        tool "send_email" {
            priority 10;
            should allow always;
        }
    "#;
    let policy = parse_and_compile(src);
    assert_eq!(policy.exact_policies["send_email"][0].priority, 10);
}

#[test]
fn test_compile_tool_with_result_block() {
    let src = r#"
        tool "get_data" {
            should allow always;
            result {
                @tags |= {"fetched"};
            }
        }
    "#;
    let policy = parse_and_compile(src);
    let tool = &policy.exact_policies["get_data"][0];
    assert_eq!(tool.result_stmts.len(), 1);
}

#[test]
fn test_compile_tool_with_session_blocks() {
    let src = r#"
        tool "process" {
            should allow always;
            session before {
                @session.tags |= {"processing"};
            }
            session after {
                @session.tags -= {"processing"};
            }
        }
    "#;
    let policy = parse_and_compile(src);
    let tool = &policy.exact_policies["process"][0];
    assert_eq!(tool.session_before_stmts.len(), 1);
    assert_eq!(tool.session_after_stmts.len(), 1);
}

#[test]
fn test_compile_shorthand_result() {
    let src = r#"tool "get_data" -> result @tags |= {"fetched"};"#;
    let policy = parse_and_compile(src);
    let tool = &policy.exact_policies["get_data"][0];
    assert!(tool.checks.is_empty());
    assert_eq!(tool.result_stmts.len(), 1);
    assert!(tool.session_before_stmts.is_empty());
    assert!(tool.session_after_stmts.is_empty());
}

#[test]
fn test_compile_shorthand_session_before() {
    let src = r#"tool "process" -> session before @tags |= {"active"};"#;
    let policy = parse_and_compile(src);
    let tool = &policy.exact_policies["process"][0];
    assert_eq!(tool.session_before_stmts.len(), 1);
}

#[test]
fn test_compile_shorthand_session_after() {
    let src = r#"tool "process" -> session after @tags -= {"active"};"#;
    let policy = parse_and_compile(src);
    let tool = &policy.exact_policies["process"][0];
    assert_eq!(tool.session_after_stmts.len(), 1);
}

#[test]
fn test_compile_shorthand_with_condition() {
    let src = r#"tool "get_data" -> result @tags |= {"external"} when data.tags overlaps {"untrusted"};"#;
    let policy = parse_and_compile(src);
    let tool = &policy.exact_policies["get_data"][0];
    assert_eq!(tool.result_stmts.len(), 1);
    // The statement should be a Conditional
    match &tool.result_stmts[0] {
        MetadataStmt::Conditional { .. } => {} // Expected
        other => panic!("Expected conditional, got {other:?}"),
    }
}

#[test]
fn test_compile_multiple_tools_same_name() {
    let src = r#"
        tool "send_email" {
            should deny when msg.tags overlaps {"spam"};
        }
        tool "send_email" {
            priority 10;
            must allow always;
        }
    "#;
    let policy = parse_and_compile(src);
    assert_eq!(policy.exact_policies["send_email"].len(), 2);
}

// ============================================================
// Value Matching Tests
// ============================================================

#[test]
fn test_match_bool_true() {
    let val = json!(true);
    assert!(matches_type_domain(&val, &TypeDomain::Bool(true)).unwrap());
    assert!(!matches_type_domain(&val, &TypeDomain::Bool(false)).unwrap());
}

#[test]
fn test_match_bool_false() {
    let val = json!(false);
    assert!(matches_type_domain(&val, &TypeDomain::Bool(false)).unwrap());
    assert!(!matches_type_domain(&val, &TypeDomain::Bool(true)).unwrap());
}

#[test]
fn test_match_bool_non_bool() {
    let val = json!("true");
    assert!(!matches_type_domain(&val, &TypeDomain::Bool(true)).unwrap());
}

#[test]
fn test_match_int_exact() {
    let val = json!(42);
    assert!(matches_type_domain(&val, &TypeDomain::Int(RangeSpec::Exact(NumberValue::Int(42)))).unwrap());
    assert!(!matches_type_domain(&val, &TypeDomain::Int(RangeSpec::Exact(NumberValue::Int(43)))).unwrap());
}

#[test]
fn test_match_int_inclusive_range() {
    let val = json!(5);
    let td = TypeDomain::Int(RangeSpec::Inclusive {
        min: NumberValue::Int(1),
        max: NumberValue::Int(10),
    });
    assert!(matches_type_domain(&val, &td).unwrap());

    let val_out = json!(11);
    assert!(!matches_type_domain(&val_out, &td).unwrap());
}

#[test]
fn test_match_int_exclusive_range() {
    let td = TypeDomain::Int(RangeSpec::ExclusiveBoth {
        min: NumberValue::Int(0),
        max: NumberValue::Int(10),
    });
    // 0 and 10 should NOT match (exclusive)
    assert!(!matches_type_domain(&json!(0), &td).unwrap());
    assert!(!matches_type_domain(&json!(10), &td).unwrap());
    // 5 should match
    assert!(matches_type_domain(&json!(5), &td).unwrap());
}

#[test]
fn test_match_int_from_inf() {
    let td = TypeDomain::Int(RangeSpec::From(NumberValue::Int(0)));
    assert!(matches_type_domain(&json!(0), &td).unwrap());
    assert!(matches_type_domain(&json!(100), &td).unwrap());
    assert!(!matches_type_domain(&json!(-1), &td).unwrap());
}

#[test]
fn test_match_int_to_inf() {
    let td = TypeDomain::Int(RangeSpec::To(NumberValue::Int(100)));
    assert!(matches_type_domain(&json!(100), &td).unwrap());
    assert!(matches_type_domain(&json!(0), &td).unwrap());
    assert!(!matches_type_domain(&json!(101), &td).unwrap());
}

#[test]
fn test_match_int_non_number() {
    let val = json!("42");
    assert!(!matches_type_domain(&val, &TypeDomain::Int(RangeSpec::Exact(NumberValue::Int(42)))).unwrap());
}

#[test]
fn test_match_float_range() {
    let td = TypeDomain::Float(RangeSpec::Inclusive {
        min: NumberValue::Float(0.0),
        max: NumberValue::Float(1.0),
    });
    assert!(matches_type_domain(&json!(0.5), &td).unwrap());
    assert!(!matches_type_domain(&json!(1.5), &td).unwrap());
}

#[test]
fn test_match_str_exact() {
    let td = TypeDomain::Str {
        pattern: StringPattern::Exact("hello".to_string()),
        length: None,
    };
    assert!(matches_type_domain(&json!("hello"), &td).unwrap());
    assert!(!matches_type_domain(&json!("world"), &td).unwrap());
}

#[test]
fn test_match_str_regex() {
    let td = TypeDomain::Str {
        pattern: StringPattern::Matching(r"^[a-z]+@[a-z]+\.[a-z]+$".to_string()),
        length: None,
    };
    assert!(matches_type_domain(&json!("user@example.com"), &td).unwrap());
    assert!(!matches_type_domain(&json!("not-an-email"), &td).unwrap());
}

#[test]
fn test_match_str_wildcard() {
    let td = TypeDomain::Str {
        pattern: StringPattern::Like("*.txt".to_string()),
        length: None,
    };
    assert!(matches_type_domain(&json!("readme.txt"), &td).unwrap());
    assert!(!matches_type_domain(&json!("readme.md"), &td).unwrap());
}

#[test]
fn test_match_str_with_length() {
    let td = TypeDomain::Str {
        pattern: StringPattern::Matching(".*".to_string()),
        length: Some(RangeSpec::Inclusive {
            min: NumberValue::Int(3),
            max: NumberValue::Int(10),
        }),
    };
    assert!(matches_type_domain(&json!("hello"), &td).unwrap());
    assert!(!matches_type_domain(&json!("hi"), &td).unwrap());
    assert!(!matches_type_domain(&json!("this is too long for the constraint"), &td).unwrap());
}

#[test]
fn test_match_str_non_string() {
    let td = TypeDomain::Str {
        pattern: StringPattern::Exact("42".to_string()),
        length: None,
    };
    assert!(!matches_type_domain(&json!(42), &td).unwrap());
}

#[test]
fn test_match_set_element_string() {
    assert!(matches_set_element(&json!("hello"), &SetElement::String("hello".to_string())).unwrap());
    assert!(!matches_set_element(&json!("world"), &SetElement::String("hello".to_string())).unwrap());
}

#[test]
fn test_match_set_element_regex() {
    assert!(matches_set_element(&json!("abc123"), &SetElement::Regex(r"^[a-z]+\d+$".to_string())).unwrap());
    assert!(!matches_set_element(&json!("123abc"), &SetElement::Regex(r"^[a-z]+\d+$".to_string())).unwrap());
}

#[test]
fn test_match_set_element_wildcard() {
    assert!(matches_set_element(&json!("file.txt"), &SetElement::Wildcard("*.txt".to_string())).unwrap());
    assert!(!matches_set_element(&json!("file.md"), &SetElement::Wildcard("*.txt".to_string())).unwrap());
}

#[test]
fn test_match_set_element_number() {
    assert!(matches_set_element(&json!(42), &SetElement::Number(NumberValue::Int(42))).unwrap());
    assert!(!matches_set_element(&json!(43), &SetElement::Number(NumberValue::Int(42))).unwrap());
}

#[test]
fn test_match_set_element_type_domain() {
    let td = TypeDomain::Int(RangeSpec::Inclusive {
        min: NumberValue::Int(1),
        max: NumberValue::Int(100),
    });
    assert!(matches_set_element(&json!(50), &SetElement::TypeDomain(td.clone())).unwrap());
    assert!(!matches_set_element(&json!(200), &SetElement::TypeDomain(td)).unwrap());
}

// ============================================================
// Set Evaluation Tests
// ============================================================

#[test]
fn test_set_eval_literal() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Literal(vec![
        SetElement::String("a".to_string()),
        SetElement::String("b".to_string()),
    ]);
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["a", "b"]));
}

#[test]
fn test_set_eval_empty_literal() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Literal(vec![]);
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_set_eval_operand_arg_tags() {
    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("hello"), meta(&[], ConsumerSet::Universal, &["tagged"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Operand(SetOperand::ArgField {
        arg_name: "msg".to_string(),
        field: MetaFieldKind::Tags,
    });
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["tagged"]));
}

#[test]
fn test_set_eval_operand_session_producers() {
    let args = IndexMap::new();
    let session = meta(&["db", "api"], ConsumerSet::Universal, &[]);
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Operand(SetOperand::SessionField(MetaFieldKind::Producers));
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["api", "db"]));
}

#[test]
fn test_set_eval_operand_session_consumers() {
    let args = IndexMap::new();
    let session = meta(&[], finite(&["alice", "bob"]), &[]);
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Operand(SetOperand::SessionField(MetaFieldKind::Consumers));
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(result.as_consumer_set(), finite(&["alice", "bob"]));
}

#[test]
fn test_set_eval_union() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Union(
        Box::new(SetExpr::Literal(vec![SetElement::String("a".to_string())])),
        Box::new(SetExpr::Literal(vec![SetElement::String("b".to_string())])),
    );
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["a", "b"]));
}

#[test]
fn test_set_eval_intersect() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Intersect(
        Box::new(SetExpr::Literal(vec![
            SetElement::String("a".to_string()),
            SetElement::String("b".to_string()),
        ])),
        Box::new(SetExpr::Literal(vec![
            SetElement::String("b".to_string()),
            SetElement::String("c".to_string()),
        ])),
    );
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["b"]));
}

#[test]
fn test_set_eval_minus() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Minus(
        Box::new(SetExpr::Literal(vec![
            SetElement::String("a".to_string()),
            SetElement::String("b".to_string()),
            SetElement::String("c".to_string()),
        ])),
        Box::new(SetExpr::Literal(vec![SetElement::String("b".to_string())])),
    );
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["a", "c"]));
}

#[test]
fn test_set_eval_xor() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Xor(
        Box::new(SetExpr::Literal(vec![
            SetElement::String("a".to_string()),
            SetElement::String("b".to_string()),
        ])),
        Box::new(SetExpr::Literal(vec![
            SetElement::String("b".to_string()),
            SetElement::String("c".to_string()),
        ])),
    );
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["a", "c"]));
}

#[test]
fn test_set_eval_with() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::With(
        Box::new(SetExpr::Literal(vec![SetElement::String("a".to_string())])),
        SetElement::String("b".to_string()),
    );
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["a", "b"]));
}

#[test]
fn test_set_eval_without() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Without(
        Box::new(SetExpr::Literal(vec![
            SetElement::String("a".to_string()),
            SetElement::String("b".to_string()),
        ])),
        SetElement::String("b".to_string()),
    );
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["a"]));
}

#[test]
fn test_set_eval_ref_static() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let mut vars = HashMap::new();
    vars.insert(
        "my_set".to_string(),
        ResolvedLetValue::Set(SetExprResolved::Static(str_set(&["x", "y"]))),
    );
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Ref("my_set".to_string());
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["x", "y"]));
}

#[test]
fn test_set_eval_ref_undefined_error() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Ref("nonexistent".to_string());
    let result = eval_set_expr(&expr, &eval_ctx);
    assert!(matches!(result, Err(EvalError::UndefinedVariable { .. })));
}

#[test]
fn test_set_eval_aggregation_union() {
    let mut args = IndexMap::new();
    args.insert(
        "a".to_string(),
        value_with_meta(json!(1), meta(&[], ConsumerSet::Universal, &["t1"])),
    );
    args.insert(
        "b".to_string(),
        value_with_meta(json!(2), meta(&[], ConsumerSet::Universal, &["t2"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Operand(SetOperand::ArgsField {
        field: MetaFieldKind::Tags,
        agg: AggregationOp::Union,
    });
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["t1", "t2"]));
}

#[test]
fn test_set_eval_aggregation_intersect() {
    let mut args = IndexMap::new();
    args.insert(
        "a".to_string(),
        value_with_meta(json!(1), meta(&[], ConsumerSet::Universal, &["shared", "t1"])),
    );
    args.insert(
        "b".to_string(),
        value_with_meta(json!(2), meta(&[], ConsumerSet::Universal, &["shared", "t2"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let expr = SetExpr::Operand(SetOperand::ArgsField {
        field: MetaFieldKind::Tags,
        agg: AggregationOp::Intersect,
    });
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(*result.as_string_set(), str_set(&["shared"]));
}

#[test]
fn test_set_eval_consumer_interop() {
    let args = IndexMap::new();
    let session = meta(&[], finite(&["alice", "bob"]), &[]);
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    // Union session.consumers with a literal set
    let expr = SetExpr::Union(
        Box::new(SetExpr::Operand(SetOperand::SessionField(MetaFieldKind::Consumers))),
        Box::new(SetExpr::Literal(vec![SetElement::String("carol".to_string())])),
    );
    let result = eval_set_expr(&expr, &eval_ctx).unwrap();
    assert_eq!(result.as_consumer_set(), finite(&["alice", "bob", "carol"]));
}

// ============================================================
// Predicate Evaluation Tests
// ============================================================

#[test]
fn test_predicate_and_true() {
    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("hello"), meta(&[], ConsumerSet::Universal, &["a", "b"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let pred = Predicate::And(
        Box::new(Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::ArgField {
                arg_name: "msg".to_string(),
                field: MetaFieldKind::Tags,
            },
            right: SetExpr::Literal(vec![SetElement::String("a".to_string())]),
        })),
        Box::new(Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::ArgField {
                arg_name: "msg".to_string(),
                field: MetaFieldKind::Tags,
            },
            right: SetExpr::Literal(vec![SetElement::String("b".to_string())]),
        })),
    );
    assert!(eval_predicate(&pred, &eval_ctx).unwrap());
}

#[test]
fn test_predicate_and_short_circuit() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    // First operand is false (empty session tags don't overlap), second would error
    // Short-circuit means we should get Ok(false) without evaluating the second operand.
    let pred = Predicate::And(
        Box::new(Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::SessionField(MetaFieldKind::Tags),
            right: SetExpr::Literal(vec![SetElement::String("nonexistent".to_string())]),
        })),
        Box::new(Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::ArgField {
                arg_name: "no_such_arg".to_string(),
                field: MetaFieldKind::Tags,
            },
            right: SetExpr::Literal(vec![]),
        })),
    );
    assert!(!eval_predicate(&pred, &eval_ctx).unwrap());
}

#[test]
fn test_predicate_or_short_circuit() {
    let args = IndexMap::new();
    let session = meta(&[], ConsumerSet::Universal, &["present"]);
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    // First operand is true, second would error
    let pred = Predicate::Or(
        Box::new(Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::SessionField(MetaFieldKind::Tags),
            right: SetExpr::Literal(vec![SetElement::String("present".to_string())]),
        })),
        Box::new(Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::ArgField {
                arg_name: "no_such_arg".to_string(),
                field: MetaFieldKind::Tags,
            },
            right: SetExpr::Literal(vec![]),
        })),
    );
    assert!(eval_predicate(&pred, &eval_ctx).unwrap());
}

#[test]
fn test_predicate_not() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let pred = Predicate::Not(Box::new(Predicate::Comparison(
        Comparison::SetIsEmpty(SetOperand::SessionField(MetaFieldKind::Tags)),
    )));
    // Session tags are empty, so SetIsEmpty is true, Not(true) = false
    assert!(!eval_predicate(&pred, &eval_ctx).unwrap());
}

#[test]
fn test_predicate_ref() {
    let args = IndexMap::new();
    let session = meta(&[], ConsumerSet::Universal, &["flagged"]);
    let ctx = make_ctx("test", &args, &session);

    let mut vars = HashMap::new();
    vars.insert(
        "is_flagged".to_string(),
        ResolvedLetValue::Predicate(Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::SessionField(MetaFieldKind::Tags),
            right: SetExpr::Literal(vec![SetElement::String("flagged".to_string())]),
        })),
    );
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let pred = Predicate::Ref("is_flagged".to_string());
    assert!(eval_predicate(&pred, &eval_ctx).unwrap());
}

#[test]
fn test_comparison_value_in_literal_set() {
    let mut args = IndexMap::new();
    args.insert(
        "action".to_string(),
        value_with_meta(json!("delete"), Metadata::default()),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::ValueIn {
        operand: ValueOperand::ArgValue("action".to_string()),
        set: SetExpr::Literal(vec![
            SetElement::String("delete".to_string()),
            SetElement::String("drop".to_string()),
        ]),
    };
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_value_in_not_found() {
    let mut args = IndexMap::new();
    args.insert(
        "action".to_string(),
        value_with_meta(json!("read"), Metadata::default()),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::ValueIn {
        operand: ValueOperand::ArgValue("action".to_string()),
        set: SetExpr::Literal(vec![
            SetElement::String("delete".to_string()),
            SetElement::String("drop".to_string()),
        ]),
    };
    assert!(!eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_value_equals() {
    let mut args = IndexMap::new();
    args.insert(
        "amount".to_string(),
        value_with_meta(json!(100), Metadata::default()),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::ValueEquals {
        left: ValueOperand::ArgValue("amount".to_string()),
        right: ValueOperand::Literal(LiteralValue::Number(NumberValue::Int(100))),
    };
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_overlaps_true() {
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["sensitive", "internal"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetOverlaps {
        left: SetOperand::ArgField {
            arg_name: "data".to_string(),
            field: MetaFieldKind::Tags,
        },
        right: SetExpr::Literal(vec![SetElement::String("sensitive".to_string())]),
    };
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_overlaps_false() {
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["public"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetOverlaps {
        left: SetOperand::ArgField {
            arg_name: "data".to_string(),
            field: MetaFieldKind::Tags,
        },
        right: SetExpr::Literal(vec![SetElement::String("sensitive".to_string())]),
    };
    assert!(!eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_subset_of() {
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&["api"], ConsumerSet::Universal, &[])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetSubsetOf {
        left: SetOperand::ArgField {
            arg_name: "data".to_string(),
            field: MetaFieldKind::Producers,
        },
        right: SetExpr::Literal(vec![
            SetElement::String("api".to_string()),
            SetElement::String("db".to_string()),
        ]),
    };
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_superset_of() {
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&["api", "db", "cache"], ConsumerSet::Universal, &[])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetSupersetOf {
        left: SetOperand::ArgField {
            arg_name: "data".to_string(),
            field: MetaFieldKind::Producers,
        },
        right: SetExpr::Literal(vec![SetElement::String("api".to_string())]),
    };
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_equals() {
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["a", "b"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetEquals {
        left: SetOperand::ArgField {
            arg_name: "data".to_string(),
            field: MetaFieldKind::Tags,
        },
        right: SetExpr::Literal(vec![
            SetElement::String("a".to_string()),
            SetElement::String("b".to_string()),
        ]),
    };
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_is_empty() {
    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetIsEmpty(SetOperand::SessionField(MetaFieldKind::Tags));
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_is_universal() {
    let args = IndexMap::new();
    let session = Metadata::default(); // consumers are Universal by default
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetIsUniversal(SetOperand::SessionField(MetaFieldKind::Consumers));
    assert!(eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

#[test]
fn test_comparison_set_is_universal_false() {
    let args = IndexMap::new();
    let session = meta(&[], finite(&["alice"]), &[]);
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let comp = Comparison::SetIsUniversal(SetOperand::SessionField(MetaFieldKind::Consumers));
    assert!(!eval_predicate(&Predicate::Comparison(comp), &eval_ctx).unwrap());
}

// ============================================================
// Metadata Update Tests
// ============================================================

#[test]
fn test_apply_tags_assign() {
    let mut m = Metadata::default();
    let update = ResolvedUpdate {
        field: MetaFieldKind::Tags,
        op: MetaUpdateOp::Assign,
        string_set: str_set(&["new_tag"]),
        consumer_set: ConsumerSet::Universal,
    };
    apply_update(&mut m, &update);
    assert_eq!(m.tags, str_set(&["new_tag"]));
}

#[test]
fn test_apply_tags_union_assign() {
    let mut m = meta(&[], ConsumerSet::Universal, &["existing"]);
    let update = ResolvedUpdate {
        field: MetaFieldKind::Tags,
        op: MetaUpdateOp::UnionAssign,
        string_set: str_set(&["new"]),
        consumer_set: ConsumerSet::Universal,
    };
    apply_update(&mut m, &update);
    assert_eq!(m.tags, str_set(&["existing", "new"]));
}

#[test]
fn test_apply_tags_intersect_assign() {
    let mut m = meta(&[], ConsumerSet::Universal, &["a", "b", "c"]);
    let update = ResolvedUpdate {
        field: MetaFieldKind::Tags,
        op: MetaUpdateOp::IntersectAssign,
        string_set: str_set(&["b", "c", "d"]),
        consumer_set: ConsumerSet::Universal,
    };
    apply_update(&mut m, &update);
    assert_eq!(m.tags, str_set(&["b", "c"]));
}

#[test]
fn test_apply_tags_minus_assign() {
    let mut m = meta(&[], ConsumerSet::Universal, &["a", "b", "c"]);
    let update = ResolvedUpdate {
        field: MetaFieldKind::Tags,
        op: MetaUpdateOp::MinusAssign,
        string_set: str_set(&["b"]),
        consumer_set: ConsumerSet::Universal,
    };
    apply_update(&mut m, &update);
    assert_eq!(m.tags, str_set(&["a", "c"]));
}

#[test]
fn test_apply_tags_xor_assign() {
    let mut m = meta(&[], ConsumerSet::Universal, &["a", "b"]);
    let update = ResolvedUpdate {
        field: MetaFieldKind::Tags,
        op: MetaUpdateOp::XorAssign,
        string_set: str_set(&["b", "c"]),
        consumer_set: ConsumerSet::Universal,
    };
    apply_update(&mut m, &update);
    assert_eq!(m.tags, str_set(&["a", "c"]));
}

#[test]
fn test_apply_producers_union_assign() {
    let mut m = meta(&["existing"], ConsumerSet::Universal, &[]);
    let update = ResolvedUpdate {
        field: MetaFieldKind::Producers,
        op: MetaUpdateOp::UnionAssign,
        string_set: str_set(&["new"]),
        consumer_set: ConsumerSet::Universal,
    };
    apply_update(&mut m, &update);
    assert_eq!(m.producers, str_set(&["existing", "new"]));
}

#[test]
fn test_apply_consumers_intersect_assign() {
    let mut m = meta(&[], finite(&["a", "b"]), &[]);
    let update = ResolvedUpdate {
        field: MetaFieldKind::Consumers,
        op: MetaUpdateOp::IntersectAssign,
        string_set: BTreeSet::new(), // not used for consumers
        consumer_set: finite(&["b", "c"]),
    };
    apply_update(&mut m, &update);
    assert_eq!(m.consumers, finite(&["b"]));
}

#[test]
fn test_apply_consumers_union_assign() {
    let mut m = meta(&[], finite(&["a"]), &[]);
    let update = ResolvedUpdate {
        field: MetaFieldKind::Consumers,
        op: MetaUpdateOp::UnionAssign,
        string_set: BTreeSet::new(),
        consumer_set: finite(&["b"]),
    };
    apply_update(&mut m, &update);
    assert_eq!(m.consumers, finite(&["a", "b"]));
}

#[test]
fn test_apply_multiple_updates() {
    let mut m = Metadata::default();
    let updates = vec![
        ResolvedUpdate {
            field: MetaFieldKind::Tags,
            op: MetaUpdateOp::UnionAssign,
            string_set: str_set(&["tag1"]),
            consumer_set: ConsumerSet::Universal,
        },
        ResolvedUpdate {
            field: MetaFieldKind::Producers,
            op: MetaUpdateOp::UnionAssign,
            string_set: str_set(&["prod1"]),
            consumer_set: ConsumerSet::Universal,
        },
        ResolvedUpdate {
            field: MetaFieldKind::Consumers,
            op: MetaUpdateOp::Assign,
            string_set: BTreeSet::new(),
            consumer_set: finite(&["admin"]),
        },
    ];
    apply_updates(&mut m, &updates);
    assert_eq!(m.tags, str_set(&["tag1"]));
    assert_eq!(m.producers, str_set(&["prod1"]));
    assert_eq!(m.consumers, finite(&["admin"]));
}

#[test]
fn test_resolve_conditional_true() {
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["sensitive"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let stmts = vec![MetadataStmt::Conditional {
        condition: Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::ArgField {
                arg_name: "data".to_string(),
                field: MetaFieldKind::Tags,
            },
            right: SetExpr::Literal(vec![SetElement::String("sensitive".to_string())]),
        }),
        updates: vec![MetadataUpdate {
            target: MetadataTarget::Result,
            field: MetaFieldKind::Tags,
            op: MetaUpdateOp::UnionAssign,
            value: SetExpr::Literal(vec![SetElement::String("flagged".to_string())]),
        }],
    }];

    let resolved = resolve_metadata_stmts(&stmts, &eval_ctx).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].string_set, str_set(&["flagged"]));
}

#[test]
fn test_resolve_conditional_false() {
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["public"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("test", &args, &session);
    let vars = HashMap::new();
    let eval_ctx = make_eval_ctx(&ctx, &vars);

    let stmts = vec![MetadataStmt::Conditional {
        condition: Predicate::Comparison(Comparison::SetOverlaps {
            left: SetOperand::ArgField {
                arg_name: "data".to_string(),
                field: MetaFieldKind::Tags,
            },
            right: SetExpr::Literal(vec![SetElement::String("sensitive".to_string())]),
        }),
        updates: vec![MetadataUpdate {
            target: MetadataTarget::Result,
            field: MetaFieldKind::Tags,
            op: MetaUpdateOp::UnionAssign,
            value: SetExpr::Literal(vec![SetElement::String("flagged".to_string())]),
        }],
    }];

    let resolved = resolve_metadata_stmts(&stmts, &eval_ctx).unwrap();
    assert!(resolved.is_empty());
}

// ============================================================
// Evaluator Tests (Full Integration)
// ============================================================

#[test]
fn test_evaluate_must_deny_immediate() {
    let policy = parse_and_compile(r#"
        tool "send_email" {
            must deny when msg.tags overlaps {"confidential"};
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("secret data"), meta(&[], ConsumerSet::Universal, &["confidential"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { enforcement: Enforcement::Must, .. }));
}

#[test]
fn test_evaluate_must_allow_immediate() {
    let policy = parse_and_compile(r#"
        tool "read_data" {
            must allow always;
        }
    "#);

    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("read_data", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Allow { .. }));
}

#[test]
fn test_evaluate_should_deny() {
    let policy = parse_and_compile(r#"
        tool "send_email" {
            should deny when msg.tags overlaps {"spam"};
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("spam message"), meta(&[], ConsumerSet::Universal, &["spam"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { enforcement: Enforcement::Should, .. }));
}

#[test]
fn test_evaluate_should_allow_overrides_should_deny() {
    // Higher-priority allow should override lower-priority deny
    let policy = parse_and_compile(r#"
        tool "send_email" {
            should deny when msg.tags overlaps {"suspicious"};
        }
        tool "send_email" {
            priority 10;
            should allow always;
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("msg"), meta(&[], ConsumerSet::Universal, &["suspicious"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Allow { .. }));
}

#[test]
fn test_evaluate_higher_priority_must_allow_preempts_must_deny() {
    // When must-allow has HIGHER priority than must-deny, it fires first.
    // This is the intended behavior: priority determines evaluation order,
    // and must-rules trigger immediate return.
    let policy = parse_and_compile(r#"
        tool "send_email" {
            must deny when msg.tags overlaps {"blocked"};
        }
        tool "send_email" {
            priority 100;
            must allow always;
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("msg"), meta(&[], ConsumerSet::Universal, &["blocked"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    // Priority 100 (must-allow) is evaluated before priority 0 (must-deny).
    // must-allow at priority 100 triggers immediate Allow return.
    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Allow { .. }));
}

#[test]
fn test_evaluate_must_deny_fires_at_higher_priority() {
    let policy = parse_and_compile(r#"
        tool "send_email" {
            priority 100;
            must deny when msg.tags overlaps {"blocked"};
        }
        tool "send_email" {
            must allow always;
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("msg"), meta(&[], ConsumerSet::Universal, &["blocked"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    // Must-deny at priority 100 fires first
    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { enforcement: Enforcement::Must, .. }));
}

#[test]
fn test_evaluate_no_matching_policy_default_allow() {
    let policy = parse_and_compile(r#"
        tool "other_tool" {
            must deny always;
        }
    "#);

    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Allow { .. }));
}

#[test]
fn test_evaluate_no_matching_policy_default_deny() {
    let preset = InternalPolicyPreset {
        default_allow: false,
        ..InternalPolicyPreset::default()
    };
    let policy = parse_and_compile_with_preset(
        r#"tool "other_tool" { must deny always; }"#,
        preset,
    );

    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { .. }));
}

#[test]
fn test_evaluate_fail_fast() {
    let policy = parse_and_compile(r#"
        tool "send_email" {
            should deny when msg.tags overlaps {"spam"};
            should allow always;
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("msg"), meta(&[], ConsumerSet::Universal, &["spam"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    // Without fail_fast: should-allow overrides should-deny
    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Allow { .. }));

    // With fail_fast: should-deny returns immediately
    let decision = evaluate(&policy, &ctx, true).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { enforcement: Enforcement::Should, .. }));
}

#[test]
fn test_evaluate_regex_tool_matching() {
    let policy = parse_and_compile(r#"
        tool r"send_.*" {
            must deny when msg.tags overlaps {"blocked"};
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("msg"), meta(&[], ConsumerSet::Universal, &["blocked"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { enforcement: Enforcement::Must, .. }));
}

#[test]
fn test_evaluate_with_result_updates() {
    let policy = parse_and_compile(r#"
        tool "get_data" {
            should allow always;
            result {
                @tags |= {"fetched"};
            }
        }
    "#);

    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("get_data", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    match decision {
        PolicyDecision::Allow { result_updates, .. } => {
            assert_eq!(result_updates.len(), 1);
            assert_eq!(result_updates[0].field, MetaFieldKind::Tags);
            assert_eq!(result_updates[0].op, MetaUpdateOp::UnionAssign);
            assert_eq!(result_updates[0].string_set, str_set(&["fetched"]));
        }
        PolicyDecision::Deny { .. } => panic!("Expected Allow"),
    }
}

#[test]
fn test_evaluate_with_let_variable() {
    let policy = parse_and_compile(r#"
        let sensitive_tags = {"confidential", "secret", "restricted"};
        tool "send_email" {
            must deny when msg.tags overlaps sensitive_tags;
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("msg"), meta(&[], ConsumerSet::Universal, &["secret"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { enforcement: Enforcement::Must, .. }));
}

#[test]
fn test_evaluate_condition_when_false() {
    let policy = parse_and_compile(r#"
        tool "send_email" {
            must deny when msg.tags overlaps {"confidential"};
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(json!("safe data"), meta(&[], ConsumerSet::Universal, &["public"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    // Condition is false, so must-deny doesn't fire. Default is allow.
    assert!(matches!(decision, PolicyDecision::Allow { .. }));
}

// ============================================================
// Branching Meta-Policy Tests
// ============================================================

#[test]
fn test_branch_deny_mode_no_overlap_ok() {
    let policy = CompiledPolicy {
        variables: HashMap::new(),
        exact_policies: HashMap::new(),
        regex_policies: Vec::new(),
        preset: InternalPolicyPreset {
            branching_meta_policy: BranchingMetaPolicy {
                mode: BranchingMode::Deny,
                producers: str_set(&["untrusted_tool"]),
                tags: str_set(&["dangerous"]),
                consumers: BTreeSet::new(),
            },
            ..InternalPolicyPreset::default()
        },
    };

    let condition_meta = meta(&["safe_tool"], ConsumerSet::Universal, &["normal"]);
    assert!(check_branch(&policy, &condition_meta).is_ok());
}

#[test]
fn test_branch_deny_mode_producer_overlap_denied() {
    let policy = CompiledPolicy {
        variables: HashMap::new(),
        exact_policies: HashMap::new(),
        regex_policies: Vec::new(),
        preset: InternalPolicyPreset {
            branching_meta_policy: BranchingMetaPolicy {
                mode: BranchingMode::Deny,
                producers: str_set(&["untrusted_tool"]),
                tags: BTreeSet::new(),
                consumers: BTreeSet::new(),
            },
            ..InternalPolicyPreset::default()
        },
    };

    let condition_meta = meta(&["untrusted_tool"], ConsumerSet::Universal, &[]);
    let result = check_branch(&policy, &condition_meta);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field, "producers");
    assert!(err.offending_values.contains(&"untrusted_tool".to_string()));
}

#[test]
fn test_branch_deny_mode_tag_overlap_denied() {
    let policy = CompiledPolicy {
        variables: HashMap::new(),
        exact_policies: HashMap::new(),
        regex_policies: Vec::new(),
        preset: InternalPolicyPreset {
            branching_meta_policy: BranchingMetaPolicy {
                mode: BranchingMode::Deny,
                producers: BTreeSet::new(),
                tags: str_set(&["__non_executable"]),
                consumers: BTreeSet::new(),
            },
            ..InternalPolicyPreset::default()
        },
    };

    let condition_meta = meta(&[], ConsumerSet::Universal, &["__non_executable"]);
    let result = check_branch(&policy, &condition_meta);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field, "tags");
}

#[test]
fn test_branch_allow_mode_subset_ok() {
    let policy = CompiledPolicy {
        variables: HashMap::new(),
        exact_policies: HashMap::new(),
        regex_policies: Vec::new(),
        preset: InternalPolicyPreset {
            branching_meta_policy: BranchingMetaPolicy {
                mode: BranchingMode::Allow,
                producers: str_set(&["trusted_tool", "safe_tool"]),
                tags: str_set(&["verified"]),
                consumers: BTreeSet::new(),
            },
            ..InternalPolicyPreset::default()
        },
    };

    let condition_meta = meta(&["trusted_tool"], ConsumerSet::Universal, &["verified"]);
    assert!(check_branch(&policy, &condition_meta).is_ok());
}

#[test]
fn test_branch_allow_mode_not_subset_denied() {
    let policy = CompiledPolicy {
        variables: HashMap::new(),
        exact_policies: HashMap::new(),
        regex_policies: Vec::new(),
        preset: InternalPolicyPreset {
            branching_meta_policy: BranchingMetaPolicy {
                mode: BranchingMode::Allow,
                producers: str_set(&["trusted_tool"]),
                tags: str_set(&["verified"]),
                consumers: BTreeSet::new(),
            },
            ..InternalPolicyPreset::default()
        },
    };

    let condition_meta = meta(&["unknown_tool"], ConsumerSet::Universal, &["verified"]);
    let result = check_branch(&policy, &condition_meta);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field, "producers");
    assert!(err.offending_values.contains(&"unknown_tool".to_string()));
}

#[test]
fn test_branch_allow_mode_extra_tags_denied() {
    let policy = CompiledPolicy {
        variables: HashMap::new(),
        exact_policies: HashMap::new(),
        regex_policies: Vec::new(),
        preset: InternalPolicyPreset {
            branching_meta_policy: BranchingMetaPolicy {
                mode: BranchingMode::Allow,
                producers: str_set(&["trusted_tool"]),
                tags: str_set(&["verified"]),
                consumers: BTreeSet::new(),
            },
            ..InternalPolicyPreset::default()
        },
    };

    let condition_meta = meta(&["trusted_tool"], ConsumerSet::Universal, &["verified", "extra"]);
    let result = check_branch(&policy, &condition_meta);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field, "tags");
    assert!(err.offending_values.contains(&"extra".to_string()));
}

#[test]
fn test_branch_clean_metadata_always_passes() {
    // Clean metadata (no producers, universal consumers, no tags) should pass both modes
    let deny_policy = CompiledPolicy {
        variables: HashMap::new(),
        exact_policies: HashMap::new(),
        regex_policies: Vec::new(),
        preset: InternalPolicyPreset {
            branching_meta_policy: BranchingMetaPolicy {
                mode: BranchingMode::Deny,
                producers: str_set(&["bad"]),
                tags: str_set(&["bad"]),
                consumers: BTreeSet::new(),
            },
            ..InternalPolicyPreset::default()
        },
    };

    let clean_meta = Metadata::default();
    assert!(check_branch(&deny_policy, &clean_meta).is_ok());
}

// ============================================================
// Integration Tests (End-to-End from SQRT Source)
// ============================================================

#[test]
fn test_integration_data_leak_prevention() {
    let policy = parse_and_compile(r#"
        let sensitive_docs = {"confidential", "secret", "restricted"};

        tool "send_email" {
            /// Block sending emails with sensitive document tags
            must deny when msg.tags overlaps sensitive_docs;
            should allow always;
        }
    "#);

    // Should deny: message tagged as "confidential"
    let mut args = IndexMap::new();
    args.insert(
        "msg".to_string(),
        value_with_meta(
            json!({"body": "secret report"}),
            meta(&["doc_system"], ConsumerSet::Universal, &["confidential"]),
        ),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_email", &args, &session);
    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { .. }));

    // Should allow: message with no sensitive tags
    let mut args2 = IndexMap::new();
    args2.insert(
        "msg".to_string(),
        value_with_meta(
            json!({"body": "meeting notes"}),
            meta(&["doc_system"], ConsumerSet::Universal, &["internal"]),
        ),
    );
    let ctx2 = make_ctx("send_email", &args2, &session);
    let decision2 = evaluate(&policy, &ctx2, false).unwrap();
    assert!(matches!(decision2, PolicyDecision::Allow { .. }));
}

#[test]
fn test_integration_pii_protection_regex() {
    let policy = parse_and_compile(r#"
        tool r".*_pii$" {
            must deny when data.tags overlaps {"external"};
            should allow always;
        }
    "#);

    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("pii_data"), meta(&[], ConsumerSet::Universal, &["external"])),
    );
    let session = Metadata::default();

    // "get_pii" matches r".*_pii$"
    let ctx = make_ctx("get_pii", &args, &session);
    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { .. }));

    // "get_data" does NOT match r".*_pii$"
    let ctx2 = make_ctx("get_data", &args, &session);
    let decision2 = evaluate(&policy, &ctx2, false).unwrap();
    assert!(matches!(decision2, PolicyDecision::Allow { .. }));
}

#[test]
fn test_integration_session_tracking() {
    let policy = parse_and_compile(r#"
        tool "process_payment" {
            should allow always;
            session before {
                @session.tags |= {"payment_in_progress"};
            }
            session after {
                @session.tags -= {"payment_in_progress"};
                @session.tags |= {"payment_completed"};
            }
        }
    "#);

    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("process_payment", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    match decision {
        PolicyDecision::Allow {
            session_before_updates,
            session_after_updates,
            ..
        } => {
            assert_eq!(session_before_updates.len(), 1);
            assert_eq!(session_before_updates[0].string_set, str_set(&["payment_in_progress"]));
            assert_eq!(session_before_updates[0].op, MetaUpdateOp::UnionAssign);

            assert_eq!(session_after_updates.len(), 2);
            assert_eq!(session_after_updates[0].string_set, str_set(&["payment_in_progress"]));
            assert_eq!(session_after_updates[0].op, MetaUpdateOp::MinusAssign);
            assert_eq!(session_after_updates[1].string_set, str_set(&["payment_completed"]));
            assert_eq!(session_after_updates[1].op, MetaUpdateOp::UnionAssign);
        }
        PolicyDecision::Deny { .. } => panic!("Expected Allow"),
    }
}

#[test]
fn test_integration_conditional_result_update() {
    let policy = parse_and_compile(r#"
        tool "get_data" {
            should allow always;
            result {
                when data.tags overlaps {"untrusted"} {
                    @tags |= {"needs_review"};
                }
            }
        }
    "#);

    // With untrusted data: should include the conditional update
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["untrusted"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("get_data", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    match decision {
        PolicyDecision::Allow { result_updates, .. } => {
            assert_eq!(result_updates.len(), 1);
            assert_eq!(result_updates[0].string_set, str_set(&["needs_review"]));
        }
        PolicyDecision::Deny { .. } => panic!("Expected Allow"),
    }

    // Without untrusted data: conditional should not fire
    let mut args2 = IndexMap::new();
    args2.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["trusted"])),
    );
    let ctx2 = make_ctx("get_data", &args2, &session);

    let decision2 = evaluate(&policy, &ctx2, false).unwrap();
    match decision2 {
        PolicyDecision::Allow { result_updates, .. } => {
            assert!(result_updates.is_empty());
        }
        PolicyDecision::Deny { .. } => panic!("Expected Allow"),
    }
}

#[test]
fn test_integration_multiple_policies_metadata_collection() {
    let policy = parse_and_compile(r#"
        tool "api_call" {
            should allow always;
            result {
                @tags |= {"api_result"};
            }
        }
        tool "api_call" {
            result {
                @producers |= {"api"};
            }
        }
    "#);

    let args = IndexMap::new();
    let session = Metadata::default();
    let ctx = make_ctx("api_call", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    match decision {
        PolicyDecision::Allow { result_updates, .. } => {
            // Both policies' result updates should be collected
            assert_eq!(result_updates.len(), 2);
        }
        PolicyDecision::Deny { .. } => panic!("Expected Allow"),
    }
}

#[test]
fn test_integration_value_in_check() {
    let policy = parse_and_compile(r#"
        tool "execute" {
            must deny when action.value in {"rm", "del", "drop"};
            should allow always;
        }
    "#);

    // Dangerous action
    let mut args = IndexMap::new();
    args.insert(
        "action".to_string(),
        value_with_meta(json!("rm"), Metadata::default()),
    );
    let session = Metadata::default();
    let ctx = make_ctx("execute", &args, &session);
    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Deny { .. }));

    // Safe action
    let mut args2 = IndexMap::new();
    args2.insert(
        "action".to_string(),
        value_with_meta(json!("ls"), Metadata::default()),
    );
    let ctx2 = make_ctx("execute", &args2, &session);
    let decision2 = evaluate(&policy, &ctx2, false).unwrap();
    assert!(matches!(decision2, PolicyDecision::Allow { .. }));
}

#[test]
fn test_integration_producer_provenance() {
    let policy = parse_and_compile(r#"
        let trusted_sources = {"internal_api", "user_input"};
        tool "send_external" {
            must deny when not data.producers subset of trusted_sources;
            should allow always;
        }
    "#);

    // Trusted producers
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("safe"), meta(&["internal_api"], ConsumerSet::Universal, &[])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("send_external", &args, &session);
    let decision = evaluate(&policy, &ctx, false).unwrap();
    assert!(matches!(decision, PolicyDecision::Allow { .. }));

    // Untrusted producer
    let mut args2 = IndexMap::new();
    args2.insert(
        "data".to_string(),
        value_with_meta(json!("untrusted"), meta(&["external_api"], ConsumerSet::Universal, &[])),
    );
    let ctx2 = make_ctx("send_external", &args2, &session);
    let decision2 = evaluate(&policy, &ctx2, false).unwrap();
    assert!(matches!(decision2, PolicyDecision::Deny { .. }));
}

#[test]
fn test_integration_shorthand_with_condition() {
    let policy = parse_and_compile(
        r#"tool "get_data" -> result @tags |= {"external"} when data.tags overlaps {"untrusted"};"#,
    );

    // With untrusted data
    let mut args = IndexMap::new();
    args.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["untrusted"])),
    );
    let session = Metadata::default();
    let ctx = make_ctx("get_data", &args, &session);

    let decision = evaluate(&policy, &ctx, false).unwrap();
    match decision {
        PolicyDecision::Allow { result_updates, .. } => {
            assert_eq!(result_updates.len(), 1);
            assert_eq!(result_updates[0].string_set, str_set(&["external"]));
        }
        PolicyDecision::Deny { .. } => panic!("Expected Allow"),
    }

    // Without untrusted data
    let mut args2 = IndexMap::new();
    args2.insert(
        "data".to_string(),
        value_with_meta(json!("x"), meta(&[], ConsumerSet::Universal, &["safe"])),
    );
    let ctx2 = make_ctx("get_data", &args2, &session);

    let decision2 = evaluate(&policy, &ctx2, false).unwrap();
    match decision2 {
        PolicyDecision::Allow { result_updates, .. } => {
            assert!(result_updates.is_empty());
        }
        PolicyDecision::Deny { .. } => panic!("Expected Allow"),
    }
}
