//! Predicate evaluator for the SQRT policy engine.
//!
//! Evaluates `Predicate` AST nodes to boolean results. Handles logical operators
//! (and, or, not) with short-circuit evaluation, variable references, and all
//! comparison types (value and set comparisons).

use sqrt_parser::{Comparison, LiteralValue, Predicate, ValueOperand};

use crate::context::EvalContext;
use crate::error::EvalError;
use crate::set_eval::eval_set_expr;
use crate::types::ResolvedLetValue;
use crate::value_match::matches_set_element;

/// Evaluate a predicate to a boolean value.
///
/// This is the main entry point for predicate evaluation. It supports
/// short-circuit evaluation for `and`/`or` operators.
pub(crate) fn eval_predicate(
    pred: &Predicate,
    ctx: &EvalContext<'_>,
) -> Result<bool, EvalError> {
    match pred {
        Predicate::Or(left, right) => {
            // Short-circuit: if left is true, skip right.
            if eval_predicate(left, ctx)? {
                Ok(true)
            } else {
                eval_predicate(right, ctx)
            }
        }

        Predicate::And(left, right) => {
            // Short-circuit: if left is false, skip right.
            if !eval_predicate(left, ctx)? {
                Ok(false)
            } else {
                eval_predicate(right, ctx)
            }
        }

        Predicate::Not(inner) => {
            let result = eval_predicate(inner, ctx)?;
            Ok(!result)
        }

        Predicate::Ref(name) => {
            let resolved = ctx
                .variables
                .get(name)
                .ok_or_else(|| EvalError::UndefinedVariable {
                    name: name.clone(),
                })?;

            match resolved {
                ResolvedLetValue::Predicate(pred) => eval_predicate(pred, ctx),
                ResolvedLetValue::Set(_) => Err(EvalError::TypeMismatch {
                    message: format!(
                        "Variable '{name}' is a set, but a predicate was expected"
                    ),
                }),
                ResolvedLetValue::TypeDomain(_) => Err(EvalError::TypeMismatch {
                    message: format!(
                        "Variable '{name}' is a type domain, but a predicate was expected"
                    ),
                }),
            }
        }

        Predicate::Comparison(comp) => eval_comparison(comp, ctx),
    }
}

/// Evaluate a comparison expression.
///
/// Handles all 8 comparison types: value-in, value-equals, set-overlaps,
/// set-subset-of, set-superset-of, set-equals, set-is-empty, set-is-universal.
fn eval_comparison(comp: &Comparison, ctx: &EvalContext<'_>) -> Result<bool, EvalError> {
    match comp {
        Comparison::ValueIn { operand, set } => {
            let value = resolve_value_operand(operand, ctx)?;

            // For ValueIn, we need to check the value against each element in the set.
            // If the set is a literal, check against each element.
            // If the set is a computed set, check membership by string representation.
            match set {
                sqrt_parser::SetExpr::Literal(elements) => {
                    for elem in elements {
                        if matches_set_element(&value, elem)? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                _ => {
                    // Evaluate the set expression and check string membership
                    let set_val = eval_set_expr(set, ctx)?;
                    let value_str = json_value_to_string(&value);
                    Ok(set_val.as_string_set().contains(&value_str))
                }
            }
        }

        Comparison::ValueEquals { left, right } => {
            let left_val = resolve_value_operand(left, ctx)?;
            let right_val = resolve_value_operand(right, ctx)?;
            Ok(json_values_equal(&left_val, &right_val))
        }

        Comparison::SetOverlaps { left, right } => {
            let left_val = ctx.resolve_operand(left)?;
            let right_val = eval_set_expr(right, ctx)?;
            Ok(left_val.overlaps(&right_val))
        }

        Comparison::SetSubsetOf { left, right } => {
            let left_val = ctx.resolve_operand(left)?;
            let right_val = eval_set_expr(right, ctx)?;
            Ok(left_val.is_subset_of(&right_val))
        }

        Comparison::SetSupersetOf { left, right } => {
            // A superset of B  ⟺  B subset of A
            let left_val = ctx.resolve_operand(left)?;
            let right_val = eval_set_expr(right, ctx)?;
            Ok(right_val.is_subset_of(&left_val))
        }

        Comparison::SetEquals { left, right } => {
            let left_val = ctx.resolve_operand(left)?;
            let right_val = eval_set_expr(right, ctx)?;
            Ok(left_val.set_eq(&right_val))
        }

        Comparison::SetIsEmpty(operand) => {
            let val = ctx.resolve_operand(operand)?;
            Ok(val.is_empty())
        }

        Comparison::SetIsUniversal(operand) => {
            let val = ctx.resolve_operand(operand)?;
            Ok(val.is_universal())
        }
    }
}

/// Resolve a value operand to a JSON value.
///
/// Value operands can reference argument values, result values, session values,
/// or literal values.
fn resolve_value_operand(
    operand: &ValueOperand,
    ctx: &EvalContext<'_>,
) -> Result<serde_json::Value, EvalError> {
    match operand {
        ValueOperand::ArgValue(name) => {
            let arg = ctx.arg_value(name)?;
            Ok(arg.value.clone())
        }
        ValueOperand::ResultValue => {
            // Result value is not directly supported; we have result_meta.
            // This would need a full ToolResultWithMeta to access .value.
            Err(EvalError::TypeMismatch {
                message: "Result value access requires a ToolResultWithMeta context".to_string(),
            })
        }
        ValueOperand::SessionValue => {
            // Session doesn't have a "value" — only metadata.
            Err(EvalError::TypeMismatch {
                message: "Session does not have a direct value; use @session.tags etc.".to_string(),
            })
        }
        ValueOperand::Literal(lit) => Ok(literal_to_json(lit)),
    }
}

/// Convert a literal value to a JSON value.
fn literal_to_json(lit: &LiteralValue) -> serde_json::Value {
    match lit {
        LiteralValue::String(s) => serde_json::Value::String(s.clone()),
        LiteralValue::Datetime(s) => serde_json::Value::String(s.clone()),
        LiteralValue::Number(nv) => match nv {
            sqrt_parser::NumberValue::Int(i) => serde_json::json!(*i),
            sqrt_parser::NumberValue::Float(f) => serde_json::json!(*f),
            sqrt_parser::NumberValue::PosInf => serde_json::json!(f64::INFINITY),
            sqrt_parser::NumberValue::NegInf => serde_json::json!(f64::NEG_INFINITY),
        },
        LiteralValue::Bool(b) => serde_json::Value::Bool(*b),
    }
}

/// Convert a JSON value to a string representation for set membership checks.
fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Compare two JSON values for equality.
///
/// Numbers are compared as f64 to handle int/float interop.
fn json_values_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    match (a, b) {
        (serde_json::Value::Number(na), serde_json::Value::Number(nb)) => {
            // Compare as f64 for number equality
            match (na.as_f64(), nb.as_f64()) {
                (Some(fa), Some(fb)) => (fa - fb).abs() < f64::EPSILON,
                _ => false,
            }
        }
        _ => a == b,
    }
}
