//! Set expression evaluator for the SQRT policy engine.
//!
//! Evaluates `SetExpr` AST nodes to `FieldValue` results, handling literal sets,
//! metadata field operands, variable references, and all binary/element set operations.

use std::collections::BTreeSet;

use sqrt_parser::{SetElement, SetExpr};

use crate::context::{EvalContext, FieldValue};
use crate::error::EvalError;
use crate::types::{ResolvedLetValue, SetExprResolved};

/// Evaluate a set expression to a `FieldValue`.
///
/// This is the main entry point for set evaluation. It recursively evaluates
/// the set expression tree, resolving operands from the evaluation context,
/// looking up variable references, and applying binary set operations.
pub(crate) fn eval_set_expr(
    expr: &SetExpr,
    ctx: &EvalContext<'_>,
) -> Result<FieldValue, EvalError> {
    match expr {
        SetExpr::Literal(elements) => {
            // Collect string elements into a BTreeSet.
            // Non-string elements (Regex, Wildcard, TypeDomain, Number) are only
            // meaningful in ValueIn comparisons and are skipped for set materialization.
            let strings: BTreeSet<String> = elements
                .iter()
                .filter_map(|elem| match elem {
                    SetElement::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect();
            Ok(FieldValue::StringSet(strings))
        }

        SetExpr::Operand(operand) => ctx.resolve_operand(operand),

        SetExpr::Ref(name) => {
            let resolved = ctx
                .variables
                .get(name)
                .ok_or_else(|| EvalError::UndefinedVariable {
                    name: name.clone(),
                })?;

            match resolved {
                ResolvedLetValue::Set(set_resolved) => match set_resolved {
                    SetExprResolved::Static(s) => Ok(FieldValue::StringSet(s.clone())),
                    SetExprResolved::Dynamic(dynamic_expr) => eval_set_expr(dynamic_expr, ctx),
                },
                ResolvedLetValue::Predicate(_) => Err(EvalError::TypeMismatch {
                    message: format!(
                        "Variable '{name}' is a predicate, but a set expression was expected"
                    ),
                }),
                ResolvedLetValue::TypeDomain(_) => Err(EvalError::TypeMismatch {
                    message: format!(
                        "Variable '{name}' is a type domain, but a set expression was expected"
                    ),
                }),
            }
        }

        SetExpr::Union(left, right) => {
            let l = eval_set_expr(left, ctx)?;
            let r = eval_set_expr(right, ctx)?;
            Ok(l.union(&r))
        }

        SetExpr::Intersect(left, right) => {
            let l = eval_set_expr(left, ctx)?;
            let r = eval_set_expr(right, ctx)?;
            Ok(l.intersect(&r))
        }

        SetExpr::Minus(left, right) => {
            let l = eval_set_expr(left, ctx)?;
            let r = eval_set_expr(right, ctx)?;
            Ok(l.minus(&r))
        }

        SetExpr::Xor(left, right) => {
            let l = eval_set_expr(left, ctx)?;
            let r = eval_set_expr(right, ctx)?;
            Ok(l.xor(&r))
        }

        SetExpr::With(base, element) => {
            let base_val = eval_set_expr(base, ctx)?;
            match element {
                SetElement::String(s) => Ok(base_val.with_element(s)),
                _ => Err(EvalError::TypeMismatch {
                    message: "With operator requires a string element".to_string(),
                }),
            }
        }

        SetExpr::Without(base, element) => {
            let base_val = eval_set_expr(base, ctx)?;
            match element {
                SetElement::String(s) => Ok(base_val.without_element(s)),
                _ => Err(EvalError::TypeMismatch {
                    message: "Without operator requires a string element".to_string(),
                }),
            }
        }
    }
}
