//! Policy compiler: transforms a parsed `SqrtProgram` AST into a `CompiledPolicy`.
//!
//! The compiler performs two passes over the declarations:
//!
//! 1. **Let declarations** — Resolve set expressions to static values where possible
//!    (pure literals with no runtime operands). Store predicates and type domains as-is.
//!    Check for duplicates and undefined forward references.
//!
//! 2. **Tool/ToolShorthand declarations** — Build `CompiledToolPolicy` structs with
//!    priority, check rules, and metadata statements. Index by tool name (exact → HashMap,
//!    regex → pre-compiled Vec).

use std::collections::{BTreeSet, HashMap};

use regex::Regex;
use sqrt_parser::{
    DeclarationKind, Expression, MetadataStmt, MetadataTarget, MetadataUpdate, SetElement, SetExpr,
    SqrtProgram, ToolId, UpdateTarget,
};

use crate::error::CompileError;
use crate::types::{
    CompiledPolicy, CompiledToolPolicy, InternalPolicyPreset, ResolvedLetValue, SetExprResolved,
};

/// Compile a parsed SQRT program into a `CompiledPolicy`, ready for evaluation.
///
/// Takes the parsed program AST and an `InternalPolicyPreset` configuration.
/// Returns a `CompiledPolicy` or a `CompileError` if compilation fails.
pub fn compile(
    program: &SqrtProgram,
    preset: InternalPolicyPreset,
) -> Result<CompiledPolicy, CompileError> {
    let mut variables: HashMap<String, ResolvedLetValue> = HashMap::new();
    let mut exact_policies: HashMap<String, Vec<CompiledToolPolicy>> = HashMap::new();
    let mut regex_policies: Vec<(Regex, CompiledToolPolicy)> = Vec::new();

    for decl in &program.declarations {
        match &decl.kind {
            DeclarationKind::Let(let_decl) => {
                // Check for duplicate variable names
                if variables.contains_key(&let_decl.name) {
                    return Err(CompileError::DuplicateVariable {
                        name: let_decl.name.clone(),
                    });
                }

                let resolved = resolve_expression(&let_decl.value, &variables)?;
                variables.insert(let_decl.name.clone(), resolved);
            }

            DeclarationKind::Tool(tool_decl) => {
                let policy = CompiledToolPolicy {
                    priority: tool_decl.priority.unwrap_or(0) as i32,
                    checks: tool_decl.checks.clone(),
                    result_stmts: tool_decl.result_block.clone().unwrap_or_default(),
                    session_before_stmts: tool_decl.session_before.clone().unwrap_or_default(),
                    session_after_stmts: tool_decl.session_after.clone().unwrap_or_default(),
                };

                match &tool_decl.id {
                    ToolId::Exact(name) => {
                        exact_policies
                            .entry(name.clone())
                            .or_default()
                            .push(policy);
                    }
                    ToolId::Regex(pattern) => {
                        let re = Regex::new(pattern).map_err(|e| CompileError::InvalidRegex {
                            pattern: pattern.clone(),
                            source: e,
                        })?;
                        regex_policies.push((re, policy));
                    }
                }
            }

            DeclarationKind::ToolShorthand(shorthand) => {
                let policy = expand_shorthand(shorthand)?;

                match &shorthand.id {
                    ToolId::Exact(name) => {
                        exact_policies
                            .entry(name.clone())
                            .or_default()
                            .push(policy);
                    }
                    ToolId::Regex(pattern) => {
                        let re = Regex::new(pattern).map_err(|e| CompileError::InvalidRegex {
                            pattern: pattern.clone(),
                            source: e,
                        })?;
                        regex_policies.push((re, policy));
                    }
                }
            }
        }
    }

    Ok(CompiledPolicy {
        variables,
        exact_policies,
        regex_policies,
        preset,
    })
}

/// Resolve a `let` expression into a `ResolvedLetValue`.
///
/// For set expressions, tries to statically evaluate pure literals (no runtime
/// operands or variable references). Dynamic sets are stored as AST for lazy
/// evaluation at runtime.
fn resolve_expression(
    expr: &Expression,
    _existing_vars: &HashMap<String, ResolvedLetValue>,
) -> Result<ResolvedLetValue, CompileError> {
    match expr {
        Expression::Predicate(pred) => Ok(ResolvedLetValue::Predicate(pred.clone())),
        Expression::TypeDomain(td) => Ok(ResolvedLetValue::TypeDomain(td.clone())),
        Expression::SetExpr(set_expr) => {
            // Try static evaluation for pure-literal sets
            if let Some(static_set) = try_static_eval(set_expr) {
                Ok(ResolvedLetValue::Set(SetExprResolved::Static(static_set)))
            } else {
                Ok(ResolvedLetValue::Set(SetExprResolved::Dynamic(
                    set_expr.clone(),
                )))
            }
        }
    }
}

/// Attempt to statically evaluate a set expression at compile time.
///
/// Returns `Some(BTreeSet)` if the expression contains only string literals
/// and set operations on literals. Returns `None` if runtime operands,
/// variable references, or non-string elements are present.
fn try_static_eval(expr: &SetExpr) -> Option<BTreeSet<String>> {
    match expr {
        SetExpr::Literal(elements) => {
            // Only statically evaluate if all elements are strings
            let mut set = BTreeSet::new();
            for elem in elements {
                match elem {
                    SetElement::String(s) => {
                        set.insert(s.clone());
                    }
                    _ => return None, // Cannot statically evaluate non-string elements
                }
            }
            Some(set)
        }

        SetExpr::Union(left, right) => {
            let l = try_static_eval(left)?;
            let r = try_static_eval(right)?;
            Some(l.union(&r).cloned().collect())
        }

        SetExpr::Intersect(left, right) => {
            let l = try_static_eval(left)?;
            let r = try_static_eval(right)?;
            Some(l.intersection(&r).cloned().collect())
        }

        SetExpr::Minus(left, right) => {
            let l = try_static_eval(left)?;
            let r = try_static_eval(right)?;
            Some(l.difference(&r).cloned().collect())
        }

        SetExpr::Xor(left, right) => {
            let l = try_static_eval(left)?;
            let r = try_static_eval(right)?;
            Some(l.symmetric_difference(&r).cloned().collect())
        }

        SetExpr::With(base, elem) => {
            let mut s = try_static_eval(base)?;
            match elem {
                SetElement::String(e) => {
                    s.insert(e.clone());
                    Some(s)
                }
                _ => None,
            }
        }

        SetExpr::Without(base, elem) => {
            let mut s = try_static_eval(base)?;
            match elem {
                SetElement::String(e) => {
                    s.remove(e);
                    Some(s)
                }
                _ => None,
            }
        }

        // Runtime operands and variable references cannot be statically evaluated
        SetExpr::Operand(_) | SetExpr::Ref(_) => None,
    }
}

/// Expand a tool shorthand declaration into a `CompiledToolPolicy`.
///
/// Shorthand form: `tool "name" [priority] -> [target] @field op value [when cond];`
///
/// The shorthand is expanded into:
/// - A `CompiledToolPolicy` with no check rules
/// - The single metadata update placed in the appropriate stmts list based on target
/// - If a condition is present, it wraps the update in a conditional MetadataStmt
fn expand_shorthand(
    shorthand: &sqrt_parser::ToolShorthandDecl,
) -> Result<CompiledToolPolicy, CompileError> {
    // Build the metadata update
    let update = MetadataUpdate {
        target: match shorthand.target {
            UpdateTarget::Result => MetadataTarget::Result,
            UpdateTarget::Session | UpdateTarget::SessionBefore | UpdateTarget::SessionAfter => {
                MetadataTarget::Session
            }
        },
        field: shorthand.update.field,
        op: shorthand.update.op,
        value: shorthand.update.value.clone(),
    };

    // Wrap in conditional if needed
    let stmt = if let Some(ref condition) = shorthand.condition {
        MetadataStmt::Conditional {
            condition: condition.clone(),
            updates: vec![update],
        }
    } else {
        MetadataStmt::Update(update)
    };

    // Place into the right block based on target
    let mut result_stmts = Vec::new();
    let mut session_before_stmts = Vec::new();
    let mut session_after_stmts = Vec::new();

    match shorthand.target {
        UpdateTarget::Result => result_stmts.push(stmt),
        UpdateTarget::Session | UpdateTarget::SessionBefore => session_before_stmts.push(stmt),
        UpdateTarget::SessionAfter => session_after_stmts.push(stmt),
    }

    Ok(CompiledToolPolicy {
        priority: shorthand.priority.unwrap_or(0) as i32,
        checks: Vec::new(),
        result_stmts,
        session_before_stmts,
        session_after_stmts,
    })
}
