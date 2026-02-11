//! Policy evaluation helpers.
//!
//! This module provides utilities for building SQRT `ToolCallContext` from
//! VM arguments and applying metadata updates from policy decisions.

use indexmap::IndexMap;
use security_compass_meta::{Metadata, ValueWithMeta};
use security_compass_vm::MontyObject;
use sqrt_eval::{ResolvedUpdate, ToolCallContext};

use crate::convert::monty_to_json;
use crate::error::InterpreterError;

// ============================================================
// Internal Tool Parameter Names
// ============================================================

/// Parameter names for the `parse_with_ai` internal tool.
pub(crate) const PARSE_WITH_AI_PARAMS: &[&str] = &["data", "query", "output_schema"];

/// Parameter names for the `verify_hypothesis` internal tool.
pub(crate) const VERIFY_HYPOTHESIS_PARAMS: &[&str] = &["hypothesis", "data"];

/// The function name used for QLLM-routed data parsing.
pub(crate) const PARSE_WITH_AI: &str = "parse_with_ai";

/// The function name used for QLLM-routed hypothesis verification.
pub(crate) const VERIFY_HYPOTHESIS: &str = "verify_hypothesis";

// ============================================================
// Positional → Named Conversion
// ============================================================

/// Converts positional VM arguments into named arguments for policy evaluation.
///
/// Zips the positional `MontyObject` values and their metadata with the tool's
/// parameter names. If there are more args than parameter names, excess args
/// are named `_arg{i}`.
///
/// # Errors
/// Returns `InterpreterError::ConversionError` if a `MontyObject` cannot be
/// converted to JSON.
pub(crate) fn positional_to_named(
    args: &[MontyObject],
    args_meta: &[Metadata],
    param_names: &[String],
) -> Result<IndexMap<String, ValueWithMeta<serde_json::Value>>, InterpreterError> {
    let mut named = IndexMap::with_capacity(args.len());

    for (i, (obj, meta)) in args.iter().zip(args_meta.iter()).enumerate() {
        let name = if i < param_names.len() {
            param_names[i].clone()
        } else {
            format!("_arg{i}")
        };
        let json_value = monty_to_json(obj)?;
        named.insert(name, ValueWithMeta {
            value: json_value,
            meta: meta.clone(),
        });
    }

    Ok(named)
}

// ============================================================
// Tool Call Context Building
// ============================================================

/// Builds a `ToolCallContext` for SQRT policy evaluation.
///
/// This is the bridge between the interpreter's named arguments and the
/// evaluator's context format. The `result_meta` is `None` for pre-execution
/// checks (we don't have the result yet).
pub(crate) fn build_tool_call_context<'a>(
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

// ============================================================
// Metadata Update Application
// ============================================================

/// Applies a list of resolved updates to session metadata.
pub(crate) fn apply_session_updates(session_meta: &mut Metadata, updates: &[ResolvedUpdate]) {
    sqrt_eval::apply_updates(session_meta, updates);
}

/// Applies a list of resolved updates to result metadata.
pub(crate) fn apply_result_updates(result_meta: &mut Metadata, updates: &[ResolvedUpdate]) {
    sqrt_eval::apply_updates(result_meta, updates);
}
