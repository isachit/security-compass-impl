//! SQRT Policy Evaluation Engine.
//!
//! This crate implements the core policy evaluation engine for the Security Compass
//! architecture. It takes parsed SQRT policy programs (from `sqrt-parser`) and
//! evaluates them against tool call contexts to produce Allow/Deny decisions with
//! metadata updates.
//!
//! # Architecture
//!
//! ```text
//! SqrtProgram (AST) ──[compile()]──> CompiledPolicy
//!                                         │
//! ToolCallContext ────[evaluate()]─────────┘──> PolicyDecision
//!                                                  │
//!                                         Allow { updates } | Deny { reason }
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use sqrt_eval::{compile, evaluate, InternalPolicyPreset, ToolCallContext};
//! use sqrt_parser::parse;
//!
//! // Parse a SQRT policy
//! let program = parse(r#"tool "send_email" { must deny when msg.tags overlaps {"confidential"}; }"#)?;
//!
//! // Compile with default preset
//! let policy = compile(&program, InternalPolicyPreset::default())?;
//!
//! // Evaluate against a tool call
//! let decision = evaluate(&policy, &ctx, false)?;
//! ```

pub mod compiler;
pub mod error;
pub mod evaluator;
pub mod metadata_update;
pub mod types;
pub mod value_match;

// Internal modules
pub(crate) mod context;
pub(crate) mod predicate_eval;
pub(crate) mod set_eval;

#[cfg(test)]
mod tests;

// Re-exports for convenient access
pub use compiler::compile;
pub use error::{BranchingDenied, CompileError, EvalError};
pub use evaluator::{check_branch, evaluate};
pub use metadata_update::{apply_update, apply_updates};
pub use types::{
    BranchingMetaPolicy, BranchingMode, CompiledPolicy, CompiledToolPolicy, InternalPolicyPreset,
    PolicyDecision, ResolvedLetValue, ResolvedUpdate, SetExprResolved, ToolCallContext,
};
