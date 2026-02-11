//! Security Compass Interpreter — Orchestrates VM execution with SQRT policy enforcement.
//!
//! This crate bridges the Monty bytecode VM, the SQRT policy evaluation engine,
//! and the metadata system. It intercepts every tool call from the VM, evaluates
//! SQRT security policies, enforces branching restrictions, and yields to the
//! caller (orchestrator) for actual tool execution and QLLM routing.

mod branch_checker;
mod convert;
mod error;
mod execution;
mod policy;
mod resume;
mod types;

#[cfg(test)]
mod tests;

pub use convert::{json_to_monty, monty_to_json};
pub use error::InterpreterError;
pub use types::{
    CacheMode, ExecutionResult, Interpreter, InterpreterConfig, ToolCallOutcome, ToolCallRecord,
    ToolDefinition, VmSnapshot,
};
