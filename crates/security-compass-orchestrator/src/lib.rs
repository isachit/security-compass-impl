//! Security Compass Orchestrator — Dual LLM Session Manager.
//!
//! This crate implements the orchestration layer of the CaMeL Dual-LLM
//! architecture. It manages the conversation loop between:
//! - **PLLM** (Planning LLM): generates Python code from user requests
//! - **QLLM** (Quarantined LLM): processes untrusted data (parse_with_ai, verify_hypothesis)
//! - **Interpreter**: executes the code with metadata tracking and SQRT policy enforcement
//!
//! # Usage Pattern
//!
//! ```text
//! // 1. Create a session
//! let session = Session::new(policy, session_config, interp_config, tools);
//!
//! // 2. Process user turns
//! let result = session.process_turn("user request", &pllm, &tool_executor).await?;
//!
//! // 3. Check the result
//! match result.status {
//!     TurnStatus::Success => { /* use result.final_return_value */ }
//!     TurnStatus::ClarificationNeeded => { /* ask user for more info */ }
//!     TurnStatus::MaxAttemptsExceeded => { /* all retries failed */ }
//!     TurnStatus::Error => { /* fatal error */ }
//! }
//! ```

mod code_extraction;
mod error;
mod interpreter_loop;
mod prompt_builder;
mod qllm;
mod traits;
mod turn;
mod types;

#[cfg(test)]
mod tests;

// Public re-exports — orchestrator's own types
pub use code_extraction::extract_code_block;
pub use error::OrchestratorError;
pub use prompt_builder::build_pllm_system_prompt;
pub use traits::{LlmClient, ToolExecutor};
pub use types::{
    ClearSessionMeta, DebugInfoLevel, InternalTool, Message, ResponseFormatConfig, Role,
    SecureVarVisibility, Session, SessionConfig, ToolCallSummary, TurnResult, TurnStatus,
};

// Re-export interpreter types that orchestrator callers need
pub use security_compass_interpreter::{
    CacheMode, Interpreter, InterpreterConfig, InterpreterError, ToolDefinition,
};
pub use sqrt_eval::{CompiledPolicy, InternalPolicyPreset};
