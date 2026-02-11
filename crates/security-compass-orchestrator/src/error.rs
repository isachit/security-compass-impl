//! Error types for the Security Compass Orchestrator.

use security_compass_interpreter::InterpreterError;

/// Errors that can occur during orchestration.
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// The PLLM response did not contain an extractable code block.
    #[error("No code block found in PLLM response")]
    NoCodeBlock,

    /// The PLLM requested clarification from the user instead of generating code.
    #[error("PLLM requested clarification: {message}")]
    ClarificationRequested {
        /// The clarification message from the PLLM.
        message: String,
    },

    /// The maximum number of PLLM retry attempts was exceeded.
    #[error("Max PLLM attempts exceeded ({attempts} attempts)")]
    MaxAttemptsExceeded {
        /// The number of attempts that were made.
        attempts: u32,
    },

    /// The maximum number of session turns was exceeded.
    #[error("Max turns exceeded (limit: {limit})")]
    MaxTurnsExceeded {
        /// The configured turn limit.
        limit: u32,
    },

    /// An error from the LLM client (PLLM or QLLM call failed).
    #[error("LLM error: {message}")]
    LlmError {
        /// Description of the LLM failure.
        message: String,
    },

    /// An error from external tool execution.
    #[error("Tool error: {tool_name}: {message}")]
    ToolError {
        /// The tool that failed.
        tool_name: String,
        /// Description of the failure.
        message: String,
    },

    /// An error from the interpreter layer.
    #[error("Interpreter error: {0}")]
    InterpreterError(#[from] InterpreterError),

    /// A serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    /// The QLLM indicated it did not have enough information to parse the data.
    #[error("QLLM: not enough information to answer")]
    QllmInsufficientInfo,

    /// An internal tool was called but is not enabled in the session configuration.
    #[error("Internal tool not enabled: {tool_name}")]
    InternalToolDisabled {
        /// The internal tool that was not enabled.
        tool_name: String,
    },
}
