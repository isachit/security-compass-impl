//! Error types for the Security Compass Interpreter.

use security_compass_vm::MontyException;
use sqrt_eval::{CompileError, EvalError};

/// Errors that can occur during interpretation.
#[derive(Debug, thiserror::Error)]
pub enum InterpreterError {
    /// A runtime error from the bytecode VM (e.g., unhandled exception).
    #[error("VM error: {0}")]
    VmError(#[from] MontyException),

    /// A SQRT policy compilation error.
    #[error("Policy compile error: {0}")]
    PolicyCompileError(#[from] CompileError),

    /// A SQRT policy evaluation error (e.g., undefined variable).
    #[error("Policy evaluation error: {0}")]
    PolicyEvalError(#[from] EvalError),

    /// An OS-level call was attempted, which is not allowed in the interpreter.
    #[error("OS call denied: {function}")]
    OsCallDenied {
        /// The name of the OS function that was called.
        function: String,
    },

    /// Async operations (await, gather) are not supported by the interpreter.
    #[error("Async operations are not supported")]
    AsyncNotSupported,

    /// The gas limit was exhausted before execution completed.
    #[error("Gas exhausted after {tool_calls} tool calls")]
    GasExhausted {
        /// Number of tool calls made before exhaustion.
        tool_calls: u32,
    },

    /// The per-execution tool call limit was exceeded.
    #[error("Tool call limit exceeded (limit: {limit})")]
    ToolCallLimitExceeded {
        /// The maximum number of tool calls allowed.
        limit: u32,
    },

    /// A `MontyObject` could not be converted to/from JSON.
    #[error("Conversion error: {message}")]
    ConversionError {
        /// Description of what went wrong during conversion.
        message: String,
    },

    /// An external tool was called that is not registered in the tool definitions.
    #[error("Unknown tool: {name}")]
    UnknownTool {
        /// The name of the unrecognized tool.
        name: String,
    },

    /// The number of positional arguments does not match the tool's parameter count.
    #[error("Argument count mismatch for '{tool_name}': expected {expected}, got {actual}")]
    ArgCountMismatch {
        /// The tool that was called.
        tool_name: String,
        /// Expected number of arguments.
        expected: usize,
        /// Actual number of arguments provided.
        actual: usize,
    },

    /// An LLM-blocked tag was detected on arguments to a QLLM-routing tool.
    #[error("LLM blocked: arguments to '{tool_name}' carry the __llm_blocked tag")]
    LlmBlocked {
        /// The tool that was blocked.
        tool_name: String,
    },
}
