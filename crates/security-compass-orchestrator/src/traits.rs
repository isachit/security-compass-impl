//! Async trait definitions for LLM clients and tool executors.
//!
//! These traits abstract over the concrete LLM provider and tool execution
//! implementations. The orchestrator depends only on these traits, allowing
//! the server layer to provide the actual implementations.

use async_trait::async_trait;
use indexmap::IndexMap;
use security_compass_meta::ValueWithMeta;

use crate::error::OrchestratorError;
use crate::types::Message;

/// Abstraction over LLM providers (OpenAI, OpenRouter, etc.).
///
/// Implementations convert their internal errors into
/// `OrchestratorError::LlmError { message }`.
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// Send a chat completion request and return the assistant's response text.
    ///
    /// Used for PLLM code generation (free-form text response containing Python code).
    async fn chat_completion(
        &self,
        messages: &[Message],
    ) -> Result<String, OrchestratorError>;

    /// Send a chat completion request with a structured JSON output schema.
    ///
    /// Used for QLLM data extraction (structured JSON response matching the schema).
    async fn chat_completion_with_schema(
        &self,
        system_prompt: &str,
        user_message: &str,
        output_schema: &serde_json::Value,
    ) -> Result<serde_json::Value, OrchestratorError>;
}

/// Abstraction over tool execution (the host provides implementations).
///
/// Implementations convert their internal errors into
/// `OrchestratorError::ToolError { tool_name, message }`.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    /// Execute a tool with the given named arguments and return the JSON result.
    ///
    /// The arguments are ordered (IndexMap) and each carries metadata via `ValueWithMeta`.
    /// The executor should use only the `.value` fields; metadata is for the interpreter.
    async fn execute(
        &self,
        tool_name: &str,
        args: &IndexMap<String, ValueWithMeta<serde_json::Value>>,
    ) -> Result<serde_json::Value, OrchestratorError>;
}
