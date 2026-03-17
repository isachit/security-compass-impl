//! Response types for the OpenAI-compatible chat completion API.
//!
//! These types model the JSON body returned from the chat completion endpoint.
//! They include both standard OpenAI fields and Security Compass extensions
//! (e.g. `session_id`, `ResponseContentJsonSchema`).

use serde::{Deserialize, Serialize};

// ============================================================
// ChatCompletionResponse
// ============================================================

/// The top-level response body for a chat completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    /// Unique response identifier (e.g. "chatcmpl-...").
    pub id: String,
    /// The list of completion choices.
    pub choices: Vec<Choice>,
    /// Unix timestamp of when the response was created.
    pub created: i64,
    /// The model used for the completion.
    pub model: String,
    /// The object type (always "chat.completion").
    pub object: String,
    /// Token usage statistics (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<CompletionUsage>,
    /// Security Compass session ID for conversation continuity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

// ============================================================
// Choice
// ============================================================

/// A single completion choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// The reason the model stopped generating (e.g. "stop", "content_filter").
    pub finish_reason: FinishReason,
    /// The index of this choice.
    pub index: u32,
    /// The assistant's response message.
    pub message: ResponseMessage,
}

/// Reason the model stopped generating tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// Natural stop (end of response or stop token).
    Stop,
    /// Maximum token limit reached.
    Length,
    /// Content was filtered by policy.
    ContentFilter,
    /// The model wants to call a tool.
    ToolCalls,
}

// ============================================================
// ResponseMessage
// ============================================================

/// The assistant's response message within a choice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMessage {
    /// The role (always "assistant").
    pub role: String,
    /// The text content (JSON string for structured, plain text otherwise).
    pub content: Option<String>,
}

// ============================================================
// Token Usage
// ============================================================

/// Token usage statistics for a completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionUsage {
    /// Number of tokens in the prompt.
    pub prompt_tokens: u32,
    /// Number of tokens in the completion.
    pub completion_tokens: u32,
    /// Total tokens used.
    pub total_tokens: u32,
}

// ============================================================
// Security Compass Structured Content
// ============================================================

/// Structured JSON content for Security Compass responses.
///
/// This is serialized as a JSON string and placed in
/// `ResponseMessage.content`. It contains the full execution result
/// including status, return value, errors, program, and debug info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseContentJsonSchema {
    /// Execution status.
    pub status: ResponseStatus,
    /// The final return value (if successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_return_value: Option<serde_json::Value>,
    /// Error details (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    /// The PLLM-generated program that was executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// A snapshot of the namespace state after execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_screenshot: Option<serde_json::Value>,
    /// Raw turn result data for debugging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Execution status of the Security Compass response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseStatus {
    /// The turn completed successfully.
    Success,
    /// The turn failed with an error.
    Failure,
    /// The status is indeterminate (e.g. clarification needed).
    Unknown,
}

/// Error information in a structured response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Human-readable error message.
    pub message: String,
    /// Error code or category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}
