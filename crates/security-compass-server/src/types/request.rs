//! Request types for the OpenAI-compatible chat completion API.
//!
//! These types model the JSON body of `POST /control/.../v1/chat/completions`.
//! They match the OpenAI API specification and the Python reference implementation.

use serde::{Deserialize, Serialize};

// ============================================================
// ChatCompletionRequest
// ============================================================

/// The top-level request body for a chat completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    /// The list of conversation messages.
    pub messages: Vec<RequestMessage>,
    /// The model identifier (e.g. "gpt-4o", "gpt-4o-mini").
    pub model: String,
    /// Optional reasoning effort hint.
    #[serde(default)]
    pub reasoning_effort: Option<String>,
    /// Optional response format specification.
    #[serde(default)]
    pub response_format: Option<RequestResponseFormat>,
    /// Optional seed for reproducibility.
    #[serde(default)]
    pub seed: Option<u64>,
    /// Whether to stream the response.
    #[serde(default)]
    pub stream: Option<bool>,
    /// Sampling temperature (0.0 - 2.0).
    #[serde(default)]
    pub temperature: Option<f64>,
    /// Available tools (function definitions).
    #[serde(default)]
    pub tools: Option<Vec<FunctionTool>>,
    /// Nucleus sampling parameter.
    #[serde(default)]
    pub top_p: Option<f64>,
}

// ============================================================
// RequestMessage (discriminated union by "role")
// ============================================================

/// A message in the chat completion request, discriminated by `role`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role")]
pub enum RequestMessage {
    /// A developer-role message (treated like system).
    #[serde(rename = "developer")]
    Developer {
        /// The text content.
        content: String,
        /// Optional sender name.
        #[serde(default)]
        name: Option<String>,
    },

    /// A system-role message.
    #[serde(rename = "system")]
    System {
        /// The text content.
        content: String,
        /// Optional sender name.
        #[serde(default)]
        name: Option<String>,
    },

    /// A user-role message with flexible content (text or parts).
    #[serde(rename = "user")]
    User {
        /// The content (text string or multimodal parts array).
        content: UserContent,
        /// Optional sender name.
        #[serde(default)]
        name: Option<String>,
    },

    /// An assistant-role message (model output).
    #[serde(rename = "assistant")]
    Assistant {
        /// The text content (may be null if tool_calls present).
        #[serde(default)]
        content: Option<String>,
        /// Optional sender name.
        #[serde(default)]
        name: Option<String>,
        /// Tool calls the assistant wants to make.
        #[serde(default)]
        tool_calls: Option<Vec<AssistantToolCall>>,
    },

    /// A tool-role message (tool result).
    #[serde(rename = "tool")]
    Tool {
        /// The tool result content.
        content: String,
        /// The ID of the tool call this is responding to.
        tool_call_id: String,
    },

    /// A function-role message (deprecated, legacy function calling).
    #[serde(rename = "function")]
    Function {
        /// The function result content.
        content: String,
        /// The function name.
        name: String,
    },
}

// ============================================================
// User Content (text or multimodal parts)
// ============================================================

/// User message content: either a plain text string or an array of
/// multimodal content parts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserContent {
    /// Plain text content.
    Text(String),
    /// Array of content parts (text, image, etc.).
    Parts(Vec<ContentPart>),
}

impl UserContent {
    /// Extracts the text content, concatenating all text parts if multimodal.
    pub fn as_text(&self) -> String {
        match self {
            UserContent::Text(s) => s.clone(),
            UserContent::Parts(parts) => parts
                .iter()
                .filter_map(|p| match p {
                    ContentPart::Text { text } => Some(text.as_str()),
                    ContentPart::ImageUrl { .. } => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

/// A single content part in a multimodal user message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    /// A text content part.
    #[serde(rename = "text")]
    Text {
        /// The text content.
        text: String,
    },
    /// An image URL content part.
    #[serde(rename = "image_url")]
    ImageUrl {
        /// The image URL details.
        image_url: ImageUrl,
    },
}

/// Image URL details within a content part.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    /// The URL of the image.
    pub url: String,
    /// Optional detail level for the image.
    #[serde(default)]
    pub detail: Option<String>,
}

// ============================================================
// Tool Calls (in assistant messages)
// ============================================================

/// A tool call requested by the assistant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantToolCall {
    /// Unique identifier for this tool call.
    pub id: String,
    /// The type of tool call (always "function").
    #[serde(rename = "type")]
    pub call_type: String,
    /// The function to call.
    pub function: AssistantFunctionCall,
}

/// A function call within an assistant tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantFunctionCall {
    /// The function name.
    pub name: String,
    /// The function arguments as a JSON string.
    pub arguments: String,
}

// ============================================================
// Tool Definitions (in request.tools)
// ============================================================

/// A tool available for the model to call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTool {
    /// The tool type (always "function").
    #[serde(rename = "type")]
    pub tool_type: String,
    /// The function definition.
    pub function: FunctionDefinition,
}

/// Definition of a callable function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// The function name.
    pub name: String,
    /// A description of what the function does.
    #[serde(default)]
    pub description: Option<String>,
    /// JSON Schema describing the function parameters.
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    /// Whether to enforce strict schema validation.
    #[serde(default)]
    pub strict: Option<bool>,
}

// ============================================================
// Request Response Format
// ============================================================

/// Response format specification in the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponseFormat {
    /// The format type (e.g. "text", "json_object", "json_schema").
    #[serde(rename = "type")]
    pub format_type: String,
    /// Optional JSON schema for structured output.
    #[serde(default)]
    pub json_schema: Option<serde_json::Value>,
}
