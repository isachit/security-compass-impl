//! Concrete LLM client implementation using reqwest and the OpenAI-compatible API.
//!
//! [`OpenAiLlmClient`] connects to OpenAI, OpenRouter, or any OpenAI-compatible
//! provider and implements the orchestrator's [`LlmClient`] trait.

use async_trait::async_trait;
use serde_json::json;

use security_compass_orchestrator::{LlmClient, Message, OrchestratorError};

/// A concrete LLM client that uses reqwest to call OpenAI-compatible APIs.
///
/// Supports multiple providers via different base URLs:
/// - "openai" -> `https://api.openai.com/v1`
/// - "openrouter" -> `https://openrouter.ai/api/v1`
/// - default -> OpenAI
pub struct OpenAiLlmClient {
    /// The reqwest HTTP client.
    http_client: reqwest::Client,
    /// The API key for the LLM provider.
    api_key: String,
    /// The base URL for the LLM API.
    base_url: String,
    /// Model identifier for the PLLM (used in chat_completion).
    pllm_model: String,
    /// Model identifier for the QLLM (used in chat_completion_with_schema).
    qllm_model: String,
}

impl OpenAiLlmClient {
    /// Creates a new LLM client for the given provider.
    ///
    /// # Supported providers
    ///
    /// | Provider | Base URL |
    /// |----------|----------|
    /// | `"openai"` | `https://api.openai.com/v1` |
    /// | `"openrouter"` | `https://openrouter.ai/api/v1` |
    /// | anything else | `https://api.openai.com/v1` |
    pub fn for_provider(
        provider: &str,
        api_key: String,
        pllm_model: String,
        qllm_model: String,
    ) -> Self {
        let base_url = match provider {
            "openai" => "https://api.openai.com/v1".to_string(),
            "openrouter" => "https://openrouter.ai/api/v1".to_string(),
            _ => "https://api.openai.com/v1".to_string(),
        };

        Self {
            http_client: reqwest::Client::new(),
            api_key,
            base_url,
            pllm_model,
            qllm_model,
        }
    }

    /// Returns the base URL for the LLM API.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Formats messages for the OpenAI API request body.
    fn format_messages(messages: &[Message]) -> Vec<serde_json::Value> {
        messages
            .iter()
            .map(|msg| {
                json!({
                    "role": msg.role,
                    "content": msg.content,
                })
            })
            .collect()
    }

    /// Extracts the assistant message content from an OpenAI response body.
    fn extract_content(body: &serde_json::Value) -> Result<String, OrchestratorError> {
        body.get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| OrchestratorError::LlmError {
                message: "Missing choices[0].message.content in LLM response".to_string(),
            })
    }
}

#[async_trait]
impl LlmClient for OpenAiLlmClient {
    /// Sends a chat completion request to the PLLM and returns the assistant's
    /// response text.
    async fn chat_completion(
        &self,
        messages: &[Message],
    ) -> Result<String, OrchestratorError> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = json!({
            "model": self.pllm_model,
            "messages": Self::format_messages(messages),
        });

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::LlmError {
                message: format!("HTTP request failed: {e}"),
            })?;

        let status = response.status();
        let response_body: serde_json::Value =
            response.json().await.map_err(|e| OrchestratorError::LlmError {
                message: format!("Failed to parse LLM response body: {e}"),
            })?;

        if !status.is_success() {
            let error_msg = response_body
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            return Err(OrchestratorError::LlmError {
                message: format!("LLM API returned {status}: {error_msg}"),
            });
        }

        Self::extract_content(&response_body)
    }

    /// Sends a chat completion request with a structured JSON output schema
    /// to the QLLM and returns the parsed JSON result.
    async fn chat_completion_with_schema(
        &self,
        system_prompt: &str,
        user_message: &str,
        output_schema: &serde_json::Value,
    ) -> Result<serde_json::Value, OrchestratorError> {
        let url = format!("{}/chat/completions", self.base_url);
        let messages = vec![
            json!({ "role": "system", "content": system_prompt }),
            json!({ "role": "user", "content": user_message }),
        ];

        let body = json!({
            "model": self.qllm_model,
            "messages": messages,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "extraction",
                    "schema": output_schema,
                    "strict": true,
                }
            }
        });

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::LlmError {
                message: format!("HTTP request failed: {e}"),
            })?;

        let status = response.status();
        let response_body: serde_json::Value =
            response.json().await.map_err(|e| OrchestratorError::LlmError {
                message: format!("Failed to parse LLM response body: {e}"),
            })?;

        if !status.is_success() {
            let error_msg = response_body
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            return Err(OrchestratorError::LlmError {
                message: format!("LLM API returned {status}: {error_msg}"),
            });
        }

        let content_str = Self::extract_content(&response_body)?;

        // Parse the content string as JSON.
        serde_json::from_str(&content_str).map_err(|e| OrchestratorError::LlmError {
            message: format!("Failed to parse structured LLM response as JSON: {e}"),
        })
    }
}
