//! Tool executor implementations for the Security Compass Server.
//!
//! Provides two executor implementations:
//! - [`NoOpToolExecutor`] — Returns an error for every tool call (production default).
//! - [`EchoToolExecutor`] — Echoes the tool call arguments back (for testing).

use async_trait::async_trait;
use indexmap::IndexMap;
use security_compass_meta::ValueWithMeta;
use security_compass_orchestrator::{OrchestratorError, ToolExecutor};

/// A tool executor that rejects every tool call with an error.
///
/// This is the default executor when no external tool backend is
/// configured. PLLM-generated code that calls external tools will
/// get an error message, which may trigger a retry.
pub struct NoOpToolExecutor;

#[async_trait]
impl ToolExecutor for NoOpToolExecutor {
    async fn execute(
        &self,
        tool_name: &str,
        _args: &IndexMap<String, ValueWithMeta<serde_json::Value>>,
    ) -> Result<serde_json::Value, OrchestratorError> {
        Err(OrchestratorError::ToolError {
            tool_name: tool_name.to_string(),
            message: "No tool execution backend configured".to_string(),
        })
    }
}

/// A tool executor that echoes the tool call back as JSON.
///
/// Returns a JSON object containing the tool name, argument values,
/// and a `"status": "echoed"` marker. Useful for integration testing
/// without a real tool backend.
pub struct EchoToolExecutor;

#[async_trait]
impl ToolExecutor for EchoToolExecutor {
    async fn execute(
        &self,
        tool_name: &str,
        args: &IndexMap<String, ValueWithMeta<serde_json::Value>>,
    ) -> Result<serde_json::Value, OrchestratorError> {
        let args_values: serde_json::Map<String, serde_json::Value> = args
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect();

        Ok(serde_json::json!({
            "tool": tool_name,
            "args": args_values,
            "status": "echoed",
        }))
    }
}
