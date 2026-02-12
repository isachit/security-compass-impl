//! Security Compass Server — HTTP API layer for the dual-LLM orchestrator.
//!
//! This crate wraps the [`security_compass_orchestrator`] in an axum HTTP
//! server providing OpenAI-compatible chat completion endpoints. It:
//!
//! - Parses security headers (`X-Security-Features`, `X-Security-Policy`,
//!   `X-Security-Config`)
//! - Manages sessions with TTL-based expiration
//! - Compiles SQRT policies from header values
//! - Maps header configuration to [`SessionConfig`] and [`InterpreterConfig`]
//! - Provides a concrete reqwest-based [`LlmClient`] for OpenAI/OpenRouter
//! - Returns structured responses in the [`ChatCompletionResponse`] format
//!
//! # Architecture
//!
//! ```text
//! HTTP Request
//!   -> parse_headers()
//!   -> build_session_config() + build_interpreter_config()
//!   -> compile_policy()
//!   -> Session::process_turn()
//!   -> build_response()
//! HTTP Response
//! ```

pub mod config;
pub mod error;
pub mod handler;
pub mod headers;
pub mod llm_client;
pub mod message;
pub mod policy;
pub mod session_store;
pub mod tool_executor;
pub mod types;

// Public re-exports for convenient access from tests and other crates.
pub use config::{build_interpreter_config, build_session_config};
pub use error::ServerError;
pub use handler::{
    build_response, handle_chat_completions, handle_chat_completions_default,
    handle_langgraph_stub, AppState,
};
pub use headers::{parse_headers, ParsedHeaders};
pub use llm_client::OpenAiLlmClient;
pub use message::{extract_messages, ExtractedMessages};
pub use policy::compile_policy;
pub use session_store::SessionStore;
pub use tool_executor::{EchoToolExecutor, NoOpToolExecutor};
pub use types::headers::{
    FeaturesHeader, FineGrainedConfigHeader, SecurityPolicyHeader,
};
pub use types::request::ChatCompletionRequest;
pub use types::response::{ChatCompletionResponse, ResponseContentJsonSchema};

#[cfg(test)]
mod tests;
