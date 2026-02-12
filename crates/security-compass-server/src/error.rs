//! Error types for the Security Compass Server.
//!
//! Defines [`ServerError`], which wraps all error conditions that can occur
//! while processing an HTTP request. Each variant maps to an appropriate
//! HTTP status code and produces an OpenAI-compatible error JSON body.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Errors that can occur while processing an HTTP request.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The `Authorization` header is missing or does not match the configured key.
    #[error("Unauthorized: missing or invalid API key")]
    Unauthorized,

    /// The `X-Api-Key` header (LLM provider key) is absent.
    #[error("Missing X-Api-Key header for LLM provider")]
    MissingApiKey,

    /// A request header contained invalid data.
    #[error("Invalid header {header}: {detail}")]
    InvalidHeader {
        /// Name of the offending header.
        header: String,
        /// What went wrong when parsing.
        detail: String,
    },

    /// The request body could not be deserialized.
    #[error("Invalid request body: {detail}")]
    InvalidRequestBody {
        /// Deserialization failure detail.
        detail: String,
    },

    /// No user-role message was found in the request.
    #[error("No user message found in request")]
    NoUserMessage,

    /// A session ID was supplied but could not be found (or has expired).
    #[error("Session not found")]
    SessionNotFound,

    /// The SQRT policy source failed to parse or compile.
    #[error("Policy compile error: {detail}")]
    PolicyCompileError {
        /// Parse or compile error detail.
        detail: String,
    },

    /// A requested feature is not yet supported (e.g. streaming, Cedar).
    #[error("Unsupported feature: {feature}")]
    UnsupportedFeature {
        /// Name of the unsupported feature.
        feature: String,
    },

    /// An error propagated from the orchestrator layer.
    #[error("Orchestrator error: {detail}")]
    OrchestratorError {
        /// Description of the orchestrator failure.
        detail: String,
    },

    /// A catch-all for unexpected internal failures.
    #[error("Internal server error: {detail}")]
    InternalError {
        /// What went wrong internally.
        detail: String,
    },
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, error_type) = match &self {
            ServerError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ServerError::MissingApiKey => (StatusCode::BAD_REQUEST, "missing_api_key"),
            ServerError::InvalidHeader { .. } => (StatusCode::BAD_REQUEST, "invalid_header"),
            ServerError::InvalidRequestBody { .. } => {
                (StatusCode::BAD_REQUEST, "invalid_request_body")
            }
            ServerError::NoUserMessage => (StatusCode::BAD_REQUEST, "no_user_message"),
            ServerError::SessionNotFound => (StatusCode::NOT_FOUND, "session_not_found"),
            ServerError::PolicyCompileError { .. } => {
                (StatusCode::BAD_REQUEST, "policy_compile_error")
            }
            ServerError::UnsupportedFeature { .. } => {
                (StatusCode::BAD_REQUEST, "unsupported_feature")
            }
            ServerError::OrchestratorError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "orchestrator_error")
            }
            ServerError::InternalError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };

        let body = json!({
            "error": {
                "message": self.to_string(),
                "type": error_type,
                "code": status.as_u16(),
            }
        });

        (status, axum::Json(body)).into_response()
    }
}
