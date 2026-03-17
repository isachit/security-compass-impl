//! Axum request handlers for the Security Compass HTTP API.
//!
//! Provides the main chat completion handler, response building,
//! and the shared application state.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use uuid::Uuid;

use security_compass_orchestrator::{Session, ToolDefinition, TurnResult, TurnStatus};

use crate::config::{build_interpreter_config, build_session_config};
use crate::error::ServerError;
use crate::headers::{parse_headers, ParsedHeaders};
use crate::llm_client::OpenAiLlmClient;
use crate::message::extract_messages;
use crate::policy::compile_policy;
use crate::session_store::SessionStore;
use crate::tool_executor::NoOpToolExecutor;
use crate::types::headers::SecurityPolicyHeader;
use crate::types::request::{ChatCompletionRequest, FunctionTool};
use crate::types::response::{
    ChatCompletionResponse, Choice, CompletionUsage, ErrorInfo, FinishReason, ResponseContentJsonSchema,
    ResponseMessage, ResponseStatus,
};

// ============================================================
// Application State
// ============================================================

/// Shared application state for all axum handlers.
pub struct AppState {
    /// The in-memory session store.
    pub session_store: SessionStore,
    /// Optional server-level API key for authenticating incoming requests.
    pub server_api_key: Option<String>,
}

// ============================================================
// Route Handlers
// ============================================================

/// Handler for `POST /control/v1/chat/completions` (default provider = "openai").
pub async fn handle_chat_completions_default(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ChatCompletionRequest>,
) -> impl IntoResponse {
    handle_chat_completions_inner(&state, &headers, request, "openai").await
}

/// Handler for `POST /control/{provider}/v1/chat/completions`.
pub async fn handle_chat_completions(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ChatCompletionRequest>,
) -> impl IntoResponse {
    handle_chat_completions_inner(&state, &headers, request, &provider).await
}

/// Handler for `POST /control/lang-graph/{provider}/v1/chat/completions`.
///
/// Returns 501 Not Implemented — LangGraph integration is out of scope
/// for this phase.
pub async fn handle_langgraph_stub(
    Path(_provider): Path<String>,
) -> impl IntoResponse {
    let body = serde_json::json!({
        "error": {
            "message": "LangGraph endpoint is not yet implemented",
            "type": "unsupported_feature",
            "code": 501,
        }
    });
    (StatusCode::NOT_IMPLEMENTED, Json(body))
}

// ============================================================
// Core Handler Logic
// ============================================================

/// Inner handler that processes a chat completion request.
///
/// This is the central flow:
/// 1. Authenticate
/// 2. Parse headers
/// 3. Validate LLM API key
/// 4. Apply defaults for missing headers
/// 5. Determine PLLM/QLLM models
/// 6. Build configs
/// 7. Extract tools
/// 8. Extract messages
/// 9. Reject streaming
/// 10. Get or create session
/// 11. Build LLM client
/// 12. Build tool executor
/// 13. Process turn
/// 14. Build response
async fn handle_chat_completions_inner(
    state: &AppState,
    headers: &HeaderMap,
    request: ChatCompletionRequest,
    provider: &str,
) -> Result<impl IntoResponse, ServerError> {
    // 1. Authenticate: check Authorization header against server_api_key.
    let parsed = parse_headers(headers)?;
    authenticate(state, &parsed)?;

    // 2. Validate LLM API key.
    let api_key = parsed.api_key.clone().ok_or(ServerError::MissingApiKey)?;

    // Extract session_id before consuming parsed fields.
    let existing_session_id = parsed.session_id;

    // 3. Apply defaults for missing headers.
    let config_header = parsed.config.unwrap_or_default();
    let policy_header = parsed.security_policy.unwrap_or_default();

    // 4. Determine PLLM/QLLM model names.
    let pllm_model = request.model.clone();
    let qllm_model = derive_qllm_model(&pllm_model);

    // 5. Build orchestrator configs.
    let session_config = build_session_config(&config_header, pllm_model.clone(), qllm_model.clone());
    let interpreter_config = build_interpreter_config(&config_header, Some(&policy_header));

    // 6. Extract tool definitions from the request.
    let tool_definitions = extract_tool_definitions(&request.tools);

    // 7. Extract messages.
    let extracted = extract_messages(
        &request.messages,
        config_header.merge_system_messages,
        &config_header.include_other_roles_in_user_query,
    )?;

    // 8. Reject streaming.
    if request.stream == Some(true) {
        return Err(ServerError::UnsupportedFeature {
            feature: "streaming (stream: true)".to_string(),
        });
    }

    // 9. Get or create session.
    let (session_id, turn_result) = process_with_session(
        state,
        existing_session_id,
        &policy_header,
        session_config,
        interpreter_config,
        tool_definitions,
        &extracted.user_query,
        provider,
        &api_key,
        &pllm_model,
        &qllm_model,
    )
    .await?;

    // 10. Build and return the response.
    let response = build_response(&turn_result, &pllm_model, &session_id);
    let session_id_str = session_id.to_string();

    Ok((
        [(
            axum::http::header::HeaderName::from_static("x-session-id"),
            axum::http::header::HeaderValue::from_str(&session_id_str)
                .unwrap_or_else(|_| axum::http::header::HeaderValue::from_static("")),
        )],
        Json(response),
    ))
}

/// Authenticates the request against the server's API key.
fn authenticate(state: &AppState, parsed: &ParsedHeaders) -> Result<(), ServerError> {
    if let Some(ref expected_key) = state.server_api_key {
        match &parsed.auth_token {
            Some(token) if token == expected_key => Ok(()),
            _ => Err(ServerError::Unauthorized),
        }
    } else {
        // No server API key configured — all requests are allowed.
        Ok(())
    }
}

/// Derives the QLLM model name from the PLLM model.
///
/// Heuristic: if the PLLM model starts with "gpt-4", use "gpt-4o-mini"
/// as the QLLM model. Otherwise, use the same model.
fn derive_qllm_model(pllm_model: &str) -> String {
    if pllm_model.starts_with("gpt-4") {
        "gpt-4o-mini".to_string()
    } else {
        pllm_model.to_string()
    }
}

/// Extracts [`ToolDefinition`] instances from the request's tool list.
///
/// Parameter names are extracted from the JSON Schema `properties` keys
/// in each function definition.
fn extract_tool_definitions(tools: &Option<Vec<FunctionTool>>) -> Vec<ToolDefinition> {
    match tools {
        None => Vec::new(),
        Some(tool_list) => tool_list
            .iter()
            .map(|ft| {
                let parameter_names = ft
                    .function
                    .parameters
                    .as_ref()
                    .and_then(|p| p.get("properties"))
                    .and_then(|p| p.as_object())
                    .map(|obj| obj.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();

                ToolDefinition {
                    name: ft.function.name.clone(),
                    parameter_names,
                    deterministic: false,
                }
            })
            .collect(),
    }
}

/// Gets an existing session or creates a new one, then processes a turn.
#[allow(clippy::too_many_arguments)]
async fn process_with_session(
    state: &AppState,
    existing_session_id: Option<Uuid>,
    policy_header: &SecurityPolicyHeader,
    session_config: security_compass_orchestrator::SessionConfig,
    interpreter_config: security_compass_orchestrator::InterpreterConfig,
    tool_definitions: Vec<ToolDefinition>,
    user_query: &str,
    provider: &str,
    api_key: &str,
    pllm_model: &str,
    qllm_model: &str,
) -> Result<(Uuid, TurnResult), ServerError> {
    let llm_client = OpenAiLlmClient::for_provider(
        provider,
        api_key.to_string(),
        pllm_model.to_string(),
        qllm_model.to_string(),
    );
    let tool_executor = NoOpToolExecutor;

    // Try to get an existing session.
    if let Some(session_id) = existing_session_id {
        if let Some(mut entry) = state.session_store.get_mut(&session_id) {
            let result = entry
                .session
                .process_turn(user_query, &llm_client, &tool_executor)
                .await
                .map_err(|e| ServerError::OrchestratorError {
                    detail: e.to_string(),
                })?;
            return Ok((session_id, result));
        }
        // Session not found or expired — fall through to create a new one.
    }

    // Create a new session.
    let policy = compile_policy(policy_header)?;
    let mut session = Session::new(policy, session_config, interpreter_config, tool_definitions);

    let result = session
        .process_turn(user_query, &llm_client, &tool_executor)
        .await
        .map_err(|e| ServerError::OrchestratorError {
            detail: e.to_string(),
        })?;

    let session_id = state.session_store.insert(session);
    Ok((session_id, result))
}

// ============================================================
// Response Building
// ============================================================

/// Builds a [`ChatCompletionResponse`] from a [`TurnResult`].
pub fn build_response(
    turn_result: &TurnResult,
    model: &str,
    session_id: &Uuid,
) -> ChatCompletionResponse {
    let (status, finish_reason) = match turn_result.status {
        TurnStatus::Success => (ResponseStatus::Success, FinishReason::Stop),
        TurnStatus::Error | TurnStatus::MaxAttemptsExceeded => {
            (ResponseStatus::Failure, FinishReason::ContentFilter)
        }
        TurnStatus::ClarificationNeeded => (ResponseStatus::Unknown, FinishReason::Stop),
    };

    let error_info = turn_result.error.as_ref().map(|msg| ErrorInfo {
        message: msg.clone(),
        code: Some(format!("{:?}", turn_result.status)),
    });

    // Build the structured content.
    let content_schema = ResponseContentJsonSchema {
        status,
        final_return_value: turn_result.final_return_value.clone(),
        error: error_info,
        program: turn_result.program.clone(),
        namespace_screenshot: None,
        raw: serde_json::to_value(turn_result).ok(),
    };

    // Serialize the structured content as a JSON string.
    let content_str = serde_json::to_string(&content_schema).unwrap_or_else(|_| "{}".to_string());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    ChatCompletionResponse {
        id: format!("chatcmpl-{}", Uuid::new_v4()),
        choices: vec![Choice {
            finish_reason,
            index: 0,
            message: ResponseMessage {
                role: "assistant".to_string(),
                content: Some(content_str),
            },
        }],
        created: now,
        model: model.to_string(),
        object: "chat.completion".to_string(),
        usage: Some(CompletionUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        }),
        session_id: Some(session_id.to_string()),
    }
}
