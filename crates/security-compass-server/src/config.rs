//! Configuration mapping: header types to orchestrator config types.
//!
//! Converts the JSON-deserialized header structs into the concrete
//! configuration types used by the orchestrator and interpreter.

use security_compass_orchestrator::{
    CacheMode, ClearSessionMeta, DebugInfoLevel, InternalTool, InterpreterConfig,
    ResponseFormatConfig, SecureVarVisibility, SessionConfig,
};

use crate::types::headers::{
    CacheToolResultStr, ClearSessionMetaStr, DebugInfoLevelStr, FineGrainedConfigHeader,
    InternalToolStr, SecureVarVisibilityStr, SecurityPolicyHeader,
};

/// Builds a [`SessionConfig`] from the fine-grained config header and model names.
///
/// Maps header string enum values to their orchestrator counterparts and
/// applies all header defaults.
pub fn build_session_config(
    config_header: &FineGrainedConfigHeader,
    pllm_model: String,
    qllm_model: String,
) -> SessionConfig {
    SessionConfig {
        max_n_turns: config_header.max_n_turns,
        max_pllm_attempts: config_header.max_pllm_attempts,
        clear_session_meta: map_clear_session_meta(&config_header.clear_session_meta),
        pllm_model,
        qllm_model,
        pllm_debug_info_level: map_debug_info_level(&config_header.pllm_debug_info_level),
        show_pllm_secure_var_values: map_secure_var_visibility(
            &config_header.show_pllm_secure_var_values,
        ),
        pllm_can_ask_for_clarification: config_header.pllm_can_ask_for_clarification,
        enable_multi_step_planning: config_header.enable_multi_step_planning,
        prune_failed_steps: config_header.prune_failed_steps,
        enabled_internal_tools: config_header
            .enabled_internal_tools
            .iter()
            .map(map_internal_tool)
            .collect(),
        response_format: ResponseFormatConfig {
            structured: config_header.response_format.structured,
            include_debug: config_header.response_format.include_debug,
        },
        disable_rllm: config_header.disable_rllm,
        rllm_confidence_threshold: config_header.rllm_confidence_score_threshold,
    }
}

/// Builds an [`InterpreterConfig`] from the fine-grained config header and
/// optional security policy header.
///
/// The `fail_fast` field is sourced from the security policy header if present.
/// The `max_tool_calls_per_attempt` defaults to 200 from the config header.
pub fn build_interpreter_config(
    config_header: &FineGrainedConfigHeader,
    policy_header: Option<&SecurityPolicyHeader>,
) -> InterpreterConfig {
    let fail_fast = policy_header
        .and_then(|p| p.fail_fast)
        .unwrap_or(false);

    InterpreterConfig {
        max_tool_calls_per_attempt: config_header.max_tool_calls_per_attempt.unwrap_or(200),
        cache_tool_result: map_cache_mode(&config_header.cache_tool_result),
        gas_limit: 0,
        fail_fast,
    }
}

// ============================================================
// Mapping Functions
// ============================================================

/// Maps [`CacheToolResultStr`] to [`CacheMode`].
fn map_cache_mode(s: &CacheToolResultStr) -> CacheMode {
    match s {
        CacheToolResultStr::None => CacheMode::None,
        CacheToolResultStr::All => CacheMode::All,
        CacheToolResultStr::DeterministicOnly => CacheMode::DeterministicOnly,
    }
}

/// Maps [`ClearSessionMetaStr`] to [`ClearSessionMeta`].
fn map_clear_session_meta(s: &ClearSessionMetaStr) -> ClearSessionMeta {
    match s {
        ClearSessionMetaStr::Never => ClearSessionMeta::Never,
        ClearSessionMetaStr::EveryAttempt => ClearSessionMeta::EveryAttempt,
        ClearSessionMetaStr::EveryTurn => ClearSessionMeta::EveryTurn,
    }
}

/// Maps [`DebugInfoLevelStr`] to [`DebugInfoLevel`].
fn map_debug_info_level(s: &DebugInfoLevelStr) -> DebugInfoLevel {
    match s {
        DebugInfoLevelStr::Minimal => DebugInfoLevel::Minimal,
        DebugInfoLevelStr::Normal => DebugInfoLevel::Normal,
        DebugInfoLevelStr::Extra => DebugInfoLevel::Extra,
    }
}

/// Maps [`SecureVarVisibilityStr`] to [`SecureVarVisibility`].
fn map_secure_var_visibility(s: &SecureVarVisibilityStr) -> SecureVarVisibility {
    match s {
        SecureVarVisibilityStr::None => SecureVarVisibility::None,
        SecureVarVisibilityStr::BasicNoText => SecureVarVisibility::BasicNoText,
        SecureVarVisibilityStr::BasicExecutable => SecureVarVisibility::BasicExecutable,
        SecureVarVisibilityStr::AllExecutable => SecureVarVisibility::AllExecutable,
    }
}

/// Maps [`InternalToolStr`] to [`InternalTool`].
fn map_internal_tool(s: &InternalToolStr) -> InternalTool {
    match s {
        InternalToolStr::ParseWithAi => InternalTool::ParseWithAi,
        InternalToolStr::VerifyHypothesis => InternalTool::VerifyHypothesis,
    }
}
