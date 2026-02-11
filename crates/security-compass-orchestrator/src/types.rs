//! Type definitions for the Security Compass Orchestrator.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use security_compass_interpreter::{Interpreter, InterpreterConfig, ToolDefinition};
use security_compass_meta::Metadata;
use sqrt_eval::CompiledPolicy;

use crate::error::OrchestratorError;

// ============================================================
// Message Types (OpenAI-compatible)
// ============================================================

/// A chat message in the OpenAI-compatible format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The role of the message sender.
    pub role: Role,
    /// The text content of the message.
    pub content: String,
}

impl Message {
    /// Creates a new message with the given role and content.
    pub fn new(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }

    /// Creates a system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(Role::System, content)
    }

    /// Creates a user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::new(Role::User, content)
    }

    /// Creates an assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(Role::Assistant, content)
    }
}

/// The role of a message sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System prompt / instructions.
    System,
    /// User input (trusted).
    User,
    /// Assistant response (PLLM output).
    Assistant,
}

// ============================================================
// Session Configuration
// ============================================================

/// Configuration for a session's behavior.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum turns before the session is auto-terminated. None = unlimited.
    pub max_n_turns: Option<u32>,
    /// Maximum PLLM retry attempts per turn (for retryable errors).
    pub max_pllm_attempts: u32,
    /// When to clear session metadata.
    pub clear_session_meta: ClearSessionMeta,
    /// Model identifier for the PLLM.
    pub pllm_model: String,
    /// Model identifier for the QLLM.
    pub qllm_model: String,
    /// How much debug info to include in PLLM error feedback.
    pub pllm_debug_info_level: DebugInfoLevel,
    /// Whether the PLLM can see secure variable values in system prompts.
    pub show_pllm_secure_var_values: SecureVarVisibility,
    /// Whether the PLLM can respond with a clarification request instead of code.
    pub pllm_can_ask_for_clarification: bool,
    /// Whether to enable multi-step planning mode.
    pub enable_multi_step_planning: bool,
    /// Whether to prune previously failed PLLM attempts from the conversation context.
    pub prune_failed_steps: bool,
    /// Which internal tools (parse_with_ai, verify_hypothesis) are enabled.
    pub enabled_internal_tools: Vec<InternalTool>,
    /// Response format configuration.
    pub response_format: ResponseFormatConfig,
    /// Whether to disable the RLLM (response review LLM) entirely.
    pub disable_rllm: bool,
    /// Confidence threshold for RLLM responses.
    pub rllm_confidence_threshold: Option<f64>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_n_turns: None,
            max_pllm_attempts: 3,
            clear_session_meta: ClearSessionMeta::Never,
            pllm_model: "gpt-4".to_string(),
            qllm_model: "gpt-4".to_string(),
            pllm_debug_info_level: DebugInfoLevel::Normal,
            show_pllm_secure_var_values: SecureVarVisibility::None,
            pllm_can_ask_for_clarification: true,
            enable_multi_step_planning: false,
            prune_failed_steps: true,
            enabled_internal_tools: vec![
                InternalTool::ParseWithAi,
                InternalTool::VerifyHypothesis,
            ],
            response_format: ResponseFormatConfig::default(),
            disable_rllm: true,
            rllm_confidence_threshold: None,
        }
    }
}

// ============================================================
// Configuration Enums
// ============================================================

/// Controls when session metadata is cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClearSessionMeta {
    /// Never clear session metadata between turns or attempts.
    Never,
    /// Clear session metadata before every PLLM attempt within a turn.
    EveryAttempt,
    /// Clear session metadata at the start of every turn.
    EveryTurn,
}

/// Controls how much debug information is included in PLLM error feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugInfoLevel {
    /// Only include the error type.
    Minimal,
    /// Include the error type and message.
    Normal,
    /// Include the full traceback and details.
    Extra,
}

/// Controls what secure variable values the PLLM can see in the system prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureVarVisibility {
    /// PLLM never sees secure variable values.
    None,
    /// PLLM sees variable names and types but not textual content.
    BasicNoText,
    /// PLLM sees basic values of non-executable variables.
    BasicExecutable,
    /// PLLM sees all values of executable variables.
    AllExecutable,
}

/// Internal tools that can be enabled in the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InternalTool {
    /// The `parse_with_ai` tool — routes data to QLLM for structured extraction.
    ParseWithAi,
    /// The `verify_hypothesis` tool — routes hypothesis verification to QLLM.
    VerifyHypothesis,
}

/// Configuration for response format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFormatConfig {
    /// Whether to return structured JSON or plain text.
    pub structured: bool,
    /// Whether to include debug fields in the response.
    pub include_debug: bool,
}

impl Default for ResponseFormatConfig {
    fn default() -> Self {
        Self {
            structured: true,
            include_debug: false,
        }
    }
}

// ============================================================
// Turn Result
// ============================================================

/// The result of processing a single conversation turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnResult {
    /// Whether the turn completed successfully.
    pub status: TurnStatus,
    /// The final return value from the interpreter (if successful).
    pub final_return_value: Option<serde_json::Value>,
    /// Error message (if the turn failed).
    pub error: Option<String>,
    /// The PLLM-generated program that was executed (last attempt).
    pub program: Option<String>,
    /// Number of PLLM attempts made for this turn.
    pub attempts: u32,
    /// Tool calls made during execution.
    pub tool_calls_made: Vec<ToolCallSummary>,
    /// Captured print output from the VM.
    pub print_output: String,
}

/// Status of a processed turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    /// The turn completed successfully.
    Success,
    /// The turn failed with an error.
    Error,
    /// The PLLM requested clarification from the user.
    ClarificationNeeded,
    /// The maximum number of PLLM attempts was exceeded.
    MaxAttemptsExceeded,
}

/// Summary of a tool call made during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallSummary {
    /// The name of the tool that was called.
    pub tool_name: String,
    /// The outcome: "executed", "denied", or "cached".
    pub outcome: String,
}

// ============================================================
// Internal Error Classification
// ============================================================

/// Classification of an error for retry eligibility.
///
/// Used internally by `process_turn` to decide whether to retry or fail.
pub(crate) enum ErrorClass {
    /// A VM exception (unhandled Python error). Retryable: feed traceback to PLLM.
    VmException(String),
    /// A policy violation. Retryable: feed denial reason to PLLM.
    PolicyViolation(String),
    /// A fatal error. Not retryable: propagate to the caller.
    Fatal(OrchestratorError),
}

// ============================================================
// Interpreter Loop Result
// ============================================================

/// The result of a successful interpreter execution loop.
#[allow(dead_code)] // `meta` field reserved for Phase 7 (server layer)
pub(crate) struct InterpreterLoopResult {
    /// The final return value from the interpreter.
    pub value: serde_json::Value,
    /// Metadata associated with the return value.
    pub meta: Metadata,
    /// Captured print output from the VM.
    pub print_output: String,
}

// ============================================================
// Session
// ============================================================

/// A conversation session with the dual-LLM orchestrator.
///
/// Manages the interpreter state, conversation history, and configuration
/// across multiple turns.
pub struct Session {
    /// Unique session identifier.
    id: Uuid,
    /// The interpreter that executes PLLM-generated code.
    pub(crate) interpreter: Interpreter,
    /// Number of turns processed so far.
    pub(crate) turn_count: u32,
    /// Session configuration.
    pub(crate) config: SessionConfig,
    /// Conversation history (user messages + assistant responses).
    pub(crate) message_history: Vec<Message>,
    /// When the session was created.
    created_at: Instant,
    /// Tool definitions available to PLLM programs in this session.
    pub(crate) tool_definitions: Vec<ToolDefinition>,
}

impl Session {
    /// Creates a new session with the given policy, configuration, and tool definitions.
    pub fn new(
        policy: CompiledPolicy,
        config: SessionConfig,
        interpreter_config: InterpreterConfig,
        tool_definitions: Vec<ToolDefinition>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            interpreter: Interpreter::new(policy, interpreter_config),
            turn_count: 0,
            config,
            message_history: Vec::new(),
            created_at: Instant::now(),
            tool_definitions,
        }
    }

    /// Creates a session with a pre-existing interpreter (primarily for testing).
    pub fn new_with_interpreter(
        interpreter: Interpreter,
        config: SessionConfig,
        tool_definitions: Vec<ToolDefinition>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            interpreter,
            turn_count: 0,
            config,
            message_history: Vec::new(),
            created_at: Instant::now(),
            tool_definitions,
        }
    }

    /// Resets the session to its initial state (keeping the same ID and policy).
    pub fn reset(&mut self) {
        self.turn_count = 0;
        self.message_history.clear();
        self.interpreter.clear_session_meta();
    }

    /// Returns the session ID.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the current turn count.
    #[must_use]
    pub fn turn_count(&self) -> u32 {
        self.turn_count
    }

    /// Returns the conversation history.
    #[must_use]
    pub fn message_history(&self) -> &[Message] {
        &self.message_history
    }

    /// Returns a reference to the interpreter's session metadata.
    #[must_use]
    pub fn session_meta(&self) -> &Metadata {
        self.interpreter.session_meta()
    }

    /// Returns a reference to the session configuration.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Returns a reference to the interpreter.
    #[must_use]
    pub fn interpreter(&self) -> &Interpreter {
        &self.interpreter
    }

    /// Returns when the session was created.
    #[must_use]
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns the tool definitions for this session.
    #[must_use]
    pub fn tool_definitions(&self) -> &[ToolDefinition] {
        &self.tool_definitions
    }
}
