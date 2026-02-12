//! HTTP header payload types for the Security Compass Server.
//!
//! These types are deserialized from JSON header values:
//! - `X-Security-Features` -> [`FeaturesHeader`]
//! - `X-Security-Policy` -> [`SecurityPolicyHeader`]
//! - `X-Security-Config` -> [`FineGrainedConfigHeader`]
//!
//! All field names and defaults match the Python reference implementation exactly.

use serde::{Deserialize, Serialize};

// ============================================================
// Features Header (X-Security-Features)
// ============================================================

/// Top-level features header controlling which LLM mode, taggers,
/// constraints, and program support features are enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesHeader {
    /// The LLM mode feature (always required).
    pub llm: LlmModeFeature,
    /// Optional list of tagger features.
    #[serde(default)]
    pub taggers: Option<Vec<TaggerFeature>>,
    /// Optional list of constraint features.
    #[serde(default)]
    pub constraints: Option<Vec<ConstraintFeature>>,
    /// Optional long program support configuration.
    #[serde(default)]
    pub long_program_support: Option<LongProgramSupportFeature>,
}

/// LLM mode feature: selects between single/dual LLM and its operating mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmModeFeature {
    /// The LLM mode name (e.g. "Single LLM" or "Dual LLM").
    pub name: LlmModeName,
    /// The operating mode.
    #[serde(default)]
    pub mode: LlmMode,
}

/// Name of the LLM operating mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmModeName {
    /// Single LLM mode: only a planning LLM is used.
    #[serde(rename = "Single LLM")]
    SingleLlm,
    /// Dual LLM mode: planning + quarantined LLMs.
    #[serde(rename = "Dual LLM")]
    DualLlm,
}

/// Operating mode for the LLM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmMode {
    /// Standard mode with default settings.
    #[default]
    Standard,
    /// Strict mode with maximum security enforcement.
    Strict,
    /// Custom mode with user-specified settings.
    Custom,
}

/// A tagger feature configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggerFeature {
    /// Which tagger to enable.
    pub name: TaggerName,
    /// Operating mode for this tagger.
    #[serde(default)]
    pub mode: TaggerMode,
}

/// Names of available taggers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaggerName {
    /// User-input tagger: marks data as user-provided.
    #[serde(rename = "User-Input Tagger")]
    UserInputTagger,
    /// API-data tagger: marks data fetched from APIs.
    #[serde(rename = "API-Data Tagger")]
    ApiDataTagger,
    /// LLM-output tagger: marks data produced by LLMs.
    #[serde(rename = "LLM-Output Tagger")]
    LlmOutputTagger,
    /// Content-type tagger: classifies content types.
    #[serde(rename = "Content-Type Tagger")]
    ContentTypeTagger,
    /// Sensitivity tagger: classifies sensitivity levels.
    #[serde(rename = "Sensitivity Tagger")]
    SensitivityTagger,
}

/// Operating mode for a tagger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaggerMode {
    /// Normal operating mode.
    #[default]
    Normal,
    /// Strict mode: more aggressive tagging.
    Strict,
}

/// A constraint feature configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintFeature {
    /// Which constraint to enable.
    pub name: ConstraintName,
    /// Whether this constraint is enabled (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Names of available constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintName {
    /// Prevents untrusted data from reaching sensitive sinks.
    #[serde(rename = "Data Flow Integrity")]
    DataFlowIntegrity,
    /// Prevents execution of untrusted code.
    #[serde(rename = "Code Execution Safety")]
    CodeExecutionSafety,
    /// Prevents sensitive data from being exfiltrated.
    #[serde(rename = "Data Exfiltration Prevention")]
    DataExfiltrationPrevention,
}

/// Long program support feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LongProgramSupportFeature {
    /// Whether long program support is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum allowed program length in characters.
    #[serde(default)]
    pub max_length: Option<u32>,
}

// ============================================================
// Security Policy Header (X-Security-Policy)
// ============================================================

/// Security policy header describing the SQRT (or other language) policy source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityPolicyHeader {
    /// The policy language (only "sqrt" is currently supported).
    #[serde(default)]
    pub language: PolicyLanguage,
    /// Policy source code(s).
    #[serde(default)]
    pub codes: PolicyCodes,
    /// Whether to auto-generate a policy from the request context.
    #[serde(default)]
    pub auto_gen: bool,
    /// Whether to use fail-fast evaluation (stop at first deny rule).
    #[serde(default)]
    pub fail_fast: Option<bool>,
    /// Internal policy preset overrides.
    #[serde(default)]
    pub internal_policy_preset: Option<InternalPolicyPresetHeader>,
}


/// Supported policy languages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyLanguage {
    /// SQRT policy language (the default and only supported language).
    #[default]
    #[serde(rename = "sqrt")]
    Sqrt,
    /// SQRT-Lite (not yet supported).
    #[serde(rename = "sqrt-lite")]
    SqrtLite,
    /// Cedar (not yet supported).
    #[serde(rename = "cedar")]
    Cedar,
}

/// Policy source codes: either a single string or a list of strings.
///
/// When multiple codes are provided, they are concatenated with newlines.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyCodes {
    /// A single policy source string.
    Single(String),
    /// Multiple policy source strings (concatenated with newlines).
    Multiple(Vec<String>),
}

impl Default for PolicyCodes {
    fn default() -> Self {
        PolicyCodes::Single(String::new())
    }
}

impl PolicyCodes {
    /// Returns all policy codes concatenated into a single string.
    ///
    /// Multiple codes are joined with newline separators.
    pub fn as_combined_string(&self) -> String {
        match self {
            PolicyCodes::Single(s) => s.clone(),
            PolicyCodes::Multiple(v) => v.join("\n"),
        }
    }
}

/// Internal policy preset overrides from the header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPolicyPresetHeader {
    /// Whether to allow tool calls by default when no rule matches.
    #[serde(default = "default_true")]
    pub default_allow: bool,
    /// Enforcement level for the default allow/deny decision.
    #[serde(default)]
    pub default_allow_enforcement_level: EnforcementLevel,
    /// Whether to inject `__non_executable` tag on tool results.
    #[serde(default = "default_true")]
    pub enable_non_executable_memory: bool,
    /// Whether to hard deny when `__llm_blocked` tag is present.
    #[serde(default = "default_true")]
    pub enable_llm_blocked_tag: bool,
    /// Branching (control flow) meta-policy overrides.
    #[serde(default)]
    pub branching_meta_policy: Option<ControlFlowMetaPolicyHeader>,
}

/// Enforcement level as a header string value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementLevel {
    /// Soft enforcement (`should` in SQRT).
    #[default]
    Soft,
    /// Hard enforcement (`must` in SQRT).
    Hard,
}

/// Branching meta-policy configuration from headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowMetaPolicyHeader {
    /// Branching mode: allow (whitelist) or deny (blacklist).
    #[serde(default)]
    pub mode: BranchingModeStr,
    /// Producer identifiers.
    #[serde(default)]
    pub producers: Vec<String>,
    /// Tag identifiers.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Consumer identifiers.
    #[serde(default)]
    pub consumers: Vec<String>,
}

/// Branching mode as a header string value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BranchingModeStr {
    /// Allow mode: whitelist — only allow branching on listed metadata.
    Allow,
    /// Deny mode: blacklist — deny branching on listed metadata.
    #[default]
    Deny,
}

// ============================================================
// Fine-Grained Config Header (X-Security-Config)
// ============================================================

/// Fine-grained configuration header with ~25 fields controlling
/// orchestrator behavior. All fields have defaults matching the Python
/// reference implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FineGrainedConfigHeader {
    /// Maximum PLLM retry attempts per turn.
    #[serde(default = "default_max_pllm_attempts")]
    pub max_pllm_attempts: u32,
    /// Whether to merge multiple system/developer messages into one.
    #[serde(default = "default_true")]
    pub merge_system_messages: bool,
    /// Whether to convert system messages to developer messages.
    #[serde(default)]
    pub convert_system_to_developer_messages: bool,
    /// Which other roles to include in the user query context.
    #[serde(default = "default_include_other_roles")]
    pub include_other_roles_in_user_query: Vec<IncludedRole>,
    /// Maximum tool calls allowed per PLLM attempt.
    #[serde(default = "default_max_tool_calls")]
    pub max_tool_calls_per_attempt: Option<u32>,
    /// Clear conversation history every N attempts (None = never).
    #[serde(default)]
    pub clear_history_every_n_attempts: Option<u32>,
    /// Whether to retry when a policy violation occurs.
    #[serde(default)]
    pub retry_on_policy_violation: bool,
    /// Tool result caching mode.
    #[serde(default)]
    pub cache_tool_result: CacheToolResultStr,
    /// Tool names to force into the cache regardless of determinism.
    #[serde(default)]
    pub force_to_cache: Vec<String>,
    /// Minimum number of available tools before filtering is applied.
    #[serde(default = "default_min_num_tools_for_filtering")]
    pub min_num_tools_for_filtering: Option<u32>,
    /// When to clear session metadata.
    #[serde(default)]
    pub clear_session_meta: ClearSessionMetaStr,
    /// Whether to disable the RLLM (response review LLM).
    #[serde(default = "default_true")]
    pub disable_rllm: bool,
    /// Whether to use a reduced grammar when RLLM reviews.
    #[serde(default = "default_true")]
    pub reduced_grammar_for_rllm_review: bool,
    /// Confidence threshold for RLLM acceptance.
    #[serde(default)]
    pub rllm_confidence_score_threshold: Option<f64>,
    /// Debug information level for PLLM error feedback.
    #[serde(default)]
    pub pllm_debug_info_level: DebugInfoLevelStr,
    /// Maximum turns per session.
    #[serde(default = "default_max_n_turns")]
    pub max_n_turns: Option<u32>,
    /// Whether to enable multi-step planning mode.
    #[serde(default)]
    pub enable_multi_step_planning: bool,
    /// Whether to prune previously failed steps from the context.
    #[serde(default)]
    pub prune_failed_steps: bool,
    /// Which internal tools are enabled.
    #[serde(default = "default_enabled_internal_tools")]
    pub enabled_internal_tools: Vec<InternalToolStr>,
    /// Whether to restate the user query before planning.
    #[serde(default)]
    pub restate_user_query_before_planning: bool,
    /// Whether the PLLM can request clarification from the user.
    #[serde(default = "default_true")]
    pub pllm_can_ask_for_clarification: bool,
    /// Version of the reduced grammar to use.
    #[serde(default = "default_reduced_grammar_version")]
    pub reduced_grammar_version: String,
    /// Response format configuration.
    #[serde(default)]
    pub response_format: ResponseFormatHeader,
    /// Visibility of secure variable values to the PLLM.
    #[serde(default)]
    pub show_pllm_secure_var_values: SecureVarVisibilityStr,
}

impl Default for FineGrainedConfigHeader {
    fn default() -> Self {
        Self {
            max_pllm_attempts: 1,
            merge_system_messages: true,
            convert_system_to_developer_messages: false,
            include_other_roles_in_user_query: vec![IncludedRole::Assistant],
            max_tool_calls_per_attempt: Some(200),
            clear_history_every_n_attempts: None,
            retry_on_policy_violation: false,
            cache_tool_result: CacheToolResultStr::DeterministicOnly,
            force_to_cache: Vec::new(),
            min_num_tools_for_filtering: Some(10),
            clear_session_meta: ClearSessionMetaStr::Never,
            disable_rllm: true,
            reduced_grammar_for_rllm_review: true,
            rllm_confidence_score_threshold: None,
            pllm_debug_info_level: DebugInfoLevelStr::Normal,
            max_n_turns: Some(5),
            enable_multi_step_planning: false,
            prune_failed_steps: false,
            enabled_internal_tools: vec![
                InternalToolStr::ParseWithAi,
                InternalToolStr::VerifyHypothesis,
            ],
            restate_user_query_before_planning: false,
            pllm_can_ask_for_clarification: true,
            reduced_grammar_version: "v2".to_string(),
            response_format: ResponseFormatHeader::default(),
            show_pllm_secure_var_values: SecureVarVisibilityStr::None,
        }
    }
}

// ============================================================
// Config Sub-types (String Enums)
// ============================================================

/// Roles that can be included in the user query context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IncludedRole {
    /// Include assistant messages in the context.
    Assistant,
    /// Include tool result messages in the context.
    Tool,
}

/// Tool result caching mode (as a header string).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheToolResultStr {
    /// No caching.
    #[serde(rename = "none")]
    None,
    /// Cache all tool results.
    #[serde(rename = "all")]
    All,
    /// Cache only deterministic tool results (the default).
    #[default]
    #[serde(rename = "deterministic-only")]
    DeterministicOnly,
}

/// When to clear session metadata (as a header string).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClearSessionMetaStr {
    /// Never clear session metadata (the default).
    #[default]
    Never,
    /// Clear before every PLLM attempt.
    EveryAttempt,
    /// Clear at the start of every turn.
    EveryTurn,
}

/// Debug information level (as a header string).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DebugInfoLevelStr {
    /// Only include the error type.
    Minimal,
    /// Include the error type and message (the default).
    #[default]
    Normal,
    /// Include the full traceback and details.
    Extra,
}

/// Internal tool identifiers (as header strings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InternalToolStr {
    /// The `parse_with_ai` internal tool.
    #[serde(rename = "parse_with_ai")]
    ParseWithAi,
    /// The `verify_hypothesis` internal tool.
    #[serde(rename = "verify_hypothesis")]
    VerifyHypothesis,
}

/// Visibility of secure variable values to the PLLM (as a header string).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureVarVisibilityStr {
    /// PLLM never sees secure variable values (the default).
    #[default]
    None,
    /// PLLM sees variable names and types but not textual content.
    BasicNoText,
    /// PLLM sees basic values of non-executable variables.
    BasicExecutable,
    /// PLLM sees all values of executable variables.
    AllExecutable,
}

/// Response format configuration from headers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseFormatHeader {
    /// Whether to return structured JSON.
    #[serde(default)]
    pub structured: bool,
    /// Whether to include debug fields in the response.
    #[serde(default)]
    pub include_debug: bool,
}

// ============================================================
// Default Value Functions
// ============================================================

fn default_true() -> bool {
    true
}

fn default_max_pllm_attempts() -> u32 {
    1
}

fn default_include_other_roles() -> Vec<IncludedRole> {
    vec![IncludedRole::Assistant]
}

fn default_max_tool_calls() -> Option<u32> {
    Some(200)
}

fn default_min_num_tools_for_filtering() -> Option<u32> {
    Some(10)
}

fn default_max_n_turns() -> Option<u32> {
    Some(5)
}

fn default_enabled_internal_tools() -> Vec<InternalToolStr> {
    vec![
        InternalToolStr::ParseWithAi,
        InternalToolStr::VerifyHypothesis,
    ]
}

fn default_reduced_grammar_version() -> String {
    "v2".to_string()
}
