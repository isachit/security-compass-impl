//! Type definitions for the Security Compass Interpreter.

use std::collections::HashMap;
use std::sync::Arc;

use security_compass_meta::{Metadata, ValueWithMeta};
use security_compass_vm::{LimitedTracker, Snapshot};
use sqrt_eval::{CompiledPolicy, ResolvedUpdate};

use crate::error::InterpreterError;

/// Type alias for VM snapshots using bounded resource tracking.
pub type VmSnapshot = Snapshot<LimitedTracker>;

// ============================================================
// Tool Definition
// ============================================================

/// Describes an external tool available to PLLM-generated programs.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    /// The tool's function name (must match the Python function name).
    pub name: String,
    /// Ordered list of positional parameter names for this tool.
    /// Used to convert positional VM args into named args for policy evaluation.
    pub parameter_names: Vec<String>,
    /// Whether this tool is deterministic (same inputs → same output).
    /// Deterministic tools may have their results cached.
    pub deterministic: bool,
}

// ============================================================
// Tool Call Recording
// ============================================================

/// Record of a tool call made during execution.
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    /// The name of the tool that was called.
    pub tool_name: String,
    /// The unique call ID assigned by the VM.
    pub call_id: u32,
    /// The outcome of the tool call.
    pub outcome: ToolCallOutcome,
}

/// Outcome of a tool call attempt.
#[derive(Debug, Clone)]
pub enum ToolCallOutcome {
    /// The tool call was allowed by policy and executed.
    Executed,
    /// The tool call was denied by policy.
    Denied {
        /// The reason for denial (from the SQRT policy).
        reason: String,
    },
    /// The tool call was served from cache.
    Cached,
}

// ============================================================
// Cache Mode
// ============================================================

/// Controls whether and how tool results are cached within an execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// No caching — every tool call is yielded to the caller.
    None,
    /// Cache all tool results (keyed by tool name + serialized args).
    All,
    /// Cache only results from tools marked as `deterministic`.
    DeterministicOnly,
}

// ============================================================
// Interpreter Configuration
// ============================================================

/// Configuration for interpreter execution behavior.
#[derive(Debug, Clone)]
pub struct InterpreterConfig {
    /// Maximum number of tool calls allowed per `execute()` invocation.
    /// After this limit, `ToolCallLimitExceeded` is returned.
    pub max_tool_calls_per_attempt: u32,
    /// Whether/how to cache tool results within an execution.
    pub cache_tool_result: CacheMode,
    /// Gas limit: each tool call costs 1 gas. 0 = unlimited.
    pub gas_limit: u64,
    /// Whether to evaluate all SQRT rules before deciding (false) or stop at first deny (true).
    pub fail_fast: bool,
}

impl Default for InterpreterConfig {
    fn default() -> Self {
        Self {
            max_tool_calls_per_attempt: 100,
            cache_tool_result: CacheMode::None,
            gas_limit: 0,
            fail_fast: false,
        }
    }
}

// ============================================================
// Interpreter State
// ============================================================

/// The interpreter: orchestrates VM execution with SQRT policy enforcement.
///
/// The interpreter manages:
/// - Starting and resuming bytecode VM execution
/// - Intercepting external function calls (tool calls, QLLM routing)
/// - Evaluating SQRT security policies before yielding tool calls
/// - Tracking and applying metadata updates
/// - Branch checking via the `PolicyBranchChecker`
/// - Session metadata that persists across tool calls
///
/// # Usage Pattern
///
/// ```text
/// let interpreter = Interpreter::new(policy, config);
///
/// // First execution
/// let result = interpreter.execute(code, inputs, tools)?;
///
/// loop {
///     match result {
///         ExecutionResult::Complete { value, meta } => break,
///         ExecutionResult::NeedsToolCall { tool_name, args, state, .. } => {
///             let tool_result = execute_tool(&tool_name, &args);
///             result = interpreter.resume_after_tool_call(state, ...)?;
///         }
///         // ... handle other yield points
///     }
/// }
/// ```
pub struct Interpreter {
    /// Compiled SQRT policy shared with `PolicyBranchChecker` instances.
    pub(crate) policy: Arc<CompiledPolicy>,
    /// Session metadata: persists across tool calls within an execution.
    pub(crate) session_meta: Metadata,
    /// Interpreter configuration.
    pub(crate) config: InterpreterConfig,
    /// History of tool calls made during the current execution.
    pub(crate) tool_call_history: Vec<ToolCallRecord>,
    /// Remaining gas for the current execution.
    pub(crate) gas_remaining: u64,
    /// Number of tool calls made in the current execution.
    pub(crate) tool_call_count: u32,
    /// Cache of tool results (keyed by "tool_name:serialized_args").
    pub(crate) tool_cache: HashMap<String, ValueWithMeta<serde_json::Value>>,
    /// Map from tool name to ordered parameter names.
    pub(crate) tool_arg_names: HashMap<String, Vec<String>>,
    /// Captured print output from the VM.
    pub(crate) print_output: String,
    /// Set of tools marked as deterministic (for cache eligibility).
    pub(crate) deterministic_tools: std::collections::HashSet<String>,
}

// ============================================================
// Execution Results (Yield Points)
// ============================================================

/// Result of an execution step — either complete or yielding for external work.
///
/// The interpreter yields at three points:
/// - **Tool calls**: The orchestrator must execute the tool and provide results
/// - **parse_with_ai**: The orchestrator must route data through the QLLM
/// - **verify_hypothesis**: The orchestrator must verify a hypothesis via the QLLM
#[derive(Debug)]
pub enum ExecutionResult {
    /// Execution completed successfully.
    Complete {
        /// The final return value (converted to JSON).
        value: serde_json::Value,
        /// Metadata associated with the return value.
        meta: Metadata,
        /// Captured print output from the VM.
        print_output: String,
    },

    /// Execution paused: a tool call was allowed by policy and needs execution.
    ///
    /// The orchestrator should:
    /// 1. Execute the tool with the provided named arguments
    /// 2. Call `interpreter.resume_after_tool_call()` with the result
    NeedsToolCall {
        /// Name of the tool to call.
        tool_name: String,
        /// Named arguments for the tool (parameter_name → value + metadata).
        args: indexmap::IndexMap<String, ValueWithMeta<serde_json::Value>>,
        /// VM call ID for correlation.
        call_id: u32,
        /// VM execution state to resume after the tool call.
        state: VmSnapshot,
        /// Metadata updates to apply to the tool result.
        result_updates: Vec<ResolvedUpdate>,
        /// Metadata updates to apply to session after the tool call completes.
        session_after_updates: Vec<ResolvedUpdate>,
    },

    /// Execution paused: data needs to be parsed by the QLLM.
    ///
    /// The orchestrator should:
    /// 1. Route `data` through the QLLM with the given `query` and `output_schema`
    /// 2. Call `interpreter.resume_after_parse_with_ai()` with the parsed result
    NeedsParseWithAi {
        /// The data to parse (value + metadata from the input argument).
        data: ValueWithMeta<serde_json::Value>,
        /// The query/instruction for parsing.
        query: String,
        /// The expected output schema (JSON Schema).
        output_schema: serde_json::Value,
        /// VM call ID for correlation.
        call_id: u32,
        /// VM execution state to resume after parsing.
        state: VmSnapshot,
    },

    /// Execution paused: a hypothesis needs verification by the QLLM.
    ///
    /// The orchestrator should:
    /// 1. Ask the QLLM to verify the hypothesis against the data
    /// 2. Call `interpreter.resume_after_verify_hypothesis()` with `true` or `false`
    NeedsVerifyHypothesis {
        /// The hypothesis to verify.
        hypothesis: String,
        /// The data to verify against (value + metadata).
        data: ValueWithMeta<serde_json::Value>,
        /// VM call ID for correlation.
        call_id: u32,
        /// VM execution state to resume after verification.
        state: VmSnapshot,
    },
}

impl Interpreter {
    /// Returns a reference to the compiled policy.
    #[must_use]
    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    /// Returns a reference to the current session metadata.
    #[must_use]
    pub fn session_meta(&self) -> &Metadata {
        &self.session_meta
    }

    /// Returns the tool call history for the current execution.
    #[must_use]
    pub fn tool_call_history(&self) -> &[ToolCallRecord] {
        &self.tool_call_history
    }

    /// Resets the session metadata to default (clean).
    ///
    /// Call this between logically independent executions if you want
    /// to start with fresh session state.
    pub fn clear_session_meta(&mut self) {
        self.session_meta = Metadata::default();
    }

    /// Returns the captured print output from the most recent execution.
    #[must_use]
    pub fn print_output(&self) -> &str {
        &self.print_output
    }

    /// Builds the tool cache key for a given tool call.
    pub(crate) fn cache_key(
        tool_name: &str,
        args: &indexmap::IndexMap<String, ValueWithMeta<serde_json::Value>>,
    ) -> String {
        // Use tool name + JSON-serialized arg values as cache key
        let args_json: serde_json::Value = args
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect::<serde_json::Map<String, serde_json::Value>>()
            .into();
        format!("{}:{}", tool_name, args_json)
    }

    /// Checks if a tool call result should be cached based on config and tool definition.
    pub(crate) fn should_cache(&self, tool_name: &str) -> bool {
        match self.config.cache_tool_result {
            CacheMode::None => false,
            CacheMode::All => true,
            CacheMode::DeterministicOnly => self.deterministic_tools.contains(tool_name),
        }
    }

    /// Returns the number of tool calls made in the current execution.
    #[must_use]
    pub fn tool_call_count(&self) -> u32 {
        self.tool_call_count
    }

    /// Checks gas and tool call limits, returning an error if exceeded.
    pub(crate) fn check_limits(&self) -> Result<(), InterpreterError> {
        if self.config.gas_limit > 0 && self.gas_remaining == 0 {
            return Err(InterpreterError::GasExhausted {
                tool_calls: self.tool_call_count,
            });
        }
        if self.tool_call_count >= self.config.max_tool_calls_per_attempt {
            return Err(InterpreterError::ToolCallLimitExceeded {
                limit: self.config.max_tool_calls_per_attempt,
            });
        }
        Ok(())
    }
}
