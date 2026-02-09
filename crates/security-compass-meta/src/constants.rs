/// Tag applied to tool results to mark them as non-executable memory.
/// Data with this tag cannot influence control flow in the interpreter.
pub const NON_EXECUTABLE_TAG: &str = "__non_executable";

/// Tag applied to results produced by the QLLM via `parse_with_ai`.
pub const PARSE_WITH_AI_TAG: &str = "__tool/parse_with_ai";

/// When this tag is present on arguments to `parse_with_ai`, the call is hard-denied.
pub const LLM_BLOCKED_TAG: &str = "__llm_blocked";
