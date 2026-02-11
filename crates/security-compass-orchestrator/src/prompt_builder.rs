//! PLLM system prompt construction and error feedback formatting.
//!
//! Builds the system prompt that instructs the PLLM to generate Python code
//! within the constraints of the Security Compass interpreter.

use security_compass_interpreter::ToolDefinition;

use crate::types::{
    DebugInfoLevel, ErrorClass, InternalTool, Message, Role, SessionConfig,
};

// ============================================================
// System Prompt Builder
// ============================================================

/// Builds the PLLM system prompt.
///
/// The prompt includes:
/// 1. Role preamble (code-generation assistant)
/// 2. Python subset constraints
/// 3. Output format instructions
/// 4. Tool function signatures
/// 5. Internal tools (conditional)
/// 6. Available builtins
/// 7. Multi-step planning section (conditional)
/// 8. Clarification instructions (conditional)
pub fn build_pllm_system_prompt(
    tool_definitions: &[ToolDefinition],
    config: &SessionConfig,
) -> String {
    let mut prompt = String::with_capacity(2048);

    // 1. Role preamble
    prompt.push_str(
        "You are a code-generation assistant. You output Python code to answer the user's \
         question. The code is run in a sandboxed interpreter with security metadata tracking.\n\n",
    );

    // 2. Python subset constraints
    prompt.push_str("## Constraints\n\n");
    prompt.push_str("You may use the following Python features:\n");
    prompt.push_str("- Variables, arithmetic, string operations\n");
    prompt.push_str("- Lists, dicts, tuples, sets\n");
    prompt.push_str("- if/elif/else conditionals\n");
    prompt.push_str("- for loops (over iterables)\n");
    prompt.push_str("- try/except blocks\n");
    prompt.push_str("- List comprehensions, dict comprehensions\n");
    prompt.push_str("- Ternary expressions (x if cond else y)\n");
    prompt.push_str("- f-strings and string formatting\n\n");
    prompt.push_str("You may NOT use:\n");
    prompt.push_str("- import statements\n");
    prompt.push_str("- while loops\n");
    prompt.push_str("- Function definitions (def)\n");
    prompt.push_str("- Class definitions\n");
    prompt.push_str("- Lambda functions\n");
    prompt.push_str("- Generators, yield\n");
    prompt.push_str("- async/await\n");
    prompt.push_str("- with statements\n");
    prompt.push_str("- Decorators\n");
    prompt.push_str("- global/nonlocal\n");
    prompt.push_str("- eval(), exec()\n");
    prompt.push_str("- break/continue\n\n");

    // 3. Output format
    prompt.push_str("## Output Format\n\n");
    prompt.push_str(
        "Wrap your Python code in a ```python code block. The value of the last expression \
         in your code is the return value.\n\n",
    );

    // 4. Tool function signatures
    if !tool_definitions.is_empty() {
        prompt.push_str("## Available Tool Functions\n\n");
        for tool in tool_definitions {
            prompt.push_str(&format_tool_signature(tool));
            prompt.push('\n');
        }
        prompt.push('\n');
    }

    // 5. Internal tools (conditional)
    let has_internal = !config.enabled_internal_tools.is_empty();
    if has_internal {
        prompt.push_str("## Internal Tools\n\n");

        if config
            .enabled_internal_tools
            .contains(&InternalTool::ParseWithAi)
        {
            prompt.push_str("def parse_with_ai(data, query, output_schema) -> Any:\n");
            prompt.push_str(
                "    \"\"\"Parse unstructured data using AI. Use this instead of regex \
                 for extracting structured information from text.\"\"\"\n\n",
            );
        }

        if config
            .enabled_internal_tools
            .contains(&InternalTool::VerifyHypothesis)
        {
            prompt.push_str("def verify_hypothesis(hypothesis, data) -> bool:\n");
            prompt.push_str(
                "    \"\"\"Verify whether a hypothesis is supported by the given data. \
                 Returns True if the hypothesis is confirmed.\"\"\"\n\n",
            );
        }
    }

    // 6. Available builtins
    prompt.push_str("## Available Built-in Functions\n\n");
    prompt.push_str(
        "print, len, range, str, int, float, bool, list, dict, tuple, set, \
         sorted, enumerate, zip, min, max, sum, abs, round, isinstance, type, \
         all, any, reversed, map, filter, hasattr, getattr, ord, chr\n\n",
    );

    // 7. Multi-step planning (conditional)
    if config.enable_multi_step_planning {
        prompt.push_str("## Multi-Step Planning\n\n");
        prompt.push_str(
            "You may use multiple tool calls in sequence. Assign intermediate results to \
             variables. Results from previous steps are available as variables in your code.\n\n",
        );
    }

    // 8. Clarification instructions (conditional)
    if config.pllm_can_ask_for_clarification {
        prompt.push_str("## Clarification\n\n");
        prompt.push_str(
            "If you need more information from the user before you can write the code, \
             respond with 'CLARIFICATION: ' followed by your question. Do NOT wrap a \
             clarification request in a code block.\n\n",
        );
    }

    prompt
}

// ============================================================
// Tool Signature Formatting
// ============================================================

/// Formats a tool definition as a Python function signature.
pub(crate) fn format_tool_signature(tool: &ToolDefinition) -> String {
    let params = tool.parameter_names.join(", ");
    format!("def {}({}) -> Any:", tool.name, params)
}

// ============================================================
// Error Feedback
// ============================================================

/// Builds an error feedback message for the PLLM retry loop.
///
/// The message is formatted as a user message instructing the PLLM
/// to fix its code and retry.
pub fn build_error_feedback(
    error_class: &ErrorClass,
    debug_level: DebugInfoLevel,
    attempt: u32,
    max_attempts: u32,
) -> Message {
    let content = match error_class {
        ErrorClass::VmException(msg) => format_vm_error(msg, debug_level, attempt, max_attempts),
        ErrorClass::PolicyViolation(msg) => {
            format_policy_violation(msg, debug_level, attempt, max_attempts)
        }
        ErrorClass::Fatal(err) => {
            // Fatal errors shouldn't reach here, but format gracefully
            format!(
                "Fatal error: {} (attempt {}/{})",
                err, attempt, max_attempts
            )
        }
    };

    Message::new(Role::User, content)
}

/// Formats a VM exception error for PLLM feedback.
fn format_vm_error(
    msg: &str,
    debug_level: DebugInfoLevel,
    attempt: u32,
    max_attempts: u32,
) -> String {
    match debug_level {
        DebugInfoLevel::Minimal => {
            format!(
                "Your code raised an error. Please fix and try again. (attempt {}/{})",
                attempt, max_attempts
            )
        }
        DebugInfoLevel::Normal => {
            // Extract the first line of the error message as the summary
            let summary = msg.lines().next().unwrap_or(msg);
            format!(
                "Your code raised an error: {}\n\nPlease fix your code and try again. \
                 (attempt {}/{})",
                summary, attempt, max_attempts
            )
        }
        DebugInfoLevel::Extra => {
            format!(
                "Your code raised an error with the following details:\n\n```\n{}\n```\n\n\
                 Please fix your code and try again. (attempt {}/{})",
                msg, attempt, max_attempts
            )
        }
    }
}

/// Formats a policy violation for PLLM feedback.
fn format_policy_violation(
    msg: &str,
    debug_level: DebugInfoLevel,
    attempt: u32,
    max_attempts: u32,
) -> String {
    match debug_level {
        DebugInfoLevel::Minimal => {
            format!(
                "Your code was blocked by a security policy. Please try a different approach. \
                 (attempt {}/{})",
                attempt, max_attempts
            )
        }
        DebugInfoLevel::Normal | DebugInfoLevel::Extra => {
            format!(
                "Your code was blocked by a security policy: {}\n\n\
                 Please try a different approach. (attempt {}/{})",
                msg, attempt, max_attempts
            )
        }
    }
}
