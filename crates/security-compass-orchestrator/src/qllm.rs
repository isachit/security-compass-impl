//! QLLM interaction wrappers.
//!
//! Routes untrusted data to the QLLM (Quarantined LLM) for structured
//! extraction (parse_with_ai) and hypothesis verification (verify_hypothesis).
//!
//! The QLLM has no tool-calling capability — it only receives a system prompt,
//! user data, and an output schema. This is a core security invariant.

use crate::error::OrchestratorError;
use crate::traits::LlmClient;

// ============================================================
// QLLM System Prompts
// ============================================================

/// System prompt for data extraction (parse_with_ai).
const QLLM_EXTRACTION_SYSTEM_PROMPT: &str =
    "You are a data extraction assistant. Extract the requested information from the \
     provided data and return your answer as JSON matching the output schema. If you \
     do not have enough information to answer, set the `have_enough_information` field \
     to false.";

/// System prompt for hypothesis verification (verify_hypothesis).
const QLLM_VERIFICATION_SYSTEM_PROMPT: &str =
    "You are a verification assistant. Given data and a hypothesis, determine whether \
     the hypothesis is supported by the data. Return a JSON object with a `result` \
     boolean field (true if the hypothesis is confirmed, false otherwise) and an \
     optional `reasoning` field explaining your conclusion.";

// ============================================================
// QLLM Call Functions
// ============================================================

/// Routes data to the QLLM for structured extraction (parse_with_ai).
///
/// Constructs a QLLM prompt with the data and query, requests structured
/// JSON output matching the provided schema, and checks the
/// `have_enough_information` field.
///
/// # Arguments
/// * `llm_client` - The LLM client to use for the QLLM call
/// * `data` - The untrusted data to parse (as JSON)
/// * `query` - The extraction query/instruction
/// * `output_schema` - The expected output JSON schema
///
/// # Errors
/// * `OrchestratorError::QllmInsufficientInfo` - QLLM reported insufficient data
/// * `OrchestratorError::LlmError` - QLLM call failed
pub async fn call_qllm(
    llm_client: &dyn LlmClient,
    data: &serde_json::Value,
    query: &str,
    output_schema: &serde_json::Value,
) -> Result<serde_json::Value, OrchestratorError> {
    // Build user message with data and query
    let data_str = serde_json::to_string_pretty(data)
        .unwrap_or_else(|_| format!("{data}"));

    let user_message = format!("Data:\n{data_str}\n\nQuery: {query}");

    // Call the QLLM with structured output
    let response = llm_client
        .chat_completion_with_schema(
            QLLM_EXTRACTION_SYSTEM_PROMPT,
            &user_message,
            output_schema,
        )
        .await?;

    // Check the have_enough_information field
    if response.get("have_enough_information") == Some(&serde_json::Value::Bool(false)) {
        return Err(OrchestratorError::QllmInsufficientInfo);
    }

    Ok(response)
}

/// Routes a hypothesis to the QLLM for verification (verify_hypothesis).
///
/// Asks the QLLM to determine if the hypothesis is supported by the data.
/// Returns `true` if confirmed, `false` otherwise.
///
/// # Arguments
/// * `llm_client` - The LLM client to use for the QLLM call
/// * `hypothesis` - The hypothesis to verify
/// * `data` - The data to verify against (as JSON)
///
/// # Errors
/// * `OrchestratorError::LlmError` - QLLM call failed
pub async fn call_qllm_verify(
    llm_client: &dyn LlmClient,
    hypothesis: &str,
    data: &serde_json::Value,
) -> Result<bool, OrchestratorError> {
    // Build the verification output schema
    let verification_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "result": { "type": "boolean" },
            "reasoning": { "type": "string" }
        },
        "required": ["result"]
    });

    // Build user message
    let data_str = serde_json::to_string_pretty(data)
        .unwrap_or_else(|_| format!("{data}"));

    let user_message = format!("Data:\n{data_str}\n\nHypothesis: {hypothesis}");

    // Call the QLLM with structured output
    let response = llm_client
        .chat_completion_with_schema(
            QLLM_VERIFICATION_SYSTEM_PROMPT,
            &user_message,
            &verification_schema,
        )
        .await?;

    // Extract the result field, defaulting to false if missing
    let result = response
        .get("result")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    Ok(result)
}
