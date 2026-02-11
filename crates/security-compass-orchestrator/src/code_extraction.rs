//! Code extraction from PLLM responses.
//!
//! The PLLM returns Python code wrapped in markdown code fences. This module
//! extracts the code from those fences, handling various formats and edge cases.

use crate::error::OrchestratorError;

/// Prefix used by the PLLM to indicate a clarification request.
const CLARIFICATION_PREFIX: &str = "CLARIFICATION:";

/// Extracts Python code from a PLLM response.
///
/// Searches for code within markdown code fences in the following priority:
/// 1. `` ```python ... ``` `` or `` ```py ... ``` `` (preferred)
/// 2. `` ``` ... ``` `` (generic, fallback)
///
/// # Arguments
/// * `response` - The raw PLLM response text
/// * `allow_clarification` - If true, detect and return clarification requests
///
/// # Returns
/// * `Ok(Some(code))` - Code was extracted successfully
/// * `Ok(None)` - No code fence was found in the response
/// * `Err(ClarificationRequested)` - The PLLM asked for clarification
pub fn extract_code_block(
    response: &str,
    allow_clarification: bool,
) -> Result<Option<String>, OrchestratorError> {
    let trimmed = response.trim();

    // Check for clarification request
    if allow_clarification && trimmed.starts_with(CLARIFICATION_PREFIX) {
        let message = trimmed[CLARIFICATION_PREFIX.len()..].trim().to_string();
        return Err(OrchestratorError::ClarificationRequested { message });
    }

    // Try to find a Python-specific code fence first
    if let Some(code) = find_code_fence(trimmed, &["python", "py"]) {
        return Ok(Some(code));
    }

    // Fallback: try a generic code fence (no language or unrecognized language)
    if let Some(code) = find_generic_code_fence(trimmed) {
        return Ok(Some(code));
    }

    // No code fence found
    Ok(None)
}

/// Searches for a code fence with one of the specified language tags.
///
/// Returns the content inside the fence (trimmed), or None if not found.
fn find_code_fence(text: &str, language_tags: &[&str]) -> Option<String> {
    for tag in language_tags {
        // Try case-insensitive matching: ```python or ```Python or ```PYTHON
        let text_lower = text.to_lowercase();
        let pattern = format!("```{}", tag.to_lowercase());

        if let Some(start_idx) = text_lower.find(&pattern) {
            // Find the actual position in the original text
            let after_tag = start_idx + pattern.len();

            // The code starts after the next newline
            let code_start = match text[after_tag..].find('\n') {
                Some(nl) => after_tag + nl + 1,
                None => continue, // No newline after tag — malformed
            };

            // Find the closing fence
            if let Some(end_offset) = find_closing_fence(&text[code_start..]) {
                let code = &text[code_start..code_start + end_offset];
                return Some(code.trim_end().to_string());
            }
        }
    }

    None
}

/// Searches for a generic code fence (``` with no language or any language).
///
/// Only matches if no Python-specific fence was already found.
fn find_generic_code_fence(text: &str) -> Option<String> {
    // Find the first ``` that starts a line or is at the beginning
    let backtick_pattern = "```";

    let mut search_from = 0;
    while search_from < text.len() {
        let start_idx = match text[search_from..].find(backtick_pattern) {
            Some(idx) => search_from + idx,
            None => return None,
        };

        // Check if this is a valid opening fence (at start of line or start of text)
        let is_line_start = start_idx == 0
            || text.as_bytes().get(start_idx - 1) == Some(&b'\n');

        if !is_line_start {
            search_from = start_idx + backtick_pattern.len();
            continue;
        }

        // Skip past the opening ``` and any language tag on the same line
        let after_backticks = start_idx + backtick_pattern.len();
        let code_start = match text[after_backticks..].find('\n') {
            Some(nl) => after_backticks + nl + 1,
            None => return None, // No newline — malformed
        };

        // Find the closing fence
        if let Some(end_offset) = find_closing_fence(&text[code_start..]) {
            let code = &text[code_start..code_start + end_offset];
            return Some(code.trim_end().to_string());
        }

        // No closing fence found for this opening — try next
        search_from = code_start;
    }

    None
}

/// Finds the position of the closing ``` fence in the given text.
///
/// The closing fence must be on its own line (possibly preceded by whitespace).
/// Returns the byte offset of the closing fence (relative to the input), or None.
fn find_closing_fence(text: &str) -> Option<usize> {
    let backtick_pattern = "```";

    for (line_start, line) in line_offsets(text) {
        let trimmed_line = line.trim();
        if trimmed_line == backtick_pattern {
            return Some(line_start);
        }
    }

    None
}

/// Yields (byte_offset, line_content) pairs for each line in the text.
fn line_offsets(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0;
    text.split('\n').map(move |line| {
        let start = offset;
        offset += line.len() + 1; // +1 for the newline
        (start, line)
    })
}
