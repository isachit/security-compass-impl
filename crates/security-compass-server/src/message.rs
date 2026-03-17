//! Message extraction from chat completion requests.
//!
//! Converts the rich [`RequestMessage`] variants into the simpler
//! orchestrator [`Message`] type, extracting the user query and
//! optionally merging system/developer messages.

use security_compass_orchestrator::{Message, Role};

use crate::error::ServerError;
use crate::types::headers::IncludedRole;
use crate::types::request::RequestMessage;

/// The result of extracting messages from a chat completion request.
#[derive(Debug)]
pub struct ExtractedMessages {
    /// The merged system prompt (from system + developer messages), if any.
    pub system_prompt: Option<String>,
    /// The user's query (last user message content).
    pub user_query: String,
    /// Prior conversation history messages (before the last user message).
    pub prior_history: Vec<Message>,
}

/// Extracts the user query, system prompt, and prior history from a
/// list of request messages.
///
/// # Parameters
///
/// - `messages` — The request messages from the chat completion request.
/// - `merge_system` — If `true`, all system/developer messages are merged
///   into a single system prompt. If `false`, only the last system/developer
///   message is used.
/// - `include_other_roles` — Which non-user roles (assistant, tool) to
///   include in the prior history.
///
/// # Errors
///
/// Returns [`ServerError::NoUserMessage`] if no user-role message is found.
pub fn extract_messages(
    messages: &[RequestMessage],
    merge_system: bool,
    include_other_roles: &[IncludedRole],
) -> Result<ExtractedMessages, ServerError> {
    // 1. Collect system/developer messages.
    let mut system_parts: Vec<String> = Vec::new();
    for msg in messages {
        match msg {
            RequestMessage::System { content, .. } | RequestMessage::Developer { content, .. } => {
                system_parts.push(content.clone());
            }
            _ => {}
        }
    }

    let system_prompt = if system_parts.is_empty() {
        None
    } else if merge_system {
        Some(system_parts.join("\n\n"))
    } else {
        // Use only the last system/developer message.
        system_parts.last().cloned()
    };

    // 2. Find the last user message (this becomes the query).
    let last_user_idx = messages
        .iter()
        .rposition(|m| matches!(m, RequestMessage::User { .. }));

    let last_user_idx = last_user_idx.ok_or(ServerError::NoUserMessage)?;

    let user_query = match &messages[last_user_idx] {
        RequestMessage::User { content, .. } => content.as_text(),
        _ => unreachable!(),
    };

    if user_query.is_empty() {
        return Err(ServerError::NoUserMessage);
    }

    // 3. Build prior history from all messages before the last user message,
    //    filtering by included roles.
    let include_assistant = include_other_roles.contains(&IncludedRole::Assistant);
    let include_tool = include_other_roles.contains(&IncludedRole::Tool);

    let mut prior_history: Vec<Message> = Vec::new();
    for msg in &messages[..last_user_idx] {
        match msg {
            // System/developer messages are handled separately (system_prompt).
            RequestMessage::System { .. } | RequestMessage::Developer { .. } => {}

            // Earlier user messages are always included.
            RequestMessage::User { content, .. } => {
                prior_history.push(Message::new(Role::User, content.as_text()));
            }

            // Assistant messages included only if configured.
            RequestMessage::Assistant { content, .. } if include_assistant => {
                let text = content.as_deref().unwrap_or("").to_string();
                if !text.is_empty() {
                    prior_history.push(Message::new(Role::Assistant, text));
                }
            }

            // Tool result messages included only if configured.
            RequestMessage::Tool { content, .. } if include_tool => {
                // Map tool messages to assistant role for the orchestrator.
                prior_history.push(Message::new(Role::Assistant, content.clone()));
            }

            // Function messages included only if tool role is configured.
            RequestMessage::Function { content, .. } if include_tool => {
                prior_history.push(Message::new(Role::Assistant, content.clone()));
            }

            // Everything else is skipped.
            _ => {}
        }
    }

    Ok(ExtractedMessages {
        system_prompt,
        user_query,
        prior_history,
    })
}
