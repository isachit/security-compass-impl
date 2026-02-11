//! Turn processing with PLLM retry loop.
//!
//! Implements the main `process_turn()` method that:
//! 1. Checks turn limits
//! 2. Builds the PLLM system prompt
//! 3. Calls the PLLM to generate Python code
//! 4. Extracts the code from the response
//! 5. Runs the interpreter loop
//! 6. Handles errors with retry logic

use security_compass_interpreter::InterpreterError;
use security_compass_meta::{Metadata, ValueWithMeta};

use crate::code_extraction::extract_code_block;
use crate::error::OrchestratorError;
use crate::prompt_builder::{build_error_feedback, build_pllm_system_prompt};
use crate::traits::{LlmClient, ToolExecutor};
use crate::types::{
    ClearSessionMeta, ErrorClass, Message, Session, ToolCallSummary, TurnResult, TurnStatus,
};

impl Session {
    /// Process a single user turn: call PLLM, execute code, handle retries.
    ///
    /// This is the main entry point called by the server layer.
    ///
    /// # Algorithm
    /// 1. Check turn limit
    /// 2. Optionally clear session metadata
    /// 3. Build PLLM system prompt
    /// 4. PLLM retry loop:
    ///    a. Call PLLM for code generation
    ///    b. Extract code from response
    ///    c. Run interpreter loop
    ///    d. On retryable error: format feedback, retry
    ///    e. On success: return TurnResult
    pub async fn process_turn(
        &mut self,
        user_message: &str,
        llm_client: &dyn LlmClient,
        tool_executor: &dyn ToolExecutor,
    ) -> Result<TurnResult, OrchestratorError> {
        // 0. Check turn limit
        if let Some(max) = self.config.max_n_turns {
            if self.turn_count >= max {
                return Err(OrchestratorError::MaxTurnsExceeded { limit: max });
            }
        }

        // 1. Increment turn count
        self.turn_count += 1;

        // 2. Clear session metadata if configured for every turn
        if self.config.clear_session_meta == ClearSessionMeta::EveryTurn {
            self.interpreter.clear_session_meta();
        }

        // 3. Add user message to history
        self.message_history
            .push(Message::user(user_message));

        // 4. Build PLLM system prompt
        let system_prompt =
            build_pllm_system_prompt(&self.tool_definitions, &self.config);

        // 5. PLLM retry loop
        let max_attempts = self.config.max_pllm_attempts;
        let debug_level = self.config.pllm_debug_info_level;
        let allow_clarification = self.config.pllm_can_ask_for_clarification;
        let prune_failed = self.config.prune_failed_steps;
        let clear_meta_every_attempt =
            self.config.clear_session_meta == ClearSessionMeta::EveryAttempt;

        let mut last_error_feedback: Option<Message> = None;
        let mut last_program: Option<String> = None;

        for attempt in 1..=max_attempts {
            // 5a. Clear session metadata if configured for every attempt
            if clear_meta_every_attempt {
                self.interpreter.clear_session_meta();
            }

            // 5b. Build messages for PLLM
            let mut pllm_messages = Vec::new();
            pllm_messages.push(Message::system(&system_prompt));

            // Add conversation history
            for msg in &self.message_history {
                pllm_messages.push(msg.clone());
            }

            // Add error feedback from previous attempt (if retrying)
            if let Some(ref feedback) = last_error_feedback {
                pllm_messages.push(feedback.clone());
            }

            // 5c. Call PLLM
            let pllm_response = llm_client.chat_completion(&pllm_messages).await?;

            // 5d. Extract code from response
            let code = match extract_code_block(&pllm_response, allow_clarification) {
                Ok(Some(code)) => code,
                Ok(None) => {
                    // No code block found — retry
                    last_error_feedback = Some(Message::user(
                        format!(
                            "No code block found in your response. Please wrap your Python code \
                             in a ```python code block. (attempt {}/{})",
                            attempt, max_attempts
                        ),
                    ));
                    continue;
                }
                Err(OrchestratorError::ClarificationRequested { message }) => {
                    // PLLM asked for clarification
                    self.message_history
                        .push(Message::assistant(&pllm_response));
                    return Ok(TurnResult {
                        status: TurnStatus::ClarificationNeeded,
                        final_return_value: None,
                        error: Some(message),
                        program: None,
                        attempts: attempt,
                        tool_calls_made: vec![],
                        print_output: String::new(),
                    });
                }
                Err(e) => return Err(e),
            };

            last_program = Some(code.clone());

            // 5e. Build input variables from user message
            let input_vars = vec![(
                "user_message".to_string(),
                ValueWithMeta {
                    value: serde_json::Value::String(user_message.to_string()),
                    meta: Metadata::default_for_user_input(),
                },
            )];

            // 5f. Run interpreter loop
            match self
                .run_interpreter_loop(&code, input_vars, llm_client, tool_executor)
                .await
            {
                Ok(loop_result) => {
                    // Success! Add assistant message to history
                    self.message_history
                        .push(Message::assistant(&code));

                    // Build tool call summaries
                    let tool_calls = self
                        .interpreter
                        .tool_call_history()
                        .iter()
                        .map(|tc| ToolCallSummary {
                            tool_name: tc.tool_name.clone(),
                            outcome: format!("{:?}", tc.outcome),
                        })
                        .collect();

                    return Ok(TurnResult {
                        status: TurnStatus::Success,
                        final_return_value: Some(loop_result.value),
                        error: None,
                        program: last_program,
                        attempts: attempt,
                        tool_calls_made: tool_calls,
                        print_output: loop_result.print_output,
                    });
                }
                Err(err) => {
                    // Classify the error for retry eligibility
                    let error_class = classify_error(err);

                    match error_class {
                        ErrorClass::VmException(_) | ErrorClass::PolicyViolation(_) => {
                            // Retryable — build error feedback
                            last_error_feedback = Some(build_error_feedback(
                                &error_class,
                                debug_level,
                                attempt,
                                max_attempts,
                            ));

                            // Optionally prune the failed code from history
                            if !prune_failed {
                                self.message_history
                                    .push(Message::assistant(&code));
                            }

                            continue;
                        }
                        ErrorClass::Fatal(fatal_err) => {
                            return Err(fatal_err);
                        }
                    }
                }
            }
        }

        // All attempts exhausted
        Ok(TurnResult {
            status: TurnStatus::MaxAttemptsExceeded,
            final_return_value: None,
            error: Some(format!("Max PLLM attempts exceeded ({max_attempts} attempts)")),
            program: last_program,
            attempts: max_attempts,
            tool_calls_made: vec![],
            print_output: String::new(),
        })
    }
}

// ============================================================
// Error Classification
// ============================================================

/// Classifies an orchestrator error for retry eligibility.
///
/// - **Retryable**: VM exceptions, policy eval errors, tool errors, resource limits
/// - **Fatal**: LLM client errors, serde errors, max turns exceeded, internal tool disabled
///
/// Note: Retryable arms use `ref` patterns to extract error details into strings,
/// discarding the original `OrchestratorError`. The `other` catch-all moves the
/// error into `ErrorClass::Fatal`. This is intentional — retryable errors only need
/// a human-readable message for the PLLM feedback, not the original error value.
pub(crate) fn classify_error(err: OrchestratorError) -> ErrorClass {
    match err {
        // VM exception — PLLM made a coding mistake
        OrchestratorError::InterpreterError(InterpreterError::VmError(ref exc)) => {
            ErrorClass::VmException(format!("{exc}"))
        }

        // Policy evaluation error — PLLM tried something forbidden
        OrchestratorError::InterpreterError(InterpreterError::PolicyEvalError(ref e)) => {
            ErrorClass::PolicyViolation(format!("{e}"))
        }

        // Tool execution failure — retryable, PLLM can try different args/approach
        OrchestratorError::ToolError {
            ref tool_name,
            ref message,
        } => ErrorClass::VmException(format!("Tool '{tool_name}' failed: {message}")),

        // Resource limits — retryable, PLLM can try simpler approach
        OrchestratorError::InterpreterError(InterpreterError::ToolCallLimitExceeded {
            limit,
        }) => ErrorClass::VmException(format!("Tool call limit exceeded (limit: {limit})")),

        OrchestratorError::InterpreterError(InterpreterError::GasExhausted { tool_calls }) => {
            ErrorClass::VmException(format!("Gas exhausted after {tool_calls} tool calls"))
        }

        // All other errors are fatal
        other => ErrorClass::Fatal(other),
    }
}
