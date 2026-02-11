//! Interpreter execution loop.
//!
//! Drives the synchronous interpreter through its async yield points.
//! The interpreter yields at tool calls, parse_with_ai, and verify_hypothesis;
//! this module performs the async work (tool execution, QLLM routing) and
//! resumes the interpreter.

use security_compass_interpreter::ExecutionResult;
use security_compass_meta::{Metadata, ValueWithMeta};

use crate::error::OrchestratorError;
use crate::qllm;
use crate::traits::{LlmClient, ToolExecutor};
use crate::types::{InternalTool, InterpreterLoopResult, Session};

impl Session {
    /// Runs the interpreter to completion, handling all yield points asynchronously.
    ///
    /// This is the core async loop that bridges the synchronous interpreter
    /// with the async tool execution and LLM calls.
    ///
    /// # Algorithm
    /// 1. Call `interpreter.execute()` to start execution
    /// 2. Loop on the `ExecutionResult`:
    ///    - `Complete` → return the result
    ///    - `NeedsToolCall` → execute the tool, resume
    ///    - `NeedsParseWithAi` → call QLLM, resume
    ///    - `NeedsVerifyHypothesis` → call QLLM, resume
    pub(crate) async fn run_interpreter_loop(
        &mut self,
        python_code: &str,
        input_vars: Vec<(String, ValueWithMeta<serde_json::Value>)>,
        llm_client: &dyn LlmClient,
        tool_executor: &dyn ToolExecutor,
    ) -> Result<InterpreterLoopResult, OrchestratorError> {
        // Read config values we need before the mutable borrow of interpreter
        let enabled_internal_tools = self.config.enabled_internal_tools.clone();
        let non_executable = self.interpreter.policy().preset.enable_non_executable_memory;

        // Start execution
        let mut result = self
            .interpreter
            .execute(python_code, input_vars, &self.tool_definitions)?;

        // Drive the interpreter through its yield points
        loop {
            match result {
                ExecutionResult::Complete {
                    value,
                    meta,
                    print_output,
                } => {
                    return Ok(InterpreterLoopResult {
                        value,
                        meta,
                        print_output,
                    });
                }

                ExecutionResult::NeedsToolCall {
                    tool_name,
                    args,
                    call_id: _,
                    state,
                    result_updates,
                    session_after_updates,
                } => {
                    // Execute the tool via the external executor
                    let tool_result = tool_executor.execute(&tool_name, &args).await?;

                    // Build result metadata
                    let result_meta =
                        Metadata::default_for_tool_result(&tool_name, non_executable);

                    // Resume the interpreter with the tool result
                    result = self.interpreter.resume_after_tool_call(
                        state,
                        &tool_name,
                        tool_result,
                        result_meta,
                        &result_updates,
                        &session_after_updates,
                    )?;
                }

                ExecutionResult::NeedsParseWithAi {
                    data,
                    query,
                    output_schema,
                    call_id: _,
                    state,
                } => {
                    // Check if parse_with_ai is enabled
                    if !enabled_internal_tools.contains(&InternalTool::ParseWithAi) {
                        return Err(OrchestratorError::InternalToolDisabled {
                            tool_name: "parse_with_ai".to_string(),
                        });
                    }

                    // Route to QLLM
                    let qllm_result =
                        qllm::call_qllm(llm_client, &data.value, &query, &output_schema).await?;

                    // Resume the interpreter with the QLLM result
                    result = self
                        .interpreter
                        .resume_after_parse_with_ai(state, &data.meta, qllm_result)?;
                }

                ExecutionResult::NeedsVerifyHypothesis {
                    hypothesis,
                    data,
                    call_id: _,
                    state,
                } => {
                    // Check if verify_hypothesis is enabled
                    if !enabled_internal_tools.contains(&InternalTool::VerifyHypothesis) {
                        return Err(OrchestratorError::InternalToolDisabled {
                            tool_name: "verify_hypothesis".to_string(),
                        });
                    }

                    // Route to QLLM
                    let verified =
                        qllm::call_qllm_verify(llm_client, &hypothesis, &data.value).await?;

                    // Resume the interpreter with the verification result
                    result = self
                        .interpreter
                        .resume_after_verify_hypothesis(state, &data.meta, verified)?;
                }
            }
        }
    }
}
