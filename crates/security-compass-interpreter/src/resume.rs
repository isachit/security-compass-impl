//! Resume methods for continuing execution after external work.
//!
//! These methods are called by the orchestrator after performing the work
//! requested by `ExecutionResult::NeedsToolCall`, `NeedsParseWithAi`, or
//! `NeedsVerifyHypothesis`.

use security_compass_meta::{Metadata, ValueWithMeta};
use sqrt_eval::ResolvedUpdate;

use crate::convert::json_to_monty;
use crate::error::InterpreterError;
use crate::policy::{apply_result_updates, apply_session_updates};
use crate::types::{ExecutionResult, Interpreter, ToolCallOutcome, ToolCallRecord, VmSnapshot};

impl Interpreter {
    /// Resumes execution after an external tool call has been performed.
    ///
    /// The orchestrator should call this after executing the tool and obtaining
    /// the result. This method:
    /// 1. Applies `result_updates` to the result metadata
    /// 2. Optionally adds `__non_executable` tag
    /// 3. Applies `session_after_updates` to session metadata
    /// 4. Records the tool call in history
    /// 5. Optionally caches the result
    /// 6. Resumes the VM with the result
    ///
    /// # Arguments
    /// * `state` - The VM snapshot from `ExecutionResult::NeedsToolCall`
    /// * `tool_name` - Name of the tool that was called
    /// * `tool_result` - The JSON result from the tool
    /// * `result_meta` - Base metadata for the tool result (typically from `Metadata::default_for_tool_result()`)
    /// * `result_updates` - Metadata updates to apply to the result (from the `NeedsToolCall`)
    /// * `session_after_updates` - Session metadata updates to apply (from the `NeedsToolCall`)
    pub fn resume_after_tool_call(
        &mut self,
        state: VmSnapshot,
        tool_name: &str,
        tool_result: serde_json::Value,
        mut result_meta: Metadata,
        result_updates: &[ResolvedUpdate],
        session_after_updates: &[ResolvedUpdate],
    ) -> Result<ExecutionResult, InterpreterError> {
        // 1. Apply result_updates to result metadata
        apply_result_updates(&mut result_meta, result_updates);

        // 2. Apply non_executable tag if enabled by policy preset
        if self.policy.preset.enable_non_executable_memory {
            // The Metadata::default_for_tool_result() already adds this tag when
            // non_executable=true, but result_updates may have changed the metadata.
            // Ensure the tag is present if the policy requires it.
            if !result_meta.is_non_executable() {
                result_meta.tags.insert(
                    security_compass_meta::NON_EXECUTABLE_TAG.to_string(),
                );
            }
        }

        // 3. Apply session_after_updates
        apply_session_updates(&mut self.session_meta, session_after_updates);

        // 4. Record tool call in history
        self.tool_call_history.push(ToolCallRecord {
            tool_name: tool_name.to_string(),
            call_id: 0, // call_id was in the NeedsToolCall, not passed here
            outcome: ToolCallOutcome::Executed,
        });

        // 5. Optionally cache the result
        if self.should_cache(tool_name) {
            // We need to rebuild the cache key. Since we don't have the original args,
            // we skip caching on resume. The cache is checked in handle_function_call()
            // where we have the args. This is a design trade-off: caching on the next
            // identical call rather than caching the result we just got.
            // To properly cache, we'd need the args passed through. For now, the cache
            // is populated via cache_key matching in the main loop.
        }

        // 6. Resume VM
        let result_obj = json_to_monty(tool_result);
        let progress = self.resume_vm_with_result(state, result_obj, result_meta)?;
        self.continue_execution(progress)
    }

    /// Resumes execution after a tool call, with full cache support.
    ///
    /// This variant also accepts the named args for cache key computation,
    /// enabling result caching on resume.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_after_tool_call_with_cache(
        &mut self,
        state: VmSnapshot,
        tool_name: &str,
        tool_result: serde_json::Value,
        mut result_meta: Metadata,
        result_updates: &[ResolvedUpdate],
        session_after_updates: &[ResolvedUpdate],
        named_args: &indexmap::IndexMap<String, ValueWithMeta<serde_json::Value>>,
    ) -> Result<ExecutionResult, InterpreterError> {
        // 1. Apply result_updates to result metadata
        apply_result_updates(&mut result_meta, result_updates);

        // 2. Apply non_executable tag if enabled
        if self.policy.preset.enable_non_executable_memory && !result_meta.is_non_executable() {
            result_meta
                .tags
                .insert(security_compass_meta::NON_EXECUTABLE_TAG.to_string());
        }

        // 3. Apply session_after_updates
        apply_session_updates(&mut self.session_meta, session_after_updates);

        // 4. Record tool call in history
        self.tool_call_history.push(ToolCallRecord {
            tool_name: tool_name.to_string(),
            call_id: 0,
            outcome: ToolCallOutcome::Executed,
        });

        // 5. Cache the result if applicable
        if self.should_cache(tool_name) {
            let cache_key = Self::cache_key(tool_name, named_args);
            self.tool_cache.insert(
                cache_key,
                ValueWithMeta {
                    value: tool_result.clone(),
                    meta: result_meta.clone(),
                },
            );
        }

        // 6. Resume VM
        let result_obj = json_to_monty(tool_result);
        let progress = self.resume_vm_with_result(state, result_obj, result_meta)?;
        self.continue_execution(progress)
    }

    /// Resumes execution after `parse_with_ai` has been performed by the QLLM.
    ///
    /// The orchestrator should call this after routing the data through the QLLM
    /// and obtaining the parsed result.
    ///
    /// # Arguments
    /// * `state` - The VM snapshot from `ExecutionResult::NeedsParseWithAi`
    /// * `input_meta` - The metadata from the `data` argument's `ValueWithMeta`
    /// * `result` - The parsed result from the QLLM (as JSON)
    pub fn resume_after_parse_with_ai(
        &mut self,
        state: VmSnapshot,
        input_meta: &Metadata,
        result: serde_json::Value,
    ) -> Result<ExecutionResult, InterpreterError> {
        // Build metadata: inherits from input, adds parse_with_ai tag and optionally non_executable
        let meta = Metadata::for_parse_with_ai_result(
            input_meta,
            self.policy.preset.enable_non_executable_memory,
        );

        // Convert and resume
        let result_obj = json_to_monty(result);
        let progress = self.resume_vm_with_result(state, result_obj, meta)?;
        self.continue_execution(progress)
    }

    /// Resumes execution after `verify_hypothesis` has been checked by the QLLM.
    ///
    /// The orchestrator should call this after the QLLM has verified whether
    /// the hypothesis holds against the data.
    ///
    /// # Arguments
    /// * `state` - The VM snapshot from `ExecutionResult::NeedsVerifyHypothesis`
    /// * `input_meta` - The metadata from the `data` argument's `ValueWithMeta`
    /// * `result` - Whether the hypothesis was verified (`true`) or not (`false`)
    pub fn resume_after_verify_hypothesis(
        &mut self,
        state: VmSnapshot,
        input_meta: &Metadata,
        result: bool,
    ) -> Result<ExecutionResult, InterpreterError> {
        // Clone input metadata and optionally add non_executable tag
        let mut meta = input_meta.clone();
        if self.policy.preset.enable_non_executable_memory && !meta.is_non_executable() {
            meta.tags
                .insert(security_compass_meta::NON_EXECUTABLE_TAG.to_string());
        }

        // Convert bool to MontyObject and resume
        let result_obj = security_compass_vm::MontyObject::Bool(result);
        let progress = self.resume_vm_with_result(state, result_obj, meta)?;
        self.continue_execution(progress)
    }
}
