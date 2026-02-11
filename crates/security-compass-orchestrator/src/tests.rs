//! Tests for the Security Compass Orchestrator.
//!
//! Test categories:
//! - Code extraction tests: Parsing PLLM responses for Python code blocks
//! - Prompt builder tests: PLLM system prompt construction
//! - Error feedback tests: Formatting error messages for PLLM retry
//! - QLLM tests: Direct call_qllm / call_qllm_verify behavior
//! - Session tests: Session lifecycle and state management
//! - Interpreter loop tests: Running code through the real VM with mock tools
//! - Turn processing tests: Full process_turn with PLLM retry logic
//! - Integration tests: End-to-end scenarios

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::json;

use security_compass_interpreter::{InterpreterConfig, ToolDefinition};
use security_compass_meta::{Metadata, ValueWithMeta};
use sqrt_eval::{CompiledPolicy, InternalPolicyPreset};

use crate::code_extraction::extract_code_block;
use crate::error::OrchestratorError;
use crate::prompt_builder::{build_error_feedback, build_pllm_system_prompt};
use crate::qllm::{call_qllm, call_qllm_verify};
use crate::traits::{LlmClient, ToolExecutor};
use crate::types::*;

// ============================================================
// Mock Infrastructure
// ============================================================

/// Mock LLM client that returns pre-configured responses in order.
struct MockLlmClient {
    /// Responses for `chat_completion` (PLLM path), popped from front.
    responses: Mutex<VecDeque<String>>,
    /// Responses for `chat_completion_with_schema` (QLLM path), popped from front.
    schema_responses: Mutex<VecDeque<serde_json::Value>>,
}

#[async_trait]
impl LlmClient for MockLlmClient {
    async fn chat_completion(
        &self,
        _messages: &[Message],
    ) -> Result<String, OrchestratorError> {
        let mut queue = self.responses.lock().unwrap();
        queue
            .pop_front()
            .ok_or_else(|| {
                OrchestratorError::LlmError {
                    message: "MockLlmClient: no more chat_completion responses queued".to_string(),
                }
            })
    }

    async fn chat_completion_with_schema(
        &self,
        _system_prompt: &str,
        _user_message: &str,
        _output_schema: &serde_json::Value,
    ) -> Result<serde_json::Value, OrchestratorError> {
        let mut queue = self.schema_responses.lock().unwrap();
        queue
            .pop_front()
            .ok_or_else(|| {
                OrchestratorError::LlmError {
                    message: "MockLlmClient: no more schema_responses queued".to_string(),
                }
            })
    }
}

/// Mock tool executor that returns pre-configured results per tool name.
struct MockToolExecutor {
    /// Results per tool name, popped from front of each queue.
    results: Mutex<HashMap<String, VecDeque<serde_json::Value>>>,
}

#[async_trait]
impl ToolExecutor for MockToolExecutor {
    async fn execute(
        &self,
        tool_name: &str,
        _args: &IndexMap<String, ValueWithMeta<serde_json::Value>>,
    ) -> Result<serde_json::Value, OrchestratorError> {
        let mut map = self.results.lock().unwrap();
        let queue = match map.get_mut(tool_name) {
            Some(q) => q,
            None => {
                return Err(OrchestratorError::ToolError {
                    tool_name: tool_name.to_string(),
                    message: format!(
                        "MockToolExecutor: no results configured for tool '{}'",
                        tool_name
                    ),
                });
            }
        };
        match queue.pop_front() {
            Some(val) => Ok(val),
            None => Err(OrchestratorError::ToolError {
                tool_name: tool_name.to_string(),
                message: format!(
                    "MockToolExecutor: result queue exhausted for tool '{}'",
                    tool_name
                ),
            }),
        }
    }
}

// ============================================================
// Test Helpers
// ============================================================

fn parse_and_compile(src: &str) -> CompiledPolicy {
    let program = sqrt_parser::parse(src).expect("Parse failed");
    sqrt_eval::compile(&program, InternalPolicyPreset::default()).expect("Compile failed")
}

fn default_session_config() -> SessionConfig {
    SessionConfig::default()
}

fn simple_tool(name: &str, params: &[&str]) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        parameter_names: params.iter().map(|s| (*s).to_string()).collect(),
        deterministic: false,
    }
}

fn make_session(policy_src: &str, tools: Vec<ToolDefinition>) -> Session {
    let policy = parse_and_compile(policy_src);
    Session::new(
        policy,
        default_session_config(),
        InterpreterConfig::default(),
        tools,
    )
}

fn mock_pllm(responses: Vec<&str>) -> MockLlmClient {
    MockLlmClient {
        responses: Mutex::new(responses.into_iter().map(String::from).collect()),
        schema_responses: Mutex::new(VecDeque::new()),
    }
}

fn mock_pllm_with_schema(
    responses: Vec<&str>,
    schema_responses: Vec<serde_json::Value>,
) -> MockLlmClient {
    MockLlmClient {
        responses: Mutex::new(responses.into_iter().map(String::from).collect()),
        schema_responses: Mutex::new(schema_responses.into_iter().collect()),
    }
}

fn mock_tool_executor(tools: HashMap<&str, Vec<serde_json::Value>>) -> MockToolExecutor {
    let results: HashMap<String, VecDeque<serde_json::Value>> = tools
        .into_iter()
        .map(|(name, vals)| (name.to_string(), vals.into_iter().collect()))
        .collect();
    MockToolExecutor {
        results: Mutex::new(results),
    }
}

fn empty_tool_executor() -> MockToolExecutor {
    MockToolExecutor {
        results: Mutex::new(HashMap::new()),
    }
}

// ============================================================
// 1. Code Extraction Tests (12)
// ============================================================

#[test]
fn extract_python_code_fence() {
    let response = "Here is the code:\n```python\nx = 42\nx\n```\n";
    let result = extract_code_block(response, true).unwrap();
    assert_eq!(result, Some("x = 42\nx".to_string()));
}

#[test]
fn extract_generic_code_fence() {
    let response = "```\nresult = 1 + 1\nresult\n```";
    let result = extract_code_block(response, true).unwrap();
    assert_eq!(result, Some("result = 1 + 1\nresult".to_string()));
}

#[test]
fn extract_py_code_fence() {
    let response = "```py\nprint('hello')\n```";
    let result = extract_code_block(response, true).unwrap();
    assert_eq!(result, Some("print('hello')".to_string()));
}

#[test]
fn extract_first_of_multiple_blocks() {
    let response = "First block:\n```python\nfirst = 1\n```\nSecond:\n```python\nsecond = 2\n```";
    let result = extract_code_block(response, true).unwrap();
    assert_eq!(
        result,
        Some("first = 1".to_string()),
        "Should extract the first python code block"
    );
}

#[test]
fn no_code_block_returns_none() {
    let response = "I think the answer is 42. No code here.";
    let result = extract_code_block(response, true).unwrap();
    assert_eq!(result, None, "Plain text without fences should return None");
}

#[test]
fn empty_code_block() {
    let response = "```python\n```";
    let result = extract_code_block(response, true).unwrap();
    // An empty code block has nothing between the fences
    assert_eq!(result, Some(String::new()));
}

#[test]
fn clarification_response() {
    let response = "CLARIFICATION: What email address should I use?";
    let result = extract_code_block(response, true);
    match result {
        Err(OrchestratorError::ClarificationRequested { message }) => {
            assert!(
                message.contains("email address"),
                "Clarification message should be preserved: got '{}'",
                message
            );
        }
        other => panic!(
            "Expected ClarificationRequested error, got {:?}",
            other
        ),
    }
}

#[test]
fn clarification_disabled_returns_none() {
    let response = "CLARIFICATION: I need more details.";
    let result = extract_code_block(response, false).unwrap();
    // With allow_clarification=false, the CLARIFICATION prefix is not treated specially.
    // Since there's no code fence, should return None.
    assert_eq!(
        result, None,
        "With clarification disabled and no code fence, should return None"
    );
}

#[test]
fn code_with_trailing_whitespace() {
    let response = "```python\nx = 42  \n  \n```";
    let result = extract_code_block(response, true).unwrap();
    // The extraction trims trailing whitespace from the code
    let code = result.unwrap();
    assert!(
        !code.ends_with(' ') && !code.ends_with('\n'),
        "Code should be trimmed, got: {:?}",
        code
    );
    assert!(code.contains("x = 42"));
}

#[test]
fn mixed_content_with_code() {
    let response = "Let me write that for you.\n\nHere is the solution:\n\n```python\nresult = 'hello'\nresult\n```\n\nThis should work!";
    let result = extract_code_block(response, true).unwrap();
    assert_eq!(result, Some("result = 'hello'\nresult".to_string()));
}

#[test]
fn only_opening_fence_no_closing() {
    let response = "```python\nthis has no closing fence";
    let result = extract_code_block(response, true).unwrap();
    assert_eq!(
        result, None,
        "An opening fence without a closing fence should return None"
    );
}

#[test]
fn code_with_backtick_inside() {
    let response = "```python\nx = \"hello `world`\"\nx\n```";
    let result = extract_code_block(response, true).unwrap();
    let code = result.unwrap();
    assert!(
        code.contains("`world`"),
        "Backticks within code should be preserved: got {:?}",
        code
    );
}

// ============================================================
// 2. Prompt Builder Tests (8)
// ============================================================

#[test]
fn prompt_contains_role_preamble() {
    let config = default_session_config();
    let prompt = build_pllm_system_prompt(&[], &config);
    assert!(
        prompt.contains("code-generation assistant"),
        "System prompt should contain role preamble"
    );
}

#[test]
fn prompt_lists_tool_signatures() {
    let tools = vec![simple_tool("send_email", &["to", "subject", "body"])];
    let config = default_session_config();
    let prompt = build_pllm_system_prompt(&tools, &config);
    assert!(
        prompt.contains("def send_email(to, subject, body) -> Any:"),
        "Prompt should contain tool signature. Got:\n{}",
        prompt
    );
}

#[test]
fn prompt_includes_internal_tools_when_enabled() {
    let config = SessionConfig {
        enabled_internal_tools: vec![InternalTool::ParseWithAi, InternalTool::VerifyHypothesis],
        ..default_session_config()
    };
    let prompt = build_pllm_system_prompt(&[], &config);
    assert!(
        prompt.contains("parse_with_ai"),
        "Prompt should include parse_with_ai when enabled"
    );
    assert!(
        prompt.contains("verify_hypothesis"),
        "Prompt should include verify_hypothesis when enabled"
    );
}

#[test]
fn prompt_excludes_internal_tools_when_disabled() {
    let config = SessionConfig {
        enabled_internal_tools: vec![],
        ..default_session_config()
    };
    let prompt = build_pllm_system_prompt(&[], &config);
    assert!(
        !prompt.contains("parse_with_ai"),
        "Prompt should not include parse_with_ai when disabled"
    );
    assert!(
        !prompt.contains("verify_hypothesis"),
        "Prompt should not include verify_hypothesis when disabled"
    );
}

#[test]
fn prompt_includes_clarification_section() {
    let config = SessionConfig {
        pllm_can_ask_for_clarification: true,
        ..default_session_config()
    };
    let prompt = build_pllm_system_prompt(&[], &config);
    assert!(
        prompt.contains("CLARIFICATION:"),
        "Prompt should contain clarification instructions when enabled"
    );
}

#[test]
fn prompt_excludes_clarification_when_disabled() {
    let config = SessionConfig {
        pllm_can_ask_for_clarification: false,
        ..default_session_config()
    };
    let prompt = build_pllm_system_prompt(&[], &config);
    assert!(
        !prompt.contains("CLARIFICATION:"),
        "Prompt should not contain CLARIFICATION when disabled"
    );
}

#[test]
fn prompt_includes_multi_step_section() {
    let config = SessionConfig {
        enable_multi_step_planning: true,
        ..default_session_config()
    };
    let prompt = build_pllm_system_prompt(&[], &config);
    assert!(
        prompt.contains("Multi-Step"),
        "Prompt should contain Multi-Step section when enabled"
    );
}

#[test]
fn error_feedback_minimal() {
    let error = ErrorClass::VmException("ZeroDivisionError: division by zero".to_string());
    let msg = build_error_feedback(&error, DebugInfoLevel::Minimal, 1, 3);
    // Minimal should NOT include the actual error message details
    assert!(
        !msg.content.contains("ZeroDivisionError"),
        "Minimal feedback should not include error details. Got: {}",
        msg.content
    );
    assert!(
        msg.content.contains("raised an error"),
        "Minimal feedback should mention an error occurred"
    );
}

// ============================================================
// 3. Error Feedback Tests (3)
// ============================================================

#[test]
fn error_feedback_normal() {
    let error = ErrorClass::VmException("NameError: name 'x' is not defined\n  at line 3".to_string());
    let msg = build_error_feedback(&error, DebugInfoLevel::Normal, 2, 3);
    // Normal includes the first line of the error
    assert!(
        msg.content.contains("NameError"),
        "Normal feedback should include the first line of the error. Got: {}",
        msg.content
    );
    assert!(
        msg.content.contains("attempt 2/3"),
        "Normal feedback should include attempt counter"
    );
}

#[test]
fn error_feedback_extra() {
    let error = ErrorClass::VmException("TypeError: unsupported operand\n  at line 5\n  in function foo".to_string());
    let msg = build_error_feedback(&error, DebugInfoLevel::Extra, 1, 3);
    // Extra includes full details in a code block
    assert!(
        msg.content.contains("```"),
        "Extra feedback should contain a code block. Got: {}",
        msg.content
    );
    assert!(
        msg.content.contains("in function foo"),
        "Extra feedback should include the full error details"
    );
}

#[test]
fn error_feedback_policy_violation() {
    let error = ErrorClass::PolicyViolation("Tool call to 'send_email' denied: must deny".to_string());
    let msg = build_error_feedback(&error, DebugInfoLevel::Normal, 1, 3);
    assert!(
        msg.content.contains("security policy"),
        "Policy violation feedback should mention security policy. Got: {}",
        msg.content
    );
}

// ============================================================
// 4. QLLM Tests (6)
// ============================================================

#[tokio::test]
async fn call_qllm_basic() {
    let llm = MockLlmClient {
        responses: Mutex::new(VecDeque::new()),
        schema_responses: Mutex::new(VecDeque::from([json!({
            "name": "John",
            "have_enough_information": true
        })])),
    };
    let data = json!("John Smith is an engineer");
    let schema = json!({"type": "object"});
    let result = call_qllm(&llm, &data, "extract name", &schema).await.unwrap();
    assert_eq!(result["name"], "John");
}

#[tokio::test]
async fn call_qllm_not_enough_info() {
    let llm = MockLlmClient {
        responses: Mutex::new(VecDeque::new()),
        schema_responses: Mutex::new(VecDeque::from([json!({
            "have_enough_information": false,
            "name": null
        })])),
    };
    let data = json!("no useful data here");
    let schema = json!({"type": "object"});
    let result = call_qllm(&llm, &data, "extract name", &schema).await;
    assert!(
        matches!(result, Err(OrchestratorError::QllmInsufficientInfo)),
        "Should return QllmInsufficientInfo when have_enough_information is false"
    );
}

#[tokio::test]
async fn call_qllm_schema_forwarded() {
    // Verify the schema is forwarded to the LLM client. Since MockLlmClient
    // does not record the schema, we verify indirectly that the call succeeds
    // and returns valid data when a response is queued.
    let llm = MockLlmClient {
        responses: Mutex::new(VecDeque::new()),
        schema_responses: Mutex::new(VecDeque::from([json!({"result": "parsed"})])),
    };
    let data = json!("some data");
    let schema = json!({
        "type": "object",
        "properties": {
            "result": {"type": "string"}
        }
    });
    let result = call_qllm(&llm, &data, "parse it", &schema).await.unwrap();
    assert_eq!(result["result"], "parsed");
}

#[tokio::test]
async fn call_qllm_verify_true() {
    let llm = MockLlmClient {
        responses: Mutex::new(VecDeque::new()),
        schema_responses: Mutex::new(VecDeque::from([json!({
            "result": true,
            "reasoning": "confirmed"
        })])),
    };
    let data = json!(42);
    let result = call_qllm_verify(&llm, "is positive", &data).await.unwrap();
    assert!(result, "Should return true when result field is true");
}

#[tokio::test]
async fn call_qllm_verify_false() {
    let llm = MockLlmClient {
        responses: Mutex::new(VecDeque::new()),
        schema_responses: Mutex::new(VecDeque::from([json!({
            "result": false,
            "reasoning": "not confirmed"
        })])),
    };
    let data = json!(-1);
    let result = call_qllm_verify(&llm, "is positive", &data).await.unwrap();
    assert!(!result, "Should return false when result field is false");
}

#[tokio::test]
async fn call_qllm_verify_missing_field() {
    let llm = MockLlmClient {
        responses: Mutex::new(VecDeque::new()),
        schema_responses: Mutex::new(VecDeque::from([json!({
            "reasoning": "no result field here"
        })])),
    };
    let data = json!("test");
    let result = call_qllm_verify(&llm, "some hypothesis", &data)
        .await
        .unwrap();
    assert!(
        !result,
        "Should default to false when result field is missing"
    );
}

// ============================================================
// 5. Session Tests (6)
// ============================================================

#[test]
fn session_new_has_uuid() {
    let session = make_session("", vec![]);
    assert!(
        !session.id().is_nil(),
        "New session should have a non-nil UUID"
    );
}

#[test]
fn session_starts_at_turn_zero() {
    let session = make_session("", vec![]);
    assert_eq!(
        session.turn_count(),
        0,
        "New session should start at turn count 0"
    );
}

#[tokio::test]
async fn session_turn_limit_enforced() {
    let policy = parse_and_compile("");
    let config = SessionConfig {
        max_n_turns: Some(1),
        ..default_session_config()
    };
    let mut session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        vec![],
    );
    let llm = mock_pllm(vec!["```python\n42\n```"]);
    let executor = empty_tool_executor();

    // First turn should succeed
    let result = session.process_turn("first", &llm, &executor).await.unwrap();
    assert_eq!(result.status, TurnStatus::Success);

    // Second turn should hit the limit
    let err = session.process_turn("second", &llm, &executor).await;
    match err {
        Err(OrchestratorError::MaxTurnsExceeded { limit }) => {
            assert_eq!(limit, 1, "Turn limit should be 1");
        }
        other => panic!("Expected MaxTurnsExceeded, got {:?}", other),
    }
}

#[tokio::test]
async fn session_reset_clears_state() {
    let policy = parse_and_compile("");
    let mut session = Session::new(
        policy,
        default_session_config(),
        InterpreterConfig::default(),
        vec![],
    );
    let llm = mock_pllm(vec!["```python\n42\n```"]);
    let executor = empty_tool_executor();

    // Process a turn
    let _ = session.process_turn("test", &llm, &executor).await.unwrap();
    assert!(session.turn_count() > 0);
    assert!(!session.message_history().is_empty());

    // Reset should clear state
    session.reset();
    assert_eq!(session.turn_count(), 0, "Turn count should be 0 after reset");
    assert!(
        session.message_history().is_empty(),
        "Message history should be empty after reset"
    );
}

#[tokio::test]
async fn session_message_history_grows() {
    let policy = parse_and_compile("");
    let mut session = Session::new(
        policy,
        default_session_config(),
        InterpreterConfig::default(),
        vec![],
    );
    let llm = mock_pllm(vec!["```python\n42\n```"]);
    let executor = empty_tool_executor();

    assert!(session.message_history().is_empty());
    let _ = session.process_turn("hello", &llm, &executor).await.unwrap();

    // After a successful turn, history should contain the user message + assistant code
    assert!(
        session.message_history().len() >= 2,
        "Message history should contain at least user + assistant messages, got {}",
        session.message_history().len()
    );
}

#[test]
fn session_config_accessible() {
    let config = SessionConfig {
        max_pllm_attempts: 5,
        pllm_model: "test-model".to_string(),
        ..default_session_config()
    };
    let policy = parse_and_compile("");
    let session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        vec![],
    );
    assert_eq!(session.config().max_pllm_attempts, 5);
    assert_eq!(session.config().pllm_model, "test-model");
}

// ============================================================
// 6. Interpreter Loop Tests (10)
// ============================================================

#[tokio::test]
async fn loop_simple_expression() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm(vec![]);
    let executor = empty_tool_executor();

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("test"),
            meta: Metadata::default(),
        },
    )];

    let result = session
        .run_interpreter_loop("1 + 1", input_vars, &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.value, json!(2), "1 + 1 should evaluate to 2");
}

#[tokio::test]
async fn loop_single_tool_call() {
    let tools = vec![simple_tool("get_data", &["query"])];
    let mut session = make_session("", tools);
    let llm = mock_pllm(vec![]);
    let mut tool_map = HashMap::new();
    tool_map.insert("get_data", vec![json!({"result": "found"})]);
    let executor = mock_tool_executor(tool_map);

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("test"),
            meta: Metadata::default(),
        },
    )];

    let result = session
        .run_interpreter_loop(
            "result = get_data('test')\nresult",
            input_vars,
            &llm,
            &executor,
        )
        .await
        .unwrap();

    assert_eq!(
        result.value,
        json!({"result": "found"}),
        "Tool call result should be returned"
    );
}

#[tokio::test]
async fn loop_multiple_tool_calls() {
    let tools = vec![simple_tool("fetch", &["url"])];
    let mut session = make_session("", tools);
    let llm = mock_pllm(vec![]);
    let mut tool_map = HashMap::new();
    tool_map.insert("fetch", vec![json!("page1"), json!("page2")]);
    let executor = mock_tool_executor(tool_map);

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("test"),
            meta: Metadata::default(),
        },
    )];

    let code = "a = fetch('url1')\nb = fetch('url2')\n[a, b]";
    let result = session
        .run_interpreter_loop(code, input_vars, &llm, &executor)
        .await
        .unwrap();

    assert_eq!(
        result.value,
        json!(["page1", "page2"]),
        "Multiple tool calls should return combined results"
    );
}

#[tokio::test]
async fn loop_parse_with_ai_routing() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm_with_schema(vec![], vec![json!({"name": "Alice"})]);
    let executor = empty_tool_executor();

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("Alice is an engineer"),
            meta: Metadata::default(),
        },
    )];

    let code = "result = parse_with_ai(user_message, 'extract name', {})\nresult";
    let result = session
        .run_interpreter_loop(code, input_vars, &llm, &executor)
        .await
        .unwrap();

    assert_eq!(
        result.value,
        json!({"name": "Alice"}),
        "parse_with_ai should route to QLLM and return result"
    );
}

#[tokio::test]
async fn loop_verify_hypothesis_routing() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm_with_schema(
        vec![],
        vec![json!({"result": true, "reasoning": "confirmed"})],
    );
    let executor = empty_tool_executor();

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!(42),
            meta: Metadata::default(),
        },
    )];

    let code = "result = verify_hypothesis('is positive', user_message)\nresult";
    let result = session
        .run_interpreter_loop(code, input_vars, &llm, &executor)
        .await
        .unwrap();

    assert_eq!(
        result.value,
        json!(true),
        "verify_hypothesis should route to QLLM and return boolean"
    );
}

#[tokio::test]
async fn loop_tool_error_propagates() {
    // Use a tool executor with no results to trigger an error
    let tools = vec![simple_tool("bad_tool", &["arg"])];
    let mut session = make_session("", tools);
    let llm = mock_pllm(vec![]);
    // Empty queue for bad_tool will cause ToolError
    let mut tool_map = HashMap::new();
    tool_map.insert("bad_tool", vec![]);
    let executor = mock_tool_executor(tool_map);

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("test"),
            meta: Metadata::default(),
        },
    )];

    let result = session
        .run_interpreter_loop("bad_tool('x')", input_vars, &llm, &executor)
        .await;

    assert!(result.is_err(), "Tool error should propagate");
    match result {
        Err(OrchestratorError::ToolError { tool_name, .. }) => {
            assert_eq!(tool_name, "bad_tool");
        }
        Err(other) => panic!("Expected ToolError, got {:?}", other),
        Ok(_) => panic!("Expected ToolError, but got Ok"),
    }
}

#[tokio::test]
async fn loop_qllm_error_propagates() {
    let mut session = make_session("", vec![]);
    // Empty schema_responses will cause an LlmError
    let llm = mock_pllm_with_schema(vec![], vec![]);
    let executor = empty_tool_executor();

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("data"),
            meta: Metadata::default(),
        },
    )];

    let code = "parse_with_ai(user_message, 'query', {})";
    let result = session
        .run_interpreter_loop(code, input_vars, &llm, &executor)
        .await;

    assert!(result.is_err(), "QLLM error should propagate");
    match result {
        Err(OrchestratorError::LlmError { .. }) => {}
        Err(other) => panic!("Expected LlmError, got {:?}", other),
        Ok(_) => panic!("Expected LlmError, but got Ok"),
    }
}

#[tokio::test]
async fn loop_mixed_tool_and_qllm() {
    let tools = vec![simple_tool("get_data", &["query"])];
    let mut session = make_session("", tools);
    let llm = mock_pllm_with_schema(
        vec![],
        vec![json!({"name": "Bob"})],
    );
    let mut tool_map = HashMap::new();
    tool_map.insert("get_data", vec![json!("Bob is a developer")]);
    let executor = mock_tool_executor(tool_map);

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("test"),
            meta: Metadata::default(),
        },
    )];

    let code = "data = get_data('bob')\nresult = parse_with_ai(data, 'extract name', {})\nresult";
    let result = session
        .run_interpreter_loop(code, input_vars, &llm, &executor)
        .await
        .unwrap();

    assert_eq!(
        result.value,
        json!({"name": "Bob"}),
        "Mixed tool + QLLM calls should work in sequence"
    );
}

#[tokio::test]
async fn loop_policy_deny_is_interpreter_error() {
    // Policy denies all calls to "dangerous_tool"
    let policy_src = r#"
        tool "dangerous_tool" {
            must deny always;
        }
    "#;
    let tools = vec![simple_tool("dangerous_tool", &["arg"])];
    let policy = parse_and_compile(policy_src);
    let mut session = Session::new(
        policy,
        default_session_config(),
        InterpreterConfig::default(),
        tools,
    );
    let llm = mock_pllm(vec![]);
    let executor = empty_tool_executor();

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("test"),
            meta: Metadata::default(),
        },
    )];

    // The policy deny raises a RuntimeError inside the VM. Since the code
    // does not catch it, it propagates as an InterpreterError::VmError.
    let code = "dangerous_tool('evil')";
    let result = session
        .run_interpreter_loop(code, input_vars, &llm, &executor)
        .await;

    assert!(
        result.is_err(),
        "Policy denial should propagate as an error when uncaught"
    );
}

#[tokio::test]
async fn loop_internal_tool_disabled() {
    let policy = parse_and_compile("");
    let config = SessionConfig {
        enabled_internal_tools: vec![], // No internal tools enabled
        ..default_session_config()
    };
    let mut session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        vec![],
    );
    let llm = mock_pllm(vec![]);
    let executor = empty_tool_executor();

    let input_vars = vec![(
        "user_message".to_string(),
        ValueWithMeta {
            value: json!("data"),
            meta: Metadata::default(),
        },
    )];

    let code = "parse_with_ai(user_message, 'query', {})";
    let result = session
        .run_interpreter_loop(code, input_vars, &llm, &executor)
        .await;

    match result {
        Err(OrchestratorError::InternalToolDisabled { tool_name }) => {
            assert_eq!(tool_name, "parse_with_ai");
        }
        Err(other) => panic!("Expected InternalToolDisabled, got {:?}", other),
        Ok(_) => panic!("Expected InternalToolDisabled, but got Ok"),
    }
}

// ============================================================
// 7. Turn Processing Tests (12)
// ============================================================

#[tokio::test]
async fn turn_success_simple() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm(vec!["```python\n42\n```"]);
    let executor = empty_tool_executor();

    let result = session.process_turn("compute", &llm, &executor).await.unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(
        result.final_return_value,
        Some(json!(42)),
        "Simple expression should return 42"
    );
    assert_eq!(result.attempts, 1);
}

#[tokio::test]
async fn turn_success_with_tool_call() {
    let tools = vec![simple_tool("get_data", &["query"])];
    let mut session = make_session("", tools);
    let llm = mock_pllm(vec!["```python\nresult = get_data('test')\nresult\n```"]);
    let mut tool_map = HashMap::new();
    tool_map.insert("get_data", vec![json!({"key": "value"})]);
    let executor = mock_tool_executor(tool_map);

    let result = session
        .process_turn("fetch data", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(
        result.final_return_value,
        Some(json!({"key": "value"}))
    );
}

#[tokio::test]
async fn turn_retry_on_vm_error() {
    let mut session = make_session("", vec![]);
    // First attempt: division by zero (VM error), second attempt: valid code
    let llm = mock_pllm(vec![
        "```python\n1/0\n```",
        "```python\n42\n```",
    ]);
    let executor = empty_tool_executor();

    let result = session.process_turn("compute", &llm, &executor).await.unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(result.final_return_value, Some(json!(42)));
    assert_eq!(result.attempts, 2, "Should succeed on second attempt");
}

#[tokio::test]
async fn turn_retry_on_no_code_block() {
    let mut session = make_session("", vec![]);
    // First attempt: plain text (no code fence), second attempt: proper code
    let llm = mock_pllm(vec![
        "I think the answer is 42",
        "```python\n42\n```",
    ]);
    let executor = empty_tool_executor();

    let result = session.process_turn("compute", &llm, &executor).await.unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(result.final_return_value, Some(json!(42)));
    assert_eq!(result.attempts, 2, "Should succeed on second attempt after no-code retry");
}

#[tokio::test]
async fn turn_max_attempts_exceeded() {
    let mut session = make_session("", vec![]);
    // All 3 attempts return bad code
    let llm = mock_pllm(vec![
        "```python\n1/0\n```",
        "```python\nundefined_var\n```",
        "```python\n1/0\n```",
    ]);
    let executor = empty_tool_executor();

    let result = session.process_turn("compute", &llm, &executor).await.unwrap();

    assert_eq!(
        result.status,
        TurnStatus::MaxAttemptsExceeded,
        "Should return MaxAttemptsExceeded after 3 failures"
    );
    assert_eq!(result.attempts, 3);
    assert!(result.error.is_some());
}

#[tokio::test]
async fn turn_clarification_requested() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm(vec!["CLARIFICATION: What email address should I use?"]);
    let executor = empty_tool_executor();

    let result = session
        .process_turn("send an email", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::ClarificationNeeded);
    assert!(
        result.error.as_ref().unwrap().contains("email address"),
        "Clarification message should be preserved"
    );
}

#[tokio::test]
async fn turn_clear_meta_every_turn() {
    // Use a policy that adds a tag to session meta via session-after updates
    let policy_src = r#"
        tool "tag_session" {
            must allow always;
            session after {
                @tags |= {"from_first_turn"};
            }
        }
    "#;
    let tools = vec![simple_tool("tag_session", &[])];
    let policy = parse_and_compile(policy_src);
    let config = SessionConfig {
        clear_session_meta: ClearSessionMeta::EveryTurn,
        ..default_session_config()
    };
    let mut session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        tools,
    );

    // First turn: calls tag_session which sets a session tag
    let llm = mock_pllm(vec![
        "```python\ntag_session()\n```",
        "```python\n42\n```",
    ]);
    let mut tool_map = HashMap::new();
    tool_map.insert("tag_session", vec![json!(null)]);
    let executor = mock_tool_executor(tool_map);

    let _ = session.process_turn("first", &llm, &executor).await.unwrap();

    // Second turn: the EveryTurn clearing should have removed the tag before this turn
    let _ = session.process_turn("second", &llm, &executor).await.unwrap();

    // After the second turn, the session meta should not contain the tag from the first turn
    // because EveryTurn clears it at the start of the turn
    assert!(
        !session.session_meta().tags.contains("from_first_turn"),
        "EveryTurn should clear session metadata between turns"
    );
}

#[tokio::test]
async fn turn_clear_meta_every_attempt() {
    let policy = parse_and_compile("");
    let config = SessionConfig {
        clear_session_meta: ClearSessionMeta::EveryAttempt,
        ..default_session_config()
    };
    let mut session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        vec![],
    );

    // First attempt fails (VM error), second succeeds.
    // Session meta should be cleared before each attempt.
    let llm = mock_pllm(vec![
        "```python\n1/0\n```",
        "```python\n42\n```",
    ]);
    let executor = empty_tool_executor();

    let result = session.process_turn("test", &llm, &executor).await.unwrap();
    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(result.attempts, 2);
}

#[tokio::test]
async fn turn_prune_failed_steps() {
    let policy = parse_and_compile("");
    let config = SessionConfig {
        prune_failed_steps: true,
        ..default_session_config()
    };
    let mut session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        vec![],
    );

    // First attempt fails, second succeeds
    let llm = mock_pllm(vec![
        "```python\n1/0\n```",
        "```python\n42\n```",
    ]);
    let executor = empty_tool_executor();

    let _ = session.process_turn("test", &llm, &executor).await.unwrap();

    // With prune_failed_steps=true, the failed assistant code should NOT be in history
    let assistant_msgs: Vec<_> = session
        .message_history()
        .iter()
        .filter(|m| matches!(m.role, Role::Assistant))
        .collect();

    // Only the successful code should be in history
    assert_eq!(
        assistant_msgs.len(),
        1,
        "With pruning enabled, only the successful attempt should be in history"
    );
}

#[tokio::test]
async fn turn_no_prune_failed_steps() {
    let policy = parse_and_compile("");
    let config = SessionConfig {
        prune_failed_steps: false,
        ..default_session_config()
    };
    let mut session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        vec![],
    );

    // First attempt fails, second succeeds
    let llm = mock_pllm(vec![
        "```python\n1/0\n```",
        "```python\n42\n```",
    ]);
    let executor = empty_tool_executor();

    let _ = session.process_turn("test", &llm, &executor).await.unwrap();

    // With prune_failed_steps=false, the failed code IS added to history
    let assistant_msgs: Vec<_> = session
        .message_history()
        .iter()
        .filter(|m| matches!(m.role, Role::Assistant))
        .collect();

    assert!(
        assistant_msgs.len() >= 2,
        "Without pruning, both failed and successful attempts should be in history, got {}",
        assistant_msgs.len()
    );
}

#[tokio::test]
async fn turn_message_history_updated() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm(vec!["```python\n'hello'\n```"]);
    let executor = empty_tool_executor();

    let _ = session.process_turn("greet me", &llm, &executor).await.unwrap();

    let history = session.message_history();
    // Should have at least a user message and an assistant message
    let has_user = history.iter().any(|m| matches!(m.role, Role::User));
    let has_assistant = history.iter().any(|m| matches!(m.role, Role::Assistant));
    assert!(has_user, "History should contain a user message");
    assert!(has_assistant, "History should contain an assistant message");
}

#[tokio::test]
async fn turn_fatal_error_not_retried() {
    let mut session = make_session("", vec![]);
    // LLM returns an error (empty response queue), which is a fatal LlmError
    let llm = mock_pllm(vec![]); // No responses = LlmError on first call
    let executor = empty_tool_executor();

    let result = session.process_turn("test", &llm, &executor).await;

    // LlmError is classified as Fatal, should not be retried
    assert!(
        result.is_err(),
        "Fatal LLM error should propagate immediately without retry"
    );
    match result.unwrap_err() {
        OrchestratorError::LlmError { .. } => {}
        other => panic!("Expected LlmError, got {:?}", other),
    }
}

// ============================================================
// 8. Integration Tests (8)
// ============================================================

#[tokio::test]
async fn full_turn_with_policy_enforcement() {
    // Policy explicitly allows get_data
    let policy_src = r#"
        tool "get_data" {
            must allow always;
        }
    "#;
    let tools = vec![simple_tool("get_data", &["query"])];
    let policy = parse_and_compile(policy_src);
    let mut session = Session::new(
        policy,
        default_session_config(),
        InterpreterConfig::default(),
        tools,
    );

    let llm = mock_pllm(vec!["```python\nresult = get_data('q')\nresult\n```"]);
    let mut tool_map = HashMap::new();
    tool_map.insert("get_data", vec![json!({"status": "ok"})]);
    let executor = mock_tool_executor(tool_map);

    let result = session
        .process_turn("get some data", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(result.final_return_value, Some(json!({"status": "ok"})));
}

#[tokio::test]
async fn full_multi_turn_session() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm(vec![
        "```python\n1\n```",
        "```python\n2\n```",
    ]);
    let executor = empty_tool_executor();

    // First turn
    let r1 = session.process_turn("first", &llm, &executor).await.unwrap();
    assert_eq!(r1.status, TurnStatus::Success);
    assert_eq!(r1.final_return_value, Some(json!(1)));
    assert_eq!(session.turn_count(), 1);

    // Second turn
    let r2 = session.process_turn("second", &llm, &executor).await.unwrap();
    assert_eq!(r2.status, TurnStatus::Success);
    assert_eq!(r2.final_return_value, Some(json!(2)));
    assert_eq!(session.turn_count(), 2, "Turn count should increment to 2");
}

#[tokio::test]
async fn parse_with_ai_end_to_end() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm_with_schema(
        vec!["```python\nresult = parse_with_ai(user_message, 'extract name', {})\nresult\n```"],
        vec![json!({"name": "Charlie"})],
    );
    let executor = empty_tool_executor();

    let result = session
        .process_turn("parse this: Charlie is a chef", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(
        result.final_return_value,
        Some(json!({"name": "Charlie"}))
    );
}

#[tokio::test]
async fn verify_hypothesis_end_to_end() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm_with_schema(
        vec!["```python\nresult = verify_hypothesis('contains a number', user_message)\nresult\n```"],
        vec![json!({"result": true, "reasoning": "yes"})],
    );
    let executor = empty_tool_executor();

    let result = session
        .process_turn("check: abc123", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(result.final_return_value, Some(json!(true)));
}

#[tokio::test]
async fn policy_deny_with_retry() {
    // Policy denies "dangerous_tool" but allows "safe_tool"
    let policy_src = r#"
        tool "dangerous_tool" {
            must deny always;
        }
        tool "safe_tool" {
            must allow always;
        }
    "#;
    let tools = vec![
        simple_tool("dangerous_tool", &["arg"]),
        simple_tool("safe_tool", &["arg"]),
    ];
    let policy = parse_and_compile(policy_src);
    let mut session = Session::new(
        policy,
        default_session_config(),
        InterpreterConfig::default(),
        tools,
    );

    // First attempt calls dangerous_tool (will get a RuntimeError from policy deny),
    // second attempt uses safe_tool (succeeds).
    let llm = mock_pllm(vec![
        "```python\ndangerous_tool('evil')\n```",
        "```python\nresult = safe_tool('good')\nresult\n```",
    ]);
    let mut tool_map = HashMap::new();
    tool_map.insert("safe_tool", vec![json!("safe_result")]);
    let executor = mock_tool_executor(tool_map);

    let result = session
        .process_turn("do something", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(result.final_return_value, Some(json!("safe_result")));
    assert_eq!(
        result.attempts, 2,
        "Should succeed on second attempt after policy denial"
    );
}

#[tokio::test]
async fn session_meta_cleared_per_config() {
    // Use a policy that adds a tag to session meta via session-after updates
    let policy_src = r#"
        tool "mark_session" {
            must allow always;
            session after {
                @tags |= {"marked"};
            }
        }
    "#;
    let tools = vec![simple_tool("mark_session", &[])];
    let policy = parse_and_compile(policy_src);
    let config = SessionConfig {
        clear_session_meta: ClearSessionMeta::EveryTurn,
        ..default_session_config()
    };
    let mut session = Session::new(
        policy,
        config,
        InterpreterConfig::default(),
        tools,
    );

    let llm = mock_pllm(vec![
        "```python\nmark_session()\n```",
        "```python\n42\n```",
    ]);
    let mut tool_map = HashMap::new();
    tool_map.insert("mark_session", vec![json!(null)]);
    let executor = mock_tool_executor(tool_map);

    // First turn: calls mark_session which sets "marked" tag in session meta
    let _ = session.process_turn("first", &llm, &executor).await.unwrap();

    // Second turn: EveryTurn clears session meta at the start, so "marked" should be gone
    let _ = session.process_turn("second", &llm, &executor).await.unwrap();

    assert!(
        !session.session_meta().tags.contains("marked"),
        "EveryTurn should clear session meta between turns"
    );
}

#[tokio::test]
async fn turn_result_includes_tool_calls() {
    let tools = vec![simple_tool("my_api", &["query"])];
    let mut session = make_session("", tools);
    let llm = mock_pllm(vec![
        "```python\nresult = my_api('test')\nresult\n```",
    ]);
    let mut tool_map = HashMap::new();
    tool_map.insert("my_api", vec![json!("response")]);
    let executor = mock_tool_executor(tool_map);

    let result = session
        .process_turn("call api", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert!(
        !result.tool_calls_made.is_empty(),
        "tool_calls_made should be populated after a tool call"
    );
    assert_eq!(
        result.tool_calls_made[0].tool_name, "my_api",
        "Tool call summary should contain the tool name"
    );
}

#[tokio::test]
async fn turn_result_includes_print_output() {
    let mut session = make_session("", vec![]);
    let llm = mock_pllm(vec!["```python\nprint('hello world')\n42\n```"]);
    let executor = empty_tool_executor();

    let result = session
        .process_turn("print something", &llm, &executor)
        .await
        .unwrap();

    assert_eq!(result.status, TurnStatus::Success);
    assert_eq!(result.final_return_value, Some(json!(42)));
    assert!(
        result.print_output.contains("hello world"),
        "print_output should contain 'hello world', got: {:?}",
        result.print_output
    );
}
