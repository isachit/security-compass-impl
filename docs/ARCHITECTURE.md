# Architecture

## System Overview

The Security Compass Engine implements the CaMeL (Capabilities, Metadata, and LLM) architecture for prompt-injection-resistant agentic AI. It uses two LLMs:

- **PLLM (Planning LLM)**: Trusted, generates Python code from user requests. Has tool definitions but never sees untrusted data directly.
- **QLLM (Quarantined LLM)**: Untrusted, processes data from external sources. Has no tool-calling capability -- only receives system prompt, user data, and output schema. This is enforced by the API shape (`chat_completion_with_schema`).

The interpreter sits between them, executing PLLM-generated code in a metadata-tracking VM. Every value carries `Metadata` (producers, consumers, tags). Before each tool call, SQRT policies are evaluated against the metadata to decide allow/deny.

## Crate Dependency Graph

```
security-compass-server
  |-- security-compass-orchestrator
  |     |-- security-compass-interpreter
  |     |     |-- security-compass-vm
  |     |     |     +-- security-compass-meta
  |     |     +-- sqrt-eval
  |     |           |-- sqrt-parser
  |     |           +-- security-compass-meta
  |     +-- security-compass-meta
  +-- sqrt-eval
  +-- sqrt-parser
  +-- security-compass-meta
```

All crates live under `crates/` in a single Cargo workspace (resolver v2, edition 2021). The VM crate uses edition 2024.

## Layer Architecture

### Layer 1: Metadata Foundation (`security-compass-meta`)

The foundational crate. Zero external dependencies beyond serde. Defines the core metadata types that flow through every other layer.

**Key types:**

- `Metadata` -- the three-field struct attached to every interpreter variable:
  - `producers: BTreeSet<String>` -- tracks where data originated (union propagation)
  - `consumers: ConsumerSet` -- restricts who can receive data (intersection propagation)
  - `tags: BTreeSet<String>` -- arbitrary classification labels (union propagation)
- `ConsumerSet` -- either `Universal` (no restrictions) or `Finite(BTreeSet<String>)`. Intersection is monotonically restrictive: combining data from two sources restricts the result to only consumers authorized by both sources.
- `ValueWithMeta<T>` -- wraps any value with its metadata. The fundamental unit of the interpreter: every variable, intermediate result, tool argument, and return value carries this wrapper.
- `ToolResultWithMeta<T>` -- tool results with `CombineMetaMode` (Merge/Replace/Ignore) for controlling how metadata from tool implementations combines with existing metadata.

**Propagation rules (binary merge):**
- producers: `a.producers UNION b.producers`
- consumers: `a.consumers INTERSECT b.consumers`
- tags: `a.tags UNION b.tags`

**Special tag constants:**
- `__non_executable` -- marks tool results as non-executable memory
- `__tool/parse_with_ai` -- marks data that has been processed by the QLLM
- `__llm_blocked` -- prevents data from being routed to the QLLM

**Source files:**
- `crates/security-compass-meta/src/metadata.rs` -- `Metadata` struct and all augmented assignment operations
- `crates/security-compass-meta/src/consumer_set.rs` -- `ConsumerSet` enum with set algebra
- `crates/security-compass-meta/src/value_with_meta.rs` -- `ValueWithMeta<T>` and `ToolResultWithMeta<T>`
- `crates/security-compass-meta/src/constants.rs` -- tag string constants

### Layer 2: Policy Language (`sqrt-parser`)

PEG grammar parser (pest) faithfully translated from the Python Lark Earley grammar. Parses SQRT policy source into a typed AST (`SqrtProgram`).

**Grammar:** `crates/sqrt-parser/src/sqrt.pest`

**AST root:** `SqrtProgram { declarations: Vec<Declaration> }`

**Declaration kinds:**
- `Let(LetDecl)` -- variable bindings: `let name = expression;`
- `Tool(ToolDecl)` -- full tool rules with check blocks and metadata update blocks
- `ToolShorthand(ToolShorthandDecl)` -- single-line tool rules with condition

**Tool declarations support:**
- Tool identification by exact name (`"send_email"`) or regex (`r"get_.*"`)
- Priority ordering (`priority 10`)
- Check rules: `must deny when ...`, `should allow always`, etc.
- Metadata update blocks: `result { @tags |= {"confidential"}; }`, `session_before { ... }`, `session_after { ... }`
- Augmented assignment operators: `=`, `|=`, `&=`, `-=`, `^=`

**Predicate system:**
- Boolean combinators: `and`, `or`, `not`
- Named references to `let`-declared predicates
- Comparisons: value-in-set, value equality, set overlaps/subset/superset/equals, set is-empty, set is-universal
- Set operands: `arg.tags`, `@result.producers`, `@session.consumers`, `@args.tags.union`, aggregation ops

**Set expressions:**
- Literals: `{"a", "b"}`, with string, regex (`r"..."`), wildcard (`w"..."`), type domain, and number elements
- Binary operations: union, intersect, minus, xor
- Element operations: with, without
- References to `let`-declared sets

**Type domain constraints:** `bool`, `int` (with range specs), `float`, `str` (with pattern and length), `datetime`

**Error reporting:** Line/column positions with `Span` information for caret-pointed source snippets.

**Source files:**
- `crates/sqrt-parser/src/ast.rs` -- complete typed AST
- `crates/sqrt-parser/src/parser.rs` -- pest pair-to-AST conversion
- `crates/sqrt-parser/src/error.rs` -- `SqrtParseError` with source location

### Layer 3: Policy Engine (`sqrt-eval`)

Compiles the AST into a `CompiledPolicy` for fast evaluation. Evaluates tool calls against compiled policies to produce Allow/Deny decisions with metadata updates.

**Compilation pipeline:**

```
SqrtProgram (AST) --[compile()]--> CompiledPolicy
                                        |
ToolCallContext ----[evaluate()]---------.---> PolicyDecision
                                                 |
                                        Allow { updates } | Deny { reason }
```

**CompiledPolicy structure:**
- `variables: HashMap<String, ResolvedLetValue>` -- resolved `let` declarations
- `exact_policies: HashMap<String, Vec<CompiledToolPolicy>>` -- O(1) exact tool name lookup
- `regex_policies: Vec<(Regex, CompiledToolPolicy)>` -- pre-compiled regex fallback (linear scan)
- `preset: InternalPolicyPreset` -- default allow/deny, enforcement level, feature flags

**Static set optimization:** At compile time, pure-literal set expressions (no runtime operands) are evaluated to `BTreeSet<String>`. Dynamic expressions are stored as AST for lazy runtime evaluation.

**Evaluation algorithm:**
1. Collect all matching policies: exact name lookup (O(1)) + regex scan (linear)
2. Sort by priority descending (stable sort preserves declaration order for equal priorities)
3. For each policy, evaluate check rules:
   - `must deny` -- immediate return Deny (cannot be overridden)
   - `must allow` -- immediate return Allow (with resolved updates)
   - `should deny` -- record as soft deny (first one wins)
   - `should allow` -- record as soft allow (first one wins)
   - If `fail_fast` and deny recorded -- return immediately
4. If no hard decision: soft allow overrides soft deny; otherwise use soft decision or preset default
5. For Allow: resolve all metadata statements from all matching policies into `ResolvedUpdate` triples (result, session_before, session_after)

**`check_branch()` -- branching meta-policy enforcement:**
- Called at bytecode-level conditional jumps (JumpIfTrue/JumpIfFalse)
- Deny mode (blacklist): blocks if condition metadata overlaps with denied sets
- Allow mode (whitelist): blocks if condition metadata is not a subset of allowed sets
- Prevents prompt injection attacks from influencing control flow through metadata manipulation

**`InternalPolicyPreset` -- configures:**
- `default_allow: bool` -- allow or deny when no rule matches
- `default_allow_enforcement: Enforcement` -- Must or Should for the default
- `enable_non_executable_memory: bool` -- inject `__non_executable` on tool results
- `enable_llm_blocked_tag: bool` -- hard deny when `__llm_blocked` tag reaches QLLM
- `branching_meta_policy: BranchingMetaPolicy` -- mode (Allow/Deny), producers, tags, consumers

**Source files:**
- `crates/sqrt-eval/src/compiler.rs` -- AST-to-CompiledPolicy, static set optimization, shorthand expansion
- `crates/sqrt-eval/src/evaluator.rs` -- `evaluate()` and `check_branch()`
- `crates/sqrt-eval/src/types.rs` -- `CompiledPolicy`, `ToolCallContext`, `PolicyDecision`, `InternalPolicyPreset`
- `crates/sqrt-eval/src/context.rs` -- `EvalContext`, `FieldValue` (string set vs consumer set abstraction)
- `crates/sqrt-eval/src/predicate_eval.rs` -- predicate evaluation
- `crates/sqrt-eval/src/set_eval.rs` -- set expression evaluation
- `crates/sqrt-eval/src/metadata_update.rs` -- metadata statement resolution
- `crates/sqrt-eval/src/value_match.rs` -- value matching (type domains, regex, wildcard)
- `crates/sqrt-eval/src/error.rs` -- `CompileError`, `EvalError`, `BranchingDenied`

### Layer 4: Execution Engine (`security-compass-vm`)

Forked from the Monty Python bytecode VM. Extended with parallel metadata tracking at the bytecode level. Every VM value has a corresponding metadata entry.

**Core invariant -- parallel metadata stacks:**
- The VM's value stack (`stack: Vec<Value>`) is mirrored by `stack_meta: Vec<Metadata>` -- lengths are always equal
- The `Namespace` struct holds parallel vectors: `values: Vec<Value>` and `metadata: Vec<Metadata>` -- lengths are always equal
- Every push/pop/store/load operation maintains both vectors in lockstep

**Opcode-level metadata propagation:**
- Constants -- `Metadata::default()` (clean)
- Binary operations (add, sub, mul, etc.) -- `merge(left_meta, right_meta)`
- Unary operations -- passthrough (metadata unchanged)
- Collection construction (list, dict, tuple, set) -- `merge_all(element_metas)`
- Variable load -- copy metadata from namespace
- Variable store -- copy metadata to namespace

**`BranchChecker` trait:**
- Injected into the VM at startup and on each resume
- Called at `JumpIfTrue`/`JumpIfFalse` opcodes
- Receives the condition value's metadata
- Returns `Ok(())` or raises a `MontyException` to deny branching
- The `PolicyBranchChecker` implementation delegates to `sqrt_eval::check_branch()`

**Execution model -- `MontyRun` and yield points:**
- `MontyRun::new(code, script_name, input_names, external_functions)` -- parse and compile
- `MontyRun::start_with_meta(inputs, input_metas, tracker, print, branch_checker)` -- begin execution with per-input metadata
- Execution yields `RunProgress<T>` variants:
  - `FunctionCall { function_name, args, args_meta, call_id, state }` -- external function call
  - `OsCall { function, args, args_meta, call_id, state }` -- OS-level operation
  - `ResolveFutures(FutureSnapshot)` -- async futures need resolution
  - `Complete(MontyObject, Metadata)` -- execution finished
- `Snapshot<T>::run(ExternalResult)` -- resume after external call
- `ExternalResult::Return(MontyObject, Metadata)` -- provide return value with metadata
- `ExternalResult::Error(MontyException)` -- propagate exception
- `ExternalResult::Future` -- push `ExternalFuture` for async resolution

**Exception handling:** Stack unwind syncs metadata -- when exceptions propagate, the metadata stack is unwound in lockstep with the value stack.

**Async support:** Task context switching preserves metadata. `FutureSnapshot::resume()` supports incremental resolution of pending futures.

**Resource tracking:** `LimitedTracker` enforces memory limits, recursion depth, and execution time. Namespace creation tracks memory for both values and metadata.

**Serialization:** `MontyRun`, `Snapshot`, and `FutureSnapshot` all support postcard serialization for caching parsed code and suspending execution state.

**Source files:**
- `crates/security-compass-vm/src/run.rs` -- `MontyRun`, `RunProgress`, `Snapshot`, `FutureSnapshot`, `ExternalResult`
- `crates/security-compass-vm/src/namespace.rs` -- `Namespace` (parallel values + metadata), `Namespaces`
- `crates/security-compass-vm/src/bytecode/vm/` -- VM core: binary ops, comparisons, collections, attribute access
- `crates/security-compass-vm/src/bytecode/compiler.rs` -- AST-to-bytecode compiler
- `crates/security-compass-vm/src/bytecode/op.rs` -- opcode definitions
- `crates/security-compass-vm/src/value.rs` -- `Value` enum
- `crates/security-compass-vm/src/object.rs` -- `MontyObject` (public interface)
- `crates/security-compass-vm/src/builtins/` -- Python builtin implementations (abs, len, sorted, etc.)
- `crates/security-compass-vm/src/types/` -- Python type implementations (str, list, dict, set, etc.)
- `crates/security-compass-vm/src/modules/` -- Module system (os, sys, pathlib, typing, asyncio)

### Layer 5: Interpreter (`security-compass-interpreter`)

Bridges the VM, policy engine, and metadata system. Orchestrates execution of PLLM-generated code with security policy enforcement at every tool call boundary.

**Entry point:** `Interpreter::execute(python_code, input_vars, tool_definitions) -> Result<ExecutionResult, InterpreterError>`

**Four yield points (`ExecutionResult` variants):**
- `Complete { value, meta, print_output }` -- execution finished
- `NeedsToolCall { tool_name, args, call_id, state, result_updates, session_after_updates }` -- tool call allowed by policy
- `NeedsParseWithAi { data, query, output_schema, call_id, state }` -- data needs QLLM extraction
- `NeedsVerifyHypothesis { hypothesis, data, call_id, state }` -- hypothesis needs QLLM verification

**Resume methods:**
- `resume_after_tool_call(state, result_value, result_meta, ...)` -- provide tool result
- `resume_after_parse_with_ai(state, parsed_value, ...)` -- provide QLLM extraction result
- `resume_after_verify_hypothesis(state, verified, ...)` -- provide QLLM verification result

**Execution loop (`continue_execution`) -- before yielding each tool call:**
1. Check gas limit (configurable, 0 = unlimited)
2. Check tool call count limit (`max_tool_calls_per_attempt`)
3. Check LLM blocked tag (`__llm_blocked` on any argument)
4. Check tool cache (keyed by `tool_name:serialized_args`)
5. Convert positional args to named args using `tool_arg_names`
6. Route internal tools (`parse_with_ai`, `verify_hypothesis`) to dedicated handlers
7. Build `ToolCallContext` and evaluate SQRT policy
8. On Allow: apply `session_before_updates`, yield `NeedsToolCall` with `result_updates` and `session_after_updates`
9. On Deny: resume VM with `RuntimeError` exception (PLLM can catch in try/except)

**`PolicyBranchChecker`:**
- Implements `BranchChecker` using `sqrt_eval::check_branch()` with `Arc<CompiledPolicy>`
- Injected into the VM at start and re-injected on every resume (not serialized)

**Tool result caching (`CacheMode`):**
- `None` -- every tool call is yielded to the caller
- `All` -- cache all tool results (keyed by tool name + serialized args)
- `DeterministicOnly` -- cache only results from tools marked as deterministic

**Session metadata:** `Interpreter.session_meta: Metadata` persists across tool calls within an execution. Updated by `session_before_updates` (applied before tool execution) and `session_after_updates` (applied after tool result).

**Source files:**
- `crates/security-compass-interpreter/src/execution.rs` -- `Interpreter::new()`, `execute()`, `continue_execution()`, `handle_function_call()`
- `crates/security-compass-interpreter/src/resume.rs` -- `resume_after_tool_call()`, `resume_after_parse_with_ai()`, `resume_after_verify_hypothesis()`
- `crates/security-compass-interpreter/src/policy.rs` -- `build_tool_call_context()`, `positional_to_named()`, `apply_session_updates()`
- `crates/security-compass-interpreter/src/branch_checker.rs` -- `PolicyBranchChecker`
- `crates/security-compass-interpreter/src/convert.rs` -- `json_to_monty()`, `monty_to_json()`
- `crates/security-compass-interpreter/src/types.rs` -- `Interpreter`, `ExecutionResult`, `InterpreterConfig`, `ToolDefinition`, `CacheMode`
- `crates/security-compass-interpreter/src/error.rs` -- `InterpreterError`

### Layer 6: Orchestrator (`security-compass-orchestrator`)

Drives the dual-LLM conversation loop. Manages sessions, PLLM retry logic, error classification, and QLLM routing.

**Main entry point:** `Session::process_turn(user_message, llm_client, tool_executor) -> Result<TurnResult, OrchestratorError>`

**`process_turn` algorithm:**
1. Check turn limit (`max_n_turns`)
2. Optionally clear session metadata (`ClearSessionMeta::EveryTurn`)
3. Add user message to conversation history
4. Build PLLM system prompt (includes tool definitions, internal tools, constraints)
5. PLLM retry loop (up to `max_pllm_attempts`):
   a. Optionally clear session metadata (`ClearSessionMeta::EveryAttempt`)
   b. Build PLLM messages: system prompt + conversation history + error feedback
   c. Call PLLM via `LlmClient::chat_completion()`
   d. Extract Python code block from response (or handle clarification)
   e. Build input variables (`user_message` with default metadata)
   f. Run interpreter loop (`run_interpreter_loop`)
   g. On success: return `TurnResult` with `TurnStatus::Success`
   h. On retryable error: format feedback, continue loop
   i. On fatal error: propagate to caller
6. If all attempts exhausted: return `TurnResult` with `TurnStatus::MaxAttemptsExceeded`

**Interpreter loop (`run_interpreter_loop`):**
- Calls `interpreter.execute()` to start
- Loops on yield points:
  - `NeedsToolCall` -- execute tool via `ToolExecutor::execute()`, then `resume_after_tool_call()`
  - `NeedsParseWithAi` -- call QLLM via `LlmClient::chat_completion_with_schema()`, then `resume_after_parse_with_ai()`
  - `NeedsVerifyHypothesis` -- call QLLM verify, then `resume_after_verify_hypothesis()`
  - `Complete` -- return `InterpreterLoopResult`

**Error classification (`ErrorClass`):**
- `VmException(String)` -- retryable: PLLM coding mistakes, tool failures, resource limits. Feed traceback to PLLM for next attempt.
- `PolicyViolation(String)` -- retryable: PLLM tried something forbidden. Feed denial reason to PLLM.
- `Fatal(OrchestratorError)` -- not retryable: LLM client errors, serde errors, max turns exceeded. Propagate to caller.

**Async/sync bridge:** The interpreter is synchronous with yield points. The orchestrator does async work (LLM calls via reqwest, tool execution) at yield points, then resumes the synchronous interpreter.

**Trait abstractions:**
- `LlmClient` -- `chat_completion(messages) -> String` + `chat_completion_with_schema(system, user, schema) -> Value`
- `ToolExecutor` -- `execute(tool_name, args) -> Value`

**Session state:**
- `Session.id: Uuid` -- unique session identifier
- `Session.interpreter: Interpreter` -- owns the compiled policy, session metadata, and tool cache
- `Session.message_history: Vec<Message>` -- conversation history (user + assistant messages)
- `Session.turn_count: u32` -- number of turns processed
- `Session.config: SessionConfig` -- session behavior configuration
- `Session.tool_definitions: Vec<ToolDefinition>` -- available tools

**Source files:**
- `crates/security-compass-orchestrator/src/turn.rs` -- `Session::process_turn()`, `classify_error()`
- `crates/security-compass-orchestrator/src/interpreter_loop.rs` -- `Session::run_interpreter_loop()`
- `crates/security-compass-orchestrator/src/qllm.rs` -- `call_qllm()`, `call_qllm_verify()`
- `crates/security-compass-orchestrator/src/prompt_builder.rs` -- `build_pllm_system_prompt()`, `build_error_feedback()`
- `crates/security-compass-orchestrator/src/code_extraction.rs` -- `extract_code_block()`
- `crates/security-compass-orchestrator/src/traits.rs` -- `LlmClient`, `ToolExecutor`
- `crates/security-compass-orchestrator/src/types.rs` -- `Session`, `SessionConfig`, `TurnResult`, `TurnStatus`, `ErrorClass`
- `crates/security-compass-orchestrator/src/error.rs` -- `OrchestratorError`

### Layer 7: HTTP Server (`security-compass-server`)

Axum 0.8 HTTP server providing OpenAI-compatible chat completion endpoints. Translates HTTP requests into orchestrator calls and back.

**Endpoints:**
- `POST /control/v1/chat/completions` -- default provider (OpenAI)
- `POST /control/{provider}/v1/chat/completions` -- explicit provider routing
- `POST /control/lang-graph/{provider}/v1/chat/completions` -- LangGraph stub (501 Not Implemented)

**Request processing pipeline (14 steps):**

```
HTTP POST /control/v1/chat/completions
  |-- Headers: X-Api-Key, X-Security-Policy, X-Security-Config, X-Session-Id, Authorization
  +-- Body: { model, messages, tools? }
      |
      |-- [1]  authenticate(server_api_key via Authorization header)
      |-- [2]  parse_headers() -> ParsedHeaders
      |-- [3]  validate LLM API key (X-Api-Key)
      |-- [4]  apply defaults for missing headers
      |-- [5]  derive QLLM model (heuristic: gpt-4* -> gpt-4o-mini)
      |-- [6]  build_session_config() + build_interpreter_config()
      |-- [7]  extract_tool_definitions() from request tools
      |-- [8]  extract_messages() -> user_query
      |-- [9]  reject streaming (stream: true -> error)
      |-- [10] session_store.get_or_create()
      |         |-- compile_policy(header) -> CompiledPolicy
      |         +-- Session::new(policy, config, interp_config, tools)
      |-- [11] OpenAiLlmClient::for_provider(provider, api_key, pllm_model, qllm_model)
      |-- [12] NoOpToolExecutor (tool execution not yet wired)
      |-- [13] session.process_turn(user_query, llm, executor)
      |         |-- PLLM: generate Python code
      |         |-- Interpreter: execute with policy checks
      |         |-- Tool execution at yield points
      |         |-- QLLM: structured extraction (if needed)
      |         +-- TurnResult { status, value, program, tool_calls }
      +-- [14] build_response() -> ChatCompletionResponse + X-Session-Id header
```

**Session store:** `SessionStore` backed by `DashMap<Uuid, SessionEntry>` with TTL-based expiration. Background task runs every 60 seconds to evict expired sessions.

**Provider routing:**
- `"openai"` -- `api.openai.com/v1`
- `"openrouter"` -- `openrouter.ai/api/v1`
- Other providers map to OpenAI-compatible base URLs

**Header parsing:**
- `Authorization: Bearer <token>` -- server authentication
- `X-Api-Key` -- LLM provider API key
- `X-Security-Policy` -- SQRT policy source (compiled at session creation)
- `X-Security-Config` -- JSON configuration overrides
- `X-Session-Id` -- UUID for session continuity

**Policy compilation:** `SecurityPolicyHeader` -> `sqrt_parser::parse()` -> `sqrt_eval::compile()` -> `CompiledPolicy`

**Response format:** OpenAI-compatible `ChatCompletionResponse` with structured content in `ResponseContentJsonSchema`:
- `status` -- success/failure/unknown
- `final_return_value` -- the interpreter's return value
- `error` -- error info if the turn failed
- `program` -- the PLLM-generated Python code
- `session_id` -- returned via `X-Session-Id` response header

**Configuration:**
- `PORT` env var (default: 8080)
- `SEQURITY_API_KEY` env var -- server-level authentication
- `SESSION_TTL_SECS` env var (default: 1800 = 30 minutes)

**Source files:**
- `crates/security-compass-server/src/main.rs` -- server startup, router, graceful shutdown
- `crates/security-compass-server/src/handler.rs` -- `handle_chat_completions_inner()`, `build_response()`, `AppState`
- `crates/security-compass-server/src/headers.rs` -- `parse_headers()`, `ParsedHeaders`
- `crates/security-compass-server/src/config.rs` -- `build_session_config()`, `build_interpreter_config()`
- `crates/security-compass-server/src/policy.rs` -- `compile_policy()`
- `crates/security-compass-server/src/session_store.rs` -- `SessionStore`, `SessionEntry`
- `crates/security-compass-server/src/llm_client.rs` -- `OpenAiLlmClient` (reqwest-based)
- `crates/security-compass-server/src/tool_executor.rs` -- `NoOpToolExecutor`, `EchoToolExecutor`
- `crates/security-compass-server/src/message.rs` -- `extract_messages()`
- `crates/security-compass-server/src/types/` -- request/response/header type definitions
- `crates/security-compass-server/src/error.rs` -- `ServerError`

## Data Flow

### Request Processing

```
HTTP POST /control/v1/chat/completions
  |-- Headers: X-Api-Key, X-Security-Policy, X-Security-Config, X-Session-Id
  +-- Body: { model, messages, tools? }
      |
      |-- [1] authenticate(server_api_key)
      |-- [2] parse_headers() -> ParsedHeaders
      |-- [3] validate api_key
      |-- [4] apply defaults
      |-- [5] derive QLLM model
      |-- [6] build_session_config() + build_interpreter_config()
      |-- [7] extract_tool_definitions()
      |-- [8] extract_messages() -> user_query
      |-- [9] reject streaming
      |-- [10] session_store.get_or_create()
      |         |-- compile_policy(header) -> CompiledPolicy
      |         +-- Session::new(policy, config, interp_config, tools)
      |-- [11] OpenAiLlmClient::for_provider()
      |-- [12] NoOpToolExecutor
      |-- [13] session.process_turn(user_query, llm, executor)
      |         |-- PLLM: generate Python code
      |         |-- Interpreter: execute with policy checks
      |         |-- Tool execution at yield points
      |         |-- QLLM: structured extraction (if needed)
      |         +-- TurnResult { status, value, program, tool_calls }
      +-- [14] build_response() -> ChatCompletionResponse + X-Session-Id
```

### Metadata Flow Through VM

```
User Input -> Metadata::default() (empty producers, universal consumers, no tags)
  |
  |-- Binary Op (a + b) -> merge(a.meta, b.meta)
  |     producers: a.producers UNION b.producers
  |     consumers: a.consumers INTERSECT b.consumers
  |     tags: a.tags UNION b.tags
  |
  |-- Tool Call -> SQRT Policy Evaluation
  |     ToolCallContext { tool_name, args(with meta), session_meta }
  |     -> PolicyDecision::Allow { result_updates, session_before_updates, session_after_updates }
  |     -> PolicyDecision::Deny { reason, enforcement }
  |
  |-- Tool Result -> Metadata::default_for_tool_result(name, non_exec)
  |     producers: {tool_name}
  |     tags: {__non_executable} if enabled
  |     + apply result_updates from policy
  |
  |-- Conditional Branch -> BranchChecker::check(condition_meta)
  |     -> Ok(()) if clean or policy allows
  |     -> Err(BranchingDenied) if untrusted metadata influences control flow
  |
  +-- Final Result -> Complete(value, metadata)
```

### PLLM/QLLM Interaction Flow

```
User Request
  |
  v
PLLM (trusted, has tool defs)
  |-- generates Python code with tool calls
  |
  v
Interpreter (metadata-tracking VM)
  |-- executes code, tracks metadata at bytecode level
  |-- at each tool call:
  |     |-- evaluate SQRT policy
  |     |-- if allowed: yield to orchestrator for execution
  |     |-- if denied: raise RuntimeError (PLLM can catch in try/except)
  |
  |-- at parse_with_ai call:
  |     |-- check __llm_blocked tag
  |     |-- yield to orchestrator
  |     |-- orchestrator routes to QLLM
  |     |-- QLLM receives: system prompt + data + output schema
  |     |-- QLLM returns: structured JSON
  |     |-- result inherits input metadata + __tool/parse_with_ai tag
  |
  +-- at verify_hypothesis call:
        |-- similar flow to parse_with_ai
        |-- QLLM returns: boolean (true/false)
```

## Security Boundaries

1. **PLLM/QLLM separation**: The PLLM never sees untrusted data. The QLLM has no tool-calling capability -- this is enforced by the API shape. The PLLM uses `chat_completion()` (free-form text output); the QLLM uses `chat_completion_with_schema()` (structured JSON only, no tool definitions).

2. **Metadata tracking**: Every VM value carries metadata. This cannot be bypassed because it is tracked at the bytecode level -- every push, pop, store, load, and binary operation maintains the parallel metadata stack in lockstep with the value stack. The `Namespace` struct enforces the invariant that `values.len() == metadata.len()`.

3. **Policy enforcement**: SQRT policies are evaluated before every tool call. `must deny` rules at equal or higher priority always fire and cannot be overridden. Policy evaluation happens in the interpreter layer, between VM execution and actual tool invocation.

4. **Branching protection**: The `BranchChecker` trait is called at every `JumpIfTrue`/`JumpIfFalse` opcode. The `PolicyBranchChecker` delegates to `sqrt_eval::check_branch()`, which verifies the condition's metadata against the branching meta-policy. This prevents untrusted metadata from influencing conditional jumps -- a key defense against prompt injection that manipulates control flow.

5. **Consumer restriction monotonicity**: Consumer set intersection is monotonically restrictive. Merging two values' metadata yields a consumer set that is a subset of both inputs. Data can only become more restricted, never less restricted, as it flows through the system. This is the core information-flow security property.

6. **Session isolation**: Each session has its own `Interpreter` instance with independent session metadata, tool cache, and tool call history. Sessions are identified by UUID and stored in a `DashMap` with TTL-based expiration.

7. **Non-executable memory**: Tool results can be tagged `__non_executable` (controlled by `InternalPolicyPreset.enable_non_executable_memory`). This tag propagates through the metadata system and can be checked in SQRT policies and branching meta-policy rules.

8. **LLM blocked tag**: Values tagged `__llm_blocked` are prevented from being routed to the QLLM. The interpreter checks this tag before yielding `NeedsParseWithAi` or `NeedsVerifyHypothesis`, returning an error if any argument carries the tag.

## Concurrency Model

- **Server**: Async (tokio multi-threaded runtime). The axum server handles requests concurrently.
- **Session store**: `DashMap` provides shard-level locking for concurrent session access. Background eviction task runs every 60 seconds.
- **Interpreter**: Synchronous with yield points. The interpreter itself is not async -- it runs synchronously until it hits a tool call or completes, then yields control. Async work (LLM API calls via reqwest, tool execution) happens at yield points in the orchestrator layer.
- **No `spawn_blocking` needed**: The interpreter yields quickly at tool call boundaries. CPU-bound work within the VM (bytecode execution) is bounded by resource limits (gas, time, recursion depth).
- **DashMap lock scope**: The DashMap `RefMut` is held across the async `process_turn()` call. This is acceptable for moderate concurrency because each session is typically accessed by one request at a time.

## Error Handling Strategy

Each layer defines its own error type, forming a hierarchy that propagates upward with context:

| Layer | Error Type | Key Variants |
|-------|-----------|-------------|
| sqrt-parser | `SqrtParseError` | Parse failures with line/column |
| sqrt-eval | `CompileError` | `InvalidRegex`, `DuplicateVariable`, `UndefinedVariable` |
| sqrt-eval | `EvalError` | `UndefinedVariable`, `TypeMismatch`, `InvalidArgRef`, `ResultMetaUnavailable` |
| sqrt-eval | `BranchingDenied` | Branching meta-policy violation (field, offending values) |
| security-compass-vm | `MontyException` | Python exception with type, message, and traceback |
| security-compass-interpreter | `InterpreterError` | `VmError`, `PolicyEvalError`, `ToolCallLimitExceeded`, `GasExhausted`, `LlmBlocked`, `UnknownTool` |
| security-compass-orchestrator | `OrchestratorError` | `InterpreterError`, `LlmError`, `ToolError`, `MaxTurnsExceeded`, `ClarificationRequested` |
| security-compass-server | `ServerError` | `Unauthorized`, `MissingApiKey`, `OrchestratorError`, `UnsupportedFeature` |

**Server error mapping**: The server maps all errors to OpenAI-compatible JSON responses:

```json
{
  "error": {
    "message": "...",
    "type": "...",
    "code": 400
  }
}
```

**HTTP status codes**:
- 400 -- validation errors, bad requests
- 401 -- authentication failure
- 404 -- session not found (implicit, session falls through to creation)
- 500 -- internal server errors
- 501 -- unimplemented features (LangGraph)

**Retry eligibility** (orchestrator layer):
- Retryable: `VmException` (PLLM coding mistakes), `PolicyViolation` (forbidden tool calls), tool failures, resource limits
- Fatal: LLM client errors, serialization errors, max turns exceeded, internal tool disabled
