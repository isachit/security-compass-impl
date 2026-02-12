# Security Compass Engine -- Design Decisions

This document explains the architectural choices and design rationale behind the Security Compass Engine, a Rust workspace implementing the CaMeL dual-LLM architecture for prompt-injection-resistant agentic AI.

Each section addresses a specific design decision, the alternatives considered, and why the chosen approach best serves the security goals of the system.

---

## Table of Contents

1. [Why Dual LLM?](#1-why-dual-llm)
2. [Why Metadata Tracking at the Bytecode Level?](#2-why-metadata-tracking-at-the-bytecode-level)
3. [Why Consumer Set Intersection?](#3-why-consumer-set-intersection)
4. [Why a Forked Python VM Instead of a Sandboxed Interpreter?](#4-why-a-forked-python-vm-instead-of-a-sandboxed-interpreter)
5. [Why SQRT as the Policy Language?](#5-why-sqrt-as-the-policy-language)
6. [Why Synchronous Interpreter with Async Orchestrator?](#6-why-synchronous-interpreter-with-async-orchestrator)
7. [Why Session-Based State Management?](#7-why-session-based-state-management)
8. [Why Error Classification with Retry?](#8-why-error-classification-with-retry)
9. [Why OpenAI-Compatible API?](#9-why-openai-compatible-api)
10. [Why DashMap for Sessions?](#10-why-dashmap-for-sessions)
11. [Why Arc\<CompiledPolicy\> in the Interpreter?](#11-why-arccompiledpolicy-in-the-interpreter)
12. [Why Separate Request/Response Types from Orchestrator Types?](#12-why-separate-requestresponse-types-from-orchestrator-types)
13. [Security Design Principles](#13-security-design-principles)

---

## 1. Why Dual LLM?

### The Problem

LLMs are susceptible to prompt injection. When an agent uses a single LLM for both reasoning and data processing, malicious content embedded in tool results can manipulate the LLM's behavior. An attacker who controls the content of a web page, email, or API response can inject instructions that the LLM follows as though they came from the user.

### The CaMeL Solution

Separate responsibilities across two LLMs with distinct trust boundaries:

- **PLLM (Planning LLM)**: Generates Python code to fulfill user requests. It never sees untrusted data directly. It is trusted to make decisions about which tools to call and how to compose results. Its inputs are limited to system prompts, user messages, tool schemas, and error feedback from previous attempts.

- **QLLM (Quarantined LLM)**: Processes untrusted data such as extracting structured information from web pages, emails, or external API responses. It has no tool-calling capability whatsoever. It receives only a system prompt, user data, and an output schema. This constraint is enforced architecturally by the `chat_completion_with_schema()` API shape -- there is no mechanism through which the QLLM can request tool execution.

### How It Works in Practice

The PLLM generates code like:

```python
data = fetch_webpage("example.com")
extracted = parse_with_ai(data, "Extract the author name", {
    "type": "object",
    "properties": {"name": {"type": "string"}}
})
send_email(to="user@example.com", body=extracted["name"])
```

The `parse_with_ai` call is an internal tool that the interpreter intercepts. Instead of executing it as a regular tool call, the interpreter yields a `NeedsParseWithAi` execution result. The orchestrator then routes the untrusted `data` to the QLLM for structured extraction. The QLLM returns a JSON object conforming to the output schema, and the orchestrator resumes the interpreter with that result.

The critical property is that the QLLM's output flows back into the VM as a value with tracked metadata. Even if the QLLM's output contains text that looks like instructions (because the original web page contained injected prompts), the metadata system ensures those values are treated as data, not as commands.

---

## 2. Why Metadata Tracking at the Bytecode Level?

### The Problem

If metadata were tracked only at tool call boundaries (recording which tool produced a value and checking which tool consumes it), clever prompt injections could use Python code to launder data provenance. For example:

```python
untrusted = fetch_webpage("evil.com")  # tagged as untrusted
clean_var = untrusted + ""             # string concatenation -- is this still untrusted?
send_email(body=clean_var)             # should this be blocked?
```

If the system only tracked that `fetch_webpage` produced `untrusted` but lost track after the concatenation, `clean_var` would appear to be a locally-created string with no provenance. The injection succeeds.

### The Solution

Track metadata for every value on the VM stack and in every namespace. Metadata propagates automatically through all bytecode operations:

| Operation | Metadata behavior |
|---|---|
| Constants and literals | Clean metadata: empty producers, universal consumers, empty tags |
| Binary operations (add, concat, etc.) | Merge metadata: producers union, consumers intersect, tags union |
| Unary operations | Passthrough: same metadata |
| Variable store/load | Propagate between stack and namespace |
| Function calls | Carry metadata through return values |
| Collection building (list, dict, tuple, set) | `merge_all` metadata from all elements |
| Comparison operations | Merge metadata from both operands |
| Exception handling | Sync metadata stack on unwind; push default metadata for exception values |

This is implemented as two parallel data structures in the VM:

- `stack_meta: Vec<Metadata>` mirrors `stack: Vec<Value>` with the invariant that `stack_meta.len() == stack.len()` at every instruction boundary.
- Each `Namespace` stores a parallel `metadata: Vec<Metadata>` alongside `values: Vec<Value>` with the invariant that `values.len() == metadata.len()`.

The result is that `x = untrusted_data + ""` preserves all metadata from `untrusted_data`. The empty string contributes clean metadata (empty producers, universal consumers, empty tags), but the merge operation produces the union of producers, the intersection of consumers, and the union of tags -- so the untrusted provenance survives.

Crucially, the metadata is invisible to PLLM-generated code. There is no Python operation that can read, modify, or remove metadata. Only SQRT policy rules, evaluated by the interpreter at tool call boundaries and by the branch checker at conditional jumps, can observe and act on metadata.

---

## 3. Why Consumer Set Intersection?

### The Design Choice

The `consumers` field in `Metadata` restricts which tools can receive a value. When two values are combined through any operation, the resulting consumers are computed as the intersection of the two input consumer sets, not the union.

### Why Intersection, Not Union

Consider two values:

- Value A can be sent to tools {X, Y} (its consumer set)
- Value B can be sent to tools {Y, Z}

When they are combined into `A + B`, the result can be sent to tools {Y} -- only the tools that both values were individually permitted to reach.

This is deliberately restrictive. The alternative -- union -- would mean that combining a restricted value with an unrestricted one would remove the restriction:

- Value A has consumers `Finite({X})` (restricted to tool X only)
- Value B has consumers `Universal` (no restriction)
- Under union: `A + B` would have consumers `Universal` -- the restriction is gone
- Under intersection: `A + B` would have consumers `Finite({X})` -- the restriction is preserved

The intersection rule is a critical security invariant. It ensures that consumer restrictions are monotonically restrictive: no operation can loosen a consumer constraint. Once a value is restricted to a specific set of tools, combining it with any other value can only maintain or further restrict that set.

### Consumer Set Algebra

The `ConsumerSet` enum has two variants:

- `Universal` -- no restriction, value can go anywhere
- `Finite(BTreeSet<String>)` -- restricted to the named tools

The intersection rules are:

```
Universal  intersect  Universal    = Universal
Universal  intersect  Finite(S)   = Finite(S)
Finite(S)  intersect  Universal   = Finite(S)
Finite(A)  intersect  Finite(B)   = Finite(A intersect B)
```

Anything intersected with a finite set becomes at most that finite set. Anything intersected with Universal remains unchanged. The empty finite set `Finite({})` is the most restrictive possible -- the value cannot go to any tool.

---

## 4. Why a Forked Python VM Instead of a Sandboxed Interpreter?

### Requirements

The system needs to execute Python code with deep instrumentation at the bytecode level. Specifically:

1. Every value push/pop on the VM stack must have a corresponding metadata push/pop.
2. Every variable store/load in every namespace must propagate metadata.
3. Every binary, unary, and comparison operation must merge metadata according to the propagation rules.
4. Conditional jump opcodes must invoke a branch checker before executing.
5. Function call and return must carry metadata through the call stack.
6. The VM must be deterministic and serializable for snapshot/resume.

### Alternatives Considered

| Approach | Pros | Cons |
|---|---|---|
| Sandboxed CPython | Full Python compatibility | Cannot intercept individual bytecodes or inject per-value metadata without deep C-level patches |
| WASM-based Python (e.g., Pyodide) | Good isolation | Same instrumentation problem -- the Python semantics are inside the WASM module |
| Custom interpreter from scratch | Maximum control | Enormous effort to implement Python semantics correctly |
| Forked Monty VM | Small Rust-native VM, explicit bytecode dispatch, already handles core Python semantics | Incomplete Python coverage (no full stdlib, limited built-ins) |

### Why Monty

We chose to fork the Monty bytecode VM (`codesandboxing/monty`) for the following reasons:

1. **Written in Rust**: No FFI boundary. Metadata types (`Metadata`, `ConsumerSet`, etc.) are native Rust structs that integrate directly with the VM's stack and namespace types.

2. **Stack-based VM with explicit opcodes**: Every opcode is handled in a `match` statement. Adding metadata propagation means adding a corresponding metadata operation in each arm. This is mechanical and auditable.

3. **Small enough to understand and modify**: Approximately 30,000 lines of Rust. A single developer can read and understand the entire codebase, which is essential for a security-critical component.

4. **Already handles Python semantics we need**: Function calls, exception handling, async tasks, bytecode compilation, namespace scoping -- these are all implemented and tested.

### Key Modifications

The fork adds the following to Monty:

- `stack_meta: Vec<Metadata>` parallel to `stack: Vec<Value>`, with the invariant enforced at every instruction boundary
- Metadata fields in `Namespace`, `Task`, `FrameExit`, `RunProgress`, and `ExternalResult`
- Metadata merge calls in every binary, comparison, and collection-building opcode handler
- `BranchChecker` trait invoked at `JumpIfTrue` and `JumpIfFalse` opcodes
- `start_with_meta()` and `Snapshot::set_branch_checker()` public API extensions
- Stripped all reference-counting feature gates and the `datatest-stable` dependency

---

## 5. Why SQRT as the Policy Language?

### Requirements for the Policy Language

The security policy language needs to:

1. Express rules per tool (including regex-matched tool IDs)
2. Distinguish hard constraints (`must`) from soft constraints (`should`)
3. Operate over metadata fields: producers (set of strings), consumers (`ConsumerSet`), tags (set of strings)
4. Modify metadata as part of policy evaluation (not just allow/deny, but also tag results and update session state)
5. Support priority ordering so higher-priority rules preempt lower-priority ones
6. Express branching meta-policy (control flow protection rules)

### Alternatives Considered

| Language | Fit | Gap |
|---|---|---|
| Rego (OPA) | General-purpose policy, well-established | No native metadata/provenance concepts, no tool-specific rule structure, no must/should distinction |
| Cedar (AWS) | Resource-based authorization | Models resources and principals, not data flow; no metadata mutation; no tool call context |
| CUE / Jsonnet | Configuration languages | No policy semantics (allow/deny/must/should), no set operations over metadata, no runtime evaluation model |
| Raw Rust code | Maximum expressiveness | Not user-configurable; policies must be compiled into the binary |

### What SQRT Provides

SQRT (Security Query and Rule Toolkit) is a domain-specific language designed specifically for this use case. Its features map directly to the security model:

**Tool-specific rules with priority ordering:**

```sqrt
tool "send_email" priority 10 {
    must deny when @args.tags overlaps {"pii"};
}
```

**Must/should enforcement levels:**

- `must deny` -- hard constraint, cannot be overridden by lower-priority rules
- `should deny` -- soft constraint, can be overridden by a higher-priority `should allow`

**Set operations over metadata fields:**

```sqrt
let pii_sources = {"user_db", "medical_records"};

tool "send_email" {
    must deny when @args.producers overlaps pii_sources;
}
```

**Metadata update operations (not just allow/deny):**

```sqrt
tool "fetch_user_data" {
    result { tags |= {"pii", "user_data"}; }
    session after { producers |= {"user_db"}; }
}
```

**Regex tool ID matching:**

```sqrt
tool /api_.*/ {
    should deny when @args.tags overlaps {"__non_executable"};
}
```

**Branching meta-policy:**

The policy can declare rules about whether values with certain metadata are allowed to influence control flow (conditional jumps in the VM). This prevents untrusted data from steering program execution paths.

### Compilation Model

SQRT source is parsed into an AST (`sqrt-parser`), then compiled into a `CompiledPolicy` (`sqrt-eval`). Compilation resolves static set expressions at compile time, pre-compiles regex patterns, expands shorthand declarations into full tool policies, and builds the priority-sorted rule list for each tool. At runtime, `evaluate()` walks the priority-sorted rules and returns a `PolicyDecision` (Allow/Deny with metadata updates to apply).

---

## 6. Why Synchronous Interpreter with Async Orchestrator?

### The Architecture

The interpreter (VM execution + policy checks) is entirely synchronous. The orchestrator wraps it in an async loop. This division is deliberate and reflects the nature of the work at each layer.

### Why the Interpreter Is Synchronous

VM execution is CPU-bound. Running Python bytecodes, propagating metadata, evaluating SQRT policies -- these are all in-memory computation. There is no I/O, no waiting. Making the interpreter async would add complexity (pinning, lifetime management, potential for accidental blocking) with no benefit.

The interpreter communicates with the outside world through yield points. When it encounters a tool call, it does not execute the tool itself. Instead, it returns an `ExecutionResult` variant that describes what it needs:

```
execute() -> NeedsToolCall { name, args, args_meta, ... }
resume_after_tool_call(result, meta) -> NeedsParseWithAi { data, prompt, schema, ... }
resume_after_parse_with_ai(result, meta) -> Complete { value, meta }
```

Each yield point is a clean boundary. The interpreter hands control back to the caller with all the information needed to perform the async work, and the caller resumes the interpreter with the result.

### Why the Orchestrator Is Async

The orchestrator performs I/O at yield points:

- HTTP calls to the PLLM (code generation)
- HTTP calls to the QLLM (structured data extraction)
- Tool execution (potentially involving network calls)

These are naturally async operations. The orchestrator uses `async_trait` for its `LlmClient` and `ToolExecutor` abstractions, and the server layer provides concrete async implementations (reqwest-based HTTP clients).

### Ownership Model

This design gives clear ownership: the interpreter owns the VM state with `&mut self`, and the orchestrator drives it through yield points. There is no shared mutable state, no locking, no data races. The `Session` struct owns both the interpreter and the configuration, and the borrow checker ensures they are used correctly.

The `ExecutionResult` enum acts as a state machine:

```
execute() -> NeedsToolCall
  | (async tool execution by orchestrator)
  v
resume_after_tool_call() -> NeedsParseWithAi
  | (async QLLM call by orchestrator)
  v
resume_after_parse_with_ai() -> Complete
```

No `spawn_blocking` is needed because the interpreter yields quickly -- it runs until the next tool call or completion, which is fast.

---

## 7. Why Session-Based State Management?

### What a Session Contains

Each conversation is a `Session` with:

- Its own `Interpreter` instance (VM state, tool cache, session metadata)
- Message history (for PLLM context across turns)
- Turn count (for enforcing turn limits)
- Configuration (max attempts, caching strategy, debug level, etc.)

### Why Sessions Instead of Stateless Processing

Stateless processing (creating a fresh interpreter for each request) would lose critical security state:

1. **Session metadata persists across turns.** If a user accesses PII in turn 1, the session metadata records this. In turn 2, SQRT policies can reference session-level metadata to enforce constraints like "once PII has been accessed, outbound communication tools are restricted." Stateless processing loses this history.

2. **Tool result caching within a session.** Deterministic tools (e.g., `get_current_time`) can be cached to avoid redundant calls. The cache is session-scoped, so it is cleared when the session expires.

3. **Message history for PLLM context.** The PLLM needs to see prior turns to generate contextually appropriate code. Without session persistence, each turn would be independent, preventing multi-step workflows.

4. **Turn limits as a safety measure.** The `max_n_turns` configuration caps how many turns a session can execute. This prevents runaway conversations and limits the blast radius of any exploitation.

### Server-Side Session Storage

The server uses a `SessionStore` backed by `DashMap<Uuid, SessionEntry>` with TTL-based expiration. Sessions are identified by UUID, returned to the client in the `X-Session-Id` response header. The client includes this header in subsequent requests to continue the conversation.

A background task periodically evicts expired sessions. Access refreshes the TTL, so active sessions do not expire prematurely.

---

## 8. Why Error Classification with Retry?

### The Problem

LLMs are imperfect code generators. A single PLLM attempt may:

- Produce Python code with syntax errors
- Reference an undefined variable (NameError)
- Pass wrong argument types to a tool (TypeError)
- Attempt a tool call that SQRT policy denies (PolicyViolation)

Failing on the first error would make the system fragile and unusable.

### Error Classification

The orchestrator's `classify_error()` function categorizes errors into three classes:

| Class | Examples | Retryable? | Handling |
|---|---|---|---|
| `VmException` | NameError, TypeError, SyntaxError, division by zero | Yes | PLLM receives error feedback and generates new code |
| `PolicyViolation` | SQRT `must deny` triggered, consumer restriction violated | Yes | PLLM receives policy violation feedback and generates alternative code that avoids the forbidden operation |
| `Fatal` | LLM API failures (network errors, rate limits), serialization errors, internal tool disabled | No | Return immediately with error status |

### Retry Mechanism

When a retryable error occurs:

1. The orchestrator formats error feedback (controlled by `pllm_debug_info_level`: minimal, normal, or extra verbosity).
2. The feedback is appended to the message history as an assistant message followed by a system correction.
3. The PLLM is called again with the updated context.
4. This repeats up to `max_pllm_attempts` times (configurable, default 1).

Giving the PLLM 2-3 attempts with error feedback dramatically improves success rates. The PLLM can see what went wrong and correct its approach -- for example, using a different tool, restructuring the code, or handling the denied operation gracefully with try/except.

### Why Policy Violations Are Retryable

A policy violation is not necessarily a permanent failure. The PLLM may have multiple strategies to achieve the user's goal, and only one of them triggers a policy violation. By receiving feedback that says "the security policy denied `send_email` because the arguments contained PII tags," the PLLM can generate alternative code that, for example, anonymizes the data first or uses a different communication channel.

---

## 9. Why OpenAI-Compatible API?

### The Decision

The server exposes an OpenAI-compatible chat completion API at `/control/v1/chat/completions`. The request format matches the OpenAI ChatCompletion API, and the response format wraps Security Compass extensions inside the standard response structure.

### Why Compatibility Matters

- **Drop-in replacement**: Existing applications using OpenAI's API can point at the Security Compass server with minimal changes. The request body (`model`, `messages`, `tools`) is identical.

- **SDK compatibility**: OpenAI's official SDKs (Python, Node.js, etc.) work against this endpoint. No custom client libraries required.

- **Tooling ecosystem**: Monitoring tools, proxy layers, and testing frameworks that understand the OpenAI API format work without modification.

### How Security Features Are Layered On

Security configuration is passed through custom HTTP headers rather than modifying the request body:

| Header | Purpose |
|---|---|
| `X-Security-Policy` | SQRT policy source and configuration |
| `X-Security-Config` | Fine-grained behavioral configuration |
| `X-Security-Features` | Feature flags (dual LLM mode, taggers, constraints) |
| `X-Session-Id` | Session continuation token |

The response `content` field contains a JSON string with Security Compass extensions:

| Field | Description |
|---|---|
| `status` | `"success"`, `"failure"`, or `"unknown"` |
| `final_return_value` | The computed result from the PLLM-generated program |
| `error` | Error details if the status is `"failure"` |
| `program` | The Python code generated by the PLLM |
| `raw` | The full `TurnResult` for debugging and introspection |

This means a standard OpenAI client receives a valid response, and a Security Compass-aware client can parse the content JSON for richer information.

---

## 10. Why DashMap for Sessions?

### The Concurrency Problem

The server handles multiple concurrent requests, each potentially accessing a different session. The session store must support concurrent reads and writes without becoming a bottleneck.

### Alternatives Considered

| Approach | Behavior | Trade-off |
|---|---|---|
| `Mutex<HashMap>` | Exclusive lock for all operations | Simple but blocks all readers during any write; serializes all session access |
| `RwLock<HashMap>` | Shared reads, exclusive writes | Better read concurrency but all readers block during a write (session creation/update) |
| `DashMap` | Shard-level locking | Multiple sessions can be accessed and modified concurrently as long as they hash to different shards |

### Why DashMap

`DashMap` partitions the key space into shards, each with its own lock. Operations on different shards proceed in parallel. For a session store where session UUIDs are uniformly distributed, this provides good concurrency without the complexity of a lock-free data structure.

### Known Trade-off

The current implementation holds the DashMap shard lock across the async `process_turn().await` call. This means that while one session is being processed (which may involve a long LLM API call), its shard is locked, potentially blocking access to other sessions that hash to the same shard.

This is acceptable for moderate concurrency because:

- UUIDs are uniformly distributed, so sessions are spread across shards
- The number of concurrent active sessions is typically much smaller than the number of shards
- Different sessions usually hash to different shards

For high-load production deployments, the optimization would be to extract the session from the map before the async call, process it outside the lock, and reinsert it after. This is noted as a future improvement.

---

## 11. Why Arc\<CompiledPolicy\> in the Interpreter?

### The Problem

The `CompiledPolicy` is needed in two places:

1. The `Interpreter`, which evaluates SQRT policies at tool call boundaries
2. The `PolicyBranchChecker`, which checks branching meta-policy at conditional jump opcodes inside the VM

These are separate components with different lifetimes. The `Interpreter` persists across the entire session, while `PolicyBranchChecker` instances are created fresh before every VM resume (because the `BranchChecker` field on the VM snapshot is `#[serde(skip)]` and gets cleared during serialization).

### Why Arc

Using `Arc<CompiledPolicy>`:

- Avoids cloning the policy (which contains compiled regex patterns, hash maps, resolved let-variable values, etc.) every time a `PolicyBranchChecker` is created
- Provides shared ownership with reference counting, which is cheap (single atomic increment per clone)
- Is thread-safe, which is necessary if the server were to process multiple sessions on different threads (though currently each session is processed sequentially)

### The Re-injection Pattern

Before every VM resume, the interpreter:

1. Creates a new `PolicyBranchChecker` wrapping `Arc::clone(&self.policy)`
2. Calls `snapshot.set_branch_checker(Box::new(checker))` to inject it into the VM
3. Resumes the VM

This ensures the branch checker is always present during execution, even after snapshot serialization/deserialization cycles that clear the `#[serde(skip)]` field.

---

## 12. Why Separate Request/Response Types from Orchestrator Types?

### The Layering

The server has its own type system in `types/`:

- `types/headers.rs` -- HTTP header structures with string-based enums
- `types/request.rs` -- OpenAI-compatible request types
- `types/response.rs` -- OpenAI-compatible response types

These map to orchestrator types via config builders in `config.rs`.

### Why the Separation Exists

**Different naming conventions**: HTTP headers use string-based enums matching the Python reference implementation (kebab-case for some fields, snake_case for others). Orchestrator types use Rust-native enums (CamelCase). For example:

- Header: `"cache_tool_result": "deterministic-only"` (string)
- Orchestrator: `CacheMode::DeterministicOnly` (enum variant)

**Independent evolution**: The HTTP API contract (request/response shapes, header formats) must remain stable for client compatibility. The orchestrator's internal type system can evolve freely -- adding new configuration options, changing enum variants, restructuring types -- without breaking the API contract.

**Mapping as a validation layer**: The `build_session_config()` and `build_interpreter_config()` functions in `config.rs` translate between the two type systems. This translation is also a validation step: invalid header values are caught during mapping rather than propagating as string values deep into the orchestrator.

**Compatibility with reference implementation**: The Python reference implementation defines specific string formats for header values. The server's type system mirrors these formats exactly (with serde annotations) to ensure interoperability, while the orchestrator uses idiomatic Rust types internally.

---

## 13. Security Design Principles

The following principles guide all design decisions across the Security Compass Engine.

### Defense in Depth

Security is enforced at multiple layers, each independent of the others:

| Layer | Mechanism | What it prevents |
|---|---|---|
| Bytecode level | Parallel metadata tracking on every value | Data provenance laundering through Python operations |
| Tool call boundary | SQRT policy evaluation before dispatch | Unauthorized tool invocations based on metadata analysis |
| Conditional jumps | Branch checker at `JumpIfTrue`/`JumpIfFalse` | Untrusted data steering program control flow |
| Value merge operations | Consumer set intersection | Restriction removal through value combination |
| LLM separation | Dual-LLM architecture (PLLM/QLLM) | Prompt injection from tool results influencing tool calls |

No single layer is solely responsible for security. An attacker would need to defeat all layers simultaneously.

### Fail-Safe Defaults

The system defaults to restriction rather than permissiveness:

- Consumer intersection is restrictive by default. Combining values never loosens restrictions.
- Missing SQRT policy behavior is configurable (`default_allow` or `default_deny`), and the choice is explicit in the policy preset.
- The QLLM has no tool-calling capability by architectural design, not by configuration.
- Unknown tools are rejected by the interpreter (`UnknownTool` error).
- Streaming is explicitly rejected rather than silently degraded.

### Separation of Concerns

Each component has a clearly bounded responsibility:

- The **PLLM** generates code. It never sees untrusted data.
- The **QLLM** processes untrusted data. It never calls tools.
- The **VM** executes bytecodes and propagates metadata. It does not evaluate policies.
- The **interpreter** evaluates policies and manages yield points. It does not perform I/O.
- The **orchestrator** performs I/O and drives the session loop. It does not evaluate policies.
- The **server** handles HTTP and session management. It does not execute code.

This separation means that a bug in one component has limited blast radius. A vulnerability in the QLLM cannot lead to unauthorized tool calls because the QLLM has no mechanism to request them.

### Monotonic Restriction

Security constraints only accumulate. No operation in the system removes or relaxes a constraint:

- **Consumer sets** only get more restrictive through intersection. The empty set (`Finite({})`) is absorbing -- once reached, no operation can restore permissions.
- **Tags** only accumulate through union. Once a value is tagged (e.g., `__non_executable`), no Python operation can remove that tag. Only SQRT policy rules with explicit metadata update operations can modify tags.
- **Producers** only accumulate through union. The provenance record of a value only grows as it flows through the system.

This monotonicity means that an attacker cannot use data combination or transformation to escape security constraints. The worst case from combining values is that the result inherits the union of all restrictions.

### Audit Trail

The system maintains a complete record of security-relevant events:

- **Tool call history**: Every tool call is recorded with its name, arguments, result, and policy decision.
- **SQRT policy decisions**: Each policy evaluation produces a `PolicyDecision` with the rule that matched, the enforcement level, and the metadata updates applied.
- **Metadata state**: The metadata of the final return value is included in the response, showing the complete provenance chain.
- **PLLM-generated code**: The Python program generated by the PLLM is included in the response for inspection.
- **Error feedback**: The error messages sent to the PLLM during retry are recorded in the message history.

All of this information is available in the `raw` field of the response's `ResponseContentJsonSchema`, enabling post-hoc analysis and debugging of security decisions.
