# Testing

## Overview

548 tests across 7 crates. All tests pass. Zero clippy warnings.

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p security-compass-meta
cargo test -p sqrt-parser
cargo test -p sqrt-eval
cargo test -p security-compass-vm
cargo test -p security-compass-interpreter
cargo test -p security-compass-orchestrator
cargo test -p security-compass-server

# Run clippy
cargo clippy --workspace --all-targets
```

## Test Distribution

| Crate | Tests | Categories |
|-------|-------|------------|
| security-compass-meta | 67 | ConsumerSet algebra (22), Metadata merge/propagation (30), ValueWithMeta (15) |
| sqrt-parser | 58 | Empty/whitespace programs, let declarations, tool declarations, predicates, set operations, type domains, metadata updates, error cases, real-world examples |
| sqrt-eval | 108 | Compiler (16), Value matching (16), Set evaluation (15), Predicate evaluation (13), Metadata updates (11), Evaluator (13), Branching (7), Integration (8), plus more |
| security-compass-vm | 36 | Unit tests (22), Integration metadata tests (14) -- literals, binary ops, branch checking, external calls, async, snapshot roundtrip |
| security-compass-interpreter | 60 | Convert tests (18), Branch checker (8), Execution (13), Policy integration (9), Edge cases (12) |
| security-compass-orchestrator | 65 | Code extraction (12), Prompt builder (8), Error feedback (3), QLLM (6), Session (6), Interpreter loop (10), Turn processing (12), Integration (8) |
| security-compass-server | 153 | Type serde (43), Header parsing (14), Config mapping (14), Policy compilation (10), Session store (10), Message extraction (14), Tool executors (4), Response building (16), Error variants (10), LLM client (8), Handler integration (11) |

## Testing Strategy

### Unit Tests

Each module is tested in isolation. The project convention is a single `tests.rs` file per crate with `#[cfg(test)]`.

### Mock Infrastructure

The orchestrator and server use mock implementations of the `LlmClient` and `ToolExecutor` traits:

```rust
// From orchestrator tests
struct MockLlmClient {
    responses: Mutex<VecDeque<String>>,
    schema_responses: Mutex<VecDeque<Value>>,
}

struct MockToolExecutor {
    results: Mutex<HashMap<String, VecDeque<Value>>>,
}
```

The server handler integration tests use `tower::ServiceExt::oneshot()` to send requests directly to the axum router without starting an HTTP server:

```rust
fn build_test_router(server_api_key: Option<String>) -> Router {
    let state = Arc::new(AppState {
        session_store: SessionStore::new(Duration::from_secs(300)),
        server_api_key,
    });
    Router::new()
        .route("/control/v1/chat/completions", post(handle_chat_completions_default))
        .route("/control/{provider}/v1/chat/completions", post(handle_chat_completions))
        .route("/control/lang-graph/{provider}/v1/chat/completions", post(handle_langgraph_stub))
        .with_state(state)
}
```

LLM client tests use `wiremock` for HTTP-level mocking.

### Integration Tests

- **sqrt-eval**: End-to-end policy compilation + evaluation for real-world scenarios (data leak prevention, PII protection, session tracking)
- **security-compass-interpreter**: Full execution with SQRT policy enforcement (tool denial, non-executable memory, session metadata persistence)
- **security-compass-orchestrator**: Multi-turn sessions, PLLM retry loops, QLLM routing, policy deny with retry
- **security-compass-server**: Handler integration tests verifying HTTP status codes, header parsing, authentication, and error responses

## Security Invariants Verified

### Metadata Propagation (security-compass-meta)

- Consumer intersection is monotonically restrictive (merging never loosens)
- Default metadata is clean (empty producers, universal consumers, empty tags)
- Special tags detected correctly (`__non_executable`, `__llm_blocked`, `__tool/parse_with_ai`)
- Serde roundtrip preserves all fields including Universal consumer set

### Policy Enforcement (sqrt-eval)

- `must deny` at equal or higher priority always fires (cannot be overridden)
- Priority ordering is deterministic (stable sort preserves declaration order)
- Consumer intersection monotonicity preserved through metadata update operations
- Branching meta-policy blocks untrusted metadata from influencing control flow
- Fail-fast mode returns immediately on first deny

### VM Metadata Tracking (security-compass-vm)

- `stack.len() == stack_meta.len()` at every instruction boundary
- `namespace.values.len() == namespace.metadata.len()` for every namespace
- `Metadata::merge()` called for every binary/comparison operation
- `BranchChecker::check()` called for every conditional jump
- Exception handling syncs metadata stack on unwind

### Interpreter Security (security-compass-interpreter)

- Policy checks are pre-execution (SQRT evaluated before yielding NeedsToolCall)
- Metadata is interpreter-managed (neither PLLM nor QLLM can see/modify metadata)
- Non-executable tag applied to all tool results when enabled
- Branch checker re-injected on every VM resume (not lost through serialization)
- LLM blocked tag prevents routing to QLLM tools

### Orchestrator Security (security-compass-orchestrator)

- SQRT policy evaluation occurs before any tool call is yielded
- QLLM has no tool-calling capability (enforced by API shape)
- Internal tools can be disabled per session config
- Session metadata clearing follows configured schedule
- Fatal errors are not retried

### Server Security (security-compass-server)

- Server API key authentication enforced (missing/wrong bearer -> 401)
- LLM API key required (missing X-Api-Key -> 400)
- SQRT-only policy language (cedar/sqrt-lite rejected)
- Invalid SQRT source -> PolicyCompileError (never silently ignored)
- Streaming rejected (stream: true -> 400)
- Session TTL enforced

## Testing Patterns

### Serde Roundtrip Tests

All types with serde derive are tested for roundtrip: serialize -> deserialize -> assert equality. This catches field renaming issues, default value problems, and serialization format mismatches.

### Error Path Testing

Every error variant is tested:

- Parser errors with specific line/column information
- Compiler errors for invalid policies (bad regex, duplicate variables)
- Evaluator errors for undefined references
- Interpreter errors for all 11 variants (VmError, PolicyCompileError, OsCallDenied, GasExhausted, etc.)
- Orchestrator errors for all 10 variants
- Server errors mapped to correct HTTP status codes

### Edge Cases

- Empty inputs (empty programs, empty messages, empty policies)
- Boundary values (zero gas limit, zero TTL, max attempts = 1)
- Unicode and special characters in tool names
- Multiple policies for the same tool (priority resolution)
- Session expiration during access
- Concurrent session access (tokio multi-task)

### Property-Based Verification

While not using a formal property testing library, several tests verify algebraic properties:

- ConsumerSet intersection commutativity and associativity
- Metadata merge associativity
- Set operation identity elements (empty set, universal set)

## Running Tests

```bash
# All tests (recommended before committing)
cargo test --workspace

# Single crate
cargo test -p security-compass-server

# Single test
cargo test -p sqrt-eval -- compile_policy_simple_sqrt

# With output (for debugging)
cargo test -p security-compass-interpreter -- --nocapture

# Clippy (zero warnings required)
cargo clippy --workspace --all-targets
```
