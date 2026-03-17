# Security Compass Engine

A Rust implementation of the CaMeL (Capabilities, Metadata, and LLM) dual-LLM architecture. Enforces SQRT security policies at the bytecode level to prevent prompt injection in agentic AI systems.

## Overview

Security Compass Engine wraps LLM-generated Python code in a metadata-tracking virtual machine with SQRT policy enforcement. Every value flowing through the VM carries rich metadata -- producers, consumers, and tags -- that propagates automatically through operations and gets checked against compiled SQRT policies before any tool call is dispatched.

The system follows a **dual-LLM approach**:

- **PLLM (Privileged LLM)**: A trusted model that generates Python programs to fulfill user requests. It sees only trusted context (system prompts, user messages, tool schemas) and produces deterministic code rather than free-form text.
- **QLLM (Quarantined LLM)**: An isolated model that processes untrusted data (web pages, emails, external API responses). Its outputs are tagged as non-executable and tracked through the metadata system, ensuring they cannot influence tool calls in unauthorized ways.

The key innovation is that every value in the VM carries metadata that records where data came from (producers), where it flows to (consumers), and what sensitivity labels apply (tags). This metadata propagates through all operations -- assignments, function calls, string concatenation, container access -- and is checked against SQRT policies at every tool invocation boundary.

## Architecture

```
security-compass-server (HTTP API)
  |
  +-- security-compass-orchestrator (Dual-LLM session loop)
  |     |
  |     +-- security-compass-interpreter (VM + policy enforcement)
  |     |     |
  |     |     +-- security-compass-vm (Python bytecode VM with metadata)
  |     |     |     |
  |     |     |     +-- security-compass-meta (Metadata types)
  |     |     |
  |     |     +-- sqrt-eval (Policy compilation & evaluation)
  |     |           |
  |     |           +-- sqrt-parser (SQRT language parser)
  |     |           |
  |     |           +-- security-compass-meta
  |     |
  |     +-- security-compass-meta
```

Data flows top-down: the server receives HTTP requests, the orchestrator manages the PLLM/QLLM session loop, the interpreter runs bytecode with policy checks, and the VM tracks metadata at the instruction level. The `security-compass-meta` crate is shared across layers to provide a unified metadata model.

## Crate Overview

| Crate | Purpose | Tests |
|---|---|---|
| `security-compass-meta` | Metadata types, propagation rules, ConsumerSet algebra | 67 |
| `sqrt-parser` | SQRT policy language lexer and parser (pest PEG grammar) | 58 |
| `sqrt-eval` | Policy compilation to decision trees, runtime evaluation, branch resolution | 108 |
| `security-compass-vm` | Forked Monty Python bytecode VM with parallel metadata tracking on every value | 36 |
| `security-compass-interpreter` | Wires together the VM, metadata engine, and SQRT policy enforcer | 60 |
| `security-compass-orchestrator` | Dual-LLM session orchestration, turn management, tool dispatch | 65 |
| `security-compass-server` | HTTP API layer (axum), OpenAI-compatible endpoints, session management | 153 |
| **Total** | | **548** |

## Quick Start

### Prerequisites

- Rust 1.75+ (2021 edition)
- An OpenAI API key (or OpenRouter API key)

### Building

```bash
cargo build --workspace
cargo test --workspace
```

### Running the Server

```bash
# Required
export PORT=8080  # default

# Optional
export SEQURITY_API_KEY=your-server-auth-key  # server authentication
export SESSION_TTL_SECS=1800                  # session timeout (default 30 min)

cargo run -p security-compass-server
```

### Making a Request

```bash
curl -X POST http://localhost:8080/control/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: your-openai-key" \
  -H "X-Security-Policy: {\"language\":\"sqrt\",\"codes\":\"tool \\\"*\\\" { must deny when @args.tags overlaps {\\\"__non_executable\\\"}; }\"}" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "What is 2+2?"}]
  }'
```

## HTTP API

### Endpoints

| Endpoint | Description |
|---|---|
| `POST /control/v1/chat/completions` | Default provider (OpenAI) |
| `POST /control/{provider}/v1/chat/completions` | Named provider (`openai`, `openrouter`) |
| `POST /control/lang-graph/{provider}/v1/chat/completions` | LangGraph integration (stub, returns 501) |

### Security Headers

| Header | Type | Description |
|---|---|---|
| `X-Api-Key` | string | LLM provider API key (required) |
| `Authorization` | Bearer token | Server authentication (required if `SEQURITY_API_KEY` is set) |
| `X-Security-Policy` | JSON | SQRT policy configuration |
| `X-Security-Config` | JSON | Fine-grained config (max attempts, caching, etc.) |
| `X-Security-Features` | JSON | Feature flags (dual LLM mode, taggers, constraints) |
| `X-Session-Id` | UUID | Session continuation token |

### Response Format

Responses are OpenAI-compatible with Security Compass extensions:

- A `session_id` field is included at the top level for session continuation.
- `choices[0].message.content` contains a JSON string conforming to `ResponseContentJsonSchema`:

| Field | Description |
|---|---|
| `status` | `"success"`, `"failure"`, or `"unknown"` |
| `final_return_value` | The computed result from the PLLM-generated program |
| `error` | Error details if the status is `"failure"` |
| `program` | The Python code generated by the PLLM |
| `raw` | The full `TurnResult` for debugging and introspection |

## SQRT Policy Language

SQRT (Security Query and Rule Toolkit) is a domain-specific language for declaring data-flow security policies. Policies are compiled into decision trees and evaluated at every tool invocation boundary.

```sqrt
// Deny tools whose arguments carry PII or sensitive tags
tool "send_email" {
    must deny when @args.tags overlaps {"pii", "sensitive"};
}

// Allow read-only tools without restriction
tool "search" {
    should allow;
}

// Track data provenance through tool results
tool "fetch_user_data" {
    result { tags |= {"pii", "user_data"}; }
    session after { producers |= {"user_db"}; }
}
```

Key concepts:

- **`must deny`** / **`should allow`**: Declares hard or soft enforcement on tool invocations.
- **`@args.tags`**: Accesses the merged tag set of all arguments passed to the tool.
- **`overlaps`**: Set intersection predicate -- true if the sets share any element.
- **`result`** block: Metadata mutations applied to the tool's return value.
- **`session after`** block: Metadata mutations applied to session-level state after tool execution.

## Configuration

The `X-Security-Config` header accepts a JSON object with the following fields:

| Field | Default | Description |
|---|---|---|
| `max_pllm_attempts` | `1` | Maximum retries for PLLM code generation per turn |
| `merge_system_messages` | `true` | Combine multiple system messages into one |
| `max_tool_calls_per_attempt` | `200` | Cap on tool invocations per PLLM attempt |
| `cache_tool_result` | `"deterministic-only"` | Tool result caching strategy |
| `clear_session_meta` | `"never"` | When to reset session-level metadata |
| `pllm_debug_info_level` | `"normal"` | Verbosity of debug info sent to the PLLM |
| `max_n_turns` | `5` | Maximum conversation turns per session |
| `enabled_internal_tools` | `["parse-with-ai", "verify-hypothesis"]` | Internal tools available to the PLLM |
| `pllm_can_ask_for_clarification` | `true` | Whether the PLLM may request user clarification |

## Project Status

All 7 implementation phases are complete. The workspace contains 548 tests across all crates with 0 clippy warnings.

For detailed documentation, see:

- [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) -- Per-phase implementation progress and notes
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) -- System architecture and design decisions
- [`docs/DESIGN.md`](docs/DESIGN.md) -- Detailed design rationale
- [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md) -- Mermaid architecture diagrams
- [`docs/TESTING.md`](docs/TESTING.md) -- Test strategy and coverage
- [`docs/EXAMPLES.md`](docs/EXAMPLES.md) -- Usage examples and walkthroughs

## License

MIT
