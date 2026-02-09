# Security Compass Engine — Implementation Status

**Repo:** `github.com/isachit/security-compass-impl`
**Spec:** `sequrity-impl/spec.md` (in parent `contextualpolicy/` directory)

---

## Phase Overview

| Phase | Crate | Status | Tests | Notes |
|-------|-------|--------|-------|-------|
| 1 | `security-compass-meta` | ✅ Complete | 67 pass | Metadata types, propagation, ConsumerSet, ValueWithMeta |
| 2 | `sqrt-parser` | ✅ Complete | 58 pass | SQRT grammar → AST (pest PEG parser) |
| 3 | `sqrt-eval` | 🔲 Not started | — | Policy evaluation engine |
| 4 | `sequrity-vm` | 🔲 Not started | — | Forked Monty with metadata hooks |
| 5 | `security-compass-interpreter` | 🔲 Not started | — | VM + metadata + policy wired together |
| 6 | `security-compass-orchestrator` | 🔲 Not started | — | Dual LLM session orchestration |
| 7 | `security-compass-server` | 🔲 Not started | — | HTTP API layer |

---

## Phase 1: `security-compass-meta` ✅

**Branch:** `main`
**Commit:** `487594f`
**Tests:** 67 passed, 0 failed

### What was built

| File | Purpose |
|------|---------|
| `src/constants.rs` | `NON_EXECUTABLE_TAG`, `PARSE_WITH_AI_TAG`, `LLM_BLOCKED_TAG` |
| `src/consumer_set.rs` | `ConsumerSet` enum (Universal/Finite) with full set algebra (22 tests) |
| `src/metadata.rs` | `Metadata` struct: merge, merge_all, builders, augmented assignments (30 tests) |
| `src/value_with_meta.rs` | `ValueWithMeta<T>`, `ToolResultWithMeta<T>`, `CombineMetaMode` (15 tests) |
| `src/lib.rs` | Public re-exports |

### Key types

- `Metadata { producers, consumers, tags }` — three-field metadata with propagation rules
- `ConsumerSet::Universal | ConsumerSet::Finite(BTreeSet<String>)` — consumer restriction
- `ValueWithMeta<T>` — value + metadata wrapper
- `ToolResultWithMeta<T>` — tool result with merge/replace/ignore combine mode
- `CombineMetaMode` — Merge | Replace | Ignore

### Security invariants verified by tests

- Consumer intersection is monotonically restrictive (merging never loosens restrictions)
- Default metadata is clean (empty producers, universal consumers, empty tags)
- Special tags (`__non_executable`, `__llm_blocked`, `__tool/parse_with_ai`) detected correctly
- Serde roundtrip preserves all fields including Universal consumer set

---

## Phase 2: `sqrt-parser` ✅

**Branch:** `phase2/sqrt-parser`
**Depends on:** `security-compass-meta`
**Tests:** 58 passed, 0 failed

### What was built

| File | Purpose |
|------|---------|
| `src/sqrt.pest` | Complete pest PEG grammar (faithfully translated from Lark Earley grammar) |
| `src/ast.rs` | Typed AST: 30+ types covering all SQRT language features |
| `src/parser.rs` | Pest parse pairs → typed AST conversion (~1340 lines) |
| `src/error.rs` | `SqrtParseError` with line/column info and caret-pointed source snippets |
| `src/tests.rs` | 58 comprehensive tests covering all SQRT features and edge cases |
| `src/lib.rs` | Public re-exports (`parse()`, `validate()`, all AST types) |

### Key design decisions

- **Lark → pest translation**: Left-recursion rewritten as repetition (PEG limitation); operator precedence encoded in grammar structure
- **Predicate precedence** (low→high): `or`, `and`, `not`, atom
- **Set operator precedence** (low→high): `xor`, `minus`, `intersect`, `union`, `with`/`without`
- **IDENTIFIER keyword exclusion**: Word-boundary checking pattern prevents keywords from being parsed as identifiers while allowing keyword-prefixed names (e.g., `session_id`)
- **Set operator disambiguation**: Negative lookahead prevents `|=` from matching as union `|`
- **predicate_not fix**: Uses span comparison to detect silently-consumed `"not"` keyword in pest PEG

### Test coverage areas

- Empty/whitespace/comment-only programs
- Let declarations (set literals, empty sets, regex sets, predicates)
- Tool shorthand (simple, priority, session targets, conditions, regex IDs)
- Tool declarations (check rules, hard/soft aliases, result blocks, session blocks, priority)
- Predicates (and, or, not, double not, not+and precedence, ref, parenthesized)
- Set comparisons (subset, superset, equals, is_empty, is_universal, overlaps)
- Value comparisons (in, equals)
- Set operations (union, intersect, minus, keyword ops)
- Type domains (bool, int ranges, int exclusive, str with length, str wildcard)
- Meta field access (@args, @session, @result, arg.field, aggregation)
- Metadata updates (all augmented assign ops: =, |=, &=, -=, ^=)
- Result/session conditionals
- Doc comments, escaped strings, multiple declarations
- Complex real-world examples (data leak prevention, PII protection, refund workflow)
- Error cases (missing semicolon, unclosed brace, invalid enforcement)
- AST serialization roundtrip

---

## Phase 3: `sqrt-eval` 🔲

**Branch:** TBD
**Depends on:** `sqrt-parser`, `security-compass-meta`

### Planned scope

- Compile parsed SQRT into `CompiledPolicy` (indexed by tool name, regex pre-compiled)
- Evaluate policies against `ToolCallContext` → `PolicyDecision` (Allow/Deny)
- Priority-based rule resolution with must/should enforcement
- Branching meta-policy check
- Internal policy preset defaults (default_allow, non-executable memory, llm_blocked)

---

## Phase 4: `security-compass-vm` 🔲

**Branch:** TBD
**Depends on:** Fork of Monty (`codesandboxing/monty`)

### Planned scope

- Fork Monty's bytecode VM
- Add parallel metadata arrays (stack_meta, namespace metadata)
- Metadata merge in binary/unary opcodes
- Branching hook in JumpIfTrue/JumpIfFalse
- Extended RunProgress::FunctionCall with metadata
- Resume with metadata for return values

---

## Phase 5: `security-compass-interpreter` 🔲

**Branch:** TBD
**Depends on:** `security-compass-vm`, `sqrt-eval`, `security-compass-meta`

### Planned scope

- Interpreter execution loop: VM + policy enforcement + metadata tracking
- Tool call interception with SQRT pre-checks
- parse_with_ai / verify_hypothesis routing
- Gas counting and tool call limits
- Namespace snapshot for debugging

---

## Phase 6: `security-compass-orchestrator` 🔲

**Branch:** TBD
**Depends on:** `security-compass-interpreter`, `security-compass-meta`

### Planned scope

- Session management with turn limits
- PLLM system prompt construction
- Code extraction from PLLM response
- QLLM routing for parse_with_ai
- Retry loop with error formatting
- LlmClient and ToolExecutor traits

---

## Phase 7: `security-compass-server` 🔲

**Branch:** TBD
**Depends on:** `security-compass-orchestrator`

### Planned scope

- HTTP API (axum): `POST /control/{provider}/v1/chat/completions`
- Header parsing: X-Security-Features, X-Security-Policy, X-Security-Config, X-Session-Id
- Session store (in-memory with DashMap)
- OpenAI-compatible request/response format
