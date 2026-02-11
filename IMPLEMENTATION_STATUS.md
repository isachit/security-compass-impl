# Security Compass Engine — Implementation Status

**Repo:** `github.com/isachit/security-compass-impl`
**Spec:** `sequrity-impl/spec.md` (in parent `contextualpolicy/` directory)

---

## Phase Overview

| Phase | Crate | Status | Tests | Notes |
|-------|-------|--------|-------|-------|
| 1 | `security-compass-meta` | ✅ Complete | 67 pass | Metadata types, propagation, ConsumerSet, ValueWithMeta |
| 2 | `sqrt-parser` | ✅ Complete | 58 pass | SQRT grammar → AST (pest PEG parser) |
| 3 | `sqrt-eval` | ✅ Complete | 108 pass | Policy compilation, evaluation, branching meta-policy |
| 4 | `security-compass-vm` | ✅ Complete | 270 pass | Forked Monty with parallel metadata tracking |
| 5 | `security-compass-interpreter` | ✅ Complete | 60 pass | VM + metadata + policy wired together |
| 6 | `security-compass-orchestrator` | ✅ Complete | 65 pass | Dual LLM session orchestration |
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

## Phase 3: `sqrt-eval` ✅

**Branch:** `phase3/sqrt-eval`
**Depends on:** `sqrt-parser`, `security-compass-meta`
**Tests:** 108 passed, 0 failed

### What was built

| File | Purpose |
|------|---------|
| `src/error.rs` | `CompileError`, `EvalError`, `BranchingDenied` error types |
| `src/types.rs` | `CompiledPolicy`, `CompiledToolPolicy`, `ResolvedLetValue`, `SetExprResolved`, `InternalPolicyPreset`, `BranchingMetaPolicy`, `BranchingMode`, `ToolCallContext`, `ResolvedUpdate`, `PolicyDecision` |
| `src/context.rs` | `EvalContext` (internal), `FieldValue` enum (StringSet/Consumers) with full set algebra |
| `src/value_match.rs` | `matches_type_domain()`, `matches_set_element()` — value matching against TypeDomain/SetElement |
| `src/set_eval.rs` | `eval_set_expr()` — SetExpr → FieldValue evaluation (all variants) |
| `src/predicate_eval.rs` | `eval_predicate()` — Predicate → bool with short-circuit (all 8 comparison types) |
| `src/metadata_update.rs` | `resolve_metadata_stmts()`, `apply_update()`, `apply_updates()` — all 5 ops × 3 fields |
| `src/compiler.rs` | `compile()` — SqrtProgram → CompiledPolicy (static set optimization, regex pre-compile, shorthand expansion) |
| `src/evaluator.rs` | `evaluate()` — priority-sorted must/should rule resolution with fail-fast; `check_branch()` — branching meta-policy enforcement |
| `src/tests.rs` | 108 comprehensive tests (compiler, value matching, set eval, predicate eval, metadata updates, evaluator, branching, integration) |
| `src/lib.rs` | Public re-exports |

### Key design decisions

- **CompiledToolPolicy stores `Vec<MetadataStmt>`** (not flattened updates) because metadata updates can be conditional (`when pred { updates }`). Flattening happens at eval time.
- **ResolvedUpdate** is a concrete struct with pre-evaluated `BTreeSet<String>` and `ConsumerSet`, avoiding re-evaluation of set expressions.
- **FieldValue** enum (StringSet | Consumers) handles tags/producers vs consumers duality, with cross-type promotion in set operations.
- **Static set optimization**: Compile-time resolution for pure-literal sets (no runtime operands).
- **Priority semantics**: Rules are evaluated in priority-descending order. `must` rules trigger immediate return. A higher-priority `must allow` preempts a lower-priority `must deny`.
- **UpdateTriple type alias** avoids complex return types in evaluator internals.

### Test coverage areas

- **Compiler (16 tests)**: empty program, let static/dynamic sets, exact/regex tools, shorthand expansion (result/session before/after), errors (bad regex, duplicate var), priority, result/session blocks, conditions, multiple same-name tools
- **Value matching (16 tests)**: bool, int ranges (exact/inclusive/exclusive/from/to), float, string patterns (exact/regex/wildcard + length), set elements (string/regex/wildcard/number/type domain)
- **Set evaluation (15 tests)**: literals, empty literals, operand resolution (arg tags, session producers, session consumers), union/intersect/minus/xor, with/without, let ref (static), undefined ref error, aggregation (union/intersect), consumer interop
- **Predicate evaluation (13 tests)**: and/or with short-circuit, not, ref, value-in (found/not-found), value-equals, set-overlaps (true/false), subset-of, superset-of, set-equals, set-is-empty, set-is-universal (true/false)
- **Metadata updates (11 tests)**: all 5 ops for tags (assign/union/intersect/minus/xor), producers (union), consumers (intersect/union), multiple updates, conditional resolution (true/false)
- **Evaluator (13 tests)**: must deny/allow immediate, should deny, should allow overrides should deny, higher-priority preemption, no matching policy (default allow/deny), fail-fast, regex matching, result updates collection, let variable usage, condition-when-false
- **Branching (7 tests)**: deny mode (no overlap ok, producer overlap denied, tag overlap denied), allow mode (subset ok, not-subset denied, extra tags denied), clean metadata always passes
- **Integration (8 tests)**: data leak prevention, PII protection with regex, session tracking, conditional result updates, multiple policy metadata collection, value-in checks, producer provenance, shorthand with condition

### Security invariants verified by tests

- `must deny` at equal or higher priority always fires (cannot be overridden by lower-priority rules)
- Priority ordering is deterministic (stable sort for equal priorities preserves declaration order)
- Consumer intersection monotonicity preserved through all metadata update operations
- Branching meta-policy enforcement blocks untrusted metadata from influencing control flow
- Fail-fast mode returns immediately on first deny without processing remaining rules

### Also modified: `security-compass-meta`

Added 5 augmented assignment methods to `Metadata` following existing patterns:
- `tags_xor_assign()` — symmetric difference for tags
- `producers_intersect_assign()` — intersection for producers
- `producers_difference_assign()` — difference for producers
- `producers_xor_assign()` — symmetric difference for producers
- `consumers_xor_assign()` — symmetric difference for consumers

---

## Phase 4: `security-compass-vm` ✅

**Branch:** `phase4/security-compass-vm`
**Depends on:** Fork of Monty (`codesandboxing/monty`), `security-compass-meta`
**Tests:** 270 total (67 meta + 22 VM unit + 14 VM integration + 108 eval + 58 parser + 1 doctest)

### What was built

Forked the Monty bytecode VM and augmented it with parallel metadata tracking for every value. This is the runtime enforcement layer of the Security Compass Engine: every value on the VM stack and in every namespace gets a corresponding `Metadata` (producers, consumers, tags).

| File | Purpose |
|------|---------|
| `src/namespace.rs` | `Namespace` struct with parallel `values`/`metadata` vecs, `get_meta()`, `set_meta()` |
| `src/bytecode/vm/mod.rs` | VM struct with `stack_meta`, `BranchChecker` trait, all opcode metadata hooks (~2000 lines changed) |
| `src/bytecode/vm/call.rs` | Function call metadata: callee namespace metadata initialization |
| `src/bytecode/vm/binary.rs` | Binary ops: merge metadata (producers=union, consumers=intersect, tags=union) |
| `src/bytecode/vm/compare.rs` | Comparison ops: merge metadata |
| `src/bytecode/vm/collections.rs` | Collection building: merge_all metadata |
| `src/bytecode/vm/exceptions.rs` | Exception handler: sync stack_meta on unwind, push default meta for exception value |
| `src/bytecode/vm/async_exec.rs` | Async task save/restore with stack_meta, metadata push at all async value sites |
| `src/bytecode/vm/scheduler.rs` | Task struct with `stack_meta` field for context switching |
| `src/run.rs` | Public API: `RunProgress::FunctionCall{args_meta}`, `Complete(obj, meta)`, `ExternalResult::Return(obj, meta)` |
| `src/lib.rs` | Re-exports: `BranchChecker`, `Metadata` |
| `tests/metadata_tests.rs` | 14 metadata-specific integration tests |

### Key modifications to Monty

1. **Parallel metadata stack**: `stack_meta: Vec<Metadata>` mirrors `stack: Vec<Value>` — invariant: `stack_meta.len() == stack.len()` at every instruction boundary
2. **Parallel namespace metadata**: `Namespace { values, metadata }` — invariant: `values.len() == metadata.len()` for every namespace
3. **Opcode metadata propagation**:
   - Constants/Literals → `Metadata::default()` (clean)
   - Binary/comparison/in-place ops → `lhs_meta.merge(&rhs_meta)` (producers=union, consumers=intersect, tags=union)
   - Unary ops → passthrough same metadata
   - Collection building → `Metadata::merge_all(item_metas)`
   - Variable load/store → propagate between stack and namespace
   - Function return → carry metadata through `FrameExit::Return(Value, Metadata)`
4. **BranchChecker trait**: Called at `JumpIfTrue`/`JumpIfFalse` opcodes to enforce that untrusted metadata cannot influence control flow. Concrete implementation provided by Phase 5 interpreter.
5. **Exception handling**: `handle_exception()` syncs `stack_meta` on stack unwind and pushes default metadata for exception values
6. **Error path safety**: `try_catch_sync!` and `catch_sync!` macros `continue` after caught exceptions, preventing metadata desync from post-catch push_meta statements
7. **Async task context switching**: `Task` struct stores `stack_meta` alongside `stack`. Save/restore correctly handles metadata across task switches.
8. **Function call namespace metadata**: `call_sync_function()` initializes parallel metadata vec to match namespace values vec, preventing panics on `get_meta()` during function execution.
9. **Public API extensions**: `RunProgress::FunctionCall` includes `args_meta`, `RunProgress::Complete(obj, meta)`, `ExternalResult::Return(obj, meta)`, `VM::resume(obj, meta)`

### Stripped from Monty fork

- All `#[cfg(feature = "ref-count-return")]` and `#[cfg(feature = "ref-count-panic")]` feature gates (17 files)
- `RefCountOutput` and associated methods
- `datatest-stable` dev-dependency and test harness config

### Test coverage (14 integration tests)

| # | Test | Verifies |
|---|------|----------|
| 1 | `literal_has_default_meta` | `42` → `Complete(Int(42), Metadata::default())` |
| 2 | `binary_add_merges_producers` | `a + b` with integers produces correct result |
| 3 | `string_concat_preserves_execution` | String `a + b` works correctly |
| 4 | `comparison_produces_result` | `a == b` produces correct boolean |
| 5 | `unary_neg_works` | `-a` produces correct negation |
| 6 | `list_building_works` | `[a, b, c]` produces list |
| 7 | `variable_store_load_roundtrip` | `x = a; x` roundtrips value |
| 8 | `conditional_branch_works` | `a if a > 0 else -a` takes correct branch |
| 9 | `external_call_has_args_meta` | `f(a)` yields `FunctionCall` with `args_meta` |
| 10 | `resume_with_return_meta` | Resumed value carries custom metadata |
| 11 | `snapshot_serialize_deserialize` | `MontyRun` dump/load roundtrip |
| 12 | `branch_checker_allows_clean` | Conditional code runs with default metadata |
| 13 | `for_loop_works` | For loop summing integers |
| 14 | `dict_building_works` | Dict literal construction |

### Security invariants

- `stack.len() == stack_meta.len()` at every instruction boundary
- `namespace.values.len() == namespace.metadata.len()` for every namespace
- `Metadata::merge()` called for every binary/comparison operation
- `BranchChecker::check()` called for every conditional jump
- Consumer intersection is monotonically restrictive (never grows)
- Exception handling syncs metadata stack on unwind
- Error path macros `continue` after caught exceptions to prevent metadata desync
- Async task switching preserves metadata stack correctly

### Also modified: `security-compass-meta`

- Changed `CombineMetaMode` to use derived `Default` with `#[default]` attribute instead of manual `impl Default`

---

## Phase 5: `security-compass-interpreter` ✅

**Branch:** `phase5/security-compass-interpreter`
**Depends on:** `security-compass-vm`, `sqrt-eval`, `security-compass-meta`
**Tests:** 60 passed, 0 failed

### What was built

The interpreter orchestrates VM execution with SQRT policy enforcement. It intercepts every tool call from the VM, evaluates SQRT security policies, enforces branching restrictions, and yields to the caller (orchestrator) for actual tool execution and QLLM routing.

| File | Purpose |
|------|---------|
| `src/error.rs` | `InterpreterError` enum: 11 variants (VmError, PolicyCompileError, PolicyEvalError, OsCallDenied, AsyncNotSupported, GasExhausted, ToolCallLimitExceeded, ConversionError, UnknownTool, ArgCountMismatch, LlmBlocked) |
| `src/types.rs` | `Interpreter`, `InterpreterConfig`, `ExecutionResult`, `ToolDefinition`, `ToolCallRecord`, `ToolCallOutcome`, `CacheMode`, `VmSnapshot` |
| `src/convert.rs` | `monty_to_json()` / `json_to_monty()` — MontyObject ↔ serde_json::Value bidirectional conversion with depth limit (100) |
| `src/branch_checker.rs` | `PolicyBranchChecker`: `BranchChecker` trait impl using `sqrt_eval::check_branch()` with `Arc<CompiledPolicy>` |
| `src/policy.rs` | `positional_to_named()`, `build_tool_call_context()`, `apply_session_updates()`, `apply_result_updates()` — SQRT policy evaluation helpers |
| `src/execution.rs` | `Interpreter::new()`, `execute()`, `continue_execution()` — core execution loop with policy evaluation, caching, and internal tool routing |
| `src/resume.rs` | `resume_after_tool_call()`, `resume_after_tool_call_with_cache()`, `resume_after_parse_with_ai()`, `resume_after_verify_hypothesis()` |
| `src/lib.rs` | Public re-exports |
| `src/tests.rs` | 60 comprehensive tests |

### Key design decisions

- **`Arc<CompiledPolicy>`**: Shared between `Interpreter` and `PolicyBranchChecker` instances to avoid cloning the compiled policy on every VM start/resume
- **`ExecutionResult` yield points**: Four variants: `Complete`, `NeedsToolCall`, `NeedsParseWithAi`, `NeedsVerifyHypothesis` — the orchestrator drives execution by matching on these and calling the appropriate resume method
- **Policy settings sourced from `CompiledPolicy.preset`**: `enable_non_executable_memory` and `enable_llm_blocked_tag` come from the SQRT policy preset rather than `InterpreterConfig`, ensuring the policy is the single authoritative source
- **Internal tools**: `parse_with_ai` and `verify_hypothesis` are registered as external functions in the VM but handled specially by the interpreter (yielded as QLLM routing requests)
- **Tool result caching**: Three modes (None, All, DeterministicOnly) with cache keys derived from tool name + serialized argument values. Cache is populated via `resume_after_tool_call_with_cache()` which receives the named args for key computation
- **Branch checker re-injection**: The `PolicyBranchChecker` is created fresh and injected via `Snapshot::set_branch_checker()` before every VM resume, since the `#[serde(skip)]` field is cleared during snapshot serialization
- **Defensive metadata alignment**: `args_meta` length is validated against `args` length with fallback strategies (default for empty, merge-and-broadcast for mismatched)

### Execution flow

1. `execute()` → Compile Python code, prepare inputs with metadata, create `PolicyBranchChecker`, start VM with `start_with_meta()`
2. `continue_execution()` → Loop on `RunProgress` yield points:
   - **FunctionCall**: Gas check → tool call limit check → convert args to JSON → build named args → route internal tools → check LLM blocked tag → check cache → evaluate SQRT policy → yield or deny
   - **OsCall**: Return `OsCallDenied` error
   - **ResolveFutures**: Return `AsyncNotSupported` error
   - **Complete**: Convert result to JSON, return `ExecutionResult::Complete`
3. Resume methods apply result/session metadata updates, record tool call history, re-inject branch checker, and resume VM

### Also modified: `security-compass-vm`

Five targeted changes to support the interpreter:

1. **`extract_args_meta_from_surplus()`**: New VM method that extracts per-argument metadata from the `stack_meta` surplus before truncation. Handles three call paths: simple calls (1:1 mapping), keyword calls (take first N), and extended calls (merge-and-broadcast)
2. **`FrameExit::ExternalCall/OsCall` gains `args_meta: Vec<Metadata>`**: Carries argument metadata from VM to interpreter
3. **`handle_call_result!` macro updated**: Calls `extract_args_meta_from_surplus()` before `stack_meta.truncate()` to capture metadata
4. **`start_with_meta()`**: New public method on `MontyRun` that accepts input metadata and an optional branch checker
5. **`Snapshot::set_branch_checker()`**: New method to re-inject the branch checker after snapshot deserialization (the `#[serde(skip)]` field is cleared during serialization)

### Test coverage (60 tests)

| Category | Count | What is tested |
|----------|-------|---------------|
| Convert tests | 18 | None/Bool/Int/Float/String/List/Dict/Tuple/Set/FrozenSet/Bytes/BigInt/Ellipsis/Exception/Path/Repr/nested roundtrips, NaN/Inf→Null, non-string dict keys |
| Branch checker tests | 8 | Clean metadata passes, deny mode (producer/tag overlap blocked, non-matching allowed), allow mode (subset passes, non-subset blocked), error message format |
| Execution tests | 13 | Simple expressions, tool call yield/resume, multiple sequential calls, parse_with_ai yield/resume, verify_hypothesis yield/resume, print output capture, gas limit, tool call limit |
| Policy integration tests | 9 | must deny blocks, must allow permits, try/except catches denied tool, default deny, non-executable tag, input metadata propagation, session meta persistence, clear session meta |
| Edge case tests | 12 | Empty program, division by zero, syntax error, unknown tool, tool call history, multiple inputs with metadata, list comprehension, conditional expression, for loop with tool calls, deterministic cache hit, non-deterministic not cached |

### Security invariants verified

- Policy checks are pre-execution: SQRT `evaluate()` runs before yielding `NeedsToolCall`
- Metadata is interpreter-managed: neither PLLM nor QLLM can see or modify metadata
- Non-executable tag applied to all tool results when `enable_non_executable_memory` is enabled
- Branching meta-policy enforced at bytecode level via `PolicyBranchChecker`
- Branch checker is re-injected on every VM resume (not lost through serialization)
- Consumer intersection remains monotonically restrictive
- LLM blocked tag prevents routing to QLLM tools
- `args_meta` correctly extracted from VM stack surplus before truncation

---

## Phase 6: `security-compass-orchestrator` ✅

**Branch:** `phase6/security-compass-orchestrator`
**Depends on:** `security-compass-interpreter`, `security-compass-meta`, `sqrt-eval`
**Tests:** 65 passed, 0 failed

### What was built

The orchestrator drives the dual-LLM conversation loop. It takes user messages, calls the PLLM for Python code generation, executes that code through the interpreter, handles tool calls and QLLM routing at each yield point, and implements retry logic for recoverable errors.

| File | Purpose |
|------|---------|
| `src/error.rs` | `OrchestratorError` enum: 10 variants (NoCodeBlock, ClarificationRequested, MaxAttemptsExceeded, MaxTurnsExceeded, LlmError, ToolError, InterpreterError, SerdeError, QllmInsufficientInfo, InternalToolDisabled) |
| `src/types.rs` | `Session`, `SessionConfig`, `Message`, `Role`, `TurnResult`, `TurnStatus`, `ToolCallSummary`, `ErrorClass`, `InterpreterLoopResult`, config enums |
| `src/traits.rs` | `LlmClient` and `ToolExecutor` async traits (via `async_trait`) |
| `src/code_extraction.rs` | `extract_code_block()` — markdown fence parsing (Python-specific, generic fallback, clarification detection) |
| `src/prompt_builder.rs` | `build_pllm_system_prompt()` — 8-section prompt (role, constraints, format, tools, internal tools, builtins, multi-step, clarification); `build_error_feedback()` — retry feedback formatting |
| `src/qllm.rs` | `call_qllm()` — routes data to QLLM for structured extraction; `call_qllm_verify()` — routes hypothesis verification to QLLM |
| `src/interpreter_loop.rs` | `Session::run_interpreter_loop()` — core async loop driving synchronous interpreter through yield points |
| `src/turn.rs` | `Session::process_turn()` — PLLM retry loop with error classification; `classify_error()` — retryable vs fatal classification |
| `src/lib.rs` | Module declarations + public re-exports |
| `src/tests.rs` | 65 comprehensive tests with mock infrastructure |

### Key design decisions

- **Async/sync bridge**: The interpreter is fully synchronous with yield points. The orchestrator's async loop calls `interpreter.execute()` synchronously, then at yield points performs async work (tool execution, LLM calls), and resumes synchronously via `interpreter.resume_*()`. No `spawn_blocking` needed.
- **Borrow management**: `Session` owns both `interpreter` (needs `&mut`) and `config` (needs `&`). Solved by reading config values into locals before the mutable borrow of interpreter in `run_interpreter_loop()`.
- **Error classification**: `classify_error()` categorizes errors as `VmException` (retryable — PLLM coding mistakes), `PolicyViolation` (retryable — forbidden actions), or `Fatal` (not retryable — LLM failures, serde errors, etc.). Retryable errors extract a message string for PLLM feedback; fatal errors preserve the original error.
- **`tokio` as dev-dependency only**: The orchestrator doesn't spawn its own runtime or tasks. It's purely async via trait object calls. Only tests need tokio's async runtime.
- **`LlmClient` and `ToolExecutor` traits**: Abstract over concrete implementations. The server layer (Phase 7) will provide the actual LLM client (OpenAI/OpenRouter) and tool executor.
- **QLLM security invariant**: The QLLM receives only a system prompt, user data, and output schema — no tool-calling capability. This is enforced by the `chat_completion_with_schema` API shape.

### Session lifecycle

1. `Session::new(policy, config, interp_config, tools)` — creates session with interpreter
2. `session.process_turn(user_msg, llm_client, tool_executor)` — processes one turn:
   - Check turn limit → increment → clear meta per config → add user message
   - Build PLLM system prompt → PLLM retry loop:
     - Call PLLM → extract code → run interpreter loop
     - On success: return `TurnResult { status: Success, value, tool_calls, print_output }`
     - On retryable error: build error feedback → retry
     - On clarification: return `TurnResult { status: ClarificationNeeded }`
     - On all attempts exhausted: return `TurnResult { status: MaxAttemptsExceeded }`
3. `session.reset()` — clears turn count, message history, session metadata

### Test coverage (65 tests)

| Category | Count | What is tested |
|----------|-------|---------------|
| Code extraction | 12 | Python/py/generic fences, multiple blocks (first taken), no fence → None, empty block, clarification detection/disabled, trailing whitespace, mixed content, missing closing fence, backticks inside code |
| Prompt builder | 8 | Role preamble, tool signatures, internal tools (enabled/disabled), clarification section (enabled/disabled), multi-step section, error feedback (minimal level) |
| Error feedback | 3 | Normal level (includes first error line), Extra level (full details in code block), policy violation (mentions security policy) |
| QLLM | 6 | Basic extraction, insufficient info, schema forwarding, verify true/false, missing result field defaults to false |
| Session | 6 | UUID creation, turn zero start, turn limit enforced, reset clears state, message history grows, config accessible |
| Interpreter loop | 10 | Simple expression, single/multiple tool calls, parse_with_ai routing, verify_hypothesis routing, tool/QLLM error propagation, mixed tool+QLLM, policy deny as interpreter error, internal tool disabled |
| Turn processing | 12 | Simple success, success with tool call, retry on VM error, retry on no code block, max attempts exceeded, clarification requested, clear meta every turn/attempt, prune/no-prune failed steps, message history updated, fatal error not retried |
| Integration | 8 | Full turn with policy enforcement, multi-turn session, parse_with_ai/verify_hypothesis end-to-end, policy deny with retry, session meta cleared per config, turn result includes tool calls, turn result includes print output |

### Security invariants verified

- SQRT policy evaluation occurs before any tool call is yielded to the external executor
- The QLLM has no tool-calling capability (enforced by API shape)
- Internal tools (parse_with_ai, verify_hypothesis) can be disabled per session config
- Session metadata clearing follows the configured schedule (Never/EveryAttempt/EveryTurn)
- Fatal errors (LLM failures, serde errors) are not retried
- Turn limits are enforced before incrementing the turn count

---

## Phase 7: `security-compass-server` 🔲

**Branch:** TBD
**Depends on:** `security-compass-orchestrator`

### Planned scope

- HTTP API (axum): `POST /control/{provider}/v1/chat/completions`
- Header parsing: X-Security-Features, X-Security-Policy, X-Security-Config, X-Session-Id
- Session store (in-memory with DashMap)
- OpenAI-compatible request/response format
