# System Diagrams

Mermaid diagrams visualizing the Security Compass Engine architecture. These render natively on GitHub.

## Table of Contents

1. [Crate Dependency Graph](#1-crate-dependency-graph)
2. [Request Processing Pipeline](#2-request-processing-pipeline)
3. [Dual-LLM Interaction Pattern](#3-dual-llm-interaction-pattern)
4. [Metadata Propagation](#4-metadata-propagation)
5. [SQRT Policy Evaluation](#5-sqrt-policy-evaluation)
6. [Session Lifecycle](#6-session-lifecycle)
7. [Interpreter Yield/Resume State Machine](#7-interpreter-yieldresume-state-machine)
8. [Security Boundaries](#8-security-boundaries)

---

## 1. Crate Dependency Graph

The workspace contains 7 crates arranged in a strict layered dependency hierarchy.
`security-compass-meta` is the shared foundation used by all layers.

```mermaid
graph TD
    SERVER["security-compass-server<br/><i>HTTP API Layer</i><br/>153 tests"]
    ORCH["security-compass-orchestrator<br/><i>Dual-LLM Session Loop</i><br/>65 tests"]
    INTERP["security-compass-interpreter<br/><i>VM + Policy Enforcement</i><br/>60 tests"]
    VM["security-compass-vm<br/><i>Bytecode VM + Metadata</i><br/>36 tests"]
    EVAL["sqrt-eval<br/><i>Policy Compilation & Evaluation</i><br/>108 tests"]
    PARSER["sqrt-parser<br/><i>SQRT Language Parser</i><br/>58 tests"]
    META["security-compass-meta<br/><i>Metadata Types & Propagation</i><br/>67 tests"]

    SERVER --> ORCH
    SERVER --> EVAL
    SERVER --> PARSER
    SERVER --> META
    ORCH --> INTERP
    ORCH --> META
    INTERP --> VM
    INTERP --> EVAL
    VM --> META
    EVAL --> PARSER
    EVAL --> META

    style META fill:#e1f5fe,stroke:#0288d1,stroke-width:3px
    style SERVER fill:#fff3e0,stroke:#f57c00,stroke-width:3px
```

---

## 2. Request Processing Pipeline

The 14-step HTTP request processing flow from client request to response.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant SS as SessionStore
    participant P as PLLM
    participant I as Interpreter
    participant Q as QLLM
    participant T as ToolExecutor

    C->>S: POST /control/v1/chat/completions
    Note over S: [1] Authenticate (Authorization: Bearer)
    Note over S: [2] parse_headers() → ParsedHeaders
    Note over S: [3] Validate X-Api-Key
    Note over S: [4] Apply defaults for missing headers
    Note over S: [5] Derive QLLM model (gpt-4* → gpt-4o-mini)
    Note over S: [6] build_session_config() + build_interpreter_config()
    Note over S: [7] extract_tool_definitions() from request
    Note over S: [8] extract_messages() → user_query
    Note over S: [9] Reject streaming (stream: true → 400)

    S->>SS: [10] get_or_create(session_id)
    SS-->>S: Session (compile SQRT policy if new)

    Note over S: [11] Create OpenAiLlmClient
    Note over S: [12] Create ToolExecutor

    S->>P: [13] session.process_turn(user_query)
    P-->>S: Python code

    S->>I: Execute code with policy checks
    loop Tool calls
        I-->>S: NeedsToolCall / NeedsParseWithAi
        alt External tool
            S->>T: execute(tool_name, args)
            T-->>S: result + metadata
        else parse_with_ai
            S->>Q: chat_completion_with_schema(data, schema)
            Q-->>S: structured JSON
        end
        S->>I: Resume with result
    end
    I-->>S: Complete(value, metadata)

    Note over S: [14] build_response() → ChatCompletionResponse
    S-->>C: 200 OK + X-Session-Id header + JSON body
```

---

## 3. Dual-LLM Interaction Pattern

How the PLLM (trusted) and QLLM (quarantined) interact through the Interpreter during a single turn. The PLLM generates code; the QLLM processes untrusted data with no tool-calling capability.

```mermaid
sequenceDiagram
    participant U as User
    participant O as Orchestrator
    participant PL as PLLM<br/>(Trusted)
    participant I as Interpreter/VM
    participant QL as QLLM<br/>(Quarantined)
    participant T as Tool

    U->>O: "Get user profile and email a summary"
    O->>PL: chat_completion(messages)
    Note right of PL: Has tool schemas<br/>Never sees untrusted data
    PL-->>O: Python code block

    O->>I: execute(code, inputs, tools)

    Note over I: VM executes bytecodes<br/>Tracks metadata on every value

    I-->>O: NeedsToolCall(fetch_user_profile, args)
    O->>T: execute("fetch_user_profile", args)
    T-->>O: profile data
    O->>I: resume(result, meta={producers: {"fetch_user_profile"}, tags: {"pii"}})

    Note over I: Result metadata propagates<br/>through all subsequent operations

    I-->>O: NeedsParseWithAi(data, query, schema)
    Note over O: Check __llm_blocked tag
    O->>QL: chat_completion_with_schema(system, data, schema)
    Note right of QL: No tool definitions<br/>Structured JSON output only
    QL-->>O: {"summary": "..."}
    O->>I: resume(parsed, meta inherits input + __tool/parse_with_ai tag)

    I-->>O: NeedsToolCall(send_email, {body: summary})
    Note over I: SQRT policy evaluates:<br/>@args.producers overlaps pii_sources?

    alt Policy: Allow
        O->>T: execute("send_email", args)
        T-->>O: result
        O->>I: resume(result, meta)
    else Policy: Deny (must deny)
        Note over I: Raise RuntimeError in VM<br/>PLLM can catch in try/except
    end

    I-->>O: Complete(value, metadata)
    O-->>U: TurnResult
```

---

## 4. Metadata Propagation

Every value in the VM carries `Metadata` with three fields. Metadata propagates automatically through all bytecode operations and is checked at enforcement points.

```mermaid
flowchart TD
    subgraph Sources["Data Sources"]
        UI["User Input<br/>producers: {}<br/>consumers: Universal<br/>tags: {}"]
        TR["Tool Result<br/>producers: {tool_name}<br/>consumers: Universal<br/>tags: {__non_executable}"]
        QR["QLLM Result<br/>producers: inherited<br/>consumers: inherited<br/>tags: inherited + {__tool/parse_with_ai}"]
        LIT["Constant/Literal<br/>producers: {}<br/>consumers: Universal<br/>tags: {}"]
    end

    subgraph Operations["VM Operations"]
        BIN["Binary Op (a + b)<br/>producers: a ∪ b<br/>consumers: a ∩ b<br/>tags: a ∪ b"]
        UNA["Unary Op<br/>passthrough"]
        COL["Collection Build<br/>merge_all(elements)"]
        SL["Store/Load<br/>copy between stack ↔ namespace"]
    end

    subgraph Enforcement["Enforcement Points"]
        POL["SQRT Policy Check<br/>evaluate(tool_name, args_meta, session_meta)<br/>→ Allow with updates / Deny"]
        BRC["Branch Checker<br/>check(condition_meta)<br/>→ Ok / BranchingDenied"]
        LLM["LLM Blocked Check<br/>__llm_blocked tag?<br/>→ block QLLM routing"]
    end

    UI --> BIN
    TR --> BIN
    QR --> BIN
    LIT --> BIN
    UI --> UNA
    TR --> COL
    BIN --> SL
    UNA --> SL
    COL --> SL

    SL -->|"tool call arg"| POL
    SL -->|"if/while condition"| BRC
    SL -->|"parse_with_ai arg"| LLM

    POL -->|"Allow"| RESULT["Apply result updates<br/>Apply session_after updates"]
    POL -->|"Deny"| DENY["RuntimeError in VM"]
    BRC -->|"Denied"| BRDENY["MontyException"]
```

---

## 5. SQRT Policy Evaluation

The policy system operates in two phases: compile-time optimization and runtime evaluation.

```mermaid
flowchart TD
    subgraph Compile["Compile Phase (once per session)"]
        SRC["SQRT Source Text"]
        PARSE["sqrt_parser::parse()"]
        AST["SqrtProgram (AST)<br/>declarations: Vec&lt;Declaration&gt;"]
        COMP["sqrt_eval::compile()"]
        CP["CompiledPolicy"]

        SRC --> PARSE --> AST --> COMP --> CP

        CP --- VARS["variables:<br/>HashMap&lt;String, ResolvedLetValue&gt;"]
        CP --- EXACT["exact_policies:<br/>HashMap&lt;String, Vec&lt;Policy&gt;&gt;<br/><i>O(1) lookup</i>"]
        CP --- REGEX["regex_policies:<br/>Vec&lt;(Regex, Policy)&gt;<br/><i>linear scan</i>"]
        CP --- PRESET["preset:<br/>InternalPolicyPreset"]
    end

    subgraph Runtime["Runtime Evaluation (per tool call)"]
        CTX["ToolCallContext<br/>{tool_name, args_meta, session_meta}"]
        COLLECT["Collect matching policies<br/>exact O(1) + regex scan"]
        SORT["Sort by priority descending<br/>(stable sort)"]

        CTX --> COLLECT --> SORT

        SORT --> RULES

        subgraph RULES["Evaluate check rules in order"]
            MD["must deny when ..."] -->|"condition true"| IMM_DENY["Immediate Deny"]
            MA["must allow"] -->|"matches"| IMM_ALLOW["Immediate Allow"]
            SD["should deny when ..."] -->|"condition true"| SOFT_D["Record soft deny"]
            SA["should allow"] -->|"matches"| SOFT_A["Record soft allow"]
        end

        SOFT_D --> RESOLVE["Resolve: soft allow > soft deny<br/>else preset default"]
        SOFT_A --> RESOLVE

        IMM_ALLOW --> UPDATES["Resolve metadata updates<br/>result / session_before / session_after"]
        RESOLVE -->|"Allow"| UPDATES
        RESOLVE -->|"Deny"| FINAL_DENY["PolicyDecision::Deny<br/>{reason, enforcement}"]
        UPDATES --> FINAL_ALLOW["PolicyDecision::Allow<br/>{result_updates, session_updates}"]
    end
```

---

## 6. Session Lifecycle

Sessions are stored in a `DashMap` with TTL-based expiration and background eviction.

```mermaid
stateDiagram-v2
    [*] --> Creating: HTTP request<br/>(no session_id or unknown UUID)

    Creating --> Active: compile_policy()<br/>Session::new(policy, config, tools)

    Active --> Active: Next request arrives<br/>with valid X-Session-Id<br/>(refreshes TTL)

    Active --> Processing: process_turn()<br/>(DashMap RefMut held)

    Processing --> Active: TurnResult returned<br/>(Success / MaxAttemptsExceeded / Clarification)

    Processing --> Processing: Retryable error<br/>(VmException / PolicyViolation)<br/>PLLM retry loop

    Active --> Expired: TTL exceeded<br/>(default 1800s)

    Expired --> [*]: Background eviction task<br/>(runs every 60s)

    note right of Active
        Session state persists:
        - Interpreter (VM + policy + cache)
        - Message history
        - Turn count
        - Session metadata (tags, producers, consumers)
    end note

    note right of Processing
        Turn limit enforced:
        max_n_turns (default 5)
        Exceeded → MaxTurnsExceeded error
    end note
```

---

## 7. Interpreter Yield/Resume State Machine

The interpreter is synchronous with yield points. At each yield, it returns an `ExecutionResult` variant and suspends. The orchestrator performs async work, then resumes.

```mermaid
stateDiagram-v2
    [*] --> Executing: interpreter.execute(code, inputs, tools)

    Executing --> NeedsToolCall: External function call<br/>Policy evaluates to Allow
    Executing --> NeedsParseWithAi: parse_with_ai() internal tool<br/>__llm_blocked check passes
    Executing --> NeedsVerifyHypothesis: verify_hypothesis() internal tool
    Executing --> Complete: VM reaches end of program
    Executing --> PolicyDeny: SQRT policy denies tool call

    NeedsToolCall --> Executing: resume_after_tool_call()<br/>(result_value, result_meta)<br/>Apply session_after_updates<br/>Re-inject PolicyBranchChecker

    NeedsParseWithAi --> Executing: resume_after_parse_with_ai()<br/>(parsed_value)<br/>Inherits input meta + __tool/parse_with_ai

    NeedsVerifyHypothesis --> Executing: resume_after_verify_hypothesis()<br/>(bool verified)<br/>Boolean result with metadata

    PolicyDeny --> Executing: RuntimeError raised in VM<br/>PLLM code can catch via try/except

    Complete --> [*]: Return value + metadata + print_output

    note right of NeedsToolCall
        Carries: tool_name, args (with meta),
        call_id, VM snapshot (state),
        result_updates, session_after_updates
    end note

    note left of Executing
        On every resume:
        PolicyBranchChecker is re-injected
        (not serialized with VM snapshot)
    end note
```

---

## 8. Security Boundaries

Eight security mechanisms operate at different layers of the architecture. No single layer is solely responsible -- an attacker must defeat all layers simultaneously.

```mermaid
graph LR
    subgraph Server["Server Layer"]
        AUTH["Session Isolation<br/><i>Each UUID → independent<br/>Interpreter, metadata, cache</i>"]
    end

    subgraph Orchestrator["Orchestrator Layer"]
        DUAL["PLLM/QLLM Separation<br/><i>PLLM: chat_completion() — trusted, has tools</i><br/><i>QLLM: chat_completion_with_schema() — no tools</i>"]
    end

    subgraph Interpreter["Interpreter Layer"]
        POLICY["Policy Enforcement<br/><i>SQRT evaluated before every tool call</i><br/><i>must deny is unoverridable</i>"]
        LLMBLK["LLM Blocked Tag<br/><i>__llm_blocked prevents<br/>routing to QLLM</i>"]
    end

    subgraph VM["VM Layer"]
        META_TRACK["Metadata Tracking<br/><i>Parallel stack_meta + namespace.metadata</i><br/><i>Every bytecode op maintains lockstep</i>"]
        BRANCH["Branching Protection<br/><i>BranchChecker at JumpIfTrue/JumpIfFalse</i><br/><i>Blocks untrusted data in control flow</i>"]
    end

    subgraph Meta["Metadata Foundation"]
        CONSUMER["Consumer Monotonicity<br/><i>Intersection only restricts, never loosens</i><br/><i>Finite({}) is absorbing</i>"]
        NONEXEC["Non-Executable Memory<br/><i>__non_executable tag on tool results</i><br/><i>Propagates through all operations</i>"]
    end

    Server --> Orchestrator --> Interpreter --> VM --> Meta

    style Server fill:#e8f5e9,stroke:#2e7d32
    style Orchestrator fill:#e3f2fd,stroke:#1565c0
    style Interpreter fill:#fff3e0,stroke:#e65100
    style VM fill:#fce4ec,stroke:#c62828
    style Meta fill:#f3e5f5,stroke:#6a1b9a
```

---

## Reading Guide

| If you want to understand... | See diagram |
|------------------------------|-------------|
| How the crates fit together | [1. Crate Dependency Graph](#1-crate-dependency-graph) |
| What happens when a request arrives | [2. Request Processing Pipeline](#2-request-processing-pipeline) |
| How PLLM and QLLM cooperate safely | [3. Dual-LLM Interaction Pattern](#3-dual-llm-interaction-pattern) |
| How data provenance is tracked | [4. Metadata Propagation](#4-metadata-propagation) |
| How security policies are compiled and enforced | [5. SQRT Policy Evaluation](#5-sqrt-policy-evaluation) |
| How sessions are managed | [6. Session Lifecycle](#6-session-lifecycle) |
| How the interpreter suspends and resumes | [7. Interpreter Yield/Resume](#7-interpreter-yieldresume-state-machine) |
| Where security is enforced | [8. Security Boundaries](#8-security-boundaries) |
