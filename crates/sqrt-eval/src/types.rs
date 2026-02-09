//! Compiled types for the SQRT policy evaluation engine.

use std::collections::{BTreeSet, HashMap};

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};

use security_compass_meta::{ConsumerSet, Metadata, ValueWithMeta};
use sqrt_parser::{CheckRule, Enforcement, MetaFieldKind, MetaUpdateOp, MetadataStmt, Predicate, SetExpr, TypeDomain};

// ============================================================
// Compiled Policy
// ============================================================

/// A compiled SQRT policy, ready for fast evaluation.
///
/// Tool policies are indexed by exact name (O(1) lookup) and by
/// pre-compiled regex patterns (linear scan).
pub struct CompiledPolicy {
    /// Let-declared variables, resolved by name.
    pub variables: HashMap<String, ResolvedLetValue>,

    /// Tool policies indexed by exact tool name.
    pub exact_policies: HashMap<String, Vec<CompiledToolPolicy>>,

    /// Regex-matched tool policies, checked in declaration order.
    pub regex_policies: Vec<(Regex, CompiledToolPolicy)>,

    /// Internal policy preset configuration.
    pub preset: InternalPolicyPreset,
}

/// Resolved value of a `let` declaration.
#[derive(Debug, Clone)]
pub enum ResolvedLetValue {
    /// A set expression — may be pre-computed (Static) or deferred (Dynamic).
    Set(SetExprResolved),
    /// A predicate — always evaluated at runtime against context.
    Predicate(Predicate),
    /// A type domain constraint.
    TypeDomain(TypeDomain),
}

/// A resolved set expression.
#[derive(Debug, Clone)]
pub enum SetExprResolved {
    /// Fully resolved at compile time (no runtime operands).
    Static(BTreeSet<String>),
    /// Contains runtime operands; stored as AST for lazy evaluation.
    Dynamic(SetExpr),
}

/// A compiled tool policy, ready for evaluation.
#[derive(Debug, Clone)]
pub struct CompiledToolPolicy {
    /// Priority for rule ordering (higher = evaluated first).
    pub priority: i32,
    /// Check rules (must/should allow/deny conditions).
    pub checks: Vec<CheckRule>,
    /// Metadata update statements for the result block.
    pub result_stmts: Vec<MetadataStmt>,
    /// Metadata update statements for the session-before block.
    pub session_before_stmts: Vec<MetadataStmt>,
    /// Metadata update statements for the session-after block.
    pub session_after_stmts: Vec<MetadataStmt>,
}

// ============================================================
// Preset Configuration
// ============================================================

/// Internal policy preset, matching the Python `InternalPolicyPreset`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalPolicyPreset {
    /// Whether to allow tool calls by default when no rule matches.
    pub default_allow: bool,
    /// Enforcement level for the default allow/deny decision.
    pub default_allow_enforcement: Enforcement,
    /// Whether to inject `__non_executable` tag on tool results.
    pub enable_non_executable_memory: bool,
    /// Whether to hard deny when `__llm_blocked` tag is in parse_with_ai args.
    pub enable_llm_blocked_tag: bool,
    /// Branching (control flow) meta-policy configuration.
    pub branching_meta_policy: BranchingMetaPolicy,
}

impl Default for InternalPolicyPreset {
    fn default() -> Self {
        Self {
            default_allow: true,
            default_allow_enforcement: Enforcement::Should,
            enable_non_executable_memory: true,
            enable_llm_blocked_tag: true,
            branching_meta_policy: BranchingMetaPolicy::default(),
        }
    }
}

/// Branching meta-policy: controls which metadata is allowed/denied in
/// control flow conditions (e.g., if/else branching in the interpreter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchingMetaPolicy {
    /// Mode: Allow (whitelist) or Deny (blacklist).
    pub mode: BranchingMode,
    /// Producer identifiers for the policy.
    pub producers: BTreeSet<String>,
    /// Tag identifiers for the policy.
    pub tags: BTreeSet<String>,
    /// Consumer identifiers for the policy.
    pub consumers: BTreeSet<String>,
}

impl Default for BranchingMetaPolicy {
    fn default() -> Self {
        Self {
            mode: BranchingMode::Deny,
            producers: BTreeSet::new(),
            tags: BTreeSet::new(),
            consumers: BTreeSet::new(),
        }
    }
}

/// Branching mode: whitelist or blacklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BranchingMode {
    /// Whitelist: only allow branching on metadata that is a subset of the allowed sets.
    Allow,
    /// Blacklist: deny branching on metadata that overlaps with the denied sets.
    Deny,
}

// ============================================================
// Evaluation Types
// ============================================================

/// The runtime context for evaluating a tool call against policies.
pub struct ToolCallContext<'a> {
    /// The name of the tool being called.
    pub tool_name: &'a str,
    /// The arguments passed to the tool, each with metadata.
    pub args: &'a IndexMap<String, ValueWithMeta<serde_json::Value>>,
    /// Result metadata (only available in session-after blocks).
    pub result_meta: Option<&'a Metadata>,
    /// Session-level metadata (persists across tool calls).
    pub session_meta: &'a Metadata,
}

/// A concrete metadata update with pre-evaluated values.
#[derive(Debug, Clone)]
pub struct ResolvedUpdate {
    /// Which metadata field to update.
    pub field: MetaFieldKind,
    /// The operation to perform.
    pub op: MetaUpdateOp,
    /// The concrete string set value (for tags/producers).
    pub string_set: BTreeSet<String>,
    /// The concrete consumer set value (for consumers).
    pub consumer_set: ConsumerSet,
}

/// The result of policy evaluation for a tool call.
#[derive(Debug)]
pub enum PolicyDecision {
    /// The tool call is allowed, with associated metadata updates.
    Allow {
        result_updates: Vec<ResolvedUpdate>,
        session_before_updates: Vec<ResolvedUpdate>,
        session_after_updates: Vec<ResolvedUpdate>,
    },
    /// The tool call is denied.
    Deny {
        reason: String,
        enforcement: Enforcement,
        rule_description: Option<String>,
    },
}
