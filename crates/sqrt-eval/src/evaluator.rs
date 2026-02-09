//! Main policy evaluator for the SQRT policy engine.
//!
//! Provides the `evaluate()` function that takes a compiled policy and a tool call
//! context, evaluates all matching rules, and returns a `PolicyDecision` (Allow/Deny).
//! Also provides `check_branch()` for branching meta-policy enforcement.

use security_compass_meta::Metadata;
use sqrt_parser::{Condition, Enforcement, Outcome};

use crate::context::EvalContext;
use crate::error::{BranchingDenied, EvalError};
use crate::metadata_update::resolve_metadata_stmts;
use crate::predicate_eval::eval_predicate;
use crate::types::{
    BranchingMode, CompiledPolicy, CompiledToolPolicy, PolicyDecision, ResolvedUpdate,
    ToolCallContext,
};

/// The three lists of metadata updates: (result, session_before, session_after).
type UpdateTriple = (Vec<ResolvedUpdate>, Vec<ResolvedUpdate>, Vec<ResolvedUpdate>);

/// Evaluate a tool call against a compiled policy.
///
/// # Algorithm
///
/// 1. Collect all matching policies: exact name lookup + regex scan
/// 2. Sort by priority (descending, stable for equal priorities)
/// 3. For each policy, evaluate check rules:
///    - `must deny`  → immediate return Deny (cannot be overridden)
///    - `must allow`  → immediate return Allow (with resolved updates)
///    - `should deny` → record as soft deny (first one wins)
///    - `should allow` → record as soft allow (first one wins)
///    - If `fail_fast` and deny recorded → return immediately
/// 4. If no hard decision: use soft decision or fall back to preset defaults
/// 5. For Allow: resolve all metadata stmts from all matching policies
///
/// # Parameters
///
/// - `policy`: The compiled policy to evaluate against.
/// - `ctx`: The tool call context (tool name, args, session metadata, etc.).
/// - `fail_fast`: If true, return immediately on first deny decision.
pub fn evaluate(
    policy: &CompiledPolicy,
    ctx: &ToolCallContext<'_>,
    fail_fast: bool,
) -> Result<PolicyDecision, EvalError> {
    let eval_ctx = EvalContext {
        ctx,
        variables: &policy.variables,
    };

    // Step 1: Collect all matching policies
    let mut matching: Vec<&CompiledToolPolicy> = Vec::new();

    // Exact name lookup (O(1))
    if let Some(policies) = policy.exact_policies.get(ctx.tool_name) {
        matching.extend(policies.iter());
    }

    // Regex scan (linear)
    for (re, tool_policy) in &policy.regex_policies {
        if re.is_match(ctx.tool_name) {
            matching.push(tool_policy);
        }
    }

    // Step 2: Sort by priority descending (stable sort preserves declaration order for equal priority)
    matching.sort_by(|a, b| b.priority.cmp(&a.priority));

    // Step 3: Evaluate check rules
    let mut soft_deny: Option<(String, Option<String>)> = None; // (reason, rule_description)
    let mut soft_allow: bool = false;

    for tool_policy in &matching {
        for check in &tool_policy.checks {
            // Evaluate the condition
            let condition_met = match &check.condition {
                Condition::Always => true,
                Condition::When(pred) => eval_predicate(pred, &eval_ctx)?,
            };

            if !condition_met {
                continue;
            }

            match (check.enforcement, check.outcome) {
                (Enforcement::Must, Outcome::Deny) => {
                    // Hard deny — immediate return, cannot be overridden
                    let reason = check
                        .doc_comment
                        .clone()
                        .unwrap_or_else(|| "Policy must-deny rule matched".to_string());
                    return Ok(PolicyDecision::Deny {
                        reason,
                        enforcement: Enforcement::Must,
                        rule_description: check.doc_comment.clone(),
                    });
                }

                (Enforcement::Must, Outcome::Allow) => {
                    // Hard allow — immediate return with resolved updates
                    let (result_updates, session_before_updates, session_after_updates) =
                        collect_all_updates(&matching, &eval_ctx)?;
                    return Ok(PolicyDecision::Allow {
                        result_updates,
                        session_before_updates,
                        session_after_updates,
                    });
                }

                (Enforcement::Should, Outcome::Deny) => {
                    // Soft deny — record first one
                    if soft_deny.is_none() {
                        let reason = check
                            .doc_comment
                            .clone()
                            .unwrap_or_else(|| "Policy should-deny rule matched".to_string());
                        let rule_desc = check.doc_comment.clone();

                        if fail_fast {
                            return Ok(PolicyDecision::Deny {
                                reason,
                                enforcement: Enforcement::Should,
                                rule_description: rule_desc,
                            });
                        }

                        soft_deny = Some((reason, rule_desc));
                    }
                }

                (Enforcement::Should, Outcome::Allow) => {
                    // Soft allow — record first one
                    if !soft_allow {
                        soft_allow = true;
                    }
                }
            }
        }
    }

    // Step 4: Resolve decision
    // If we have a soft deny and no soft allow to override it, deny.
    // If we have a soft allow (or no deny), allow.
    // If no rules matched at all, fall back to preset defaults.

    if let Some((reason, rule_desc)) = soft_deny {
        if soft_allow {
            // Soft allow overrides soft deny (higher-priority allow already recorded)
            // Actually, since we sort by priority and iterate in order, if a soft allow
            // was found, it has equal or higher priority than the soft deny.
            let (result_updates, session_before_updates, session_after_updates) =
                collect_all_updates(&matching, &eval_ctx)?;
            Ok(PolicyDecision::Allow {
                result_updates,
                session_before_updates,
                session_after_updates,
            })
        } else {
            Ok(PolicyDecision::Deny {
                reason,
                enforcement: Enforcement::Should,
                rule_description: rule_desc,
            })
        }
    } else if soft_allow || (!matching.is_empty() && policy.preset.default_allow) {
        // Explicit soft allow, or rules matched but none denied and default is allow
        let (result_updates, session_before_updates, session_after_updates) =
            collect_all_updates(&matching, &eval_ctx)?;
        Ok(PolicyDecision::Allow {
            result_updates,
            session_before_updates,
            session_after_updates,
        })
    } else if matching.is_empty() {
        // No rules matched: use preset default
        if policy.preset.default_allow {
            Ok(PolicyDecision::Allow {
                result_updates: Vec::new(),
                session_before_updates: Vec::new(),
                session_after_updates: Vec::new(),
            })
        } else {
            Ok(PolicyDecision::Deny {
                reason: "No matching policy found; default is deny".to_string(),
                enforcement: policy.preset.default_allow_enforcement,
                rule_description: None,
            })
        }
    } else {
        // Rules matched but no explicit decision: use default
        if policy.preset.default_allow {
            let (result_updates, session_before_updates, session_after_updates) =
                collect_all_updates(&matching, &eval_ctx)?;
            Ok(PolicyDecision::Allow {
                result_updates,
                session_before_updates,
                session_after_updates,
            })
        } else {
            Ok(PolicyDecision::Deny {
                reason: "No explicit allow decision; default is deny".to_string(),
                enforcement: policy.preset.default_allow_enforcement,
                rule_description: None,
            })
        }
    }
}

/// Collect all metadata updates from all matching policies.
///
/// Returns (result_updates, session_before_updates, session_after_updates).
fn collect_all_updates(
    matching: &[&CompiledToolPolicy],
    ctx: &EvalContext<'_>,
) -> Result<UpdateTriple, EvalError> {
    let mut result_updates = Vec::new();
    let mut session_before_updates = Vec::new();
    let mut session_after_updates = Vec::new();

    for policy in matching {
        result_updates.extend(resolve_metadata_stmts(&policy.result_stmts, ctx)?);
        session_before_updates.extend(resolve_metadata_stmts(&policy.session_before_stmts, ctx)?);
        session_after_updates.extend(resolve_metadata_stmts(&policy.session_after_stmts, ctx)?);
    }

    Ok((result_updates, session_before_updates, session_after_updates))
}

/// Check if a branching condition's metadata is allowed by the branching meta-policy.
///
/// Called before evaluating an if/else condition in the interpreter to enforce
/// the branching meta-policy. This prevents prompt injection attacks from
/// influencing control flow through metadata manipulation.
///
/// # Deny mode (blacklist)
/// Blocks branching if the condition metadata overlaps with the denied sets.
///
/// # Allow mode (whitelist)
/// Blocks branching if the condition metadata is NOT a subset of the allowed sets.
pub fn check_branch(
    policy: &CompiledPolicy,
    condition_meta: &Metadata,
) -> Result<(), BranchingDenied> {
    let bp = &policy.preset.branching_meta_policy;

    match bp.mode {
        BranchingMode::Deny => {
            // Check producers overlap
            let producer_overlap: Vec<String> = condition_meta
                .producers
                .intersection(&bp.producers)
                .cloned()
                .collect();
            if !producer_overlap.is_empty() {
                return Err(BranchingDenied {
                    reason: "Condition metadata has denied producers".to_string(),
                    field: "producers".to_string(),
                    offending_values: producer_overlap,
                });
            }

            // Check tags overlap
            let tag_overlap: Vec<String> = condition_meta
                .tags
                .intersection(&bp.tags)
                .cloned()
                .collect();
            if !tag_overlap.is_empty() {
                return Err(BranchingDenied {
                    reason: "Condition metadata has denied tags".to_string(),
                    field: "tags".to_string(),
                    offending_values: tag_overlap,
                });
            }

            // Check consumers overlap
            let consumer_overlap = check_consumer_overlap(condition_meta, &bp.consumers);
            if !consumer_overlap.is_empty() {
                return Err(BranchingDenied {
                    reason: "Condition metadata has denied consumers".to_string(),
                    field: "consumers".to_string(),
                    offending_values: consumer_overlap,
                });
            }

            Ok(())
        }

        BranchingMode::Allow => {
            // Check producers are a subset
            let non_allowed_producers: Vec<String> = condition_meta
                .producers
                .difference(&bp.producers)
                .cloned()
                .collect();
            if !non_allowed_producers.is_empty() {
                return Err(BranchingDenied {
                    reason: "Condition metadata has producers not in allow list".to_string(),
                    field: "producers".to_string(),
                    offending_values: non_allowed_producers,
                });
            }

            // Check tags are a subset
            let non_allowed_tags: Vec<String> = condition_meta
                .tags
                .difference(&bp.tags)
                .cloned()
                .collect();
            if !non_allowed_tags.is_empty() {
                return Err(BranchingDenied {
                    reason: "Condition metadata has tags not in allow list".to_string(),
                    field: "tags".to_string(),
                    offending_values: non_allowed_tags,
                });
            }

            // For consumers in allow mode: the condition's consumers must be a subset of allowed.
            // This is tricky with ConsumerSet::Universal. If condition has Universal consumers
            // but the allow list is finite, that's a policy decision.
            // For now, skip consumer checks in allow mode if the allow list is empty.
            if !bp.consumers.is_empty() {
                let consumer_not_allowed =
                    check_consumer_not_subset(condition_meta, &bp.consumers);
                if !consumer_not_allowed.is_empty() {
                    return Err(BranchingDenied {
                        reason: "Condition metadata has consumers not in allow list".to_string(),
                        field: "consumers".to_string(),
                        offending_values: consumer_not_allowed,
                    });
                }
            }

            Ok(())
        }
    }
}

/// Check for consumer overlap with denied consumers (deny mode).
fn check_consumer_overlap(
    condition_meta: &Metadata,
    denied_consumers: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    match &condition_meta.consumers {
        security_compass_meta::ConsumerSet::Universal => {
            // Universal consumers overlap with everything
            if denied_consumers.is_empty() {
                Vec::new()
            } else {
                denied_consumers.iter().cloned().collect()
            }
        }
        security_compass_meta::ConsumerSet::Finite(consumers) => consumers
            .intersection(denied_consumers)
            .cloned()
            .collect(),
    }
}

/// Check for consumers not in the allow list (allow mode).
fn check_consumer_not_subset(
    condition_meta: &Metadata,
    allowed_consumers: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    match &condition_meta.consumers {
        security_compass_meta::ConsumerSet::Universal => {
            // Universal is never a subset of a finite set
            vec!["*".to_string()]
        }
        security_compass_meta::ConsumerSet::Finite(consumers) => consumers
            .difference(allowed_consumers)
            .cloned()
            .collect(),
    }
}
