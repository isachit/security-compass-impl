//! Internal evaluation context for the SQRT policy engine.
//!
//! Provides the `EvalContext` wrapper and `FieldValue` enum that bridge
//! the public `ToolCallContext` with the internal evaluation functions.

use std::collections::BTreeSet;

use security_compass_meta::{ConsumerSet, Metadata, ValueWithMeta};
use sqrt_parser::{AggregationOp, MetaFieldKind, SetOperand};

use crate::error::EvalError;
use crate::types::{ResolvedLetValue, ToolCallContext};

use std::collections::HashMap;

/// A resolved field value — either a string set (tags/producers) or a consumer set.
///
/// This abstraction is necessary because tags and producers are `BTreeSet<String>`
/// while consumers are `ConsumerSet` (which has a `Universal` variant). The evaluator
/// must handle both uniformly in set operations.
#[derive(Debug, Clone)]
pub(crate) enum FieldValue {
    /// A plain string set (used for tags, producers).
    StringSet(BTreeSet<String>),
    /// A consumer set (has Universal variant).
    Consumers(ConsumerSet),
}

impl FieldValue {
    /// Returns true if the field value represents an empty set.
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            FieldValue::StringSet(s) => s.is_empty(),
            FieldValue::Consumers(c) => c.is_empty(),
        }
    }

    /// Returns true if the field value represents a universal set.
    /// Only meaningful for ConsumerSet; string sets are never universal.
    pub(crate) fn is_universal(&self) -> bool {
        match self {
            FieldValue::StringSet(_) => false,
            FieldValue::Consumers(c) => c.is_universal(),
        }
    }

    /// Compute the union of two field values.
    pub(crate) fn union(&self, other: &FieldValue) -> FieldValue {
        match (self, other) {
            (FieldValue::StringSet(a), FieldValue::StringSet(b)) => {
                FieldValue::StringSet(a.union(b).cloned().collect())
            }
            (FieldValue::Consumers(a), FieldValue::Consumers(b)) => {
                FieldValue::Consumers(a.union(b))
            }
            // Cross-type: promote string set to finite consumer set
            (FieldValue::StringSet(a), FieldValue::Consumers(b)) => {
                let a_cs = ConsumerSet::Finite(a.clone());
                FieldValue::Consumers(a_cs.union(b))
            }
            (FieldValue::Consumers(a), FieldValue::StringSet(b)) => {
                let b_cs = ConsumerSet::Finite(b.clone());
                FieldValue::Consumers(a.union(&b_cs))
            }
        }
    }

    /// Compute the intersection of two field values.
    pub(crate) fn intersect(&self, other: &FieldValue) -> FieldValue {
        match (self, other) {
            (FieldValue::StringSet(a), FieldValue::StringSet(b)) => {
                FieldValue::StringSet(a.intersection(b).cloned().collect())
            }
            (FieldValue::Consumers(a), FieldValue::Consumers(b)) => {
                FieldValue::Consumers(a.intersect(b))
            }
            (FieldValue::StringSet(a), FieldValue::Consumers(b)) => {
                let a_cs = ConsumerSet::Finite(a.clone());
                FieldValue::Consumers(a_cs.intersect(b))
            }
            (FieldValue::Consumers(a), FieldValue::StringSet(b)) => {
                let b_cs = ConsumerSet::Finite(b.clone());
                FieldValue::Consumers(a.intersect(&b_cs))
            }
        }
    }

    /// Compute the set difference (self \ other).
    pub(crate) fn minus(&self, other: &FieldValue) -> FieldValue {
        match (self, other) {
            (FieldValue::StringSet(a), FieldValue::StringSet(b)) => {
                FieldValue::StringSet(a.difference(b).cloned().collect())
            }
            (FieldValue::Consumers(a), FieldValue::Consumers(b)) => {
                FieldValue::Consumers(a.difference(b))
            }
            (FieldValue::StringSet(a), FieldValue::Consumers(b)) => {
                let a_cs = ConsumerSet::Finite(a.clone());
                FieldValue::Consumers(a_cs.difference(b))
            }
            (FieldValue::Consumers(a), FieldValue::StringSet(b)) => {
                let b_cs = ConsumerSet::Finite(b.clone());
                FieldValue::Consumers(a.difference(&b_cs))
            }
        }
    }

    /// Compute the symmetric difference (XOR) of two field values.
    pub(crate) fn xor(&self, other: &FieldValue) -> FieldValue {
        match (self, other) {
            (FieldValue::StringSet(a), FieldValue::StringSet(b)) => {
                FieldValue::StringSet(a.symmetric_difference(b).cloned().collect())
            }
            (FieldValue::Consumers(a), FieldValue::Consumers(b)) => {
                FieldValue::Consumers(a.symmetric_difference(b))
            }
            (FieldValue::StringSet(a), FieldValue::Consumers(b)) => {
                let a_cs = ConsumerSet::Finite(a.clone());
                FieldValue::Consumers(a_cs.symmetric_difference(b))
            }
            (FieldValue::Consumers(a), FieldValue::StringSet(b)) => {
                let b_cs = ConsumerSet::Finite(b.clone());
                FieldValue::Consumers(a.symmetric_difference(&b_cs))
            }
        }
    }

    /// Check if two field values overlap (share at least one element).
    pub(crate) fn overlaps(&self, other: &FieldValue) -> bool {
        match (self, other) {
            (FieldValue::StringSet(a), FieldValue::StringSet(b)) => {
                a.intersection(b).next().is_some()
            }
            (FieldValue::Consumers(a), FieldValue::Consumers(b)) => a.overlaps(b),
            (FieldValue::StringSet(a), FieldValue::Consumers(b)) => {
                let a_cs = ConsumerSet::Finite(a.clone());
                a_cs.overlaps(b)
            }
            (FieldValue::Consumers(a), FieldValue::StringSet(b)) => {
                let b_cs = ConsumerSet::Finite(b.clone());
                a.overlaps(&b_cs)
            }
        }
    }

    /// Check if self is a subset of other.
    pub(crate) fn is_subset_of(&self, other: &FieldValue) -> bool {
        match (self, other) {
            (FieldValue::StringSet(a), FieldValue::StringSet(b)) => a.is_subset(b),
            (FieldValue::Consumers(a), FieldValue::Consumers(b)) => a.is_subset_of(b),
            (FieldValue::StringSet(a), FieldValue::Consumers(b)) => {
                let a_cs = ConsumerSet::Finite(a.clone());
                a_cs.is_subset_of(b)
            }
            (FieldValue::Consumers(a), FieldValue::StringSet(b)) => {
                let b_cs = ConsumerSet::Finite(b.clone());
                a.is_subset_of(&b_cs)
            }
        }
    }

    /// Check if two field values are equal.
    pub(crate) fn set_eq(&self, other: &FieldValue) -> bool {
        match (self, other) {
            (FieldValue::StringSet(a), FieldValue::StringSet(b)) => a == b,
            (FieldValue::Consumers(a), FieldValue::Consumers(b)) => a == b,
            // Cross-type: promote and compare
            (FieldValue::StringSet(a), FieldValue::Consumers(b)) => {
                ConsumerSet::Finite(a.clone()) == *b
            }
            (FieldValue::Consumers(a), FieldValue::StringSet(b)) => {
                *a == ConsumerSet::Finite(b.clone())
            }
        }
    }

    /// Add a single string element.
    pub(crate) fn with_element(&self, elem: &str) -> FieldValue {
        match self {
            FieldValue::StringSet(s) => {
                let mut new = s.clone();
                new.insert(elem.to_string());
                FieldValue::StringSet(new)
            }
            FieldValue::Consumers(c) => {
                let singleton = ConsumerSet::Finite(BTreeSet::from([elem.to_string()]));
                FieldValue::Consumers(c.union(&singleton))
            }
        }
    }

    /// Remove a single string element.
    pub(crate) fn without_element(&self, elem: &str) -> FieldValue {
        match self {
            FieldValue::StringSet(s) => {
                let mut new = s.clone();
                new.remove(elem);
                FieldValue::StringSet(new)
            }
            FieldValue::Consumers(c) => {
                let singleton = ConsumerSet::Finite(BTreeSet::from([elem.to_string()]));
                FieldValue::Consumers(c.difference(&singleton))
            }
        }
    }

    /// Convert to a BTreeSet<String>, losing the Universal distinction.
    /// Universal consumers become an empty set (conservative fallback).
    pub(crate) fn as_string_set(&self) -> &BTreeSet<String> {
        static EMPTY: std::sync::LazyLock<BTreeSet<String>> =
            std::sync::LazyLock::new(BTreeSet::new);
        match self {
            FieldValue::StringSet(s) => s,
            FieldValue::Consumers(ConsumerSet::Finite(s)) => s,
            FieldValue::Consumers(ConsumerSet::Universal) => &EMPTY,
        }
    }

    /// Convert to a ConsumerSet, promoting string sets to Finite.
    pub(crate) fn as_consumer_set(&self) -> ConsumerSet {
        match self {
            FieldValue::StringSet(s) => ConsumerSet::Finite(s.clone()),
            FieldValue::Consumers(c) => c.clone(),
        }
    }

    /// Extract the owned string set (for ResolvedUpdate).
    #[allow(dead_code)]
    pub(crate) fn into_string_set(self) -> BTreeSet<String> {
        match self {
            FieldValue::StringSet(s) => s,
            FieldValue::Consumers(ConsumerSet::Finite(s)) => s,
            FieldValue::Consumers(ConsumerSet::Universal) => BTreeSet::new(),
        }
    }

    /// Extract the owned consumer set (for ResolvedUpdate).
    #[allow(dead_code)]
    pub(crate) fn into_consumer_set(self) -> ConsumerSet {
        match self {
            FieldValue::StringSet(s) => ConsumerSet::Finite(s),
            FieldValue::Consumers(c) => c,
        }
    }
}

/// The internal evaluation context, wrapping the public ToolCallContext
/// together with resolved let-variables.
pub(crate) struct EvalContext<'a> {
    /// The public tool call context (tool name, args, result meta, session meta).
    pub ctx: &'a ToolCallContext<'a>,
    /// Resolved let-declared variables.
    pub variables: &'a HashMap<String, ResolvedLetValue>,
}

impl<'a> EvalContext<'a> {
    /// Get the metadata for a specific named argument.
    pub(crate) fn arg_meta(&self, arg_name: &str) -> Result<&'a Metadata, EvalError> {
        self.ctx
            .args
            .get(arg_name)
            .map(|v| &v.meta)
            .ok_or_else(|| EvalError::InvalidArgRef {
                name: arg_name.to_string(),
            })
    }

    /// Get the JSON value for a specific named argument.
    pub(crate) fn arg_value(
        &self,
        arg_name: &str,
    ) -> Result<&'a ValueWithMeta<serde_json::Value>, EvalError> {
        self.ctx
            .args
            .get(arg_name)
            .ok_or_else(|| EvalError::InvalidArgRef {
                name: arg_name.to_string(),
            })
    }

    /// Get a metadata field from a specific argument.
    pub(crate) fn arg_field(
        &self,
        arg_name: &str,
        field: &MetaFieldKind,
    ) -> Result<FieldValue, EvalError> {
        let meta = self.arg_meta(arg_name)?;
        Ok(extract_field(meta, field))
    }

    /// Get a metadata field from the result metadata.
    pub(crate) fn result_field(&self, field: &MetaFieldKind) -> Result<FieldValue, EvalError> {
        let meta = self
            .ctx
            .result_meta
            .ok_or(EvalError::ResultMetaUnavailable)?;
        Ok(extract_field(meta, field))
    }

    /// Get a metadata field from session metadata.
    pub(crate) fn session_field(&self, field: &MetaFieldKind) -> FieldValue {
        extract_field(self.ctx.session_meta, field)
    }

    /// Aggregate a metadata field across all arguments.
    ///
    /// `Union` → union of the field across all args.
    /// `Intersect` → intersection of the field across all args.
    pub(crate) fn aggregate_args_field(
        &self,
        field: &MetaFieldKind,
        op: &AggregationOp,
    ) -> FieldValue {
        let mut iter = self.ctx.args.values().map(|v| extract_field(&v.meta, field));

        let Some(first) = iter.next() else {
            // No arguments: return the identity element for the operation.
            // Union identity is the empty set; Intersect identity is the universal set.
            return match (op, field) {
                (AggregationOp::Intersect, MetaFieldKind::Consumers) => {
                    FieldValue::Consumers(ConsumerSet::Universal)
                }
                _ => FieldValue::StringSet(BTreeSet::new()),
            };
        };

        iter.fold(first, |acc, val| match op {
            AggregationOp::Union => acc.union(&val),
            AggregationOp::Intersect => acc.intersect(&val),
        })
    }

    /// Resolve a SetOperand to a FieldValue.
    pub(crate) fn resolve_operand(&self, operand: &SetOperand) -> Result<FieldValue, EvalError> {
        match operand {
            SetOperand::ArgField { arg_name, field } => self.arg_field(arg_name, field),
            SetOperand::ResultField(field) => self.result_field(field),
            SetOperand::SessionField(field) => Ok(self.session_field(field)),
            SetOperand::ContextField(_field) => {
                // ContextField is resolved at compile time to either Result or Session
                // based on the block context. At eval time, we treat it as session.
                // (This should be resolved during compilation, but we handle it gracefully.)
                Err(EvalError::TypeMismatch {
                    message: "ContextField should be resolved during compilation".to_string(),
                })
            }
            SetOperand::ArgsField { field, agg } | SetOperand::Aggregation { op: agg, field } => {
                Ok(self.aggregate_args_field(field, agg))
            }
        }
    }
}

/// Extract a specific metadata field as a FieldValue.
fn extract_field(meta: &Metadata, field: &MetaFieldKind) -> FieldValue {
    match field {
        MetaFieldKind::Tags => FieldValue::StringSet(meta.tags.clone()),
        MetaFieldKind::Producers => FieldValue::StringSet(meta.producers.clone()),
        MetaFieldKind::Consumers => FieldValue::Consumers(meta.consumers.clone()),
    }
}
