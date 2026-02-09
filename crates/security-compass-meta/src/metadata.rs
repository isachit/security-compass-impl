use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::consumer_set::ConsumerSet;
use crate::constants::{LLM_BLOCKED_TAG, NON_EXECUTABLE_TAG, PARSE_WITH_AI_TAG};

/// The three-field metadata attached to every interpreter variable.
///
/// Propagation rules when combining data (e.g., `c = a + b`):
/// - **producers**: Union — `c.producers = a.producers ∪ b.producers`
/// - **consumers**: Intersection — `c.consumers = a.consumers ∩ b.consumers`
/// - **tags**: Union — `c.tags = a.tags ∪ b.tags`
///
/// The intersection rule for consumers is the core security property:
/// combining data from two sources restricts the result to only consumers
/// authorized by **both** sources. This makes consumer restriction monotonic —
/// it can only get tighter, never looser.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    /// Tracks where this data originated. Union propagation.
    pub producers: BTreeSet<String>,
    /// Restricts who can receive this data. Intersection propagation.
    pub consumers: ConsumerSet,
    /// Arbitrary classification labels. Union propagation.
    pub tags: BTreeSet<String>,
}

impl Metadata {
    /// Create metadata with no provenance, universal consumers, no tags.
    /// This is the default for user-provided input variables.
    pub fn default_for_user_input() -> Self {
        Metadata {
            producers: BTreeSet::new(),
            consumers: ConsumerSet::Universal,
            tags: BTreeSet::new(),
        }
    }

    /// Create default metadata for a tool result.
    /// Adds the tool name as a producer.
    /// If `non_executable` is true, also adds the `__non_executable` tag.
    pub fn default_for_tool_result(tool_name: &str, non_executable: bool) -> Self {
        let mut tags = BTreeSet::new();
        if non_executable {
            tags.insert(NON_EXECUTABLE_TAG.to_string());
        }
        Metadata {
            producers: BTreeSet::from([tool_name.to_string()]),
            consumers: ConsumerSet::Universal,
            tags,
        }
    }

    /// Create default metadata for a `parse_with_ai` (QLLM) result.
    /// Inherits the input metadata and adds the parse_with_ai tag.
    /// If `non_executable` is true, also adds the `__non_executable` tag.
    pub fn for_parse_with_ai_result(input_meta: &Metadata, non_executable: bool) -> Self {
        let mut meta = input_meta.clone();
        meta.tags.insert(PARSE_WITH_AI_TAG.to_string());
        if non_executable {
            meta.tags.insert(NON_EXECUTABLE_TAG.to_string());
        }
        meta
    }

    /// Merge two metadata values.
    ///
    /// This is the fundamental propagation operation, used when two values
    /// are combined by a binary operation (e.g., `c = a + b`), string
    /// concatenation, or any expression that depends on multiple inputs.
    ///
    /// - producers: union
    /// - consumers: intersection
    /// - tags: union
    pub fn merge(&self, other: &Metadata) -> Metadata {
        Metadata {
            producers: self.producers.union(&other.producers).cloned().collect(),
            consumers: self.consumers.intersect(&other.consumers),
            tags: self.tags.union(&other.tags).cloned().collect(),
        }
    }

    /// Merge N metadata values.
    ///
    /// Used when a function call has multiple arguments, or when building
    /// a collection from multiple elements.
    /// Returns default user-input metadata if the iterator is empty.
    pub fn merge_all<'a>(metas: impl IntoIterator<Item = &'a Metadata>) -> Metadata {
        let mut iter = metas.into_iter();
        let Some(first) = iter.next() else {
            return Metadata::default_for_user_input();
        };
        let mut result = first.clone();
        for m in iter {
            result = result.merge(m);
        }
        result
    }

    /// Returns `true` if this metadata carries the `__non_executable` tag.
    pub fn is_non_executable(&self) -> bool {
        self.tags.contains(NON_EXECUTABLE_TAG)
    }

    /// Returns `true` if this metadata carries the `__llm_blocked` tag.
    pub fn is_llm_blocked(&self) -> bool {
        self.tags.contains(LLM_BLOCKED_TAG)
    }

    /// Returns `true` if this metadata carries the `__tool/parse_with_ai` tag.
    pub fn is_parse_with_ai(&self) -> bool {
        self.tags.contains(PARSE_WITH_AI_TAG)
    }

    /// Returns `true` if producers, consumers, and tags are all empty/default.
    pub fn is_clean(&self) -> bool {
        self.producers.is_empty() && self.consumers.is_universal() && self.tags.is_empty()
    }

    /// Add a producer.
    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producers.insert(producer.into());
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.insert(tag.into());
        self
    }

    /// Set consumers to a finite set.
    pub fn with_consumers(mut self, consumers: ConsumerSet) -> Self {
        self.consumers = consumers;
        self
    }

    /// Apply an augmented union assignment to tags: `@tags |= new_tags`.
    pub fn tags_union_assign(&mut self, new_tags: &BTreeSet<String>) {
        self.tags = self.tags.union(new_tags).cloned().collect();
    }

    /// Apply an augmented intersection assignment to tags: `@tags &= new_tags`.
    pub fn tags_intersect_assign(&mut self, new_tags: &BTreeSet<String>) {
        self.tags = self.tags.intersection(new_tags).cloned().collect();
    }

    /// Apply an augmented difference assignment to tags: `@tags -= new_tags`.
    pub fn tags_difference_assign(&mut self, new_tags: &BTreeSet<String>) {
        self.tags = self.tags.difference(new_tags).cloned().collect();
    }

    /// Apply an augmented union assignment to producers: `@producers |= new_producers`.
    pub fn producers_union_assign(&mut self, new_producers: &BTreeSet<String>) {
        self.producers = self.producers.union(new_producers).cloned().collect();
    }

    /// Apply an augmented intersection assignment to consumers: `@consumers &= new_consumers`.
    pub fn consumers_intersect_assign(&mut self, new_consumers: &ConsumerSet) {
        self.consumers = self.consumers.intersect(new_consumers);
    }

    /// Apply an augmented union assignment to consumers: `@consumers |= new_consumers`.
    pub fn consumers_union_assign(&mut self, new_consumers: &ConsumerSet) {
        self.consumers = self.consumers.union(new_consumers);
    }

    /// Apply an augmented difference assignment to consumers: `@consumers -= new_consumers`.
    pub fn consumers_difference_assign(&mut self, new_consumers: &ConsumerSet) {
        self.consumers = self.consumers.difference(new_consumers);
    }
}

impl Default for Metadata {
    /// Default metadata is equivalent to `default_for_user_input`:
    /// no producers, universal consumers, no tags.
    fn default() -> Self {
        Self::default_for_user_input()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn producers(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn finite_consumers(items: &[&str]) -> ConsumerSet {
        ConsumerSet::Finite(items.iter().map(|s| s.to_string()).collect())
    }

    fn meta(p: &[&str], c: ConsumerSet, t: &[&str]) -> Metadata {
        Metadata {
            producers: producers(p),
            consumers: c,
            tags: tags(t),
        }
    }

    // ---- default constructors ----

    #[test]
    fn test_default_for_user_input() {
        let m = Metadata::default_for_user_input();
        assert!(m.producers.is_empty());
        assert_eq!(m.consumers, ConsumerSet::Universal);
        assert!(m.tags.is_empty());
    }

    #[test]
    fn test_default_is_same_as_user_input() {
        assert_eq!(Metadata::default(), Metadata::default_for_user_input());
    }

    #[test]
    fn test_default_for_tool_result() {
        let m = Metadata::default_for_tool_result("get_email", true);
        assert_eq!(m.producers, producers(&["get_email"]));
        assert_eq!(m.consumers, ConsumerSet::Universal);
        assert!(m.tags.contains(NON_EXECUTABLE_TAG));
    }

    #[test]
    fn test_default_for_tool_result_no_non_exec() {
        let m = Metadata::default_for_tool_result("get_email", false);
        assert!(!m.tags.contains(NON_EXECUTABLE_TAG));
    }

    #[test]
    fn test_for_parse_with_ai_result() {
        let input_meta = meta(&["search_tool"], ConsumerSet::Universal, &["external"]);
        let m = Metadata::for_parse_with_ai_result(&input_meta, true);
        assert_eq!(m.producers, producers(&["search_tool"]));
        assert!(m.tags.contains(PARSE_WITH_AI_TAG));
        assert!(m.tags.contains(NON_EXECUTABLE_TAG));
        assert!(m.tags.contains("external"));
    }

    // ---- merge ----

    #[test]
    fn test_merge_producers_are_unioned() {
        let a = meta(&["tool_a"], ConsumerSet::Universal, &[]);
        let b = meta(&["tool_b"], ConsumerSet::Universal, &[]);
        let merged = a.merge(&b);
        assert_eq!(merged.producers, producers(&["tool_a", "tool_b"]));
    }

    #[test]
    fn test_merge_consumers_are_intersected() {
        let a = meta(&[], finite_consumers(&["alice", "bob"]), &[]);
        let b = meta(&[], finite_consumers(&["bob", "carol"]), &[]);
        let merged = a.merge(&b);
        assert_eq!(merged.consumers, finite_consumers(&["bob"]));
    }

    #[test]
    fn test_merge_tags_are_unioned() {
        let a = meta(&[], ConsumerSet::Universal, &["confidential"]);
        let b = meta(&[], ConsumerSet::Universal, &["internal"]);
        let merged = a.merge(&b);
        assert_eq!(merged.tags, tags(&["confidential", "internal"]));
    }

    #[test]
    fn test_merge_all_fields() {
        let a = Metadata {
            producers: producers(&["db"]),
            consumers: finite_consumers(&["admin", "user"]),
            tags: tags(&["pii"]),
        };
        let b = Metadata {
            producers: producers(&["api"]),
            consumers: finite_consumers(&["user", "auditor"]),
            tags: tags(&["external"]),
        };
        let merged = a.merge(&b);
        assert_eq!(merged.producers, producers(&["api", "db"]));
        assert_eq!(merged.consumers, finite_consumers(&["user"]));
        assert_eq!(merged.tags, tags(&["external", "pii"]));
    }

    #[test]
    fn test_merge_with_universal_consumers() {
        let a = meta(&[], ConsumerSet::Universal, &[]);
        let b = meta(&[], finite_consumers(&["alice"]), &[]);
        let merged = a.merge(&b);
        assert_eq!(merged.consumers, finite_consumers(&["alice"]));
    }

    #[test]
    fn test_merge_identity() {
        let a = meta(&["x"], finite_consumers(&["a"]), &["t"]);
        let merged = a.merge(&Metadata::default());
        assert_eq!(merged.producers, producers(&["x"]));
        assert_eq!(merged.consumers, finite_consumers(&["a"]));
        assert_eq!(merged.tags, tags(&["t"]));
    }

    // ---- merge_all ----

    #[test]
    fn test_merge_all_empty() {
        let result = Metadata::merge_all(std::iter::empty());
        assert_eq!(result, Metadata::default());
    }

    #[test]
    fn test_merge_all_single() {
        let m = meta(&["x"], finite_consumers(&["a"]), &["t"]);
        let result = Metadata::merge_all([&m]);
        assert_eq!(result, m);
    }

    #[test]
    fn test_merge_all_multiple() {
        let a = meta(&["tool_a"], finite_consumers(&["alice", "bob"]), &["tag_a"]);
        let b = meta(&["tool_b"], finite_consumers(&["bob", "carol"]), &["tag_b"]);
        let c = meta(&["tool_c"], finite_consumers(&["bob"]), &["tag_c"]);
        let result = Metadata::merge_all([&a, &b, &c]);
        assert_eq!(result.producers, producers(&["tool_a", "tool_b", "tool_c"]));
        assert_eq!(result.consumers, finite_consumers(&["bob"]));
        assert_eq!(result.tags, tags(&["tag_a", "tag_b", "tag_c"]));
    }

    // ---- consumer monotonicity (critical security property) ----

    #[test]
    fn test_consumer_intersection_is_monotonically_restrictive() {
        // This test verifies the key security invariant:
        // Combining data can only restrict, never expand, the consumer set.
        let public = meta(&[], ConsumerSet::Universal, &[]);
        let restricted = meta(&[], finite_consumers(&["admin"]), &[]);

        // Merging public with restricted yields restricted
        let merged = public.merge(&restricted);
        assert_eq!(merged.consumers, finite_consumers(&["admin"]));

        // Further merging with another restricted set narrows further
        let more_restricted = meta(&[], finite_consumers(&["admin", "auditor"]), &[]);
        let merged2 = merged.merge(&more_restricted);
        assert_eq!(merged2.consumers, finite_consumers(&["admin"]));

        // Merging two disjoint restricted sets yields empty (no one can read)
        let disjoint = meta(&[], finite_consumers(&["nobody"]), &[]);
        let merged3 = merged2.merge(&disjoint);
        assert!(merged3.consumers.is_empty());
    }

    // ---- special tag checks ----

    #[test]
    fn test_is_non_executable() {
        let m = meta(&[], ConsumerSet::Universal, &[NON_EXECUTABLE_TAG]);
        assert!(m.is_non_executable());
        assert!(!Metadata::default().is_non_executable());
    }

    #[test]
    fn test_is_llm_blocked() {
        let m = meta(&[], ConsumerSet::Universal, &[LLM_BLOCKED_TAG]);
        assert!(m.is_llm_blocked());
        assert!(!Metadata::default().is_llm_blocked());
    }

    #[test]
    fn test_is_parse_with_ai() {
        let m = meta(&[], ConsumerSet::Universal, &[PARSE_WITH_AI_TAG]);
        assert!(m.is_parse_with_ai());
        assert!(!Metadata::default().is_parse_with_ai());
    }

    #[test]
    fn test_is_clean() {
        assert!(Metadata::default().is_clean());
        assert!(!meta(&["x"], ConsumerSet::Universal, &[]).is_clean());
        assert!(!meta(&[], finite_consumers(&["a"]), &[]).is_clean());
        assert!(!meta(&[], ConsumerSet::Universal, &["t"]).is_clean());
    }

    // ---- builder methods ----

    #[test]
    fn test_with_producer() {
        let m = Metadata::default().with_producer("db");
        assert_eq!(m.producers, producers(&["db"]));
    }

    #[test]
    fn test_with_tag() {
        let m = Metadata::default().with_tag("confidential");
        assert_eq!(m.tags, tags(&["confidential"]));
    }

    #[test]
    fn test_with_consumers() {
        let m = Metadata::default().with_consumers(finite_consumers(&["alice"]));
        assert_eq!(m.consumers, finite_consumers(&["alice"]));
    }

    #[test]
    fn test_chained_builders() {
        let m = Metadata::default()
            .with_producer("api")
            .with_producer("db")
            .with_tag("internal")
            .with_consumers(finite_consumers(&["admin"]));
        assert_eq!(m.producers, producers(&["api", "db"]));
        assert_eq!(m.tags, tags(&["internal"]));
        assert_eq!(m.consumers, finite_consumers(&["admin"]));
    }

    // ---- augmented assignments ----

    #[test]
    fn test_tags_union_assign() {
        let mut m = meta(&[], ConsumerSet::Universal, &["existing"]);
        m.tags_union_assign(&tags(&["new", "existing"]));
        assert_eq!(m.tags, tags(&["existing", "new"]));
    }

    #[test]
    fn test_tags_intersect_assign() {
        let mut m = meta(&[], ConsumerSet::Universal, &["a", "b", "c"]);
        m.tags_intersect_assign(&tags(&["b", "c", "d"]));
        assert_eq!(m.tags, tags(&["b", "c"]));
    }

    #[test]
    fn test_tags_difference_assign() {
        let mut m = meta(&[], ConsumerSet::Universal, &["a", "b", "c"]);
        m.tags_difference_assign(&tags(&["b"]));
        assert_eq!(m.tags, tags(&["a", "c"]));
    }

    #[test]
    fn test_producers_union_assign() {
        let mut m = meta(&["a"], ConsumerSet::Universal, &[]);
        m.producers_union_assign(&producers(&["b", "c"]));
        assert_eq!(m.producers, producers(&["a", "b", "c"]));
    }

    #[test]
    fn test_consumers_intersect_assign() {
        let mut m = meta(&[], finite_consumers(&["a", "b"]), &[]);
        m.consumers_intersect_assign(&finite_consumers(&["b", "c"]));
        assert_eq!(m.consumers, finite_consumers(&["b"]));
    }

    #[test]
    fn test_consumers_union_assign() {
        let mut m = meta(&[], finite_consumers(&["a"]), &[]);
        m.consumers_union_assign(&finite_consumers(&["b"]));
        assert_eq!(m.consumers, finite_consumers(&["a", "b"]));
    }

    #[test]
    fn test_consumers_difference_assign() {
        let mut m = meta(&[], finite_consumers(&["a", "b", "c"]), &[]);
        m.consumers_difference_assign(&finite_consumers(&["b"]));
        assert_eq!(m.consumers, finite_consumers(&["a", "c"]));
    }

    // ---- serialization ----

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let m = Metadata {
            producers: producers(&["tool_a", "tool_b"]),
            consumers: finite_consumers(&["admin"]),
            tags: tags(&["confidential", "pii"]),
        };
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: Metadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m, deserialized);
    }

    #[test]
    fn test_serialize_universal_consumers() {
        let m = Metadata::default();
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: Metadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m, deserialized);
    }
}
