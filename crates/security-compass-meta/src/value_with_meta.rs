use serde::{Deserialize, Serialize};

use crate::metadata::Metadata;

/// A value paired with its security metadata.
///
/// This is the fundamental unit of the Security Compass interpreter:
/// every variable, every intermediate result, every tool argument and
/// return value is wrapped in this type so metadata propagation is
/// enforced at every step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueWithMeta<T> {
    pub value: T,
    pub meta: Metadata,
}

/// How to combine metadata when a tool result provides explicit metadata.
/// Used by the `ValueWithMeta` protocol in tool result handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CombineMetaMode {
    /// Merge the provided metadata with the existing metadata using
    /// the standard propagation rules (producers=union, consumers=intersect, tags=union).
    Merge,
    /// Replace the existing metadata entirely with the provided metadata.
    Replace,
    /// Ignore the provided metadata and keep the existing metadata.
    Ignore,
}

impl Default for CombineMetaMode {
    fn default() -> Self {
        CombineMetaMode::Merge
    }
}

/// A tool result that includes explicit metadata and a combine mode.
///
/// When tool implementations return results, they can optionally wrap them
/// in this structure to control how metadata is applied. This corresponds
/// to the `is_sequrity_var` / `ValueWithMeta` protocol in the API docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultWithMeta<T> {
    pub value: T,
    pub meta: Metadata,
    /// Signals that this is a Security Compass metadata-wrapped value.
    #[serde(default = "default_true")]
    pub is_security_compass_var: bool,
    /// How to combine the provided metadata with existing metadata.
    #[serde(default)]
    pub combine_meta: CombineMetaMode,
}

fn default_true() -> bool {
    true
}

impl<T> ValueWithMeta<T> {
    /// Create a new value with the given metadata.
    pub fn new(value: T, meta: Metadata) -> Self {
        Self { value, meta }
    }

    /// Create a new value with default (user-input) metadata.
    pub fn with_default_meta(value: T) -> Self {
        Self {
            value,
            meta: Metadata::default(),
        }
    }

    /// Map the inner value while preserving metadata.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> ValueWithMeta<U> {
        ValueWithMeta {
            value: f(self.value),
            meta: self.meta,
        }
    }

    /// Replace the metadata.
    pub fn with_meta(mut self, meta: Metadata) -> Self {
        self.meta = meta;
        self
    }
}

impl<T: PartialEq> PartialEq for ValueWithMeta<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.meta == other.meta
    }
}

impl<T: Eq> Eq for ValueWithMeta<T> {}

impl<T> ToolResultWithMeta<T> {
    /// Apply this tool result's metadata to the given base metadata,
    /// according to the `combine_meta` mode.
    pub fn resolve_metadata(&self, base: &Metadata) -> Metadata {
        match self.combine_meta {
            CombineMetaMode::Merge => base.merge(&self.meta),
            CombineMetaMode::Replace => self.meta.clone(),
            CombineMetaMode::Ignore => base.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumer_set::ConsumerSet;
    use std::collections::BTreeSet;

    fn tags(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn producers(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn finite_consumers(items: &[&str]) -> ConsumerSet {
        ConsumerSet::Finite(items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_new() {
        let v = ValueWithMeta::new(42, Metadata::default());
        assert_eq!(v.value, 42);
        assert_eq!(v.meta, Metadata::default());
    }

    #[test]
    fn test_with_default_meta() {
        let v = ValueWithMeta::with_default_meta("hello");
        assert_eq!(v.value, "hello");
        assert!(v.meta.is_clean());
    }

    #[test]
    fn test_map() {
        let v = ValueWithMeta::new(42, Metadata::default().with_tag("tagged"));
        let mapped = v.map(|x| x.to_string());
        assert_eq!(mapped.value, "42");
        assert!(mapped.meta.tags.contains("tagged"));
    }

    #[test]
    fn test_with_meta() {
        let v = ValueWithMeta::new(42, Metadata::default());
        let new_meta = Metadata::default().with_producer("db");
        let v2 = v.with_meta(new_meta.clone());
        assert_eq!(v2.meta, new_meta);
    }

    #[test]
    fn test_equality() {
        let a = ValueWithMeta::new(42, Metadata::default().with_tag("t"));
        let b = ValueWithMeta::new(42, Metadata::default().with_tag("t"));
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality_value() {
        let a = ValueWithMeta::new(42, Metadata::default());
        let b = ValueWithMeta::new(43, Metadata::default());
        assert_ne!(a, b);
    }

    #[test]
    fn test_inequality_meta() {
        let a = ValueWithMeta::new(42, Metadata::default());
        let b = ValueWithMeta::new(42, Metadata::default().with_tag("t"));
        assert_ne!(a, b);
    }

    #[test]
    fn test_combine_meta_merge() {
        let base = Metadata {
            producers: producers(&["tool_a"]),
            consumers: finite_consumers(&["alice", "bob"]),
            tags: tags(&["existing"]),
        };
        let provided = Metadata {
            producers: producers(&["tool_b"]),
            consumers: finite_consumers(&["bob", "carol"]),
            tags: tags(&["new"]),
        };
        let tool_result = ToolResultWithMeta {
            value: "result",
            meta: provided,
            is_security_compass_var: true,
            combine_meta: CombineMetaMode::Merge,
        };
        let resolved = tool_result.resolve_metadata(&base);
        assert_eq!(resolved.producers, producers(&["tool_a", "tool_b"]));
        assert_eq!(resolved.consumers, finite_consumers(&["bob"]));
        assert_eq!(resolved.tags, tags(&["existing", "new"]));
    }

    #[test]
    fn test_combine_meta_replace() {
        let base = Metadata {
            producers: producers(&["tool_a"]),
            consumers: ConsumerSet::Universal,
            tags: tags(&["old"]),
        };
        let provided = Metadata {
            producers: producers(&["tool_b"]),
            consumers: finite_consumers(&["admin"]),
            tags: tags(&["new"]),
        };
        let tool_result = ToolResultWithMeta {
            value: "result",
            meta: provided.clone(),
            is_security_compass_var: true,
            combine_meta: CombineMetaMode::Replace,
        };
        let resolved = tool_result.resolve_metadata(&base);
        assert_eq!(resolved, provided);
    }

    #[test]
    fn test_combine_meta_ignore() {
        let base = Metadata {
            producers: producers(&["tool_a"]),
            consumers: ConsumerSet::Universal,
            tags: tags(&["old"]),
        };
        let provided = Metadata {
            producers: producers(&["tool_b"]),
            consumers: finite_consumers(&["admin"]),
            tags: tags(&["new"]),
        };
        let tool_result = ToolResultWithMeta {
            value: "result",
            meta: provided,
            is_security_compass_var: true,
            combine_meta: CombineMetaMode::Ignore,
        };
        let resolved = tool_result.resolve_metadata(&base);
        assert_eq!(resolved, base);
    }

    #[test]
    fn test_default_combine_mode_is_merge() {
        assert_eq!(CombineMetaMode::default(), CombineMetaMode::Merge);
    }

    #[test]
    fn test_serialize_value_with_meta() {
        let v = ValueWithMeta::new(42, Metadata::default().with_tag("test"));
        let json = serde_json::to_string(&v).unwrap();
        let deserialized: ValueWithMeta<i32> = serde_json::from_str(&json).unwrap();
        assert_eq!(v, deserialized);
    }

    #[test]
    fn test_serialize_combine_meta_mode() {
        assert_eq!(
            serde_json::to_string(&CombineMetaMode::Merge).unwrap(),
            "\"merge\""
        );
        assert_eq!(
            serde_json::to_string(&CombineMetaMode::Replace).unwrap(),
            "\"replace\""
        );
        assert_eq!(
            serde_json::to_string(&CombineMetaMode::Ignore).unwrap(),
            "\"ignore\""
        );
    }
}
