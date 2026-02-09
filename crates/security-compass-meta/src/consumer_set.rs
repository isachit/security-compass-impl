use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Represents the set of allowed consumers for a piece of data.
///
/// The default is `Universal` — meaning anyone can consume the data.
/// When data is combined, consumer sets are **intersected**, which means
/// the set of allowed consumers can only shrink. This is the core security
/// property: combining restricted data never loosens restrictions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConsumerSet {
    /// `{"*"}` — no restrictions, anyone can read this data.
    Universal,
    /// A finite set of allowed consumer identifiers.
    Finite(BTreeSet<String>),
}

impl ConsumerSet {
    /// Intersect two consumer sets.
    ///
    /// This is the propagation rule for consumers when data is combined:
    /// - Universal ∩ X = X
    /// - X ∩ Universal = X
    /// - Finite(A) ∩ Finite(B) = Finite(A ∩ B)
    pub fn intersect(&self, other: &ConsumerSet) -> ConsumerSet {
        match (self, other) {
            (ConsumerSet::Universal, other) => other.clone(),
            (this, ConsumerSet::Universal) => this.clone(),
            (ConsumerSet::Finite(a), ConsumerSet::Finite(b)) => {
                ConsumerSet::Finite(a.intersection(b).cloned().collect())
            }
        }
    }

    /// Union two consumer sets.
    ///
    /// Used by SQRT augmented assignment `@consumers |= {...}`.
    /// - Universal ∪ X = Universal
    /// - X ∪ Universal = Universal
    /// - Finite(A) ∪ Finite(B) = Finite(A ∪ B)
    pub fn union(&self, other: &ConsumerSet) -> ConsumerSet {
        match (self, other) {
            (ConsumerSet::Universal, _) | (_, ConsumerSet::Universal) => ConsumerSet::Universal,
            (ConsumerSet::Finite(a), ConsumerSet::Finite(b)) => {
                ConsumerSet::Finite(a.union(b).cloned().collect())
            }
        }
    }

    /// Set difference.
    ///
    /// Used by SQRT augmented assignment `@consumers -= {...}`.
    /// - Universal - Finite(B) = Universal (cannot subtract from universal)
    /// - Finite(A) - Universal = Finite({}) (empty)
    /// - Finite(A) - Finite(B) = Finite(A \ B)
    pub fn difference(&self, other: &ConsumerSet) -> ConsumerSet {
        match (self, other) {
            (ConsumerSet::Universal, ConsumerSet::Finite(_)) => ConsumerSet::Universal,
            (_, ConsumerSet::Universal) => ConsumerSet::Finite(BTreeSet::new()),
            (ConsumerSet::Finite(a), ConsumerSet::Finite(b)) => {
                ConsumerSet::Finite(a.difference(b).cloned().collect())
            }
        }
    }

    /// Symmetric difference (XOR).
    ///
    /// Used by SQRT augmented assignment `@consumers ^= {...}`.
    /// - Universal ^ X = Universal (symmetric difference with universal is universal)
    /// - X ^ Universal = Universal
    /// - Finite(A) ^ Finite(B) = Finite(A △ B)
    pub fn symmetric_difference(&self, other: &ConsumerSet) -> ConsumerSet {
        match (self, other) {
            (ConsumerSet::Universal, _) | (_, ConsumerSet::Universal) => ConsumerSet::Universal,
            (ConsumerSet::Finite(a), ConsumerSet::Finite(b)) => {
                ConsumerSet::Finite(a.symmetric_difference(b).cloned().collect())
            }
        }
    }

    /// Check if a specific consumer is allowed.
    pub fn contains(&self, consumer: &str) -> bool {
        match self {
            ConsumerSet::Universal => true,
            ConsumerSet::Finite(set) => set.contains(consumer),
        }
    }

    /// Returns true if this is the universal set.
    pub fn is_universal(&self) -> bool {
        matches!(self, ConsumerSet::Universal)
    }

    /// Returns true if this consumer set is empty (no consumers allowed).
    pub fn is_empty(&self) -> bool {
        match self {
            ConsumerSet::Universal => false,
            ConsumerSet::Finite(set) => set.is_empty(),
        }
    }

    /// Check if two consumer sets share at least one element.
    pub fn overlaps(&self, other: &ConsumerSet) -> bool {
        match (self, other) {
            (ConsumerSet::Universal, ConsumerSet::Finite(b)) => !b.is_empty(),
            (ConsumerSet::Finite(a), ConsumerSet::Universal) => !a.is_empty(),
            (ConsumerSet::Universal, ConsumerSet::Universal) => true,
            (ConsumerSet::Finite(a), ConsumerSet::Finite(b)) => {
                a.intersection(b).next().is_some()
            }
        }
    }

    /// Check if self is a subset of other.
    pub fn is_subset_of(&self, other: &ConsumerSet) -> bool {
        match (self, other) {
            (_, ConsumerSet::Universal) => true,
            (ConsumerSet::Universal, ConsumerSet::Finite(_)) => false,
            (ConsumerSet::Finite(a), ConsumerSet::Finite(b)) => a.is_subset(b),
        }
    }
}

impl Default for ConsumerSet {
    /// Default consumer set is Universal — no restrictions.
    fn default() -> Self {
        ConsumerSet::Universal
    }
}

impl From<Vec<String>> for ConsumerSet {
    fn from(items: Vec<String>) -> Self {
        if items.len() == 1 && items[0] == "*" {
            ConsumerSet::Universal
        } else {
            ConsumerSet::Finite(items.into_iter().collect())
        }
    }
}

impl From<BTreeSet<String>> for ConsumerSet {
    fn from(set: BTreeSet<String>) -> Self {
        if set.len() == 1 && set.contains("*") {
            ConsumerSet::Universal
        } else {
            ConsumerSet::Finite(set)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finite(items: &[&str]) -> ConsumerSet {
        ConsumerSet::Finite(items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_intersect_universal_with_finite() {
        let result = ConsumerSet::Universal.intersect(&finite(&["a", "b"]));
        assert_eq!(result, finite(&["a", "b"]));
    }

    #[test]
    fn test_intersect_finite_with_universal() {
        let result = finite(&["a", "b"]).intersect(&ConsumerSet::Universal);
        assert_eq!(result, finite(&["a", "b"]));
    }

    #[test]
    fn test_intersect_universal_with_universal() {
        let result = ConsumerSet::Universal.intersect(&ConsumerSet::Universal);
        assert_eq!(result, ConsumerSet::Universal);
    }

    #[test]
    fn test_intersect_finite_sets() {
        let result = finite(&["a", "b", "c"]).intersect(&finite(&["b", "c", "d"]));
        assert_eq!(result, finite(&["b", "c"]));
    }

    #[test]
    fn test_intersect_disjoint_finite_sets() {
        let result = finite(&["a", "b"]).intersect(&finite(&["c", "d"]));
        assert_eq!(result, finite(&[]));
    }

    #[test]
    fn test_union_universal_absorbs() {
        let result = ConsumerSet::Universal.union(&finite(&["a"]));
        assert_eq!(result, ConsumerSet::Universal);
    }

    #[test]
    fn test_union_finite_sets() {
        let result = finite(&["a", "b"]).union(&finite(&["b", "c"]));
        assert_eq!(result, finite(&["a", "b", "c"]));
    }

    #[test]
    fn test_difference_universal_minus_finite() {
        let result = ConsumerSet::Universal.difference(&finite(&["a"]));
        assert_eq!(result, ConsumerSet::Universal);
    }

    #[test]
    fn test_difference_finite_minus_universal() {
        let result = finite(&["a", "b"]).difference(&ConsumerSet::Universal);
        assert_eq!(result, finite(&[]));
    }

    #[test]
    fn test_difference_finite_sets() {
        let result = finite(&["a", "b", "c"]).difference(&finite(&["b"]));
        assert_eq!(result, finite(&["a", "c"]));
    }

    #[test]
    fn test_symmetric_difference_finite_sets() {
        let result = finite(&["a", "b"]).symmetric_difference(&finite(&["b", "c"]));
        assert_eq!(result, finite(&["a", "c"]));
    }

    #[test]
    fn test_symmetric_difference_universal() {
        let result = ConsumerSet::Universal.symmetric_difference(&finite(&["a"]));
        assert_eq!(result, ConsumerSet::Universal);
    }

    #[test]
    fn test_contains_universal() {
        assert!(ConsumerSet::Universal.contains("anything"));
    }

    #[test]
    fn test_contains_finite_present() {
        assert!(finite(&["a", "b"]).contains("a"));
    }

    #[test]
    fn test_contains_finite_absent() {
        assert!(!finite(&["a", "b"]).contains("c"));
    }

    #[test]
    fn test_is_universal() {
        assert!(ConsumerSet::Universal.is_universal());
        assert!(!finite(&["a"]).is_universal());
    }

    #[test]
    fn test_is_empty() {
        assert!(!ConsumerSet::Universal.is_empty());
        assert!(finite(&[]).is_empty());
        assert!(!finite(&["a"]).is_empty());
    }

    #[test]
    fn test_overlaps() {
        assert!(finite(&["a", "b"]).overlaps(&finite(&["b", "c"])));
        assert!(!finite(&["a"]).overlaps(&finite(&["b"])));
        assert!(ConsumerSet::Universal.overlaps(&finite(&["a"])));
        assert!(!ConsumerSet::Universal.overlaps(&finite(&[])));
    }

    #[test]
    fn test_is_subset_of() {
        assert!(finite(&["a"]).is_subset_of(&finite(&["a", "b"])));
        assert!(!finite(&["a", "b"]).is_subset_of(&finite(&["a"])));
        assert!(finite(&["a"]).is_subset_of(&ConsumerSet::Universal));
        assert!(!ConsumerSet::Universal.is_subset_of(&finite(&["a"])));
    }

    #[test]
    fn test_default_is_universal() {
        assert_eq!(ConsumerSet::default(), ConsumerSet::Universal);
    }

    #[test]
    fn test_from_vec_star_is_universal() {
        let cs: ConsumerSet = vec!["*".to_string()].into();
        assert_eq!(cs, ConsumerSet::Universal);
    }

    #[test]
    fn test_from_vec_items() {
        let cs: ConsumerSet = vec!["a".to_string(), "b".to_string()].into();
        assert_eq!(cs, finite(&["a", "b"]));
    }
}
