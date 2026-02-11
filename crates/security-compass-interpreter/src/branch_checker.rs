//! Policy-aware branch checker that integrates SQRT branching meta-policy with the VM.
//!
//! The `PolicyBranchChecker` is injected into the VM at startup and on each resume.
//! It is called at every conditional jump (JumpIfTrue/JumpIfFalse) to verify that
//! the condition's metadata does not violate the configured branching meta-policy.

use std::sync::Arc;

use security_compass_meta::Metadata;
use security_compass_vm::{BranchChecker, ExcType, MontyException};
use sqrt_eval::CompiledPolicy;

/// A `BranchChecker` implementation backed by a compiled SQRT policy.
///
/// Delegates to `sqrt_eval::check_branch()` which evaluates the branching
/// meta-policy against the condition's metadata (producers, tags, consumers).
///
/// If the branching check fails (e.g., untrusted producer on a deny list),
/// this returns a `MontyException` with `ExcType::RuntimeError` containing
/// a descriptive message about why branching was denied.
pub struct PolicyBranchChecker {
    policy: Arc<CompiledPolicy>,
}

impl PolicyBranchChecker {
    /// Creates a new branch checker from a shared compiled policy.
    pub fn new(policy: Arc<CompiledPolicy>) -> Self {
        Self { policy }
    }
}

impl BranchChecker for PolicyBranchChecker {
    fn check(&self, condition_meta: &Metadata) -> Result<(), MontyException> {
        sqrt_eval::check_branch(&self.policy, condition_meta).map_err(|denied| {
            MontyException::new(
                ExcType::RuntimeError,
                Some(format!(
                    "Branching denied: {} (field: {}, values: {:?})",
                    denied.reason, denied.field, denied.offending_values
                )),
            )
        })
    }
}
