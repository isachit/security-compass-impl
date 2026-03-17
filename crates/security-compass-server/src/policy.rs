//! Policy compilation: converts a [`SecurityPolicyHeader`] into a [`CompiledPolicy`].
//!
//! Parses the SQRT source code from the header, builds an
//! [`InternalPolicyPreset`] from the header's preset overrides, and
//! compiles the policy using the sqrt-parser and sqrt-eval crates.

use std::collections::BTreeSet;

use sqrt_eval::{BranchingMetaPolicy, BranchingMode, CompiledPolicy, InternalPolicyPreset};
use sqrt_parser::Enforcement;

use crate::error::ServerError;
use crate::types::headers::{
    BranchingModeStr, EnforcementLevel, PolicyLanguage, SecurityPolicyHeader,
};

/// Compiles a [`SecurityPolicyHeader`] into a [`CompiledPolicy`].
///
/// # Errors
///
/// - [`ServerError::UnsupportedFeature`] if the policy language is not `sqrt`.
/// - [`ServerError::PolicyCompileError`] if parsing or compilation fails.
pub fn compile_policy(header: &SecurityPolicyHeader) -> Result<CompiledPolicy, ServerError> {
    // 1. Validate language: only SQRT is supported.
    match header.language {
        PolicyLanguage::Sqrt => {}
        PolicyLanguage::SqrtLite => {
            return Err(ServerError::UnsupportedFeature {
                feature: "sqrt-lite policy language".to_string(),
            });
        }
        PolicyLanguage::Cedar => {
            return Err(ServerError::UnsupportedFeature {
                feature: "cedar policy language".to_string(),
            });
        }
    }

    // 2. Build InternalPolicyPreset from header overrides.
    let preset = build_preset(header);

    // 3. Get the combined policy source code.
    let source = header.codes.as_combined_string();

    // 4. Empty source: compile with an empty program.
    if source.trim().is_empty() {
        let empty_program = sqrt_parser::SqrtProgram {
            declarations: Vec::new(),
        };
        return sqrt_eval::compile(&empty_program, preset).map_err(|e| {
            ServerError::PolicyCompileError {
                detail: e.to_string(),
            }
        });
    }

    // 5. Parse the SQRT source.
    let program = sqrt_parser::parse(&source).map_err(|e| ServerError::PolicyCompileError {
        detail: e.to_string(),
    })?;

    // 6. Compile the parsed program.
    sqrt_eval::compile(&program, preset).map_err(|e| ServerError::PolicyCompileError {
        detail: e.to_string(),
    })
}

/// Builds an [`InternalPolicyPreset`] from the header's preset overrides.
///
/// If no preset is specified in the header, returns the default preset.
fn build_preset(header: &SecurityPolicyHeader) -> InternalPolicyPreset {
    match &header.internal_policy_preset {
        None => InternalPolicyPreset::default(),
        Some(preset_header) => {
            let enforcement = match preset_header.default_allow_enforcement_level {
                EnforcementLevel::Soft => Enforcement::Should,
                EnforcementLevel::Hard => Enforcement::Must,
            };

            let branching_meta_policy = match &preset_header.branching_meta_policy {
                None => BranchingMetaPolicy::default(),
                Some(bmp) => {
                    let mode = match bmp.mode {
                        BranchingModeStr::Allow => BranchingMode::Allow,
                        BranchingModeStr::Deny => BranchingMode::Deny,
                    };
                    BranchingMetaPolicy {
                        mode,
                        producers: bmp.producers.iter().cloned().collect::<BTreeSet<_>>(),
                        tags: bmp.tags.iter().cloned().collect::<BTreeSet<_>>(),
                        consumers: bmp.consumers.iter().cloned().collect::<BTreeSet<_>>(),
                    }
                }
            };

            InternalPolicyPreset {
                default_allow: preset_header.default_allow,
                default_allow_enforcement: enforcement,
                enable_non_executable_memory: preset_header.enable_non_executable_memory,
                enable_llm_blocked_tag: preset_header.enable_llm_blocked_tag,
                branching_meta_policy,
            }
        }
    }
}
