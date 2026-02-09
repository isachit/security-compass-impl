//! Error types for the SQRT policy evaluation engine.

use std::fmt;
use thiserror::Error;

/// Errors that occur during policy compilation (AST → CompiledPolicy).
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("Invalid regex pattern '{pattern}': {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("Undefined variable '{name}' referenced in {context}")]
    UndefinedVariable { name: String, context: String },

    #[error("Duplicate variable declaration: '{name}'")]
    DuplicateVariable { name: String },
}

/// Errors that occur during policy evaluation at runtime.
#[derive(Debug, Error)]
pub enum EvalError {
    #[error("Undefined variable '{name}' during evaluation")]
    UndefinedVariable { name: String },

    #[error("Type mismatch during evaluation: {message}")]
    TypeMismatch { message: String },

    #[error("Invalid argument reference: no argument named '{name}'")]
    InvalidArgRef { name: String },

    #[error("Result metadata not available in this context")]
    ResultMetaUnavailable,

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

/// Error returned when a branching meta-policy check fails.
#[derive(Debug)]
pub struct BranchingDenied {
    pub reason: String,
    pub field: String,
    pub offending_values: Vec<String>,
}

impl fmt::Display for BranchingDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Branching denied: {} (field: {}, offending: {:?})",
            self.reason, self.field, self.offending_values
        )
    }
}

impl std::error::Error for BranchingDenied {}
