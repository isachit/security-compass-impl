//! Error types for the SQRT parser.

use std::fmt;

/// An error encountered during SQRT parsing.
#[derive(Debug, Clone)]
pub struct SqrtParseError {
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub source_snippet: Option<String>,
}

impl SqrtParseError {
    pub fn new(
        message: impl Into<String>,
        line: Option<usize>,
        column: Option<usize>,
        source_snippet: Option<String>,
    ) -> Self {
        Self {
            message: message.into(),
            line,
            column,
            source_snippet,
        }
    }

    pub fn internal(message: &str) -> Self {
        Self {
            message: format!("Internal parser error: {message}"),
            line: None,
            column: None,
            source_snippet: None,
        }
    }

    pub fn from_pest_error(input: &str, error: pest::error::Error<crate::parser::Rule>) -> Self {
        let (line, column) = match error.line_col {
            pest::error::LineColLocation::Pos((l, c)) => (Some(l), Some(c)),
            pest::error::LineColLocation::Span((l, c), _) => (Some(l), Some(c)),
        };

        let source_snippet = line.and_then(|l| {
            input.lines().nth(l.saturating_sub(1)).map(|line_str| {
                let mut snippet = line_str.to_string();
                if let Some(col) = column {
                    snippet.push('\n');
                    snippet.push_str(&" ".repeat(col.saturating_sub(1)));
                    snippet.push('^');
                }
                snippet
            })
        });

        Self {
            message: error.variant.message().to_string(),
            line,
            column,
            source_snippet,
        }
    }
}

impl fmt::Display for SqrtParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SQRT parse error: {}", self.message)?;
        if let Some(line) = self.line {
            write!(f, " at line {line}")?;
            if let Some(col) = self.column {
                write!(f, ", column {col}")?;
            }
        }
        if let Some(ref snippet) = self.source_snippet {
            write!(f, "\n{snippet}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SqrtParseError {}
