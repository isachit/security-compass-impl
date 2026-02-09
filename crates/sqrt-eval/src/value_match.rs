//! Value matching against type domains and set elements.
//!
//! This module implements the logic for checking whether a `serde_json::Value`
//! matches a SQRT type domain constraint or set element pattern. Used by the
//! predicate evaluator for `ValueIn` comparisons.

use regex::Regex;
use sqrt_parser::{DatetimeSpec, NumberValue, RangeSpec, SetElement, StringPattern, TypeDomain};

use crate::error::EvalError;

/// Check if a JSON value matches a type domain constraint.
///
/// Type domains constrain the shape of values: booleans, integer ranges,
/// float ranges, string patterns (exact/regex/wildcard) with optional length,
/// and datetime specifications.
pub(crate) fn matches_type_domain(
    value: &serde_json::Value,
    td: &TypeDomain,
) -> Result<bool, EvalError> {
    match td {
        TypeDomain::Bool(expected) => match value {
            serde_json::Value::Bool(b) => Ok(b == expected),
            _ => Ok(false),
        },

        TypeDomain::Int(range) => {
            let n = match value {
                serde_json::Value::Number(n) => n.as_i64(),
                _ => None,
            };
            match n {
                Some(n) => check_number_range(n as f64, range),
                None => Ok(false),
            }
        }

        TypeDomain::Float(range) => {
            let n = match value {
                serde_json::Value::Number(n) => n.as_f64(),
                _ => None,
            };
            match n {
                Some(n) => check_number_range(n, range),
                None => Ok(false),
            }
        }

        TypeDomain::Str { pattern, length } => {
            let s = match value {
                serde_json::Value::String(s) => s,
                _ => return Ok(false),
            };

            // Check string pattern
            let pattern_matches = match pattern {
                StringPattern::Exact(expected) => s == expected,
                StringPattern::Matching(regex_str) => {
                    let re = Regex::new(regex_str).map_err(EvalError::RegexError)?;
                    re.is_match(s)
                }
                StringPattern::Like(glob) => {
                    let re = wildcard_to_regex(glob);
                    let compiled = Regex::new(&re).map_err(EvalError::RegexError)?;
                    compiled.is_match(s)
                }
            };

            if !pattern_matches {
                return Ok(false);
            }

            // Check optional length constraint
            if let Some(len_range) = length {
                let len = s.len() as f64;
                check_number_range(len, len_range)
            } else {
                Ok(true)
            }
        }

        TypeDomain::Datetime(spec) => {
            let s = match value {
                serde_json::Value::String(s) => s.as_str(),
                _ => return Ok(false),
            };
            matches_datetime(s, spec)
        }
    }
}

/// Check if a JSON value matches a set element (for `ValueIn` comparisons).
///
/// Set elements can be exact strings, regex patterns, wildcards, type domains,
/// or numeric values.
pub(crate) fn matches_set_element(
    value: &serde_json::Value,
    elem: &SetElement,
) -> Result<bool, EvalError> {
    match elem {
        SetElement::String(expected) => match value {
            serde_json::Value::String(s) => Ok(s == expected),
            _ => Ok(false),
        },

        SetElement::Regex(pattern) => match value {
            serde_json::Value::String(s) => {
                let re = Regex::new(pattern).map_err(EvalError::RegexError)?;
                Ok(re.is_match(s))
            }
            _ => Ok(false),
        },

        SetElement::Wildcard(glob) => match value {
            serde_json::Value::String(s) => {
                let re_str = wildcard_to_regex(glob);
                let re = Regex::new(&re_str).map_err(EvalError::RegexError)?;
                Ok(re.is_match(s))
            }
            _ => Ok(false),
        },

        SetElement::TypeDomain(td) => matches_type_domain(value, td),

        SetElement::Number(nv) => match value {
            serde_json::Value::Number(n) => {
                let val = n.as_f64();
                let expected = number_value_to_f64(nv);
                match (val, expected) {
                    (Some(v), Some(e)) => Ok((v - e).abs() < f64::EPSILON),
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        },
    }
}

/// Convert a wildcard/glob pattern to a regex.
///
/// `*` → `.*` (match anything)
/// `?` → `.` (match single char)
/// Everything else is regex-escaped and the pattern is anchored with `^...$`.
fn wildcard_to_regex(glob: &str) -> String {
    let mut re = String::with_capacity(glob.len() + 4);
    re.push('^');
    for ch in glob.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            // Regex meta-characters that need escaping
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '^' | '$' | '|' => {
                re.push('\\');
                re.push(ch);
            }
            _ => re.push(ch),
        }
    }
    re.push('$');
    re
}

/// Convert a NumberValue to f64 for comparison.
fn number_value_to_f64(nv: &NumberValue) -> Option<f64> {
    match nv {
        NumberValue::Int(i) => Some(*i as f64),
        NumberValue::Float(f) => Some(*f),
        NumberValue::PosInf => Some(f64::INFINITY),
        NumberValue::NegInf => Some(f64::NEG_INFINITY),
    }
}

/// Check if a number falls within a range specification.
fn check_number_range(value: f64, range: &RangeSpec<NumberValue>) -> Result<bool, EvalError> {
    match range {
        RangeSpec::Exact(n) => {
            let expected = number_value_to_f64(n).unwrap_or(f64::NAN);
            Ok((value - expected).abs() < f64::EPSILON)
        }
        RangeSpec::Inclusive { min, max } => {
            let lo = number_value_to_f64(min).unwrap_or(f64::NAN);
            let hi = number_value_to_f64(max).unwrap_or(f64::NAN);
            Ok(value >= lo && value <= hi)
        }
        RangeSpec::ExclusiveBoth { min, max } => {
            let lo = number_value_to_f64(min).unwrap_or(f64::NAN);
            let hi = number_value_to_f64(max).unwrap_or(f64::NAN);
            Ok(value > lo && value < hi)
        }
        RangeSpec::ExclusiveLeft { min, max } => {
            let lo = number_value_to_f64(min).unwrap_or(f64::NAN);
            let hi = number_value_to_f64(max).unwrap_or(f64::NAN);
            Ok(value > lo && value <= hi)
        }
        RangeSpec::ExclusiveRight { min, max } => {
            let lo = number_value_to_f64(min).unwrap_or(f64::NAN);
            let hi = number_value_to_f64(max).unwrap_or(f64::NAN);
            Ok(value >= lo && value < hi)
        }
        RangeSpec::To(max) => {
            let hi = number_value_to_f64(max).unwrap_or(f64::NAN);
            Ok(value <= hi)
        }
        RangeSpec::ToExclusive(max) => {
            let hi = number_value_to_f64(max).unwrap_or(f64::NAN);
            Ok(value < hi)
        }
        RangeSpec::From(min) => {
            let lo = number_value_to_f64(min).unwrap_or(f64::NAN);
            Ok(value >= lo)
        }
        RangeSpec::FromExclusive(min) => {
            let lo = number_value_to_f64(min).unwrap_or(f64::NAN);
            Ok(value > lo)
        }
    }
}

/// Check if a string matches a datetime specification.
///
/// For now, datetime comparison is string-based (ISO 8601 strings can be
/// compared lexicographically for correctly formatted timestamps).
fn matches_datetime(s: &str, spec: &DatetimeSpec) -> Result<bool, EvalError> {
    match spec {
        DatetimeSpec::Exact(expected) => Ok(s == expected),
        DatetimeSpec::String(expected) => Ok(s == expected),
        DatetimeSpec::Epoch(_nv) => {
            // Epoch comparison: we'd need to parse the datetime string to epoch.
            // For now, return false for epoch-based matching against strings.
            // A full implementation would parse ISO 8601 → epoch and compare.
            Ok(false)
        }
        DatetimeSpec::Range(range) => check_datetime_range(s, range),
    }
}

/// Check if a datetime string falls within a range (lexicographic comparison).
///
/// This works correctly for ISO 8601 formatted datetime strings because they
/// are lexicographically sortable (e.g., "2023-01-01T00:00:00Z" < "2024-01-01T00:00:00Z").
fn check_datetime_range(s: &str, range: &RangeSpec<String>) -> Result<bool, EvalError> {
    match range {
        RangeSpec::Exact(expected) => Ok(s == expected.as_str()),
        RangeSpec::Inclusive { min, max } => Ok(s >= min.as_str() && s <= max.as_str()),
        RangeSpec::ExclusiveBoth { min, max } => Ok(s > min.as_str() && s < max.as_str()),
        RangeSpec::ExclusiveLeft { min, max } => Ok(s > min.as_str() && s <= max.as_str()),
        RangeSpec::ExclusiveRight { min, max } => Ok(s >= min.as_str() && s < max.as_str()),
        RangeSpec::To(max) => Ok(s <= max.as_str()),
        RangeSpec::ToExclusive(max) => Ok(s < max.as_str()),
        RangeSpec::From(min) => Ok(s >= min.as_str()),
        RangeSpec::FromExclusive(min) => Ok(s > min.as_str()),
    }
}
