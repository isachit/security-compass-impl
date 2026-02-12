//! HTTP header extraction and parsing.
//!
//! Extracts Security Compass headers from the axum `HeaderMap` and
//! deserializes their JSON payloads into typed structs.

use axum::http::HeaderMap;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::ServerError;
use crate::types::headers::{FeaturesHeader, FineGrainedConfigHeader, SecurityPolicyHeader};

/// Header names used by the Security Compass API.
pub const HEADER_FEATURES: &str = "x-security-features";
pub const HEADER_POLICY: &str = "x-security-policy";
pub const HEADER_CONFIG: &str = "x-security-config";
pub const HEADER_SESSION_ID: &str = "x-session-id";
pub const HEADER_API_KEY: &str = "x-api-key";
pub const HEADER_AUTHORIZATION: &str = "authorization";

/// All parsed header values from a single request.
#[derive(Debug)]
pub struct ParsedHeaders {
    /// Parsed features header (if present).
    pub features: Option<FeaturesHeader>,
    /// Parsed security policy header (if present).
    pub security_policy: Option<SecurityPolicyHeader>,
    /// Parsed fine-grained config header (if present).
    pub config: Option<FineGrainedConfigHeader>,
    /// Session ID for conversation continuity (if present).
    pub session_id: Option<Uuid>,
    /// API key for the upstream LLM provider (if present).
    pub api_key: Option<String>,
    /// Bearer token from the Authorization header (if present).
    pub auth_token: Option<String>,
}

/// Parses all Security Compass headers from the request.
///
/// Absent headers yield `None` for the corresponding field. Invalid JSON
/// in a present header yields `Err(ServerError::InvalidHeader)`.
pub fn parse_headers(headers: &HeaderMap) -> Result<ParsedHeaders, ServerError> {
    let features = parse_optional_json_header::<FeaturesHeader>(headers, HEADER_FEATURES)?;
    let security_policy =
        parse_optional_json_header::<SecurityPolicyHeader>(headers, HEADER_POLICY)?;
    let config = parse_optional_json_header::<FineGrainedConfigHeader>(headers, HEADER_CONFIG)?;
    let session_id = parse_optional_uuid_header(headers, HEADER_SESSION_ID)?;
    let api_key = extract_string_header(headers, HEADER_API_KEY);
    let auth_token = extract_bearer_token(headers);

    Ok(ParsedHeaders {
        features,
        security_policy,
        config,
        session_id,
        api_key,
        auth_token,
    })
}

/// Parses an optional JSON header value.
///
/// - Absent or empty header -> `Ok(None)`
/// - Present, valid JSON -> `Ok(Some(T))`
/// - Present, invalid JSON -> `Err(InvalidHeader)`
///
/// As a fallback, the raw header value is URL-decoded before parsing,
/// since JSON in HTTP headers is sometimes URL-encoded by proxies.
fn parse_optional_json_header<T: DeserializeOwned>(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<T>, ServerError> {
    let value = match headers.get(name) {
        Some(v) => v,
        None => return Ok(None),
    };

    let raw = value.to_str().map_err(|_| ServerError::InvalidHeader {
        header: name.to_string(),
        detail: "header contains non-ASCII characters".to_string(),
    })?;

    // Treat empty string as absent.
    if raw.is_empty() {
        return Ok(None);
    }

    // Try direct JSON parse first.
    match serde_json::from_str::<T>(raw) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(direct_err) => {
            // Fallback: URL-decode then parse.
            let decoded = urlencoded_decode(raw);
            serde_json::from_str::<T>(&decoded).map(Some).map_err(|_| {
                ServerError::InvalidHeader {
                    header: name.to_string(),
                    detail: direct_err.to_string(),
                }
            })
        }
    }
}

/// Parses an optional UUID header value.
///
/// - Absent or empty header -> `Ok(None)`
/// - Valid UUID -> `Ok(Some(Uuid))`
/// - Invalid format -> `Err(InvalidHeader)`
fn parse_optional_uuid_header(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<Uuid>, ServerError> {
    let value = match headers.get(name) {
        Some(v) => v,
        None => return Ok(None),
    };

    let raw = value.to_str().map_err(|_| ServerError::InvalidHeader {
        header: name.to_string(),
        detail: "header contains non-ASCII characters".to_string(),
    })?;

    if raw.is_empty() {
        return Ok(None);
    }

    raw.parse::<Uuid>()
        .map(Some)
        .map_err(|e| ServerError::InvalidHeader {
            header: name.to_string(),
            detail: format!("invalid UUID: {e}"),
        })
}

/// Extracts a plain string header value, returning `None` if absent or empty.
fn extract_string_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Extracts a Bearer token from the `Authorization` header.
///
/// Returns `None` if the header is absent, empty, or does not start with
/// "Bearer ".
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Simple percent-decoding for URL-encoded header values.
///
/// Decodes `%XX` sequences and `+` as space. This is a minimal
/// implementation for headers that may have been URL-encoded by
/// intermediate proxies.
fn urlencoded_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                    } else {
                        result.push('%');
                        result.push_str(&hex);
                    }
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            }
            '+' => result.push(' '),
            _ => result.push(c),
        }
    }
    result
}
