// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::model::AuditEvent;
use crate::validation::has_forbidden_key_name;

const MAX_SANITIZED_STRING_BYTES: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum SanitizationError {
    #[error("audit event serialization failed before sanitization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("audit event contains forbidden field name at {path}: {field}")]
    ForbiddenFieldName { path: String, field: String },
    #[error("audit event contains credential-like value at {path}: {reason}")]
    CredentialLikeValue { path: String, reason: String },
    #[error("audit event string exceeds sanitization limit at {path}: {byte_len} bytes")]
    ExcessiveString { path: String, byte_len: usize },
}

#[derive(Debug, Clone, Default)]
pub struct SanitizationGuard;

impl SanitizationGuard {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn check(&self, event: &AuditEvent) -> Result<(), SanitizationError> {
        let value = serde_json::to_value(event)?;
        check_value("$", &value)
    }
}

fn check_value(path: &str, value: &Value) -> Result<(), SanitizationError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let child_path = format!("{path}.{key}");
                if is_redacted_surface(path) && has_forbidden_key_name(key) {
                    return Err(SanitizationError::ForbiddenFieldName {
                        path: path.to_owned(),
                        field: key.clone(),
                    });
                }
                check_value(&child_path, value)?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                check_value(&format!("{path}[{index}]"), value)?;
            }
        }
        Value::String(value) => check_string(path, value)?,
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }

    Ok(())
}

fn is_redacted_surface(path: &str) -> bool {
    path.starts_with("$.argument_summary")
        || path.starts_with("$.result_summary")
        || path.starts_with("$.extensions")
        || path.starts_with("$.resource.attributes")
}

fn check_string(path: &str, value: &str) -> Result<(), SanitizationError> {
    if value.len() > MAX_SANITIZED_STRING_BYTES {
        return Err(SanitizationError::ExcessiveString {
            path: path.to_owned(),
            byte_len: value.len(),
        });
    }

    if let Some(reason) = classify_credential_like_value(value) {
        return Err(SanitizationError::CredentialLikeValue {
            path: path.to_owned(),
            reason,
        });
    }

    Ok(())
}

fn classify_credential_like_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();

    if lower.contains("-----begin ") && lower.contains(" private key-----") {
        return Some("private key marker".to_owned());
    }

    if has_auth_prefix(&lower, "bearer ") || has_auth_prefix(&lower, "basic ") {
        return Some("authorization header value".to_owned());
    }

    if contains_prefixed_secret(trimmed, "sk-", 16) {
        return Some("sk-prefixed API key".to_owned());
    }

    if contains_prefixed_secret(trimmed, "ghp_", 20)
        || contains_prefixed_secret(trimmed, "gho_", 20)
        || contains_prefixed_secret(trimmed, "ghu_", 20)
        || contains_prefixed_secret(trimmed, "ghs_", 20)
        || contains_prefixed_secret(trimmed, "ghr_", 20)
    {
        return Some("GitHub token".to_owned());
    }

    if contains_prefixed_secret(trimmed, "xoxb-", 20)
        || contains_prefixed_secret(trimmed, "xoxp-", 20)
        || contains_prefixed_secret(trimmed, "xoxa-", 20)
        || contains_prefixed_secret(trimmed, "xoxr-", 20)
    {
        return Some("Slack token".to_owned());
    }

    if contains_aws_access_key(trimmed) {
        return Some("AWS access key".to_owned());
    }

    if looks_like_jwt(trimmed) {
        return Some("JWT-like token".to_owned());
    }

    None
}

fn has_auth_prefix(lower: &str, prefix: &str) -> bool {
    lower
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.len() >= 12 && rest.chars().all(is_token_char))
}

fn contains_prefixed_secret(value: &str, prefix: &str, min_suffix_len: usize) -> bool {
    value.find(prefix).is_some_and(|index| {
        let suffix = &value[index + prefix.len()..];
        suffix.chars().take_while(|ch| is_token_char(*ch)).count() >= min_suffix_len
    })
}

fn contains_aws_access_key(value: &str) -> bool {
    value.as_bytes().windows(20).any(is_aws_access_key)
}

fn is_aws_access_key(window: &[u8]) -> bool {
    (window.starts_with(b"AKIA") || window.starts_with(b"ASIA"))
        && window[4..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn looks_like_jwt(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].len() >= 16
        && parts[1].len() >= 16
        && parts[2].len() >= 16
        && parts
            .iter()
            .all(|part| part.chars().all(is_base64_url_char))
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '~' | '+' | '/' | '=')
}

fn is_base64_url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '=')
}
