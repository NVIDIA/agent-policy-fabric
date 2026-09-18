// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::sync::OnceLock;

use serde_json::Value;

use crate::AUDIT_EVENT_SCHEMA_JSON;
use crate::model::{AuditEvent, RedactedObject, Resource};

const REDACTED_MAX_DEPTH: usize = 8;

static AUDIT_SCHEMA_VALIDATOR: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();

pub type ValidationResult<T> = Result<T, ValidationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    violations: Vec<String>,
}

impl ValidationError {
    #[must_use]
    pub fn new(violations: Vec<String>) -> Self {
        Self { violations }
    }

    #[must_use]
    pub fn violations(&self) -> &[String] {
        &self.violations
    }
}

impl Display for ValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "audit event validation failed: {}",
            self.violations.join("; ")
        )
    }
}

impl std::error::Error for ValidationError {}

impl AuditEvent {
    pub fn validate(&self) -> ValidationResult<()> {
        let mut errors = Vec::new();
        check_audit_safety_invariants(&mut errors, self);
        if errors.is_empty() {
            errors = validate_with_json_schema(self);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(errors))
        }
    }
}

fn validate_with_json_schema(event: &AuditEvent) -> Vec<String> {
    let value = match serde_json::to_value(event) {
        Ok(value) => value,
        Err(error) => {
            return vec![format!(
                "event serialization failed before schema validation: {error}"
            )];
        }
    };

    let validator = match audit_schema_validator() {
        Ok(validator) => validator,
        Err(error) => {
            return vec![format!(
                "audit schema validator failed to initialize: {error}"
            )];
        }
    };

    let mut seen = BTreeSet::new();
    validator
        .iter_errors(&value)
        .map(|error| format_schema_error(&error))
        // `envelope` is applied at the root and again inside each event def —
        // the root ref is what produces a clean error when no dispatch branch
        // matches, so both are load-bearing. The cost is that an envelope
        // violation is reported twice, identically. Deduplicating is safe
        // precisely because the messages are identical: no information is lost,
        // unlike filtering by kind.
        .filter(|violation| seen.insert(violation.clone()))
        .collect()
}

fn audit_schema_validator() -> Result<&'static jsonschema::Validator, String> {
    match AUDIT_SCHEMA_VALIDATOR.get_or_init(build_schema_validator) {
        Ok(validator) => Ok(validator),
        Err(error) => Err(error.clone()),
    }
}

fn build_schema_validator() -> Result<jsonschema::Validator, String> {
    let schema = serde_json::from_str::<Value>(AUDIT_EVENT_SCHEMA_JSON)
        .map_err(|error| format!("schema JSON parse failed: {error}"))?;

    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .with_pattern_options(jsonschema::PatternOptions::regex())
        .build(&schema)
        .map_err(|error| format!("schema compilation failed: {error}"))
}

fn format_schema_error(error: &jsonschema::ValidationError<'_>) -> String {
    let path = error.instance_path().to_string();
    if path.is_empty() {
        error.to_string()
    } else {
        format!("{path}: {error}")
    }
}

fn check_audit_safety_invariants(errors: &mut Vec<String>, event: &AuditEvent) {
    if let Some(argument_summary) = &event.argument_summary {
        check_redacted_object_depth(errors, "argument_summary", argument_summary);
    }
    if let Some(result_summary) = &event.result_summary {
        check_redacted_object_depth(errors, "result_summary", result_summary);
    }
    if let Some(extensions) = &event.extensions {
        check_extensions(errors, extensions);
    }
    if let Some(resource) = &event.resource {
        check_resource_attributes(errors, resource);
    }
}

fn check_resource_attributes(errors: &mut Vec<String>, resource: &Resource) {
    if let Some(attributes) = &resource.attributes {
        for key in attributes.keys() {
            check_safe_key(errors, "resource.attributes", key);
        }
    }
}

fn check_extensions(errors: &mut Vec<String>, extensions: &BTreeMap<String, RedactedObject>) {
    for (key, value) in extensions {
        check_redacted_object_depth(errors, &format!("extensions.{key}"), value);
    }
}

fn check_redacted_object_depth(errors: &mut Vec<String>, path: &str, object: &RedactedObject) {
    for (key, value) in object {
        check_safe_key(errors, path, key);
        check_redacted_value_depth(errors, &format!("{path}.{key}"), value, 1);
    }
}

fn check_redacted_value_depth(errors: &mut Vec<String>, path: &str, value: &Value, depth: usize) {
    require(
        errors,
        depth <= REDACTED_MAX_DEPTH,
        &format!("{path} exceeds redacted object depth {REDACTED_MAX_DEPTH}"),
    );
    if depth > REDACTED_MAX_DEPTH {
        return;
    }

    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                check_redacted_value_depth(errors, &format!("{path}[{index}]"), value, depth + 1);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                check_safe_key(errors, path, key);
                check_redacted_value_depth(errors, &format!("{path}.{key}"), value, depth + 1);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn check_safe_key(errors: &mut Vec<String>, path: &str, key: &str) {
    require(
        errors,
        !has_forbidden_key_name(key),
        &format!("{path}.{key}: forbidden sensitive field name"),
    );
}

fn require(errors: &mut Vec<String>, condition: bool, message: &str) {
    if !condition {
        errors.push(message.to_owned());
    }
}

pub(crate) fn has_forbidden_key_name(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "credential",
        "private_key",
        "api_key",
        "apikey",
        "refresh_token",
        "access_token",
        "cookie",
        "authorization",
        "body",
        "text",
        "raw",
        "message",
        "file_content",
    ]
    .iter()
    .any(|forbidden| normalized.contains(forbidden))
}
