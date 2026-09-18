// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde_json::{Map, Number, Value};

use crate::model::RedactedObject;
use crate::validation::has_forbidden_key_name;

const DEFAULT_MAX_STRING_BYTES: usize = 512;
const DEFAULT_MAX_ARRAY_ITEMS: usize = 25;
const DEFAULT_MAX_OBJECT_FIELDS: usize = 25;
const DEFAULT_MAX_DEPTH: usize = 4;
const DEFAULT_MAX_TOTAL_VALUES: usize = 250;
const SCHEMA_MAX_STRING_BYTES: usize = 2048;
const SCHEMA_MAX_ARRAY_ITEMS: usize = 100;
const SCHEMA_MAX_OBJECT_FIELDS: usize = 100;
const SCHEMA_MAX_TOTAL_VALUES: usize = 1_000;
const HELPER_MAX_DEPTH: usize = 2;
const MAX_LABEL_BYTES: usize = 128;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RedactionError {
    #[error("redaction payload must be a JSON object")]
    NonObjectPayload,
    #[error("redaction profile name must not be empty")]
    EmptyProfileName,
    #[error("redaction profile name is not an audit-safe label: {0}")]
    InvalidProfileName(String),
    #[error("redaction resource type is not an audit-safe label: {0}")]
    InvalidResourceType(String),
    #[error("redaction allowlist field must not be empty")]
    EmptyAllowedField,
    #[error("redaction allowlist field is forbidden in audit summaries: {0}")]
    ForbiddenAllowedField(String),
    #[error("redaction allowlist field is not an audit-safe key: {0}")]
    InvalidAllowedField(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionProfile {
    name: String,
    allowed_fields: BTreeSet<String>,
    max_string_bytes: usize,
    max_array_items: usize,
    max_object_fields: usize,
    max_depth: usize,
    max_total_values: usize,
}

impl RedactionProfile {
    /// Creates a conservative profile that drops all payload fields unless the
    /// producer explicitly allowlists them.
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty. Use [`Self::try_new`] when profile names are
    /// loaded from configuration.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self::try_new(name).expect("redaction profile name must not be empty")
    }

    pub fn try_new(name: impl Into<String>) -> Result<Self, RedactionError> {
        let name = name.into();
        if name.is_empty() {
            return Err(RedactionError::EmptyProfileName);
        }
        if !is_safe_label(&name) {
            return Err(RedactionError::InvalidProfileName(name));
        }

        Ok(Self {
            name,
            allowed_fields: BTreeSet::new(),
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            max_array_items: DEFAULT_MAX_ARRAY_ITEMS,
            max_object_fields: DEFAULT_MAX_OBJECT_FIELDS,
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_values: DEFAULT_MAX_TOTAL_VALUES,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn allowed_fields(&self) -> &BTreeSet<String> {
        &self.allowed_fields
    }

    pub fn add_allowed_field(&mut self, field: impl Into<String>) -> Result<(), RedactionError> {
        let field = field.into();
        validate_allowed_field(&field)?;
        self.allowed_fields.insert(field);
        Ok(())
    }

    pub fn with_allowed_field(mut self, field: impl Into<String>) -> Result<Self, RedactionError> {
        self.add_allowed_field(field)?;
        Ok(self)
    }

    pub fn with_allowed_fields<I, S>(mut self, fields: I) -> Result<Self, RedactionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for field in fields {
            self.add_allowed_field(field)?;
        }
        Ok(self)
    }

    #[must_use]
    pub fn with_limits(
        mut self,
        max_string_bytes: usize,
        max_array_items: usize,
        max_depth: usize,
    ) -> Self {
        self.max_string_bytes = max_string_bytes.min(SCHEMA_MAX_STRING_BYTES);
        self.max_array_items = max_array_items.min(SCHEMA_MAX_ARRAY_ITEMS);
        self.max_object_fields = self.max_object_fields.min(SCHEMA_MAX_OBJECT_FIELDS);
        self.max_depth = max_depth.min(HELPER_MAX_DEPTH);
        self.max_total_values = self
            .max_array_items
            .saturating_mul(self.max_object_fields)
            .min(SCHEMA_MAX_TOTAL_VALUES);
        self
    }
}

/// Builds a deterministic audit-safe summary for a producer payload.
///
/// The helper only preserves top-level fields explicitly allowlisted by the
/// profile. Forbidden key names are dropped recursively, large or suspicious
/// strings are replaced with length/class metadata, and the returned object is
/// shaped to pass APF redacted-object validation.
pub fn redact(
    resource_type: impl Into<String>,
    payload: &Value,
    profile: &RedactionProfile,
) -> Result<RedactedObject, RedactionError> {
    let Some(object) = payload.as_object() else {
        return Err(RedactionError::NonObjectPayload);
    };

    let mut summary = RedactedObject::new();
    let resource_type = resource_type.into();
    if !resource_type.is_empty() {
        if !is_safe_label(&resource_type) {
            return Err(RedactionError::InvalidResourceType(resource_type));
        }
        summary.insert("resource_type".to_owned(), Value::String(resource_type));
    }
    summary.insert(
        "redaction_profile".to_owned(),
        Value::String(profile.name.clone()),
    );
    summary.insert("payload_included".to_owned(), Value::Bool(false));
    summary.insert("field_count".to_owned(), number_from_usize(object.len()));

    let mut fields = Map::new();
    let mut dropped_field_count = 0usize;
    let mut summarized_field_count = 0usize;
    let mut truncated_fields = false;
    let mut budget = RedactionBudget::new(profile.max_total_values);

    for (key, value) in object {
        if has_forbidden_key_name(key) {
            dropped_field_count += 1;
            continue;
        }

        if profile.allowed_fields.contains(key) {
            if fields.len() >= profile.max_object_fields {
                summarized_field_count += 1;
                truncated_fields = true;
                continue;
            }

            fields.insert(
                key.clone(),
                redact_value(value, profile, 0, &mut dropped_field_count, &mut budget),
            );
        } else {
            summarized_field_count += 1;
        }
    }

    let retained_field_count = fields.len();
    if retained_field_count > 0 {
        summary.insert("fields".to_owned(), Value::Object(fields));
    }
    if truncated_fields {
        summary.insert("fields_truncated".to_owned(), Value::Bool(true));
    }
    if budget.truncated {
        summary.insert("budget_truncated".to_owned(), Value::Bool(true));
    }
    summary.insert(
        "retained_field_count".to_owned(),
        number_from_usize(retained_field_count),
    );
    summary.insert(
        "summarized_field_count".to_owned(),
        number_from_usize(summarized_field_count),
    );
    summary.insert(
        "dropped_field_count".to_owned(),
        number_from_usize(dropped_field_count),
    );

    Ok(summary)
}

fn validate_allowed_field(field: &str) -> Result<(), RedactionError> {
    if field.is_empty() {
        return Err(RedactionError::EmptyAllowedField);
    }

    if has_forbidden_key_name(field) {
        return Err(RedactionError::ForbiddenAllowedField(field.to_owned()));
    }
    if !is_safe_key(field) {
        return Err(RedactionError::InvalidAllowedField(field.to_owned()));
    }

    Ok(())
}

fn redact_value(
    value: &Value,
    profile: &RedactionProfile,
    depth: usize,
    dropped_field_count: &mut usize,
    budget: &mut RedactionBudget,
) -> Value {
    if !budget.take() {
        return value_class(value);
    }

    if depth >= profile.max_depth {
        budget.truncated = true;
        return value_class(value);
    }

    match value {
        Value::String(value) => redact_string(value, profile),
        Value::Array(values) => redact_array(values, profile, depth, dropped_field_count, budget),
        Value::Object(object) => redact_object(object, profile, depth, dropped_field_count, budget),
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    }
}

fn redact_string(value: &str, profile: &RedactionProfile) -> Value {
    let mut summary = Map::new();
    summary.insert("value_class".to_owned(), Value::String("string".to_owned()));
    summary.insert("byte_len".to_owned(), number_from_usize(value.len()));
    if value.len() > profile.max_string_bytes {
        summary.insert("truncated".to_owned(), Value::Bool(true));
    }
    Value::Object(summary)
}

fn redact_array(
    values: &[Value],
    profile: &RedactionProfile,
    depth: usize,
    dropped_field_count: &mut usize,
    budget: &mut RedactionBudget,
) -> Value {
    let mut summary = Map::new();
    summary.insert("item_count".to_owned(), number_from_usize(values.len()));

    let retained_values = values
        .iter()
        .take(profile.max_array_items)
        .map(|value| redact_value(value, profile, depth + 1, dropped_field_count, budget))
        .collect::<Vec<_>>();

    if !retained_values.is_empty() {
        summary.insert("items".to_owned(), Value::Array(retained_values));
    }
    if values.len() > profile.max_array_items {
        summary.insert("truncated".to_owned(), Value::Bool(true));
    }

    Value::Object(summary)
}

fn redact_object(
    object: &Map<String, Value>,
    profile: &RedactionProfile,
    depth: usize,
    dropped_field_count: &mut usize,
    budget: &mut RedactionBudget,
) -> Value {
    let mut summary = Map::new();
    summary.insert("value_class".to_owned(), Value::String("object".to_owned()));
    summary.insert("property_count".to_owned(), number_from_usize(object.len()));

    for (index, (key, value)) in object.iter().enumerate() {
        if index >= profile.max_object_fields {
            summary.insert("fields_truncated".to_owned(), Value::Bool(true));
            break;
        }
        if has_forbidden_key_name(key) || !is_safe_key(key) {
            *dropped_field_count += 1;
            continue;
        }
        if budget.is_exhausted() {
            budget.truncated = true;
            summary.insert("budget_truncated".to_owned(), Value::Bool(true));
            break;
        }

        count_dropped_keys(value, profile, depth + 1, dropped_field_count, budget);
    }

    Value::Object(summary)
}

fn count_dropped_keys(
    value: &Value,
    profile: &RedactionProfile,
    depth: usize,
    dropped_field_count: &mut usize,
    budget: &mut RedactionBudget,
) {
    if depth >= profile.max_depth || !budget.take() {
        return;
    }

    match value {
        Value::Array(values) => {
            for value in values.iter().take(profile.max_array_items) {
                count_dropped_keys(value, profile, depth + 1, dropped_field_count, budget);
            }
        }
        Value::Object(object) => {
            for (index, (key, value)) in object.iter().enumerate() {
                if index >= profile.max_object_fields {
                    break;
                }
                if has_forbidden_key_name(key) || !is_safe_key(key) {
                    *dropped_field_count += 1;
                    continue;
                }
                count_dropped_keys(value, profile, depth + 1, dropped_field_count, budget);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[derive(Debug)]
struct RedactionBudget {
    remaining: usize,
    truncated: bool,
}

impl RedactionBudget {
    fn new(remaining: usize) -> Self {
        Self {
            remaining,
            truncated: false,
        }
    }

    fn take(&mut self) -> bool {
        if self.remaining == 0 {
            self.truncated = true;
            return false;
        }

        self.remaining -= 1;
        true
    }

    fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }
}

fn value_class(value: &Value) -> Value {
    let mut summary = Map::new();
    let class = match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    summary.insert("value_class".to_owned(), Value::String(class.to_owned()));
    Value::Object(summary)
}

fn is_safe_label(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES {
        return false;
    }

    let mut chars = value.chars();
    let starts_valid = chars.next().is_some_and(|ch| ch.is_ascii_alphanumeric());
    let rest_valid =
        chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'));
    starts_valid && rest_valid
}

fn is_safe_key(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES {
        return false;
    }

    let mut chars = value.chars();
    let starts_valid = chars.next().is_some_and(|ch| ch.is_ascii_alphabetic());
    let rest_valid = chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    starts_valid && rest_valid
}

fn number_from_usize(value: usize) -> Value {
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    Value::Number(Number::from(value))
}
