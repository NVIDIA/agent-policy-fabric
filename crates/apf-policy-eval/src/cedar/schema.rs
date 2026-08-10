// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compilation of one [`PolicyRuleDoc`] into a validated Cedar policy set.

use std::collections::HashMap;
use std::str::FromStr;

use cedar_policy::{PolicyId, PolicySet, Schema, ValidationMode, Validator};

use super::PolicyRuleDoc;
use super::effect::PolicyRefs;
use crate::EvalError;

/// A rule compiled to its own policy set and (optional) schema, evaluated in
/// isolation from every other rule.
pub struct CompiledRule {
    pub name: String,
    pub policies: PolicySet,
    #[allow(dead_code)] // Retained for request validation in later phases.
    pub schema: Option<Schema>,
    /// `@apf_effect`/`@apf_finding` references keyed by policy id, populated
    /// after compilation once the effect engine exists to validate against.
    pub effect_refs: HashMap<PolicyId, PolicyRefs>,
    /// Contributor data from `PolicyRule.spec.data`. Exposed as `context.data`.
    pub data: serde_json::Value,
    /// Role governing how the evaluator handles this rule's default-deny.
    pub role: super::PolicyRuleRole,
}

/// Parse the rule's schema and definition and validate the policies against
/// the schema. All failures are load-time errors carrying the rule name.
pub fn compile_rule(doc: &PolicyRuleDoc) -> Result<CompiledRule, EvalError> {
    let load_err = |cause: String| EvalError::Engine(format!("rule '{}': {cause}", doc.name));

    let schema = if let Some(text) = &doc.schema {
        let (schema, _warnings) = Schema::from_cedarschema_str(text)
            .map_err(|e| load_err(format!("schema parse: {e}")))?;
        Some(schema)
    } else {
        if definition_opens_with_schema(&doc.definition) {
            return Err(load_err(
                "definition starts with a schema declaration; \
                 move the Cedar schema into the rule's `schema` field"
                    .to_string(),
            ));
        }
        None
    };

    let policies =
        PolicySet::from_str(&doc.definition).map_err(|e| load_err(format!("policy parse: {e}")))?;

    if let Some(schema) = &schema {
        let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::default());
        if !result.validation_passed() {
            let causes: Vec<String> = result
                .validation_errors()
                .map(std::string::ToString::to_string)
                .collect();
            return Err(load_err(format!("validation: {}", causes.join("; "))));
        }
    }

    Ok(CompiledRule {
        name: doc.name.clone(),
        policies,
        schema,
        effect_refs: HashMap::new(),
        data: doc.data.clone(),
        role: doc.role,
    })
}

/// Whether the definition's first non-comment content is a schema
/// declaration: a `namespace` keyword appearing before any `permit`/`forbid`.
/// A definition like that would only parse as policy text by accident, so it
/// gets a targeted error pointing at the schema field instead of an opaque
/// Cedar parse failure.
fn definition_opens_with_schema(definition: &str) -> bool {
    let text: String = definition
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let position = |word: &str| {
        text.match_indices(word).find_map(|(i, _)| {
            let before_ok = i == 0
                || !text[..i]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
            let after = text[i + word.len()..].chars().next();
            let after_ok = !after.is_some_and(|c| c.is_alphanumeric() || c == '_');
            (before_ok && after_ok).then_some(i)
        })
    };
    match (
        position("namespace"),
        position("permit")
            .into_iter()
            .chain(position("forbid"))
            .min(),
    ) {
        (Some(ns), Some(head)) => ns < head,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_shaped_definition_detected() {
        assert!(definition_opens_with_schema(
            "namespace APF {\n  entity User;\n}\npermit(p, a, r);\n"
        ));
        assert!(definition_opens_with_schema(
            "namespace APF { entity User; }"
        ));
    }

    #[test]
    fn policy_text_not_flagged() {
        assert!(!definition_opens_with_schema(
            "permit(principal, action, resource);"
        ));
        // A `namespace` mention after the first policy head is policy text.
        assert!(!definition_opens_with_schema(
            "permit(principal, action, resource) when { context.namespace == \"x\" };"
        ));
        // Word-boundary check: identifiers containing the keyword don't match.
        assert!(!definition_opens_with_schema(
            "permit(p, a, r) when { context.my_namespace_id == 1 };"
        ));
    }

    #[test]
    fn leading_comments_ignored() {
        assert!(definition_opens_with_schema(
            "// a leading comment\nnamespace APF { entity User; }"
        ));
        assert!(!definition_opens_with_schema(
            "// namespace APF\npermit(principal, action, resource);"
        ));
    }
}
