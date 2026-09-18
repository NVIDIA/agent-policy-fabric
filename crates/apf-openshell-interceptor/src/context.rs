// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Extract OpenShell context from an InterceptorEvaluation and build RuntimeContext.

use std::collections::HashMap;

use prost_types::Struct;
use serde_json::Value as JsonValue;

use crate::proto::{InterceptorEvaluation, interceptor_evaluation};
use apf_proto::json::struct_to_json;
use apf_proto::runtime_v1alpha1::{OpenShellContext, RuntimeContext, runtime_context::Platform};

/// Contextual fields extracted from an `InterceptorEvaluation` for a sandbox operation.
#[derive(Debug)]
pub struct SandboxReviewContext {
    pub sandbox_id: String,
    pub user_subject: String,
    pub agent_type: String,
    /// Locally generated; no `request_id` in the new proto.
    pub correlation_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("operation missing name (sandbox_id)")]
    MissingSandboxId,
}

/// Return the proposed-operation `Struct` from whichever phase variant carries one.
///
/// `ModifyOperation` and `Validate` both carry `proposed_operation`; `PostCommit` does not.
#[must_use]
pub fn operation_struct(eval: &InterceptorEvaluation) -> Option<&Struct> {
    match eval.phase.as_ref()? {
        interceptor_evaluation::Phase::ModifyOperation(m) => m.proposed_operation.as_ref(),
        interceptor_evaluation::Phase::Validate(v) => v.proposed_operation.as_ref(),
        interceptor_evaluation::Phase::PostCommit(_) => None,
    }
}

/// Extract `SandboxReviewContext` from an `InterceptorEvaluation`.
pub fn extract(eval: &InterceptorEvaluation) -> Result<SandboxReviewContext, ContextError> {
    let op = operation_struct(eval).map_or(JsonValue::Null, struct_to_json);

    // CreateSandboxRequest has name as a top-level field (not under metadata).
    let sandbox_id = op
        .pointer("/name")
        .and_then(JsonValue::as_str)
        .ok_or(ContextError::MissingSandboxId)?
        .to_string();

    let user_subject = eval.principal.get("subject").cloned().unwrap_or_default();

    // Labels are top-level in CreateSandboxRequest.
    let agent_type = op
        .pointer("/labels/agent-type")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();

    let correlation_id = uuid::Uuid::new_v4().to_string();

    Ok(SandboxReviewContext {
        sandbox_id,
        user_subject,
        agent_type,
        correlation_id,
    })
}

/// Build a `RuntimeContext` from the extracted sandbox context.
#[must_use]
pub fn to_runtime_context(ctx: &SandboxReviewContext) -> RuntimeContext {
    let mut audit_context = HashMap::new();
    audit_context.insert("correlation_id".to_string(), ctx.correlation_id.clone());

    RuntimeContext {
        platform: Some(Platform::Openshell(OpenShellContext {
            sandbox_id: ctx.sandbox_id.clone(),
            user_subject: ctx.user_subject.clone(),
            agent_type: ctx.agent_type.clone(),
        })),
        audit_context,
    }
}

/// Contextual fields extracted from an `InterceptorEvaluation` for a provider profile operation.
#[derive(Debug)]
pub struct ProviderReviewContext {
    pub user_subject: String,
    pub correlation_id: String,
}

/// Extract `ProviderReviewContext` from an `InterceptorEvaluation`.
#[must_use]
pub fn extract_provider(eval: &InterceptorEvaluation) -> ProviderReviewContext {
    let user_subject = eval.principal.get("subject").cloned().unwrap_or_default();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    ProviderReviewContext {
        user_subject,
        correlation_id,
    }
}

/// Build a `RuntimeContext` from the extracted provider context.
#[must_use]
pub fn to_provider_runtime_context(ctx: &ProviderReviewContext) -> RuntimeContext {
    let mut audit_context = HashMap::new();
    audit_context.insert("correlation_id".to_string(), ctx.correlation_id.clone());
    RuntimeContext {
        platform: Some(Platform::Openshell(OpenShellContext {
            sandbox_id: String::new(),
            user_subject: ctx.user_subject.clone(),
            agent_type: String::new(),
        })),
        audit_context,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::{Struct, Value as ProstValue, value::Kind};

    fn make_struct(fields: Vec<(&str, ProstValue)>) -> Struct {
        Struct {
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    fn string_val(s: &str) -> ProstValue {
        ProstValue {
            kind: Some(Kind::StringValue(s.to_string())),
        }
    }

    fn struct_val(s: Struct) -> ProstValue {
        ProstValue {
            kind: Some(Kind::StructValue(s)),
        }
    }

    fn eval_with_operation(operation: Struct) -> InterceptorEvaluation {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        InterceptorEvaluation {
            phase: Some(Phase::Validate(ValidateEvaluation {
                proposed_operation: Some(operation),
                ..Default::default()
            })),
            principal: [
                ("subject".to_string(), "user@example.com".to_string()),
                ("kind".to_string(), "user".to_string()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }
    }

    fn sandbox_operation(name: &str, agent_type: Option<&str>) -> Struct {
        let mut label_fields = vec![];
        if let Some(at) = agent_type {
            label_fields.push(("agent-type", string_val(at)));
        }
        let labels = make_struct(label_fields);
        make_struct(vec![
            ("name", string_val(name)),
            ("labels", struct_val(labels)),
        ])
    }

    #[test]
    fn missing_name_returns_error() {
        let empty = make_struct(vec![]);
        let eval = eval_with_operation(empty);
        let err = extract(&eval).unwrap_err();
        assert!(matches!(err, ContextError::MissingSandboxId));
    }

    #[test]
    fn present_name_is_extracted() {
        let op = sandbox_operation("my-sandbox", None);
        let eval = eval_with_operation(op);
        let ctx = extract(&eval).unwrap();
        assert_eq!(ctx.sandbox_id, "my-sandbox");
        assert_eq!(ctx.user_subject, "user@example.com");
        assert!(!ctx.correlation_id.is_empty());
    }

    #[test]
    fn absent_agent_type_label_defaults_to_empty() {
        let op = sandbox_operation("s1", None);
        let eval = eval_with_operation(op);
        let ctx = extract(&eval).unwrap();
        assert_eq!(ctx.agent_type, "");
    }

    #[test]
    fn present_agent_type_label_is_extracted() {
        let op = sandbox_operation("s2", Some("claude-code"));
        let eval = eval_with_operation(op);
        let ctx = extract(&eval).unwrap();
        assert_eq!(ctx.agent_type, "claude-code");
    }

    #[test]
    fn audit_context_has_correlation_id() {
        let op = sandbox_operation("s3", None);
        let eval = eval_with_operation(op);
        let ctx = extract(&eval).unwrap();
        let rt = to_runtime_context(&ctx);
        assert!(rt.audit_context.contains_key("correlation_id"));
    }

    #[test]
    fn runtime_context_carries_openshell_platform() {
        let op = sandbox_operation("s4", Some("cursor"));
        let eval = eval_with_operation(op);
        let ctx = extract(&eval).unwrap();
        let rt = to_runtime_context(&ctx);
        let Platform::Openshell(os) = rt.platform.unwrap();
        assert_eq!(os.sandbox_id, "s4");
        assert_eq!(os.user_subject, "user@example.com");
        assert_eq!(os.agent_type, "cursor");
    }

    #[test]
    fn provider_extract_user_subject() {
        let eval = InterceptorEvaluation {
            principal: [("subject".to_string(), "alice@example.com".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let ctx = extract_provider(&eval);
        assert_eq!(ctx.user_subject, "alice@example.com");
    }

    #[test]
    fn provider_audit_context_has_correlation_id() {
        let eval = InterceptorEvaluation {
            principal: [("subject".to_string(), "bob@example.com".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let ctx = extract_provider(&eval);
        let rt = to_provider_runtime_context(&ctx);
        assert!(rt.audit_context.contains_key("correlation_id"));
    }
}
