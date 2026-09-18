// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{AuditContext, AuditError, AuditEvent, EventType};

#[must_use]
pub fn governed_action(ctx: &AuditContext) -> tracing::Span {
    let span = tracing::info_span!(
        target: "apf.audit.obs",
        "apf.governed_action",
        correlation_id = %ctx.correlation_id,
        causation_id = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        user_id = optional_field(ctx.user_id.as_deref()),
        agent_id = optional_field(ctx.agent_id.as_deref()),
        workspace_id = optional_field(ctx.workspace_id.as_deref()),
        session_id = optional_field(ctx.session_id.as_deref()),
        enforcement_point_id = %ctx.enforcement_point_id,
        runtime_substrate = %ctx.runtime_substrate,
        bundle_digest = %ctx.bundle_digest,
        policy_revision = tracing::field::Empty,
        trust_root_id = %ctx.trust_root_id,
    );

    if let Some(policy_revision) = ctx.policy_revision {
        span.record("policy_revision", policy_revision);
    }
    if let Some(causation_id) = &ctx.causation_id {
        span.record("causation_id", tracing::field::display(causation_id));
    }
    if let Some(trace_id) = &ctx.trace_id {
        span.record("trace_id", tracing::field::display(trace_id));
    }
    if let Some(span_id) = &ctx.span_id {
        span.record("span_id", tracing::field::display(span_id));
    }

    span
}

#[must_use]
pub fn authorize(ctx: &AuditContext, verb: &str) -> tracing::Span {
    tracing::info_span!(
        target: "apf.audit.obs",
        "apf.authorize",
        correlation_id = %ctx.correlation_id,
        verb = %verb,
        enforcement_point_id = %ctx.enforcement_point_id,
        bundle_digest = %ctx.bundle_digest,
    )
}

#[must_use]
pub fn credential_issuance(ctx: &AuditContext, provider: &str) -> tracing::Span {
    tracing::info_span!(
        target: "apf.audit.obs",
        "apf.credential_issuance",
        correlation_id = %ctx.correlation_id,
        provider = %provider,
        enforcement_point_id = %ctx.enforcement_point_id,
        bundle_digest = %ctx.bundle_digest,
    )
}

#[must_use]
pub fn resource_call(ctx: &AuditContext, resource_type: &str, verb: &str) -> tracing::Span {
    tracing::info_span!(
        target: "apf.audit.obs",
        "apf.resource_call",
        correlation_id = %ctx.correlation_id,
        resource_type = %resource_type,
        verb = %verb,
        enforcement_point_id = %ctx.enforcement_point_id,
        bundle_digest = %ctx.bundle_digest,
    )
}

fn optional_field(value: Option<&str>) -> &str {
    value.unwrap_or("")
}

pub fn record_audit_written(event: &AuditEvent) {
    tracing::info!(
        target: "apf.audit.obs",
        event_type = %event.event_type,
        event_id = %event.event_id,
        correlation_id = %event.correlation_id,
        causation_id = event.causation_id.as_deref().unwrap_or(""),
        decision_id = event.decision_id.as_deref().unwrap_or(""),
        enforcement_point_id = %event.enforcement_point_id,
        "audit_event_written",
    );
}

pub fn record_audit_failed(ctx: &AuditContext, event_type: EventType, error: &AuditError) {
    tracing::warn!(
        target: "apf.audit.obs",
        event_type = %event_type,
        correlation_id = %ctx.correlation_id,
        enforcement_point_id = %ctx.enforcement_point_id,
        error_kind = audit_error_kind(error),
        "audit_event_failed",
    );
}

#[must_use]
pub fn audit_error_kind(error: &AuditError) -> &'static str {
    match error {
        AuditError::Validation(_) => "validation",
        AuditError::Io(_) => "io",
        AuditError::Sanitization(_) => "sanitization",
        AuditError::Serialization(_) => "serialization",
        AuditError::Lock(_) => "lock",
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        AuditError, CommonFields, Component, EventType, PolicyActivationEvent, TypedAuditEvent,
        ValidationError,
    };

    #[test]
    fn governed_action_span_can_be_constructed() {
        let mut ctx = CommonFields::new(
            "corr_test_span",
            "user:example",
            "agent:example",
            "workspace:example",
            "session:example",
            "apf-openshell-middleware:local",
            "openshell",
            Component::new("apf-openshell-middleware", "0.1.0", "middleware:0"),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "trustroot:dev",
        );
        ctx.causation_id = Some("request:test".to_owned());

        let span = super::governed_action(&ctx);
        let _entered = span.enter();
    }

    #[test]
    fn operational_spans_can_be_constructed() {
        let ctx = test_context();
        let _authorize_span = super::authorize(&ctx, "mail.search");
        let _credential_span = super::credential_issuance(&ctx, "graph");
        let _resource_span = super::resource_call(&ctx, "mailbox", "mail.search");
    }

    #[test]
    fn audit_observability_records_do_not_require_full_payloads() {
        let ctx = test_context();
        let event =
            PolicyActivationEvent::new(crate::model::Outcome::Success, "policy.bundle.loaded")
                .into_audit_event(&ctx)
                .expect("policy load event should build");

        super::record_audit_written(&event);

        let error = AuditError::Validation(ValidationError::new(vec![
            "result_summary is required".to_owned(),
        ]));
        super::record_audit_failed(&ctx, EventType::PolicyDistribution, &error);
        assert_eq!(super::audit_error_kind(&error), "validation");
    }

    fn test_context() -> CommonFields {
        CommonFields::new(
            "corr_test_span",
            "user:example",
            "agent:example",
            "workspace:example",
            "session:example",
            "apf-openshell-middleware:local",
            "openshell",
            Component::new("apf-openshell-middleware", "0.1.0", "middleware:0"),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "trustroot:dev",
        )
    }
}
