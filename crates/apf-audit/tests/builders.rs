// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{read_to_string, remove_file};

use apf_audit::{
    AuditEmitter, AuditErrorInfo, AuthorizationEvent, CommonFields, Component,
    CredentialIssuanceEvent, CredentialScope, Decision, EventType, JsonlSink, Obligations, Outcome,
    PolicyActivationEvent, PolicyDistributionEvent, PolicyVerificationEvent, RedactedObject,
    Resource, ReviewDecisionEvent, ReviewRef, ReviewRequestEvent, TypedAuditEvent,
};
use serde_json::json;
use uuid::Uuid;

fn context() -> CommonFields {
    let mut ctx = CommonFields::new(
        "corr_test_builders",
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
    ctx.bundle_id = Some("bundle:apf-v0-demo".to_owned());
    ctx.signer_id = Some("signer:dev".to_owned());
    ctx
}

fn context_without_subject() -> CommonFields {
    let mut ctx = CommonFields::new_without_subject(
        "corr_test_builders_no_subject",
        "apf-openshell-middleware:local",
        "openshell",
        Component::new("apf-openshell-middleware", "0.1.0", "middleware:0"),
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "trustroot:dev",
    );
    ctx.bundle_id = Some("bundle:apf-v0-demo".to_owned());
    ctx.signer_id = Some("signer:dev".to_owned());
    ctx
}

fn resource() -> Resource {
    let mut resource = Resource::new("mailbox", "mailbox:user:example");
    resource.resource_class = Some("outlook".to_owned());
    resource.data_class = Some("business_email".to_owned());
    resource
}

fn scope() -> CredentialScope {
    CredentialScope {
        provider: "graph".to_owned(),
        mode: Some("token_vending".to_owned()),
        audience: "graph.microsoft.com".to_owned(),
        scopes: vec!["Mail.Read".to_owned()],
        ttl_seconds: Some(600),
        expires_at: Some("2026-05-15T19:30:31.244Z".to_owned()),
        decision_id: Some("dec_test_builders".to_owned()),
    }
}

fn argument_summary() -> RedactedObject {
    BTreeMap::from([
        ("query_class".to_owned(), json!("sender_and_date")),
        ("max_results".to_owned(), json!(10)),
    ])
}

fn obligations() -> Obligations {
    Obligations {
        credential_scope: Some(scope()),
        redaction_profile: Some("pii_basic".to_owned()),
        max_result_size: Some(10),
        audit_level: Some("standard".to_owned()),
        ..Obligations::default()
    }
}

fn error_info(code: &str) -> AuditErrorInfo {
    AuditErrorInfo {
        code: code.to_owned(),
        message: "sanitized failure".to_owned(),
        retryable: Some(false),
    }
}

#[test]
fn typed_builders_create_valid_events() {
    let ctx = context();

    let events = vec![
        PolicyActivationEvent::new(Outcome::Success, "policy.bundle_loaded").into_audit_event(&ctx),
        PolicyVerificationEvent::new(Outcome::Refused, "policy.signature_invalid")
            .with_error(error_info("policy.signature_invalid"))
            .into_audit_event(&ctx),
        AuthorizationEvent::new(
            resource(),
            "mail.search",
            Decision::Allow,
            "dec_test_builders",
            "decision.allow",
        )
        .with_obligations(obligations())
        .with_argument_summary(argument_summary())
        .into_audit_event(&ctx),
        AuthorizationEvent::new(
            resource(),
            "mail.delete",
            Decision::Deny,
            "dec_test_builders_deny",
            "decision.deny",
        )
        .with_error(error_info("decision.deny"))
        .into_audit_event(&ctx),
        ReviewRequestEvent::new(
            resource(),
            "mail.send",
            "dec_test_builders_review",
            "decision.require_review",
        )
        .into_audit_event(&ctx),
        ReviewDecisionEvent::new(
            ReviewRef {
                review_id: "review:test".to_owned(),
                status: "approved".to_owned(),
                reviewer_id: Some("user:reviewer".to_owned()),
                decision_at: Some("2026-05-15T19:22:31.244Z".to_owned()),
                evidence_ref: Some("ticket:123".to_owned()),
            },
            Decision::Allow,
            "review.approved",
        )
        .into_audit_event(&ctx),
        CredentialIssuanceEvent::new(
            resource(),
            "mail.search",
            Outcome::Success,
            "credential.issued",
            "credreq_test_builders",
            scope(),
        )
        .into_audit_event(&ctx),
        CredentialIssuanceEvent::new(
            resource(),
            "mail.search",
            Outcome::Refused,
            "credential.denied",
            "credreq_test_builders_denied",
            scope(),
        )
        .with_error(error_info("credential.denied"))
        .into_audit_event(&ctx),
        PolicyDistributionEvent::new(
            resource(),
            "policy.get_document",
            Outcome::Success,
            "policy.document_vended",
        )
        .into_audit_event(&ctx),
    ];

    let events = events
        .into_iter()
        .map(|event| event.expect("typed event should convert into a valid audit event"))
        .collect::<Vec<_>>();

    let credential_refused = events
        .iter()
        .find(|event| {
            event.event_type == EventType::CredentialIssuance
                && event.outcome == Some(Outcome::Refused)
        })
        .expect("refused credential_issuance event should be built");
    assert_eq!(credential_refused.decision, None, "outcome, not decision");
}

#[test]
fn typed_builders_allow_missing_subject_identity() {
    let ctx = context_without_subject();

    let authorize = AuthorizationEvent::new(
        resource(),
        "mail.search",
        Decision::Allow,
        "dec_test_builders_no_subject",
        "decision.allow",
    )
    .with_obligations(obligations())
    .with_argument_summary(argument_summary())
    .into_audit_event(&ctx)
    .expect("authorize should not require subject identity");
    assert_eq!(authorize.user_id, None);
    assert_eq!(authorize.agent_id, None);
    assert_eq!(authorize.workspace_id, None);
    assert_eq!(authorize.session_id, None);

    let denied = AuthorizationEvent::new(
        resource(),
        "egress.request",
        Decision::Deny,
        "dec_test_builders_denied",
        "substrate.egress_denied",
    )
    .into_audit_event(&ctx)
    .expect("a denial should not require subject identity");
    assert_eq!(denied.user_id, None);
    assert_eq!(denied.agent_id, None);
    assert_eq!(denied.workspace_id, None);
    assert_eq!(denied.session_id, None);
}

#[test]
fn typed_event_display_is_safe_metadata_only() {
    let event = AuthorizationEvent::new(
        resource(),
        "mail.search",
        Decision::Allow,
        "dec_test_builders",
        "decision.allow",
    )
    .with_obligations(obligations())
    .with_argument_summary(BTreeMap::from([(
        "query_class".to_owned(),
        json!("raw-search-value"),
    )]));

    let display = event.to_string();

    assert!(display.contains("authorization"));
    assert!(display.contains("mail.search"));
    assert!(!display.contains("raw-search-value"));
}

#[test]
fn emitter_can_emit_typed_required_event() {
    let path = std::env::temp_dir().join(format!(
        "apf-audit-typed-builder-test-{}.jsonl",
        Uuid::new_v4().simple()
    ));
    let emitter = AuditEmitter::new(JsonlSink::new(path.clone()));
    let event = emitter
        .emit_typed_required(
            &context(),
            PolicyActivationEvent::new(Outcome::Success, "policy.bundle_loaded"),
        )
        .expect("typed event should write");

    assert_eq!(event.event_type, EventType::PolicyActivation);
    let contents = read_to_string(&path).expect("jsonl file should be readable");
    assert!(contents.contains("\"event_type\":\"policy_activation\""));
    let _ = remove_file(path);
}
