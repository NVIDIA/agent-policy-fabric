// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! `policy_service_startup` — the security state of the config the service
//! started with.
//!
//! These events are emitted during preflight, before a bundle has been fetched
//! or a trust root used. The point of the tests below is that absent policy
//! identity is *correct* for this event type, not a gap to be papered over with
//! a sentinel value.

use apf_audit::{
    AuditErrorInfo, AuditEvent, Component, EventType, PolicyServiceStartupEvent, SecurityState,
    StartupContext,
};

fn gateway_ctx() -> StartupContext {
    StartupContext::new(
        "corr_boot_11111111-1111-4111-8111-111111111111",
        "apf-policy-gateway:local",
        "openshell",
        Component::new("apf-policy-gateway", "0.1.0", "gateway-0"),
    )
    .expect("startup context should be valid")
}

#[test]
fn healthy_boot_validates_without_any_policy_context() {
    let event = PolicyServiceStartupEvent::secure()
        .into_audit_event(&gateway_ctx())
        .expect("secure startup event should validate");

    assert_eq!(event.event_type, EventType::PolicyServiceStartup);
    assert_eq!(event.security_state, Some(SecurityState::Secure));
    assert_eq!(event.reason_code.as_deref(), Some("startup.secure"));

    // The whole reason this event type exists: no bundle is loaded yet.
    assert!(event.bundle_digest.is_none());
    assert!(event.trust_root_id.is_none());
    assert!(event.policy_revision.is_none());
    assert!(event.error_info.is_none());
}

#[test]
fn degraded_boot_carries_reason_and_error() {
    let event = PolicyServiceStartupEvent::degraded(
        "startup.insecure_transport_enabled",
        AuditErrorInfo {
            code: "startup.insecure_transport_enabled".to_owned(),
            message: "middleware listener: TLS and caller authentication disabled".to_owned(),
            retryable: Some(false),
        },
    )
    .into_audit_event(&gateway_ctx())
    .expect("degraded startup event should validate");

    assert_eq!(event.security_state, Some(SecurityState::Degraded));
    assert_eq!(
        event.error_info.as_ref().map(|error| error.code.as_str()),
        Some("startup.insecure_transport_enabled")
    );
}

#[test]
fn rejected_boot_validates() {
    let ctx = StartupContext::new(
        "corr_boot_22222222-2222-4222-8222-222222222222",
        "apf-policy-service:local",
        "openshell",
        Component::new("apf-policy-service", "0.1.0", "service-0"),
    )
    .expect("startup context should be valid");

    let event = PolicyServiceStartupEvent::rejected(
        "startup.trust_profile_rejected",
        AuditErrorInfo {
            code: "startup.trust_profile_rejected".to_owned(),
            message: "extension trust profile has group-write permissions".to_owned(),
            retryable: Some(false),
        },
    )
    .into_audit_event(&ctx)
    .expect("rejected startup event should validate");

    assert_eq!(event.security_state, Some(SecurityState::Rejected));
}

#[test]
fn security_state_is_required_on_a_startup_event() {
    let mut event = PolicyServiceStartupEvent::secure()
        .into_audit_event(&gateway_ctx())
        .expect("baseline event should validate");

    event.security_state = None;
    let error = event
        .validate()
        .expect_err("a startup event without security_state must be rejected");
    assert!(
        error.violations().join("; ").contains("security_state"),
        "expected a security_state violation, got {:?}",
        error.violations()
    );
}

#[test]
fn other_event_types_still_require_bundle_context() {
    // Guards the exclusion from allOf[0]: relaxing it for policy_service_startup
    // must not relax it for policy_verification, which is emitted after a bundle
    // has at least been read.
    let mut event = AuditEvent::from_startup(&gateway_ctx());
    event.event_type = EventType::PolicyVerification;
    event.reason_code = Some("policy.bundle_rejected.signature_invalid".to_owned());
    event.error_info = Some(AuditErrorInfo {
        code: "policy.bundle_rejected.signature_invalid".to_owned(),
        message: "signature mismatch".to_owned(),
        retryable: Some(false),
    });

    let error = event
        .validate()
        .expect_err("policy_verification without bundle context must still be rejected");
    let joined = error.violations().join("; ");
    assert!(joined.contains("bundle_digest"), "got {joined}");
    assert!(joined.contains("trust_root_id"), "got {joined}");
}

#[test]
fn security_state_serializes_as_snake_case_and_round_trips() {
    let event = PolicyServiceStartupEvent::degraded(
        "startup.ephemeral_signing_key",
        AuditErrorInfo {
            code: "startup.ephemeral_signing_key".to_owned(),
            message: "no signing key configured; generated ephemeral key".to_owned(),
            retryable: Some(false),
        },
    )
    .into_audit_event(&gateway_ctx())
    .expect("event should validate");

    let json = serde_json::to_string(&event).expect("event should serialize");
    assert!(json.contains(r#""event_type":"policy_service_startup""#));
    assert!(json.contains(r#""security_state":"degraded""#));
    // Absent policy identity must be omitted, not serialized as null.
    assert!(!json.contains("bundle_digest"));
    assert!(!json.contains("trust_root_id"));

    let parsed: AuditEvent = serde_json::from_str(&json).expect("event should round-trip");
    parsed
        .validate()
        .expect("round-tripped event should validate");
    assert_eq!(parsed.security_state, Some(SecurityState::Degraded));
}

#[test]
fn a_startup_event_rejects_a_decision_shaped_payload() {
    // The allOf[0] exemption is meant to relax exactly one thing: the absence
    // of a bundle at preflight. It must not become a way to write
    // authorization-shaped records with no policy identity.
    let mut event = PolicyServiceStartupEvent::secure()
        .into_audit_event(&gateway_ctx())
        .expect("baseline should validate");
    event.decision = Some(apf_audit::Decision::Allow);
    event.decision_id = Some("dec_bogus".to_owned());
    event.verb = Some("mail.search".to_owned());

    let error = event
        .validate()
        .expect_err("decision fields must not be permitted on policy_service_startup");
    let joined = error.violations().join("; ");
    assert!(joined.contains("decision"), "got {joined}");
}

#[test]
fn a_startup_event_rejects_policy_identity() {
    // A startup event describes a process, not a policy. Carrying a digest
    // would imply the security state was tied to a bundle not yet loaded.
    let mut event = PolicyServiceStartupEvent::secure()
        .into_audit_event(&gateway_ctx())
        .expect("baseline should validate");
    event.bundle_digest =
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned());

    let error = event
        .validate()
        .expect_err("policy identity must not be permitted on policy_service_startup");
    assert!(
        error.violations().join("; ").contains("bundle_digest"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn degraded_state_requires_an_error() {
    // Recording that something was weakened without recording which control
    // defeats the purpose of the event.
    let mut event = PolicyServiceStartupEvent::degraded(
        "startup.insecure_transport_enabled",
        AuditErrorInfo {
            code: "startup.insecure_transport_enabled".to_owned(),
            message: "middleware listener: TLS disabled".to_owned(),
            retryable: Some(false),
        },
    )
    .into_audit_event(&gateway_ctx())
    .expect("baseline should validate");

    event.error_info = None;
    let error = event
        .validate()
        .expect_err("a degraded state without an error must be rejected");
    assert!(
        error.violations().join("; ").contains("error"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn security_state_is_not_permitted_on_other_event_types() {
    let mut event = AuditEvent::from_startup(&gateway_ctx());
    event.event_type = EventType::PolicyActivation;
    event.security_state = Some(SecurityState::Degraded);

    let error = event
        .validate()
        .expect_err("security_state must not appear on non-startup events");
    assert!(
        error.violations().join("; ").contains("security_state"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn from_startup_clears_every_policy_identity_field() {
    // Guards the invariant at one site rather than relying on
    // `new_without_subject` defaults holding for fields added later.
    let event = AuditEvent::from_startup(&gateway_ctx());
    assert!(event.bundle_digest.is_none());
    assert!(event.bundle_id.is_none());
    assert!(event.policy_revision.is_none());
    assert!(event.signer_id.is_none());
    assert!(event.trust_root_id.is_none());
    assert_eq!(event.event_type, EventType::PolicyServiceStartup);
}

#[test]
fn a_secure_state_rejects_an_error() {
    // "Secure" means every configured control is active. An attached error
    // contradicts that, and a dashboard counting security_state==secure would
    // report a healthy fleet while the error says otherwise.
    let mut event = PolicyServiceStartupEvent::secure()
        .into_audit_event(&gateway_ctx())
        .expect("baseline should validate");
    event.error_info = Some(AuditErrorInfo {
        code: "startup.insecure_transport_enabled".to_owned(),
        message: "TLS disabled".to_owned(),
        retryable: Some(false),
    });

    let error = event
        .validate()
        .expect_err("a secure state must not carry an error");
    assert!(
        error.violations().join("; ").contains("error"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn a_startup_event_rejects_evidence_pointers() {
    // Preflight precedes any detector run, so a startup record can never
    // legitimately reference a verdict.
    let mut event = PolicyServiceStartupEvent::secure()
        .into_audit_event(&gateway_ctx())
        .expect("baseline should validate");
    event.review_ref = Some(apf_audit::ReviewRef {
        review_id: "review:1".to_owned(),
        status: "approved".to_owned(),
        reviewer_id: None,
        decision_at: None,
        evidence_ref: None,
    });

    let error = event
        .validate()
        .expect_err("evidence pointers must not be permitted on policy_service_startup");
    assert!(
        error.violations().join("; ").contains("review_ref"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn a_startup_event_rejects_subject_identity() {
    // Preflight runs before any user, agent, or session exists — which is why
    // StartupContext structurally cannot supply these.
    fn assert_rejected(field: &str, apply: impl FnOnce(&mut AuditEvent)) {
        let mut event = PolicyServiceStartupEvent::secure()
            .into_audit_event(&gateway_ctx())
            .expect("baseline should validate");
        apply(&mut event);

        let Err(error) = event.validate() else {
            panic!("{field} must not be permitted on policy_service_startup");
        };
        assert!(
            error.violations().join("; ").contains(field),
            "{field}: got {:?}",
            error.violations()
        );
    }

    assert_rejected("user_id", |e| e.user_id = Some("user:x".to_owned()));
    assert_rejected("agent_id", |e| e.agent_id = Some("agent:x".to_owned()));
    assert_rejected("session_id", |e| {
        e.session_id = Some("session:x".to_owned())
    });
    assert_rejected("workspace_id", |e| {
        e.workspace_id = Some("workspace:x".to_owned());
    });
}

#[test]
fn a_startup_event_still_allows_process_scoped_context() {
    // device_id and deployment_profile describe the booting process rather
    // than a subject, so they stay permitted.
    let mut event = PolicyServiceStartupEvent::secure()
        .into_audit_event(&gateway_ctx())
        .expect("baseline should validate");
    event.device_id = Some("host:gw-01".to_owned());
    event.deployment_profile = Some("dev".to_owned());

    event
        .validate()
        .expect("process-scoped context must remain permitted");
}
