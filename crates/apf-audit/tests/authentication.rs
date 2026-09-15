// SPDX-License-Identifier: Apache-2.0
//! `authentication` — a caller refused on identity grounds, before policy.
//!
//! Covers the four denial points in `apf-openshell-auth` and the middleware
//! that are enforced today and recorded nowhere.

use apf_audit::{
    AuditErrorInfo, AuditEvent, AuthenticationEvent, CallerKind, CommonFields, Component,
    EventType, Resource, TypedAuditEvent,
};

/// Every event type except `authentication`. A full sweep, not a spot check:
/// the auth-only fields must be rejected on all of them, not just the one type
/// anyone tries.
const NON_AUTH_EVENT_TYPES: [EventType; 13] = [
    EventType::Authorization,
    EventType::PolicyVerification,
    EventType::PolicyActivation,
    EventType::PolicyDistribution,
    EventType::PolicyRefresh,
    EventType::ProvenanceSigning,
    EventType::PolicyInjection,
    EventType::AdmissionValidation,
    EventType::ConfigGovernance,
    EventType::PolicyServiceStartup,
    EventType::ReviewRequest,
    EventType::ReviewDecision,
    EventType::CredentialIssuance,
];

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ctx() -> CommonFields {
    CommonFields::new(
        "corr_auth_1",
        "user:example",
        "agent:example",
        "workspace:example",
        "session:example",
        "apf-policy-gateway:openshell-middleware",
        "openshell",
        Component::new("apf-openshell-middleware", "0.1.0", "gw-0"),
        DIGEST,
        "trustroot:apf",
    )
}

fn error(code: &str) -> AuditErrorInfo {
    AuditErrorInfo {
        code: code.to_owned(),
        message: "caller refused".to_owned(),
        retryable: Some(false),
    }
}

#[test]
fn a_bad_credential_is_recorded_without_a_caller_identity() {
    // The verifier collapses every credential failure into one opaque status,
    // so nothing about the token is known.
    let event = AuthenticationEvent::unauthenticated(
        "auth.credential_invalid",
        error("auth.credential_invalid"),
    )
    .into_audit_event(&ctx())
    .expect("a refused caller must be auditable");

    assert_eq!(event.event_type, EventType::Authentication);
    assert!(event.caller_kind.is_none(), "no identity was established");
    // ctx() supplies all four. Carrying them through would attribute a failed
    // authentication to whoever the unverified token named.
    assert!(event.user_id.is_none(), "user_id must not survive");
    assert!(event.agent_id.is_none(), "agent_id must not survive");
    assert!(
        event.workspace_id.is_none(),
        "workspace_id must not survive"
    );
    assert!(event.session_id.is_none(), "session_id must not survive");
}

#[test]
fn a_sandbox_binding_mismatch_records_the_authenticated_kind() {
    // A valid supervisor token scoped to one sandbox, used on another. The
    // identity is known here, so recording it is the point.
    let event = AuthenticationEvent::sandbox_binding_mismatch(
        "sandbox:bound-to-token",
        "sandbox:claimed-by-request",
        "auth.sandbox_binding_mismatch",
        error("auth.sandbox_binding_mismatch"),
    )
    .into_audit_event(&ctx())
    .expect("should validate");

    assert_eq!(
        event.caller_kind.as_deref(),
        Some(CallerKind::Supervisor.as_str())
    );
    // Either id alone says a mismatch happened without saying which sandbox
    // impersonated which — the only question this event answers.
    assert_eq!(
        event.caller_sandbox_id.as_deref(),
        Some("sandbox:bound-to-token")
    );
    assert_eq!(
        event.claimed_sandbox_id.as_deref(),
        Some("sandbox:claimed-by-request")
    );
}

#[test]
fn a_caller_kind_not_permitted_for_the_rpc_is_recorded() {
    // Authenticated, but the wrong caller kind for this RPC.
    let event = AuthenticationEvent::authenticated(
        CallerKind::Gateway,
        "auth.caller_kind_not_allowed",
        error("auth.caller_kind_not_allowed"),
    )
    .with_target(Resource::new("rpc", "EvaluateHttpRequest"), "rpc.call")
    .into_audit_event(&ctx())
    .expect("should validate");

    assert_eq!(
        event.caller_kind.as_deref(),
        Some(CallerKind::Gateway.as_str())
    );
    assert!(event.resource.is_some() && event.verb.is_some());
}

#[test]
fn an_authentication_carries_no_policy_identity() {
    // No bundle is consulted to reach this outcome.
    let event =
        AuthenticationEvent::unauthenticated("auth.caller_missing", error("auth.caller_missing"))
            .into_audit_event(&ctx())
            .expect("should validate");

    let json = serde_json::to_value(&event).expect("should serialize");
    for absent in [
        "bundle_digest",
        "trust_root_id",
        "policy_revision",
        "bundle_id",
    ] {
        assert!(
            json.get(absent).is_none(),
            "authentication must not carry {absent}"
        );
    }
}

#[test]
fn an_authentication_requires_its_error() {
    // A bare authentication says a caller was refused and nothing about why.
    let mut event = AuthenticationEvent::unauthenticated("auth.credential_invalid", error("x"))
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.error_info = None;

    let failure = event.validate().expect_err("error must be required");
    assert!(
        failure.violations().join("; ").contains("error"),
        "got {:?}",
        failure.violations()
    );
}

#[test]
fn an_authentication_cannot_claim_it_was_allowed() {
    let mut event = AuthenticationEvent::unauthenticated("auth.credential_invalid", error("x"))
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.result_class = Some(apf_audit::ResultClass::Success);

    event
        .validate()
        .expect_err("a denial must not carry a success result class");
}

#[test]
fn a_denial_needs_no_subject_to_be_recordable() {
    // Counterpart to forbidding them: a credential failure knows least, and
    // must still produce a complete record.
    let event = AuthenticationEvent::unauthenticated("auth.credential_invalid", error("x"))
        .into_audit_event(&ctx())
        .expect("a denial with no established subject must still be recordable");

    let json = serde_json::to_value(&event).expect("should serialize");
    for absent in ["user_id", "agent_id", "workspace_id", "session_id"] {
        assert!(json.get(absent).is_none(), "{absent} must not be present");
    }
    assert!(
        json.get("reason_code").is_some(),
        "the record still says why"
    );
}

#[test]
fn caller_kind_is_confined_to_authentication() {
    // Meaningless on an event about an already-established subject.
    for event_type in NON_AUTH_EVENT_TYPES {
        let mut event = AuditEvent::new(event_type, ctx());
        event.caller_kind = Some(CallerKind::Supervisor.into());

        let violations = match event.validate() {
            Ok(()) => String::new(),
            Err(error) => error.violations().join("; "),
        };
        assert!(
            violations.contains("caller_kind"),
            "{event_type} must not carry caller_kind"
        );
    }
}

#[test]
fn subject_identity_is_forbidden_not_merely_dropped() {
    // The builder clears it; the schema is what stops a hand-built event
    // quietly publishing a token's claim about who the caller was.
    let mut event = AuthenticationEvent::unauthenticated("auth.credential_invalid", error("x"))
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.user_id = Some("user:victim".to_owned());

    let failure = event
        .validate()
        .expect_err("an unverified subject must not be recordable on authentication");
    assert!(
        failure.violations().join("; ").contains("user_id"),
        "got {:?}",
        failure.violations()
    );
}

#[test]
fn a_sandbox_id_is_recorded_whatever_shape_it_takes() {
    // claimed_sandbox_id comes from the request, so it is attacker-controlled
    // at exactly the moment it matters. A charset rule would drop the record of
    // the impersonation attempt it exists to capture.
    for claimed in [
        "sandbox:normal",
        "../../etc/passwd",
        "sandbox with spaces",
        "sandbox|pipe~tilde",
        "既存のサンドボックス",
        "-leading-dash",
    ] {
        let event = AuthenticationEvent::sandbox_binding_mismatch(
            "sandbox:bound",
            claimed,
            "auth.sandbox_binding_mismatch",
            error("auth.sandbox_binding_mismatch"),
        )
        .into_audit_event(&ctx());

        assert!(
            event.is_ok(),
            "a mismatch claiming {claimed:?} must still be recorded: {:?}",
            event.err().map(|e| e.violations().to_vec())
        );
    }
}

#[test]
fn the_sandbox_pair_is_confined_to_authentication() {
    for event_type in NON_AUTH_EVENT_TYPES {
        let mut event = AuditEvent::new(event_type, ctx());
        event.caller_sandbox_id = Some("sandbox:a".to_owned());
        event.claimed_sandbox_id = Some("sandbox:b".to_owned());

        let violations = match event.validate() {
            Ok(()) => String::new(),
            Err(error) => error.violations().join("; "),
        };
        assert!(
            violations.contains("sandbox_id"),
            "{event_type} must not carry the auth sandbox pair"
        );
    }
}

#[test]
fn half_a_sandbox_binding_is_not_evidence() {
    // The constructor makes this unrepresentable; dependentRequired is what
    // stops a hand-built event sidestepping it.
    for (caller, claimed) in [(Some("sandbox:a"), None), (None, Some("sandbox:b"))] {
        let mut event = AuthenticationEvent::authenticated(
            CallerKind::Supervisor,
            "auth.sandbox_binding_mismatch",
            error("auth.sandbox_binding_mismatch"),
        )
        .into_audit_event(&ctx())
        .expect("baseline should validate");
        event.caller_sandbox_id = caller.map(str::to_owned);
        event.claimed_sandbox_id = claimed.map(str::to_owned);

        event
            .validate()
            .expect_err("half a binding must not validate");
    }
}

#[test]
fn only_a_supervisor_can_have_a_sandbox_binding() {
    // verify_token gives every gateway caller sandbox_id: None, so there is
    // nothing for a claimed id to be a mismatch against.
    let mut event = AuthenticationEvent::authenticated(
        CallerKind::Gateway,
        "auth.sandbox_binding_mismatch",
        error("auth.sandbox_binding_mismatch"),
    )
    .into_audit_event(&ctx())
    .expect("baseline should validate");
    event.caller_sandbox_id = Some("sandbox:a".to_owned());
    event.claimed_sandbox_id = Some("sandbox:b".to_owned());

    event
        .validate()
        .expect_err("a gateway caller has no sandbox binding to record");
}

#[test]
fn an_unauthenticated_denial_cannot_claim_a_binding() {
    let mut event = AuthenticationEvent::unauthenticated("auth.credential_invalid", error("x"))
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.caller_sandbox_id = Some("sandbox:a".to_owned());
    event.claimed_sandbox_id = Some("sandbox:b".to_owned());

    let failure = event
        .validate()
        .expect_err("no caller was established, so no binding was verified");
    assert!(
        failure.violations().join("; ").contains("caller_kind"),
        "got {:?}",
        failure.violations()
    );
}

#[test]
fn a_caller_class_from_another_runtime_is_still_recordable() {
    // Caller classes are defined by each substrate's authentication protocol.
    // OpenShell's happen to be gateway and supervisor; a closed enum would
    // reject a second runtime's auth denial outright, losing the record of a
    // refusal that was still enforced.
    for kind in ["gateway", "supervisor", "workload", "sidecar", "node-agent"] {
        let event = AuthenticationEvent::authenticated(kind, "auth.caller_not_allowed", error("x"))
            .into_audit_event(&ctx());

        assert!(
            event.is_ok(),
            "caller class {kind} must be recordable: {:?}",
            event.err().map(|e| e.violations().to_vec())
        );
    }
}
