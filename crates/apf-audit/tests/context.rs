// SPDX-License-Identifier: Apache-2.0

use apf_audit::{
    AuditContextTemplate, Component, CorrelationContext, PolicyIdentity, SubjectIdentity,
    generate_correlation_id, generate_credential_request_id, generate_decision_id,
    generate_event_id, generate_request_id,
};

const BUNDLE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn id_helpers_generate_schema_compatible_prefixed_ids() {
    let ids = [
        (generate_event_id(), "evt_"),
        (generate_correlation_id(), "corr_"),
        (generate_request_id(), "req_"),
        (generate_decision_id(), "dec_"),
        (generate_credential_request_id(), "credreq_"),
    ];

    for (id, prefix) in ids {
        assert!(id.starts_with(prefix));
        assert_eq!(id.len(), prefix.len() + 32);
        assert!(
            id[prefix.len()..]
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
    }
}

#[test]
fn audit_context_template_derives_component_contexts() {
    let template = template();

    let gateway_context = template
        .for_component(
            "apf-policy-gateway:local",
            Component::new("apf-policy-gateway", "0.1.0", "apf-policy-gateway:local"),
        )
        .expect("policy-gateway context should be valid");
    let middleware_context = template
        .for_component_with_causation(
            "apf-openshell-middleware:local",
            Component::new("apf-openshell-middleware", "0.1.0", "middleware:0"),
            "dec_test_context",
        )
        .expect("middleware context should be valid");

    assert_eq!(
        gateway_context.correlation_id,
        middleware_context.correlation_id
    );
    assert_eq!(
        gateway_context.bundle_digest,
        middleware_context.bundle_digest
    );
    assert_eq!(
        gateway_context.bundle_id.as_deref(),
        Some("bundle:apf-v0-demo")
    );
    assert_eq!(gateway_context.signer_id.as_deref(), Some("signer:dev"));
    assert_eq!(gateway_context.device_id.as_deref(), Some("device:managed"));
    assert_eq!(
        gateway_context.deployment_profile.as_deref(),
        Some("azure-sandbox-dev")
    );
    assert_eq!(gateway_context.component.name, "apf-policy-gateway");
    assert_eq!(
        middleware_context.component.name,
        "apf-openshell-middleware"
    );
    assert_eq!(
        middleware_context.causation_id.as_deref(),
        Some("dec_test_context")
    );
}

#[test]
fn correlation_context_keeps_causation_explicit() {
    let context = CorrelationContext::root()
        .with_causation("req_test_context")
        .expect("causation id should be valid")
        .with_trace("trace_test_context", "span_test_context")
        .expect("trace ids should be valid");

    assert!(context.correlation_id().starts_with("corr_"));
    assert_eq!(context.causation_id(), Some("req_test_context"));
    assert_eq!(context.trace_id(), Some("trace_test_context"));
    assert_eq!(context.span_id(), Some("span_test_context"));
}

#[test]
fn context_helpers_reject_malformed_ids() {
    assert!(CorrelationContext::new("").is_err());
    assert!(CorrelationContext::new("bad id").is_err());
    assert!(
        CorrelationContext::root()
            .with_causation("bad causation id")
            .is_err()
    );
    assert!(
        SubjectIdentity::new("", "agent:example", "workspace:example", "session:example").is_err()
    );

    let template = template();
    assert!(
        template
            .for_component_with_causation(
                "apf-openshell-middleware:local",
                Component::new("apf-openshell-middleware", "0.1.0", "middleware:0"),
                "bad causation id",
            )
            .is_err()
    );
}

fn template() -> AuditContextTemplate {
    let subject = SubjectIdentity::new(
        "user:example",
        "agent:demo:research-assistant",
        "workspace:example",
        "session:apf-v0-demo",
    )
    .expect("subject identity should be valid")
    .with_device_id("device:managed")
    .expect("device id should be valid")
    .with_deployment_profile("azure-sandbox-dev");
    let subject = subject.expect("deployment profile should be valid");
    let policy = PolicyIdentity::new(BUNDLE_DIGEST, "trustroot:dev")
        .expect("policy identity should be valid")
        .with_policy_revision(1)
        .with_bundle_id("bundle:apf-v0-demo")
        .expect("bundle id should be valid")
        .with_signer_id("signer:dev")
        .expect("signer id should be valid");

    AuditContextTemplate::new("corr_test_context", subject, "openshell", policy)
        .expect("audit context template should be valid")
        .with_trace("trace_test_context", "span_test_context")
        .expect("trace ids should be valid")
}
