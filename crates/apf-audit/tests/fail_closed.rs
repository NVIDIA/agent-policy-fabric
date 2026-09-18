// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use apf_audit::{
    AuditContext, AuditContextTemplate, AuditEmitter, AuditError, AuditEvent, AuditSink,
    AuthorizationEvent, Component, CredentialIssuanceEvent, CredentialScope, Decision, EventType,
    Obligations, Outcome, PolicyActivationEvent, PolicyIdentity, RedactedObject, RedactionProfile,
    Resource, SubjectIdentity, generate_correlation_id, generate_credential_request_id,
    generate_decision_id, generate_request_id, redact,
};
use serde_json::json;

const BUNDLE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn required_credential_audit_failure_prevents_wrapper_invocation() {
    // The credential-issuance record is the last required audit before the
    // egress call. If it cannot be written, the call must not be made — an
    // issued-but-unrecorded credential is exactly the unsafe state fail-closed
    // emission exists to prevent.
    let sink = RecordingSink::fail_on(EventType::CredentialIssuance);
    let wrapper = SpyOutlookWrapper::default();
    let agent = MockAgent::new(sink.clone(), wrapper.clone());

    let error = agent
        .mail_search("sender_and_date")
        .expect_err("credential audit failure should fail closed");

    assert!(
        error
            .to_string()
            .contains("simulated required audit sink failure")
    );
    assert_eq!(wrapper.call_count(), 0);

    let events = sink.events();
    assert_event_types(
        &events,
        &[EventType::PolicyActivation, EventType::Authorization],
    );
    assert_no_event_type(&events, EventType::CredentialIssuance);
    assert_one_correlation_id(&events);
}

struct MockAgent {
    adapter: MockReferenceAdapter,
}

impl MockAgent {
    fn new(sink: RecordingSink, wrapper: SpyOutlookWrapper) -> Self {
        let emitter = AuditEmitter::new(sink);
        let adapter = MockReferenceAdapter {
            gateway: MockPolicyGateway {
                emitter: emitter.clone(),
            },
            credential_issuer: MockCredentialIssuer { emitter },
            wrapper,
        };

        Self { adapter }
    }

    fn mail_search(&self, query_class: &'static str) -> Result<(), AuditError> {
        self.adapter.mail_search(query_class)
    }
}

#[derive(Clone)]
struct MockReferenceAdapter {
    gateway: MockPolicyGateway,
    credential_issuer: MockCredentialIssuer,
    wrapper: SpyOutlookWrapper,
}

impl MockReferenceAdapter {
    fn mail_search(&self, query_class: &'static str) -> Result<(), AuditError> {
        let template = audit_template(generate_correlation_id());
        self.gateway.load_policy(&template)?;

        let request = AuthorizationRequest::mail_search(generate_request_id(), query_class);
        let decision = self.gateway.authorize(&template, &request)?;
        let credential_request = CredentialRequest::new(generate_credential_request_id());
        let credential =
            self.credential_issuer
                .issue(&template, &decision, &request, &credential_request)?;

        // Policy allowed the request and the credential was recorded; the
        // middleware may now make the egress call. The call itself is not a
        // policy decision, so it emits no audit record.
        self.wrapper.search(&credential);
        Ok(())
    }
}

#[derive(Clone)]
struct MockPolicyGateway {
    emitter: AuditEmitter<RecordingSink>,
}

impl MockPolicyGateway {
    fn load_policy(&self, template: &AuditContextTemplate) -> Result<(), AuditError> {
        self.emitter
            .emit_typed_required(
                &gateway_context(template, None),
                PolicyActivationEvent::new(Outcome::Success, "policy.bundle_loaded"),
            )
            .map(|_event| ())
    }

    fn authorize(
        &self,
        template: &AuditContextTemplate,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationDecision, AuditError> {
        let decision_id = generate_decision_id();
        let obligations = obligations(&decision_id);
        self.emitter.emit_typed_required(
            &gateway_context(template, Some(&request.request_id)),
            AuthorizationEvent::new(
                request.resource.clone(),
                request.verb.clone(),
                Decision::Allow,
                decision_id.clone(),
                "decision.allow",
            )
            .with_obligations(obligations.clone())
            .with_argument_summary(request.argument_summary.clone()),
        )?;

        Ok(AuthorizationDecision {
            decision_id,
            obligations,
        })
    }
}

#[derive(Clone)]
struct MockCredentialIssuer {
    emitter: AuditEmitter<RecordingSink>,
}

impl MockCredentialIssuer {
    fn issue(
        &self,
        template: &AuditContextTemplate,
        decision: &AuthorizationDecision,
        request: &AuthorizationRequest,
        credential_request: &CredentialRequest,
    ) -> Result<CredentialGrant, AuditError> {
        let credential_scope = decision
            .obligations
            .credential_scope
            .clone()
            .expect("allow decision should include credential scope");
        self.emitter.emit_typed_required(
            &credential_issuer_context(template, &decision.decision_id),
            CredentialIssuanceEvent::new(
                request.resource.clone(),
                request.verb.clone(),
                Outcome::Success,
                "credential.issued.scope_bounded",
                credential_request.value.clone(),
                credential_scope,
            ),
        )?;

        Ok(CredentialGrant {
            token_material: "Bearer fail-closed-test-token".to_owned(),
        })
    }
}

#[derive(Clone, Default)]
struct SpyOutlookWrapper {
    calls: Arc<AtomicUsize>,
}

impl SpyOutlookWrapper {
    fn search(&self, credential: &CredentialGrant) {
        assert!(credential.token_material.starts_with("Bearer "));
        self.calls.fetch_add(1, Ordering::SeqCst);
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

struct AuthorizationRequest {
    request_id: String,
    resource: Resource,
    verb: String,
    argument_summary: RedactedObject,
}

impl AuthorizationRequest {
    fn mail_search(request_id: String, query_class: &'static str) -> Self {
        let raw_arguments = json!({
            "query_class": query_class,
            "max_results": 10,
            "access_token": "Bearer fail-closed-test-token",
        });

        Self {
            request_id,
            resource: mailbox_resource(),
            verb: "mail.search".to_owned(),
            argument_summary: redact(
                "outlook",
                &raw_arguments,
                &outlook_redaction_profile(["query_class", "max_results"]),
            )
            .expect("argument summary redaction should succeed"),
        }
    }
}

struct AuthorizationDecision {
    decision_id: String,
    obligations: Obligations,
}

struct CredentialRequest {
    value: String,
}

impl CredentialRequest {
    fn new(value: String) -> Self {
        Self { value }
    }
}

struct CredentialGrant {
    token_material: String,
}

#[derive(Debug, Clone)]
struct RecordingSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
    failure: EventType,
}

impl RecordingSink {
    fn fail_on(failure: EventType) -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            failure,
        }
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .expect("recording sink should not be poisoned")
            .clone()
    }
}

impl AuditSink for RecordingSink {
    fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        event.validate()?;
        if event.event_type == self.failure {
            return Err(std::io::Error::other("simulated required audit sink failure").into());
        }

        self.events
            .lock()
            .map_err(|error| AuditError::Lock(error.to_string()))?
            .push(event.clone());
        Ok(())
    }
}

fn audit_template(correlation_id: String) -> AuditContextTemplate {
    let subject = SubjectIdentity::new(
        "user:example",
        "agent:demo:research-assistant",
        "workspace:example",
        "session:apf-v0-demo",
    )
    .expect("subject identity should be valid")
    .with_device_id("device:managed")
    .expect("device id should be valid")
    .with_deployment_profile("azure-sandbox-dev")
    .expect("deployment profile should be valid");
    let policy = PolicyIdentity::new(BUNDLE_DIGEST, "trustroot:dev")
        .expect("policy identity should be valid")
        .with_policy_revision(1)
        .with_bundle_id("bundle:apf-v0-demo")
        .expect("bundle id should be valid")
        .with_signer_id("signer:dev")
        .expect("signer id should be valid");

    AuditContextTemplate::new(correlation_id, subject, "openshell", policy)
        .expect("audit context template should be valid")
}

fn gateway_context(template: &AuditContextTemplate, causation: Option<&str>) -> AuditContext {
    match causation {
        Some(causation) => template
            .for_component_with_causation(
                "apf-policy-gateway:local",
                gateway_component(),
                causation,
            )
            .expect("policy-gateway context with causation should be valid"),
        None => template
            .for_component("apf-policy-gateway:local", gateway_component())
            .expect("policy-gateway context should be valid"),
    }
}

fn credential_issuer_context(template: &AuditContextTemplate, causation: &str) -> AuditContext {
    template
        .for_component_with_causation(
            "apf-credential-issuer:local",
            Component::new("apf-policy-gateway", "0.1.0", "apf-credential-issuer:local"),
            causation,
        )
        .expect("credential-issuer context should be valid")
}

fn gateway_component() -> Component {
    Component::new("apf-policy-gateway", "0.1.0", "apf-policy-gateway:local")
}

fn mailbox_resource() -> Resource {
    let mut resource = Resource::new("mailbox", "mailbox:user:example");
    resource.resource_class = Some("outlook".to_owned());
    resource.data_class = Some("business_email".to_owned());
    resource
}

fn credential_scope(decision_id: &str) -> CredentialScope {
    CredentialScope {
        provider: "graph".to_owned(),
        mode: Some("token_vending".to_owned()),
        audience: "graph.microsoft.com".to_owned(),
        scopes: vec!["Mail.Read".to_owned()],
        ttl_seconds: Some(600),
        expires_at: Some("2026-05-15T19:30:31.244Z".to_owned()),
        decision_id: Some(decision_id.to_owned()),
    }
}

fn obligations(decision_id: &str) -> Obligations {
    Obligations {
        credential_scope: Some(credential_scope(decision_id)),
        redaction_profile: Some("outlook_pii_basic".to_owned()),
        max_result_size: Some(10),
        audit_level: Some("required".to_owned()),
        ..Obligations::default()
    }
}

fn outlook_redaction_profile<const N: usize>(
    allowed_fields: [&'static str; N],
) -> RedactionProfile {
    let mut profile =
        RedactionProfile::try_new("outlook_pii_basic").expect("redaction profile should be valid");
    for field in allowed_fields {
        profile
            .add_allowed_field(field)
            .expect("redaction field should be valid");
    }
    profile
}

fn assert_event_types(events: &[AuditEvent], expected: &[EventType]) {
    let actual = events
        .iter()
        .map(|event| event.event_type)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

fn assert_no_event_type(events: &[AuditEvent], event_type: EventType) {
    assert!(
        events.iter().all(|event| event.event_type != event_type),
        "{event_type} should not be emitted after fail-closed audit failure"
    );
}

fn assert_one_correlation_id(events: &[AuditEvent]) {
    let correlation_id = events
        .first()
        .expect("at least one event should be recorded")
        .correlation_id
        .as_str();
    assert!(
        events
            .iter()
            .all(|event| event.correlation_id == correlation_id)
    );
}
