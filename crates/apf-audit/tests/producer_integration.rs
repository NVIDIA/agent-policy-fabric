// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{read_to_string, remove_file};
use std::path::{Path, PathBuf};

use apf_audit::{
    AuditContextTemplate, AuditEmitter, AuditEvent, AuthorizationEvent, Component,
    CredentialIssuanceEvent, CredentialScope, Decision, EventType, JsonlSink, Obligations, Outcome,
    PolicyActivationEvent, PolicyIdentity, RedactedObject, RedactionProfile, Resource,
    SubjectIdentity, generate_correlation_id, generate_credential_request_id, generate_decision_id,
    generate_request_id, redact,
};
use serde_json::{Value, json};
use uuid::Uuid;

const BUNDLE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn gateway_middleware_credential_flow_writes_audit_log_end_to_end() {
    let system = TestSystem::new();
    let flow = system.adapter.mail_search("sender_and_date");
    let contents = read_to_string(&system.path).expect("audit JSONL should be readable");
    let events = read_timeline(&system.path);

    assert_event_order(&events);
    assert_component_ownership(&events);
    assert_flow_ids(&events, &flow);
    assert_policy_identity(&events);
    assert_authorize_event(&events[1], &flow);
    assert_credential_issue_event(&events[2], &flow);
    assert!(!contents.contains("access_token"));
    assert!(!contents.contains("refresh_token"));
    assert!(!contents.contains("raw_message"));
    assert!(!contents.contains("confidential raw Outlook"));
    assert!(!contents.contains("apf-test-access-token"));
    assert!(!contents.contains("Bearer "));

    let _ = remove_file(system.path);
}

struct TestSystem {
    path: PathBuf,
    adapter: TestReferenceAdapter,
}

impl TestSystem {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "apf-audit-producer-integration-{}.jsonl",
            Uuid::new_v4().simple()
        ));
        let emitter = AuditEmitter::new(JsonlSink::new(path.clone()));
        let gateway = TestPolicyGateway {
            emitter: emitter.clone(),
        };
        let credential_issuer = TestCredentialIssuer { emitter };
        let adapter = TestReferenceAdapter {
            gateway,
            credential_issuer,
        };

        Self { path, adapter }
    }
}

#[derive(Clone)]
struct TestReferenceAdapter {
    gateway: TestPolicyGateway,
    credential_issuer: TestCredentialIssuer,
}

impl TestReferenceAdapter {
    fn mail_search(&self, query_class: &'static str) -> FlowIds {
        let template = audit_template(generate_correlation_id());
        self.gateway.load_policy(&template);

        let request = AuthorizationRequest::mail_search(generate_request_id(), query_class);
        let decision = self.gateway.authorize(&template, &request);
        let credential_request = CredentialRequest::new(generate_credential_request_id());
        let credential =
            self.credential_issuer
                .issue(&template, &decision, &request, &credential_request);

        // The middleware makes the egress call once policy has allowed it; the
        // call itself is not a policy decision, so it emits no audit record.
        TestOutlookCli::search(&credential);

        FlowIds {
            correlation: template.correlation_id().to_owned(),
            request: request.request_id,
            decision: decision.decision_id,
            credential_request: credential_request.credential_request_id,
        }
    }
}

#[derive(Clone)]
struct TestPolicyGateway {
    emitter: AuditEmitter<JsonlSink>,
}

impl TestPolicyGateway {
    fn load_policy(&self, template: &AuditContextTemplate) {
        self.emitter
            .emit_typed_required(
                &gateway_context(template, None),
                PolicyActivationEvent::new(Outcome::Success, "policy.bundle.loaded"),
            )
            .expect("policy_activation audit should write");
    }

    fn authorize(
        &self,
        template: &AuditContextTemplate,
        request: &AuthorizationRequest,
    ) -> AuthorizationDecision {
        let decision_id = generate_decision_id();
        let obligations = obligations(&decision_id);
        self.emitter
            .emit_typed_required(
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
            )
            .expect("authorize audit should write");

        AuthorizationDecision {
            decision_id,
            obligations,
        }
    }
}

#[derive(Clone)]
struct TestCredentialIssuer {
    emitter: AuditEmitter<JsonlSink>,
}

impl TestCredentialIssuer {
    fn issue(
        &self,
        template: &AuditContextTemplate,
        decision: &AuthorizationDecision,
        request: &AuthorizationRequest,
        credential_request: &CredentialRequest,
    ) -> CredentialGrant {
        let credential_scope = decision
            .obligations
            .credential_scope
            .clone()
            .expect("allow decision should include credential scope");
        self.emitter
            .emit_typed_required(
                &credential_issuer_context(template, &decision.decision_id),
                CredentialIssuanceEvent::new(
                    request.resource.clone(),
                    request.verb.clone(),
                    Outcome::Success,
                    "credential.issued.scope_bounded",
                    credential_request.credential_request_id.clone(),
                    credential_scope,
                ),
            )
            .expect("credential_issuance audit should write");

        CredentialGrant {
            token_material: "Bearer apf-test-access-token".to_owned(),
        }
    }
}

struct TestOutlookCli;

impl TestOutlookCli {
    fn search(credential: &CredentialGrant) {
        assert!(credential.token_material.starts_with("Bearer "));
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
            "access_token": "Bearer apf-test-access-token",
            "raw_message": "confidential raw Outlook query text",
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

struct CredentialGrant {
    token_material: String,
}

struct CredentialRequest {
    credential_request_id: String,
}

impl CredentialRequest {
    fn new(credential_request_id: String) -> Self {
        Self {
            credential_request_id,
        }
    }
}

struct FlowIds {
    correlation: String,
    request: String,
    decision: String,
    credential_request: String,
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
    .with_deployment_profile("azure-sandbox-dev");
    let subject = subject.expect("deployment profile should be valid");
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

fn gateway_context(
    template: &AuditContextTemplate,
    causation_id: Option<&str>,
) -> apf_audit::AuditContext {
    match causation_id {
        Some(causation_id) => template
            .for_component_with_causation(
                "apf-policy-gateway:local",
                gateway_component(),
                causation_id,
            )
            .expect("policy-gateway context with causation should be valid"),
        None => template
            .for_component("apf-policy-gateway:local", gateway_component())
            .expect("policy-gateway context should be valid"),
    }
}

fn credential_issuer_context(
    template: &AuditContextTemplate,
    causation_id: &str,
) -> apf_audit::AuditContext {
    template
        .for_component_with_causation(
            "apf-credential-issuer:local",
            Component::new("apf-policy-gateway", "0.1.0", "apf-credential-issuer:local"),
            causation_id,
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

fn read_timeline(path: &Path) -> Vec<AuditEvent> {
    read_to_string(path)
        .expect("timeline JSONL should be readable")
        .lines()
        .map(|line| {
            let event =
                serde_json::from_str::<AuditEvent>(line).expect("JSONL line should deserialize");
            event.validate().expect("JSONL event should validate");
            event
        })
        .collect()
}

fn assert_event_order(events: &[AuditEvent]) {
    let actual = events
        .iter()
        .map(|event| event.event_type)
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        [
            EventType::PolicyActivation,
            EventType::Authorization,
            EventType::CredentialIssuance,
        ]
    );
}

fn assert_component_ownership(events: &[AuditEvent]) {
    assert_eq!(events[0].component.name, "apf-policy-gateway");
    assert_eq!(events[1].component.name, "apf-policy-gateway");
    assert_eq!(events[2].component.name, "apf-policy-gateway");
}

fn assert_flow_ids(events: &[AuditEvent], flow: &FlowIds) {
    assert!(flow.correlation.starts_with("corr_"));
    assert!(flow.request.starts_with("req_"));
    assert!(flow.decision.starts_with("dec_"));
    assert!(flow.credential_request.starts_with("credreq_"));

    for event in events {
        assert_eq!(event.correlation_id, flow.correlation);
    }
    assert_eq!(
        events[1].causation_id.as_deref(),
        Some(flow.request.as_str())
    );
    assert_eq!(
        events[2].causation_id.as_deref(),
        Some(flow.decision.as_str())
    );
}

fn assert_policy_identity(events: &[AuditEvent]) {
    for event in events {
        assert_eq!(event.bundle_digest.as_deref(), Some(BUNDLE_DIGEST));
        assert_eq!(event.bundle_id.as_deref(), Some("bundle:apf-v0-demo"));
        assert_eq!(event.policy_revision, Some(1));
        assert_eq!(event.signer_id.as_deref(), Some("signer:dev"));
        assert_eq!(event.trust_root_id.as_deref(), Some("trustroot:dev"));
    }
}

fn assert_authorize_event(event: &AuditEvent, flow: &FlowIds) {
    assert_eq!(event.event_type, EventType::Authorization);
    assert_eq!(event.verb.as_deref(), Some("mail.search"));
    assert_eq!(event.decision, Some(Decision::Allow));
    assert_eq!(event.decision_id.as_deref(), Some(flow.decision.as_str()));
    assert_eq!(event.reason_code.as_deref(), Some("decision.allow"));
    assert_redacted_summary_fields(
        event
            .argument_summary
            .as_ref()
            .expect("authorize should include argument summary"),
        &["query_class", "max_results"],
    );
}

fn assert_credential_issue_event(event: &AuditEvent, flow: &FlowIds) {
    assert_eq!(event.event_type, EventType::CredentialIssuance);
    assert_eq!(
        event.credential_request_id.as_deref(),
        Some(flow.credential_request.as_str())
    );
    assert_eq!(event.outcome, Some(Outcome::Success));
    assert_eq!(
        event.credential_scope.as_ref(),
        Some(&credential_scope(&flow.decision))
    );
}

fn assert_redacted_summary_fields(summary: &RedactedObject, expected_fields: &[&str]) {
    assert_eq!(summary.get("resource_type"), Some(&json!("outlook")));
    assert_eq!(
        summary.get("redaction_profile"),
        Some(&json!("outlook_pii_basic"))
    );
    assert_eq!(summary.get("payload_included"), Some(&Value::Bool(false)));
    assert_eq!(summary.get("dropped_field_count"), Some(&json!(2)));

    let fields = summary
        .get("fields")
        .and_then(Value::as_object)
        .expect("redacted summary should include retained fields");
    for expected_field in expected_fields {
        assert!(
            fields.contains_key(*expected_field),
            "redacted summary should retain {expected_field}"
        );
    }
}
