// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, remove_file};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use apf_audit::{
    AuditContext, AuditContextTemplate, AuditEmitter, AuditEvent, AuthorizationEvent, Component,
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
fn jsonl_audit_events_forward_through_line_oriented_delivery_contract() {
    let path = temp_jsonl_path();
    let flow = emit_mocked_governed_action(&path);

    let collector = TestCollector::default();
    TestJsonlForwarder::new(&path).forward_all(&collector);

    let delivered = collector.events();
    assert_event_types(
        &delivered,
        &[
            EventType::PolicyActivation,
            EventType::Authorization,
            EventType::CredentialIssuance,
        ],
    );
    assert_eq!(delivered.len(), collector.raw_records().len());
    assert_correlation_and_causation(&delivered, &flow);
    assert_policy_identity(&delivered);
    assert_downstream_payload_is_sanitized(&collector.raw_records());

    let _ = remove_file(path);
}

fn emit_mocked_governed_action(path: &Path) -> FlowIds {
    let emitter = AuditEmitter::new(JsonlSink::new(path.to_path_buf()));
    let template = audit_template(generate_correlation_id());
    let request = AuthorizationRequest::mail_search(generate_request_id(), "sender_and_date");

    emitter
        .emit_typed_required(
            &gateway_context(&template, None),
            PolicyActivationEvent::new(Outcome::Success, "policy.bundle.loaded"),
        )
        .expect("policy_activation should write");

    let decision_id = generate_decision_id();
    let obligations = obligations(&decision_id);
    emitter
        .emit_typed_required(
            &gateway_context(&template, Some(&request.request_id)),
            AuthorizationEvent::new(
                request.resource.clone(),
                request.verb.clone(),
                Decision::Allow,
                decision_id.clone(),
                "decision.allow",
            )
            .with_obligations(obligations)
            .with_argument_summary(request.argument_summary.clone()),
        )
        .expect("authorize should write");

    let credential_request_id = generate_credential_request_id();
    emitter
        .emit_typed_required(
            &credential_issuer_context(&template, &decision_id),
            CredentialIssuanceEvent::new(
                request.resource.clone(),
                request.verb.clone(),
                Outcome::Success,
                "credential.issued.scope_bounded",
                credential_request_id.clone(),
                credential_scope(&decision_id),
            ),
        )
        .expect("credential_issuance should write");

    FlowIds {
        correlation: template.correlation_id().to_owned(),
        request: request.request_id,
        decision: decision_id,
        credential_request: credential_request_id,
    }
}

struct TestJsonlForwarder<'a> {
    input: &'a Path,
}

impl<'a> TestJsonlForwarder<'a> {
    fn new(input: &'a Path) -> Self {
        Self { input }
    }

    fn forward_all(&self, collector: &TestCollector) {
        let file = File::open(self.input).expect("delivery input JSONL should open");
        let reader = BufReader::new(file);

        for line in reader.lines() {
            collector.ingest(&line.expect("JSONL line should be readable"));
        }
    }
}

#[derive(Default)]
struct TestCollector {
    records: Mutex<Vec<AuditEvent>>,
    raw_records: Mutex<Vec<String>>,
}

impl TestCollector {
    fn ingest(&self, raw_record: &str) {
        let event = serde_json::from_str::<AuditEvent>(raw_record)
            .expect("collector should parse APF JSON");
        event
            .validate()
            .expect("collector should receive valid APF audit event");

        self.raw_records
            .lock()
            .expect("raw collector records should not be poisoned")
            .push(raw_record.to_owned());
        self.records
            .lock()
            .expect("collector records should not be poisoned")
            .push(event);
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.records
            .lock()
            .expect("collector records should not be poisoned")
            .clone()
    }

    fn raw_records(&self) -> Vec<String> {
        self.raw_records
            .lock()
            .expect("raw collector records should not be poisoned")
            .clone()
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
            "raw_message": "confidential raw Outlook query",
            "access_token": "Bearer jsonl-delivery-test-token",
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

fn temp_jsonl_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "apf-audit-jsonl-delivery-contract-{}.jsonl",
        Uuid::new_v4().simple()
    ))
}

fn assert_event_types(events: &[AuditEvent], expected: &[EventType]) {
    let actual = events
        .iter()
        .map(|event| event.event_type)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

fn assert_correlation_and_causation(events: &[AuditEvent], flow: &FlowIds) {
    for event in events {
        assert_eq!(event.correlation_id, flow.correlation);
    }

    assert_eq!(events[0].causation_id, None);
    assert_eq!(
        events[1].causation_id.as_deref(),
        Some(flow.request.as_str())
    );
    assert_eq!(
        events[2].causation_id.as_deref(),
        Some(flow.decision.as_str())
    );
    assert_eq!(
        events[2].credential_request_id.as_deref(),
        Some(flow.credential_request.as_str())
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

fn assert_downstream_payload_is_sanitized(raw_records: &[String]) {
    let joined = raw_records.join("\n");
    assert!(!joined.contains("access_token"));
    assert!(!joined.contains("raw_message"));
    assert!(!joined.contains("confidential raw Outlook"));
    assert!(!joined.contains("jsonl-delivery-test-token"));
    assert!(!joined.contains("Bearer "));

    let jsonl = joined.lines().count();
    assert_eq!(jsonl, raw_records.len());
    assert!(raw_records.iter().all(|record| {
        serde_json::from_str::<Value>(record).is_ok_and(|value| value.is_object())
    }));
}
