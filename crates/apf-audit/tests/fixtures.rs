// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs::{File, read_dir, read_to_string, remove_file};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use apf_audit::{
    AuditEmitter, AuditEvent, CommonFields, Component, CredentialScope, Decision, EmitOutcome,
    EventType, JsonlSink, Resource, ResultClass, ReviewRef,
};
use uuid::Uuid;

const EXPECTED_VALID_FIXTURES: &[&str] = &[
    "admission_validation.valid.json",
    "authentication.valid.json",
    "authorization_allow.valid.json",
    "authorization_deny.valid.json",
    "authorization_findings.valid.json",
    "authorization_provenance.valid.json",
    "config_governance.valid.json",
    "credential_issuance.valid.json",
    "credential_issuance_refused.valid.json",
    "policy_service_startup.valid.json",
    "policy_activation.valid.json",
    "policy_distribution.valid.json",
    "policy_injection.valid.json",
    "policy_refresh.valid.json",
    "policy_verification.valid.json",
    "provenance_signing.valid.json",
    "review_decision.valid.json",
    "review_request.valid.json",
];

const EXPECTED_INVALID_FIXTURES: &[&str] = &[
    "bad_decision_id.invalid.json",
    "bad_bundle_digest.invalid.json",
    "bad_timestamp.invalid.json",
    "duplicate_scope.invalid.json",
    "forbidden_secret_field.invalid.json",
    "missing_auth_error.invalid.json",
    "missing_correlation.invalid.json",
    "nested_duplicate_scope.invalid.json",
    "nested_forbidden_credential_scope.invalid.json",
    "unknown_property.invalid.json",
];

const EXPECTED_TIMELINE_FIXTURES: &[&str] = &["happy_path.valid.jsonl"];

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load_event(path: &Path) -> Result<AuditEvent, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    serde_json::from_reader(file).map_err(|error| error.to_string())
}

fn base_event(event_type: EventType, event_id: &str) -> AuditEvent {
    AuditEvent::with_ids(
        event_type,
        CommonFields::new(
            "corr_test_schema_validation",
            "user:example",
            "agent:example",
            "workspace:example",
            "session:example",
            "apf-policy-gateway:local",
            "openshell",
            Component::new("apf-policy-gateway", "0.1.0", "apf-policy-gateway:local"),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "trustroot:dev",
        ),
        event_id,
        "2026-05-15T19:20:31.010Z",
    )
}

fn fixture_paths(dir: &str, suffix: &str) -> Vec<PathBuf> {
    let mut paths = read_dir(fixture_root().join(dir))
        .expect("fixture directory should exist")
        .map(|entry| entry.expect("fixture entry should be readable").path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(suffix))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn assert_expected_fixtures(paths: &[PathBuf], expected: &[&str]) {
    let actual = paths
        .iter()
        .map(|path| {
            path.file_name()
                .expect("fixture path should have file name")
                .to_string_lossy()
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

fn assert_validation_failure(relative_path: &str, expected_fragment: &str) {
    let path = fixture_root().join(relative_path);
    let event = load_event(&path).unwrap_or_else(|error| {
        panic!("{} should deserialize: {error}", path.display());
    });
    let error = event
        .validate()
        .expect_err("fixture should fail validation");
    let joined = error.violations().join("; ");
    assert!(
        joined.contains(expected_fragment),
        "{} should contain {expected_fragment:?}, got {joined}",
        path.display()
    );
}

fn assert_deserialization_failure(relative_path: &str, expected_fragment: &str) {
    let path = fixture_root().join(relative_path);
    let error = load_event(&path).expect_err("fixture should fail deserialization");
    assert!(
        error.contains(expected_fragment),
        "{} should contain {expected_fragment:?}, got {error}",
        path.display()
    );
}

#[test]
fn valid_json_fixtures_validate() {
    let paths = fixture_paths("valid", ".valid.json");
    assert_expected_fixtures(&paths, EXPECTED_VALID_FIXTURES);

    for path in paths {
        let event = load_event(&path).unwrap_or_else(|error| {
            panic!("{} should deserialize: {error}", path.display());
        });
        event.validate().unwrap_or_else(|error| {
            panic!("{} should validate: {error}", path.display());
        });
    }
}

#[test]
fn invalid_json_fixtures_are_rejected() {
    let paths = fixture_paths("invalid", ".invalid.json");
    assert_expected_fixtures(&paths, EXPECTED_INVALID_FIXTURES);

    for path in paths {
        if let Ok(event) = load_event(&path) {
            assert!(
                event.validate().is_err(),
                "{} should fail validation",
                path.display()
            );
        }
    }
}

#[test]
fn invalid_fixture_rejection_categories_are_stable() {
    assert_validation_failure("invalid/bad_decision_id.invalid.json", "decision_id");
    assert_validation_failure("invalid/bad_bundle_digest.invalid.json", "bundle_digest");
    assert_validation_failure("invalid/bad_timestamp.invalid.json", "timestamp");
    assert_validation_failure("invalid/duplicate_scope.invalid.json", "scopes");
    assert_validation_failure("invalid/forbidden_secret_field.invalid.json", "forbidden");
    assert_validation_failure("invalid/missing_auth_error.invalid.json", "error");
    assert_validation_failure("invalid/nested_duplicate_scope.invalid.json", "scopes");
    assert_deserialization_failure("invalid/missing_correlation.invalid.json", "correlation_id");
    assert_deserialization_failure(
        "invalid/nested_forbidden_credential_scope.invalid.json",
        "token",
    );
    assert_deserialization_failure("invalid/unknown_property.invalid.json", "unknown");
}

#[test]
fn nested_datetime_fields_are_schema_validated() {
    // These must be built on event types that legitimately carry the field.
    // An earlier version bolted `credential_scope` onto a `policy_activation`, which
    // only validated far enough to reach the date-time check because the schema
    // let any field onto any type. It no longer does, so the vehicle has to be
    // a real credential event.
    let mut credential_event = base_event(
        EventType::CredentialIssuance,
        "evt_test_bad_credential_expiry",
    );
    credential_event.resource = Some(Resource::new("mailbox", "user@corp"));
    credential_event.verb = Some("mail.search".to_owned());
    // A valid credential_issuance in every respect except `expires_at`, so the
    // only violation the assertion can be reacting to is the date-time one.
    credential_event.outcome = Some(apf_audit::Outcome::Success);
    credential_event.decision_id = Some("decision:cred".to_owned());
    credential_event.reason_code = Some("credential.issued".to_owned());
    credential_event.credential_request_id = Some("credreq:1".to_owned());
    credential_event.result_class = Some(ResultClass::Success);
    credential_event.credential_scope = Some(CredentialScope {
        provider: "graph".to_owned(),
        mode: Some("token_vending".to_owned()),
        audience: "graph.microsoft.com".to_owned(),
        scopes: vec!["Mail.Read".to_owned()],
        ttl_seconds: Some(900),
        expires_at: Some("not-a-timestamp".to_owned()),
        decision_id: Some("dec_test_bad_credential_expiry".to_owned()),
    });
    let error = credential_event
        .validate()
        .expect_err("credential expiry should fail date-time validation");
    assert!(
        error.violations().join("; ").contains("expires_at"),
        "got {:?}",
        error.violations()
    );

    let mut review_event = base_event(EventType::ReviewDecision, "evt_test_bad_review_decision_at");
    review_event.decision = Some(Decision::Allow);
    review_event.reason_code = Some("review.approved".to_owned());
    review_event.review_ref = Some(ReviewRef {
        review_id: "review:test".to_owned(),
        status: "approved".to_owned(),
        reviewer_id: None,
        decision_at: Some("not-a-timestamp".to_owned()),
        evidence_ref: None,
    });
    let error = review_event
        .validate()
        .expect_err("review decision timestamp should fail date-time validation");
    assert!(
        error.violations().join("; ").contains("decision_at"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn timeline_fixture_events_validate() {
    let paths = fixture_paths("timelines", ".valid.jsonl");
    assert_expected_fixtures(&paths, EXPECTED_TIMELINE_FIXTURES);

    let path = fixture_root().join("timelines/happy_path.valid.jsonl");
    let file = File::open(&path).expect("timeline fixture should open");
    let reader = BufReader::new(file);

    let mut event_types = Vec::new();
    let mut correlation_id = None;
    for line in reader.lines() {
        let line = line.expect("timeline line should be readable");
        let event: AuditEvent =
            serde_json::from_str(&line).expect("timeline line should deserialize");
        event.validate().expect("timeline event should validate");
        if let Some(expected_correlation_id) = &correlation_id {
            assert_eq!(expected_correlation_id, &event.correlation_id);
        } else {
            correlation_id = Some(event.correlation_id.clone());
        }
        event_types.push(event.event_type);
    }

    assert_eq!(
        event_types,
        vec![EventType::PolicyActivation, EventType::Authorization]
    );
}

#[test]
fn jsonl_sink_appends_valid_event() {
    let mut common = CommonFields::new(
        "corr_test_jsonl_sink",
        "user:example",
        "agent:example",
        "workspace:example",
        "session:example",
        "apf-policy-gateway:local",
        "openshell",
        Component::new("apf-policy-gateway", "0.1.0", "apf-policy-gateway:local"),
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "trustroot:dev",
    );
    common.bundle_id = Some("bundle:apf-v0-demo".to_owned());

    let mut event = AuditEvent::with_ids(
        EventType::Authorization,
        common,
        "evt_test_jsonl_sink",
        "2026-05-15T19:20:31.010Z",
    );
    event.resource = Some(Resource::new("mailbox", "mailbox:user:example"));
    event.verb = Some("mail.search".to_owned());
    event.decision = Some(Decision::Deny);
    event.decision_id = Some("dec_test_jsonl_sink".to_owned());
    event.reason_code = Some("decision.deny".to_owned());

    let path =
        std::env::temp_dir().join(format!("apf-audit-test-{}.jsonl", Uuid::new_v4().simple()));
    let sink = JsonlSink::new(path.clone());
    let emitter = AuditEmitter::new(sink);
    emitter
        .emit_required(&event)
        .expect("event should be written");
    emitter.emit_required(&event).expect("event should append");

    let contents = read_to_string(&path).expect("jsonl file should be readable");
    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    let written: AuditEvent = serde_json::from_str(lines[0]).expect("written event should parse");
    assert_eq!(written.event_id, "evt_test_jsonl_sink");

    let _ = remove_file(path);
}

#[test]
fn jsonl_sink_rejects_invalid_event_before_write() {
    let common = CommonFields::new(
        "corr_test_jsonl_invalid",
        "user:example",
        "agent:example",
        "workspace:example",
        "session:example",
        "apf-policy-gateway:local",
        "openshell",
        Component::new("apf-policy-gateway", "0.1.0", "apf-policy-gateway:local"),
        "bad digest with spaces",
        "trustroot:dev",
    );
    let event = AuditEvent::with_ids(
        EventType::PolicyActivation,
        common,
        "evt_test_jsonl_invalid",
        "2026-05-15T19:20:31.010Z",
    );

    let path = std::env::temp_dir().join(format!(
        "apf-audit-invalid-test-{}.jsonl",
        Uuid::new_v4().simple()
    ));
    let sink = JsonlSink::new(path.clone());
    let emitter = AuditEmitter::new(sink);

    assert!(emitter.emit_required(&event).is_err());
    assert!(!path.exists());
}

#[test]
fn emitter_rejects_secret_like_values_before_write() {
    let common = CommonFields::new(
        "corr_test_secret_scan",
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
    let mut event = AuditEvent::with_ids(
        EventType::Authorization,
        common,
        "evt_test_secret_scan",
        "2026-05-15T19:20:31.010Z",
    );
    event.resource = Some(Resource::new("mailbox", "mailbox:user:example"));
    event.verb = Some("mail.search".to_owned());
    event.decision = Some(Decision::Allow);
    event.decision_id = Some("dec_test_secret_scan".to_owned());
    event.reason_code = Some("resource.call.success".to_owned());
    event.result_class = Some(ResultClass::Success);
    event.result_summary = Some(std::collections::BTreeMap::from([(
        "provider_label".to_owned(),
        serde_json::json!("Bearer abcdefghijklmnopqrstuvwxyz123456"),
    )]));

    let path = std::env::temp_dir().join(format!(
        "apf-audit-secret-test-{}.jsonl",
        Uuid::new_v4().simple()
    ));
    let sink = JsonlSink::new(path.clone());
    let emitter = AuditEmitter::new(sink);

    let error = emitter
        .emit_required(&event)
        .expect_err("secret-like values should be rejected");
    assert!(error.to_string().contains("credential-like value"));
    assert!(!path.exists());
}

#[test]
fn best_effort_emission_uses_sanitization_guard() {
    let common = CommonFields::new(
        "corr_test_best_effort_secret_scan",
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
    let mut event = AuditEvent::with_ids(
        EventType::Authorization,
        common,
        "evt_test_best_effort_secret_scan",
        "2026-05-15T19:20:31.010Z",
    );
    event.resource = Some(Resource::new("mailbox", "mailbox:user:example"));
    event.verb = Some("mail.search".to_owned());
    event.decision = Some(Decision::Allow);
    event.decision_id = Some("dec_test_best_effort_secret_scan".to_owned());
    event.reason_code = Some("resource.call.success".to_owned());
    event.result_class = Some(ResultClass::Success);
    event.result_summary = Some(std::collections::BTreeMap::from([(
        "provider_label".to_owned(),
        serde_json::json!("Bearer abcdefghijklmnopqrstuvwxyz123456"),
    )]));

    let path = std::env::temp_dir().join(format!(
        "apf-audit-best-effort-secret-test-{}.jsonl",
        Uuid::new_v4().simple()
    ));
    let emitter = AuditEmitter::new(JsonlSink::new(path.clone()));

    let outcome = emitter.emit_best_effort(&event);

    assert!(
        matches!(outcome, EmitOutcome::Failed(message) if message.contains("credential-like value"))
    );
    assert!(!path.exists());
}

#[test]
fn optional_null_fields_are_rejected() {
    // Every optional field rejects an explicit null, including the operation
    // fields (outcome/served_unsigned/checks) added with the noun taxonomy —
    // a null would otherwise deserialize to None and slip past validation.
    for field in ["trace_id", "outcome", "served_unsigned", "checks"] {
        let path = fixture_root().join("valid/policy_activation.valid.json");
        let event = load_event(&path).expect("valid fixture should deserialize");
        let mut value = serde_json::to_value(event).expect("event should serialize to value");
        value[field] = serde_json::Value::Null;

        let error = serde_json::from_value::<AuditEvent>(value)
            .expect_err("explicit null optional fields should be rejected");
        assert!(
            error.to_string().contains("null is not allowed"),
            "{field}: got {error}"
        );
    }
}
