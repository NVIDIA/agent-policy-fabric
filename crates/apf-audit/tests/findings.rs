// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! `findings[]` — observations emitted alongside a decision.
//!
//! Findings do not change the decision. Their value is the case no other field
//! can express: a request that was **allowed** while carrying a critical
//! finding. The decision says `allow` and the reason code says the rule fired
//! normally; only `findings` shows that a secret was in the body.

use apf_audit::{
    AuditEvent, AuthorizationEvent, CommonFields, Component, Decision, EventType, Finding,
    Obligations, Outcome, PolicyActivationEvent, Resource, Severity, TypedAuditEvent,
};

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ctx() -> CommonFields {
    CommonFields::new(
        "corr_s3_probe",
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

fn authorize(findings: Vec<Finding>) -> AuthorizationEvent {
    AuthorizationEvent::new(
        Resource::new("http_request", "graph.microsoft.com"),
        "http.post",
        Decision::Allow,
        "decision:1",
        "middleware.allowed",
    )
    .with_obligations(Obligations::default())
    .with_argument_summary(std::collections::BTreeMap::new())
    .with_findings(findings)
}

#[test]
fn an_allowed_request_can_carry_a_critical_finding() {
    // The reason this field exists. Nothing else in the record shows it.
    let event = authorize(vec![
        Finding::new("secret_detected", "github_pat", Severity::Critical).with_confidence(95),
    ])
    .into_audit_event(&ctx())
    .expect("allow-with-finding should validate");

    assert_eq!(event.decision, Some(Decision::Allow));
    let findings = event.findings.as_ref().expect("findings should be present");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].confidence, Some(95));
}

#[test]
fn duplicate_findings_are_permitted() {
    // `EffectEngine` pushes each resolved finding unconditionally, so two rules
    // referencing the same PolicyFinding legitimately produce identical
    // entries. The schema must not set uniqueItems.
    let duplicate = Finding::new("secret_detected", "aws_key", Severity::Critical);
    let event = authorize(vec![duplicate.clone(), duplicate])
        .into_audit_event(&ctx())
        .expect("duplicate findings must be permitted");

    assert_eq!(event.findings.as_ref().map(Vec::len), Some(2));
}

#[test]
fn finding_order_is_preserved() {
    // Order mirrors bundle manifest order, then policy order within a rule.
    // Consumers rely on it, so serialization must not sort or reorder.
    let event = authorize(vec![
        Finding::new("secret_detected", "github_pat", Severity::Critical),
        Finding::new("pii_detected", "email_address", Severity::Medium),
        Finding::new("budget_signal", "tool_call_count", Severity::Low),
    ])
    .into_audit_event(&ctx())
    .expect("event should validate");

    let json = serde_json::to_string(&event).expect("event should serialize");
    let parsed: AuditEvent = serde_json::from_str(&json).expect("event should round-trip");
    let labels: Vec<&str> = parsed
        .findings
        .as_ref()
        .expect("findings should survive the round-trip")
        .iter()
        .map(|finding| finding.label.as_str())
        .collect();
    assert_eq!(labels, ["github_pat", "email_address", "tool_call_count"]);
}

#[test]
fn findings_are_omitted_rather_than_emitted_empty() {
    // An empty array would be forbidden on event types that cannot carry
    // findings, so "none" must serialize as absence.
    let event = authorize(Vec::new())
        .into_audit_event(&ctx())
        .expect("event should validate");

    assert!(event.findings.is_none());
    let json = serde_json::to_string(&event).expect("event should serialize");
    assert!(!json.contains(r#""findings":"#), "got {json}");
}

#[test]
fn findings_are_not_permitted_on_non_decision_events() {
    // Same lesson as `security_state`: an unconstrained field is silently valid
    // everywhere. policy_activation has no evaluation and so no findings.
    let mut event = PolicyActivationEvent::new(Outcome::Success, "policy.bundle_verified")
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.findings = Some(vec![Finding::new(
        "secret_detected",
        "github_pat",
        Severity::Critical,
    )]);

    let error = event
        .validate()
        .expect_err("findings must not be permitted on policy_activation");
    assert!(
        error.violations().join("; ").contains("findings"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn findings_are_permitted_on_the_authorization_event() {
    // Authorization is the only event that evaluates a request, so it is the
    // only one that carries evaluation findings.
    let event = authorize(vec![Finding::new(
        "secret_detected",
        "github_pat",
        Severity::Critical,
    )])
    .into_audit_event(&ctx())
    .expect("authorization with findings should validate");

    event
        .validate()
        .expect("authorization must permit findings");
}

#[test]
fn a_finding_requires_kind_label_and_severity() {
    let event = authorize(vec![Finding::new(
        "secret_detected",
        "github_pat",
        Severity::Critical,
    )])
    .into_audit_event(&ctx())
    .expect("baseline should validate");

    let mut json = serde_json::to_value(&event).expect("event should serialize");
    json["findings"][0]
        .as_object_mut()
        .expect("finding should be an object")
        .remove("severity");

    let error = serde_json::from_value::<AuditEvent>(json)
        .expect_err("a finding without severity must not deserialize");
    assert!(error.to_string().contains("severity"), "got {error}");
}

#[test]
fn severity_serializes_as_snake_case() {
    let event = authorize(vec![
        Finding::new("secret_detected", "github_pat", Severity::Critical),
        Finding::new("pii_detected", "email_address", Severity::Medium),
    ])
    .into_audit_event(&ctx())
    .expect("event should validate");

    let json = serde_json::to_string(&event).expect("event should serialize");
    assert!(json.contains(r#""severity":"critical""#), "got {json}");
    assert!(json.contains(r#""severity":"medium""#), "got {json}");
}

#[test]
fn more_than_thirty_two_findings_are_rejected() {
    // Matches the middleware's MAX_FINDINGS_PER_STAGE, which already hard-denies
    // above this count.
    let findings = (0..33)
        .map(|_| Finding::new("secret_detected", "github_pat", Severity::Low))
        .collect();
    let error = authorize(findings)
        .into_audit_event(&ctx())
        .expect_err("more than 32 findings must be rejected");
    assert!(
        error.violations().join("; ").contains("findings"),
        "got {:?}",
        error.violations()
    );
}

// --- label/kind domain: bounded, but otherwise unconstrained ------------------------
//
// `label` is resolved at runtime from annotation values with no charset
// guarantee on the producing side (`CompiledFinding::resolve` in
// apf-policy-eval does no validation). A charset rule here would reject the
// *entire audit event* over a cosmetic label, which through the best-effort
// emit path means the record for an already-enforced decision is silently
// dropped. A bad label must cost the label, never the record.

#[test]
fn realistic_labels_do_not_destroy_the_event() {
    for label in [
        "AWS access key",       // spaces — the common case
        "github pat (classic)", // parentheses
        "kind/subkind",         // slash
        "clé_secrète",          // non-ASCII
        "",                     // neither label nor label_source set
        "github_pat",           // the symbolic style still works
    ] {
        authorize(vec![Finding::new(
            "secret_detected",
            label,
            Severity::Critical,
        )])
        .into_audit_event(&ctx())
        .unwrap_or_else(|error| panic!("label {label:?} must not invalidate the event: {error}"));
    }
}

#[test]
fn kind_accepts_descriptive_text_too() {
    authorize(vec![Finding::new(
        "secret detected (high confidence)",
        "AWS access key",
        Severity::Critical,
    )])
    .into_audit_event(&ctx())
    .expect("descriptive kind must be permitted");
}

#[test]
fn label_and_kind_are_length_bounded() {
    // The cap is the one constraint worth keeping: the value can be
    // annotation-derived, so it is attacker-influenceable in length, and these
    // records ship to a SIEM.
    let over = "a".repeat(257);
    authorize(vec![Finding::new("secret_detected", &over, Severity::Low)])
        .into_audit_event(&ctx())
        .expect_err("an over-long label must be rejected");
    authorize(vec![Finding::new(&over, "github_pat", Severity::Low)])
        .into_audit_event(&ctx())
        .expect_err("an over-long kind must be rejected");

    let at_limit = "a".repeat(256);
    authorize(vec![Finding::new(
        "secret_detected",
        &at_limit,
        Severity::Low,
    )])
    .into_audit_event(&ctx())
    .expect("a label at the limit must be accepted");
}

#[test]
fn a_credential_shaped_label_is_still_caught_by_sanitization() {
    // Relaxing the charset must not weaken the credential scanner, which is
    // what actually protects this field.
    use apf_audit::{AuditEmitter, AuditSink, EmitOutcome};

    struct Discard;
    impl AuditSink for Discard {
        fn write_event(&self, _event: &AuditEvent) -> Result<(), apf_audit::AuditError> {
            Ok(())
        }
    }

    let event = authorize(vec![Finding::new(
        "secret_detected",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        Severity::Critical,
    )])
    .into_audit_event(&ctx())
    .expect("event should validate — the charset no longer objects");

    let outcome = AuditEmitter::new(Discard).emit_best_effort(&event);
    assert!(
        matches!(outcome, EmitOutcome::Failed(_)),
        "a credential-shaped label must still be caught by the sanitizer, got {outcome:?}"
    );
}

// --- verdict -------------------------------------------------------------------
//
// `Verdict::Warn` previously did not deserialize at all — the audit `decision`
// enum has no such member. Carrying it as its own field keeps "allowed" and
// "allowed with elevated signal" distinguishable.

#[test]
fn warn_is_an_allow_with_a_separate_signal() {
    let event = authorize(vec![])
        .with_verdict(apf_audit::Verdict::Warn)
        .into_audit_event(&ctx())
        .expect("warn verdict should validate");

    assert_eq!(event.decision, Some(Decision::Allow));
    assert_eq!(event.verdict, Some(apf_audit::Verdict::Warn));

    let json = serde_json::to_string(&event).expect("should serialize");
    assert!(json.contains(r#""verdict":"warn""#), "got {json}");
}

#[test]
fn every_verdict_variant_round_trips() {
    for verdict in [
        apf_audit::Verdict::Allow,
        apf_audit::Verdict::Warn,
        apf_audit::Verdict::Escalate,
    ] {
        let event = authorize(vec![])
            .with_verdict(verdict)
            .into_audit_event(&ctx())
            .expect("verdict should validate");
        let json = serde_json::to_string(&event).expect("should serialize");
        let parsed: AuditEvent = serde_json::from_str(&json).expect("should round-trip");
        assert_eq!(parsed.verdict, Some(verdict));
    }
}

#[test]
fn verdict_is_omitted_when_unset() {
    let event = authorize(vec![])
        .into_audit_event(&ctx())
        .expect("should validate");
    assert!(event.verdict.is_none());
    let json = serde_json::to_string(&event).expect("should serialize");
    assert!(!json.contains(r#""verdict":"#), "got {json}");
}

#[test]
fn verdict_is_not_permitted_on_non_decision_events() {
    let mut event = PolicyActivationEvent::new(Outcome::Success, "policy.bundle_verified")
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.verdict = Some(apf_audit::Verdict::Warn);

    let error = event
        .validate()
        .expect_err("verdict must not be permitted on policy_activation");
    assert!(
        error.violations().join("; ").contains("verdict"),
        "got {:?}",
        error.violations()
    );
}

// --- verdict / synthetic-finding duplication ----------------------------------------
//
// The OpenShell wire has findings but no verdict field, so the middleware
// injects a synthetic `policy_verdict` finding on the allow path. Audit has a
// real verdict field, so carrying both records the same advisory signal twice.
// Both reviewers found this independently; it is guarded at two layers because
// the schema binds every producer while the builder catches the Rust one at the
// call site.

#[test]
fn setting_a_verdict_drops_the_synthetic_finding() {
    // The natural mistake: pass the wire list, which already contains the
    // stand-in, and also set the verdict.
    let event = authorize(vec![
        Finding::new("secret_detected", "github_pat", Severity::Critical),
        Finding::new("policy_verdict", "warn", Severity::Medium),
    ])
    .with_verdict(apf_audit::Verdict::Warn)
    .into_audit_event(&ctx())
    .expect("the builder should reconcile this rather than reject it");

    let findings = event
        .findings
        .as_ref()
        .expect("the real finding should survive");
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].kind, "secret_detected");
    assert_eq!(event.verdict, Some(apf_audit::Verdict::Warn));
}

#[test]
fn builder_order_does_not_matter() {
    // with_findings after with_verdict must filter too, or the guard depends on
    // call order.
    let event = authorize(vec![])
        .with_verdict(apf_audit::Verdict::Escalate)
        .with_findings(vec![Finding::new(
            "policy_verdict",
            "escalate",
            Severity::High,
        )])
        .into_audit_event(&ctx())
        .expect("should validate regardless of builder order");

    assert!(event.findings.is_none(), "got {:?}", event.findings);
}

#[test]
fn the_schema_rejects_the_duplicate_independently_of_the_builder() {
    // The builder filters, so reach past it: the schema must hold for any
    // producer, including non-Rust ones.
    let mut event = authorize(vec![Finding::new(
        "secret_detected",
        "github_pat",
        Severity::Critical,
    )])
    .with_verdict(apf_audit::Verdict::Warn)
    .into_audit_event(&ctx())
    .expect("baseline should validate");

    // The literal, not the crate constant: this pins the value the OpenShell
    // wire actually sends, so the two cannot drift together unnoticed.
    event.findings = Some(vec![Finding::new(
        "policy_verdict",
        "warn",
        Severity::Medium,
    )]);

    event
        .validate()
        .expect_err("verdict + synthetic policy_verdict finding must be rejected");
}

#[test]
fn a_producer_without_a_verdict_may_still_send_the_synthetic_finding() {
    // Back-compatibility: a producer that predates `verdict` and emits only the
    // stand-in stays valid.
    let mut event = authorize(vec![])
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.findings = Some(vec![Finding::new(
        "policy_verdict",
        "warn",
        Severity::Medium,
    )]);

    event
        .validate()
        .expect("the synthetic finding alone must remain valid");
}

#[test]
fn verdict_is_ordered_by_severity() {
    // Upstream aggregates concurrent effects with `.max()`; a consumer computing
    // the strongest verdict across a correlation must not hand-roll a rank.
    use apf_audit::Verdict;
    assert!(Verdict::Allow < Verdict::Warn);
    assert!(Verdict::Warn < Verdict::Escalate);
    assert_eq!(
        [Verdict::Allow, Verdict::Escalate, Verdict::Warn]
            .into_iter()
            .max(),
        Some(Verdict::Escalate)
    );
}

#[test]
fn advisory_signals_are_confined_to_evaluating_event_types() {
    // Pins the exact matrix. The schema restructure bundled findings/verdict
    // into a shared `decision_fields` fragment, which leaked them onto
    // credential and review events — those are DOWNSTREAM of a decision and
    // must not re-report its signals. A table beats one spot-check here,
    // because the leak was invisible until every type was swept.
    use apf_audit::{AuditEvent, CredentialScope, ResultClass, ReviewRef};

    let permitted = [EventType::Authorization];
    let forbidden = [
        EventType::Authentication,
        EventType::PolicyActivation,
        EventType::PolicyVerification,
        EventType::PolicyDistribution,
        EventType::PolicyRefresh,
        EventType::ProvenanceSigning,
        EventType::PolicyInjection,
        EventType::AdmissionValidation,
        EventType::ConfigGovernance,
        EventType::CredentialIssuance,
        EventType::ReviewRequest,
        EventType::ReviewDecision,
        EventType::PolicyServiceStartup,
    ];

    for event_type in permitted.into_iter().chain(forbidden) {
        let mut event = AuditEvent::new(event_type, ctx());
        // Populate enough of every shape that the only interesting violation
        // is the advisory one.
        event.resource = Some(Resource::new("mailbox", "user@corp"));
        event.verb = Some("mail.search".to_owned());
        event.decision = Some(Decision::Allow);
        event.decision_id = Some("decision:1".to_owned());
        event.reason_code = Some("x.y".to_owned());
        event.argument_summary = Some(Default::default());
        event.obligations = Some(Default::default());
        event.result_class = Some(ResultClass::Success);
        event.result_summary = Some(Default::default());
        event.credential_request_id = Some("credreq:1".to_owned());
        event.credential_scope = Some(CredentialScope {
            provider: "graph".to_owned(),
            mode: None,
            audience: "graph.microsoft.com".to_owned(),
            scopes: vec!["Mail.Read".to_owned()],
            ttl_seconds: None,
            expires_at: None,
            decision_id: None,
        });
        event.review_ref = Some(ReviewRef {
            review_id: "review:1".to_owned(),
            status: "approved".to_owned(),
            reviewer_id: None,
            decision_at: None,
            evidence_ref: None,
        });
        event.findings = Some(vec![Finding::new(
            "secret_detected",
            "github_pat",
            Severity::Critical,
        )]);
        event.verdict = Some(apf_audit::Verdict::Warn);

        let violations = match event.validate() {
            Ok(()) => String::new(),
            Err(error) => error.violations().join("; "),
        };
        let rejected = violations.contains("findings") || violations.contains("verdict");

        if permitted.contains(&event_type) {
            assert!(
                !rejected,
                "{event_type} evaluates, so it must carry advisory signals: {violations}"
            );
        } else {
            assert!(
                rejected,
                "{event_type} does not evaluate, so it must not carry advisory signals"
            );
        }
    }
}

#[test]
fn event_types_pin_their_own_result_class() {
    // A credential_issuance means a credential WAS issued: any result class
    // other than success contradicts the event type, and the schema pins it so
    // the contradiction is unrepresentable.
    use apf_audit::{AuditEvent, CredentialScope, ResultClass};

    let mut issue = AuditEvent::new(EventType::CredentialIssuance, ctx());
    issue.resource = Some(Resource::new("mailbox", "user@corp"));
    issue.verb = Some("mail.search".to_owned());
    issue.outcome = Some(apf_audit::Outcome::Success);
    issue.decision_id = Some("decision:1".to_owned());
    issue.reason_code = Some("credential.issued".to_owned());
    issue.credential_request_id = Some("credreq:1".to_owned());
    issue.credential_scope = Some(CredentialScope {
        provider: "graph".to_owned(),
        mode: None,
        audience: "graph.microsoft.com".to_owned(),
        scopes: vec!["Mail.Read".to_owned()],
        ttl_seconds: None,
        expires_at: None,
        decision_id: None,
    });
    issue.result_class = Some(ResultClass::Success);
    issue
        .clone()
        .validate()
        .expect("success is the only valid outcome");
    for wrong in [
        ResultClass::Denied,
        ResultClass::Failure,
        ResultClass::Timeout,
    ] {
        let mut event = issue.clone();
        event.result_class = Some(wrong);
        event
            .validate()
            .unwrap_err_or_panic("credential_issuance must pin result_class to success");
    }

    // A refused issuance has no credential to classify, so result_class — even
    // `success` — must not ride on it: read `outcome` for success vs refused.
    let mut refused = issue.clone();
    refused.outcome = Some(apf_audit::Outcome::Refused);
    refused.reason_code = Some("credential.denied".to_owned());
    refused.error_info = Some(apf_audit::AuditErrorInfo {
        code: "credential.denied".to_owned(),
        message: "scope exceeds the authorized decision".to_owned(),
        retryable: Some(false),
    });
    refused.result_class = None;
    refused
        .clone()
        .validate()
        .expect("a refused issuance without result_class should validate");
    refused.result_class = Some(ResultClass::Success);
    refused
        .validate()
        .unwrap_err_or_panic("a refused issuance must not carry result_class");
}

trait UnwrapErrOrPanic {
    fn unwrap_err_or_panic(self, message: &str);
}
impl UnwrapErrOrPanic for Result<(), apf_audit::ValidationError> {
    fn unwrap_err_or_panic(self, message: &str) {
        assert!(self.is_err(), "{message}");
    }
}

#[test]
fn a_bad_value_in_a_shared_block_still_names_the_real_cause() {
    // Each event composes shared $ref blocks, so one bad property fails the
    // whole subschema and `unevaluatedProperties` additionally names every
    // field in that block. That extra message is noisy but honest, and three
    // attempts at filtering it either hid genuine unknown-field errors or left
    // the cascade almost intact — so the validator reports what the schema
    // says and the schema description explains how to read it.
    //
    // What must hold: the real cause is always present and identifiable.
    let mut event = AuthorizationEvent::new(
        Resource::new("http_request", "graph.microsoft.com"),
        "http.post",
        Decision::Allow,
        "decision:1",
        "middleware.allowed",
    )
    .with_obligations(Obligations::default())
    .with_argument_summary(std::collections::BTreeMap::new())
    .into_audit_event(&ctx())
    .expect("baseline should validate");
    event.reason_code = Some("Not A Code".to_owned());

    let violations = event
        .validate()
        .expect_err("bad reason_code must fail")
        .violations()
        .to_vec();
    assert!(
        violations.iter().any(|v| v.starts_with("/reason_code:")),
        "the value-level cause must be reported: {violations:?}"
    );

    // A genuinely unknown field is reported, and is never suppressed by an
    // unrelated failure elsewhere in the event.
    let mut stray = PolicyActivationEvent::new(Outcome::Success, "policy.bundle_verified")
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    stray.security_state = Some(apf_audit::SecurityState::Secure);
    let violations = stray
        .validate()
        .expect_err("stray field must fail")
        .violations()
        .to_vec();
    assert!(
        violations.iter().any(|v| v.contains("security_state")),
        "got {violations:?}"
    );

    // Both at once: neither masks the other.
    let mut both = event.clone();
    both.security_state = Some(apf_audit::SecurityState::Secure);
    let violations = both
        .validate()
        .expect_err("must fail")
        .violations()
        .join("; ");
    assert!(violations.contains("/reason_code:"), "got {violations}");
    assert!(violations.contains("security_state"), "got {violations}");
}

#[test]
fn identical_violations_are_reported_once() {
    // `envelope` is applied at the root and again inside each event def. Both
    // refs are load-bearing — the root one is what gives a clean error when no
    // dispatch branch matches — so an envelope violation fires twice.
    // Deduplicating identical messages is safe; dropping violations by kind is
    // not, and distinct causes must all survive.
    use apf_audit::AuditEvent;

    let mut common = ctx();
    common.correlation_id = "!!bad!!".to_owned();
    let mut event = AuditEvent::new(EventType::PolicyActivation, common);
    event.reason_code = Some("policy.bundle_verified".to_owned());

    let violations = event
        .validate()
        .expect_err("a malformed correlation_id must fail")
        .violations()
        .to_vec();
    let correlation_faults = violations
        .iter()
        .filter(|violation| violation.starts_with("/correlation_id:"))
        .count();
    assert_eq!(
        correlation_faults, 1,
        "one fault should be reported once, got {violations:?}"
    );

    // Two genuinely different faults must both survive the dedup.
    let mut common = ctx();
    common.correlation_id = "!!bad!!".to_owned();
    common.bundle_id = Some("!!alsobad!!".to_owned());
    let mut event = AuditEvent::new(EventType::PolicyActivation, common);
    event.reason_code = Some("policy.bundle_verified".to_owned());

    let violations = event
        .validate()
        .expect_err("both faults must fail")
        .violations()
        .join("; ");
    assert!(violations.contains("/correlation_id:"), "got {violations}");
    assert!(violations.contains("/bundle_id:"), "got {violations}");
}

#[test]
fn the_real_cause_is_reported_before_the_cascade() {
    // The schema description tells readers to "read the value-level violation
    // first; the unevaluated list that accompanies it is a consequence". That
    // is only actionable if the order is stable — and nothing else pins it, so
    // a future sort, partition or HashSet in validate_with_json_schema would
    // silently invalidate the documentation while every other test stayed green.
    let mut event = AuthorizationEvent::new(
        Resource::new("http_request", "graph.microsoft.com"),
        "http.post",
        Decision::Allow,
        "decision:1",
        "middleware.allowed",
    )
    .with_obligations(Obligations::default())
    .with_argument_summary(std::collections::BTreeMap::new())
    .into_audit_event(&ctx())
    .expect("baseline should validate");
    event.reason_code = Some("Not A Code".to_owned());

    let violations = event
        .validate()
        .expect_err("bad reason_code must fail")
        .violations()
        .to_vec();

    let cause = violations
        .iter()
        .position(|violation| !violation.contains("Unevaluated"));
    let cascade = violations
        .iter()
        .position(|violation| violation.contains("Unevaluated"));
    assert!(
        cause < cascade,
        "the real cause must precede the cascade: {violations:?}"
    );
}

#[test]
fn distinct_faults_at_one_path_both_survive_dedup() {
    // The only shape where dedup's safety is not guaranteed by the instance
    // path prefix: two faults reported at the SAME path with different text.
    // Here both bad extension keys are reported at `/extensions`, so this is
    // the case where the test is load-bearing rather than confirmatory.
    use apf_audit::AuditEvent;
    use std::collections::BTreeMap;

    let mut event = AuditEvent::new(EventType::PolicyActivation, ctx());
    event.reason_code = Some("policy.bundle_verified".to_owned());

    // The namespace keys carry the constraint (`^x_[a-z][a-z0-9_]*$`), so two
    // bad namespaces both fault at `/extensions`.
    let mut extensions = BTreeMap::new();
    extensions.insert("BAD1".to_owned(), BTreeMap::new());
    extensions.insert("BAD2".to_owned(), BTreeMap::new());
    event.extensions = Some(extensions);

    let violations = event
        .validate()
        .expect_err("malformed extension keys must fail")
        .violations()
        .join("; ");
    assert!(violations.contains("BAD1"), "got {violations}");
    assert!(violations.contains("BAD2"), "got {violations}");
}

/// `accepts_string` lets a producer drop one unrecordable field instead of
/// losing the record. It duplicates `check`'s rules, so a drift would be
/// silent: a producer would keep a value the guard then rejects, and the whole
/// record would degrade — exactly what asking was meant to avoid.
#[test]
fn accepts_string_agrees_with_the_guard_it_speaks_for() {
    use apf_audit::SanitizationGuard;

    let cases = [
        // Ordinary values a policy would plausibly author.
        "x-openshell-middleware-trace",
        "/messages/0/content",
        "content.class",
        // Credential-shaped, including the substring case that motivated this:
        // "task-classification" contains "sk-".
        "x-openshell-middleware-task-classification-id",
        "sk-abcdefghijklmnopqrstuvwxyz",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "AKIAIOSFODNN7EXAMPLE",
        "aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccccccccccc",
    ];

    // The length rule is not exercised here: `label` caps at 256, well under
    // the guard's 2048, so no value reaches it through this field. Both sides
    // read the same constant.
    for case in cases {
        // The label is unpatterned, so the value reaches the guard unchanged
        // and the event's fate is decided by the guard alone.
        let event = authorize(vec![Finding::new("probe", case, Severity::Low)])
            .into_audit_event(&ctx())
            .expect("an unpatterned label always validates");
        let guard_accepts = SanitizationGuard::new().check(&event).is_ok();

        assert_eq!(
            SanitizationGuard::accepts_string(case),
            guard_accepts,
            "predicate and guard disagree on {case:?}"
        );
    }
}
