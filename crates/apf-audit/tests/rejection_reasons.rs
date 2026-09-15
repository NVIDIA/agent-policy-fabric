// SPDX-License-Identifier: Apache-2.0
//! `rejection_reasons[]` and the `error.message` budget.
//!
//! `verify_bundle` accumulates rather than short-circuits — a bundle can fail
//! expiry *and* runtime-compat *and* the monotonic counter at once. The schema
//! has one `reason_code`, so without this field the other failures are lost.
//!
//! The message cap is the sharper problem: ten reasons at ~80 characters each
//! overflow the 1024-byte limit, and a `policy_verification` that fails to serialize
//! is the one record you cannot afford to lose.

use apf_audit::{
    AuditErrorInfo, AuditEvent, CommonFields, Component, ERROR_MESSAGE_MAX_BYTES, EventType,
    Outcome, PolicyActivationEvent, PolicyVerificationEvent, TypedAuditEvent,
    join_rejection_detail, normalize_rejection_reasons,
};

/// Old two-arg PolicyReject shape, mapped onto the new vocabulary.
fn policy_reject(
    reason_code: impl Into<String>,
    error: apf_audit::AuditErrorInfo,
) -> PolicyVerificationEvent {
    PolicyVerificationEvent::new(Outcome::Refused, reason_code).with_error(error)
}

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ctx() -> CommonFields {
    CommonFields::new(
        "corr_reject_1",
        "user:example",
        "agent:example",
        "workspace:example",
        "session:example",
        "apf-policy-service:local",
        "openshell",
        Component::new("apf-policy-service", "0.1.0", "svc-0"),
        DIGEST,
        "trustroot:apf",
    )
}

/// The real shape `verify_bundle` produces: prefixed code, colon, detail.
fn verifier_reasons() -> Vec<String> {
    vec![
        "counter_regression: bundle counter 5 <= high-water-mark 7".to_owned(),
        "bundle_expired: now 2026-09-03T00:00:00Z > expires_at 2026-08-01T00:00:00Z".to_owned(),
        "runtime_compat_mismatch: bundle requires openshell >= 0.3.0, caller is 0.2.0".to_owned(),
    ]
}

fn reject(reasons: Vec<String>) -> AuditEvent {
    let mut event = policy_reject(
        "policy.bundle_rejected.counter_regression",
        AuditErrorInfo {
            code: "policy.bundle_rejected.counter_regression".to_owned(),
            message: join_rejection_detail(&verifier_reasons()),
            retryable: Some(false),
        },
    )
    .into_audit_event(&ctx())
    .expect("baseline reject should validate");
    event.rejection_reasons = Some(reasons);
    event
}

#[test]
fn a_reject_can_carry_every_failed_check() {
    let event = reject(vec![
        "counter_regression".to_owned(),
        "bundle_expired".to_owned(),
        "runtime_compat_mismatch".to_owned(),
    ]);
    event.validate().expect("multiple reasons should validate");

    // reason_code still names the primary cause; the array carries the rest.
    assert_eq!(
        event.reason_code.as_deref(),
        Some("policy.bundle_rejected.counter_regression")
    );
    assert_eq!(event.rejection_reasons.as_ref().map(Vec::len), Some(3));
}

#[test]
fn reasons_must_be_normalized_codes_not_raw_strings() {
    // The raw verifier strings contain spaces, colons and `<=`, none of which
    // are legal reason codes — that detail belongs in error.message.
    let event = reject(verifier_reasons());
    event
        .validate()
        .expect_err("raw verifier strings must not be accepted as reason codes");
}

#[test]
fn duplicate_reasons_are_rejected() {
    let event = reject(vec![
        "bundle_expired".to_owned(),
        "bundle_expired".to_owned(),
    ]);
    event
        .validate()
        .expect_err("the same check cannot fail twice");
}

#[test]
fn rejection_reasons_are_confined_to_events_that_accumulate_them() {
    let mut event = PolicyActivationEvent::new(Outcome::Success, "policy.bundle_verified")
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.rejection_reasons = Some(vec!["bundle_expired".to_owned()]);

    let error = event
        .validate()
        .expect_err("rejection_reasons must not be permitted on policy_activation");
    assert!(
        error.violations().join("; ").contains("rejection_reasons"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn a_startup_event_may_also_accumulate_reasons() {
    // A boot can be degraded for several independent reasons at once, the same
    // shape of problem as a bundle failing several checks.
    let mut event = reject(vec!["bundle_expired".to_owned()]);
    event.event_type = EventType::PolicyServiceStartup;
    // policy_service_startup forbids policy identity AND subject identity — a
    // boot precedes any user or session. Both sets must go.
    event.bundle_digest = None;
    event.trust_root_id = None;
    event.policy_revision = None;
    event.outcome = None;
    event.user_id = None;
    event.agent_id = None;
    event.session_id = None;
    event.workspace_id = None;
    event.security_state = Some(apf_audit::SecurityState::Degraded);
    event.rejection_reasons = Some(vec![
        "startup.insecure_transport_enabled".to_owned(),
        "startup.provenance_verification_disabled".to_owned(),
    ]);

    event
        .validate()
        .expect("a startup event should accept multiple degraded-control reasons");
}

// --- error.message budget -----------------------------------------------------

#[test]
fn a_short_detail_is_left_alone() {
    let joined = join_rejection_detail(&verifier_reasons());
    assert!(joined.len() <= ERROR_MESSAGE_MAX_BYTES);
    assert!(joined.contains("counter_regression"));
    assert!(
        !joined.contains("[+"),
        "should not be marked truncated: {joined}"
    );
}

#[test]
fn an_overlong_detail_is_truncated_and_marked() {
    // Ten realistic reasons overflow the cap.
    let many: Vec<String> = (0..10)
        .map(|i| format!("runtime_compat_mismatch: bundle requires adapter-{i} >= 1.2.3, caller is 0.9.0, which is outside the declared compatibility window"))
        .collect();
    let joined = join_rejection_detail(&many);

    assert!(
        joined.len() <= ERROR_MESSAGE_MAX_BYTES,
        "must fit the cap, got {} bytes",
        joined.len()
    );
    assert!(
        joined.contains("[+"),
        "truncation must be visible: {joined}"
    );
}

/// Bytes of actual detail, excluding the ` [+N more]` marker.
fn content_len(message: &str) -> usize {
    message.split(" [+").next().unwrap_or_default().len()
}

#[test]
fn a_single_oversized_reason_keeps_a_prefix_of_it() {
    // `verify_bundle` early-returns exactly one long reason on signature or
    // parse failure, so this is the most likely truncating path, not an edge
    // case. An earlier version emitted the marker alone — and the test asserted
    // only `len <= cap`, which " [+1 more]" satisfies. The property that
    // matters is that diagnostic content SURVIVES.
    let one = vec![format!("bundle_parse_failed: {}", "x".repeat(4096))];
    let joined = join_rejection_detail(&one);

    assert!(
        joined.len() <= ERROR_MESSAGE_MAX_BYTES,
        "got {}",
        joined.len()
    );
    assert!(
        joined.starts_with("bundle_parse_failed:"),
        "the reason must stay recognisable: {joined}"
    );
    assert!(
        content_len(&joined) > ERROR_MESSAGE_MAX_BYTES * 3 / 4,
        "most of the budget should carry content, got {} of {ERROR_MESSAGE_MAX_BYTES}",
        content_len(&joined)
    );
}

#[test]
fn truncation_uses_most_of_the_available_budget() {
    // Guards against regressing toward "drop everything, it still fits".
    let many: Vec<String> = (0..16)
        .map(|i| {
            format!(
                "manifest_hash_mismatch: members/policy-{i}.yaml declared abc123, actual def456"
            )
        })
        .collect();
    let joined = join_rejection_detail(&many);

    assert!(joined.len() <= ERROR_MESSAGE_MAX_BYTES);
    assert!(
        content_len(&joined) > ERROR_MESSAGE_MAX_BYTES * 3 / 4,
        "only {} of {ERROR_MESSAGE_MAX_BYTES} bytes used",
        content_len(&joined)
    );
}

#[test]
fn an_empty_reason_list_still_yields_a_valid_message() {
    // `error.message` has minLength 1, so an empty join would invalidate the
    // event a defensive producer was trying to emit.
    let joined = join_rejection_detail(&[]);
    assert!(!joined.is_empty());

    policy_reject(
        "policy.bundle_rejected.signature_invalid",
        AuditErrorInfo {
            code: "policy.bundle_rejected.signature_invalid".to_owned(),
            message: joined,
            retryable: Some(false),
        },
    )
    .into_audit_event(&ctx())
    .expect("an empty reason list must still produce a valid event");
}

// --- normalizer ---------------------------------------------------------------------

#[test]
fn the_normalizer_turns_verifier_output_into_valid_codes() {
    // The assignment that compiles and destroys the record:
    //   event.rejection_reasons = Some(outcome.rejection_reasons)
    // The verifier emits prose; the schema demands reason codes.
    let normalized = apf_audit::normalize_rejection_reasons(&verifier_reasons());
    assert_eq!(
        normalized,
        vec![
            "counter_regression",
            "bundle_expired",
            "runtime_compat_mismatch"
        ]
    );
    reject(normalized)
        .validate()
        .expect("normalized codes must validate");
}

#[test]
fn the_normalizer_dedups_because_verify_bundle_repeats_codes() {
    // check_manifest_hashes pushes per manifest entry and check_runtime_compat
    // per adapter, so the same code legitimately repeats. `uniqueItems` is only
    // a safe constraint because this collapses them.
    let raw = vec![
        "manifest_hash_mismatch: members/a.yaml: declared x, actual y".to_owned(),
        "manifest_hash_mismatch: members/b.yaml: declared x, actual y".to_owned(),
        "manifest_hash_mismatch: members/c.yaml: declared x, actual y".to_owned(),
    ];
    assert_eq!(
        apf_audit::normalize_rejection_reasons(&raw),
        vec!["manifest_hash_mismatch"]
    );
    reject(apf_audit::normalize_rejection_reasons(&raw))
        .validate()
        .expect("deduped codes must validate");
}

#[test]
fn the_normalizer_respects_the_schema_cap() {
    let raw: Vec<String> = (0..40).map(|i| format!("check_{i}: detail")).collect();
    let normalized = apf_audit::normalize_rejection_reasons(&raw);
    assert_eq!(normalized.len(), apf_audit::MAX_REJECTION_REASONS);
    reject(normalized)
        .validate()
        .expect("must validate at the cap");
}

#[test]
fn the_normalizer_drops_anything_that_is_not_a_reason_code() {
    let raw = vec![
        "Not A Code: detail".to_owned(),
        "UPPER: detail".to_owned(),
        "valid_code: detail".to_owned(),
        String::new(),
    ];
    assert_eq!(
        apf_audit::normalize_rejection_reasons(&raw),
        vec!["valid_code"]
    );
}

#[test]
fn a_secure_startup_rejects_rejection_reasons() {
    // Same contradiction the schema already blocks for `error`: a secure boot
    // cannot also list checks that failed.
    let startup = apf_audit::StartupContext::new(
        "corr_boot",
        "apf-policy-gateway:local",
        "openshell",
        Component::new("apf-policy-gateway", "0.1.0", "gw-0"),
    )
    .expect("startup context should be valid");

    let mut event = apf_audit::PolicyServiceStartupEvent::secure()
        .into_audit_event(&startup)
        .expect("baseline should validate");
    event.rejection_reasons = Some(vec!["startup.insecure_transport_enabled".to_owned()]);

    event
        .validate()
        .expect_err("a secure boot must not list failed checks");
}

#[test]
fn truncation_never_splits_a_character() {
    // Multi-byte characters straddling the cut point must not produce invalid
    // UTF-8 — the message is a Rust String, so a bad cut would panic.
    let many: Vec<String> = (0..40).map(|_| "é".repeat(60)).collect();
    let joined = join_rejection_detail(&many);
    assert!(joined.len() <= ERROR_MESSAGE_MAX_BYTES);
    assert!(joined.is_char_boundary(joined.len()));
}

#[test]
fn a_truncated_detail_still_validates_on_a_real_event() {
    // The point of the helper: whatever the producer throws at it, the event
    // must still serialize and validate.
    let many: Vec<String> = (0..16)
        .map(|i| {
            format!(
                "manifest_hash_mismatch: members/policy-{i}.yaml declared abc123, actual def456"
            )
        })
        .collect();

    policy_reject(
        "policy.bundle_rejected.manifest_hash_mismatch",
        AuditErrorInfo {
            code: "policy.bundle_rejected.manifest_hash_mismatch".to_owned(),
            message: join_rejection_detail(&many),
            retryable: Some(false),
        },
    )
    .into_audit_event(&ctx())
    .expect("a truncated message must still produce a valid event");
}

#[test]
fn an_untruncated_detail_would_have_failed() {
    // Guards the helper's reason for existing: without it, the naive join is
    // rejected by the schema.
    let many: Vec<String> = (0..16)
        .map(|i| {
            format!(
                "manifest_hash_mismatch: members/policy-{i}.yaml declared abc123, actual def456"
            )
        })
        .collect();
    let naive = many.join("; ");
    assert!(naive.len() > ERROR_MESSAGE_MAX_BYTES);

    policy_reject(
        "policy.bundle_rejected.manifest_hash_mismatch",
        AuditErrorInfo {
            code: "policy.bundle_rejected.manifest_hash_mismatch".to_owned(),
            message: naive,
            retryable: Some(false),
        },
    )
    .into_audit_event(&ctx())
    .expect_err("the naive join must be rejected — this is why the helper exists");
}

// --- normalizer must guarantee schema-valid output ----------------------------------
//
// The normalizer is documented as "the conversion producers must go through".
// A conversion that can still emit an invalid code is the defect it exists to
// remove — the producer does the right thing and the record is destroyed anyway.

#[test]
fn the_normalizer_enforces_the_reason_code_length_bound() {
    use apf_audit::REASON_CODE_MAX_BYTES;

    // At the bound: kept, and the resulting event validates.
    let at_limit = vec![format!("{}: detail", "a".repeat(REASON_CODE_MAX_BYTES))];
    let kept = apf_audit::normalize_rejection_reasons(&at_limit);
    assert_eq!(kept.len(), 1);
    reject(kept)
        .validate()
        .expect("a code at the bound must validate");

    // One byte over: dropped rather than passed through to fail validation.
    for over in [REASON_CODE_MAX_BYTES + 1, 300] {
        let raw = vec![format!("{}: detail", "a".repeat(over))];
        assert!(
            apf_audit::normalize_rejection_reasons(&raw).is_empty(),
            "a {over}-byte prefix must not be returned as a code"
        );
    }
}

#[test]
fn a_reason_with_no_colon_is_not_silently_promoted_to_a_code() {
    // split(':').next() returns the whole string when there is no colon, so a
    // long prose message would otherwise become a 200+ byte "code".
    let raw = vec!["a_long_message_with_no_colon_anywhere_in_it".repeat(6)];
    assert!(apf_audit::normalize_rejection_reasons(&raw).is_empty());
}

#[test]
fn whatever_the_normalizer_returns_always_validates() {
    // The property that matters: no input produces output the schema rejects.
    let adversarial: Vec<String> = vec![
        "counter_regression: bundle counter 5 <= high-water-mark 7".into(),
        format!("{}: over the length bound", "z".repeat(400)),
        "UPPER_CASE: detail".into(),
        "has space: detail".into(),
        ".leading_dot: detail".into(),
        "trailing_dot.: detail".into(),
        "double..dot: detail".into(),
        "no_colon_at_all".into(),
        String::new(),
        "é_non_ascii: detail".into(),
        "bundle_expired: now > expires_at".into(),
    ];
    let normalized = apf_audit::normalize_rejection_reasons(&adversarial);
    reject(normalized)
        .validate()
        .expect("normalizer output must always be schema-valid");
}

#[test]
fn an_all_empty_reason_list_still_yields_a_valid_message() {
    // `&[]` and `&[String::new()]` are equally empty; guarding the input slice
    // alone missed the second.
    for input in [vec![], vec![String::new()]] {
        let joined = join_rejection_detail(&input);
        assert!(!joined.is_empty(), "got {joined:?}");
    }
}

#[test]
fn a_clipped_single_reason_does_not_claim_another_exists() {
    // The marker is the only signal a reader has that content was cut, so it
    // must not imply a reason they are not seeing.
    let one = vec![format!("bundle_parse_failed: {}", "x".repeat(4096))];
    let joined = join_rejection_detail(&one);
    assert!(
        joined.ends_with('…'),
        "got tail {:?}",
        &joined[joined.len() - 12..]
    );
    assert!(
        !joined.contains("[+"),
        "n=1 must not claim omitted reasons: {joined}"
    );

    // With a genuine second reason, the count reflects only what is absent.
    let two = vec![
        format!("bundle_parse_failed: {}", "x".repeat(4096)),
        "bundle_expired: detail".to_owned(),
    ];
    assert!(join_rejection_detail(&two).ends_with("[+1 more]"));
}

#[test]
fn a_rejection_whose_reasons_are_all_prose_is_still_recorded() {
    // normalize_rejection_reasons yields [] when nothing parses as a reason
    // code, and the schema requires at least one entry. Assigning that directly
    // would fail validation and destroy the record of a bundle that really was
    // rejected — the one record you cannot afford to lose. The setter drops the
    // field instead; the prose survives in error.message.
    let prose = vec![
        "the bundle looked wrong to me".to_owned(),
        "something went badly".to_owned(),
    ];
    let codes = normalize_rejection_reasons(&prose);
    assert!(codes.is_empty(), "precondition: no code survives");

    let mut event = reject(Vec::new());
    event.rejection_reasons = None;
    event.set_rejection_reasons(codes);

    assert!(
        event.rejection_reasons.is_none(),
        "an empty reason list must be dropped, not serialized as []"
    );
    event
        .validate()
        .expect("the rejection must still be recorded");
}

#[test]
fn surviving_reason_codes_are_kept() {
    // The guard must not swallow the normal case.
    let mut event = reject(Vec::new());
    event.rejection_reasons = None;
    event.set_rejection_reasons(normalize_rejection_reasons(&[
        "bundle_expired".to_owned(),
        "prose that does not parse".to_owned(),
    ]));

    assert_eq!(
        event.rejection_reasons.as_deref(),
        Some(["bundle_expired".to_owned()].as_slice())
    );
    event.validate().expect("should validate");
}
