// SPDX-License-Identifier: Apache-2.0
//! `effects{}` — what the enforcement point applied to a request in flight.
//!
//! On *allow*, the middleware rewrites live agent traffic: body patches, whole
//! replacement, header mutations. The request the agent sent is not the request
//! that reached the destination. Without this field the audit record says
//! "allow" and nothing about the rewrite, so you cannot tell a redaction that
//! fired from one that silently didn't.

use apf_audit::{
    AuditEvent, AuthorizationEvent, CommonFields, Component, Decision, Effects, EventType,
    HeaderAction, HeaderMutationRecord, MAX_RECORDED_PATCHES, Obligations, Outcome, PatchOp,
    PatchRecord, PolicyActivationEvent, Resource, TypedAuditEvent,
};

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ctx() -> CommonFields {
    CommonFields::new(
        "corr_effects_1",
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

fn authorize() -> AuthorizationEvent {
    AuthorizationEvent::new(
        Resource::new("http_request", "graph.microsoft.com"),
        "http.post",
        Decision::Allow,
        "decision:1",
        "middleware.allowed",
    )
    .with_obligations(Obligations::default())
    .with_argument_summary(std::collections::BTreeMap::new())
}

fn redaction() -> Effects {
    Effects {
        patch_count: Some(1),
        patches: vec![PatchRecord::new("/messages/0/content", PatchOp::Replace)],
        payload_replaced: Some(false),
        header_mutations: vec![HeaderMutationRecord::new(
            "authorization",
            HeaderAction::Remove,
        )],
    }
}

#[test]
fn an_allowed_request_records_what_was_rewritten() {
    // The case the field exists for: allowed, and modified before forwarding.
    let event = authorize()
        .with_effects(redaction())
        .into_audit_event(&ctx())
        .expect("effects should validate");

    let effects = event.effects.as_ref().expect("effects should be present");
    assert_eq!(effects.patch_count, Some(1));
    assert_eq!(effects.patches.len(), 1);
    assert_eq!(effects.patches[0].path, "/messages/0/content");
    assert_eq!(effects.patches[0].op, PatchOp::Replace);
    assert_eq!(effects.header_mutations.len(), 1);
    assert_eq!(effects.header_mutations[0].action, HeaderAction::Remove);
}

#[test]
fn paths_answer_which_field_was_touched() {
    // A count cannot distinguish "the secret field was redacted" from
    // "something else was, and the secret got through".
    let event = authorize()
        .with_effects(redaction())
        .into_audit_event(&ctx())
        .expect("effects should validate");

    let json = serde_json::to_string(&event).expect("should serialize");
    assert!(json.contains("/messages/0/content"), "got {json}");
}

#[test]
fn an_unchanged_request_omits_effects_entirely() {
    // Absent must mean "unmodified", not "we did not look".
    let event = authorize()
        .with_effects(Effects::default())
        .into_audit_event(&ctx())
        .expect("should validate");

    assert!(event.effects.is_none());
    let json = serde_json::to_string(&event).expect("should serialize");
    assert!(!json.contains(r#""effects":"#), "got {json}");
}

#[test]
fn a_wholesale_replacement_is_distinguishable_from_patches() {
    // Replacement takes precedence over patches, so both counts are
    // legitimately zero while the body was still rewritten.
    let event = authorize()
        .with_effects(Effects {
            payload_replaced: Some(true),
            ..Effects::default()
        })
        .into_audit_event(&ctx())
        .expect("should validate");

    let effects = event
        .effects
        .as_ref()
        .expect("replacement must be recorded");
    assert_eq!(effects.payload_replaced, Some(true));
    assert_eq!(effects.patch_count, None);
}

#[test]
fn header_mutations_record_names_but_never_values() {
    // An injected credential is exactly what would sit in the value.
    let json = serde_json::json!({
        "name": "authorization",
        "action": "set",
        "value": "Bearer sk-live-abc123"
    });
    let error = serde_json::from_value::<HeaderMutationRecord>(json)
        .expect_err("a header value must not be representable");
    assert!(error.to_string().contains("value"), "got {error}");
}

#[test]
fn effects_are_not_permitted_on_events_that_change_nothing() {
    // policy_activation applies nothing to a request.
    let mut event = PolicyActivationEvent::new(Outcome::Success, "policy.bundle_verified")
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.effects = Some(redaction());

    let error = event
        .validate()
        .expect_err("effects must not be permitted on policy_activation");
    assert!(
        error.violations().join("; ").contains("effects"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn effects_are_permitted_on_exactly_the_mutating_event_types() {
    // Table over every type, not a spot check: a shared-block leak is invisible
    // if authorization works, since that is the one type anyone tries. Effects
    // record an applied request rewrite, so they belong on exactly the two
    // types that mutate: an authorization (redaction enforcing an allow) and a
    // policy_injection (the interceptor rewriting the admission manifest).
    let permitted = [EventType::Authorization, EventType::PolicyInjection];
    let forbidden = [
        EventType::Authentication,
        EventType::PolicyActivation,
        EventType::PolicyVerification,
        EventType::PolicyDistribution,
        EventType::PolicyRefresh,
        EventType::ProvenanceSigning,
        EventType::AdmissionValidation,
        EventType::ConfigGovernance,
        EventType::CredentialIssuance,
        EventType::ReviewRequest,
        EventType::ReviewDecision,
        EventType::PolicyServiceStartup,
    ];

    for event_type in permitted.into_iter().chain(forbidden) {
        let mut event = AuditEvent::new(event_type, ctx());
        event.effects = Some(redaction());

        let violations = match event.validate() {
            Ok(()) => String::new(),
            Err(error) => error.violations().join("; "),
        };
        let rejected = violations.contains("effects");

        if permitted.contains(&event_type) {
            assert!(
                !rejected,
                "{event_type} rewrites requests, so it must record effects: {violations}"
            );
        } else {
            assert!(
                rejected,
                "{event_type} applies nothing, so it must not record effects"
            );
        }
    }
}

#[test]
fn header_names_the_middleware_accepts_are_never_rejected_here() {
    // The middleware's is_valid_header_name accepts the full RFC 7230 token
    // set. A charset rule here would drop the whole record over a header the
    // producer considered legal, after the rewrite already went out.
    let token_chars = "!#$%&'*+-.^_`|~";
    for character in token_chars.chars() {
        let name = format!("x-openshell-middleware-a{character}b");
        let event = authorize()
            .with_effects(Effects {
                header_mutations: vec![HeaderMutationRecord::new(name.clone(), HeaderAction::Set)],
                ..Effects::default()
            })
            .into_audit_event(&ctx());

        assert!(
            event.is_ok(),
            "middleware accepts header {name}, so audit must record it: {:?}",
            event.err().map(|error| error.violations().to_vec())
        );
    }
}

#[test]
fn a_removed_header_needs_no_write_prefix() {
    // `remove` has no write-prefix requirement, so any non-protected header is
    // removable and must therefore be recordable.
    let event = authorize()
        .with_effects(Effects {
            header_mutations: vec![HeaderMutationRecord::new(
                "X-Rate-Limit~Bucket",
                HeaderAction::Remove,
            )],
            ..Effects::default()
        })
        .into_audit_event(&ctx());

    assert!(event.is_ok(), "got {:?}", event.err());
}

#[test]
fn more_patches_than_can_be_recorded_still_produce_a_valid_event() {
    // The engine applies patches with no cap, so without truncation a broad
    // redaction policy would rewrite the request and then fail validation.
    let overflow = MAX_RECORDED_PATCHES + 1;
    let event = authorize()
        .with_effects(Effects {
            patch_count: Some(overflow as u64),
            patches: (0..overflow)
                .map(|index| {
                    PatchRecord::new(format!("/messages/{index}/content"), PatchOp::Remove)
                })
                .collect(),
            ..Effects::default()
        })
        .into_audit_event(&ctx())
        .expect("an over-cap rewrite must still be auditable");

    let effects = event.effects.as_ref().expect("effects should be present");
    assert_eq!(effects.patches.len(), MAX_RECORDED_PATCHES);
    // The count stays exact, so truncation is visible rather than silent.
    assert_eq!(effects.patch_count, Some(overflow as u64));
}

#[test]
fn an_empty_effects_object_is_rejected_by_the_schema() {
    // `with_effects` drops it, but the field is public and a non-Rust producer
    // has no builder at all. Absent means unmodified, so `{}` would read as
    // "we changed something, but nothing".
    let mut event = authorize()
        .into_audit_event(&ctx())
        .expect("baseline should validate");
    event.effects = Some(Effects::default());

    let error = event
        .validate()
        .expect_err("an empty effects object must not validate");
    assert!(
        error.violations().join("; ").contains("effects"),
        "got {:?}",
        error.violations()
    );
}

#[test]
fn a_replaced_path_is_distinguishable_from_a_removed_one() {
    // Redacted-in-altered-form and gone-entirely are different answers to what
    // the request looked like when it left.
    let event = authorize()
        .with_effects(Effects {
            patch_count: Some(2),
            patches: vec![
                PatchRecord::new("/messages/0/content", PatchOp::Replace),
                PatchRecord::new("/metadata/api_key", PatchOp::Remove),
            ],
            ..Effects::default()
        })
        .into_audit_event(&ctx())
        .expect("should validate");

    let effects = event.effects.as_ref().expect("effects should be present");
    assert_eq!(effects.patches[0].op, PatchOp::Replace);
    assert_eq!(effects.patches[1].op, PatchOp::Remove);
}

#[test]
fn a_patch_record_cannot_carry_its_value() {
    // Recording the value would defeat the redaction being recorded.
    let json = serde_json::json!({
        "path": "/metadata/api_key",
        "op": "replace",
        "value": "sk-live-abc123"
    });
    let error = serde_json::from_value::<PatchRecord>(json)
        .expect_err("a patch value must not be representable");
    assert!(error.to_string().contains("value"), "got {error}");
}

#[test]
fn the_schema_rejects_a_patch_value_independently_of_serde() {
    // serde and the schema are independent guards on the property that matters
    // most here: no patch value ever reaches the record. Only serde was tested.
    let schema: serde_json::Value =
        serde_json::from_str(apf_audit::AUDIT_EVENT_SCHEMA_JSON).expect("schema should parse");
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .expect("schema should compile");

    let mut event = serde_json::to_value(
        authorize()
            .with_effects(redaction())
            .into_audit_event(&ctx())
            .expect("baseline should validate"),
    )
    .expect("should serialize");

    for forbidden in ["value", "from"] {
        event["effects"]["patches"] = serde_json::json!([{
            "path": "/metadata/api_key",
            "op": "replace",
            forbidden: "sk-live-abc123"
        }]);
        assert!(
            !validator.is_valid(&event),
            "the schema must reject a patch carrying `{forbidden}`"
        );
    }

    event["effects"]["patches"] = serde_json::json!([{"path": "/x", "op": "replace"}]);
    event["effects"]["header_mutations"] =
        serde_json::json!([{"name": "authorization", "action": "set", "value": "Bearer x"}]);
    assert!(
        !validator.is_valid(&event),
        "the schema must reject a header mutation carrying a value"
    );
}

#[test]
fn effects_that_assert_no_mutation_are_rejected() {
    // Non-empty, yet asserting nothing happened — which contradicts "absent
    // means unmodified" just as much as `{}` does.
    let schema: serde_json::Value =
        serde_json::from_str(apf_audit::AUDIT_EVENT_SCHEMA_JSON).expect("schema should parse");
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .expect("schema should compile");

    let mut event = serde_json::to_value(
        authorize()
            .into_audit_event(&ctx())
            .expect("baseline should validate"),
    )
    .expect("should serialize");

    for no_op in [
        serde_json::json!({}),
        serde_json::json!({"payload_replaced": false}),
        serde_json::json!({"patch_count": 0}),
        serde_json::json!({"patch_count": 0, "payload_replaced": false}),
    ] {
        event["effects"] = no_op.clone();
        assert!(
            !validator.is_valid(&event),
            "effects {no_op} asserts no mutation and must be rejected"
        );
    }

    // The four real mutation shapes must all still pass.
    for applied in [
        serde_json::json!({"patches": [{"path": "/text", "op": "replace"}]}),
        serde_json::json!({"header_mutations": [{"name": "authorization", "action": "remove"}]}),
        serde_json::json!({"payload_replaced": true}),
        serde_json::json!({"patch_count": 1}),
    ] {
        event["effects"] = applied.clone();
        assert!(
            validator.is_valid(&event),
            "effects {applied} records a real mutation and must validate"
        );
    }
}
