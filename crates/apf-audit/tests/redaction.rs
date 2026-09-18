// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use apf_audit::{
    AuditEvent, CommonFields, Component, EventType, RedactedObject, RedactionError,
    RedactionProfile, Resource, ResultClass, redact,
};
use serde_json::{Value, json};

fn common_fields() -> CommonFields {
    CommonFields::new(
        "corr_test_redaction",
        "user:example",
        "agent:example",
        "workspace:example",
        "session:example",
        "apf-openshell-middleware:local",
        "openshell",
        Component::new("apf-openshell-middleware", "0.1.0", "middleware:0"),
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "trustroot:dev",
    )
}

fn result_event_with_summary(summary: RedactedObject) -> AuditEvent {
    // result_summary rides on the authorization record, the event that carries
    // the decision_fields block in which the summary lives.
    let mut event = AuditEvent::with_ids(
        EventType::Authorization,
        common_fields(),
        "evt_test_redaction_result",
        "2026-05-15T19:20:31.010Z",
    );
    event.resource = Some(Resource::new("mailbox", "mailbox:user:example"));
    event.verb = Some("mail.search".to_owned());
    event.decision = Some(apf_audit::Decision::Allow);
    event.decision_id = Some("dec_test_redaction_result".to_owned());
    event.reason_code = Some("result.success.redacted".to_owned());
    event.result_class = Some(ResultClass::Scrubbed);
    event.result_summary = Some(summary);
    event
}

#[test]
fn redaction_preserves_only_allowlisted_fields() {
    let payload = json!({
        "query_class": "sender_and_date",
        "max_results": 10,
        "access_token": "secret-value",
        "body": "full email body",
        "unapproved": "do not copy",
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields(["query_class", "max_results"])
        .expect("allowlist should be valid");

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    assert_eq!(
        summary["resource_type"],
        Value::String("mailbox".to_owned())
    );
    assert_eq!(
        summary["redaction_profile"],
        Value::String("pii_basic".to_owned())
    );
    assert_eq!(summary["payload_included"], Value::Bool(false));
    assert_eq!(summary["field_count"], json!(5));
    assert_eq!(summary["retained_field_count"], json!(2));
    assert_eq!(summary["summarized_field_count"], json!(1));
    assert_eq!(summary["dropped_field_count"], json!(2));
    assert_eq!(
        summary["fields"]["query_class"]["value_class"],
        json!("string")
    );
    assert_eq!(summary["fields"]["max_results"], json!(10));

    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert!(!encoded.contains("sender_and_date"));
    assert!(!encoded.contains("secret-value"));
    assert!(!encoded.contains("full email body"));
    assert!(!encoded.contains("do not copy"));
}

#[test]
fn redaction_rejects_forbidden_allowlist_fields() {
    let error = RedactionProfile::new("pii_basic")
        .with_allowed_field("access_token")
        .expect_err("forbidden audit field should be rejected");

    assert_eq!(
        error,
        RedactionError::ForbiddenAllowedField("access_token".to_owned())
    );

    let error = RedactionProfile::new("pii_basic")
        .with_allowed_field("api_key")
        .expect_err("API key field should be rejected");

    assert_eq!(
        error,
        RedactionError::ForbiddenAllowedField("api_key".to_owned())
    );
}

#[test]
fn redaction_rejects_invalid_profiles_and_payloads() {
    assert_eq!(
        RedactionProfile::try_new("").expect_err("empty profile should be rejected"),
        RedactionError::EmptyProfileName
    );
    assert!(matches!(
        RedactionProfile::try_new("not a safe profile"),
        Err(RedactionError::InvalidProfileName(_))
    ));

    assert_eq!(
        RedactionProfile::new("pii_basic")
            .with_allowed_field("")
            .expect_err("empty allowlist field should be rejected"),
        RedactionError::EmptyAllowedField
    );
    assert!(matches!(
        RedactionProfile::new("pii_basic").with_allowed_field("not.safe"),
        Err(RedactionError::InvalidAllowedField(_))
    ));

    let profile = RedactionProfile::new("pii_basic");
    assert_eq!(
        redact("mailbox", &json!("not an object"), &profile)
            .expect_err("non-object payload should be rejected"),
        RedactionError::NonObjectPayload
    );
    assert!(matches!(
        redact("not a safe resource", &json!({}), &profile),
        Err(RedactionError::InvalidResourceType(_))
    ));
}

#[test]
fn redaction_recursively_drops_forbidden_nested_fields() {
    let payload = json!({
        "metadata": {
            "query_class": "sender_and_date",
            "refresh_token": "refresh-secret",
            "nested": {
                "authorization": "Bearer secret",
                "count": 3
            }
        }
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_field("metadata")
        .expect("allowlist should be valid");

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    assert_eq!(summary["dropped_field_count"], json!(2));
    assert_eq!(
        summary["fields"]["metadata"]["value_class"],
        json!("object")
    );
    assert_eq!(summary["fields"]["metadata"]["property_count"], json!(3));

    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert!(!encoded.contains("query_class"));
    assert!(!encoded.contains("sender_and_date"));
    assert!(!encoded.contains("nested"));
    assert!(!encoded.contains("refresh-secret"));
    assert!(!encoded.contains("Bearer secret"));
    assert!(!encoded.contains("refresh_token"));
    assert!(!encoded.contains("authorization"));
}

#[test]
fn redaction_summarizes_suspicious_string_values_under_safe_keys() {
    let payload = json!({
        "provider_label": "Bearer secret-token-value",
        "basic_label": "Basic secret-token-value",
        "openai_label": "sk-test-secret-token-value",
        "github_label": "ghp_secretTokenValue1234567890",
        "request_id": "req_123"
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields([
            "provider_label",
            "basic_label",
            "openai_label",
            "github_label",
            "request_id",
        ])
        .expect("allowlist should be valid");

    let summary = redact("credential_issuer", &payload, &profile).expect("payload should redact");

    assert_eq!(
        summary["fields"]["provider_label"]["value_class"],
        json!("string")
    );
    assert_eq!(
        summary["fields"]["basic_label"]["value_class"],
        json!("string")
    );
    assert_eq!(
        summary["fields"]["openai_label"]["value_class"],
        json!("string")
    );
    assert_eq!(
        summary["fields"]["github_label"]["value_class"],
        json!("string")
    );
    assert_eq!(
        summary["fields"]["request_id"]["value_class"],
        json!("string")
    );

    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert!(!encoded.contains("req_123"));
    assert!(!encoded.contains("secret-token-value"));
    assert!(!encoded.contains("ghp_secretTokenValue1234567890"));
}

#[test]
fn redaction_summarizes_safe_named_pii_and_free_text_fields() {
    let payload = json!({
        "email": "ada@example.com",
        "subject": "Quarterly results and staffing plan",
        "customer_name": "Ada Lovelace",
        "query": "from:ada@example.com after:2026-05-01",
        "prompt": "Summarize this customer thread",
        "query_class": "sender_and_date"
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields([
            "email",
            "subject",
            "customer_name",
            "query",
            "prompt",
            "query_class",
        ])
        .expect("allowlist should be valid");

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    for field in ["email", "subject", "customer_name", "query", "prompt"] {
        assert_eq!(
            summary["fields"][field]["value_class"],
            json!("string"),
            "{field} should be summarized"
        );
    }
    assert_eq!(
        summary["fields"]["query_class"]["value_class"],
        json!("string")
    );

    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert!(!encoded.contains("sender_and_date"));
    assert!(!encoded.contains("ada@example.com"));
    assert!(!encoded.contains("Quarterly results"));
    assert!(!encoded.contains("Ada Lovelace"));
    assert!(!encoded.contains("Summarize this customer thread"));
}

#[test]
fn redaction_summarizes_label_shaped_pii() {
    let payload = json!({
        "phone": "555-123-4567",
        "ssn": "123-45-6789",
        "customer_name": "AdaLovelace",
        "diagnosis": "diagnosis:HIV-positive"
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields(["phone", "ssn", "customer_name", "diagnosis"])
        .expect("allowlist should be valid");

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    for field in ["phone", "ssn", "customer_name", "diagnosis"] {
        assert_eq!(
            summary["fields"][field]["value_class"],
            json!("string"),
            "{field} should be summarized"
        );
    }

    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert!(!encoded.contains("555-123-4567"));
    assert!(!encoded.contains("123-45-6789"));
    assert!(!encoded.contains("AdaLovelace"));
    assert!(!encoded.contains("diagnosis:HIV-positive"));
}

#[test]
fn redaction_bounds_arrays_and_depth() {
    let payload = json!({
        "items": [1, 2, 3, 4],
        "metadata": {
            "level1": {
                "level2": {
                    "level3": "too deep"
                }
            }
        }
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields(["items", "metadata"])
        .expect("allowlist should be valid")
        .with_limits(512, 2, 2);

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    assert_eq!(summary["fields"]["items"]["item_count"], json!(4));
    assert_eq!(summary["fields"]["items"]["items"], json!([1, 2]));
    assert_eq!(summary["fields"]["items"]["truncated"], json!(true));
    assert_eq!(
        summary["fields"]["metadata"]["value_class"],
        json!("object")
    );

    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert!(!encoded.contains("level1"));
    assert!(!encoded.contains("too deep"));
}

#[test]
fn redaction_bounds_nested_object_fanout() {
    let mut metadata = serde_json::Map::new();
    for index in 0..30 {
        metadata.insert(format!("field_{index:02}"), json!(index));
    }
    let payload = json!({
        "metadata": Value::Object(metadata),
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_field("metadata")
        .expect("allowlist should be valid")
        .with_limits(512, 25, 4);

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");
    let metadata = summary["fields"]["metadata"]
        .as_object()
        .expect("metadata summary should be an object");

    assert_eq!(metadata.get("value_class"), Some(&json!("object")));
    assert_eq!(metadata.get("property_count"), Some(&json!(30)));
    assert_eq!(metadata.get("fields_truncated"), Some(&json!(true)));
    assert!(!metadata.contains_key("field_00"));
    assert!(!metadata.contains_key("field_25"));
}

#[test]
fn redaction_bounds_recursive_output_budget() {
    let items = (0..100)
        .map(|_| json!((0..100).collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    let payload = json!({
        "items": items,
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_field("items")
        .expect("allowlist should be valid")
        .with_limits(512, 100, 8);

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    assert_eq!(summary["budget_truncated"], json!(true));
}

#[test]
fn redaction_does_not_emit_nested_producer_keys() {
    let payload = json!({
        "metadata": {
            "AdaLovelace": 1,
            "diagnosis_HIV_positive": true
        }
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_field("metadata")
        .expect("allowlist should be valid");

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    assert_eq!(
        summary["fields"]["metadata"]["value_class"],
        json!("object")
    );
    let encoded = serde_json::to_string(&summary).expect("summary should serialize");
    assert!(!encoded.contains("AdaLovelace"));
    assert!(!encoded.contains("diagnosis_HIV_positive"));
}

#[test]
fn redaction_caps_custom_limits_to_schema_bounds() {
    let long_value = "a".repeat(2049);
    let payload = json!({
        "long_value": long_value,
        "items": (0..105).collect::<Vec<_>>()
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields(["long_value", "items"])
        .expect("allowlist should be valid")
        .with_limits(4096, 150, 8);

    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    assert_eq!(
        summary["fields"]["long_value"]["value_class"],
        json!("string")
    );
    assert_eq!(summary["fields"]["long_value"]["byte_len"], json!(2049));
    assert_eq!(
        summary["fields"]["items"]["items"]
            .as_array()
            .expect("items should be retained")
            .len(),
        100
    );
    assert_eq!(summary["fields"]["items"]["truncated"], json!(true));
}

#[test]
fn redaction_rejects_long_metadata_labels() {
    let profile_name = "a".repeat(129);
    assert!(matches!(
        RedactionProfile::try_new(profile_name),
        Err(RedactionError::InvalidProfileName(_))
    ));

    let resource_type = "a".repeat(129);
    let profile = RedactionProfile::new("pii_basic");
    assert!(matches!(
        redact(resource_type, &json!({}), &profile),
        Err(RedactionError::InvalidResourceType(_))
    ));
}

#[test]
fn redacted_result_summary_validates_on_event() {
    let payload = json!({
        "count": 3,
        "redaction_profile": "pii_basic",
        "payload_included": false,
        "message": "raw response text"
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields(["count", "redaction_profile", "payload_included"])
        .expect("allowlist should be valid");
    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    let event = result_event_with_summary(summary);

    event.validate().expect("redacted event should validate");
}

#[test]
fn redaction_with_capped_limits_validates_on_event() {
    let payload = json!({
        "long_value": "a".repeat(2049),
        "items": (0..105).collect::<Vec<_>>(),
        "nested": [[[[[[[[["too deep"]]]]]]]]]
    });
    let profile = RedactionProfile::new("pii_basic")
        .with_allowed_fields(["long_value", "items", "nested"])
        .expect("allowlist should be valid")
        .with_limits(4096, 150, 8);
    let summary = redact("mailbox", &payload, &profile).expect("payload should redact");

    let event = result_event_with_summary(summary);

    event
        .validate()
        .expect("capped redacted event should validate");
}

#[test]
fn direct_redacted_object_rejects_api_key_fields() {
    let mut summary = RedactedObject::new();
    summary.insert("api_key".to_owned(), json!("sk-secret"));

    let error = result_event_with_summary(summary)
        .validate()
        .expect_err("api_key field should fail validation");

    assert!(error.violations().join("; ").contains("api_key"));
}

#[test]
fn direct_redacted_object_rejects_excessive_width_and_depth() {
    let mut wide = RedactedObject::new();
    for index in 0..101 {
        wide.insert(format!("field_{index:03}"), json!(index));
    }
    let error = result_event_with_summary(wide)
        .validate()
        .expect_err("wide object should fail validation");
    assert!(error.violations().join("; ").contains("properties"));

    let mut nested = json!("leaf");
    for index in (0..9).rev() {
        nested = json!({ format!("level_{index}"): nested });
    }
    let summary = BTreeMap::from([("nested".to_owned(), nested)]);
    let error = result_event_with_summary(summary)
        .validate()
        .expect_err("deep object should fail validation");
    assert!(error.violations().join("; ").contains("depth"));
}
