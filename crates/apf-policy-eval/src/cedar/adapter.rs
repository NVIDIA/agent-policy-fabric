// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! [`EvalInput`] → Cedar request mapping.
//!
//! - principal: `APF::User::"<user_subject>"`
//! - action:    `APF::Action::"<tool>::<capability>"`, or `"invoke"` when
//!   either identity is missing
//! - resource:  `APF::Tool::"<tool>"`, or `"__none__"` for non-tool traffic
//! - context:   body/target metadata plus flattened args. Each string arg
//!   additionally yields `args_<name>_len` (character count) and, when it
//!   parses as an integer, `args_<name>_num` — Cedar has no string-length or
//!   numeric-coercion builtins, so policies constrain these derived fields.
//!   Provider attributes appear as one record per namespace, e.g.
//!   `context.identity`, beside the request-derived roots.

use cedar_policy::{EntityId, EntityTypeName, EntityUid};
use serde_json::{Map, Value};

use crate::EvalInput;

const PRINCIPAL_TYPE: &str = "APF::User";
const ACTION_TYPE: &str = "APF::Action";
const RESOURCE_TYPE: &str = "APF::Tool";

/// Resource id for requests without a tool identity.
const RESOURCE_NONE: &str = "__none__";

/// Build the Cedar request tuple: principal, action, resource, and the
/// context as a JSON object ready for `Context::from_json_value`.
pub fn to_cedar(input: &EvalInput) -> (EntityUid, EntityUid, EntityUid, Value) {
    let principal = entity_uid(PRINCIPAL_TYPE, &input.user_subject);
    let action = entity_uid(ACTION_TYPE, &input.action_id());

    let resource = entity_uid(
        RESOURCE_TYPE,
        input.tool.as_deref().unwrap_or(RESOURCE_NONE),
    );

    (principal, action, resource, context_json(input))
}

fn entity_uid(type_name: &str, id: &str) -> EntityUid {
    let type_name: EntityTypeName = type_name.parse().expect("static entity type name");
    EntityUid::from_type_name_and_id(type_name, EntityId::new(id))
}

fn context_json(input: &EvalInput) -> Value {
    let mut ctx = Map::new();
    ctx.insert(
        "body_text".to_string(),
        Value::String(input.body_text.clone()),
    );
    ctx.insert(
        "has_tool_name".to_string(),
        Value::Bool(input.has_tool_name),
    );

    if let Some(target) = &input.target {
        ctx.insert(
            "target_host".to_string(),
            Value::String(target.host.clone()),
        );
        ctx.insert(
            "target_method".to_string(),
            Value::String(target.method.clone()),
        );
        ctx.insert(
            "target_path".to_string(),
            Value::String(target.path.clone()),
        );
        ctx.insert(
            "target_scheme".to_string(),
            Value::String(target.scheme.clone()),
        );
    }

    // Build a nested `args` record. Raw values are accessible as
    // context.args.<name>; derived length and numeric fields live alongside
    // them as context.args.<name>_len / context.args.<name>_num since Cedar
    // has no string-length or numeric-coercion builtins.
    let mut args_map = Map::new();
    for (name, value) in &input.args {
        // Cedar's context JSON has no null; a null anywhere in the value
        // makes Context::from_json_value fail and the evaluation deny.
        // Treat null as absent instead.
        let Some(value) = strip_nulls(value) else {
            continue;
        };
        if let Value::String(s) = &value {
            args_map.insert(
                format!("{name}_len"),
                Value::from(i64::try_from(s.chars().count()).unwrap_or(i64::MAX)),
            );
            if let Ok(n) = s.trim().parse::<i64>() {
                args_map.insert(format!("{name}_num"), Value::from(n));
            }
        }
        args_map.insert(name.clone(), value);
    }
    ctx.insert("args".to_string(), Value::Object(args_map));

    // Provider namespaces sit beside the request-derived roots. The
    // evaluator rejects a namespace that would shadow one of them before
    // the context is built.
    for (namespace, record) in &input.context_attributes {
        ctx.insert(namespace.clone(), Value::Object(record.clone()));
    }

    Value::Object(ctx)
}

/// Remove JSON nulls from a value: `None` for null itself, null-valued keys
/// dropped from objects, null elements dropped from arrays, recursively.
fn strip_nulls(value: &Value) -> Option<Value> {
    match value {
        Value::Null => None,
        Value::Object(map) => Some(Value::Object(
            map.iter()
                .filter_map(|(k, v)| strip_nulls(v).map(|v| (k.clone(), v)))
                .collect(),
        )),
        Value::Array(items) => Some(Value::Array(items.iter().filter_map(strip_nulls).collect())),
        other => Some(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestTarget;

    fn base_input() -> EvalInput {
        EvalInput::for_tool_call(
            Some("outlook".to_string()),
            Some("message_search".to_string()),
            "user@corp.com".to_string(),
            serde_json::Map::new(),
        )
    }

    #[test]
    fn maps_identities() {
        let (principal, action, resource, _) = to_cedar(&base_input());
        assert_eq!(principal.to_string(), r#"APF::User::"user@corp.com""#);
        assert_eq!(
            action.to_string(),
            r#"APF::Action::"outlook::message_search""#
        );
        assert_eq!(resource.to_string(), r#"APF::Tool::"outlook""#);
    }

    #[test]
    fn missing_identity_maps_to_generic_action_and_resource() {
        let input = EvalInput::for_tool_call(
            None,
            None,
            "user@corp.com".to_string(),
            serde_json::Map::new(),
        );
        let (_, action, resource, ctx) = to_cedar(&input);
        assert_eq!(action.to_string(), r#"APF::Action::"invoke""#);
        assert_eq!(resource.to_string(), r#"APF::Tool::"__none__""#);
        assert_eq!(ctx["has_tool_name"], Value::Bool(false));
    }

    #[test]
    fn derives_len_and_num_for_string_args() {
        let mut input = base_input();
        input
            .args
            .insert("limit".to_string(), Value::String("25".to_string()));
        input
            .args
            .insert("folder".to_string(), Value::String("inbox".to_string()));
        let (_, _, _, ctx) = to_cedar(&input);
        let args = ctx["args"].as_object().expect("args is a record");
        assert_eq!(args["limit"], Value::String("25".to_string()));
        assert_eq!(args["limit_num"], Value::from(25));
        assert_eq!(args["limit_len"], Value::from(2));
        assert_eq!(args["folder_len"], Value::from(5));
        assert!(args.get("folder_num").is_none());
    }

    #[test]
    fn non_string_args_pass_through_without_derived_fields() {
        let mut input = base_input();
        input.args.insert("limit".to_string(), Value::from(25));
        let (_, _, _, ctx) = to_cedar(&input);
        let args = ctx["args"].as_object().expect("args is a record");
        assert_eq!(args["limit"], Value::from(25));
        assert!(args.get("limit_len").is_none());
        assert!(args.get("limit_num").is_none());
    }

    #[test]
    fn target_fields_present_only_when_target_set() {
        let mut input = base_input();
        let (_, _, _, ctx) = to_cedar(&input);
        assert!(ctx.get("target_host").is_none());

        input.target = Some(RequestTarget {
            host: "api.example.com".to_string(),
            method: "GET".to_string(),
            path: "/v1/messages".to_string(),
            scheme: "https".to_string(),
        });
        let (_, _, _, ctx) = to_cedar(&input);
        assert_eq!(
            ctx["target_host"],
            Value::String("api.example.com".to_string())
        );
        assert_eq!(ctx["target_method"], Value::String("GET".to_string()));
        assert_eq!(
            ctx["target_path"],
            Value::String("/v1/messages".to_string())
        );
        assert_eq!(ctx["target_scheme"], Value::String("https".to_string()));
    }

    #[test]
    fn provider_namespaces_become_context_records() {
        let mut input = base_input();
        let identity = serde_json::json!({
            "groups": ["eng"],
            "_meta": {"provider": "idp", "verified": true}
        });
        input.context_attributes.insert(
            "identity".to_string(),
            identity.as_object().cloned().expect("record"),
        );
        let change = serde_json::json!({"approval": "approved"});
        input.context_attributes.insert(
            "change".to_string(),
            change.as_object().cloned().expect("record"),
        );
        let (_, _, _, ctx) = to_cedar(&input);
        assert_eq!(ctx["identity"]["groups"], serde_json::json!(["eng"]));
        assert_eq!(
            ctx["identity"]["_meta"]["provider"],
            Value::String("idp".to_string())
        );
        assert_eq!(
            ctx["change"]["approval"],
            Value::String("approved".to_string())
        );
        // Request-derived roots are untouched.
        assert!(ctx["args"].is_object());
        assert_eq!(ctx["has_tool_name"], Value::Bool(true));
    }

    #[test]
    fn null_args_are_treated_as_absent() {
        let mut args = serde_json::Map::new();
        args.insert("channel".to_string(), Value::String("C123".to_string()));
        args.insert("thread_ts".to_string(), Value::Null);
        args.insert(
            "blocks".to_string(),
            serde_json::json!([{"type": "section", "extra": null}, null]),
        );
        let input = EvalInput::for_tool_call(
            Some("slack".to_string()),
            Some("chat_post".to_string()),
            "user@corp.com".to_string(),
            args,
        );
        let (_, _, _, ctx) = to_cedar(&input);
        let ctx_args = ctx["args"].as_object().expect("args record");
        assert!(ctx_args.get("thread_ts").is_none());
        assert_eq!(ctx_args["blocks"], serde_json::json!([{"type": "section"}]));
        assert_eq!(ctx_args["channel"], Value::String("C123".to_string()));
    }
}
