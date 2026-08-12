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

use cedar_policy::{EntityId, EntityTypeName, EntityUid};
use serde_json::{Map, Value};

use crate::EvalInput;

const PRINCIPAL_TYPE: &str = "APF::User";
const ACTION_TYPE: &str = "APF::Action";
const RESOURCE_TYPE: &str = "APF::Tool";

/// Generic action id when the request carries no tool/capability identity.
const ACTION_INVOKE: &str = "invoke";
/// Resource id for requests without a tool identity.
const RESOURCE_NONE: &str = "__none__";

/// Build the Cedar request tuple: principal, action, resource, and the
/// context as a JSON object ready for `Context::from_json_value`.
pub fn to_cedar(input: &EvalInput) -> (EntityUid, EntityUid, EntityUid, Value) {
    let principal = entity_uid(PRINCIPAL_TYPE, &input.user_subject);

    let action_id = match (&input.tool, &input.capability) {
        (Some(tool), Some(capability)) => format!("{tool}::{capability}"),
        (Some(tool), None) => tool.clone(),
        _ => ACTION_INVOKE.to_string(),
    };
    let action = entity_uid(ACTION_TYPE, &action_id);

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
        if let Value::String(s) = value {
            args_map.insert(
                format!("{name}_len"),
                Value::from(i64::try_from(s.chars().count()).unwrap_or(i64::MAX)),
            );
            if let Ok(n) = s.trim().parse::<i64>() {
                args_map.insert(format!("{name}_num"), Value::from(n));
            }
        }
        args_map.insert(name.clone(), value.clone());
    }
    ctx.insert("args".to_string(), Value::Object(args_map));

    Value::Object(ctx)
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
}
