// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Application of an [`EvalResult`]'s mutations to a request.
//!
//! Enforcement points call [`apply_effects`] to turn the mutations carried by
//! an allow decision into concrete request changes. The semantics live here,
//! next to the decision contract, so every enforcement point shares one
//! implementation.
//!
//! Semantics:
//!
//! - A deny result is an error ([`ApplyError::DeniedResult`]): applying
//!   mutations from a denied decision is caller misuse and must stay loud.
//! - `body_replacement` takes precedence over `body_patches`; the result body
//!   is the UTF-8 bytes of the replacement string.
//! - `body_patches` apply sequentially in vector order with RFC 6902
//!   semantics, so a later op targeting the same path wins. `replace` and
//!   `remove` on a missing path are errors — enforcement fails closed rather
//!   than silently skipping a mandated mutation. `add` creates the target
//!   member where RFC 6902 allows (existing parent object or array).
//! - Patches against a non-JSON body (`body_json` is `None`) are an error:
//!   the engine emits patches regardless of body type, and dropping a
//!   mandated mutation is the one wrong answer.
//! - No patches and no replacement → `body: None` (unchanged).
//! - Header mutations pass through unmodified, in order. Executing them is
//!   the wire layer's job; this module only guarantees ordering and a stable
//!   type.
//! - Findings and the verdict are audit/wire concerns and are not handled
//!   here.

use serde_json::Value;

use crate::{EvalResult, HeaderMutation, JsonPatch, PatchOp};

/// Request mutations resolved into concrete values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRequest {
    /// The new body bytes; `None` when the body is unchanged.
    pub body: Option<Vec<u8>>,
    /// Header mutations to execute, in decision order.
    pub headers: Vec<HeaderMutation>,
}

/// Errors from applying an [`EvalResult`] to a request.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The result is a deny; there is nothing to apply.
    #[error("cannot apply effects of a deny result: {reason}")]
    DeniedResult { reason: String },
    /// The result carries body patches but the body is not JSON.
    #[error("body patches require a JSON body")]
    NonJsonBody,
    /// A `replace`/`remove` op targets a path that does not exist.
    #[error("{op:?} patch targets missing path '{path}'")]
    MissingPath { op: PatchOp, path: String },
    /// A patch path is not a valid JSON Pointer for its operation.
    #[error("invalid patch path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },
    /// A `replace`/`add` op carries no operand value.
    #[error("{op:?} patch at '{path}' carries no value")]
    MissingValue { op: PatchOp, path: String },
}

/// Apply the mutations of an allow decision to a request body.
///
/// `body` is the raw request body; `body_json` is its parsed form when the
/// body is JSON. See the module docs for the full semantics.
pub fn apply_effects(
    body: &[u8],
    body_json: Option<&Value>,
    result: &EvalResult,
) -> Result<AppliedRequest, ApplyError> {
    // The raw bytes are part of the call contract; patching works on the
    // parsed form, so only `body_json` is consumed today.
    let _ = body;

    if !result.allow {
        return Err(ApplyError::DeniedResult {
            reason: result.deny_reason.clone(),
        });
    }

    let headers = result.header_mutations.clone();

    if let Some(replacement) = &result.body_replacement {
        return Ok(AppliedRequest {
            body: Some(replacement.clone().into_bytes()),
            headers,
        });
    }

    if result.body_patches.is_empty() {
        return Ok(AppliedRequest {
            body: None,
            headers,
        });
    }

    let Some(json) = body_json else {
        return Err(ApplyError::NonJsonBody);
    };
    let mut doc = json.clone();
    for patch in &result.body_patches {
        apply_patch(&mut doc, patch)?;
    }
    let bytes = serde_json::to_vec(&doc).expect("serializing a Value cannot fail");
    Ok(AppliedRequest {
        body: Some(bytes),
        headers,
    })
}

/// Apply one RFC 6902 op to the document in place.
fn apply_patch(doc: &mut Value, patch: &JsonPatch) -> Result<(), ApplyError> {
    let operand = || {
        patch.value.clone().ok_or(ApplyError::MissingValue {
            op: patch.op,
            path: patch.path.clone(),
        })
    };

    let tokens = parse_pointer(&patch.path)?;

    // The whole-document pointer has no parent to navigate.
    if tokens.is_empty() {
        return match patch.op {
            PatchOp::Replace | PatchOp::Add => {
                *doc = operand()?;
                Ok(())
            }
            PatchOp::Remove => Err(ApplyError::InvalidPath {
                path: patch.path.clone(),
                reason: "cannot remove the whole document".to_string(),
            }),
        };
    }

    let (last, parents) = tokens.split_last().expect("tokens is non-empty");
    let mut target = doc;
    for token in parents {
        target = descend(target, token).ok_or_else(|| ApplyError::MissingPath {
            op: patch.op,
            path: patch.path.clone(),
        })?;
    }

    match target {
        Value::Object(map) => match patch.op {
            PatchOp::Replace => match map.get_mut(last) {
                Some(slot) => {
                    *slot = operand()?;
                    Ok(())
                }
                None => Err(missing(patch)),
            },
            PatchOp::Add => {
                map.insert(last.clone(), operand()?);
                Ok(())
            }
            PatchOp::Remove => match map.remove(last) {
                Some(_) => Ok(()),
                None => Err(missing(patch)),
            },
        },
        Value::Array(items) => {
            if last == "-" {
                return match patch.op {
                    PatchOp::Add => {
                        items.push(operand()?);
                        Ok(())
                    }
                    // "-" points past the end; nothing exists there to
                    // replace or remove.
                    PatchOp::Replace | PatchOp::Remove => Err(missing(patch)),
                };
            }
            let index = parse_index(last).ok_or_else(|| ApplyError::InvalidPath {
                path: patch.path.clone(),
                reason: format!("'{last}' is not a valid array index"),
            })?;
            match patch.op {
                PatchOp::Replace => match items.get_mut(index) {
                    Some(slot) => {
                        *slot = operand()?;
                        Ok(())
                    }
                    None => Err(missing(patch)),
                },
                PatchOp::Add => {
                    if index > items.len() {
                        return Err(missing(patch));
                    }
                    items.insert(index, operand()?);
                    Ok(())
                }
                PatchOp::Remove => {
                    if index >= items.len() {
                        return Err(missing(patch));
                    }
                    items.remove(index);
                    Ok(())
                }
            }
        }
        _ => Err(missing(patch)),
    }
}

fn missing(patch: &JsonPatch) -> ApplyError {
    ApplyError::MissingPath {
        op: patch.op,
        path: patch.path.clone(),
    }
}

/// Step one reference token into an object member or array element.
fn descend<'a>(value: &'a mut Value, token: &str) -> Option<&'a mut Value> {
    match value {
        Value::Object(map) => map.get_mut(token),
        Value::Array(items) => items.get_mut(parse_index(token)?),
        _ => None,
    }
}

/// Parse an RFC 6901 array index: digits only, no leading zeros.
fn parse_index(token: &str) -> Option<usize> {
    if token.len() > 1 && token.starts_with('0') {
        return None;
    }
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// Split an RFC 6901 JSON Pointer into unescaped reference tokens.
fn parse_pointer(path: &str) -> Result<Vec<String>, ApplyError> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let invalid = |reason: &str| ApplyError::InvalidPath {
        path: path.to_string(),
        reason: reason.to_string(),
    };
    let Some(rest) = path.strip_prefix('/') else {
        return Err(invalid("must start with '/'"));
    };
    rest.split('/')
        .map(|token| unescape_token(token).ok_or_else(|| invalid("bad '~' escape")))
        .collect()
}

/// Unescape `~1` → `/` and `~0` → `~`; any other `~` sequence is invalid.
fn unescape_token(token: &str) -> Option<String> {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c != '~' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            _ => return None,
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderAction;
    use serde_json::json;

    fn allow() -> EvalResult {
        EvalResult::default()
    }

    fn patch(op: PatchOp, path: &str, value: Option<Value>) -> JsonPatch {
        JsonPatch {
            op,
            path: path.to_string(),
            value,
        }
    }

    fn apply_json(doc: Value, patches: Vec<JsonPatch>) -> Result<Value, ApplyError> {
        let body = serde_json::to_vec(&doc).unwrap();
        let result = EvalResult {
            body_patches: patches,
            ..allow()
        };
        let applied = apply_effects(&body, Some(&doc), &result)?;
        Ok(serde_json::from_slice(&applied.body.expect("patched body")).unwrap())
    }

    #[test]
    fn replacement_wins_over_patches() {
        let doc = json!({"model": "big"});
        let result = EvalResult {
            body_replacement: Some("[REDACTED]".to_string()),
            body_patches: vec![patch(PatchOp::Replace, "/model", Some(json!("small")))],
            ..allow()
        };
        let applied = apply_effects(b"{\"model\":\"big\"}", Some(&doc), &result).unwrap();
        assert_eq!(applied.body.as_deref(), Some(b"[REDACTED]".as_slice()));
    }

    #[test]
    fn replacement_applies_to_non_json_body() {
        let result = EvalResult {
            body_replacement: Some("clean".to_string()),
            ..allow()
        };
        let applied = apply_effects(b"\x00binary", None, &result).unwrap();
        assert_eq!(applied.body.as_deref(), Some(b"clean".as_slice()));
    }

    #[test]
    fn sequential_replaces_later_wins() {
        let out = apply_json(
            json!({"model": "big"}),
            vec![
                patch(PatchOp::Replace, "/model", Some(json!("small"))),
                patch(PatchOp::Replace, "/model", Some(json!("tiny"))),
            ],
        )
        .unwrap();
        assert_eq!(out, json!({"model": "tiny"}));
    }

    #[test]
    fn add_then_replace() {
        let out = apply_json(
            json!({}),
            vec![
                patch(PatchOp::Add, "/limit", Some(json!(10))),
                patch(PatchOp::Replace, "/limit", Some(json!(5))),
            ],
        )
        .unwrap();
        assert_eq!(out, json!({"limit": 5}));
    }

    #[test]
    fn remove_deletes_member() {
        let out = apply_json(
            json!({"model": "big", "stream": true}),
            vec![patch(PatchOp::Remove, "/stream", None)],
        )
        .unwrap();
        assert_eq!(out, json!({"model": "big"}));
    }

    #[test]
    fn replace_missing_path_errors() {
        let err = apply_json(
            json!({}),
            vec![patch(PatchOp::Replace, "/model", Some(json!("x")))],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ApplyError::MissingPath {
                op: PatchOp::Replace,
                ..
            }
        ));
    }

    #[test]
    fn remove_missing_path_errors() {
        let err = apply_json(json!({}), vec![patch(PatchOp::Remove, "/model", None)]).unwrap_err();
        assert!(matches!(
            err,
            ApplyError::MissingPath {
                op: PatchOp::Remove,
                ..
            }
        ));
    }

    #[test]
    fn add_creates_member_in_existing_parent() {
        let out = apply_json(
            json!({"opts": {}}),
            vec![patch(PatchOp::Add, "/opts/limit", Some(json!(1)))],
        )
        .unwrap();
        assert_eq!(out, json!({"opts": {"limit": 1}}));
    }

    #[test]
    fn add_with_missing_intermediate_errors() {
        // RFC 6902: add requires the parent to exist; it creates only the
        // final member.
        let err = apply_json(
            json!({}),
            vec![patch(PatchOp::Add, "/opts/limit", Some(json!(1)))],
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::MissingPath { .. }));
    }

    #[test]
    fn add_appends_to_array_with_dash() {
        let out = apply_json(
            json!({"tags": ["a"]}),
            vec![patch(PatchOp::Add, "/tags/-", Some(json!("b")))],
        )
        .unwrap();
        assert_eq!(out, json!({"tags": ["a", "b"]}));
    }

    #[test]
    fn add_inserts_into_array_at_index() {
        let out = apply_json(
            json!({"tags": ["a", "c"]}),
            vec![patch(PatchOp::Add, "/tags/1", Some(json!("b")))],
        )
        .unwrap();
        assert_eq!(out, json!({"tags": ["a", "b", "c"]}));
    }

    #[test]
    fn patches_without_json_body_error() {
        let result = EvalResult {
            body_patches: vec![patch(PatchOp::Replace, "/x", Some(json!(1)))],
            ..allow()
        };
        let err = apply_effects(b"not json", None, &result).unwrap_err();
        assert!(matches!(err, ApplyError::NonJsonBody));
    }

    #[test]
    fn deny_result_errors() {
        let result = EvalResult {
            allow: false,
            deny_reason: "no_grant".to_string(),
            ..allow()
        };
        let err = apply_effects(b"{}", Some(&json!({})), &result).unwrap_err();
        match err {
            ApplyError::DeniedResult { reason } => assert_eq!(reason, "no_grant"),
            other => panic!("expected DeniedResult, got {other:?}"),
        }
    }

    #[test]
    fn no_op_result_leaves_body_unchanged() {
        let applied = apply_effects(b"{}", Some(&json!({})), &allow()).unwrap();
        assert_eq!(applied.body, None);
        assert!(applied.headers.is_empty());
    }

    #[test]
    fn header_mutations_pass_through_in_order() {
        let headers = vec![
            HeaderMutation {
                name: "X-First".to_string(),
                action: HeaderAction::Set,
                value: Some("1".to_string()),
            },
            HeaderMutation {
                name: "X-Gone".to_string(),
                action: HeaderAction::Remove,
                value: None,
            },
        ];
        let result = EvalResult {
            header_mutations: headers.clone(),
            ..allow()
        };
        let applied = apply_effects(b"", None, &result).unwrap();
        assert_eq!(applied.body, None);
        assert_eq!(applied.headers, headers);
    }

    #[test]
    fn round_trips_bytes_through_patching() {
        let body = br#"{"model": "big", "opts": {"stream": true}}"#;
        let doc: Value = serde_json::from_slice(body).unwrap();
        let result = EvalResult {
            body_patches: vec![
                patch(PatchOp::Replace, "/model", Some(json!("small"))),
                patch(PatchOp::Remove, "/opts/stream", None),
                patch(PatchOp::Add, "/opts/max_tokens", Some(json!(256))),
            ],
            ..allow()
        };
        let applied = apply_effects(body, Some(&doc), &result).unwrap();
        let patched: Value = serde_json::from_slice(&applied.body.unwrap()).unwrap();
        assert_eq!(
            patched,
            json!({"model": "small", "opts": {"max_tokens": 256}})
        );
    }

    #[test]
    fn escaped_pointer_tokens_resolve() {
        let out = apply_json(
            json!({"a/b": 1, "c~d": 2}),
            vec![
                patch(PatchOp::Replace, "/a~1b", Some(json!(10))),
                patch(PatchOp::Remove, "/c~0d", None),
            ],
        )
        .unwrap();
        assert_eq!(out, json!({"a/b": 10}));
    }

    #[test]
    fn invalid_pointer_errors() {
        let err = apply_json(
            json!({}),
            vec![patch(PatchOp::Add, "no-slash", Some(json!(1)))],
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::InvalidPath { .. }));

        let err = apply_json(
            json!({"x": 1}),
            vec![patch(PatchOp::Add, "/x~2", Some(json!(1)))],
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::InvalidPath { .. }));
    }
}
