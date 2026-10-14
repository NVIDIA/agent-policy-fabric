// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cedar-backed [`Evaluator`] implementation.
//!
//! [`CedarEvaluator`] compiles a list of [`PolicyRuleDoc`]s at construction
//! time — one Cedar `PolicySet` (plus optional `Schema`) per rule — and
//! evaluates each request against all rules. Rules carry a `role`:
//!
//! * **`Grant`** rules grant access to specific tools. Cedar
//!   default-deny (no permit matched) means the rule is not applicable —
//!   the evaluator skips it and continues. An explicit `forbid` always stops
//!   evaluation. For MCP tool calls, at least one Grant rule must fire a
//!   permit; if none do, the request is denied.
//! * **`Control`** rules enforce content policy for all traffic. Their
//!   permits (including a baseline-allow) pass traffic through and may carry
//!   `@apf_effect` annotations. Default-deny is still a skip; only an
//!   explicit `forbid` stops evaluation. A Control permit does NOT count
//!   toward the Grant requirement for MCP calls.
//!
//! After all rules, effects from fired permits accumulate and are applied.
//!
//! A rule carries its Cedar schema (human syntax) and policy statements as
//! separate fields. When the schema is absent the policies are compiled
//! without schema validation.
//!
//! Before rule evaluation, the [`AnnotatorEngine`] derives annotation values
//! from the raw input and injects them into the Cedar context as the
//! `annotations` record. With zero annotators the record is empty and rule
//! evaluation is unaffected.
//!
//! After rule evaluation, the [`EffectEngine`] resolves the effects and
//! findings referenced via `@apf_effect`/`@apf_finding` annotations on the
//! fired policies: on allow, effects from every fired permit aggregate into
//! the result's mutations, verdict, and findings; on deny, findings from the
//! fired forbids accompany the deny. With zero effects and findings the
//! result is unchanged.
//!
//! Provider attributes on the input appear as `context.<namespace>` records
//! beside the request-derived roots; a namespace that would shadow one of
//! those roots is rejected before the context is built.
//!
//! A `forbid` that fails to evaluate, typically because it reads an attribute
//! the request does not carry, denies the request unless another `forbid` in
//! the same rule fired, in which case that `forbid` decides. Cedar would
//! otherwise drop the erroring policy from the decision, turning a missing
//! attribute into a grant. The deny reason names the statement; the engine's
//! error text is logged, not returned. A `permit` that fails to evaluate
//! grants nothing, as in plain Cedar.

use cedar_policy::{
    AuthorizationError, Authorizer, Context, Decision, Effect, Entities, PolicyId, Request,
    Response,
};
use serde_json::{Map, Value};

use crate::{EvalError, EvalInput, EvalResult, Evaluator, Finding, RESERVED_CONTEXT_ROOTS};

mod adapter;
pub mod annotator;
pub mod effect;
mod schema;

pub use annotator::{
    AnnotationOp, AnnotationOutput, AnnotationRule, AnnotationSpec, AnnotatorEngine,
    PolicyAnnotatorDoc, SetTrueIf, SetValueFrom,
};
use effect::MissingSource;
pub use effect::{
    BodySpec, EffectEngine, FindingSpec, HeaderSpec, InlineFindingSpec, PatchSpec, PolicyEffectDoc,
    PolicyFindingDoc,
};
use schema::CompiledRule;

/// Re-export so callers don't need to depend on apf-proto directly.
pub use apf_proto::ir::PolicyRuleRole;

/// One `PolicyRule` document as handed to the evaluator: a name, an optional
/// Cedar schema, the policy statements, an opaque contributor data document,
/// and a role that governs how the evaluator interprets default-deny.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyRuleDoc {
    pub name: String,
    /// Cedar schema in human syntax. Absent means the policies compile
    /// without schema validation.
    pub schema: Option<String>,
    /// Cedar policy statements.
    pub definition: String,
    /// Contributor data from `PolicyRule.spec.data`. Exposed as `context.data`.
    pub data: Value,
    /// How the evaluator treats this rule's default-deny.
    pub role: PolicyRuleRole,
}

/// Cedar-driven policy evaluator. Immutable after construction; safe to share
/// across threads.
pub struct CedarEvaluator {
    rules: Vec<CompiledRule>,
    annotators: AnnotatorEngine,
    effects: EffectEngine,
}

impl std::fmt::Debug for CedarEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarEvaluator")
            .field(
                "rules",
                &self.rules.iter().map(|r| &r.name).collect::<Vec<_>>(),
            )
            .field("annotators", &self.annotators)
            .field("effects", &self.effects)
            .finish()
    }
}

impl CedarEvaluator {
    /// Compile every rule's schema and policy set, every annotator's match
    /// rules, and every effect/finding definition. Any parse or validation
    /// failure — including an `@apf_effect` on a forbid or a reference to an
    /// unknown effect/finding — is a load-time error: a `CedarEvaluator`
    /// never carries a rule it cannot evaluate.
    pub fn from_policy_rules(
        rules: &[PolicyRuleDoc],
        annotators: &[PolicyAnnotatorDoc],
        effects: &[PolicyEffectDoc],
        findings: &[PolicyFindingDoc],
    ) -> Result<Self, EvalError> {
        let effects = EffectEngine::from_docs(effects, findings)?;
        let rules = rules
            .iter()
            .map(|doc| {
                let mut rule = schema::compile_rule(doc)?;
                rule.effect_refs = effect::build_ref_table(&rule.name, &rule.policies, &effects)?;
                Ok(rule)
            })
            .collect::<Result<Vec<_>, EvalError>>()?;
        let annotators = AnnotatorEngine::from_docs(annotators)?;
        Ok(Self {
            rules,
            annotators,
            effects,
        })
    }

    /// Findings referenced by the forbids that fired in a deny response, in
    /// the rule's policy order.
    fn deny_findings(
        &self,
        rule: &CompiledRule,
        response: &Response,
        annotations: &Map<String, Value>,
    ) -> Result<Vec<Finding>, MissingSource> {
        let mut refs: Vec<(usize, &str)> = response
            .diagnostics()
            .reason()
            .filter_map(|id| rule.effect_refs.get(id))
            .filter_map(|r| r.finding.as_deref().map(|name| (r.order, name)))
            .collect();
        refs.sort_unstable_by_key(|(order, _)| *order);
        refs.into_iter()
            .map(|(_, name)| self.effects.resolve_finding(name, annotations))
            .collect()
    }
}

impl Evaluator for CedarEvaluator {
    fn evaluate(&self, input: EvalInput) -> Result<EvalResult, EvalError> {
        if let Some(namespace) = input
            .context_attributes
            .keys()
            .find(|namespace| RESERVED_CONTEXT_ROOTS.contains(&namespace.as_str()))
        {
            return Err(EvalError::Engine(format!(
                "context namespace '{namespace}' shadows a reserved context root"
            )));
        }
        let (principal, action, resource, mut base_context_json) = adapter::to_cedar(&input);
        // Annotators derive from the raw input once per request; policies
        // read the results as the `annotations` context record and effects
        // resolve `source:` references against the same map.
        let annotations = self.annotators.run(&input);
        if let Value::Object(ctx) = &mut base_context_json {
            ctx.insert(
                "annotations".to_string(),
                Value::Object(annotations.clone()),
            );
        }

        let has_tool_name = input.has_tool_name;
        let tool_name_str = input.tool.as_deref().unwrap_or("");
        let authorizer = Authorizer::new();
        // Effect and finding references from fired permits, accumulated in
        // rule bundle order and policy order within each rule.
        let mut fired_effects: Vec<String> = Vec::new();
        let mut fired_findings: Vec<String> = Vec::new();
        // Tracks whether at least one Grant rule fired a permit. Required
        // for MCP tool calls; non-MCP requests bypass this check.
        let mut any_capability_fired = false;
        // Name of the first Grant rule that covers this tool (contains the
        // tool name in its rule name) but still default-denied — used to build
        // a more specific deny message when conditions didn't match.
        let mut grant_rule_near_miss: Option<String> = None;
        for rule in &self.rules {
            // Merge rule-specific data into the context as `data` so Cedar
            // policies can reference operator-supplied values from PolicyRule.spec.data
            // without hardcoding them in the Cedar definition.
            let mut context_json = base_context_json.clone();
            if !rule.data.is_null()
                && let Value::Object(ctx) = &mut context_json
            {
                ctx.insert("data".to_string(), rule.data.clone());
            }
            // The context is schema-independent: rules validate policies against
            // their schema at load time, but requests are built unvalidated so
            // adapter-derived fields a rule does not declare are simply unused.
            let context = Context::from_json_value(context_json, None)
                .map_err(|e| EvalError::Engine(format!("cedar context: {e}")))?;
            let request = Request::new(
                principal.clone(),
                action.clone(),
                resource.clone(),
                context,
                None,
            )
            .map_err(|e| EvalError::Engine(format!("cedar request: {e}")))?;
            let response = authorizer.is_authorized(&request, &rule.policies, &Entities::empty());
            // A forbid that fired decides on its own terms, findings included. A
            // forbid that failed to evaluate denies only when no forbid fired, and
            // the engine's error text goes to the log: the reason that reaches the
            // caller names the statement alone.
            let explicit_forbid = response.decision() == Decision::Deny
                && response.diagnostics().reason().next().is_some();
            if !explicit_forbid && let Some((policy_id, error)) = failed_forbid(rule, &response) {
                let label = policy_label(rule, policy_id);
                tracing::warn!(
                    rule = %rule.name,
                    policy = %label,
                    error = %error,
                    "forbid failed to evaluate; request denied"
                );
                return Ok(EvalResult {
                    allow: false,
                    deny_reason: format!("{label}: evaluation error"),
                    ..EvalResult::default()
                });
            }
            if response.decision() == Decision::Deny {
                // Explicit forbid: stop immediately regardless of rule role.
                // Default-deny (reason() empty) means this rule is not
                // applicable to the request — skip it and continue.
                if response.diagnostics().reason().next().is_none() {
                    // Record a near-miss for Grant rules whose name
                    // contains the tool name (e.g. "slack-grants" for "slack").
                    // This distinguishes "grant rule exists but conditions failed"
                    // from "no rule covers this tool at all".
                    if rule.role == PolicyRuleRole::Grant
                        && grant_rule_near_miss.is_none()
                        && !tool_name_str.is_empty()
                        && rule.name.contains(tool_name_str)
                    {
                        grant_rule_near_miss = Some(rule.name.clone());
                    }
                    continue;
                }
                let findings = match self.deny_findings(rule, &response, &annotations) {
                    Ok(findings) => findings,
                    Err(missing) => return Ok(missing_source_deny(&missing)),
                };
                return Ok(EvalResult {
                    allow: false,
                    deny_reason: deny_reason(rule, &response),
                    findings,
                    ..EvalResult::default()
                });
            }
            // Cedar allow: Grant permits count toward the MCP grant check;
            // Control permits do not (they handle content, not access grants).
            if rule.role == PolicyRuleRole::Grant {
                any_capability_fired = true;
            }
            let mut refs: Vec<&effect::PolicyRefs> = response
                .diagnostics()
                .reason()
                .filter_map(|id| rule.effect_refs.get(id))
                .collect();
            refs.sort_unstable_by_key(|r| r.order);
            for r in refs {
                fired_effects.extend(r.effect.clone());
                fired_findings.extend(r.finding.clone());
            }
        }

        // MCP tool calls require at least one Grant rule to have granted access.
        if has_tool_name && !any_capability_fired {
            let action_id = match (&input.tool, &input.capability) {
                (Some(t), Some(c)) => format!("{t}::{c}"),
                (Some(t), None) => t.clone(),
                _ => "unknown".to_string(),
            };
            let deny_reason = match grant_rule_near_miss {
                // A grant rule for this tool exists but its conditions were not met.
                Some(rule_name) => {
                    format!("{rule_name}: conditions not met for {action_id}")
                }
                // No grant rule covers this tool/capability.
                None => format!("no grant for {action_id}"),
            };
            return Ok(EvalResult {
                allow: false,
                deny_reason,
                ..EvalResult::default()
            });
        }

        let outcome = match self
            .effects
            .apply(&fired_effects, &fired_findings, &annotations)
        {
            Ok(outcome) => outcome,
            Err(missing) => return Ok(missing_source_deny(&missing)),
        };
        Ok(EvalResult {
            allow: true,
            deny_reason: String::new(),
            verdict: outcome.verdict,
            reason: outcome.reason,
            message: outcome.message,
            body_patches: outcome.body_patches,
            body_replacement: outcome.body_replacement,
            header_mutations: outcome.header_mutations,
            findings: outcome.findings,
        })
    }
}

/// A `source:` path with no annotation behind it fails the whole evaluation
/// closed.
fn missing_source_deny(missing: &MissingSource) -> EvalResult {
    EvalResult {
        allow: false,
        deny_reason: missing.deny_reason(),
        ..EvalResult::default()
    }
}

/// The first `forbid` in the rule that failed to evaluate for this request,
/// with the evaluation error behind it.
fn failed_forbid<'a>(
    rule: &CompiledRule,
    response: &'a Response,
) -> Option<(&'a PolicyId, &'a cedar_policy::EvaluationError)> {
    response
        .diagnostics()
        .errors()
        .map(|error| {
            let AuthorizationError::PolicyEvaluationError(error) = error;
            (error.policy_id(), error.inner())
        })
        .find(|(policy_id, _)| {
            rule.policies
                .policy(policy_id)
                .is_some_and(|policy| policy.effect() == Effect::Forbid)
        })
}

/// Policy label `<rule>/<@id or policy id>`. If the `@id` annotation already
/// contains `/` it is used verbatim (the author embedded the rule name prefix
/// in the id, e.g. `@id("security-content-gate/deny-secret")`).
fn policy_label(rule: &CompiledRule, policy_id: &PolicyId) -> String {
    let label = rule
        .policies
        .annotation(policy_id, "id")
        .map_or_else(|| policy_id.to_string(), str::to_string);
    if label.contains('/') {
        label
    } else {
        format!("{}/{label}", rule.name)
    }
}

/// Deny reason: the label of the first determining `forbid`, or
/// `<rule>/no permit matched` when the deny came from Cedar's default.
fn deny_reason(rule: &CompiledRule, response: &Response) -> String {
    match response.diagnostics().reason().next() {
        Some(policy_id) => policy_label(rule, policy_id),
        None => format!("{}/no permit matched", rule.name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTLOOK_SCHEMA: &str = r#"
namespace APF {
  entity User;
  entity Tool;
  action "outlook::message_search" appliesTo {
    principal: [User],
    resource: [Tool],
    context: {
      args: {
        folder: String,
        limit_num: Long,
      },
    }
  };
  action "outlook::message_send" appliesTo {
    principal: [User],
    resource: [Tool],
    context: {
      args: {
        subject_len: Long,
        body_len: Long,
      },
    }
  };
}
"#;

    const OUTLOOK_POLICIES: &str = r#"
permit(
  principal,
  action == APF::Action::"outlook::message_search",
  resource == APF::Tool::"outlook"
) when {
  context.args.folder == "inbox" && context.args.limit_num <= 25
};

permit(
  principal,
  action == APF::Action::"outlook::message_send",
  resource == APF::Tool::"outlook"
) when {
  context.args.subject_len <= 200 && context.args.body_len <= 4000
};
"#;

    fn outlook_rule() -> PolicyRuleDoc {
        PolicyRuleDoc {
            name: "outlook-grants".to_string(),
            schema: Some(OUTLOOK_SCHEMA.to_string()),
            definition: OUTLOOK_POLICIES.to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        }
    }

    fn evaluator(rules: &[PolicyRuleDoc]) -> CedarEvaluator {
        CedarEvaluator::from_policy_rules(rules, &[], &[], &[]).expect("evaluator should build")
    }

    fn args(pairs: &[(&str, &str)]) -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
            .collect()
    }

    fn input(tool: &str, capability: &str, args_pairs: &[(&str, &str)]) -> EvalInput {
        EvalInput::for_tool_call(
            Some(tool.to_string()),
            Some(capability.to_string()),
            "user@corp.com".to_string(),
            args(args_pairs),
        )
    }

    #[test]
    fn permit_const_equality_allow() {
        let ev = evaluator(&[outlook_rule()]);
        let r = ev
            .evaluate(input(
                "outlook",
                "message_search",
                &[("folder", "inbox"), ("limit", "15")],
            ))
            .unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);
        assert!(r.deny_reason.is_empty());
    }

    #[test]
    fn numeric_max_fail_deny() {
        let ev = evaluator(&[outlook_rule()]);
        let r = ev
            .evaluate(input(
                "outlook",
                "message_search",
                &[("folder", "inbox"), ("limit", "30")],
            ))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(
            r.deny_reason,
            "outlook-grants: conditions not met for outlook::message_search"
        );
    }

    #[test]
    fn const_equality_fail_deny() {
        let ev = evaluator(&[outlook_rule()]);
        let r = ev
            .evaluate(input(
                "outlook",
                "message_search",
                &[("folder", "sent"), ("limit", "10")],
            ))
            .unwrap();
        assert!(!r.allow);
    }

    #[test]
    fn max_length_pass_and_fail() {
        let ev = evaluator(&[outlook_rule()]);
        let ok = ev
            .evaluate(input(
                "outlook",
                "message_send",
                &[("subject", "hello"), ("body", "short body")],
            ))
            .unwrap();
        assert!(ok.allow, "unexpected deny: {}", ok.deny_reason);

        let long = "x".repeat(201);
        let denied = ev
            .evaluate(input(
                "outlook",
                "message_send",
                &[("subject", long.as_str()), ("body", "fine")],
            ))
            .unwrap();
        assert!(!denied.allow);
    }

    #[test]
    fn wrong_tool_deny() {
        let ev = evaluator(&[outlook_rule()]);
        let r = ev
            .evaluate(input("slack", "message_search", &[("folder", "inbox")]))
            .unwrap();
        assert!(!r.allow);
    }

    #[test]
    fn wrong_capability_deny() {
        let ev = evaluator(&[outlook_rule()]);
        let r = ev
            .evaluate(input("outlook", "message_delete", &[("folder", "inbox")]))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(
            r.deny_reason,
            "outlook-grants: conditions not met for outlook::message_delete"
        );
    }

    // A non-MCP request (no tool_name) with only capability rules passes through:
    // capability rules skip on default-deny, and no capability requirement exists
    // for non-tool traffic.
    #[test]
    fn non_mcp_with_capability_rules_allows() {
        let ev = evaluator(&[outlook_rule()]);
        let r = ev
            .evaluate(EvalInput::for_tool_call(
                None,
                None,
                "user@corp.com".to_string(),
                args(&[]),
            ))
            .unwrap();
        assert!(r.allow);
    }

    // MCP tool call with zero rules: no capability ever fires, so the request
    // is denied.
    #[test]
    fn no_rules_mcp_deny() {
        let ev = evaluator(&[]);
        let r = ev
            .evaluate(input("outlook", "message_search", &[]))
            .unwrap();
        assert!(!r.allow);
        // No rules at all → no near-miss, generic message.
        assert_eq!(r.deny_reason, "no grant for outlook::message_search");
    }

    #[test]
    fn deny_reason_carries_forbid_id_annotation() {
        let rule = PolicyRuleDoc {
            name: "guard".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@id("no-archive-access")
forbid(principal, action, resource) when {
  context.args.folder == "archive"
};
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = evaluator(&[rule]);
        let r = ev
            .evaluate(input("outlook", "message_search", &[("folder", "archive")]))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "guard/no-archive-access");
    }

    #[test]
    fn deny_reason_falls_back_to_policy_id() {
        let rule = PolicyRuleDoc {
            name: "guard".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

forbid(principal, action, resource) when {
  context.args.folder == "archive"
};
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = evaluator(&[rule]);
        let r = ev
            .evaluate(input("outlook", "message_search", &[("folder", "archive")]))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "guard/policy1");
    }

    #[test]
    fn multi_rule_bundle_order_first_deny_wins() {
        let allow_all = PolicyRuleDoc {
            name: "open".to_string(),
            schema: None,
            definition: "permit(principal, action, resource);".to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let deny_first = PolicyRuleDoc {
            name: "first-deny".to_string(),
            schema: None,
            definition: r#"
@id("first")
forbid(principal, action, resource);
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let deny_second = PolicyRuleDoc {
            name: "second-deny".to_string(),
            schema: None,
            definition: r#"
@id("second")
forbid(principal, action, resource);
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };

        let ev = evaluator(&[allow_all.clone(), deny_first, deny_second]);
        let r = ev
            .evaluate(input("outlook", "message_search", &[]))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "first-deny/first");

        // All rules allowing yields allow.
        let ev = evaluator(&[allow_all.clone(), allow_all]);
        let r = ev
            .evaluate(input("outlook", "message_search", &[]))
            .unwrap();
        assert!(r.allow);
    }

    #[test]
    fn invalid_policy_syntax_is_load_error() {
        let rule = PolicyRuleDoc {
            name: "broken".to_string(),
            schema: None,
            definition: "permit(principal action resource".to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let err = CedarEvaluator::from_policy_rules(&[rule], &[], &[], &[]).expect_err("must fail");
        assert!(err.to_string().contains("broken"), "got: {err}");
    }

    #[test]
    fn schema_shaped_definition_is_load_error() {
        let rule = PolicyRuleDoc {
            name: "stale-format".to_string(),
            schema: None,
            definition: format!("{OUTLOOK_SCHEMA}\n{OUTLOOK_POLICIES}"),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let err = CedarEvaluator::from_policy_rules(&[rule], &[], &[], &[]).expect_err("must fail");
        assert!(err.to_string().contains("`schema` field"), "got: {err}");
    }

    #[test]
    fn invalid_schema_syntax_is_load_error() {
        let rule = PolicyRuleDoc {
            name: "bad-schema".to_string(),
            schema: Some("entity User {".to_string()),
            definition: "permit(principal, action, resource);".to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let err = CedarEvaluator::from_policy_rules(&[rule], &[], &[], &[]).expect_err("must fail");
        assert!(err.to_string().contains("bad-schema"), "got: {err}");
    }

    #[test]
    fn schema_policy_type_mismatch_is_load_error() {
        let rule = PolicyRuleDoc {
            name: "mismatch".to_string(),
            schema: Some(OUTLOOK_SCHEMA.to_string()),
            definition: r#"
permit(
  principal,
  action == APF::Action::"outlook::message_search",
  resource == APF::Tool::"outlook"
) when {
  context.args.limit_num == "not a number"
};
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let err = CedarEvaluator::from_policy_rules(&[rule], &[], &[], &[]).expect_err("must fail");
        assert!(err.to_string().contains("mismatch"), "got: {err}");
    }

    fn secret_annotator() -> PolicyAnnotatorDoc {
        PolicyAnnotatorDoc {
            name: "secret-detector".to_string(),
            annotations: vec![AnnotationSpec {
                name: "secret_detected".to_string(),
                output: AnnotationOutput::Bool,
                set_true_if: SetTrueIf::Any,
                set_value_from: SetValueFrom::FirstMatch,
                rules: vec![AnnotationRule {
                    field: "body_text".to_string(),
                    op: AnnotationOp::RegexMatch,
                    pattern: Some(r"AKIA[0-9A-Z]{16}".to_string()),
                    ..AnnotationRule::default()
                }],
            }],
        }
    }

    #[test]
    fn bool_annotation_drives_forbid() {
        let rule = PolicyRuleDoc {
            name: "guard".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@id("no-secrets")
forbid(principal, action, resource) when {
  context.annotations.secret_detected == true
};
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = CedarEvaluator::from_policy_rules(&[rule], &[secret_annotator()], &[], &[])
            .expect("evaluator builds");

        let mut leaky = input("outlook", "message_send", &[]);
        leaky.body_text = "key=AKIA0123456789ABCDEF".to_string();
        let r = ev.evaluate(leaky).unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "guard/no-secrets");

        let mut clean = input("outlook", "message_send", &[]);
        clean.body_text = "nothing sensitive".to_string();
        let r = ev.evaluate(clean).unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);
    }

    #[test]
    fn string_annotation_read_in_when_clause() {
        let annotator = PolicyAnnotatorDoc {
            name: "content-classifier".to_string(),
            annotations: vec![AnnotationSpec {
                name: "content_class".to_string(),
                output: AnnotationOutput::String,
                set_true_if: SetTrueIf::Any,
                set_value_from: SetValueFrom::FirstMatch,
                rules: vec![AnnotationRule {
                    field: "body_text".to_string(),
                    op: AnnotationOp::Contains,
                    substring: Some("password".to_string()),
                    value: Some("credential".to_string()),
                    ..AnnotationRule::default()
                }],
            }],
        };
        let rule = PolicyRuleDoc {
            name: "classify".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@id("no-credentials")
forbid(principal, action, resource) when {
  context.annotations has content_class &&
  context.annotations.content_class == "credential"
};
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = CedarEvaluator::from_policy_rules(&[rule], &[annotator], &[], &[])
            .expect("evaluator builds");

        let mut flagged = input("outlook", "message_send", &[]);
        flagged.body_text = "my password is hunter2".to_string();
        let r = ev.evaluate(flagged).unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "classify/no-credentials");

        // No match → annotation absent → the `has` guard keeps the forbid off.
        let mut clean = input("outlook", "message_send", &[]);
        clean.body_text = "hello".to_string();
        let r = ev.evaluate(clean).unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);
    }

    fn secret_kind_annotator() -> PolicyAnnotatorDoc {
        PolicyAnnotatorDoc {
            name: "secret-classifier".to_string(),
            annotations: vec![AnnotationSpec {
                name: "secret_kind".to_string(),
                output: AnnotationOutput::String,
                set_true_if: SetTrueIf::Any,
                set_value_from: SetValueFrom::FirstMatch,
                rules: vec![AnnotationRule {
                    field: "body_text".to_string(),
                    op: AnnotationOp::RegexMatch,
                    pattern: Some(r"AKIA[0-9A-Z]{16}".to_string()),
                    value: Some("aws_key".to_string()),
                    ..AnnotationRule::default()
                }],
            }],
        }
    }

    fn redact_effect() -> PolicyEffectDoc {
        PolicyEffectDoc {
            name: "redact-body-and-audit".to_string(),
            verdict: crate::Verdict::Warn,
            reason: Some("secret_in_body".to_string()),
            message: None,
            body: Some(BodySpec {
                replace: Some("[REDACTED]".to_string()),
                patches: Vec::new(),
            }),
            headers: vec![HeaderSpec {
                name: "X-APF-Event".to_string(),
                action: crate::HeaderAction::Set,
                value: None,
                source: Some("context.annotations.secret_kind".to_string()),
            }],
            finding: Some(FindingSpec::Reference("secret-detected".to_string())),
        }
    }

    fn secret_finding() -> PolicyFindingDoc {
        PolicyFindingDoc {
            name: "secret-detected".to_string(),
            kind: "secret_detected".to_string(),
            severity: crate::Severity::Critical,
            label: None,
            label_source: Some("context.annotations.secret_kind".to_string()),
        }
    }

    const SECRET_STAGES_RULE: &str = r#"
@id("baseline_allow")
permit(principal, action, resource);

@apf_finding("secret-detected")
@id("deny_mcp_secret")
forbid(principal, action, resource) when {
  context.has_tool_name &&
  context.annotations has secret_kind
};

@apf_effect("redact-body-and-audit")
@id("redact_rest_secret")
permit(principal, action, resource) when {
  !context.has_tool_name &&
  context.annotations has secret_kind
};
"#;

    fn three_stage_evaluator() -> CedarEvaluator {
        let rule = PolicyRuleDoc {
            name: "secret-redactor".to_string(),
            schema: None,
            definition: SECRET_STAGES_RULE.to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        CedarEvaluator::from_policy_rules(
            &[rule],
            &[secret_kind_annotator()],
            &[redact_effect()],
            &[secret_finding()],
        )
        .expect("evaluator builds")
    }

    #[test]
    fn permit_effect_produces_mutations_verdict_and_finding() {
        let ev = three_stage_evaluator();
        // Non-tool traffic with a secret: the redaction permit fires.
        let mut leaky = EvalInput {
            user_subject: "user@corp.com".to_string(),
            body_text: "key=AKIA0123456789ABCDEF".to_string(),
            ..EvalInput::default()
        };
        leaky.has_tool_name = false;
        let r = ev.evaluate(leaky).unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);
        assert_eq!(r.verdict, crate::Verdict::Warn);
        assert_eq!(r.reason.as_deref(), Some("secret_in_body"));
        assert_eq!(r.body_replacement.as_deref(), Some("[REDACTED]"));
        assert_eq!(r.header_mutations.len(), 1);
        assert_eq!(r.header_mutations[0].value.as_deref(), Some("aws_key"));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].kind, "secret_detected");
        assert_eq!(r.findings[0].label, "aws_key");
        assert_eq!(r.findings[0].severity, crate::Severity::Critical);
    }

    #[test]
    fn deny_path_collects_findings_from_fired_forbid() {
        let ev = three_stage_evaluator();
        let mut leaky = input("outlook", "message_send", &[]);
        leaky.body_text = "key=AKIA0123456789ABCDEF".to_string();
        let r = ev.evaluate(leaky).unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "secret-redactor/deny_mcp_secret");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].label, "aws_key");
        // No mutations accompany a deny.
        assert!(r.body_replacement.is_none());
        assert!(r.header_mutations.is_empty());
    }

    #[test]
    fn clean_request_passes_through_unchanged() {
        let ev = three_stage_evaluator();
        let mut clean = input("outlook", "message_send", &[]);
        clean.body_text = "nothing sensitive".to_string();
        let r = ev.evaluate(clean).unwrap();
        assert_eq!(r, EvalResult::default());
    }

    #[test]
    fn missing_effect_source_denies_closed() {
        // The header source reads an annotation no annotator emits — the
        // permit still fires, so resolution fails closed at evaluation time.
        let rule = PolicyRuleDoc {
            name: "tagger".to_string(),
            schema: None,
            definition: r#"
@apf_effect("tag")
@id("tag_all")
permit(principal, action, resource);
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let effect = PolicyEffectDoc {
            name: "tag".to_string(),
            verdict: crate::Verdict::Allow,
            reason: None,
            message: None,
            body: None,
            headers: vec![HeaderSpec {
                name: "X-Tag".to_string(),
                action: crate::HeaderAction::Set,
                value: None,
                source: Some("context.annotations.absent_key".to_string()),
            }],
            finding: None,
        };
        let ev = CedarEvaluator::from_policy_rules(&[rule], &[], &[effect], &[])
            .expect("evaluator builds");
        let r = ev
            .evaluate(input("outlook", "message_search", &[]))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(
            r.deny_reason,
            "runtime_error:missing_annotation_source:context.annotations.absent_key"
        );
    }

    #[test]
    fn effects_aggregate_across_multiple_fired_permits() {
        let rule = PolicyRuleDoc {
            name: "multi".to_string(),
            schema: None,
            definition: r#"
@apf_effect("first")
@id("first_permit")
permit(principal, action, resource);

@apf_effect("second")
@id("second_permit")
permit(principal, action, resource);
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let mk = |name: &str, verdict: crate::Verdict, header: &str| PolicyEffectDoc {
            name: name.to_string(),
            verdict,
            reason: Some(format!("{name}_reason")),
            message: None,
            body: Some(BodySpec {
                replace: Some(format!("[{name}]")),
                patches: Vec::new(),
            }),
            headers: vec![HeaderSpec {
                name: header.to_string(),
                action: crate::HeaderAction::Set,
                value: Some("1".to_string()),
                source: None,
            }],
            finding: None,
        };
        let ev = CedarEvaluator::from_policy_rules(
            &[rule],
            &[],
            &[
                mk("first", crate::Verdict::Warn, "X-First"),
                mk("second", crate::Verdict::Escalate, "X-Second"),
            ],
            &[],
        )
        .expect("evaluator builds");

        let r = ev
            .evaluate(input("outlook", "message_search", &[]))
            .unwrap();
        assert!(r.allow);
        // Policy order within the rule drives aggregation order.
        assert_eq!(
            r.header_mutations
                .iter()
                .map(|h| h.name.as_str())
                .collect::<Vec<_>>(),
            vec!["X-First", "X-Second"]
        );
        assert_eq!(r.body_replacement.as_deref(), Some("[second]"));
        assert_eq!(r.verdict, crate::Verdict::Escalate);
        assert_eq!(r.reason.as_deref(), Some("second_reason"));
    }

    #[test]
    fn apf_effect_on_forbid_is_load_error() {
        let rule = PolicyRuleDoc {
            name: "bad".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@apf_effect("redact-body-and-audit")
@id("bad_forbid")
forbid(principal, action, resource);
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let err = CedarEvaluator::from_policy_rules(
            &[rule],
            &[],
            &[redact_effect()],
            &[secret_finding()],
        )
        .expect_err("must fail");
        assert!(
            err.to_string().contains("not valid on a forbid"),
            "got: {err}"
        );
    }

    #[test]
    fn unknown_effect_and_finding_references_are_load_errors() {
        let effect_rule = PolicyRuleDoc {
            name: "dangling-effect".to_string(),
            schema: None,
            definition: r#"
@apf_effect("nonexistent")
permit(principal, action, resource);
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let err = CedarEvaluator::from_policy_rules(&[effect_rule], &[], &[], &[])
            .expect_err("must fail");
        assert!(
            err.to_string()
                .contains("unknown PolicyEffect reference 'nonexistent'"),
            "got: {err}"
        );

        let finding_rule = PolicyRuleDoc {
            name: "dangling-finding".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@apf_finding("nonexistent")
forbid(principal, action, resource) when { context.args.folder == "archive" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let err = CedarEvaluator::from_policy_rules(&[finding_rule], &[], &[], &[])
            .expect_err("must fail");
        assert!(
            err.to_string()
                .contains("unknown PolicyFinding reference 'nonexistent'"),
            "got: {err}"
        );
    }

    #[test]
    fn zero_effect_bundle_matches_effect_free_behavior() {
        // A bundle with no effects/findings evaluates identically to the
        // pre-effect engine: plain-allow results and unchanged deny reasons.
        let ev = evaluator(&[outlook_rule()]);
        let allow = ev
            .evaluate(input(
                "outlook",
                "message_search",
                &[("folder", "inbox"), ("limit", "15")],
            ))
            .unwrap();
        assert_eq!(allow, EvalResult::default());
        let deny = ev
            .evaluate(input(
                "outlook",
                "message_search",
                &[("folder", "inbox"), ("limit", "30")],
            ))
            .unwrap();
        assert!(!deny.allow);
        assert_eq!(
            deny.deny_reason,
            "outlook-grants: conditions not met for outlook::message_search"
        );
        assert_eq!(deny.verdict, crate::Verdict::Allow);
        assert!(deny.findings.is_empty());
    }

    #[test]
    fn a_forbid_that_fires_wins_over_a_forbid_that_fails_to_evaluate() {
        let rule = PolicyRuleDoc {
            name: "secret-redactor".to_string(),
            schema: None,
            definition: r#"
@id("baseline_allow")
permit(principal, action, resource);

@apf_finding("secret-detected")
@id("deny_mcp_secret")
forbid(principal, action, resource) when {
  context.has_tool_name &&
  context.annotations has secret_kind
};

@id("needs-approval")
forbid(principal, action, resource) when { context.args.approved == "no" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = CedarEvaluator::from_policy_rules(
            &[rule],
            &[secret_kind_annotator()],
            &[redact_effect()],
            &[secret_finding()],
        )
        .expect("evaluator builds");
        // The approval argument is absent, so the second forbid cannot evaluate;
        // the first forbid fires on the secret and decides, finding included.
        let mut leaky = input("slack", "chat_post_message", &[]);
        leaky.body_text = "key=AKIA0123456789ABCDEF".to_string();
        let r = ev.evaluate(leaky).unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "secret-redactor/deny_mcp_secret");
        assert_eq!(r.findings.len(), 1, "the fired forbid's finding is kept");
        assert_eq!(r.findings[0].kind, "secret_detected");
    }

    #[test]
    fn forbid_that_fails_to_evaluate_denies() {
        let rule = PolicyRuleDoc {
            name: "guard".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@id("needs-approval")
forbid(principal, action, resource) when { context.args.approved == "no" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = evaluator(&[rule]);

        // The argument is absent: the forbid cannot evaluate, so the request
        // is denied rather than the forbid being dropped.
        let r = ev
            .evaluate(input("gitlab", "merge_request_merge", &[]))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "guard/needs-approval: evaluation error");
        assert!(
            !r.deny_reason.contains("approved") && !r.deny_reason.contains("attribute"),
            "the engine's error text must not reach the caller: {}",
            r.deny_reason
        );

        // With the argument present the forbid evaluates normally.
        let r = ev
            .evaluate(input(
                "gitlab",
                "merge_request_merge",
                &[("approved", "yes")],
            ))
            .unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);
        let r = ev
            .evaluate(input(
                "gitlab",
                "merge_request_merge",
                &[("approved", "no")],
            ))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "guard/needs-approval");
    }

    #[test]
    fn forbid_error_denies_even_after_an_earlier_rule_allowed() {
        let allow_all = PolicyRuleDoc {
            name: "open".to_string(),
            schema: None,
            definition: "permit(principal, action, resource);".to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let guard = PolicyRuleDoc {
            name: "guard".to_string(),
            schema: None,
            definition: r#"
@id("needs-approval")
forbid(principal, action, resource) when { context.args.approved == "no" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Control,
        };
        let ev = evaluator(&[allow_all, guard]);
        let r = ev
            .evaluate(input("gitlab", "merge_request_merge", &[]))
            .unwrap();
        assert!(!r.allow);
        assert!(
            r.deny_reason
                .starts_with("guard/needs-approval: evaluation error"),
            "got: {}",
            r.deny_reason
        );
    }

    #[test]
    fn guarded_forbid_is_unaffected_by_a_missing_attribute() {
        let rule = PolicyRuleDoc {
            name: "guard".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@id("needs-approval")
forbid(principal, action, resource)
when { context.args has approved && context.args.approved == "no" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = evaluator(&[rule]);
        let r = ev
            .evaluate(input("gitlab", "merge_request_merge", &[]))
            .unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);
    }

    #[test]
    fn permit_that_fails_to_evaluate_grants_nothing() {
        let rule = PolicyRuleDoc {
            name: "gitlab-grants".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource) when { context.args.approved == "yes" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = evaluator(&[rule]);
        let r = ev
            .evaluate(input("gitlab", "merge_request_merge", &[]))
            .unwrap();
        assert!(!r.allow);
        assert_eq!(
            r.deny_reason,
            "gitlab-grants: conditions not met for gitlab::merge_request_merge"
        );
    }

    fn with_attributes(mut input: EvalInput, namespace: &str, record: Value) -> EvalInput {
        input.context_attributes.insert(
            namespace.to_string(),
            record.as_object().cloned().expect("record"),
        );
        input
    }

    fn change_gated_grant() -> PolicyRuleDoc {
        PolicyRuleDoc {
            name: "change-grants".to_string(),
            schema: None,
            definition: r#"
permit(principal, action == APF::Action::"gitlab::merge_request_merge", resource)
when { context.change has approval && context.change.approval == "approved" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        }
    }

    #[test]
    fn provider_attributes_drive_a_grant() {
        let ev = evaluator(&[change_gated_grant()]);
        let request = || input("gitlab", "merge_request_merge", &[]);

        let approved = with_attributes(
            request(),
            "change",
            serde_json::json!({"approval": "approved", "_meta": {"provider": "cm", "verified": true}}),
        );
        let r = ev.evaluate(approved).unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);

        let withdrawn = with_attributes(
            request(),
            "change",
            serde_json::json!({"approval": "rejected", "_meta": {"provider": "cm", "verified": true}}),
        );
        let r = ev.evaluate(withdrawn).unwrap();
        assert!(!r.allow);
        assert_eq!(r.deny_reason, "no grant for gitlab::merge_request_merge");

        // A degraded provider leaves only provenance behind; the `has` guard
        // keeps the grant off.
        let degraded = with_attributes(
            request(),
            "change",
            serde_json::json!({"_meta": {"provider": "cm", "degraded": true, "status": "timeout"}}),
        );
        let r = ev.evaluate(degraded).unwrap();
        assert!(!r.allow);

        // No provider ran at all: same outcome.
        let r = ev.evaluate(request()).unwrap();
        assert!(!r.allow);
    }

    #[test]
    fn lenient_policy_reads_provenance() {
        let rule = PolicyRuleDoc {
            name: "lenient".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource)
when { context.change._meta.degraded && !(context.change has approval) };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = evaluator(&[rule]);
        let degraded = with_attributes(
            input("gitlab", "merge_request_merge", &[]),
            "change",
            serde_json::json!({"_meta": {"provider": "cm", "degraded": true}}),
        );
        let r = ev.evaluate(degraded).unwrap();
        assert!(r.allow, "unexpected deny: {}", r.deny_reason);
    }

    #[test]
    fn unguarded_forbid_over_a_degraded_provider_denies() {
        let rule = PolicyRuleDoc {
            name: "guard".to_string(),
            schema: None,
            definition: r#"
permit(principal, action, resource);

@id("high-risk")
forbid(principal, action, resource) when { context.change.risk == "high" };
"#
            .to_string(),
            data: serde_json::json!({}),
            role: PolicyRuleRole::Grant,
        };
        let ev = evaluator(&[rule]);
        let degraded = with_attributes(
            input("gitlab", "merge_request_merge", &[]),
            "change",
            serde_json::json!({"_meta": {"provider": "cm", "degraded": true}}),
        );
        let r = ev.evaluate(degraded).unwrap();
        assert!(!r.allow);
        assert!(
            r.deny_reason
                .starts_with("guard/high-risk: evaluation error"),
            "got: {}",
            r.deny_reason
        );
    }

    #[test]
    fn reserved_namespace_is_an_engine_error() {
        let ev = evaluator(&[outlook_rule()]);
        let shadowing = with_attributes(
            input(
                "outlook",
                "message_search",
                &[("folder", "inbox"), ("limit", "15")],
            ),
            "args",
            serde_json::json!({"folder": "inbox", "limit_num": 1}),
        );
        let err = ev.evaluate(shadowing).expect_err("must fail");
        assert!(err.to_string().contains("reserved"), "got: {err}");
    }

    #[test]
    fn zero_annotators_match_annotator_free_behavior() {
        let with_empty = evaluator(&[outlook_rule()]);
        let allow = with_empty
            .evaluate(input(
                "outlook",
                "message_search",
                &[("folder", "inbox"), ("limit", "15")],
            ))
            .unwrap();
        assert_eq!(allow, EvalResult::default());
        let deny = with_empty
            .evaluate(input(
                "outlook",
                "message_search",
                &[("folder", "inbox"), ("limit", "30")],
            ))
            .unwrap();
        assert!(!deny.allow);
        assert_eq!(
            deny.deny_reason,
            "outlook-grants: conditions not met for outlook::message_search"
        );
    }
}
