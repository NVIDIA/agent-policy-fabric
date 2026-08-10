// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Effect post-processor for the Cedar evaluator.
//!
//! [`EffectEngine`] compiles [`PolicyEffectDoc`] and [`PolicyFindingDoc`]
//! definitions at construction time. After Cedar allows a request, the
//! effects referenced by `@apf_effect` on the fired permits are resolved and
//! aggregated into body mutations, header mutations, a verdict, and findings.
//! On deny, `@apf_finding` references on the fired forbids resolve to
//! findings emitted alongside the deny.
//!
//! `source`/`label_source` fields read dynamic values from the annotation
//! record derived by the annotator stage. A source path that is absent at
//! evaluation time fails closed: the caller turns [`MissingSource`] into a
//! deny.

use std::collections::BTreeMap;

use cedar_policy::{Effect, PolicyId, PolicySet};
use serde_json::{Map, Value};

use crate::{
    EvalError, Finding, HeaderAction, HeaderMutation, JsonPatch, PatchOp, Severity, Verdict,
};

/// One `PolicyEffect` document as handed to the evaluator.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEffectDoc {
    pub name: String,
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub body: Option<BodySpec>,
    pub headers: Vec<HeaderSpec>,
    pub finding: Option<FindingSpec>,
}

/// Body mutation carried by an effect: a full replacement or a list of RFC
/// 6902 patches. Exactly one of the two must be set; the engine validates at
/// load time.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BodySpec {
    pub replace: Option<String>,
    pub patches: Vec<PatchSpec>,
}

/// One RFC 6902 patch operation. `value` carries a static operand; `source`
/// reads the operand from an annotation at evaluation time. `replace`/`add`
/// take exactly one of the two; `remove` takes neither.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchSpec {
    pub op: PatchOp,
    pub path: String,
    pub value: Option<Value>,
    pub source: Option<String>,
}

/// One header mutation. `set`/`add` take exactly one of `value`/`source`;
/// `remove` takes neither.
#[derive(Debug, Clone, PartialEq)]
pub struct HeaderSpec {
    pub name: String,
    pub action: HeaderAction,
    pub value: Option<String>,
    pub source: Option<String>,
}

/// The finding an effect emits: a reference to a `PolicyFinding` by name, or
/// an inline definition local to the effect.
#[derive(Debug, Clone, PartialEq)]
pub enum FindingSpec {
    Reference(String),
    Inline(InlineFindingSpec),
}

/// Inline finding definition inside a `PolicyEffect`.
#[derive(Debug, Clone, PartialEq)]
pub struct InlineFindingSpec {
    pub kind: String,
    pub label: Option<String>,
    pub severity: Severity,
    pub confidence: Option<u8>,
    pub label_source: Option<String>,
}

/// One `PolicyFinding` document as handed to the evaluator.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyFindingDoc {
    pub name: String,
    pub kind: String,
    pub severity: Severity,
    pub label: Option<String>,
    pub label_source: Option<String>,
}

/// Prefix every `source`/`label_source` path must carry.
const SOURCE_PREFIX: &str = "context.annotations.";

/// A `source` path is absent from the annotation record at evaluation time.
/// The evaluation fails closed on this.
#[derive(Debug)]
pub(super) struct MissingSource {
    pub path: String,
}

impl MissingSource {
    /// The deny reason the whole evaluation collapses to.
    pub(super) fn deny_reason(&self) -> String {
        format!("runtime_error:missing_annotation_source:{}", self.path)
    }
}

/// Aggregated output of the fired effects for one allowed request.
#[derive(Debug, Default, PartialEq)]
pub(super) struct EffectOutcome {
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub body_patches: Vec<JsonPatch>,
    pub body_replacement: Option<String>,
    pub header_mutations: Vec<HeaderMutation>,
    pub findings: Vec<Finding>,
}

/// A validated annotation source: the key to look up and the original path
/// for error reporting.
#[derive(Debug)]
struct SourceRef {
    key: String,
    path: String,
}

impl SourceRef {
    fn parse(context: &dyn Fn() -> String, path: &str) -> Result<Self, EvalError> {
        let key = path.strip_prefix(SOURCE_PREFIX).filter(|k| !k.is_empty());
        match key {
            Some(key) => Ok(Self {
                key: key.to_string(),
                path: path.to_string(),
            }),
            None => Err(EvalError::Engine(format!(
                "{}: source '{path}' must be a context.annotations.<key> path",
                context()
            ))),
        }
    }

    fn resolve<'a>(&self, annotations: &'a Map<String, Value>) -> Result<&'a Value, MissingSource> {
        annotations.get(&self.key).ok_or_else(|| MissingSource {
            path: self.path.clone(),
        })
    }
}

/// String view of an annotation value for header operands and finding labels.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[derive(Debug)]
struct CompiledEffect {
    verdict: Verdict,
    reason: Option<String>,
    message: Option<String>,
    body_replacement: Option<String>,
    patches: Vec<CompiledPatch>,
    headers: Vec<CompiledHeader>,
    finding: Option<CompiledFindingRef>,
}

#[derive(Debug)]
struct CompiledPatch {
    op: PatchOp,
    path: String,
    value: Option<Value>,
    source: Option<SourceRef>,
}

impl CompiledPatch {
    fn resolve(&self, annotations: &Map<String, Value>) -> Result<JsonPatch, MissingSource> {
        let value = match &self.source {
            Some(source) => Some(source.resolve(annotations)?.clone()),
            None => self.value.clone(),
        };
        Ok(JsonPatch {
            op: self.op,
            path: self.path.clone(),
            value,
        })
    }
}

#[derive(Debug)]
struct CompiledHeader {
    name: String,
    action: HeaderAction,
    value: Option<String>,
    source: Option<SourceRef>,
}

impl CompiledHeader {
    fn resolve(&self, annotations: &Map<String, Value>) -> Result<HeaderMutation, MissingSource> {
        let value = match &self.source {
            Some(source) => Some(value_to_string(source.resolve(annotations)?)),
            None => self.value.clone(),
        };
        Ok(HeaderMutation {
            name: self.name.clone(),
            action: self.action,
            value,
        })
    }
}

#[derive(Debug)]
enum CompiledFindingRef {
    Named(String),
    Inline(CompiledFinding),
}

#[derive(Debug)]
struct CompiledFinding {
    kind: String,
    label: Option<String>,
    severity: Severity,
    confidence: Option<u8>,
    label_source: Option<SourceRef>,
}

impl CompiledFinding {
    fn resolve(&self, annotations: &Map<String, Value>) -> Result<Finding, MissingSource> {
        let label = match &self.label_source {
            Some(source) => value_to_string(source.resolve(annotations)?),
            None => self.label.clone().unwrap_or_default(),
        };
        Ok(Finding {
            kind: self.kind.clone(),
            label,
            severity: self.severity,
            confidence: self.confidence,
        })
    }
}

/// Resolves effects and findings referenced by fired Cedar policies.
/// Immutable after construction; safe to share across threads.
pub struct EffectEngine {
    effects: BTreeMap<String, CompiledEffect>,
    findings: BTreeMap<String, CompiledFinding>,
}

impl std::fmt::Debug for EffectEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectEngine")
            .field("effects", &self.effects.keys().collect::<Vec<_>>())
            .field("findings", &self.findings.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl EffectEngine {
    /// Compile every effect and finding definition. Invalid operand
    /// combinations, malformed source paths, duplicate names, and dangling
    /// finding references are load-time errors.
    pub fn from_docs(
        effects: &[PolicyEffectDoc],
        findings: &[PolicyFindingDoc],
    ) -> Result<Self, EvalError> {
        let mut compiled_findings = BTreeMap::new();
        for doc in findings {
            let compiled = compile_finding_doc(doc)?;
            if compiled_findings
                .insert(doc.name.clone(), compiled)
                .is_some()
            {
                return Err(EvalError::Engine(format!(
                    "duplicate PolicyFinding '{}'",
                    doc.name
                )));
            }
        }

        let mut compiled_effects = BTreeMap::new();
        for doc in effects {
            let compiled = compile_effect_doc(doc)?;
            if let Some(CompiledFindingRef::Named(name)) = &compiled.finding
                && !compiled_findings.contains_key(name)
            {
                return Err(EvalError::Engine(format!(
                    "effect '{}': unknown PolicyFinding reference '{name}'",
                    doc.name
                )));
            }
            if compiled_effects
                .insert(doc.name.clone(), compiled)
                .is_some()
            {
                return Err(EvalError::Engine(format!(
                    "duplicate PolicyEffect '{}'",
                    doc.name
                )));
            }
        }

        Ok(Self {
            effects: compiled_effects,
            findings: compiled_findings,
        })
    }

    pub(super) fn has_effect(&self, name: &str) -> bool {
        self.effects.contains_key(name)
    }

    pub(super) fn has_finding(&self, name: &str) -> bool {
        self.findings.contains_key(name)
    }

    /// Resolve a named finding against the request's annotations.
    pub(super) fn resolve_finding(
        &self,
        name: &str,
        annotations: &Map<String, Value>,
    ) -> Result<Finding, MissingSource> {
        // Load-time reference checks guarantee the name is present.
        self.findings
            .get(name)
            .expect("finding reference validated at load")
            .resolve(annotations)
    }

    /// Aggregate the effects and findings fired by the permits of an allowed
    /// request, in the caller-supplied order.
    ///
    /// Aggregation is ordered, not conflict-resolving: patches accumulate in
    /// fire order with sequential RFC 6902 semantics (a later op targeting the
    /// same path wins at application time — the engine neither dedupes nor
    /// rejects overlaps, it only guarantees deterministic order), a body
    /// replacement is last-wins, headers accumulate in order, and the verdict
    /// is the strongest fired one. `reason`/`message` come from the first
    /// fired effect carrying the final verdict.
    pub(super) fn apply(
        &self,
        effect_names: &[String],
        finding_names: &[String],
        annotations: &Map<String, Value>,
    ) -> Result<EffectOutcome, MissingSource> {
        let mut outcome = EffectOutcome::default();

        let fired: Vec<&CompiledEffect> = effect_names
            .iter()
            .map(|name| {
                self.effects
                    .get(name)
                    .expect("effect reference validated at load")
            })
            .collect();

        outcome.verdict = fired
            .iter()
            .map(|e| e.verdict)
            .max()
            .unwrap_or(Verdict::Allow);
        if let Some(winner) = fired.iter().find(|e| e.verdict == outcome.verdict) {
            outcome.reason.clone_from(&winner.reason);
            outcome.message.clone_from(&winner.message);
        }

        for effect in &fired {
            for patch in &effect.patches {
                outcome.body_patches.push(patch.resolve(annotations)?);
            }
            if let Some(replacement) = &effect.body_replacement {
                outcome.body_replacement = Some(replacement.clone());
            }
            for header in &effect.headers {
                outcome.header_mutations.push(header.resolve(annotations)?);
            }
            if let Some(finding) = &effect.finding {
                outcome.findings.push(match finding {
                    CompiledFindingRef::Named(name) => self.resolve_finding(name, annotations)?,
                    CompiledFindingRef::Inline(inline) => inline.resolve(annotations)?,
                });
            }
        }

        for name in finding_names {
            outcome
                .findings
                .push(self.resolve_finding(name, annotations)?);
        }

        Ok(outcome)
    }
}

fn compile_effect_doc(doc: &PolicyEffectDoc) -> Result<CompiledEffect, EvalError> {
    let context = || format!("effect '{}'", doc.name);
    let load_err = |cause: String| EvalError::Engine(format!("{}: {cause}", context()));

    let (body_replacement, patches) = match &doc.body {
        Some(body) => {
            if body.replace.is_some() && !body.patches.is_empty() {
                return Err(load_err(
                    "body.replace and body.patches are mutually exclusive".to_string(),
                ));
            }
            if body.replace.is_none() && body.patches.is_empty() {
                return Err(load_err(
                    "body requires either replace or patches".to_string(),
                ));
            }
            let patches = body
                .patches
                .iter()
                .map(|p| compile_patch(&context, p))
                .collect::<Result<Vec<_>, _>>()?;
            (body.replace.clone(), patches)
        }
        None => (None, Vec::new()),
    };

    let headers = doc
        .headers
        .iter()
        .map(|h| compile_header(&context, h))
        .collect::<Result<Vec<_>, _>>()?;

    let finding = match &doc.finding {
        Some(FindingSpec::Reference(name)) => Some(CompiledFindingRef::Named(name.clone())),
        Some(FindingSpec::Inline(inline)) => Some(CompiledFindingRef::Inline(CompiledFinding {
            kind: inline.kind.clone(),
            label: inline.label.clone(),
            severity: inline.severity,
            confidence: inline.confidence,
            label_source: inline
                .label_source
                .as_deref()
                .map(|path| SourceRef::parse(&context, path))
                .transpose()?,
        })),
        None => None,
    };

    Ok(CompiledEffect {
        verdict: doc.verdict,
        reason: doc.reason.clone(),
        message: doc.message.clone(),
        body_replacement,
        patches,
        headers,
        finding,
    })
}

fn compile_patch(
    context: &dyn Fn() -> String,
    spec: &PatchSpec,
) -> Result<CompiledPatch, EvalError> {
    let load_err = |cause: String| EvalError::Engine(format!("{}: {cause}", context()));
    match spec.op {
        PatchOp::Replace | PatchOp::Add => {
            if spec.value.is_some() == spec.source.is_some() {
                return Err(load_err(format!(
                    "patch '{}' requires exactly one of value or source",
                    spec.path
                )));
            }
        }
        PatchOp::Remove => {
            if spec.value.is_some() || spec.source.is_some() {
                return Err(load_err(format!(
                    "patch '{}': remove takes neither value nor source",
                    spec.path
                )));
            }
        }
    }
    Ok(CompiledPatch {
        op: spec.op,
        path: spec.path.clone(),
        value: spec.value.clone(),
        source: spec
            .source
            .as_deref()
            .map(|path| SourceRef::parse(context, path))
            .transpose()?,
    })
}

fn compile_header(
    context: &dyn Fn() -> String,
    spec: &HeaderSpec,
) -> Result<CompiledHeader, EvalError> {
    let load_err = |cause: String| EvalError::Engine(format!("{}: {cause}", context()));
    match spec.action {
        HeaderAction::Set | HeaderAction::Add => {
            if spec.value.is_some() == spec.source.is_some() {
                return Err(load_err(format!(
                    "header '{}' requires exactly one of value or source",
                    spec.name
                )));
            }
        }
        HeaderAction::Remove => {
            if spec.value.is_some() || spec.source.is_some() {
                return Err(load_err(format!(
                    "header '{}': remove takes neither value nor source",
                    spec.name
                )));
            }
        }
    }
    Ok(CompiledHeader {
        name: spec.name.clone(),
        action: spec.action,
        value: spec.value.clone(),
        source: spec
            .source
            .as_deref()
            .map(|path| SourceRef::parse(context, path))
            .transpose()?,
    })
}

fn compile_finding_doc(doc: &PolicyFindingDoc) -> Result<CompiledFinding, EvalError> {
    let context = || format!("finding '{}'", doc.name);
    Ok(CompiledFinding {
        kind: doc.kind.clone(),
        label: doc.label.clone(),
        severity: doc.severity,
        confidence: None,
        label_source: doc
            .label_source
            .as_deref()
            .map(|path| SourceRef::parse(&context, path))
            .transpose()?,
    })
}

// ---------------------------------------------------------------------------
// Fired-policy reference table
// ---------------------------------------------------------------------------

/// `@apf_effect`/`@apf_finding` references carried by one Cedar policy, plus
/// its position for deterministic aggregation order.
#[derive(Debug)]
pub(super) struct PolicyRefs {
    pub effect: Option<String>,
    pub finding: Option<String>,
    pub order: usize,
}

/// Build the per-policy reference table for one compiled rule and validate
/// the references against the effect engine. Cedar's response diagnostics
/// expose only the `PolicyId`s of fired policies, so annotations are read
/// once at load time and looked up by id at evaluation time.
pub(super) fn build_ref_table(
    rule_name: &str,
    policies: &PolicySet,
    engine: &EffectEngine,
) -> Result<std::collections::HashMap<PolicyId, PolicyRefs>, EvalError> {
    let load_err = |cause: String| EvalError::Engine(format!("rule '{rule_name}': {cause}"));

    // Statically parsed policies are assigned ids `policy0..policyN` in text
    // order, but `PolicySet::policies()` iteration order is unspecified —
    // recover text order from the numeric id suffix.
    let mut ordered: Vec<&cedar_policy::Policy> = policies.policies().collect();
    ordered.sort_by(|a, b| {
        let key = |p: &cedar_policy::Policy| {
            let id = p.id().to_string();
            let numeric = id
                .strip_prefix("policy")
                .and_then(|n| n.parse::<u64>().ok());
            (numeric, id)
        };
        key(a).cmp(&key(b))
    });

    let mut table = std::collections::HashMap::new();
    for (order, policy) in ordered.into_iter().enumerate() {
        let effect_ref = policy.annotation("apf_effect").map(str::to_string);
        let finding_ref = policy.annotation("apf_finding").map(str::to_string);

        if let Some(name) = &effect_ref {
            if policy.effect() == Effect::Forbid {
                return Err(load_err(format!(
                    "@apf_effect(\"{name}\") is not valid on a forbid policy"
                )));
            }
            if !engine.has_effect(name) {
                return Err(load_err(format!("unknown PolicyEffect reference '{name}'")));
            }
        }
        if let Some(name) = &finding_ref
            && !engine.has_finding(name)
        {
            return Err(load_err(format!(
                "unknown PolicyFinding reference '{name}'"
            )));
        }

        if effect_ref.is_some() || finding_ref.is_some() {
            table.insert(
                policy.id().clone(),
                PolicyRefs {
                    effect: effect_ref,
                    finding: finding_ref,
                    order,
                },
            );
        }
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect(name: &str) -> PolicyEffectDoc {
        PolicyEffectDoc {
            name: name.to_string(),
            verdict: Verdict::Allow,
            reason: None,
            message: None,
            body: None,
            headers: Vec::new(),
            finding: None,
        }
    }

    fn finding_doc(name: &str) -> PolicyFindingDoc {
        PolicyFindingDoc {
            name: name.to_string(),
            kind: "secret_detected".to_string(),
            severity: Severity::Critical,
            label: None,
            label_source: None,
        }
    }

    fn annotations(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn verdict_aggregates_to_strongest() {
        let mut warn = effect("warn");
        warn.verdict = Verdict::Warn;
        warn.reason = Some("warn_reason".to_string());
        let mut escalate = effect("escalate");
        escalate.verdict = Verdict::Escalate;
        escalate.reason = Some("escalate_reason".to_string());
        escalate.message = Some("needs review".to_string());
        let plain = effect("plain");

        let engine = EffectEngine::from_docs(&[warn, escalate, plain], &[]).unwrap();
        let outcome = engine
            .apply(&names(&["plain", "warn", "escalate"]), &[], &Map::new())
            .unwrap();
        assert_eq!(outcome.verdict, Verdict::Escalate);
        assert_eq!(outcome.reason.as_deref(), Some("escalate_reason"));
        assert_eq!(outcome.message.as_deref(), Some("needs review"));

        let outcome = engine
            .apply(&names(&["plain", "warn"]), &[], &Map::new())
            .unwrap();
        assert_eq!(outcome.verdict, Verdict::Warn);
        assert_eq!(outcome.reason.as_deref(), Some("warn_reason"));
    }

    #[test]
    fn patches_aggregate_in_fire_order() {
        let mut first = effect("first");
        first.body = Some(BodySpec {
            replace: None,
            patches: vec![
                PatchSpec {
                    op: PatchOp::Replace,
                    path: "/model".to_string(),
                    value: Some(Value::String("small".to_string())),
                    source: None,
                },
                PatchSpec {
                    op: PatchOp::Remove,
                    path: "/stream".to_string(),
                    value: None,
                    source: None,
                },
            ],
        });
        let mut second = effect("second");
        second.body = Some(BodySpec {
            replace: None,
            patches: vec![PatchSpec {
                op: PatchOp::Replace,
                path: "/model".to_string(),
                value: Some(Value::String("tiny".to_string())),
                source: None,
            }],
        });

        let engine = EffectEngine::from_docs(&[first, second], &[]).unwrap();
        let outcome = engine
            .apply(&names(&["first", "second"]), &[], &Map::new())
            .unwrap();
        assert_eq!(
            outcome.body_patches,
            vec![
                JsonPatch {
                    op: PatchOp::Replace,
                    path: "/model".to_string(),
                    value: Some(Value::String("small".to_string())),
                },
                JsonPatch {
                    op: PatchOp::Remove,
                    path: "/stream".to_string(),
                    value: None,
                },
                JsonPatch {
                    op: PatchOp::Replace,
                    path: "/model".to_string(),
                    value: Some(Value::String("tiny".to_string())),
                },
            ]
        );
    }

    #[test]
    fn body_replacement_last_wins() {
        let mut first = effect("first");
        first.body = Some(BodySpec {
            replace: Some("[FIRST]".to_string()),
            patches: Vec::new(),
        });
        let mut second = effect("second");
        second.body = Some(BodySpec {
            replace: Some("[SECOND]".to_string()),
            patches: Vec::new(),
        });

        let engine = EffectEngine::from_docs(&[first, second], &[]).unwrap();
        let outcome = engine
            .apply(&names(&["first", "second"]), &[], &Map::new())
            .unwrap();
        assert_eq!(outcome.body_replacement.as_deref(), Some("[SECOND]"));
    }

    #[test]
    fn headers_aggregate_in_fire_order() {
        let mut first = effect("first");
        first.headers = vec![HeaderSpec {
            name: "X-First".to_string(),
            action: HeaderAction::Set,
            value: Some("1".to_string()),
            source: None,
        }];
        let mut second = effect("second");
        second.headers = vec![
            HeaderSpec {
                name: "X-Second".to_string(),
                action: HeaderAction::Add,
                value: Some("2".to_string()),
                source: None,
            },
            HeaderSpec {
                name: "X-Gone".to_string(),
                action: HeaderAction::Remove,
                value: None,
                source: None,
            },
        ];

        let engine = EffectEngine::from_docs(&[first, second], &[]).unwrap();
        let outcome = engine
            .apply(&names(&["first", "second"]), &[], &Map::new())
            .unwrap();
        assert_eq!(
            outcome
                .header_mutations
                .iter()
                .map(|h| h.name.as_str())
                .collect::<Vec<_>>(),
            vec!["X-First", "X-Second", "X-Gone"]
        );
    }

    #[test]
    fn source_resolves_from_annotations() {
        let mut redact = effect("redact");
        redact.body = Some(BodySpec {
            replace: None,
            patches: vec![PatchSpec {
                op: PatchOp::Replace,
                path: "/kind".to_string(),
                value: None,
                source: Some("context.annotations.secret_kind".to_string()),
            }],
        });
        redact.headers = vec![HeaderSpec {
            name: "X-APF-Event".to_string(),
            action: HeaderAction::Set,
            value: None,
            source: Some("context.annotations.secret_kind".to_string()),
        }];

        let engine = EffectEngine::from_docs(&[redact], &[]).unwrap();
        let ann = annotations(&[("secret_kind", Value::String("openai_key".to_string()))]);
        let outcome = engine.apply(&names(&["redact"]), &[], &ann).unwrap();
        assert_eq!(
            outcome.body_patches[0].value,
            Some(Value::String("openai_key".to_string()))
        );
        assert_eq!(
            outcome.header_mutations[0].value.as_deref(),
            Some("openai_key")
        );
    }

    #[test]
    fn missing_source_fails_closed() {
        let mut redact = effect("redact");
        redact.headers = vec![HeaderSpec {
            name: "X-APF-Event".to_string(),
            action: HeaderAction::Set,
            value: None,
            source: Some("context.annotations.secret_kind".to_string()),
        }];

        let engine = EffectEngine::from_docs(&[redact], &[]).unwrap();
        let err = engine
            .apply(&names(&["redact"]), &[], &Map::new())
            .expect_err("must fail closed");
        assert_eq!(
            err.deny_reason(),
            "runtime_error:missing_annotation_source:context.annotations.secret_kind"
        );
    }

    #[test]
    fn inline_and_referenced_findings_resolve() {
        let mut inline = effect("inline");
        inline.finding = Some(FindingSpec::Inline(InlineFindingSpec {
            kind: "budget_signal".to_string(),
            label: Some("tool_call_count".to_string()),
            severity: Severity::Medium,
            confidence: Some(90),
            label_source: None,
        }));
        let mut referenced = effect("referenced");
        referenced.finding = Some(FindingSpec::Reference("secret-detected".to_string()));

        let engine =
            EffectEngine::from_docs(&[inline, referenced], &[finding_doc("secret-detected")])
                .unwrap();
        let outcome = engine
            .apply(&names(&["inline", "referenced"]), &[], &Map::new())
            .unwrap();
        assert_eq!(
            outcome.findings,
            vec![
                Finding {
                    kind: "budget_signal".to_string(),
                    label: "tool_call_count".to_string(),
                    severity: Severity::Medium,
                    confidence: Some(90),
                },
                Finding {
                    kind: "secret_detected".to_string(),
                    label: String::new(),
                    severity: Severity::Critical,
                    confidence: None,
                },
            ]
        );
    }

    #[test]
    fn label_source_overrides_label() {
        let mut doc = finding_doc("secret-detected");
        doc.label = Some("static".to_string());
        doc.label_source = Some("context.annotations.secret_kind".to_string());
        let engine = EffectEngine::from_docs(&[], &[doc]).unwrap();

        let ann = annotations(&[("secret_kind", Value::String("github_pat".to_string()))]);
        let finding = engine.resolve_finding("secret-detected", &ann).unwrap();
        assert_eq!(finding.label, "github_pat");

        // Fail closed when the source annotation is absent.
        let err = engine
            .resolve_finding("secret-detected", &Map::new())
            .expect_err("must fail closed");
        assert_eq!(
            err.deny_reason(),
            "runtime_error:missing_annotation_source:context.annotations.secret_kind"
        );
    }

    #[test]
    fn non_string_source_values_stringify_for_headers() {
        let mut tag = effect("tag");
        tag.headers = vec![HeaderSpec {
            name: "X-Count".to_string(),
            action: HeaderAction::Set,
            value: None,
            source: Some("context.annotations.count".to_string()),
        }];
        let engine = EffectEngine::from_docs(&[tag], &[]).unwrap();
        let ann = annotations(&[("count", Value::from(42))]);
        let outcome = engine.apply(&names(&["tag"]), &[], &ann).unwrap();
        assert_eq!(outcome.header_mutations[0].value.as_deref(), Some("42"));
    }

    #[test]
    fn zero_effects_yield_default_outcome() {
        let engine = EffectEngine::from_docs(&[], &[]).unwrap();
        let outcome = engine.apply(&[], &[], &Map::new()).unwrap();
        assert_eq!(outcome, EffectOutcome::default());
    }

    #[test]
    fn replace_and_patches_together_is_load_error() {
        let mut bad = effect("bad");
        bad.body = Some(BodySpec {
            replace: Some("[X]".to_string()),
            patches: vec![PatchSpec {
                op: PatchOp::Remove,
                path: "/x".to_string(),
                value: None,
                source: None,
            }],
        });
        let err = EffectEngine::from_docs(&[bad], &[]).expect_err("must fail");
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn empty_body_spec_is_load_error() {
        let mut bad = effect("bad");
        bad.body = Some(BodySpec::default());
        let err = EffectEngine::from_docs(&[bad], &[]).expect_err("must fail");
        assert!(err.to_string().contains("replace or patches"), "got: {err}");
    }

    #[test]
    fn patch_operand_combinations_are_validated() {
        // Both value and source.
        let mut both = effect("both");
        both.body = Some(BodySpec {
            replace: None,
            patches: vec![PatchSpec {
                op: PatchOp::Replace,
                path: "/x".to_string(),
                value: Some(Value::from(1)),
                source: Some("context.annotations.x".to_string()),
            }],
        });
        let err = EffectEngine::from_docs(&[both], &[]).expect_err("must fail");
        assert!(err.to_string().contains("exactly one"), "got: {err}");

        // Neither value nor source.
        let mut neither = effect("neither");
        neither.body = Some(BodySpec {
            replace: None,
            patches: vec![PatchSpec {
                op: PatchOp::Add,
                path: "/x".to_string(),
                value: None,
                source: None,
            }],
        });
        let err = EffectEngine::from_docs(&[neither], &[]).expect_err("must fail");
        assert!(err.to_string().contains("exactly one"), "got: {err}");

        // Remove with an operand.
        let mut remove = effect("remove");
        remove.body = Some(BodySpec {
            replace: None,
            patches: vec![PatchSpec {
                op: PatchOp::Remove,
                path: "/x".to_string(),
                value: Some(Value::from(1)),
                source: None,
            }],
        });
        let err = EffectEngine::from_docs(&[remove], &[]).expect_err("must fail");
        assert!(err.to_string().contains("neither"), "got: {err}");
    }

    #[test]
    fn header_operand_combinations_are_validated() {
        let mut neither = effect("neither");
        neither.headers = vec![HeaderSpec {
            name: "X".to_string(),
            action: HeaderAction::Set,
            value: None,
            source: None,
        }];
        let err = EffectEngine::from_docs(&[neither], &[]).expect_err("must fail");
        assert!(err.to_string().contains("exactly one"), "got: {err}");

        let mut remove = effect("remove");
        remove.headers = vec![HeaderSpec {
            name: "X".to_string(),
            action: HeaderAction::Remove,
            value: Some("v".to_string()),
            source: None,
        }];
        let err = EffectEngine::from_docs(&[remove], &[]).expect_err("must fail");
        assert!(err.to_string().contains("neither"), "got: {err}");
    }

    #[test]
    fn malformed_source_path_is_load_error() {
        let mut bad = effect("bad");
        bad.headers = vec![HeaderSpec {
            name: "X".to_string(),
            action: HeaderAction::Set,
            value: None,
            source: Some("annotations.secret_kind".to_string()),
        }];
        let err = EffectEngine::from_docs(&[bad], &[]).expect_err("must fail");
        assert!(
            err.to_string().contains("context.annotations.<key>"),
            "got: {err}"
        );
    }

    #[test]
    fn unknown_finding_reference_is_load_error() {
        let mut bad = effect("bad");
        bad.finding = Some(FindingSpec::Reference("nope".to_string()));
        let err = EffectEngine::from_docs(&[bad], &[]).expect_err("must fail");
        assert!(
            err.to_string()
                .contains("unknown PolicyFinding reference 'nope'"),
            "got: {err}"
        );
    }

    #[test]
    fn duplicate_names_are_load_errors() {
        let err =
            EffectEngine::from_docs(&[effect("dup"), effect("dup")], &[]).expect_err("must fail");
        assert!(
            err.to_string().contains("duplicate PolicyEffect"),
            "got: {err}"
        );

        let err = EffectEngine::from_docs(&[], &[finding_doc("dup"), finding_doc("dup")])
            .expect_err("must fail");
        assert!(
            err.to_string().contains("duplicate PolicyFinding"),
            "got: {err}"
        );
    }
}
