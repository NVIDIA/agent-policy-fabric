// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Frontend: parse a canonical APF `SandboxPolicy` YAML document into the
//! `nvidia.agent_policy_fabric.policy.v1alpha1.SandboxPolicy` IR, a canonical
//! `PolicyRule` YAML document into the canonical `PolicyRule` IR, a canonical
//! `PolicyAnnotator` YAML document into [`PolicyAnnotator`], and canonical
//! `PolicyEffect`/`PolicyFinding` YAML documents into
//! [`PolicyEffect`]/[`PolicyFinding`].
//!
//! The serde types below are private parse-tree nodes. They mirror the APF
//! proto schema field-for-field but use serde rather than prost so the
//! YAML round-trip is clean. `parse` is the single public entry point.

use std::collections::BTreeMap;

use apf_proto::ir;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    #[error("utf-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("{0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unsupported language: {0} (not registered)")]
    UnsupportedLanguage(String),
    #[error("data document is not JSON-representable: {0}")]
    Data(String),
    #[error("annotation '{0}': threshold_from is not supported (use a static threshold)")]
    ThresholdFrom(String),
}

/// Parse `bytes` as a canonical APF `SandboxPolicy` YAML document and return
/// the canonical IR. The caller feeds this to the pass pipeline and then to
/// each backend.
pub fn parse(bytes: &[u8]) -> Result<ir::SandboxPolicy, FrontendError> {
    let yaml = std::str::from_utf8(bytes)?;
    let doc: Document = serde_yaml::from_str(yaml)?;
    Ok(to_ir(doc))
}

// ---------------------------------------------------------------------------
// PolicyRule frontend
// ---------------------------------------------------------------------------

/// Evaluation languages a `PolicyRule` may declare. A language is registered
/// only once an `Evaluator` backend exists for it; unregistered values fail
/// compilation rather than passing through unevaluated.
const REGISTERED_LANGUAGES: &[&str] = &["cedar"];

/// Parse `bytes` as a canonical APF `PolicyRule` YAML document into the
/// canonical IR, validating `spec.language` against the registered-language
/// set.
pub fn parse_policy_rule(bytes: &[u8]) -> Result<ir::PolicyRule, FrontendError> {
    let yaml = std::str::from_utf8(bytes)?;
    let doc: PolicyRuleDocument = serde_yaml::from_str(yaml)?;
    if !REGISTERED_LANGUAGES.contains(&doc.spec.language.as_str()) {
        return Err(FrontendError::UnsupportedLanguage(doc.spec.language));
    }
    let data = doc.spec.data.map(yaml_to_struct).transpose()?;
    let m = doc.metadata.unwrap_or_default();
    Ok(ir::PolicyRule {
        metadata: Some(ir::ObjectMeta {
            name: m.name,
            namespace: m.namespace,
            version: m.version,
            title: m.title,
            description: m.description,
        }),
        spec: Some(ir::PolicyRuleSpec {
            description: doc.spec.description,
            language: doc.spec.language,
            schema: doc.spec.schema,
            definition: doc.spec.definition,
            data,
            role: apf_policy_eval::PolicyRuleRole::Grant as i32,
        }),
    })
}

/// Convert a proto `PolicyRule` IR message to an evaluator-facing doc.
/// The `role` field is taken directly from the proto; absent/unspecified
/// defaults to `Grant`.
#[must_use]
pub fn policy_rule_to_doc(rule: &ir::PolicyRule) -> apf_policy_eval::PolicyRuleDoc {
    let spec = rule.spec.clone().unwrap_or_default();
    apf_policy_eval::PolicyRuleDoc {
        name: rule
            .metadata
            .as_ref()
            .map(|m| m.name.clone())
            .unwrap_or_default(),
        schema: spec.schema,
        definition: spec.definition,
        data: spec
            .data
            .as_ref()
            .map_or(serde_json::Value::Null, apf_proto::json::struct_to_json),
        role: apf_policy_eval::PolicyRuleRole::Grant,
    }
}

/// Convert a proto `PolicyRule` IR message to an evaluator-facing doc,
/// preserving the `role` field set during compilation.
pub fn parse_policy_rule_doc(
    rule: &ir::PolicyRule,
) -> Result<apf_policy_eval::PolicyRuleDoc, FrontendError> {
    let spec = rule.spec.clone().unwrap_or_default();
    if !REGISTERED_LANGUAGES.contains(&spec.language.as_str()) {
        return Err(FrontendError::UnsupportedLanguage(spec.language));
    }
    let data = spec
        .data
        .as_ref()
        .map_or(serde_json::Value::Null, apf_proto::json::struct_to_json);
    let role = apf_policy_eval::PolicyRuleRole::try_from(spec.role)
        .unwrap_or(apf_policy_eval::PolicyRuleRole::Grant);
    Ok(apf_policy_eval::PolicyRuleDoc {
        name: rule
            .metadata
            .as_ref()
            .map(|m| m.name.clone())
            .unwrap_or_default(),
        schema: spec.schema,
        definition: spec.definition,
        data,
        role,
    })
}

/// Convert a YAML mapping to a `google.protobuf.Struct`; non-mapping values
/// are rejected because the canonical `spec.data` field is a Struct.
fn yaml_to_struct(v: serde_yaml::Value) -> Result<prost_types::Struct, FrontendError> {
    let json = serde_json::to_value(v).map_err(|e| FrontendError::Data(e.to_string()))?;
    let value = apf_proto::json::json_to_proto_value(&json).map_err(FrontendError::Data)?;
    match value.kind {
        Some(prost_types::value::Kind::StructValue(s)) => Ok(s),
        _ => Err(FrontendError::Data(
            "data document must be a mapping".to_string(),
        )),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRuleDocument {
    #[serde(rename = "apiVersion", default)]
    #[allow(dead_code)]
    api_version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    metadata: Option<MetadataDef>,
    spec: PolicyRuleSpecDef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRuleSpecDef {
    #[serde(default)]
    description: String,
    language: String,
    #[serde(default)]
    schema: Option<String>,
    definition: String,
    #[serde(default)]
    data: Option<serde_yaml::Value>,
    // role is parsed from YAML but mapped to the proto IR enum separately
    // via parse_policy_rule_doc; stored here only to satisfy deny_unknown_fields.
    #[serde(default)]
    #[allow(dead_code)]
    role: Option<String>,
}

// ---------------------------------------------------------------------------
// PolicyAnnotator frontend
// ---------------------------------------------------------------------------

/// A parsed `kind: PolicyAnnotator` document. The annotation specs use the
/// evaluator's types directly — the frontend's job is YAML shape validation
/// and enum mapping, not a second representation.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyAnnotator {
    pub name: String,
    pub description: String,
    pub annotations: Vec<apf_policy_eval::AnnotationSpec>,
}

impl PolicyAnnotator {
    /// The evaluator-facing shape of this annotator.
    #[must_use]
    pub fn to_doc(&self) -> apf_policy_eval::PolicyAnnotatorDoc {
        apf_policy_eval::PolicyAnnotatorDoc {
            name: self.name.clone(),
            annotations: self.annotations.clone(),
        }
    }
}

/// Parse `bytes` as a canonical APF `PolicyAnnotator` YAML document.
pub fn parse_policy_annotator(bytes: &[u8]) -> Result<PolicyAnnotator, FrontendError> {
    let yaml = std::str::from_utf8(bytes)?;
    let doc: PolicyAnnotatorDocument = serde_yaml::from_str(yaml)?;
    let annotations = doc
        .spec
        .annotations
        .into_iter()
        .map(to_annotation_spec)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyAnnotator {
        name: doc.metadata.unwrap_or_default().name,
        description: doc.spec.description,
        annotations,
    })
}

fn to_annotation_spec(
    def: AnnotationDef,
) -> Result<apf_policy_eval::AnnotationSpec, FrontendError> {
    let rules = def
        .rules
        .into_iter()
        .map(|r| {
            if r.threshold_from.is_some() {
                return Err(FrontendError::ThresholdFrom(def.name.clone()));
            }
            Ok(apf_policy_eval::AnnotationRule {
                field: r.field,
                op: r.op.into(),
                pattern: r.pattern,
                value: r.value,
                suffix: r.suffix,
                prefix: r.prefix,
                substring: r.substring,
                threshold: r.threshold,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(apf_policy_eval::AnnotationSpec {
        name: def.name,
        output: def.output.into(),
        set_true_if: def.set_true_if.into(),
        set_value_from: def.set_value_from.into(),
        rules,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAnnotatorDocument {
    #[serde(rename = "apiVersion", default)]
    #[allow(dead_code)]
    api_version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    metadata: Option<MetadataDef>,
    spec: PolicyAnnotatorSpecDef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAnnotatorSpecDef {
    #[serde(default)]
    description: String,
    #[serde(default)]
    annotations: Vec<AnnotationDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnotationDef {
    name: String,
    output: AnnotationOutputDef,
    #[serde(default)]
    set_true_if: SetTrueIfDef,
    #[serde(default)]
    set_value_from: SetValueFromDef,
    #[serde(default)]
    rules: Vec<AnnotationRuleDef>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AnnotationOutputDef {
    Bool,
    String,
    Integer,
}

impl From<AnnotationOutputDef> for apf_policy_eval::AnnotationOutput {
    fn from(def: AnnotationOutputDef) -> Self {
        match def {
            AnnotationOutputDef::Bool => Self::Bool,
            AnnotationOutputDef::String => Self::String,
            AnnotationOutputDef::Integer => Self::Integer,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SetTrueIfDef {
    #[default]
    Any,
    All,
}

impl From<SetTrueIfDef> for apf_policy_eval::SetTrueIf {
    fn from(def: SetTrueIfDef) -> Self {
        match def {
            SetTrueIfDef::Any => Self::Any,
            SetTrueIfDef::All => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
enum SetValueFromDef {
    #[default]
    #[serde(rename = "first_match")]
    FirstMatch,
}

impl From<SetValueFromDef> for apf_policy_eval::SetValueFrom {
    fn from(def: SetValueFromDef) -> Self {
        match def {
            SetValueFromDef::FirstMatch => Self::FirstMatch,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnotationRuleDef {
    field: String,
    op: AnnotationOpDef,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    suffix: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    substring: Option<String>,
    #[serde(default)]
    threshold: Option<i64>,
    #[serde(default)]
    threshold_from: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum AnnotationOpDef {
    #[serde(rename = "regex_match")]
    RegexMatch,
    #[serde(rename = "equals")]
    Equals,
    #[serde(rename = "endswith")]
    EndsWith,
    #[serde(rename = "startswith")]
    StartsWith,
    #[serde(rename = "contains")]
    Contains,
    #[serde(rename = "length")]
    Length,
    #[serde(rename = "gte")]
    Gte,
    #[serde(rename = "lte")]
    Lte,
    #[serde(rename = "passthrough")]
    Passthrough,
}

impl From<AnnotationOpDef> for apf_policy_eval::AnnotationOp {
    fn from(def: AnnotationOpDef) -> Self {
        match def {
            AnnotationOpDef::RegexMatch => Self::RegexMatch,
            AnnotationOpDef::Equals => Self::Equals,
            AnnotationOpDef::EndsWith => Self::EndsWith,
            AnnotationOpDef::StartsWith => Self::StartsWith,
            AnnotationOpDef::Contains => Self::Contains,
            AnnotationOpDef::Length => Self::Length,
            AnnotationOpDef::Gte => Self::Gte,
            AnnotationOpDef::Lte => Self::Lte,
            AnnotationOpDef::Passthrough => Self::Passthrough,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyEffect / PolicyFinding frontend
// ---------------------------------------------------------------------------

fn meta_name(meta: &Option<ir::ObjectMeta>) -> &str {
    meta.as_ref().map_or("", |m| m.name.as_str())
}

/// Parse `bytes` as a canonical APF `PolicyEffect` YAML document.
pub fn parse_policy_effect(bytes: &[u8]) -> Result<ir::PolicyEffect, FrontendError> {
    let yaml = std::str::from_utf8(bytes)?;
    let doc: PolicyEffectDocument = serde_yaml::from_str(yaml)?;
    let m = doc.metadata.unwrap_or_default();
    let spec = doc.spec;

    let body = spec
        .body
        .map(|b| {
            Ok::<_, FrontendError>(ir::BodySpec {
                replace: b.replace,
                patches: b
                    .patches
                    .into_iter()
                    .map(to_patch_spec)
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .transpose()?;

    let headers = spec
        .headers
        .into_iter()
        .map(|h| ir::HeaderSpec {
            name: h.name,
            action: ir::HeaderAction::from(h.action) as i32,
            value: h.value,
            source: h.source,
        })
        .collect();

    let finding = spec.finding.map(|f| match f {
        FindingDef::Reference(name) => ir::FindingRef {
            kind: Some(ir::finding_ref::Kind::Reference(name)),
        },
        FindingDef::Inline(inline) => ir::FindingRef {
            kind: Some(ir::finding_ref::Kind::Inline(ir::InlineFinding {
                kind: inline.kind,
                label: inline.label,
                severity: ir::Severity::from(inline.severity) as i32,
                confidence: inline.confidence.map(u32::from),
                label_source: inline.label_source,
            })),
        },
    });

    Ok(ir::PolicyEffect {
        metadata: Some(ir::ObjectMeta {
            name: m.name,
            namespace: m.namespace,
            version: m.version,
            title: m.title,
            description: spec.description.clone(),
        }),
        spec: Some(ir::PolicyEffectSpec {
            description: spec.description,
            verdict: ir::Verdict::from(spec.verdict) as i32,
            reason: spec.reason,
            message: spec.message,
            body,
            headers,
            finding,
        }),
    })
}

/// Parse `bytes` as a canonical APF `PolicyFinding` YAML document.
pub fn parse_policy_finding(bytes: &[u8]) -> Result<ir::PolicyFinding, FrontendError> {
    let yaml = std::str::from_utf8(bytes)?;
    let doc: PolicyFindingDocument = serde_yaml::from_str(yaml)?;
    let m = doc.metadata.unwrap_or_default();
    Ok(ir::PolicyFinding {
        metadata: Some(ir::ObjectMeta {
            name: m.name,
            namespace: m.namespace,
            version: m.version,
            title: m.title,
            description: doc.spec.description.clone(),
        }),
        spec: Some(ir::PolicyFindingSpec {
            description: doc.spec.description,
            kind: doc.spec.kind,
            severity: ir::Severity::from(doc.spec.severity) as i32,
            label: doc.spec.label,
            label_source: doc.spec.label_source,
        }),
    })
}

/// Convert a proto IR `PolicyEffect` to the evaluator-facing doc type.
#[must_use]
pub fn effect_to_doc(e: &ir::PolicyEffect) -> apf_policy_eval::PolicyEffectDoc {
    let name = meta_name(&e.metadata).to_string();
    let spec = e.spec.as_ref().cloned().unwrap_or_default();

    let verdict = match ir::Verdict::try_from(spec.verdict).unwrap_or_default() {
        ir::Verdict::Unspecified | ir::Verdict::Allow => apf_policy_eval::Verdict::Allow,
        ir::Verdict::Warn => apf_policy_eval::Verdict::Warn,
        ir::Verdict::Escalate => apf_policy_eval::Verdict::Escalate,
    };

    let body = spec.body.map(|b| apf_policy_eval::BodySpec {
        replace: b.replace,
        patches: b
            .patches
            .into_iter()
            .map(|p| {
                let op = match ir::PatchOp::try_from(p.op).unwrap_or_default() {
                    ir::PatchOp::Unspecified | ir::PatchOp::Replace => {
                        apf_policy_eval::PatchOp::Replace
                    }
                    ir::PatchOp::Add => apf_policy_eval::PatchOp::Add,
                    ir::PatchOp::Remove => apf_policy_eval::PatchOp::Remove,
                };
                apf_policy_eval::PatchSpec {
                    op,
                    path: p.path,
                    value: p.value.as_ref().map(apf_proto::json::prost_value_to_json),
                    source: p.source,
                }
            })
            .collect(),
    });

    let headers = spec
        .headers
        .into_iter()
        .map(|h| {
            let action = match ir::HeaderAction::try_from(h.action).unwrap_or_default() {
                ir::HeaderAction::Unspecified | ir::HeaderAction::Set => {
                    apf_policy_eval::HeaderAction::Set
                }
                ir::HeaderAction::Add => apf_policy_eval::HeaderAction::Add,
                ir::HeaderAction::Remove => apf_policy_eval::HeaderAction::Remove,
            };
            apf_policy_eval::HeaderSpec {
                name: h.name,
                action,
                value: h.value,
                source: h.source,
            }
        })
        .collect();

    let finding = spec.finding.and_then(|f| {
        f.kind.map(|k| match k {
            ir::finding_ref::Kind::Reference(r) => apf_policy_eval::FindingSpec::Reference(r),
            ir::finding_ref::Kind::Inline(inline) => {
                let severity = match ir::Severity::try_from(inline.severity).unwrap_or_default() {
                    ir::Severity::Unspecified | ir::Severity::Low => apf_policy_eval::Severity::Low,
                    ir::Severity::Medium => apf_policy_eval::Severity::Medium,
                    ir::Severity::High => apf_policy_eval::Severity::High,
                    ir::Severity::Critical => apf_policy_eval::Severity::Critical,
                };
                apf_policy_eval::FindingSpec::Inline(apf_policy_eval::InlineFindingSpec {
                    kind: inline.kind,
                    label: inline.label,
                    severity,
                    confidence: inline.confidence.and_then(|c| u8::try_from(c).ok()),
                    label_source: inline.label_source,
                })
            }
        })
    });

    apf_policy_eval::PolicyEffectDoc {
        name,
        verdict,
        reason: spec.reason,
        message: spec.message,
        body,
        headers,
        finding,
    }
}

/// Convert a proto IR `PolicyFinding` to the evaluator-facing doc type.
#[must_use]
pub fn finding_to_doc(f: &ir::PolicyFinding) -> apf_policy_eval::PolicyFindingDoc {
    let name = meta_name(&f.metadata).to_string();
    let spec = f.spec.as_ref().cloned().unwrap_or_default();

    let severity = match ir::Severity::try_from(spec.severity).unwrap_or_default() {
        ir::Severity::Unspecified | ir::Severity::Low => apf_policy_eval::Severity::Low,
        ir::Severity::Medium => apf_policy_eval::Severity::Medium,
        ir::Severity::High => apf_policy_eval::Severity::High,
        ir::Severity::Critical => apf_policy_eval::Severity::Critical,
    };

    apf_policy_eval::PolicyFindingDoc {
        name,
        kind: spec.kind,
        severity,
        label: spec.label,
        label_source: spec.label_source,
    }
}

fn to_patch_spec(def: PatchDef) -> Result<ir::PatchSpec, FrontendError> {
    let value = def
        .value
        .map(|v| {
            let json = serde_json::to_value(v).map_err(|e| FrontendError::Data(e.to_string()))?;
            apf_proto::json::json_to_proto_value(&json).map_err(FrontendError::Data)
        })
        .transpose()?;
    Ok(ir::PatchSpec {
        op: ir::PatchOp::from(def.op) as i32,
        path: def.path,
        value,
        source: def.source,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEffectDocument {
    #[serde(rename = "apiVersion", default)]
    #[allow(dead_code)]
    api_version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    metadata: Option<MetadataDef>,
    spec: PolicyEffectSpecDef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEffectSpecDef {
    #[serde(default)]
    description: String,
    #[serde(default)]
    verdict: VerdictDef,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    body: Option<BodyDef>,
    #[serde(default)]
    headers: Vec<HeaderDef>,
    #[serde(default)]
    finding: Option<FindingDef>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum VerdictDef {
    #[default]
    Allow,
    Warn,
    Escalate,
}

impl From<VerdictDef> for ir::Verdict {
    fn from(def: VerdictDef) -> Self {
        match def {
            VerdictDef::Allow => Self::Allow,
            VerdictDef::Warn => Self::Warn,
            VerdictDef::Escalate => Self::Escalate,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyDef {
    #[serde(default)]
    replace: Option<String>,
    #[serde(default)]
    patches: Vec<PatchDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchDef {
    op: PatchOpDef,
    path: String,
    #[serde(default)]
    value: Option<serde_yaml::Value>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PatchOpDef {
    Replace,
    Add,
    Remove,
}

impl From<PatchOpDef> for ir::PatchOp {
    fn from(def: PatchOpDef) -> Self {
        match def {
            PatchOpDef::Replace => Self::Replace,
            PatchOpDef::Add => Self::Add,
            PatchOpDef::Remove => Self::Remove,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderDef {
    name: String,
    action: HeaderActionDef,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum HeaderActionDef {
    Set,
    Add,
    Remove,
}

impl From<HeaderActionDef> for ir::HeaderAction {
    fn from(def: HeaderActionDef) -> Self {
        match def {
            HeaderActionDef::Set => Self::Set,
            HeaderActionDef::Add => Self::Add,
            HeaderActionDef::Remove => Self::Remove,
        }
    }
}

/// `spec.finding` is either a string reference to a `PolicyFinding` by name
/// or an inline finding object.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FindingDef {
    Reference(String),
    Inline(InlineFindingDef),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineFindingDef {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    label: Option<String>,
    severity: SeverityDef,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    label_source: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SeverityDef {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityDef> for ir::Severity {
    fn from(def: SeverityDef) -> Self {
        match def {
            SeverityDef::Low => Self::Low,
            SeverityDef::Medium => Self::Medium,
            SeverityDef::High => Self::High,
            SeverityDef::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFindingDocument {
    #[serde(rename = "apiVersion", default)]
    #[allow(dead_code)]
    api_version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    metadata: Option<MetadataDef>,
    spec: PolicyFindingSpecDef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFindingSpecDef {
    #[serde(default)]
    description: String,
    #[serde(rename = "type")]
    kind: String,
    severity: SeverityDef,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    label_source: Option<String>,
}

// ---------------------------------------------------------------------------
// Parse tree — private YAML serde types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(rename = "apiVersion", default)]
    #[allow(dead_code)]
    api_version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    metadata: Option<MetadataDef>,
    spec: SpecDef,
}

// No deny_unknown_fields on metadata — forward-compat (labels, annotations, …).
#[derive(Debug, Default, Deserialize)]
struct MetadataDef {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    version: u32,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecDef {
    #[serde(default)]
    filesystem: Option<FilesystemDef>,
    #[serde(default)]
    landlock: Option<LandlockDef>,
    #[serde(default)]
    process: Option<ProcessDef>,
    #[serde(default)]
    network_policies: BTreeMap<String, NetworkPolicyRuleDef>,
    #[serde(default)]
    network_middlewares: BTreeMap<String, NetworkMiddlewareConfigDef>,
}

/// Parsed `network_middlewares` entry from a `SandboxPolicy` YAML document.
/// Mirrors `openshell.sandbox.v1.NetworkMiddlewareConfig`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMiddlewareConfigDef {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub middleware: String,
    #[serde(default)]
    pub on_error: String,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub endpoints: MiddlewareEndpointSelectorDef,
}

/// Host selector for a `NetworkMiddlewareConfig`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiddlewareEndpointSelectorDef {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Parse the `network_middlewares` map from a `SandboxPolicy` YAML document.
/// Returns an empty map when the document has no `network_middlewares` key.
pub fn parse_network_middlewares(
    bytes: &[u8],
) -> Result<BTreeMap<String, NetworkMiddlewareConfigDef>, FrontendError> {
    let yaml = std::str::from_utf8(bytes)?;
    let doc: Document = serde_yaml::from_str(yaml)?;
    Ok(doc.spec.network_middlewares)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemDef {
    #[serde(default)]
    include_workdir: bool,
    #[serde(default)]
    read_only: Vec<String>,
    #[serde(default)]
    read_write: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LandlockDef {
    #[serde(default)]
    compatibility: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessDef {
    #[serde(default)]
    run_as_user: String,
    #[serde(default)]
    run_as_group: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyRuleDef {
    #[serde(default)]
    name: String,
    #[serde(default)]
    endpoints: Vec<NetworkEndpointDef>,
    #[serde(default)]
    binaries: Vec<NetworkBinaryDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkEndpointDef {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    // u16 so values > 65535 are rejected up front.
    #[serde(default)]
    port: u16,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    enforcement: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    rules: Vec<L7RuleDef>,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    deny_rules: Vec<L7DenyRuleDef>,
    #[serde(default)]
    allow_encoded_slash: bool,
    #[serde(default)]
    websocket_credential_rewrite: bool,
    #[serde(default)]
    request_body_credential_rewrite: bool,
    #[serde(default)]
    persisted_queries: String,
    #[serde(default)]
    graphql_persisted_queries: BTreeMap<String, GraphqlOperationDef>,
    #[serde(default)]
    graphql_max_body_bytes: u32,
    #[serde(default)]
    json_rpc_max_body_bytes: u32,
    #[serde(default)]
    mcp: Option<McpConfigDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct McpConfigDef {
    #[serde(default)]
    max_body_bytes: u32,
    #[serde(default)]
    strict_tool_names: Option<bool>,
    #[serde(default)]
    allow_all_known_mcp_methods: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlOperationDef {
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7RuleDef {
    allow: L7AllowDef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7AllowDef {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    query: BTreeMap<String, QueryMatcherDef>,
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    params: BTreeMap<String, QueryMatcherDef>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum QueryMatcherDef {
    Glob(String),
    Any(QueryAnyDef),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryAnyDef {
    #[serde(default)]
    any: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7DenyRuleDef {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    query: BTreeMap<String, QueryMatcherDef>,
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    params: BTreeMap<String, QueryMatcherDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkBinaryDef {
    path: String,
    #[serde(default)]
    #[allow(dead_code)]
    harness: bool,
}

// ---------------------------------------------------------------------------
// Parse tree → canonical IR
// ---------------------------------------------------------------------------

fn to_ir(doc: Document) -> ir::SandboxPolicy {
    let metadata = doc.metadata.map(|m| ir::ObjectMeta {
        name: m.name,
        namespace: m.namespace,
        version: m.version,
        title: m.title,
        description: m.description,
    });
    ir::SandboxPolicy {
        metadata,
        spec: Some(to_spec(doc.spec)),
    }
}

fn to_spec(raw: SpecDef) -> ir::SandboxPolicySpec {
    ir::SandboxPolicySpec {
        filesystem: raw.filesystem.map(|fs| ir::FilesystemPolicy {
            include_workdir: fs.include_workdir,
            read_only: fs.read_only,
            read_write: fs.read_write,
        }),
        landlock: raw.landlock.map(|ll| ir::LandlockPolicy {
            compatibility: ll.compatibility,
        }),
        process: raw.process.map(|p| ir::ProcessPolicy {
            run_as_user: p.run_as_user,
            run_as_group: p.run_as_group,
        }),
        network_policies: raw
            .network_policies
            .into_iter()
            .map(|(key, rule)| {
                // Invariant: every NetworkPolicyRule in the IR has a non-empty name.
                let name = if rule.name.is_empty() {
                    key.clone()
                } else {
                    rule.name
                };
                let ir_rule = ir::NetworkPolicyRule {
                    name,
                    endpoints: rule.endpoints.into_iter().map(to_endpoint).collect(),
                    binaries: rule
                        .binaries
                        .into_iter()
                        .map(|b| ir::NetworkBinary { path: b.path })
                        .collect(),
                };
                (key, ir_rule)
            })
            .collect(),
    }
}

pub(crate) fn to_endpoint(e: NetworkEndpointDef) -> ir::NetworkEndpoint {
    // `ports` takes precedence; a single `port` is promoted to `ports: [port]`.
    let normalized_ports: Vec<u32> = if !e.ports.is_empty() {
        e.ports.into_iter().map(u32::from).collect()
    } else if e.port > 0 {
        vec![u32::from(e.port)]
    } else {
        vec![]
    };

    // Propagate mcp.max_body_bytes → json_rpc_max_body_bytes when the
    // top-level field is unset (explicit top-level takes precedence).
    let json_rpc_max_body_bytes = if e.json_rpc_max_body_bytes > 0 {
        e.json_rpc_max_body_bytes
    } else {
        e.mcp.as_ref().map_or(0, |m| m.max_body_bytes)
    };

    ir::NetworkEndpoint {
        host: e.host,
        path: e.path,
        port: normalized_ports.first().copied().unwrap_or(0),
        ports: normalized_ports,
        protocol: e.protocol,
        tls: e.tls,
        enforcement: e.enforcement,
        access: e.access,
        rules: e.rules.into_iter().map(to_l7rule).collect(),
        allowed_ips: e.allowed_ips,
        deny_rules: e.deny_rules.into_iter().map(to_deny_rule).collect(),
        allow_encoded_slash: e.allow_encoded_slash,
        websocket_credential_rewrite: e.websocket_credential_rewrite,
        request_body_credential_rewrite: e.request_body_credential_rewrite,
        persisted_queries: e.persisted_queries,
        graphql_persisted_queries: e
            .graphql_persisted_queries
            .into_iter()
            .map(|(k, op)| {
                (
                    k,
                    ir::GraphqlOperation {
                        operation_type: op.operation_type,
                        operation_name: op.operation_name,
                        fields: op.fields,
                    },
                )
            })
            .collect(),
        graphql_max_body_bytes: e.graphql_max_body_bytes,
        json_rpc_max_body_bytes,
        mcp: e.mcp.map(|m| ir::McpOptions {
            strict_tool_names: m.strict_tool_names,
            allow_all_known_mcp_methods: m.allow_all_known_mcp_methods,
        }),
    }
}

fn to_l7rule(r: L7RuleDef) -> ir::L7Rule {
    ir::L7Rule {
        allow: Some(ir::L7Allow {
            method: r.allow.method,
            path: r.allow.path,
            command: r.allow.command,
            operation_type: r.allow.operation_type,
            operation_name: r.allow.operation_name,
            fields: r.allow.fields,
            query: r.allow.query.into_iter().map(to_query_matcher).collect(),
            params: r.allow.params.into_iter().map(to_query_matcher).collect(),
        }),
    }
}

fn to_deny_rule(d: L7DenyRuleDef) -> ir::L7DenyRule {
    ir::L7DenyRule {
        method: d.method,
        path: d.path,
        command: d.command,
        operation_type: d.operation_type,
        operation_name: d.operation_name,
        fields: d.fields,
        query: d.query.into_iter().map(to_query_matcher).collect(),
        params: d.params.into_iter().map(to_query_matcher).collect(),
    }
}

fn to_query_matcher(kv: (String, QueryMatcherDef)) -> (String, ir::L7QueryMatcher) {
    let (key, matcher) = kv;
    let proto = match matcher {
        QueryMatcherDef::Glob(glob) => ir::L7QueryMatcher { glob, any: vec![] },
        QueryMatcherDef::Any(any) => ir::L7QueryMatcher {
            glob: String::new(),
            any: any.any,
        },
    };
    (key, proto)
}

// ---------------------------------------------------------------------------
// Bundle-level parse helpers
// ---------------------------------------------------------------------------

/// Parse all `PolicyRule` members from a bundle into IR order.
pub fn parse_policy_rules(
    members: &apf_bundle::BundleMembers,
) -> Result<Vec<ir::PolicyRule>, FrontendError> {
    members
        .policy_rules
        .iter()
        .map(|(_, bytes)| parse_policy_rule(bytes))
        .collect()
}

/// Parse all `PolicyAnnotator` members from a bundle into IR order.
pub fn parse_policy_annotators(
    members: &apf_bundle::BundleMembers,
) -> Result<Vec<PolicyAnnotator>, FrontendError> {
    members
        .policy_annotators
        .iter()
        .map(|(_, bytes)| parse_policy_annotator(bytes))
        .collect()
}

/// Parse all `PolicyEffect` members from a bundle into IR order.
pub fn parse_policy_effects(
    members: &apf_bundle::BundleMembers,
) -> Result<Vec<ir::PolicyEffect>, FrontendError> {
    members
        .policy_effects
        .iter()
        .map(|(_, bytes)| parse_policy_effect(bytes))
        .collect()
}

/// Parse all `PolicyFinding` members from a bundle into IR order.
pub fn parse_policy_findings(
    members: &apf_bundle::BundleMembers,
) -> Result<Vec<ir::PolicyFinding>, FrontendError> {
    members
        .policy_findings
        .iter()
        .map(|(_, bytes)| parse_policy_finding(bytes))
        .collect()
}

/// Assemble a `CanonicalPolicy` from already-verified bundle members.
pub fn build_canonical_policy(
    members: &apf_bundle::BundleMembers,
) -> Result<crate::backend::CanonicalPolicy, FrontendError> {
    use std::collections::BTreeMap;
    let mut sandbox_policies = BTreeMap::new();
    let sandbox_middleware = BTreeMap::new();
    for (name, bytes) in &members.sandbox_policies {
        let policy = parse(bytes)?;
        // sandbox_middleware is carried out-of-band (BSR field not yet available)
        sandbox_policies.insert(name.clone(), policy);
    }
    let mut providers = BTreeMap::new();
    for (name, bytes) in &members.providers {
        let provider = crate::provider::parse(bytes)?;
        providers.insert(name.clone(), provider);
    }
    let policy_rules = parse_policy_rules(members)?;
    let policy_annotators = parse_policy_annotators(members)?;
    let policy_effects = parse_policy_effects(members)?;
    let policy_findings = parse_policy_findings(members)?;
    let provider_profiles = members.provider_profiles.clone();
    Ok(crate::backend::CanonicalPolicy {
        sandbox_policies,
        sandbox_middleware,
        providers,
        provider_profiles,
        policy_rules,
        policy_annotators,
        policy_effects,
        policy_findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STUB: &str = r#"apiVersion: nvidia.agent-policy-fabric.sandbox/v1alpha1
kind: SandboxPolicy
metadata:
  name: default
spec:
  filesystem:
    include_workdir: true
    read_only:
      - /usr
      - /lib
      - /proc
      - /dev/urandom
      - /app
      - /etc
      - /var/log
    read_write:
      - /sandbox
      - /tmp
      - /dev/null
  landlock:
    compatibility: best_effort
  process:
    run_as_user: sandbox
    run_as_group: sandbox
"#;

    #[test]
    fn parses_stub_fixture() {
        let ir = parse(STUB.as_bytes()).expect("stub fixture must parse");
        let spec = ir.spec.expect("spec present");
        let fs = spec.filesystem.expect("filesystem present");
        assert!(fs.include_workdir);
        assert_eq!(
            fs.read_only,
            vec![
                "/usr",
                "/lib",
                "/proc",
                "/dev/urandom",
                "/app",
                "/etc",
                "/var/log"
            ]
        );
        assert_eq!(fs.read_write, vec!["/sandbox", "/tmp", "/dev/null"]);
        let ll = spec.landlock.expect("landlock present");
        assert_eq!(ll.compatibility, "best_effort");
        let proc_p = spec.process.expect("process present");
        assert_eq!(proc_p.run_as_user, "sandbox");
    }

    #[test]
    fn propagates_metadata() {
        let yaml = "metadata:\n  name: test\n  version: 3\nspec: {}\n";
        let ir = parse(yaml.as_bytes()).expect("parse");
        let meta = ir.metadata.expect("metadata present");
        assert_eq!(meta.name, "test");
        assert_eq!(meta.version, 3);
    }

    #[test]
    fn rejects_unknown_spec_field() {
        let yaml = "spec:\n  bogus_field: true\n";
        let err = parse(yaml.as_bytes()).expect_err("unknown field must reject");
        assert!(format!("{err}").contains("bogus_field"));
    }

    const POLICY_RULE: &str = r"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyRule
metadata:
  name: outlook-grants
spec:
  description: Outlook grant enforcement
  language: cedar
  definition: |
    permit(principal, action, resource);
  data:
    grants:
      - tool: outlook
";

    #[test]
    fn parses_policy_rule_fixture() {
        let rule = parse_policy_rule(POLICY_RULE.as_bytes()).expect("policy rule must parse");
        let metadata = rule.metadata.as_ref().expect("metadata present");
        assert_eq!(metadata.name, "outlook-grants");
        let spec = rule.spec.as_ref().expect("spec present");
        assert_eq!(spec.description, "Outlook grant enforcement");
        assert_eq!(spec.language, "cedar");
        assert_eq!(spec.schema, None);
        assert!(spec.definition.contains("permit"));
        assert!(spec.data.is_some());

        let doc = policy_rule_to_doc(&rule);
        assert_eq!(doc.name, "outlook-grants");
        assert_eq!(doc.schema, None);
        assert_eq!(doc.definition, spec.definition);
        assert_eq!(doc.data["grants"][0]["tool"], "outlook");
    }

    #[test]
    fn parses_policy_rule_schema_field() {
        let yaml = POLICY_RULE.replace(
            "  definition: |",
            "  schema: |\n    namespace APF {\n      entity User;\n    }\n  definition: |",
        );
        let rule = parse_policy_rule(yaml.as_bytes()).expect("policy rule must parse");
        let spec = rule.spec.as_ref().expect("spec present");
        let schema = spec.schema.as_deref().expect("schema present");
        assert!(schema.contains("namespace APF"));
        assert!(spec.definition.contains("permit"));

        let doc = policy_rule_to_doc(&rule);
        assert_eq!(doc.schema.as_deref(), Some(schema));
    }

    #[test]
    fn policy_rule_without_data_maps_to_json_null() {
        let yaml = POLICY_RULE.replace("  data:\n    grants:\n      - tool: outlook\n", "");
        let rule = parse_policy_rule(yaml.as_bytes()).expect("policy rule must parse");
        assert_eq!(rule.spec.as_ref().expect("spec present").data, None);
        assert_eq!(policy_rule_to_doc(&rule).data, serde_json::Value::Null);
    }

    #[test]
    fn rejects_non_mapping_policy_rule_data() {
        let yaml = POLICY_RULE.replace(
            "  data:\n    grants:\n      - tool: outlook\n",
            "  data: 7\n",
        );
        let err = parse_policy_rule(yaml.as_bytes()).expect_err("scalar data must reject");
        assert!(format!("{err}").contains("mapping"));
    }

    #[test]
    fn policy_rule_role_defaults_to_grant() {
        let rule = parse_policy_rule(POLICY_RULE.as_bytes()).expect("must parse");
        let doc = parse_policy_rule_doc(&rule).expect("must build doc");
        assert_eq!(doc.role, apf_policy_eval::PolicyRuleRole::Grant);
    }

    #[test]
    fn policy_rule_role_control_parsed() {
        let yaml = POLICY_RULE.replace("language: cedar", "language: cedar");
        let mut rule = parse_policy_rule(yaml.as_bytes()).expect("must parse");
        if let Some(spec) = rule.spec.as_mut() {
            spec.role = apf_policy_eval::PolicyRuleRole::Control as i32;
        }
        let doc = parse_policy_rule_doc(&rule).expect("must build doc");
        assert_eq!(doc.role, apf_policy_eval::PolicyRuleRole::Control);
    }

    #[test]
    fn rejects_unregistered_policy_rule_language() {
        let yaml = POLICY_RULE.replace("language: cedar", "language: rego");
        let err = parse_policy_rule(yaml.as_bytes()).expect_err("rego is not registered");
        assert_eq!(
            err.to_string(),
            "unsupported language: rego (not registered)"
        );
    }

    #[test]
    fn rejects_unknown_policy_rule_spec_field() {
        let yaml = POLICY_RULE.replace("description:", "bogus_field: true\n  description:");
        let err = parse_policy_rule(yaml.as_bytes()).expect_err("unknown field must reject");
        assert!(format!("{err}").contains("bogus_field"));
    }

    const POLICY_ANNOTATOR: &str = r"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyAnnotator
metadata:
  name: secret-detector
spec:
  description: Detects credentials in outbound content
  annotations:
    - name: secret_detected
      output: bool
      set_true_if: any
      rules:
        - field: body_text
          op: regex_match
          pattern: 'AKIA[0-9A-Z]{16}'
        - field: args.subject
          op: contains
          substring: password
    - name: content_class
      output: string
      set_value_from: first_match
      rules:
        - field: body_text
          op: contains
          substring: password
          value: credential
    - name: limit_value
      output: integer
      rules:
        - field: args.limit
          op: passthrough
";

    #[test]
    fn parses_policy_annotator_fixture() {
        let annotator =
            parse_policy_annotator(POLICY_ANNOTATOR.as_bytes()).expect("annotator must parse");
        assert_eq!(annotator.name, "secret-detector");
        assert_eq!(
            annotator.description,
            "Detects credentials in outbound content"
        );
        assert_eq!(annotator.annotations.len(), 3);

        let secret = &annotator.annotations[0];
        assert_eq!(secret.name, "secret_detected");
        assert_eq!(secret.output, apf_policy_eval::AnnotationOutput::Bool);
        assert_eq!(secret.set_true_if, apf_policy_eval::SetTrueIf::Any);
        assert_eq!(secret.rules.len(), 2);
        assert_eq!(
            secret.rules[0].op,
            apf_policy_eval::AnnotationOp::RegexMatch
        );
        assert_eq!(secret.rules[0].pattern.as_deref(), Some("AKIA[0-9A-Z]{16}"));
        assert_eq!(secret.rules[1].field, "args.subject");

        let class = &annotator.annotations[1];
        assert_eq!(class.output, apf_policy_eval::AnnotationOutput::String);
        assert_eq!(
            class.set_value_from,
            apf_policy_eval::SetValueFrom::FirstMatch
        );
        assert_eq!(class.rules[0].value.as_deref(), Some("credential"));

        let limit = &annotator.annotations[2];
        assert_eq!(limit.output, apf_policy_eval::AnnotationOutput::Integer);
        assert_eq!(
            limit.rules[0].op,
            apf_policy_eval::AnnotationOp::Passthrough
        );

        let doc = annotator.to_doc();
        assert_eq!(doc.name, "secret-detector");
        assert_eq!(doc.annotations, annotator.annotations);
    }

    #[test]
    fn rejects_threshold_from() {
        let yaml = r"
kind: PolicyAnnotator
metadata:
  name: dynamic
spec:
  annotations:
    - name: over_limit
      output: bool
      rules:
        - field: args.limit
          op: gte
          threshold_from: /limits/max
";
        let err = parse_policy_annotator(yaml.as_bytes()).expect_err("threshold_from must reject");
        assert_eq!(
            err.to_string(),
            "annotation 'over_limit': threshold_from is not supported (use a static threshold)"
        );
    }

    #[test]
    fn rejects_unknown_annotator_fields() {
        let yaml = POLICY_ANNOTATOR.replace("description:", "bogus_field: true\n  description:");
        let err = parse_policy_annotator(yaml.as_bytes()).expect_err("unknown field must reject");
        assert!(format!("{err}").contains("bogus_field"));

        let yaml = POLICY_ANNOTATOR.replace("op: contains", "op: contains\n          extra: x");
        let err =
            parse_policy_annotator(yaml.as_bytes()).expect_err("unknown rule field must reject");
        assert!(format!("{err}").contains("extra"));
    }

    #[test]
    fn rejects_unknown_annotator_enum_values() {
        let yaml = POLICY_ANNOTATOR.replace("output: bool", "output: float");
        assert!(parse_policy_annotator(yaml.as_bytes()).is_err());

        let yaml = POLICY_ANNOTATOR.replace("set_true_if: any", "set_true_if: none");
        assert!(parse_policy_annotator(yaml.as_bytes()).is_err());

        let yaml = POLICY_ANNOTATOR.replace("op: regex_match", "op: glob_match");
        assert!(parse_policy_annotator(yaml.as_bytes()).is_err());
    }

    const POLICY_EFFECT: &str = r"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyEffect
metadata:
  name: redact-body-and-audit
spec:
  description: Redact leaked secrets and audit
  verdict: warn
  reason: secret_in_body
  message: A secret pattern was detected in the request body
  body:
    replace: '[REDACTED]'
  headers:
    - name: X-APF-Event
      action: set
      source: context.annotations.secret_kind
  finding: secret-detected
";

    const POLICY_EFFECT_INLINE: &str = r"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyEffect
metadata:
  name: strip-stream
spec:
  body:
    patches:
      - op: remove
        path: /stream
      - op: replace
        path: /model
        value: small-model
  finding:
    type: model_downgrade
    label: forced
    severity: low
    confidence: 80
";

    #[test]
    fn parses_policy_effect_fixture() {
        let effect = parse_policy_effect(POLICY_EFFECT.as_bytes()).expect("effect must parse");
        let meta = effect.metadata.as_ref().expect("metadata present");
        assert_eq!(meta.name, "redact-body-and-audit");
        let spec = effect.spec.as_ref().expect("spec present");
        assert_eq!(spec.description, "Redact leaked secrets and audit");

        let doc = effect_to_doc(&effect);
        assert_eq!(doc.name, "redact-body-and-audit");
        assert_eq!(doc.verdict, apf_policy_eval::Verdict::Warn);
        assert_eq!(doc.reason.as_deref(), Some("secret_in_body"));
        assert!(doc.message.is_some());
        let body = doc.body.expect("body present");
        assert_eq!(body.replace.as_deref(), Some("[REDACTED]"));
        assert!(body.patches.is_empty());
        assert_eq!(doc.headers.len(), 1);
        assert_eq!(doc.headers[0].action, apf_policy_eval::HeaderAction::Set);
        assert_eq!(
            doc.headers[0].source.as_deref(),
            Some("context.annotations.secret_kind")
        );
        assert_eq!(
            doc.finding,
            Some(apf_policy_eval::FindingSpec::Reference(
                "secret-detected".to_string()
            ))
        );
    }

    #[test]
    fn parses_policy_effect_patches_and_inline_finding() {
        let effect =
            parse_policy_effect(POLICY_EFFECT_INLINE.as_bytes()).expect("effect must parse");
        let doc = effect_to_doc(&effect);
        // Verdict defaults to allow.
        assert_eq!(doc.verdict, apf_policy_eval::Verdict::Allow);
        let body = doc.body.expect("body present");
        assert!(body.replace.is_none());
        assert_eq!(body.patches.len(), 2);
        assert_eq!(body.patches[0].op, apf_policy_eval::PatchOp::Remove);
        assert_eq!(body.patches[0].path, "/stream");
        assert_eq!(body.patches[1].op, apf_policy_eval::PatchOp::Replace);
        assert_eq!(
            body.patches[1].value,
            Some(serde_json::Value::String("small-model".to_string()))
        );
        match doc.finding {
            Some(apf_policy_eval::FindingSpec::Inline(inline)) => {
                assert_eq!(inline.kind, "model_downgrade");
                assert_eq!(inline.label.as_deref(), Some("forced"));
                assert_eq!(inline.severity, apf_policy_eval::Severity::Low);
                assert_eq!(inline.confidence, Some(80));
                assert!(inline.label_source.is_none());
            }
            other => panic!("expected inline finding, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_policy_effect_fields_and_enums() {
        let yaml = POLICY_EFFECT.replace("description:", "bogus_field: true\n  description:");
        let err = parse_policy_effect(yaml.as_bytes()).expect_err("unknown field must reject");
        assert!(format!("{err}").contains("bogus_field"));

        let yaml = POLICY_EFFECT.replace("verdict: warn", "verdict: block");
        assert!(parse_policy_effect(yaml.as_bytes()).is_err());

        let yaml = POLICY_EFFECT.replace("action: set", "action: append");
        assert!(parse_policy_effect(yaml.as_bytes()).is_err());

        let yaml = POLICY_EFFECT_INLINE.replace("op: remove", "op: move");
        assert!(parse_policy_effect(yaml.as_bytes()).is_err());
    }

    const POLICY_FINDING: &str = r"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyFinding
metadata:
  name: secret-detected
spec:
  description: Credential material observed in outbound content
  type: secret_detected
  severity: critical
  label_source: context.annotations.secret_kind
";

    #[test]
    fn parses_policy_finding_fixture() {
        let finding = parse_policy_finding(POLICY_FINDING.as_bytes()).expect("finding must parse");
        let meta = finding.metadata.as_ref().expect("metadata present");
        assert_eq!(meta.name, "secret-detected");
        let doc = finding_to_doc(&finding);
        assert_eq!(doc.name, "secret-detected");
        assert_eq!(doc.kind, "secret_detected");
        assert_eq!(doc.severity, apf_policy_eval::Severity::Critical);
        assert!(doc.label.is_none());
        assert_eq!(
            doc.label_source.as_deref(),
            Some("context.annotations.secret_kind")
        );
    }

    #[test]
    fn rejects_unknown_policy_finding_fields_and_enums() {
        let yaml = POLICY_FINDING.replace("description:", "bogus_field: true\n  description:");
        let err = parse_policy_finding(yaml.as_bytes()).expect_err("unknown field must reject");
        assert!(format!("{err}").contains("bogus_field"));

        let yaml = POLICY_FINDING.replace("severity: critical", "severity: fatal");
        assert!(parse_policy_finding(yaml.as_bytes()).is_err());
    }

    #[test]
    fn name_falls_back_to_map_key() {
        let yaml =
            "spec:\n  network_policies:\n    github:\n      endpoints: []\n      binaries: []\n";
        let ir = parse(yaml.as_bytes()).expect("parse");
        let spec = ir.spec.unwrap();
        let rule = spec.network_policies.get("github").expect("github rule");
        assert_eq!(rule.name, "github");
    }
}
