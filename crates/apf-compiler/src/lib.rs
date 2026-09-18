// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Bundle compilation pipeline: frontend → passes → projectors.
//!
//! `Compiler` receives projector implementations at construction time. The
//! frontend and pass pipeline are substrate-agnostic; each `Projector` impl
//! lowers the `CanonicalPolicy` IR to one substrate's native surfaces.
//! Adding a new substrate means implementing `Projector` and passing it to
//! `Compiler::new` — no changes here.

use std::collections::BTreeSet;
use std::path::Path;

use apf_bundle::{Bundle, BundleMembers};
use apf_proto::ir;
use apf_proto::{PolicySet, ProviderProfileSet};
use prost::Message as _;

pub mod backend;
pub mod envelope;
pub mod frontend;
pub mod pass;
pub mod provider;

pub use backend::{CanonicalPolicy, ProjectError, Projector};
use frontend::FrontendError;
use pass::{PassError, PassPipeline};

/// One lowered surface from a single projector.
#[derive(Debug)]
pub struct CompiledSurface {
    pub kind: String,
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Output of a successful compilation run.
#[derive(Debug, Default)]
pub struct CompiledBundle {
    pub surfaces: Vec<CompiledSurface>,
    pub policy_rule_docs: Vec<apf_policy_eval::PolicyRuleDoc>,
    pub policy_annotators: Vec<frontend::PolicyAnnotator>,
    pub policy_effects: Vec<ir::PolicyEffect>,
    pub policy_findings: Vec<ir::PolicyFinding>,
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bundle parse: {0}")]
    Bundle(#[from] apf_bundle::BundleParseError),
    #[error("frontend: {0}")]
    Frontend(#[from] FrontendError),
    #[error("pass: {0}")]
    Pass(#[from] PassError),
    #[error("projector: {0}")]
    Project(#[from] ProjectError),
    #[error("surface allow-list rejects all projector output for bundle")]
    NoSurfaces,
}

/// The compilation pipeline.
pub struct Compiler {
    passes: PassPipeline,
    projectors: Vec<Box<dyn Projector>>,
}

impl Compiler {
    /// Build a compiler with the given projector implementations. The service
    /// binary registers `OpenShellProjector`; the `apf-compile` CLI may
    /// register a different set.
    pub fn new(projectors: Vec<Box<dyn Projector>>) -> Self {
        Self {
            passes: PassPipeline::default(),
            projectors,
        }
    }

    /// Read and compile `bundle_path`. No signature verification — callers
    /// that need it (e.g. the `apf-compile` CLI) must verify via `apf-bundle`
    /// before calling this.
    pub fn compile_file(&self, bundle_path: &Path) -> Result<CompiledBundle, CompileError> {
        let bytes = std::fs::read(bundle_path)?;
        let bundle = Bundle::from_payload_bytes(&bytes)?;
        let members = bundle
            .load_members(bundle_path.parent().unwrap_or_else(|| Path::new(".")))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.lower_members(&members, None)
    }

    /// Lower already-loaded `BundleMembers` to compiled surfaces.
    /// `allowed_surfaces` filters output; `None` passes everything through.
    pub fn lower_members(
        &self,
        members: &BundleMembers,
        allowed_surfaces: Option<&BTreeSet<String>>,
    ) -> Result<CompiledBundle, CompileError> {
        let policy_rules = compile_policy_rule_docs(members)?;
        let policy_annotators = frontend::parse_policy_annotators(members)?;
        let policy_effects = frontend::parse_policy_effects(members)?;
        let policy_findings = frontend::parse_policy_findings(members)?;

        let mut canonical = frontend::build_canonical_policy(members)?;
        for policy in canonical.sandbox_policies.values_mut() {
            self.passes.run(policy)?;
        }

        let mut surfaces: Vec<CompiledSurface> = Vec::new();

        // Emit apf.policy.v1/{bundle_id} — all Cedar policy inputs in one atomic fetch.
        // Feeds the Cedar evaluator on the policy-gateway with a consistent snapshot.
        let policy_set = PolicySet {
            rules: members
                .policy_rules
                .iter()
                .filter_map(|(_, bytes)| frontend::parse_policy_rule(bytes).ok())
                .collect(),
            annotators: policy_annotators
                .iter()
                .map(|a| ir::PolicyAnnotator {
                    metadata: Some(ir::ObjectMeta {
                        name: a.name.clone(),
                        description: a.description.clone(),
                        ..Default::default()
                    }),
                    spec: Some(ir::PolicyAnnotatorSpec {
                        description: a.description.clone(),
                        annotations: a.annotations.iter().map(annotation_spec_to_ir).collect(),
                    }),
                })
                .collect(),
            effects: policy_effects.clone(),
            findings: policy_findings.clone(),
        };
        let policy_set_kind = "apf.policy.v1".to_string();
        if allowed_surfaces.is_none_or(|s| s.contains(&policy_set_kind)) {
            surfaces.push(CompiledSurface {
                kind: policy_set_kind,
                name: "default".to_string(),
                bytes: policy_set.encode_to_vec(),
            });
        }

        // Emit openshell.provider-profile.v1/default — all provider profiles in
        // one atomic fetch for the reconciler.
        let profile_set_kind = "openshell.provider-profile.v1".to_string();
        if allowed_surfaces.is_none_or(|s| s.contains(&profile_set_kind)) {
            let provider_profile_set = ProviderProfileSet {
                profiles: members.provider_profiles.values().cloned().collect(),
            };
            surfaces.push(CompiledSurface {
                kind: profile_set_kind,
                name: "default".to_string(),
                bytes: provider_profile_set.encode_to_vec(),
            });
        }

        for projector in &self.projectors {
            for surface in projector.project(&canonical)? {
                if allowed_surfaces.is_none_or(|s| s.contains(&surface.kind)) {
                    surfaces.push(surface);
                }
            }
        }

        Ok(CompiledBundle {
            surfaces,
            policy_rule_docs: policy_rules,
            policy_annotators,
            policy_effects,
            policy_findings,
        })
    }
}

/// Parse `PolicyRule` bundle members and compile to evaluator doc format.
pub fn compile_policy_rule_docs(
    members: &BundleMembers,
) -> Result<Vec<apf_policy_eval::PolicyRuleDoc>, CompileError> {
    let rules = frontend::parse_policy_rules(members)?;
    rules
        .iter()
        .map(frontend::parse_policy_rule_doc)
        .collect::<Result<_, _>>()
        .map_err(CompileError::Frontend)
}

/// Convert compiled surfaces to a `(surface_id, name) → bytes` map.
pub fn surfaces_to_projections(
    surfaces: Vec<CompiledSurface>,
) -> std::collections::BTreeMap<(String, String), Vec<u8>> {
    surfaces
        .into_iter()
        .map(|s| ((s.kind, s.name), s.bytes))
        .collect()
}

fn annotation_spec_to_ir(spec: &apf_policy_eval::AnnotationSpec) -> ir::AnnotationSpec {
    let output = match spec.output {
        apf_policy_eval::AnnotationOutput::Bool => ir::AnnotationOutput::Bool,
        apf_policy_eval::AnnotationOutput::String => ir::AnnotationOutput::String,
        apf_policy_eval::AnnotationOutput::Integer => ir::AnnotationOutput::Integer,
    } as i32;
    let set_true_if = match spec.set_true_if {
        apf_policy_eval::SetTrueIf::Any => ir::SetTrueIf::Any,
        apf_policy_eval::SetTrueIf::All => ir::SetTrueIf::All,
    } as i32;
    let set_value_from = match spec.set_value_from {
        apf_policy_eval::SetValueFrom::FirstMatch => ir::SetValueFrom::FirstMatch,
    } as i32;
    let rules = spec
        .rules
        .iter()
        .map(|r| {
            let op = match r.op {
                apf_policy_eval::AnnotationOp::RegexMatch => ir::AnnotationOp::RegexMatch,
                apf_policy_eval::AnnotationOp::Equals => ir::AnnotationOp::Equals,
                apf_policy_eval::AnnotationOp::EndsWith => ir::AnnotationOp::Endswith,
                apf_policy_eval::AnnotationOp::StartsWith => ir::AnnotationOp::Startswith,
                apf_policy_eval::AnnotationOp::Contains => ir::AnnotationOp::Contains,
                apf_policy_eval::AnnotationOp::Length => ir::AnnotationOp::Length,
                apf_policy_eval::AnnotationOp::Gte => ir::AnnotationOp::Gte,
                apf_policy_eval::AnnotationOp::Lte => ir::AnnotationOp::Lte,
                apf_policy_eval::AnnotationOp::Passthrough => ir::AnnotationOp::Passthrough,
            } as i32;
            ir::AnnotationRule {
                field: r.field.clone(),
                op,
                pattern: r.pattern.clone(),
                value: r.value.clone(),
                suffix: r.suffix.clone(),
                prefix: r.prefix.clone(),
                substring: r.substring.clone(),
                threshold: r.threshold,
            }
        })
        .collect();
    ir::AnnotationSpec {
        name: spec.name.clone(),
        output,
        set_true_if,
        set_value_from,
        rules,
    }
}
