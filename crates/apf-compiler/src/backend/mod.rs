// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Projector trait — one implementor per target substrate.
//!
//! A projector receives the aggregate `CanonicalPolicy` IR and lowers it to
//! the substrate's native surfaces. Adding a new substrate means implementing
//! this trait and registering it in `Compiler::new` — no changes to the
//! frontend, the pass pipeline, or any other projector.

use std::collections::BTreeMap;

use apf_proto::ir;

use super::CompiledSurface;

#[derive(Debug, thiserror::Error)]
#[error("projector '{target}' surface '{surface}': {cause}")]
pub struct ProjectError {
    pub target: String,
    pub surface: String,
    pub cause: String,
}

/// Aggregate IR for one bundle — the input every projector lowers from.
#[derive(Debug, Default)]
pub struct CanonicalPolicy {
    /// Compiled `SandboxPolicy` IR keyed by `metadata.name`.
    pub sandbox_policies: BTreeMap<String, ir::SandboxPolicy>,
    /// `network_middlewares` from each `SandboxPolicy`, carried out-of-band
    /// because `SandboxPolicySpec` does not yet have this field on BSR.
    pub sandbox_middleware:
        BTreeMap<String, BTreeMap<String, crate::frontend::NetworkMiddlewareConfigDef>>,
    /// Compiled `Provider` IR keyed by `metadata.name`.
    pub providers: BTreeMap<String, ir::Provider>,
    /// Raw `ProviderProfile` YAML bytes keyed by name (passthrough for native profiles).
    pub provider_profiles: BTreeMap<String, Vec<u8>>,
    /// Compiled `PolicyRule` documents in bundle order.
    pub policy_rules: Vec<ir::PolicyRule>,
    /// Compiled `PolicyAnnotator` documents in bundle order.
    pub policy_annotators: Vec<crate::frontend::PolicyAnnotator>,
    /// Compiled `PolicyEffect` documents in bundle order.
    pub policy_effects: Vec<ir::PolicyEffect>,
    /// Compiled `PolicyFinding` documents in bundle order.
    pub policy_findings: Vec<ir::PolicyFinding>,
}

/// A projector lowers `CanonicalPolicy` IR to one substrate's native surfaces.
pub trait Projector: Send + Sync {
    /// Stable substrate identifier, e.g. `"openshell"`.
    fn target(&self) -> &str;

    /// Project `p` to this substrate's native surfaces.
    fn project(&self, p: &CanonicalPolicy) -> Result<Vec<CompiledSurface>, ProjectError>;
}
