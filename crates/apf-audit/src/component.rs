// SPDX-License-Identifier: Apache-2.0
//! Per-component JSONL emitter: the scaffolding every producer repeats.
//!
//! Producers own their event vocabulary. This owns the file, the envelope and
//! the enabled/disabled branch, so a fix here reaches all of them rather than
//! one.

use std::path::Path;
use std::sync::Arc;

use crate::emitter::{AuditEmitter, EmitOutcome, JsonlSink};
use crate::model::{AuditEvent, CommonFields, Component, generate_correlation_id};

/// Who is writing, and under what trust.
///
/// Const rather than owned strings: these name the deployment topology, so a
/// value computed at runtime is a sign the wrong thing is being recorded.
#[derive(Clone, Copy, Debug)]
pub struct AuditIdentity {
    /// `component.name`, and the audit filename stem.
    pub component_name: &'static str,
    /// `<emitting-process>:<seam>`.
    pub enforcement_point_id: &'static str,
    /// The substrate this component governs, or `none` if it governs nothing.
    pub runtime_substrate: &'static str,
    /// The signing identity whose bundles this component trusts.
    pub trust_root_id: &'static str,
    /// Producer version, normally `env!("CARGO_PKG_VERSION")`.
    pub version: &'static str,
}

/// JSONL emitter for one component. `disabled()` drops every event.
#[derive(Clone, Default)]
pub struct ComponentAudit {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    emitter: AuditEmitter<JsonlSink>,
    component: Component,
    identity: AuditIdentity,
}

impl ComponentAudit {
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Open `<dir>/<component_name>-audit.jsonl` now, so an unusable directory
    /// fails at startup rather than at the first event.
    ///
    /// One file per component: components may move to their own processes
    /// later, and a shared file would make that split a log-path migration.
    ///
    /// # Errors
    ///
    /// Returns the sink error when the file cannot be opened for appending.
    pub fn to_jsonl_in(dir: impl AsRef<Path>, identity: AuditIdentity) -> Result<Self, String> {
        let stem = identity.component_name;
        let sink = JsonlSink::new(dir.as_ref().join(format!("{stem}-audit.jsonl")));
        sink.preflight().map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Some(Arc::new(Inner {
                emitter: AuditEmitter::new(sink),
                component: Component::new(stem, identity.version, identity.enforcement_point_id),
                identity,
            })),
        })
    }

    /// Shared envelope fields. `None` when disabled, so a producer can skip
    /// building the event at all.
    ///
    /// `digest` is used verbatim. Producers on a fail-closed path want an
    /// invalid one to fail the record; producers on a best-effort path should
    /// coerce it themselves and use a sentinel in their fallback.
    #[must_use]
    pub fn common(&self, digest: &str, revision: Option<u64>) -> Option<CommonFields> {
        let inner = self.inner.as_ref()?;
        let mut common = CommonFields::new_without_subject(
            generate_correlation_id(),
            inner.identity.enforcement_point_id,
            inner.identity.runtime_substrate,
            inner.component.clone(),
            digest,
            inner.identity.trust_root_id,
        );
        common.policy_revision = revision;
        Some(common)
    }

    /// Fail-closed: the caller must halt rather than continue unrecorded.
    ///
    /// # Errors
    ///
    /// Returns the emission error.
    pub fn emit_required(&self, event: &AuditEvent) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        inner
            .emitter
            .emit_required(event)
            .map_err(|e| e.to_string())
    }

    /// Best-effort: the caller logs and continues.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_best_effort(&self, event: &AuditEvent) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        match inner.emitter.emit_best_effort(event) {
            EmitOutcome::Written => Ok(()),
            EmitOutcome::Failed(error) => Err(error),
        }
    }
}
