// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Policy lifecycle audit emission: bundle verification, load, hot-swap, rejection.
//!
//! Evaluation events belong to policy-gateway; this component never evaluates.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use apf_audit::host_qualified_instance_id;
use apf_audit::{
    AuditEmitter, AuditErrorInfo, AuditEvent, AuthenticationEvent, CommonFields, Component,
    JsonlSink, Outcome, PolicyActivationEvent, PolicyDistributionEvent, PolicyRefreshEvent,
    PolicyServiceStartupEvent, PolicyVerificationEvent, ProvenanceSigningEvent, Resource,
    SanitizationGuard, StartupContext, TypedAuditEvent, coerce_id as safe_id,
    coerce_lower_dotted as safe_lower_dotted, coerce_name as safe_name, generate_correlation_id,
    join_rejection_detail, normalize_rejection_reasons,
};

use crate::runtime::runtime_context::RuntimeContext;
use apf_bundle::{Bundle, VerifyOutcome};

/// Audit naming rule: `<emitting-process>:<seam>`.
const ENFORCEMENT_POINT_ID: &str = "apf-policy-service:local";

/// Also the audit filename stem. Seams get one file each — the interceptor and
/// middleware share a process today but may not later, and a shared file would
/// make that split a log-path migration.
const COMPONENT_NAME: &str = "apf-policy-service";

/// No substrate governs the PAP, and the envelope requires the field. Naming a
/// real substrate here would imply this process enforced something.
const RUNTIME_SUBSTRATE: &str = "none";

/// The PAP signs bundles rather than verifying them against a trust root.
const TRUST_ROOT_ID: &str = "apf-policy-service:signing";

/// Stands in for `bundle_digest` when no bundle governed the refusal — an
/// unserved-kind probe before the first load, or a variant that never fetched.
///
/// The envelope requires the field, and recording an authenticated caller as
/// an authentication failure to avoid it would assert something untrue about
/// the caller. Same reasoning as `RUNTIME_SUBSTRATE`: a sentinel that matches
/// no real bundle makes a downstream join return nothing rather than
/// something wrong.
const UNBUNDLED_DIGEST: &str = "none";

/// Marks a record whose policy identity is a sentinel rather than a real
/// bundle, so the two are never conflated. Not caller-influenced.
const NO_BUNDLE_REASON: &str = "no active bundle: recorded without policy identity";

/// Bundle identity fields attached to audit records for a policy lifecycle event.
#[derive(Debug, Clone, Default)]
pub struct BundleAuditMetadata {
    pub monotonic_counter: u64,
    pub digest_hex: String,
}

impl BundleAuditMetadata {
    pub fn from_counter_and_digest(counter: u64, digest: &str) -> Self {
        Self {
            monotonic_counter: counter,
            digest_hex: digest.to_string(),
        }
    }
}

/// Structured payload for a bundle-rejection audit record.
#[derive(Debug)]
pub struct PolicyRejectAudit {
    reason_code: String,
    message: String,
    retryable: bool,
    bundle_counter: Option<u64>,
    metadata_source: String,
}

impl PolicyRejectAudit {
    pub fn new(reason_code: &str, message: String) -> Self {
        Self {
            reason_code: reason_code.to_string(),
            message,
            retryable: false,
            bundle_counter: None,
            metadata_source: String::new(),
        }
    }

    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_bundle_counter(mut self, counter: Option<u64>) -> Self {
        self.bundle_counter = counter;
        self
    }

    pub fn with_metadata_source(mut self, source: &str) -> Self {
        self.metadata_source = source.to_string();
        self
    }
}

/// Audit emitter for policy lifecycle events. `disabled()` drops them.
#[derive(Clone, Default)]
pub struct PolicyServiceAudit {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    emitter: AuditEmitter<JsonlSink>,
    component: Component,
    /// Last `(digest, version)` recorded per `(kind, name)`. A refresh poll
    /// that returns the same document is a liveness check, not a distribution,
    /// and recording it as one both overstates it and buries the real events.
    vended: Mutex<HashMap<(String, String), (String, u64)>>,
}

impl PolicyServiceAudit {
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Build an emitter writing to `<dir>/apf-policy-service-audit.jsonl`,
    /// opening it now so a bad directory fails here rather than at the first
    /// bundle load.
    ///
    /// # Errors
    ///
    /// Returns the sink error when the file cannot be opened for appending.
    pub fn to_jsonl_in(dir: impl AsRef<Path>) -> Result<Self, String> {
        let sink = JsonlSink::new(dir.as_ref().join(format!("{COMPONENT_NAME}-audit.jsonl")));
        sink.preflight().map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Some(Arc::new(Inner {
                emitter: AuditEmitter::new(sink),
                component: Component::new(
                    COMPONENT_NAME,
                    env!("CARGO_PKG_VERSION"),
                    host_qualified_instance_id(ENFORCEMENT_POINT_ID),
                ),
                vended: Mutex::new(HashMap::new()),
            })),
        })
    }

    /// Envelope fields shared by every event this component writes.
    ///
    /// No subject identity: bundle lifecycle has no user or agent behind it.
    fn common(&self, inner: &Inner, ctx: &RuntimeContext, digest: &str) -> CommonFields {
        let correlation_id = ctx
            .correlation_id
            .clone()
            .unwrap_or_else(generate_correlation_id);
        CommonFields::new_without_subject(
            correlation_id,
            ENFORCEMENT_POINT_ID,
            RUNTIME_SUBSTRATE,
            inner.component.clone(),
            digest,
            TRUST_ROOT_ID,
        )
    }

    /// Fail-closed: the caller must halt rather than continue unrecorded.
    fn emit(&self, event: AuditEvent) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        inner
            .emitter
            .emit_required(&event)
            .map_err(|e| e.to_string())
    }

    /// Best-effort: the caller logs and continues.
    fn emit_best_effort(&self, event: AuditEvent) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        match inner.emitter.emit_best_effort(&event) {
            apf_audit::EmitOutcome::Written => Ok(()),
            apf_audit::EmitOutcome::Failed(error) => Err(error),
        }
    }

    /// Record the outcome of `verify_bundle`, pass or fail.
    ///
    /// # Errors
    ///
    /// Returns the emission error; the caller must halt.
    pub fn emit_verify_bundle(
        &self,
        ctx: &RuntimeContext,
        meta: &BundleAuditMetadata,
        outcome: &VerifyOutcome,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, ctx, &meta.digest_hex);

        if outcome.ok {
            let mut event =
                PolicyVerificationEvent::new(Outcome::Success, "policy.bundle_verified")
                    .into_audit_event(&common)
                    .map_err(|e| e.to_string())?;
            event.policy_revision = Some(meta.monotonic_counter);
            if let Some(bundle) = &outcome.bundle {
                event.bundle_id = Some(bundle.bundle_id.clone());
            }
            return self.emit(event);
        }

        let codes = normalize_rejection_reasons(&outcome.rejection_reasons);
        let reason_code = codes.first().map_or_else(
            || "policy.bundle_rejected.unspecified".to_owned(),
            |code| format!("policy.bundle_rejected.{code}"),
        );
        let mut event = PolicyVerificationEvent::new(Outcome::Refused, reason_code.clone())
            .with_error(AuditErrorInfo {
                code: reason_code,
                message: join_rejection_detail(&outcome.rejection_reasons),
                retryable: Some(false),
            })
            .with_rejection_reasons(codes)
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        // Every post-parse rejection — expiry, manifest mismatch, runtime
        // incompatibility, counter regression — carries the parsed bundle, so
        // the rejection can be joined to the bundle it concerns.
        if outcome.parsed {
            event.policy_revision = Some(meta.monotonic_counter);
            if let Some(bundle) = &outcome.bundle {
                event.bundle_id = Some(bundle.bundle_id.clone());
            }
        }
        self.emit(event)
    }

    /// Record that a verified bundle became the active policy.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log. Best-effort: the
    /// bundle is already in force, and its verification is recorded fail-closed.
    pub fn emit_policy_load(
        &self,
        bundle: &Bundle,
        meta: &BundleAuditMetadata,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, &RuntimeContext::default(), &meta.digest_hex);
        let mut event = PolicyActivationEvent::new(Outcome::Success, "policy.bundle_loaded")
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        event.policy_revision = Some(meta.monotonic_counter);
        event.bundle_id = Some(bundle.bundle_id.clone());
        self.emit(event)
    }

    /// Record that a bundle became the active policy, from its identity parts,
    /// for callers that never hold a parsed [`Bundle`].
    ///
    /// # Errors
    ///
    /// Returns the emission error; the caller must halt.
    pub fn emit_policy_load_parts(
        &self,
        digest: &str,
        counter: u64,
        bundle_id: &str,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, &RuntimeContext::default(), digest);
        let mut event = PolicyActivationEvent::new(Outcome::Success, "policy.bundle_loaded")
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        event.policy_revision = Some(counter);
        event.bundle_id = Some(bundle_id.to_owned());
        self.emit(event)
    }

    /// Record a hot-swap to a new revision.
    ///
    /// `counter_not_persisted` marks a swap that took effect while the durable
    /// counter lagged: the bundle is serving, so this is not a rejection.
    ///
    /// # Errors
    ///
    /// Returns the emission error. Callers recording the swap itself must undo
    /// it; callers recording `counter_not_persisted` log and continue, since
    /// the swap is already recorded.
    pub fn emit_policy_hot_swap(
        &self,
        digest: &str,
        counter: u64,
        bundle_id: Option<&str>,
        counter_not_persisted: bool,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, &RuntimeContext::default(), digest);
        let reason_code = if counter_not_persisted {
            "policy.bundle_hot_swapped.counter_not_persisted"
        } else {
            "policy.bundle_hot_swapped"
        };
        let mut event = PolicyActivationEvent::new(Outcome::Success, reason_code)
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        event.policy_revision = Some(counter);
        event.bundle_id = bundle_id.map(str::to_owned);
        self.emit(event)
    }

    /// Record the security posture this process resolved at startup.
    ///
    /// Emitted on every boot that reaches policy load, healthy or not, so a
    /// positive record always exists for a process that goes on to serve.
    /// `weakened` names each control that is not active, most severe first.
    ///
    /// # Errors
    ///
    /// Returns the emission error. The caller must abort startup: a serving
    /// process whose posture was not recorded is the ambiguity this event
    /// exists to remove, so absence must mean the process never served.
    pub fn emit_service_startup(&self, weakened: &[(&str, String)]) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let ctx = StartupContext::new(
            generate_correlation_id(),
            ENFORCEMENT_POINT_ID,
            RUNTIME_SUBSTRATE,
            inner.component.clone(),
        )
        .map_err(|e| e.to_string())?;

        let event = match weakened.split_first() {
            None => PolicyServiceStartupEvent::secure(),
            Some(((primary, _), _)) => {
                let detail: Vec<String> = weakened
                    .iter()
                    .map(|(code, message)| format!("{code}: {message}"))
                    .collect();
                PolicyServiceStartupEvent::degraded(
                    *primary,
                    AuditErrorInfo {
                        code: (*primary).to_owned(),
                        message: join_rejection_detail(&detail),
                        retryable: Some(false),
                    },
                )
            }
        };
        let event = event.into_audit_event(&ctx).map_err(|e| e.to_string())?;
        self.emit_best_effort(event)
    }

    /// Record a caller refused on identity grounds, before any policy was
    /// consulted. Distinct from a policy denial: no bundle decided this, and
    /// `AuthenticationEvent` clears the policy and subject identity the context
    /// carries, so a rejected credential cannot name a principal.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log. Best-effort: the
    /// request is already refused, and failing to record that must not turn a
    /// rejected probe into a served one.
    pub fn emit_auth_deny(&self, reason_code: &str, message: String) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, &RuntimeContext::default(), "");
        let event = AuthenticationEvent::unauthenticated(
            reason_code,
            AuditErrorInfo {
                code: reason_code.to_owned(),
                // Capped: callers on this path handle request-derived text.
                message: join_rejection_detail(&[message]),
                retryable: Some(false),
            },
        )
        .into_audit_event(&common)
        .map_err(|e| e.to_string())?;
        self.emit_best_effort(event)
    }

    /// Record a policy document served to a caller — the evidence of which
    /// bundle reached which consumer.
    ///
    /// Emitted from both serving surfaces: the gRPC socket gateways poll, and
    /// the optional HTTP surface.
    ///
    /// Records a document the first time it is served and whenever its digest
    /// or version changes. An unchanged re-poll writes nothing: gateways poll
    /// on a timer, so recording every one produced thousands of byte-identical
    /// records a day that named no caller and evidenced no distribution.
    ///
    /// Best-effort by design. Refusing to serve policy because a log line did
    /// not write would take the fleet down over a full disk. Unlike a bundle
    /// load, the record is distribution evidence rather than a security
    /// property.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_document_vended(
        &self,
        digest: &str,
        kind: &str,
        name: &str,
        version: u64,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        // Same sentinel as the denial and refresh paths: an empty digest here
        // would otherwise fail the primary and the fallback identically, since
        // both rebuild the same `common`, and a vend that happened is evidence
        // whether or not its bundle can be named.
        let unbundled = digest.is_empty();
        let digest = if unbundled { UNBUNDLED_DIGEST } else { digest };

        // Keyed on the raw kind/name, before coercion: two documents whose
        // names coerce alike are still distinct documents.
        let key = (kind.to_owned(), name.to_owned());
        let current = (digest.to_owned(), version);
        // A poisoned lock is recovered rather than propagated: the guarded
        // region only touches owned strings, so there is nothing to corrupt.
        let already_recorded = |inner: &Inner| {
            let vended = match inner.vended.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            vended.get(&key) == Some(&current)
        };
        // Held only for the lookup, never across the write.
        if already_recorded(inner) {
            return Ok(());
        }
        let vend = |kind: &str, name: &str| {
            PolicyDistributionEvent::new(
                Resource::new(kind.to_owned(), name.to_owned()),
                "policy.get_document",
                Outcome::Success,
                "policy.document_vended",
            )
            .into_audit_event(&self.common(inner, &RuntimeContext::default(), digest))
            .ok()
            .map(|mut event| {
                event.policy_revision = Some(version);
                event
            })
            .filter(|event| SanitizationGuard::new().check(event).is_ok())
        };

        // Same protection as the denial path: a document whose own name the
        // record cannot carry would otherwise vanish from the distribution
        // evidence entirely, every time it is served.
        // Recorded only once the write succeeded. Marking it first would turn
        // a transient failure — a full disk, the very thing this suppression
        // protects — into permanent loss of that bundle's distribution record,
        // since no later poll would try again.
        let remember = |inner: &Inner| {
            let mut vended = match inner.vended.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            vended.insert(key.clone(), current.clone());
        };

        if let Some(mut event) = vend(&safe_name(kind), &safe_id(name)) {
            if unbundled {
                event.reason = Some(NO_BUNDLE_REASON.to_owned());
            }
            let outcome = self.emit_best_effort(event);
            if outcome.is_ok() {
                remember(inner);
            }
            return outcome;
        }
        let Some(mut fallback) = vend("unspecified", "unspecified") else {
            return Err("vend record could not be constructed".to_owned());
        };
        fallback.reason = Some(if unbundled {
            format!("{NO_BUNDLE_REASON}; document kind and name omitted")
        } else {
            "document kind and name omitted".to_owned()
        });
        let outcome = self.emit_best_effort(fallback);
        if outcome.is_ok() {
            remember(inner);
        }
        outcome
    }

    /// Record a document request refused by this surface — unknown kind or
    /// name. A policy denial rather than an identity one: the caller is
    /// authenticated, the document simply is not served here.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_document_denied(
        &self,
        digest: &str,
        reason_code: &str,
        kind: &str,
        name: &str,
        verb: &str,
        message: String,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        // A refused distribution whether or not a bundle is loaded: the caller
        // authenticated and this surface would not serve them the document.
        let unbundled = digest.is_empty();
        let digest = if unbundled { UNBUNDLED_DIGEST } else { digest };
        let reason_code = &safe_lower_dotted(reason_code);
        let verb = &safe_lower_dotted(verb);
        let common = self.common(inner, &RuntimeContext::default(), digest);
        let event = PolicyDistributionEvent::new(
            Resource::new(safe_name(kind), safe_id(name)),
            verb,
            Outcome::Refused,
            reason_code,
        )
        .with_error(AuditErrorInfo {
            code: reason_code.to_owned(),
            // Free text, but capped: the raw request reaches it.
            message: join_rejection_detail(&[message]),
            retryable: Some(false),
        })
        .into_audit_event(&common)
        .ok()
        // Decided before writing, not by retrying after: the emitter collapses
        // validation, sanitization and I/O into one error, so a retry would
        // also fire on a failed write — leaving a truncated line plus a second
        // record for one refusal.
        //
        // Construction is part of the decision: `into_audit_event` validates,
        // so a schema-invalid record fails here and must fall through to the
        // fallback rather than return, or the hostile input has erased the
        // record after all. Sanitization is the emitter's other pre-write
        // check; `SanitizationGuard` is a unit struct, so this is provably the
        // same guard the emitter holds.
        .filter(|event| SanitizationGuard::new().check(event).is_ok());

        if let Some(mut event) = event {
            if unbundled {
                event.reason = Some(NO_BUNDLE_REASON.to_owned());
            }
            return self.emit_best_effort(event);
        }

        // Both segments are caller-controlled, so both are dropped: a hostile
        // KIND would otherwise fail exactly as the name did, leaving no record
        // at all. A bad path costs the path, never the record.
        //
        // The sentinels are forgeable — any schema-valid string is reachable
        // through coercion — so `reason` marks the record instead. That field
        // is not caller-influenced.
        let common = self.common(inner, &RuntimeContext::default(), digest);
        let mut fallback = PolicyDistributionEvent::new(
            Resource::new("unspecified", "unspecified"),
            verb,
            Outcome::Refused,
            reason_code,
        )
        .with_error(AuditErrorInfo {
            code: reason_code.to_owned(),
            message: "caller-supplied kind and name omitted: not safely recordable".to_owned(),
            retryable: Some(false),
        })
        .into_audit_event(&common)
        .map_err(|e| e.to_string())?;
        fallback.reason = Some(if unbundled {
            format!("{NO_BUNDLE_REASON}; caller-supplied resource omitted")
        } else {
            "caller-supplied resource omitted".to_owned()
        });
        self.emit_best_effort(fallback)
    }

    /// Record an operator-triggered refresh. The outcome is carried by the
    /// hot-swap record the refresh itself emits, so this names only the action
    /// and the policy in force when it was requested.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_refresh_triggered(&self, digest: &str) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let unbundled = digest.is_empty();
        let digest = if unbundled { UNBUNDLED_DIGEST } else { digest };
        let common = self.common(inner, &RuntimeContext::default(), digest);
        let event = PolicyRefreshEvent::new(Outcome::Success, "policy.refresh_triggered")
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        let mut event = event;
        if unbundled {
            event.reason = Some(NO_BUNDLE_REASON.to_owned());
        }
        self.emit_best_effort(event)
    }

    /// Record a provenance token that could not be minted. The document is
    /// still vended, unsigned, so the consumer cannot verify it came from here.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_provenance_mint_failed(
        &self,
        digest: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(
            inner,
            &RuntimeContext::default(),
            if digest.is_empty() {
                UNBUNDLED_DIGEST
            } else {
                digest
            },
        );
        let reason_code = "policy.provenance_mint_failed";
        let event = ProvenanceSigningEvent::new(Outcome::Failure, reason_code)
            .with_error(AuditErrorInfo {
                code: reason_code.to_owned(),
                message: join_rejection_detail(&[format!(
                    "provenance JWT could not be minted for {}/{}",
                    safe_name(kind),
                    safe_id(name)
                )]),
                retryable: Some(false),
            })
            // The caller vends the document anyway; this record is the only
            // evidence that what went out was unsigned.
            .served_unsigned()
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        self.emit_best_effort(event)
    }

    /// Record a bundle that compiled to nothing. It loaded and verified, so
    /// this is not a rejection — but no policy is being projected from it, and
    /// only this record distinguishes that from a bundle that is enforcing.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_no_projections(
        &self,
        digest: &str,
        counter: u64,
        bundle_id: &str,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, &RuntimeContext::default(), digest);
        let mut event = PolicyActivationEvent::new(Outcome::Success, "policy.no_projections")
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        event.policy_revision = Some(counter);
        event.bundle_id = Some(bundle_id.to_owned());
        self.emit_best_effort(event)
    }

    /// Record a bundle refused from force — a counter-persist failure or a
    /// failed hot-swap. Best-effort: the load is already failing, and a lost
    /// record must not change that outcome.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_policy_reject(
        &self,
        ctx: &RuntimeContext,
        digest: &str,
        reject: PolicyRejectAudit,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, ctx, digest);
        let mut event = PolicyActivationEvent::new(Outcome::Refused, reject.reason_code.clone())
            .with_error(AuditErrorInfo {
                code: reject.reason_code,
                message: reject.message,
                retryable: Some(reject.retryable),
            })
            .into_audit_event(&common)
            .map_err(|e| e.to_string())?;
        event.policy_revision = reject.bundle_counter;
        if !reject.metadata_source.is_empty() {
            event.reason = Some(reject.metadata_source);
        }
        self.emit_best_effort(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Components share one audit directory and are told apart by filename, so
    /// the derived name is a deployment contract, not an implementation detail.
    #[test]
    fn events_land_in_a_file_named_for_the_component() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");

        let digest = "a".repeat(64);
        audit
            .emit_policy_load_parts(&digest, 7, "acme-baseline")
            .expect("emit");

        let expected = dir.path().join("apf-policy-service-audit.jsonl");
        let written = std::fs::read_to_string(&expected).expect("audit file at derived path");
        assert!(written.contains(&digest), "event not written: {written}");

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("apf-policy-service-audit.jsonl")]
        );
    }

    /// Returns the written line, having first re-parsed and re-validated it —
    /// schema validation is what gates emission, so asserting only on the JSON
    /// text would pass on a record the schema rejects.
    fn posture_record(weakened: &[(&str, String)]) -> String {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        audit.emit_service_startup(weakened).expect("emit");
        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("read");
        let parsed: AuditEvent =
            serde_json::from_str(written.trim()).expect("record deserializes as an audit event");
        parsed
            .validate()
            .expect("record validates against the schema");
        written
    }

    /// A refusal raised before any bundle loaded still leaves a record. The
    /// interesting refusal — an unserved kind probed during the startup window,
    /// or a variant that never fetched — is exactly the one with no digest to
    /// name, and the envelope requires one. Losing it would be a silent gap.
    #[test]
    fn a_refusal_without_a_bundle_is_still_recorded() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");

        audit
            .emit_document_denied(
                "",
                "policy.document_request_invalid",
                "openshell.sandbox.v1",
                "-",
                "policy.list_documents",
                "kind is not served by this instance".to_owned(),
            )
            .expect("a refusal without a bundle must still be recorded");

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("read");
        let parsed: AuditEvent = serde_json::from_str(written.trim()).expect("deserializes");
        parsed.validate().expect("validates against the schema");
        // A refused distribution, not an auth failure: the caller
        // authenticated and this surface would not serve them the document.
        assert_eq!(parsed.event_type, apf_audit::EventType::PolicyDistribution);
        assert_eq!(parsed.outcome, Some(apf_audit::Outcome::Refused));
        assert_eq!(parsed.verb.as_deref(), Some("policy.list_documents"));
        assert_eq!(
            parsed.bundle_digest.as_deref(),
            Some(UNBUNDLED_DIGEST),
            "the sentinel must be distinguishable from a real digest"
        );
        assert_eq!(
            parsed.reason.as_deref(),
            Some(NO_BUNDLE_REASON),
            "the record must say why it names no bundle"
        );
        let resource = parsed.resource.expect("the refused resource is recorded");
        assert_eq!(resource.resource_type, "openshell.sandbox.v1");
    }

    /// Hostile input on the no-bundle path costs the path, never the record —
    /// the same guarantee the digest-bearing path makes.
    #[test]
    fn a_hostile_resource_cannot_suppress_an_unbundled_refusal() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");

        // The credential-shaped name is the entry that matters: coercion
        // rescues the others, so without it the fallback branch — the whole
        // reason this path has two attempts — is never exercised.
        for hostile in [
            "sk-abcdefghijklmnopqrstuvwx",
            "../../etc/shadow",
            "clé_secrète",
            "!!!",
            "",
            &"x".repeat(2000),
        ] {
            audit
                .emit_document_denied(
                    "",
                    "policy.document_not_found",
                    hostile,
                    hostile,
                    "policy.get_document",
                    format!("document '{hostile}' not found"),
                )
                .unwrap_or_else(|e| panic!("emit failed for {hostile:?}: {e}"));
        }

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("read");
        assert_eq!(written.lines().count(), 6, "{written}");
        let mut fell_back = 0;
        for line in written.lines() {
            let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
            parsed.validate().expect("validates against the schema");
            assert_eq!(parsed.event_type, apf_audit::EventType::PolicyDistribution);
            assert_eq!(parsed.outcome, Some(apf_audit::Outcome::Refused));
            let reason = parsed.reason.as_deref().unwrap_or_default();
            assert!(
                reason.starts_with(NO_BUNDLE_REASON),
                "every record must still name the missing bundle: {reason}"
            );
            if reason.ends_with("caller-supplied resource omitted") {
                fell_back += 1;
            }
        }
        // Distinguishes coercion from erasure: without this the test would pass
        // even if every record had degraded to the fallback.
        assert_eq!(
            fell_back, 1,
            "only the credential-shaped name should reach the fallback: {written}"
        );
    }

    /// Gateways poll on a timer. Recording every unchanged answer produced
    /// thousands of byte-identical records a day, burying the real events and
    /// risking the disk that fail-closed writes depend on.
    #[test]
    fn an_unchanged_re_poll_writes_nothing() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let digest = "c".repeat(64);

        for _ in 0..50 {
            audit
                .emit_document_vended(&digest, "openshell.sandbox.v1", "default", 1)
                .expect("vended");
        }

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("audit file");
        assert_eq!(
            written.lines().count(),
            1,
            "first vend records, the other 49 are liveness checks: {written}"
        );
    }

    /// Suppression must not cost a real distribution. A new digest, a new
    /// version, or a different document each mean policy actually moved.
    #[test]
    fn a_changed_document_still_records() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let v1 = "d".repeat(64);
        let v2 = "e".repeat(64);

        audit
            .emit_document_vended(&v1, "openshell.sandbox.v1", "default", 1)
            .expect("first vend");
        audit
            .emit_document_vended(&v1, "openshell.sandbox.v1", "default", 1)
            .expect("unchanged");
        // Hot-swap: the whole point of auditing distribution.
        audit
            .emit_document_vended(&v2, "openshell.sandbox.v1", "default", 2)
            .expect("new digest");
        // Same digest, new projection version.
        audit
            .emit_document_vended(&v2, "openshell.sandbox.v1", "default", 3)
            .expect("new version");
        // A different document is tracked separately, not shadowed.
        audit
            .emit_document_vended(&v2, "openshell.provider-profile.v1", "slack", 3)
            .expect("other document");
        // Back to the first digest — a rollback is a distribution too.
        audit
            .emit_document_vended(&v1, "openshell.sandbox.v1", "default", 1)
            .expect("rollback");

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("audit file");
        assert_eq!(
            written.lines().count(),
            5,
            "only the repeat is dropped: {written}"
        );
    }

    /// Two documents from one bundle share a digest and version exactly, so
    /// only `kind` separates them. Without it in the key they mask each other
    /// permanently — one is served for the life of the process unrecorded.
    #[test]
    fn documents_differing_only_by_kind_are_tracked_apart() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let digest = "f".repeat(64);

        audit
            .emit_document_vended(&digest, "openshell.sandbox.v1", "default", 1)
            .expect("sandbox doc");
        audit
            .emit_document_vended(&digest, "openshell.provider-profile.v1", "default", 1)
            .expect("profile doc, same name and version");

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("audit file");
        assert_eq!(
            written.lines().count(),
            2,
            "same name, different kind: both are distributions: {written}"
        );
    }

    /// One bundle serves many documents of the same kind — the demo bundle has
    /// six provider profiles — all sharing a digest and version. Without `name`
    /// in the key the first one served masks the rest permanently.
    #[test]
    fn documents_differing_only_by_name_are_tracked_apart() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let digest = "9".repeat(64);

        for name in ["slack", "github", "anthropic"] {
            audit
                .emit_document_vended(&digest, "openshell.provider-profile.v1", name, 1)
                .expect("profile vended");
        }

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("audit file");
        assert_eq!(
            written.lines().count(),
            3,
            "same kind, digest and version: each name is its own document: {written}"
        );
    }

    /// A hot-swap can carry a new bundle at the same projection version, so the
    /// digest has to discriminate on its own.
    #[test]
    fn a_digest_change_alone_still_records() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");

        audit
            .emit_document_vended(&"1".repeat(64), "openshell.sandbox.v1", "default", 4)
            .expect("first bundle");
        audit
            .emit_document_vended(&"2".repeat(64), "openshell.sandbox.v1", "default", 4)
            .expect("new bundle, same version");

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("audit file");
        assert_eq!(
            written.lines().count(),
            2,
            "the digest alone must discriminate: {written}"
        );
    }

    /// The serving surfaces emit shapes this component had never written
    /// before — distribution, refresh, authentication, provenance. Each must
    /// survive schema validation, which is what gates emission.
    #[test]
    fn every_serving_event_validates() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let digest = "b".repeat(64);

        audit
            .emit_document_vended(&digest, "openshell.sandbox.v1", "default", 7)
            .expect("vended");
        audit
            .emit_document_denied(
                &digest,
                "policy.document_not_found",
                "openshell.sandbox.v1",
                "missing",
                "policy.get_document",
                "not found".to_owned(),
            )
            .expect("denied");
        audit
            .emit_refresh_triggered(&digest)
            .expect("refresh triggered");
        audit
            .emit_provenance_mint_failed(&digest, "openshell.sandbox.v1", "default")
            .expect("mint failed");
        audit
            .emit_auth_deny("auth.http_bearer_invalid", "bad token".to_owned())
            .expect("auth deny");

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("read");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 5, "one record per emit: {written}");
        for line in lines {
            let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
            parsed.validate().unwrap_or_else(|e| panic!("{line}: {e}"));
        }

        // The identity refusal must not name a policy: no bundle decided it.
        let auth_deny: AuditEvent =
            serde_json::from_str(written.lines().next_back().expect("last")).expect("parse");
        assert!(auth_deny.bundle_digest.is_none(), "{written}");
        assert!(auth_deny.user_id.is_none(), "{written}");
    }

    /// A caller must not be able to suppress the record of their own refusal
    /// by requesting a name the schema would reject.
    #[test]
    fn a_hostile_document_name_still_produces_a_valid_denial() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let digest = "c".repeat(64);

        // Both segments, since a hostile KIND failed the retry exactly as a
        // hostile name did — leaving no record at all.
        for hostile in [
            "sk-abcdefghijklmnopqrstuvwx",
            "../../etc/passwd",
            "name with spaces",
            "clé_secrète",
            "!!!",
            "",
            &"x".repeat(2000),
        ] {
            audit
                .emit_document_denied(
                    &digest,
                    "policy.document_not_found",
                    hostile,
                    hostile,
                    "policy.get_document",
                    format!("document '{hostile}' not found"),
                )
                .unwrap_or_else(|e| panic!("emit failed for {hostile:?}: {e}"));
        }

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("read");
        assert_eq!(written.lines().count(), 7, "{written}");
        for line in written.lines() {
            let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
            parsed.validate().unwrap_or_else(|e| panic!("{line}: {e}"));
        }
    }

    /// Coercion satisfies the schema, but the sanitizer independently rejects
    /// credential-shaped strings — so a caller could still suppress their own
    /// denial by naming a document that looks like a secret.
    #[test]
    fn a_credential_shaped_document_name_still_produces_a_denial() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let digest = "d".repeat(64);
        let hostile = "sk-abcdefghijklmnop";

        audit
            .emit_document_denied(
                &digest,
                "policy.document_not_found",
                "openshell.sandbox.v1",
                hostile,
                "policy.get_document",
                format!("document '{hostile}' not found"),
            )
            .expect("a denial is recorded even when the name cannot be");

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("read");
        assert_eq!(written.lines().count(), 1, "{written}");
        assert!(
            !written.contains(hostile),
            "the caller value must not reach the record: {written}"
        );
        assert!(
            written.contains("caller-supplied resource omitted"),
            "the fallback must mark itself in a field the caller cannot set: {written}"
        );
        let parsed: AuditEvent = serde_json::from_str(written.trim()).expect("deserializes");
        parsed.validate().expect("validates");
    }

    /// The verifier's structured codes must survive into the record — flattened
    /// into prose they stop being queryable, which is what they exist for.
    #[test]
    fn a_refused_verification_carries_the_rejection_codes() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let audit = PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter");
        let outcome = apf_bundle::VerifyOutcome {
            ok: false,
            digest_hex: "c".repeat(64),
            payload_digest_hex: String::new(),
            parsed: true,
            monotonic_counter: 4,
            // The verifier's shape: `code: detail`. The normalizer keeps the code.
            rejection_reasons: vec![
                "bundle_expired: now 2026 > expires_at".to_owned(),
                "counter_regression: bundle counter 4 <= high-water-mark 9".to_owned(),
            ],
            bundle: Some(
                serde_yaml::from_str(
                    "id: expired-bundle\npolicy_revision: 4\nnot_before: \"2026-01-01T00:00:00Z\"\nexpires_at: \"2026-01-02T00:00:00Z\"\nmanifest: []\nruntime_compatibility: {}\n",
                )
                .expect("fixture bundle parses"),
            ),
        };
        audit
            .emit_verify_bundle(
                &RuntimeContext::default(),
                &BundleAuditMetadata::from_counter_and_digest(4, &outcome.digest_hex),
                &outcome,
            )
            .expect("a refused verification must be recorded");

        let written = std::fs::read_to_string(dir.path().join("apf-policy-service-audit.jsonl"))
            .expect("read");
        let parsed: AuditEvent = serde_json::from_str(written.trim()).expect("deserializes");
        parsed.validate().expect("validates against the schema");
        assert_eq!(parsed.event_type, apf_audit::EventType::PolicyVerification);
        assert_eq!(parsed.outcome, Some(apf_audit::Outcome::Refused));
        let codes = parsed.rejection_reasons.expect("codes recorded");
        assert_eq!(
            codes,
            vec!["bundle_expired".to_owned(), "counter_regression".to_owned()],
            "normalized codes, not prose"
        );
        assert_eq!(
            parsed.reason_code.as_deref(),
            Some("policy.bundle_rejected.bundle_expired"),
            "the leading verifier code names the record"
        );
        assert_eq!(
            parsed.policy_revision,
            Some(4),
            "parsed bundles are joinable"
        );
        assert_eq!(parsed.bundle_id.as_deref(), Some("expired-bundle"));
    }

    /// A healthy boot must still be recorded, or absence cannot be told apart
    /// from a failed audit write.
    #[test]
    fn a_clean_startup_records_an_enforcing_posture() {
        let written = posture_record(&[]);
        assert!(
            written.contains(r#""security_state":"secure""#),
            "{written}"
        );
        assert!(
            written.contains(r#""reason_code":"startup.secure""#),
            "{written}"
        );
    }

    #[test]
    fn a_weakened_startup_names_every_control_and_leads_with_the_first() {
        let written = posture_record(&[
            ("startup.ephemeral_signing_key", "generated key".to_owned()),
            (
                "startup.http_bind_non_loopback",
                "reachable off-host".to_owned(),
            ),
        ]);
        assert!(
            written.contains(r#""security_state":"degraded""#),
            "{written}"
        );
        assert!(
            written.contains(r#""reason_code":"startup.ephemeral_signing_key""#),
            "{written}"
        );
        // The detail carries every control, not just the one named above.
        assert!(written.contains("generated key"), "{written}");
        assert!(written.contains("reachable off-host"), "{written}");
    }
}
