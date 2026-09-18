// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Audit emission for the OpenShell interceptor.
//!
//! Covers sandbox admission and config governance. A permitted record is
//! evidence that this phase did not refuse — `reason_code` says what it
//! permitted. Injection at MODIFY is not evidence a workload ran: VALIDATE
//! follows and can still refuse.

use std::path::Path;

use apf_audit::{
    AdmissionValidationEvent, AuditErrorInfo, AuditIdentity, ComponentAudit, ConfigGovernanceEvent,
    Effects, Outcome as AuditOutcome, PolicyInjectionEvent, Resource, SanitizationGuard,
    TypedAuditEvent, UNSPECIFIED, coerce_digest, coerce_id, coerce_lower_dotted, coerce_name,
    generate_correlation_id, join_rejection_detail,
};

/// Runs inside the gateway process, so it is named for that process.
const IDENTITY: AuditIdentity = AuditIdentity {
    component_name: "apf-policy-gateway-interceptor",
    enforcement_point_id: "apf-policy-gateway:interceptor",
    runtime_substrate: "openshell",
    trust_root_id: "apf-policy-service:signing",
    version: env!("CARGO_PKG_VERSION"),
};

/// Stands in for a digest that cannot be recorded as given. Distinct from
/// `unverified`: the policy was proven, its identity just is not writable.
const UNRECORDABLE_DIGEST: &str = "unrecordable";

/// Audit emitter for admission decisions. `disabled()` drops them.
#[derive(Clone, Default)]
pub struct InterceptorAudit {
    inner: ComponentAudit,
}

impl InterceptorAudit {
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// This seam's emitter, for the extension verifier to record refusals it
    /// makes on this listener's behalf. Shared so both write one file under
    /// one identity.
    #[must_use]
    pub fn component(&self) -> apf_audit::ComponentAudit {
        self.inner.clone()
    }

    /// Open `<dir>/apf-policy-gateway-interceptor-audit.jsonl` now, so an
    /// unusable directory fails at startup rather than at the first admission.
    ///
    /// # Errors
    ///
    /// Returns the sink error when the file cannot be opened for appending.
    pub fn to_jsonl_in(dir: impl AsRef<Path>) -> Result<Self, String> {
        Ok(Self {
            inner: ComponentAudit::to_jsonl_in(dir, IDENTITY)?,
        })
    }

    /// Record an admission decision.
    ///
    /// Best-effort: the decision is already made by the time this runs, and
    /// refusing to admit because a log line did not write would take the
    /// substrate down over a full disk.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_admission(&self, record: &AdmissionRecord<'_>) -> Result<(), String> {
        let Some(mut common) = self
            .inner
            .common(&coerce_digest(record.policy_digest), record.policy_revision)
        else {
            return Ok(());
        };
        if !record.correlation_id.is_empty() {
            common.correlation_id = coerce_id(record.correlation_id);
        }
        common.user_id = non_empty(record.user_subject);
        common.agent_id = non_empty(record.agent_type);
        common.session_id = non_empty(record.sandbox_id);

        let resource = Resource::new(
            coerce_name(record.resource_kind),
            coerce_id(record.resource_id),
        );
        let verb = coerce_lower_dotted(record.verb);
        let reason_code = coerce_lower_dotted(record.reason_code);
        let (outcome, error) = match record.outcome {
            Outcome::Allowed => (AuditOutcome::Success, None),
            Outcome::Refused { detail } => (
                AuditOutcome::Refused,
                Some(AuditErrorInfo {
                    code: reason_code.clone(),
                    message: join_rejection_detail(&[detail.to_owned()]),
                    retryable: Some(false),
                }),
            ),
        };

        let event = build_admission_event(
            record.phase,
            resource,
            verb.clone(),
            outcome,
            reason_code.clone(),
            error.clone(),
            record.applied.clone(),
        )
        .into_audit_event(&common);

        // Both checks happen before writing, and both must fall through to the
        // fallback rather than return, or hostile input erases the record.
        let event = event
            .ok()
            .filter(|event| SanitizationGuard::new().check(event).is_ok());
        if let Some(event) = event {
            return self.inner.emit_best_effort(&event);
        }

        // The fallback reuses `common`, so any caller-derived value left in it
        // fails the retry exactly as it failed the first attempt.
        common.correlation_id = generate_correlation_id();
        // Coercion fixes the charset only, so a credential-shaped digest would
        // trip the sanitizer on the retry exactly as it did on the primary.
        common.bundle_digest = UNRECORDABLE_DIGEST.to_owned();
        common.user_id = None;
        common.agent_id = None;
        common.session_id = None;

        // The phase and outcome survive degradation: recording a permitted
        // phase as refused would say the interceptor blocked something it did
        // not, and losing the phase would unmoor the record from its seam.
        // Patch paths are policy-derived strings and could be what tripped the
        // guard; the count is a number and cannot. Keeping it stops a degraded
        // injection reading as one that changed nothing.
        let mut fallback = build_admission_event(
            record.phase,
            Resource::new(UNSPECIFIED, UNSPECIFIED),
            UNSPECIFIED.to_owned(),
            outcome,
            reason_code,
            None,
            Effects {
                patch_count: record.applied.patch_count,
                ..Effects::default()
            },
        )
        .into_audit_event(&common)
        .map_err(|e| e.to_string())?;
        fallback.reason = Some("caller-supplied admission detail omitted".to_owned());
        self.inner.emit_best_effort(&fallback)
    }
}

/// Emptiness is tested on the input, not the coerced output. A subject that
/// coerces away was still presented, and recording it as absent is
/// indistinguishable from an anonymous request.
fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| coerce_id(value))
}

/// One admission event, typed by phase. `Box<dyn>` is avoided on purpose: the
/// three constructors share no trait beyond `TypedAuditEvent`, and this enum
/// keeps the choice exhaustive.
enum AdmissionEvent {
    Injection(PolicyInjectionEvent),
    Validation(AdmissionValidationEvent),
    Governance(ConfigGovernanceEvent),
}

impl AdmissionEvent {
    fn into_audit_event(
        self,
        common: &apf_audit::CommonFields,
    ) -> apf_audit::ValidationResult<apf_audit::AuditEvent> {
        match self {
            Self::Injection(e) => e.into_audit_event(common),
            Self::Validation(e) => e.into_audit_event(common),
            Self::Governance(e) => e.into_audit_event(common),
        }
    }
}

fn build_admission_event(
    phase: AdmissionPhase,
    resource: Resource,
    verb: String,
    outcome: AuditOutcome,
    reason_code: String,
    error: Option<AuditErrorInfo>,
    applied: Effects,
) -> AdmissionEvent {
    match phase {
        AdmissionPhase::Injection => {
            let mut event = PolicyInjectionEvent::new(resource, verb, outcome, reason_code)
                .with_effects(applied);
            if let Some(error) = error {
                event = event.with_error(error);
            }
            AdmissionEvent::Injection(event)
        }
        AdmissionPhase::Validation => {
            let mut event = AdmissionValidationEvent::new(resource, verb, outcome, reason_code);
            if let Some(error) = error {
                event = event.with_error(error);
            }
            AdmissionEvent::Validation(event)
        }
        AdmissionPhase::Governance => {
            let mut event =
                ConfigGovernanceEvent::new(verb, outcome, reason_code).with_resource(resource);
            if let Some(error) = error {
                event = event.with_error(error);
            }
            AdmissionEvent::Governance(event)
        }
    }
}

/// Which admission phase decided — and therefore which event type records it.
#[derive(Clone, Copy)]
pub enum AdmissionPhase {
    /// MODIFY_OPERATION: policy material injected into the specification.
    Injection,
    /// VALIDATE: the injected policy reached commit intact.
    Validation,
    /// Config-surface governance: UpdateConfig MODIFY and VALIDATE. Provider
    /// profile refusals are enforced but not yet recorded.
    Governance,
}

/// Whether the phase refused, and why if it did.
pub enum Outcome<'a> {
    /// This phase did not refuse. What it permitted is carried by
    /// `reason_code`, not by this.
    Allowed,
    Refused {
        detail: &'a str,
    },
}

/// One admission decision, as recorded.
///
/// A struct rather than a parameter list: these are all request-derived
/// strings, and passed positionally a swap produces a record that is valid,
/// plausible and wrong.
pub struct AdmissionRecord<'a> {
    pub outcome: Outcome<'a>,
    /// Selects the event type; the verb alone is caller text, not a contract.
    pub phase: AdmissionPhase,
    /// The phase and verb decided, e.g. `interceptor.create_sandbox`.
    pub verb: &'a str,
    pub reason_code: &'a str,
    /// What the policy was applied to — the document kind it came from.
    pub resource_kind: &'a str,
    /// What was acted on. Separate from `sandbox_id` because a config
    /// operation has a resource but no sandbox; the sandbox paths pass the
    /// sandbox id as both.
    pub resource_id: &'a str,
    /// The sandbox this decision belongs to, empty when there is none.
    pub sandbox_id: &'a str,
    pub user_subject: &'a str,
    pub agent_type: &'a str,
    pub correlation_id: &'a str,
    /// The policy the decision was made under.
    pub policy_digest: &'a str,
    pub policy_revision: Option<u64>,
    /// What the injection changed. Empty on every path that changed nothing —
    /// the record says a policy was injected, this says which parts of the
    /// spec it rewrote.
    pub applied: Effects,
}

#[cfg(test)]
mod tests {
    use super::*;
    use apf_audit::AuditEvent;

    const DIGEST: &str = "a1b2c3";

    fn record<'a>(outcome: Outcome<'a>, sandbox_id: &'a str) -> AdmissionRecord<'a> {
        AdmissionRecord {
            outcome,
            phase: AdmissionPhase::Injection,
            verb: "interceptor.create_sandbox",
            reason_code: "interceptor.policy_injected",
            resource_kind: "openshell.sandbox.v1",
            resource_id: sandbox_id,
            sandbox_id,
            user_subject: "alice@corp",
            agent_type: "claude-code",
            correlation_id: "corr-1",
            policy_digest: DIGEST,
            policy_revision: Some(7),
            applied: Effects::default(),
        }
    }

    /// The phase selects the noun. Unpinned, a swapped arm in
    /// `build_admission_event` records validations as governance — schema-valid
    /// and silently wrong on every record from that seam.
    #[test]
    fn each_phase_records_as_its_own_event_type() {
        let cases = [
            (
                AdmissionPhase::Injection,
                apf_audit::EventType::PolicyInjection,
            ),
            (
                AdmissionPhase::Validation,
                apf_audit::EventType::AdmissionValidation,
            ),
            (
                AdmissionPhase::Governance,
                apf_audit::EventType::ConfigGovernance,
            ),
        ];
        for (phase, expected) in cases {
            for refused in [false, true] {
                for degrade in [false, true] {
                    let dir = tempfile::tempdir().expect("temp dir");
                    let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");
                    let outcome = if refused {
                        Outcome::Refused { detail: "no" }
                    } else {
                        Outcome::Allowed
                    };
                    audit
                        .emit_admission(&AdmissionRecord {
                            phase,
                            // A credential-shaped digest forces the degraded path.
                            policy_digest: if degrade {
                                "AKIAAAAAAAAAAAAAAAAA"
                            } else {
                                DIGEST
                            },
                            ..record(outcome, "sbx-9")
                        })
                        .expect("recorded");
                    let r = &records(dir.path())[0];
                    assert_eq!(r.event_type, expected, "phase must pick the noun");
                    let want = if refused {
                        apf_audit::Outcome::Refused
                    } else {
                        apf_audit::Outcome::Success
                    };
                    assert_eq!(r.outcome, Some(want), "outcome survives degradation");
                    assert_eq!(
                        r.reason.is_some(),
                        degrade,
                        "degradation is marked exactly when it happened"
                    );
                    // After degradation the reason_code is the record's only
                    // remaining semantic — resource and verb are sentinels.
                    assert_eq!(
                        r.reason_code.as_deref(),
                        Some("interceptor.policy_injected"),
                        "the reason code must survive degradation"
                    );
                }
            }
        }
    }

    /// A degraded injection must still say how much it changed: the count is
    /// a number the guard cannot object to, while the paths go with the rest
    /// of the caller-derived strings.
    #[test]
    fn a_degraded_injection_keeps_its_patch_count() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");
        audit
            .emit_admission(&AdmissionRecord {
                policy_digest: "AKIAAAAAAAAAAAAAAAAA",
                applied: Effects {
                    patch_count: Some(8),
                    patches: vec![apf_audit::PatchRecord::new(
                        "/spec/policy",
                        apf_audit::PatchOp::Add,
                    )],
                    ..Effects::default()
                },
                ..record(Outcome::Allowed, "sbx-9")
            })
            .expect("recorded");

        let r = &records(dir.path())[0];
        assert!(r.reason.is_some(), "this must be the degraded record");
        let effects = r.effects.as_ref().expect("the count survives");
        assert_eq!(effects.patch_count, Some(8));
        assert!(effects.patches.is_empty(), "paths are dropped: {effects:?}");
    }

    fn records(dir: &Path) -> Vec<AuditEvent> {
        let written =
            std::fs::read_to_string(dir.join("apf-policy-gateway-interceptor-audit.jsonl"))
                .expect("audit log was written");
        written
            .lines()
            .map(|line| {
                let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
                parsed.validate().expect("validates against the schema");
                parsed
            })
            .collect()
    }

    /// An injected policy must be attributable: whose sandbox, under which
    /// policy, in which session.
    #[test]
    fn an_injected_policy_names_itself_and_the_subject() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");

        audit
            .emit_admission(&record(Outcome::Allowed, "sbx-9"))
            .expect("recorded");

        let r = &records(dir.path())[0];
        assert_eq!(r.event_type, apf_audit::EventType::PolicyInjection);
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Success));
        assert_eq!(r.bundle_digest.as_deref(), Some(DIGEST));
        assert_eq!(r.user_id.as_deref(), Some("alice@corp"));
        assert_eq!(r.session_id.as_deref(), Some("sbx-9"));
        assert_eq!(r.correlation_id, "corr-1");
    }

    /// A refusal must record as a refusal. An admission logged as denied, or a
    /// denial logged as permitted, is worse than no record.
    #[test]
    fn a_refused_sandbox_is_recorded_as_a_denial() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");

        audit
            .emit_admission(&AdmissionRecord {
                reason_code: "interceptor.inject_denied.invalid_jwt",
                ..record(
                    Outcome::Refused {
                        detail: "provenance JWT invalid at inject time",
                    },
                    "sbx-9",
                )
            })
            .expect("recorded");

        let r = &records(dir.path())[0];
        assert_eq!(r.event_type, apf_audit::EventType::PolicyInjection);
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.inject_denied.invalid_jwt")
        );
        assert!(
            r.error_info
                .as_ref()
                .is_some_and(|e| e.message.contains("invalid at inject time")),
            "the refusal detail must reach the record: {:?}",
            r.error_info
        );
    }

    /// The fallback rebuilds the event from the same phase and outcome, and
    /// getting that wrong records a refused sandbox as permitted. Reached with
    /// a credential-shaped id, which coerces clean but trips the sanitizer.
    #[test]
    fn a_refusal_reaching_the_fallback_is_still_a_denial() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");

        audit
            .emit_admission(&AdmissionRecord {
                reason_code: "interceptor.inject_denied.invalid_jwt",
                ..record(
                    Outcome::Refused {
                        detail: "provenance JWT invalid at inject time",
                    },
                    "AKIAAAAAAAAAAAAAAAAA",
                )
            })
            .expect("recorded");

        let r = &records(dir.path())[0];
        assert_eq!(
            r.outcome,
            Some(apf_audit::Outcome::Refused),
            "a refused sandbox must never read as permitted"
        );
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied admission detail omitted"),
            "the fallback must mark itself"
        );
        assert_eq!(r.session_id, None, "the degraded record must not carry it");
    }

    /// Coercion fixes the digest charset but not credential shapes, and the
    /// fallback reuses the envelope — so without a sentinel the retry fails
    /// exactly as the primary did and the record is lost.
    #[test]
    fn a_credential_shaped_digest_cannot_erase_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");

        audit
            .emit_admission(&AdmissionRecord {
                policy_digest: "AKIAAAAAAAAAAAAAAAAA",
                ..record(Outcome::Allowed, "sbx-9")
            })
            .expect("the admission must still be recorded");

        let r = &records(dir.path())[0];
        assert_eq!(r.bundle_digest.as_deref(), Some("unrecordable"));
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Success));
    }

    /// A sandbox id or subject a caller controls must not be able to erase the
    /// record of its own admission.
    #[test]
    fn a_hostile_sandbox_id_cannot_suppress_the_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");

        for hostile in [
            "AKIAAAAAAAAAAAAAAAAA",
            "../../etc/shadow",
            "clé_secrète",
            "!!!",
            "",
        ] {
            audit
                .emit_admission(&record(Outcome::Allowed, hostile))
                .unwrap_or_else(|e| panic!("emit failed for {hostile:?}: {e}"));
        }

        let written = std::fs::read_to_string(
            dir.path()
                .join("apf-policy-gateway-interceptor-audit.jsonl"),
        )
        .expect("read");
        assert!(
            !written.contains("AKIAAAAAAAAAAAAAAAAA"),
            "the degraded record must not carry the value that tripped it"
        );
        let records = records(dir.path());
        assert_eq!(records.len(), 5, "every admission left a record");
        for r in &records {
            assert_eq!(
                r.outcome,
                Some(apf_audit::Outcome::Success),
                "a permitted phase must never read as refused"
            );
        }
    }
}
