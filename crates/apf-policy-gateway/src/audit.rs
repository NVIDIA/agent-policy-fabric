// SPDX-License-Identifier: Apache-2.0
//! Audit emission for the policy gateway: bundle lifecycle and decisions.
//!
//! This component is the local PDP. Unlike the policy service, which records
//! what policy was *published*, these records are what policy *did* — the
//! decision trail for the requests an agent actually made.

use std::path::Path;
use std::sync::Arc;

use apf_audit::{
    AuditEmitter, AuditErrorInfo, AuditEvent, AuthorizationEvent, CommonFields, Component,
    Decision, Finding, JsonlSink, Outcome, PolicyActivationEvent, Resource, SanitizationGuard,
    Severity, TypedAuditEvent, UNSPECIFIED, Verdict, coerce_id, coerce_lower_dotted, coerce_name,
    generate_correlation_id, generate_decision_id, join_rejection_detail,
};
use apf_policy_eval::{Finding as EvalFinding, Severity as EvalSeverity, Verdict as EvalVerdict};

/// Which enforcement seam is emitting.
///
/// One file each. The seams share this process today but may not later, and a
/// shared file would make that split a log-path migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seam {
    /// Decisions this gateway's PDP reached.
    Pdp,
    /// Sandbox admission, at the OpenShell interceptor.
    SandboxAdmission,
    /// Per-request egress, at the OpenShell supervisor middleware.
    Egress,
}

impl Seam {
    /// Component name, and the audit filename stem.
    ///
    /// Prefixed by the process, not the adapter crate: all three seams run
    /// inside this gateway.
    const fn component(self) -> &'static str {
        match self {
            Self::Pdp => "apf-policy-gateway",
            Self::SandboxAdmission => "apf-policy-gateway-interceptor",
            Self::Egress => "apf-policy-gateway-middleware",
        }
    }

    /// Audit naming rule: `<emitting-process>:<seam>`.
    const fn enforcement_point_id(self) -> &'static str {
        match self {
            Self::Pdp => "apf-policy-gateway:pdp",
            Self::SandboxAdmission => "apf-policy-gateway:interceptor",
            Self::Egress => "apf-policy-gateway:middleware",
        }
    }
}

/// The substrate this gateway governs.
const RUNTIME_SUBSTRATE: &str = "openshell";

/// The gateway verifies against the policy service's signing identity.
const TRUST_ROOT_ID: &str = "apf-policy-service:signing";

const ALLOW_REASON_CODE: &str = "policy.request_allowed";
const DENY_REASON_CODE: &str = "policy.request_denied";

/// Audit emitter for gateway events. `disabled()` drops them.
#[derive(Clone, Default)]
pub struct PolicyGatewayAudit {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    emitter: AuditEmitter<JsonlSink>,
    component: Component,
    seam: Seam,
}

impl PolicyGatewayAudit {
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Build an emitter for one seam, writing to `<dir>/<component>-audit.jsonl`
    /// and opening it now so an unusable directory fails at startup rather than
    /// at the first decision.
    ///
    /// # Errors
    ///
    /// Returns the sink error when the file cannot be opened for appending.
    pub fn to_jsonl_in(dir: impl AsRef<Path>, seam: Seam) -> Result<Self, String> {
        let component_name = seam.component();
        let sink = JsonlSink::new(dir.as_ref().join(format!("{component_name}-audit.jsonl")));
        sink.preflight().map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Some(Arc::new(Inner {
                emitter: AuditEmitter::new(sink),
                component: Component::new(
                    component_name,
                    env!("CARGO_PKG_VERSION"),
                    seam.enforcement_point_id(),
                ),
                seam,
            })),
        })
    }

    /// Envelope for an event with no caller behind it — a policy activation.
    fn common_for_policy(&self, inner: &Inner, digest: &str, revision: u64) -> CommonFields {
        let mut common = CommonFields::new_without_subject(
            generate_correlation_id(),
            inner.seam.enforcement_point_id(),
            RUNTIME_SUBSTRATE,
            inner.component.clone(),
            digest,
            TRUST_ROOT_ID,
        );
        common.policy_revision = Some(revision);
        common
    }

    /// Envelope for a decision, carrying the caller's identity and correlation.
    fn common(&self, inner: &Inner, decision: &DecisionRecord<'_>) -> CommonFields {
        let mut common = CommonFields::new_without_subject(
            // The caller's correlation id when it sent one, so a decision joins
            // to the calling gateway's own events; a fresh one otherwise.
            decision
                .correlation_id
                .filter(|id| !id.is_empty())
                .map_or_else(generate_correlation_id, coerce_id),
            inner.seam.enforcement_point_id(),
            RUNTIME_SUBSTRATE,
            inner.component.clone(),
            decision.bundle_digest,
            TRUST_ROOT_ID,
        );
        common.policy_revision = Some(decision.policy_revision);
        // Absent stays absent: a sentinel would assert an identity never sent.
        common.user_id = non_empty(decision.subject);
        common.agent_id = non_empty(decision.agent_type);
        common.session_id = non_empty(decision.sandbox_id);
        common
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

    /// Fail-closed: the caller must halt rather than continue unrecorded.
    fn emit_required(&self, event: AuditEvent) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        inner
            .emitter
            .emit_required(&event)
            .map_err(|e| e.to_string())
    }

    /// Record the policy this gateway is now enforcing.
    ///
    /// Fail-closed: policy nobody can name makes every later decision
    /// unattributable.
    ///
    /// # Errors
    ///
    /// Returns the emission error; the caller must halt.
    pub fn emit_policy_activated(
        &self,
        reason_code: &str,
        digest: &str,
        revision: u64,
    ) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let event = PolicyActivationEvent::new(Outcome::Success, reason_code)
            .into_audit_event(&self.common_for_policy(inner, digest, revision))
            .map_err(|e| e.to_string())?;
        self.emit_required(event)
    }

    /// Record a decision the PDP reached.
    ///
    /// Best-effort: this fires per governed request, and a failed write must not
    /// take enforcement down. The record is evidence, not the control.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_decision(&self, decision: &DecisionRecord<'_>) -> Result<(), String> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let common = self.common(inner, decision);
        // Coerced so a malformed value cannot drop the record. `resource.id`
        // is what was acted on; the subject belongs to subject identity.
        let resource = Resource::new(
            coerce_name(decision.resource_class),
            coerce_id(decision.resource_id),
        );
        let verb = coerce_lower_dotted(decision.verb);
        let decision_id = generate_decision_id();

        let event = if decision.allow {
            AuthorizationEvent::new(
                resource,
                verb,
                Decision::Allow,
                decision_id,
                ALLOW_REASON_CODE,
            )
            .with_findings(decision.findings.to_vec())
            // Also drops any finding of kind `policy_verdict`, the wire's
            // stand-in for the verdict field. The kind is not reserved
            // upstream, so a policy that defines it loses that finding here.
            .with_verdict(decision.verdict)
            .into_audit_event(&common)
        } else {
            AuthorizationEvent::new(
                resource,
                verb,
                Decision::Deny,
                decision_id,
                DENY_REASON_CODE,
            )
            .with_error(AuditErrorInfo {
                code: DENY_REASON_CODE.to_owned(),
                // The policy's own explanation. Without it every denial
                // reads the same and the log says only that one happened.
                message: join_rejection_detail(&[decision.deny_reason.to_owned()]),
                retryable: Some(false),
            })
            .with_findings(decision.findings.to_vec())
            .with_verdict(decision.verdict)
            .into_audit_event(&common)
        };

        // Both checks happen before writing, and both must fall through to the
        // fallback rather than return, or hostile input erases the record.
        let event = event
            .ok()
            .filter(|event| SanitizationGuard::new().check(event).is_ok());

        if let Some(event) = event {
            return self.emit_best_effort(event);
        }

        // All caller values dropped at once, not retried piecemeal. Sentinels
        // are forgeable, so `reason` marks the degradation instead.
        // The fallback reuses `common`: any caller value left in it fails the
        // retry exactly as it failed the first attempt.
        let mut common = common;
        common.user_id = None;
        common.agent_id = None;
        common.session_id = None;
        // Required, so regenerated rather than cleared. Coercion fixes the
        // charset; a credential-shaped id passes it and still trips sanitizing.
        common.correlation_id = generate_correlation_id();

        // The fallback keeps the primary's decision: an allow that degrades
        // must never read as a request that was blocked, or vice versa.
        let (fallback_decision, fallback_code) = if decision.allow {
            (Decision::Allow, ALLOW_REASON_CODE)
        } else {
            (Decision::Deny, DENY_REASON_CODE)
        };
        let mut fallback = AuthorizationEvent::new(
            Resource::new(UNSPECIFIED, UNSPECIFIED),
            UNSPECIFIED,
            fallback_decision,
            generate_decision_id(),
            fallback_code,
        )
        .into_audit_event(&common)
        .map_err(|e| e.to_string())?;
        fallback.reason = Some("caller-supplied request detail omitted".to_owned());
        self.emit_best_effort(fallback)
    }
}

/// Translate the evaluator's advisory signal into the audit vocabulary.
///
/// The two enums are deliberately separate types: `apf-audit` describes a wire
/// schema and `apf-policy-eval` describes an engine's output, and letting one
/// depend on the other would couple the log format to the engine. The cost is
/// this conversion, which must stay exhaustive — a new variant should fail to
/// compile here rather than silently record as `allow`.
#[must_use]
pub fn verdict_for_audit(verdict: EvalVerdict) -> Verdict {
    match verdict {
        EvalVerdict::Allow => Verdict::Allow,
        EvalVerdict::Warn => Verdict::Warn,
        EvalVerdict::Escalate => Verdict::Escalate,
    }
}

fn non_empty(value: &str) -> Option<String> {
    // Emptiness is tested on the input, not the coerced output. A subject that
    // coerces away is still a subject that was presented, and recording it as
    // absent is indistinguishable from an anonymous request — which a caller
    // could then choose. The sentinel is forgeable but visible; absence is not.
    (!value.is_empty()).then(|| coerce_id(value))
}

/// `advisory_signals.findings` maxItems.
const MAX_FINDINGS: usize = 32;

/// `$defs/finding.kind` and `.label`: length-capped, no charset rule.
fn truncate_finding_text(value: &str) -> String {
    value.chars().take(256).collect()
}

/// Translate the evaluator's observations into the audit vocabulary.
#[must_use]
pub fn findings_for_audit(findings: &[EvalFinding]) -> Vec<Finding> {
    // Over the schema cap the whole record degrades to the fallback, so the
    // record keeps the most severe. Taking the first N would drop a lone
    // critical behind a run of low ones — the inversion that matters.
    let mut kept: Vec<(usize, &EvalFinding)> = findings.iter().enumerate().collect();
    if kept.len() > MAX_FINDINGS {
        kept.sort_by_key(|(i, f)| (std::cmp::Reverse(f.severity), *i));
        kept.truncate(MAX_FINDINGS);
        // Schema documents findings order as significant.
        kept.sort_by_key(|(i, _)| *i);
    }
    kept.into_iter()
        .map(|(_, f)| Finding {
            // Not coerced: the schema leaves these unpatterned on purpose,
            // since they carry runtime annotation text. Length cap only.
            kind: truncate_finding_text(&f.kind),
            label: truncate_finding_text(&f.label),
            severity: match f.severity {
                EvalSeverity::Low => Severity::Low,
                EvalSeverity::Medium => Severity::Medium,
                EvalSeverity::High => Severity::High,
                EvalSeverity::Critical => Severity::Critical,
            },
            // Schema caps this at 100; an out-of-range value would fail the
            // whole record rather than just the finding.
            confidence: f.confidence.map(|c| c.min(100)),
        })
        .collect()
}

/// One PDP decision, as recorded.
///
/// A struct rather than a parameter list because `resource_class`, `verb` and
/// `subject` are all request-derived strings: passed positionally they are
/// trivially swappable, and a swap produces a record that is valid, plausible
/// and wrong.
pub struct DecisionRecord<'a> {
    pub allow: bool,
    /// What was acted on.
    pub resource_class: &'a str,
    pub resource_id: &'a str,
    pub verb: &'a str,
    /// Who acted. Recorded as subject identity, never as the resource.
    pub subject: &'a str,
    pub agent_type: &'a str,
    pub sandbox_id: &'a str,
    /// The caller's correlation id, so a decision joins to the events around
    /// it. Empty when none was sent.
    pub correlation_id: Option<&'a str>,
    /// The policy's explanation for a denial. Empty on allow.
    pub deny_reason: &'a str,
    pub verdict: Verdict,
    pub findings: &'a [Finding],
    /// Read atomically with the evaluator that decided, never separately.
    pub bundle_digest: &'a str,
    pub policy_revision: u64,
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    /// One file per seam, named for the process that writes it. Pinned because
    /// a rename is invisible at runtime — the logs simply appear somewhere else,
    /// and a consumer tailing the old path goes quiet without erroring.
    #[test]
    fn each_seam_writes_its_own_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        for (seam, expected) in [
            (Seam::Pdp, "apf-policy-gateway-audit.jsonl"),
            (
                Seam::SandboxAdmission,
                "apf-policy-gateway-interceptor-audit.jsonl",
            ),
            (Seam::Egress, "apf-policy-gateway-middleware-audit.jsonl"),
        ] {
            PolicyGatewayAudit::to_jsonl_in(dir.path(), seam)
                .expect("build emitter")
                .emit_policy_activated("policy.bundle_activated", &"a".repeat(64), 1)
                .expect("activation recorded");
            assert!(
                dir.path().join(expected).exists(),
                "{seam:?} should write {expected}"
            );
        }
    }
}
