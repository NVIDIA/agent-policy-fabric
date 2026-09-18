// SPDX-License-Identifier: Apache-2.0
//! Audit emission for per-request egress.
//!
//! The busiest seam: one decision per governed request an agent makes. The
//! record is the evidence of what the agent tried and what policy did about it.

use std::path::Path;

use apf_audit::{
    AuditErrorInfo, AuditIdentity, AuthenticationEvent, AuthorizationEvent, ComponentAudit,
    Decision, Effects, Finding, Resource, SanitizationGuard, Severity, TypedAuditEvent,
    UNSPECIFIED, Verdict, coerce_digest, coerce_id, coerce_lower_dotted, coerce_name,
    generate_correlation_id, generate_decision_id, join_rejection_detail,
};

/// Runs inside the gateway process, so it is named for that process.
const IDENTITY: AuditIdentity = AuditIdentity {
    component_name: "apf-policy-gateway-middleware",
    enforcement_point_id: "apf-policy-gateway:middleware",
    runtime_substrate: "openshell",
    trust_root_id: "apf-policy-service:signing",
    version: env!("CARGO_PKG_VERSION"),
};

/// Stands in for a digest that cannot be recorded as given. Coercion fixes the
/// charset only, so a credential-shaped digest still trips sanitizing and would
/// fail the fallback exactly as it failed the primary.
const UNRECORDABLE_DIGEST: &str = "unrecordable";

/// Stands in for the policy identity on a refusal raised before any policy is
/// consulted — an identity refusal, not a policy one.
pub const UNVERIFIED_POLICY: &str = "unverified";

/// `advisory_signals.findings` maxItems. Over the cap the whole record degrades
/// to the fallback, so the most severe are kept rather than the first.
const MAX_FINDINGS: usize = 32;

/// Audit emitter for egress decisions. `disabled()` drops them.
#[derive(Clone, Default)]
pub struct MiddlewareAudit {
    inner: ComponentAudit,
}

impl MiddlewareAudit {
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

    /// Open `<dir>/apf-policy-gateway-middleware-audit.jsonl` now, so an
    /// unusable directory fails at startup rather than at the first request.
    ///
    /// # Errors
    ///
    /// Returns the sink error when the file cannot be opened for appending.
    pub fn to_jsonl_in(dir: impl AsRef<Path>) -> Result<Self, String> {
        Ok(Self {
            inner: ComponentAudit::to_jsonl_in(dir, IDENTITY)?,
        })
    }

    /// Record one egress decision.
    ///
    /// Best-effort: this fires on every governed request, and taking egress
    /// down because a log line did not write would turn a full disk into an
    /// outage. The decision is enforced either way.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_egress(&self, record: &EgressRecord<'_>) -> Result<(), String> {
        let Some(mut common) = self
            .inner
            .common(&coerce_digest(record.policy_digest), record.policy_revision)
        else {
            return Ok(());
        };
        if !record.correlation_id.is_empty() {
            common.correlation_id = coerce_id(record.correlation_id);
        }
        // No `user_id`: OpenShell V1 carries no authenticated user subject, and
        // recording the sandbox as one would assert a human identity nothing
        // established. The sandbox is a session.
        common.session_id = non_empty(record.sandbox_id);

        // Host and method, not the path: a URL path carries request content and
        // the record is evidence of what was attempted, not a copy of it.
        let resource = Resource::new(coerce_name(record.resource_kind), coerce_id(record.host));
        // The tool name is caller-influenced; the coercion pins it to the verb
        // profile so it cannot fail validation, and the fallback below drops
        // it with every other caller-derived string.
        let verb = record.tool.map_or_else(
            || coerce_lower_dotted(record.verb),
            |tool| coerce_lower_dotted(&format!("tool.{tool}")),
        );
        let decision_id = generate_decision_id();
        let reason_code = coerce_lower_dotted(record.reason_code);

        // One `authorization` record per egress decision — the deny that was
        // once `substrate_deny` keeps its distinct reason_code, and the
        // policy's own explanation rides in `error` for every denial.
        let decision = if record.allowed {
            Decision::Allow
        } else {
            Decision::Deny
        };
        let mut event =
            AuthorizationEvent::new(resource, verb, decision, decision_id, reason_code.clone())
                .with_findings(record.findings.to_vec())
                .with_effects(record.effects.clone());
        if !record.allowed {
            event = event.with_error(AuditErrorInfo {
                code: reason_code.clone(),
                // The policy's own explanation; without it every denial
                // reads the same.
                message: join_rejection_detail(&[record.reason.to_owned()]),
                retryable: Some(false),
            });
        }
        let event = match record.verdict {
            // `Allow` is the absence of a signal. Omitting it also lets a
            // policy-authored `policy_verdict` finding survive; on a
            // non-`Allow` verdict the schema forbids the pair, and the
            // verdict is kept over the finding.
            Some(verdict) if verdict != Verdict::Allow => event.with_verdict(verdict),
            _ => event,
        };
        let event = event.into_audit_event(&common);

        // Both checks happen before writing, and both must fall through to the
        // fallback rather than return, or hostile input erases the record.
        let event = event
            .ok()
            .filter(|event| SanitizationGuard::new().check(event).is_ok());
        if let Some(event) = event {
            return self.inner.emit_best_effort(&event);
        }

        // The fallback reuses `common`, so every caller-derived value in it
        // fails the retry exactly as it failed the first attempt.
        common.correlation_id = generate_correlation_id();
        common.session_id = None;
        common.bundle_digest = UNRECORDABLE_DIGEST.to_owned();

        // The event type follows the decision: recording an allowed request as
        // denied would say egress was blocked when it went through.
        // Keep what cannot have tripped the guard: a bool and a count. The
        // strings go — a header name or patch path may be what failed — but
        // dropping the counts too would degrade a redacted request to a bare
        // allow, which is the reading this field exists to prevent.
        let effects = Effects {
            payload_replaced: record.effects.payload_replaced,
            patch_count: record.effects.patch_count,
            ..Effects::default()
        };

        // The decision survives degradation: an allow that degrades must never
        // read as blocked egress, and the substrate-vs-policy distinction
        // survives in the reason_code, which is a producer constant.
        let mut fallback = AuthorizationEvent::new(
            Resource::new(UNSPECIFIED, UNSPECIFIED),
            UNSPECIFIED,
            decision,
            generate_decision_id(),
            reason_code,
        )
        .with_effects(effects)
        .into_audit_event(&common)
        .map_err(|e| e.to_string())?;
        fallback.reason = Some("caller-supplied request detail omitted".to_owned());
        self.inner.emit_best_effort(&fallback)
    }
}

/// The two sandbox ids of an impersonation attempt. Named rather than
/// positional: both are `&str`, and a swap names the attacker's claim as the
/// authenticated caller.
#[derive(Clone, Copy)]
pub struct BindingMismatch<'a> {
    /// From the verified token.
    pub bound_sandbox: &'a str,
    /// Caller-chosen, and the reason this event exists.
    pub claimed_sandbox: &'a str,
}

impl MiddlewareAudit {
    /// Record a supervisor credential used on a request claiming another
    /// sandbox — one sandbox acting as another.
    ///
    /// An `authentication` record, not an egress denial: no policy was consulted, and
    /// the audit model has a shape that carries both sandbox ids and clears
    /// policy identity. Recording it as egress would hide the highest-value
    /// event this seam sees from anything looking for auth failures.
    ///
    /// # Errors
    ///
    /// Returns the emission error for the caller to log.
    pub fn emit_sandbox_binding_mismatch(&self, ids: &BindingMismatch<'_>) -> Result<(), String> {
        let BindingMismatch {
            bound_sandbox,
            claimed_sandbox,
        } = *ids;
        const REASON_CODE: &str = "extension_auth.sandbox_binding_mismatch";
        let Some(common) = self.inner.common("", None) else {
            return Ok(());
        };
        let mismatch = |bound: &str, claimed: &str| {
            AuthenticationEvent::sandbox_binding_mismatch(
                bound,
                claimed,
                REASON_CODE,
                AuditErrorInfo {
                    code: REASON_CODE.to_owned(),
                    message: join_rejection_detail(&[
                        "supervisor credential is bound to a different sandbox".to_owned(),
                    ]),
                    retryable: Some(false),
                },
            )
            .into_audit_event(&common)
            .ok()
            .filter(|event| SanitizationGuard::new().check(event).is_ok())
        };

        // Length only: the schema leaves these unpatterned on purpose, since a
        // charset rule would let a claimed id be rewritten into a legitimate
        // one. The sanitizer still walks them, hence the fallback below.
        if let Some(event) = mismatch(&sandbox_id(bound_sandbox), &sandbox_id(claimed_sandbox)) {
            return self.inner.emit_best_effort(&event);
        }

        // Without a fallback the caller picks a sandbox id that trips the
        // sanitizer and the record vanishes — on the one event that exists to
        // catch them doing it.
        let Some(mut fallback) = mismatch(UNSPECIFIED, UNSPECIFIED) else {
            return Err("binding mismatch record could not be constructed".to_owned());
        };
        fallback.reason = Some("caller-supplied sandbox ids omitted".to_owned());
        self.inner.emit_best_effort(&fallback)
    }
}

/// The authentication record's sandbox-id length cap. Not coerced: see the call site. Empty
/// becomes the sentinel, since `minLength: 1` would fail the record and take
/// the authenticated id down with it.
fn sandbox_id(value: &str) -> String {
    if value.is_empty() {
        return UNSPECIFIED.to_owned();
    }
    value.chars().take(256).collect()
}

/// Emptiness is tested on the input, not the coerced output: a value that
/// coerces away was still presented, and recording it as absent is
/// indistinguishable from a request that carried none.
fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| coerce_id(value))
}

/// Translate the evaluator's observations into the audit vocabulary, keeping
/// the most severe when over the schema cap.
///
/// `kind` and `label` are not coerced: the schema leaves them unpatterned
/// because they carry runtime annotation text. Only the length cap applies.
#[must_use]
pub fn findings_for_audit(findings: &[apf_policy_eval::Finding]) -> Vec<Finding> {
    let mut kept: Vec<(usize, &apf_policy_eval::Finding)> = findings.iter().enumerate().collect();
    if kept.len() > MAX_FINDINGS {
        kept.sort_by_key(|(i, f)| (std::cmp::Reverse(f.severity), *i));
        kept.truncate(MAX_FINDINGS);
        // Schema documents findings order as significant.
        kept.sort_by_key(|(i, _)| *i);
    }
    kept.into_iter()
        .map(|(_, f)| Finding {
            kind: f.kind.chars().take(256).collect(),
            label: f.label.chars().take(256).collect(),
            severity: match f.severity {
                apf_policy_eval::Severity::Low => Severity::Low,
                apf_policy_eval::Severity::Medium => Severity::Medium,
                apf_policy_eval::Severity::High => Severity::High,
                apf_policy_eval::Severity::Critical => Severity::Critical,
            },
            // Schema caps this at 100; an out-of-range value would fail the
            // whole record rather than just the finding.
            confidence: f.confidence.map(|c| c.min(100)),
        })
        .collect()
}

/// Translate the evaluator's advisory signal. Exhaustive by intent: a new
/// variant should fail to compile here rather than record as `allow`.
#[must_use]
pub fn verdict_for_audit(verdict: apf_policy_eval::Verdict) -> Verdict {
    match verdict {
        apf_policy_eval::Verdict::Allow => Verdict::Allow,
        apf_policy_eval::Verdict::Warn => Verdict::Warn,
        apf_policy_eval::Verdict::Escalate => Verdict::Escalate,
    }
}

/// One egress decision, as recorded.
///
/// A struct rather than a parameter list: these are request-derived strings and
/// passed positionally a swap produces a record that is valid, plausible and
/// wrong.
pub struct EgressRecord<'a> {
    pub allowed: bool,
    /// What was acted on — the substrate surface, and the host reached.
    pub resource_kind: &'a str,
    pub host: &'a str,
    /// The HTTP method; superseded on the record by `tool` when present.
    pub verb: &'a str,
    /// The MCP tool the request invoked, where one was parsed. Recorded as
    /// the verb (`tool.<name>`): the governed action was a tool invocation,
    /// not a bare HTTP request, and without it every MCP-path record reads
    /// as an indistinguishable POST to the MCP front.
    pub tool: Option<&'a str>,
    pub reason_code: &'a str,
    /// The policy's explanation for a denial. Empty on allow.
    pub reason: &'a str,
    pub sandbox_id: &'a str,
    pub correlation_id: &'a str,
    /// The evaluator's advisory signal. `None` when the evaluator was never
    /// reached; `Allow` means no signal was raised and is not recorded.
    pub verdict: Option<Verdict>,
    pub findings: &'a [Finding],
    /// What was applied to the request in flight. A redaction that rewrote the
    /// body is the difference between "allowed it" and "allowed a sanitised
    /// copy of it" — without this the record understates the control.
    pub effects: Effects,
    /// Read atomically with the evaluator that decided, never separately.
    pub policy_digest: &'a str,
    pub policy_revision: Option<u64>,
}
