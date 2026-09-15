// SPDX-License-Identifier: Apache-2.0
//! Typed builders for the `apf.audit.event.v1` vocabulary.
//!
//! One rule governs the taxonomy: `event_type` names the operation or fact —
//! never its outcome. [`AuthorizationEvent`] is the only type that carries a
//! [`Decision`]; every other operation carries an [`Outcome`]; `reason_code`
//! explains why. Builders validate against the schema before returning, so an
//! event that would not validate cannot be constructed.

use std::fmt::{Display, Formatter};

use crate::model::{
    AuditContext, AuditErrorInfo, AuditEvent, CallerKind, CredentialScope, Decision, Effects,
    EventType, Finding, Obligations, Outcome, RedactedObject, Resource, ReviewRef, SecurityState,
    StartupContext, ValidationChecks, Verdict,
};
use crate::validation::ValidationResult;

pub trait TypedAuditEvent: Display {
    #[must_use]
    fn event_type(&self) -> EventType;

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent>;
}

// ── authorization ─────────────────────────────────────────────────────────────

/// An authorization decision on a governed action — the only event type that
/// carries a [`Decision`]. Allows and denials are one type distinguished by
/// that field; a denial's policy explanation rides in `error`.
///
/// This records the enforcement point *making* the decision (and, via
/// `effects`, any mutation it instructed) — not independent confirmation that
/// the substrate applied it.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationEvent {
    pub resource: Resource,
    pub verb: String,
    pub decision: Decision,
    pub decision_id: String,
    pub reason_code: String,
    pub obligations: Option<Obligations>,
    pub argument_summary: Option<RedactedObject>,
    pub error: Option<AuditErrorInfo>,
    pub findings: Vec<Finding>,
    pub verdict: Option<Verdict>,
    pub effects: Option<Effects>,
}

impl AuthorizationEvent {
    #[must_use]
    pub fn new(
        resource: Resource,
        verb: impl Into<String>,
        decision: Decision,
        decision_id: impl Into<String>,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            resource,
            verb: verb.into(),
            decision,
            decision_id: decision_id.into(),
            reason_code: reason_code.into(),
            obligations: None,
            argument_summary: None,
            error: None,
            findings: Vec::new(),
            verdict: None,
            effects: None,
        }
    }

    /// The policy's own explanation of a denial. Without it every denial
    /// reads the same and the log says only that one happened.
    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }

    #[must_use]
    pub fn with_obligations(mut self, obligations: Obligations) -> Self {
        self.obligations = Some(obligations);
        self
    }

    #[must_use]
    pub fn with_argument_summary(mut self, argument_summary: RedactedObject) -> Self {
        self.argument_summary = Some(argument_summary);
        self
    }

    /// Attach the observations the effect stage emitted alongside this
    /// decision. Order is significant — preserve the evaluator's ordering.
    #[must_use]
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        if self.verdict.is_some() {
            drop_synthetic_verdict_finding(&mut self.findings);
        }
        self
    }

    /// Attach the evaluator's advisory verdict.
    ///
    /// Do not additionally emit a synthetic warn/escalate finding — that
    /// duplication exists only on the OpenShell wire, which has findings but
    /// no verdict field.
    #[must_use]
    pub fn with_verdict(mut self, verdict: Verdict) -> Self {
        self.verdict = Some(verdict);
        drop_synthetic_verdict_finding(&mut self.findings);
        self
    }

    /// Record what was applied to the request in flight.
    ///
    /// Omitted when nothing changed, so an absent field means "unmodified"
    /// rather than "we did not look".
    #[must_use]
    pub fn with_effects(mut self, mut effects: Effects) -> Self {
        effects.truncate_patches();
        self.effects = (!effects.is_empty()).then_some(effects);
        self
    }
}

impl TypedAuditEvent for AuthorizationEvent {
    fn event_type(&self) -> EventType {
        EventType::Authorization
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::Authorization, ctx.clone());
        event.resource = Some(self.resource);
        event.verb = Some(self.verb);
        event.decision = Some(self.decision);
        event.decision_id = Some(self.decision_id);
        event.reason_code = Some(self.reason_code);
        event.obligations = self.obligations;
        event.argument_summary = self.argument_summary;
        event.error_info = self.error;
        if !self.findings.is_empty() {
            event.findings = Some(self.findings);
        }
        event.verdict = self.verdict;
        event.effects = self.effects;
        validate(event)
    }
}

impl Display for AuthorizationEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "authorization {} {} -> {} ({})",
            self.resource.id, self.verb, self.decision, self.reason_code
        )
    }
}

// ── authentication ────────────────────────────────────────────────────────────

/// A rejection at the authentication / caller-access boundary.
///
/// Deliberately not an [`AuthorizationEvent`]. Authorization answers "policy
/// refused this action"; this answers "this caller failed the caller checks" —
/// a bad credential, no verified caller, a caller kind the RPC does not
/// permit, or a sandbox binding that does not match. Different detection
/// rules, different responders. No policy was consulted, so no policy
/// identity is carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationEvent {
    pub reason_code: String,
    pub error_info: AuditErrorInfo,
    pub caller_kind: Option<String>,
    pub caller_sandbox_id: Option<String>,
    pub claimed_sandbox_id: Option<String>,
    pub resource: Option<Resource>,
    pub verb: Option<String>,
}

impl AuthenticationEvent {
    /// A caller that never authenticated — a bad or missing credential.
    ///
    /// No caller kind, because none was established.
    #[must_use]
    pub fn unauthenticated(reason_code: impl Into<String>, error_info: AuditErrorInfo) -> Self {
        Self {
            reason_code: reason_code.into(),
            error_info,
            caller_kind: None,
            caller_sandbox_id: None,
            claimed_sandbox_id: None,
            resource: None,
            verb: None,
        }
    }

    /// A caller that authenticated and was still refused — the wrong caller
    /// kind for the RPC, or a sandbox binding that does not match the request.
    #[must_use]
    pub fn authenticated(
        caller_kind: impl Into<String>,
        reason_code: impl Into<String>,
        error_info: AuditErrorInfo,
    ) -> Self {
        Self {
            reason_code: reason_code.into(),
            error_info,
            caller_kind: Some(caller_kind.into()),
            caller_sandbox_id: None,
            claimed_sandbox_id: None,
            resource: None,
            verb: None,
        }
    }

    /// A supervisor credential bound to one sandbox, used on a request
    /// claiming another — one sandbox acting as another.
    ///
    /// A constructor rather than a builder because the caller kind is not a
    /// free choice: only a supervisor ever has a verified binding. Taking both
    /// ids together makes a half-recorded mismatch unrepresentable.
    #[must_use]
    pub fn sandbox_binding_mismatch(
        caller_sandbox_id: impl Into<String>,
        claimed_sandbox_id: impl Into<String>,
        reason_code: impl Into<String>,
        error_info: AuditErrorInfo,
    ) -> Self {
        Self {
            reason_code: reason_code.into(),
            error_info,
            caller_kind: Some(CallerKind::Supervisor.into()),
            caller_sandbox_id: Some(caller_sandbox_id.into()),
            claimed_sandbox_id: Some(claimed_sandbox_id.into()),
            resource: None,
            verb: None,
        }
    }

    /// What the refused call targeted, when the producer got far enough to
    /// know. A credential failure is refused before the body is parsed.
    #[must_use]
    pub fn with_target(mut self, resource: Resource, verb: impl Into<String>) -> Self {
        self.resource = Some(resource);
        self.verb = Some(verb.into());
        self
    }
}

impl TypedAuditEvent for AuthenticationEvent {
    fn event_type(&self) -> EventType {
        EventType::Authentication
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::Authentication, ctx.clone());
        // The caller's context carries the bundle live in this process, but
        // none was consulted to reach this outcome.
        event.bundle_digest = None;
        event.trust_root_id = None;
        event.bundle_id = None;
        event.policy_revision = None;
        event.signer_id = None;
        // The important clear of the two. The auth layer establishes only a
        // caller kind and a sandbox id, so a user, agent, workspace or session
        // could only have come from the request that just failed — letting an
        // attacker choose whose name appears on their own failed attempts.
        event.user_id = None;
        event.agent_id = None;
        event.workspace_id = None;
        event.session_id = None;
        event.outcome = Some(Outcome::Refused);
        event.reason_code = Some(self.reason_code);
        event.error_info = Some(self.error_info);
        event.caller_kind = self.caller_kind;
        event.caller_sandbox_id = self.caller_sandbox_id;
        event.claimed_sandbox_id = self.claimed_sandbox_id;
        event.resource = self.resource;
        event.verb = self.verb;
        validate(event)
    }
}

impl Display for AuthenticationEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self.caller_kind.as_deref() {
            Some(kind) => write!(formatter, "authentication {kind} ({})", self.reason_code),
            None => write!(
                formatter,
                "authentication unauthenticated ({})",
                self.reason_code
            ),
        }
    }
}

// ── policy lifecycle: verification and activation ─────────────────────────────

/// A signed bundle was checked — signature, manifest hashes, expiry, runtime
/// compatibility, counter regression. Verification success does not establish
/// activation; that is a separate [`PolicyActivationEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerificationEvent {
    pub outcome: Outcome,
    pub reason_code: String,
    pub error: Option<AuditErrorInfo>,
    pub rejection_reasons: Option<Vec<String>>,
}

impl PolicyVerificationEvent {
    #[must_use]
    pub fn new(outcome: Outcome, reason_code: impl Into<String>) -> Self {
        Self {
            outcome,
            reason_code: reason_code.into(),
            error: None,
            rejection_reasons: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }

    /// The verifier's structured rejection codes, normalized upstream.
    #[must_use]
    pub fn with_rejection_reasons(mut self, reasons: Vec<String>) -> Self {
        self.rejection_reasons = (!reasons.is_empty()).then_some(reasons);
        self
    }
}

impl TypedAuditEvent for PolicyVerificationEvent {
    fn event_type(&self) -> EventType {
        EventType::PolicyVerification
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::PolicyVerification, ctx.clone());
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.error_info = self.error;
        event.rejection_reasons = self.rejection_reasons;
        validate(event)
    }
}

impl Display for PolicyVerificationEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy_verification {} ({})",
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

/// A verified bundle was put into (or refused from) force: initial load,
/// hot-swap, or a refused activation — counter regression, persist failure,
/// compile failure. The digest names exactly which policy is now enforcing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyActivationEvent {
    pub outcome: Outcome,
    pub reason_code: String,
    pub error: Option<AuditErrorInfo>,
}

impl PolicyActivationEvent {
    #[must_use]
    pub fn new(outcome: Outcome, reason_code: impl Into<String>) -> Self {
        Self {
            outcome,
            reason_code: reason_code.into(),
            error: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }
}

impl TypedAuditEvent for PolicyActivationEvent {
    fn event_type(&self) -> EventType {
        EventType::PolicyActivation
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::PolicyActivation, ctx.clone());
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.error_info = self.error;
        validate(event)
    }
}

impl Display for PolicyActivationEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy_activation {} ({})",
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

// ── policy distribution and refresh ───────────────────────────────────────────

/// A policy document was requested from a serving surface: vended, refused
/// (unknown document, invalid request), or served degraded.
///
/// Carries no consumer identity — it records that a document was served, not
/// to whom. Producers suppress unchanged re-serves, so absence of a record is
/// not absence of a fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDistributionEvent {
    pub resource: Resource,
    pub verb: String,
    pub outcome: Outcome,
    pub reason_code: String,
    pub error: Option<AuditErrorInfo>,
}

impl PolicyDistributionEvent {
    #[must_use]
    pub fn new(
        resource: Resource,
        verb: impl Into<String>,
        outcome: Outcome,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            resource,
            verb: verb.into(),
            outcome,
            reason_code: reason_code.into(),
            error: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }
}

impl TypedAuditEvent for PolicyDistributionEvent {
    fn event_type(&self) -> EventType {
        EventType::PolicyDistribution
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::PolicyDistribution, ctx.clone());
        event.resource = Some(self.resource);
        event.verb = Some(self.verb);
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.error_info = self.error;
        validate(event)
    }
}

impl Display for PolicyDistributionEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy_distribution {} {} ({})",
            self.resource.id,
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

/// An operator asked the service to reload policy. Records the request; the
/// resulting load is its own verification/activation pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefreshEvent {
    pub outcome: Outcome,
    pub reason_code: String,
    pub error: Option<AuditErrorInfo>,
}

impl PolicyRefreshEvent {
    #[must_use]
    pub fn new(outcome: Outcome, reason_code: impl Into<String>) -> Self {
        Self {
            outcome,
            reason_code: reason_code.into(),
            error: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }
}

impl TypedAuditEvent for PolicyRefreshEvent {
    fn event_type(&self) -> EventType {
        EventType::PolicyRefresh
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::PolicyRefresh, ctx.clone());
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.error_info = self.error;
        validate(event)
    }
}

impl Display for PolicyRefreshEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy_refresh {} ({})",
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

// ── provenance signing ────────────────────────────────────────────────────────

/// Minting the provenance token that accompanies a vended document.
///
/// A failure here does not stop the document being served — it is served
/// unsigned, and this record is the only evidence of that degradation. That
/// is why this is not a rejection event: nothing was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceSigningEvent {
    pub outcome: Outcome,
    pub reason_code: String,
    pub error: Option<AuditErrorInfo>,
    pub served_unsigned: Option<bool>,
}

impl ProvenanceSigningEvent {
    #[must_use]
    pub fn new(outcome: Outcome, reason_code: impl Into<String>) -> Self {
        Self {
            outcome,
            reason_code: reason_code.into(),
            error: None,
            served_unsigned: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }

    /// The document went out anyway. Recorded explicitly because "signing
    /// failed" alone does not say whether the failure was load-bearing.
    #[must_use]
    pub fn served_unsigned(mut self) -> Self {
        self.served_unsigned = Some(true);
        self
    }
}

impl TypedAuditEvent for ProvenanceSigningEvent {
    fn event_type(&self) -> EventType {
        EventType::ProvenanceSigning
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::ProvenanceSigning, ctx.clone());
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.error_info = self.error;
        event.served_unsigned = self.served_unsigned;
        validate(event)
    }
}

impl Display for ProvenanceSigningEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "provenance_signing {} ({})",
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

// ── admission: injection, validation, governance ──────────────────────────────

/// Policy material was injected into a resource specification at admission:
/// patches prepared, provenance stamped. Records what the injection changed —
/// it does not prove the runtime applied it; [`AdmissionValidationEvent`]
/// later checks exactly that.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyInjectionEvent {
    pub resource: Resource,
    pub verb: String,
    pub outcome: Outcome,
    pub reason_code: String,
    pub error: Option<AuditErrorInfo>,
    pub effects: Option<Effects>,
}

impl PolicyInjectionEvent {
    #[must_use]
    pub fn new(
        resource: Resource,
        verb: impl Into<String>,
        outcome: Outcome,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            resource,
            verb: verb.into(),
            outcome,
            reason_code: reason_code.into(),
            error: None,
            effects: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }

    /// What the injection changed: patch count and paths, never values — a
    /// patch value is the policy content itself.
    #[must_use]
    pub fn with_effects(mut self, mut effects: Effects) -> Self {
        effects.truncate_patches();
        self.effects = (!effects.is_empty()).then_some(effects);
        self
    }
}

impl TypedAuditEvent for PolicyInjectionEvent {
    fn event_type(&self) -> EventType {
        EventType::PolicyInjection
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::PolicyInjection, ctx.clone());
        event.resource = Some(self.resource);
        event.verb = Some(self.verb);
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.error_info = self.error;
        event.effects = self.effects;
        validate(event)
    }
}

impl Display for PolicyInjectionEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy_injection {} {} ({})",
            self.resource.id,
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

/// The admission-time integrity check: is the specification still the one
/// policy injection produced?
///
/// `checks` records which comparisons actually ran — a validation that
/// skipped a check (e.g. no spec digest was present to compare) proves less
/// than one that performed it, and silence would count it as passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionValidationEvent {
    pub resource: Resource,
    pub verb: String,
    pub outcome: Outcome,
    pub reason_code: String,
    pub error: Option<AuditErrorInfo>,
    pub checks: Option<ValidationChecks>,
}

impl AdmissionValidationEvent {
    #[must_use]
    pub fn new(
        resource: Resource,
        verb: impl Into<String>,
        outcome: Outcome,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            resource,
            verb: verb.into(),
            outcome,
            reason_code: reason_code.into(),
            error: None,
            checks: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }

    #[must_use]
    pub fn with_checks(mut self, checks: ValidationChecks) -> Self {
        self.checks = (!checks.is_empty()).then_some(checks);
        self
    }
}

impl TypedAuditEvent for AdmissionValidationEvent {
    fn event_type(&self) -> EventType {
        EventType::AdmissionValidation
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::AdmissionValidation, ctx.clone());
        event.resource = Some(self.resource);
        event.verb = Some(self.verb);
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.error_info = self.error;
        event.checks = self.checks;
        validate(event)
    }
}

impl Display for AdmissionValidationEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "admission_validation {} {} ({})",
            self.resource.id,
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

/// A governance decision over configuration-changing operations:
/// approval-mode changes, direct policy mutation, deletion attempts.
///
/// Refusals here are governance, not authentication — the caller is who it
/// claims to be; the operation itself is what policy governs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigGovernanceEvent {
    pub verb: String,
    pub outcome: Outcome,
    pub reason_code: String,
    pub resource: Option<Resource>,
    pub error: Option<AuditErrorInfo>,
}

impl ConfigGovernanceEvent {
    #[must_use]
    pub fn new(verb: impl Into<String>, outcome: Outcome, reason_code: impl Into<String>) -> Self {
        Self {
            verb: verb.into(),
            outcome,
            reason_code: reason_code.into(),
            resource: None,
            error: None,
        }
    }

    #[must_use]
    pub fn with_resource(mut self, resource: Resource) -> Self {
        self.resource = Some(resource);
        self
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }
}

impl TypedAuditEvent for ConfigGovernanceEvent {
    fn event_type(&self) -> EventType {
        EventType::ConfigGovernance
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::ConfigGovernance, ctx.clone());
        event.verb = Some(self.verb);
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.resource = self.resource;
        event.error_info = self.error;
        validate(event)
    }
}

impl Display for ConfigGovernanceEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "config_governance {} {} ({})",
            self.verb,
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

// ── policy-service startup ────────────────────────────────────────────────────

/// The security state of the configuration the policy service started with.
///
/// Unlike every other typed event this one builds from a [`StartupContext`]
/// rather than an [`AuditContext`]: it is emitted during preflight, before a
/// bundle has been fetched or a trust root used, so there is no policy identity
/// to attach. It therefore does not implement [`TypedAuditEvent`], whose
/// signature assumes policy context is available.
///
/// Emit once per process start, including healthy starts — otherwise the
/// absence of a record is ambiguous between "booted secure" and "the audit
/// write failed". A startup record proves the security state at that moment
/// only; it does not prove continued enforcement of requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyServiceStartupEvent {
    pub reason_code: String,
    pub security_state: SecurityState,
    pub error: Option<AuditErrorInfo>,
}

impl PolicyServiceStartupEvent {
    /// A process that started with every configured control active.
    #[must_use]
    pub fn secure() -> Self {
        Self {
            reason_code: "startup.secure".to_owned(),
            security_state: SecurityState::Secure,
            error: None,
        }
    }

    /// A process serving with a control weakened — TLS disabled, provenance
    /// verification off, an ephemeral signing key.
    ///
    /// `error` is mandatory: recording that *something* was weakened without
    /// recording *which* control defeats the point of the event.
    #[must_use]
    pub fn degraded(reason_code: impl Into<String>, error: AuditErrorInfo) -> Self {
        Self {
            reason_code: reason_code.into(),
            security_state: SecurityState::Degraded,
            error: Some(error),
        }
    }

    /// A process that refused to start — preflight rejected the configuration.
    #[must_use]
    pub fn rejected(reason_code: impl Into<String>, error: AuditErrorInfo) -> Self {
        Self {
            reason_code: reason_code.into(),
            security_state: SecurityState::Rejected,
            error: Some(error),
        }
    }

    #[must_use]
    pub const fn event_type(&self) -> EventType {
        EventType::PolicyServiceStartup
    }

    /// # Errors
    ///
    /// Returns [`crate::ValidationError`] when the built event fails schema
    /// validation.
    pub fn into_audit_event(self, ctx: &StartupContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::from_startup(ctx);
        event.reason_code = Some(self.reason_code);
        event.security_state = Some(self.security_state);
        event.error_info = self.error;
        validate(event)
    }
}

impl Display for PolicyServiceStartupEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy_service_startup ({}, {})",
            self.security_state, self.reason_code
        )
    }
}

// ── reserved events (no producer yet; retained for vocabulary stability) ──────

/// RESERVED — no producer. A decision was deferred to human review; this
/// records the request for review, not its outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewRequestEvent {
    pub resource: Resource,
    pub verb: String,
    pub decision_id: String,
    pub reason_code: String,
    pub review_ref: Option<ReviewRef>,
}

impl ReviewRequestEvent {
    #[must_use]
    pub fn new(
        resource: Resource,
        verb: impl Into<String>,
        decision_id: impl Into<String>,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            resource,
            verb: verb.into(),
            decision_id: decision_id.into(),
            reason_code: reason_code.into(),
            review_ref: None,
        }
    }

    #[must_use]
    pub fn with_review_ref(mut self, review_ref: ReviewRef) -> Self {
        self.review_ref = Some(review_ref);
        self
    }
}

impl TypedAuditEvent for ReviewRequestEvent {
    fn event_type(&self) -> EventType {
        EventType::ReviewRequest
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::ReviewRequest, ctx.clone());
        event.resource = Some(self.resource);
        event.verb = Some(self.verb);
        event.decision_id = Some(self.decision_id);
        event.reason_code = Some(self.reason_code);
        event.outcome = Some(Outcome::Success);
        event.review_ref = self.review_ref;
        validate(event)
    }
}

impl Display for ReviewRequestEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "review_request {} {} ({})",
            self.resource.id, self.verb, self.reason_code
        )
    }
}

/// RESERVED — no producer. The outcome of a human review requested by
/// [`ReviewRequestEvent`]. Carries `decision` because it records a decision.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewDecisionEvent {
    pub review_ref: ReviewRef,
    pub decision: Decision,
    pub reason_code: String,
}

impl ReviewDecisionEvent {
    #[must_use]
    pub fn new(review_ref: ReviewRef, decision: Decision, reason_code: impl Into<String>) -> Self {
        Self {
            review_ref,
            decision,
            reason_code: reason_code.into(),
        }
    }
}

impl TypedAuditEvent for ReviewDecisionEvent {
    fn event_type(&self) -> EventType {
        EventType::ReviewDecision
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::ReviewDecision, ctx.clone());
        event.review_ref = Some(self.review_ref);
        event.decision = Some(self.decision);
        event.reason_code = Some(self.reason_code);
        validate(event)
    }
}

impl Display for ReviewDecisionEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "review_decision {} ({})",
            self.decision, self.reason_code
        )
    }
}

/// RESERVED — no producer. A credential was requested for a governed action:
/// issued (`outcome: success`) or refused (`outcome: refused`).
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialIssuanceEvent {
    pub resource: Resource,
    pub verb: String,
    pub outcome: Outcome,
    pub reason_code: String,
    pub credential_request_id: String,
    pub credential_scope: CredentialScope,
    pub error: Option<AuditErrorInfo>,
}

impl CredentialIssuanceEvent {
    #[must_use]
    pub fn new(
        resource: Resource,
        verb: impl Into<String>,
        outcome: Outcome,
        reason_code: impl Into<String>,
        credential_request_id: impl Into<String>,
        credential_scope: CredentialScope,
    ) -> Self {
        Self {
            resource,
            verb: verb.into(),
            outcome,
            reason_code: reason_code.into(),
            credential_request_id: credential_request_id.into(),
            credential_scope,
            error: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AuditErrorInfo) -> Self {
        self.error = Some(error);
        self
    }
}

impl TypedAuditEvent for CredentialIssuanceEvent {
    fn event_type(&self) -> EventType {
        EventType::CredentialIssuance
    }

    fn into_audit_event(self, ctx: &AuditContext) -> ValidationResult<AuditEvent> {
        let mut event = AuditEvent::new(EventType::CredentialIssuance, ctx.clone());
        event.resource = Some(self.resource);
        event.verb = Some(self.verb);
        event.outcome = Some(self.outcome);
        event.reason_code = Some(self.reason_code);
        event.credential_request_id = Some(self.credential_request_id);
        event.credential_scope = Some(self.credential_scope);
        event.error_info = self.error;
        validate(event)
    }
}

impl Display for CredentialIssuanceEvent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "credential_issuance {} {} ({})",
            self.resource.id,
            self.outcome.as_str(),
            self.reason_code
        )
    }
}

// ── shared helpers ────────────────────────────────────────────────────────────

/// The synthetic finding kind the OpenShell wire uses to carry a verdict.
///
/// The wire format has findings but no verdict field, so `map_findings` in
/// `apf-openshell-middleware` injects one of these on the allow path. Audit has
/// a real `verdict` field, so the stand-in is redundant here — and carrying
/// both double-counts the same advisory signal downstream.
pub(crate) const SYNTHETIC_VERDICT_FINDING_KIND: &str = "policy_verdict";

/// Drop the wire's synthetic verdict finding once a real `verdict` is set.
///
/// The middleware has both lists in scope at the call site — the real
/// detections, and the wire list that already contains the stand-in — and they
/// differ by one element of the same type. Filtering here means reaching for
/// the wrong one is harmless rather than a schema rejection at emit time.
fn drop_synthetic_verdict_finding(findings: &mut Vec<Finding>) {
    findings.retain(|finding| finding.kind != SYNTHETIC_VERDICT_FINDING_KIND);
}

fn validate(event: AuditEvent) -> ValidationResult<AuditEvent> {
    event.validate()?;
    Ok(event)
}
