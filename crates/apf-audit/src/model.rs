// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

pub const SCHEMA_VERSION: &str = "apf.audit.event.v1";
const ID_MAX_BYTES: usize = 512;
const NAME_MAX_BYTES: usize = 128;
const DIGEST_MAX_BYTES: usize = 256;
const VERSION_MAX_BYTES: usize = 128;

pub type RedactedObject = BTreeMap<String, serde_json::Value>;
pub type AuditContextResult<T> = Result<T, AuditContextError>;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AuditContextError {
    #[error("audit context field {field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?
        .map(Some)
        .ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("null is not allowed for optional audit fields")
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Authorization,
    Authentication,
    PolicyVerification,
    PolicyActivation,
    PolicyDistribution,
    PolicyRefresh,
    ProvenanceSigning,
    PolicyInjection,
    AdmissionValidation,
    ConfigGovernance,
    PolicyServiceStartup,
    ReviewRequest,
    ReviewDecision,
    CredentialIssuance,
}

impl EventType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::Authentication => "authentication",
            Self::PolicyVerification => "policy_verification",
            Self::PolicyActivation => "policy_activation",
            Self::PolicyDistribution => "policy_distribution",
            Self::PolicyRefresh => "policy_refresh",
            Self::ProvenanceSigning => "provenance_signing",
            Self::PolicyInjection => "policy_injection",
            Self::AdmissionValidation => "admission_validation",
            Self::ConfigGovernance => "config_governance",
            Self::PolicyServiceStartup => "policy_service_startup",
            Self::ReviewRequest => "review_request",
            Self::ReviewDecision => "review_decision",
            Self::CredentialIssuance => "credential_issuance",
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Well-known caller classes for the OpenShell substrate, mirroring
/// `apf_openshell_auth::ExtensionCallerKind`.
///
/// A convenience for OpenShell producers, not a closed vocabulary: the audit
/// field is a plain string, because caller classes are defined by each
/// substrate's own authentication protocol and a closed list would reject an
/// auth denial from any other runtime outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerKind {
    Gateway,
    Supervisor,
}

impl CallerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Supervisor => "supervisor",
        }
    }
}

impl std::fmt::Display for CallerKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<CallerKind> for String {
    fn from(kind: CallerKind) -> Self {
        kind.as_str().to_owned()
    }
}

/// Resolved security state of the service's startup configuration.
///
/// `Degraded` is the consequential one: the process keeps serving with a
/// control deliberately or accidentally weakened, and nothing else in the
/// records it goes on to write would show that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityState {
    /// Every configured control is active.
    Secure,
    /// At least one control is weakened; the process continues to serve.
    Degraded,
    /// Preflight refused to start the process.
    Rejected,
}

impl SecurityState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Degraded => "degraded",
            Self::Rejected => "rejected",
        }
    }
}

impl std::fmt::Display for SecurityState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Severity of a policy finding, mirroring `apf_policy_eval::Severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An observation emitted alongside a decision by the policy engine's effect
/// stage. Findings do not change the decision — they record what was detected,
/// on allows and denies alike.
///
/// Mirrors `apf_policy_eval::Finding`. The conversion lives in the producer,
/// not here: `apf-audit` must not depend on `apf-policy-eval`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Finding category, from the `PolicyFinding` `type` field.
    pub kind: String,
    /// Specific label within the category. Static, or resolved at evaluation
    /// time from a `label_source` annotation.
    pub label: String,
    pub severity: Severity,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub confidence: Option<u8>,
}

impl Finding {
    #[must_use]
    pub fn new(kind: impl Into<String>, label: impl Into<String>, severity: Severity) -> Self {
        Self {
            kind: kind.into(),
            label: label.into(),
            severity,
            confidence: None,
        }
    }

    #[must_use]
    pub const fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

/// Schema cap on `error.message`.
pub const ERROR_MESSAGE_MAX_BYTES: usize = 1024;

/// Join rejection detail into an `error.message` that always fits the cap.
///
/// `verify_bundle` can return ten reasons at ~80 characters each, which
/// overflows the schema's 1024-byte limit. A `policy_verification` that fails to
/// serialize because its message was too long is the worst possible outcome —
/// the record for a rejected bundle is the one you cannot afford to lose — so
/// this truncates rather than letting the producer emit something invalid.
///
/// Reasons are kept in producer order, which for `verify_bundle` is its
/// deterministic check order. No severity ranking is imposed: the primary
/// cause is already carried separately in `reason_code`, and inventing an
/// ordering here would be a guess that drifts from the producer's.
///
/// Truncation is marked, so a reader can tell a complete message from a
/// clipped one, and never splits a UTF-8 character.
#[must_use]
pub fn join_rejection_detail(reasons: &[String]) -> String {
    let joined = reasons.join("; ");
    if joined.is_empty() {
        // `error.message` has minLength 1, so an empty join would invalidate
        // the whole event — the outcome this helper exists to prevent. Guard
        // the result rather than the input: `&[]` and `&[String::new()]` are
        // equally empty.
        return "no rejection detail recorded".to_owned();
    }
    if joined.len() <= ERROR_MESSAGE_MAX_BYTES {
        return joined;
    }

    // Reserve the widest marker that could be emitted, so the result cannot
    // exceed the cap regardless of how many end up omitted. One budget, not
    // two — an earlier version bounded selection separately from truncation,
    // which silently discarded half the allowance and made the truncation
    // branch unreachable.
    let reserve = format!(" [+{} more]", reasons.len()).len();
    let budget = ERROR_MESSAGE_MAX_BYTES - reserve;

    let (mut kept, mut used) = (0usize, 0usize);
    for reason in reasons {
        let addition = if kept == 0 {
            reason.len()
        } else {
            reason.len() + SEPARATOR_BYTES
        };
        if used + addition > budget {
            break;
        }
        used += addition;
        kept += 1;
    }
    let marker = format!(" [+{} more]", reasons.len() - kept);

    if kept == 0 {
        // A single reason overruns the whole budget — a serde error with
        // context does this routinely. Keep a prefix of it rather than
        // emitting a marker with no diagnostic content at all.
        //
        // The marker counts only the reasons NOT shown: reasons[0] is
        // displayed, truncated, so counting it as omitted would tell a reader
        // there is another reason when they are looking at it.
        let head = &reasons[0];
        let clipped = if reasons.len() == 1 {
            "…".to_owned()
        } else {
            format!("… [+{} more]", reasons.len() - 1)
        };
        let mut cut = (ERROR_MESSAGE_MAX_BYTES - clipped.len()).min(head.len());
        while cut > 0 && !head.is_char_boundary(cut) {
            cut -= 1;
        }
        return format!("{}{clipped}", &head[..cut]);
    }

    format!("{}{marker}", reasons[..kept].join("; "))
}

/// Reduce raw verifier detail to the normalized codes the schema accepts.
///
/// `VerifyOutcome.rejection_reasons` and `AuditEvent.rejection_reasons` share a
/// name and assignment-compatible types but have incompatible domains: the
/// verifier pushes prose (`"counter_regression: bundle counter 5 <= 7"`), while
/// the schema requires `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`. Assigning one
/// to the other compiles and produces a record that fails validation on every
/// element, so this is the conversion producers must go through.
///
/// Takes the text before the first `:`, drops anything that is not a valid
/// reason code, deduplicates preserving first-seen order — `verify_bundle`
/// pushes per manifest entry and per adapter, so the same code legitimately
/// repeats — and truncates to the schema's `maxItems`.
#[must_use]
pub fn normalize_rejection_reasons(reasons: &[String]) -> Vec<String> {
    let mut seen = Vec::with_capacity(reasons.len().min(MAX_REJECTION_REASONS));
    for reason in reasons {
        let code = reason.split(':').next().unwrap_or_default().trim();
        if code.is_empty() || !is_reason_code(code) {
            continue;
        }
        if !seen.iter().any(|kept: &String| kept == code) {
            seen.push(code.to_owned());
        }
        if seen.len() == MAX_REJECTION_REASONS {
            break;
        }
    }
    seen
}

/// Schema cap on `rejection_reasons`.
pub const MAX_REJECTION_REASONS: usize = 16;

/// Schema cap on a single `reason_code`.
pub const REASON_CODE_MAX_BYTES: usize = 160;

const SEPARATOR_BYTES: usize = 2; // "; "

fn is_reason_code(value: &str) -> bool {
    // Mirrors every constraint on `$defs/reason_code`, not only the pattern.
    // Omitting the length bound let the normalizer return a code the schema
    // then rejected — defeating the point of a conversion that exists to
    // guarantee valid output.
    if value.is_empty() || value.len() > REASON_CODE_MAX_BYTES {
        return false;
    }
    let mut segments = value.split('.');
    segments.all(|segment| {
        let mut chars = segment.chars();
        chars.next().is_some_and(|first| first.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    })
}

/// How a header was changed. Mirrors `apf_policy_eval::HeaderAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderAction {
    Set,
    Add,
    Remove,
}

impl HeaderAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Add => "add",
            Self::Remove => "remove",
        }
    }
}

impl std::fmt::Display for HeaderAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One applied header mutation.
///
/// Carries the header NAME and the action, never the value — an injected
/// credential is precisely what would be in the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMutationRecord {
    pub name: String,
    pub action: HeaderAction,
}

impl HeaderMutationRecord {
    #[must_use]
    pub fn new(name: impl Into<String>, action: HeaderAction) -> Self {
        Self {
            name: name.into(),
            action,
        }
    }
}

/// Body patch operation, mirroring `apf_policy_eval::PatchOp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchOp {
    Replace,
    Add,
    Remove,
}

impl PatchOp {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Add => "add",
            Self::Remove => "remove",
        }
    }
}

impl std::fmt::Display for PatchOp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One applied body patch.
///
/// Carries the target path and the operation, never the value — a patch value
/// is the sensitive content the redaction exists to remove. Parallel to
/// [`HeaderMutationRecord`]: replaced and removed are different answers to what
/// the request looked like when it left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchRecord {
    pub path: String,
    pub op: PatchOp,
}

impl PatchRecord {
    #[must_use]
    pub fn new(path: impl Into<String>, op: PatchOp) -> Self {
        Self {
            path: path.into(),
            op,
        }
    }
}

/// Upper bound on recorded patches, matching the schema's `maxItems`.
///
/// The engine applies patches with no cap of its own, so without truncation a
/// broad redaction policy would produce an event that fails validation, losing
/// the record of a rewrite that already went out. `patch_count` stays exact.
pub const MAX_RECORDED_PATCHES: usize = 64;

/// What an enforcement point applied to a request in flight.
///
/// Distinct from [`Obligations`], which records what policy *required*: merged,
/// an unapplied obligation would be indistinguishable from an applied one.
///
/// Records paths and header names only. A patch value is the sensitive content
/// the redaction exists to remove, so recording it here would defeat the very
/// effect being recorded.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Effects {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patches: Vec<PatchRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_replaced: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_mutations: Vec<HeaderMutationRecord>,
}

impl Effects {
    /// `true` when nothing was applied, so producers can omit the field rather
    /// than emit an empty object that reads as "we changed something".
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patch_count.unwrap_or(0) == 0
            && self.patches.is_empty()
            && !self.payload_replaced.unwrap_or(false)
            && self.header_mutations.is_empty()
    }

    /// Drop recorded patches beyond [`MAX_RECORDED_PATCHES`], leaving
    /// `patch_count` exact.
    ///
    /// Public so a producer assembling an [`AuditEvent`] directly has a way to
    /// comply with the cap it can already read.
    pub fn truncate_patches(&mut self) {
        self.patches.truncate(MAX_RECORDED_PATCHES);
    }
}

/// Result of an operation event. `Refused` is a deliberate rejection by
/// policy, integrity or governance checks; `Failure` is an operational error,
/// not a judgement. Authorization events carry [`Decision`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Refused,
}

impl Outcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Refused => "refused",
        }
    }
}

/// Which integrity checks a validation actually ran. A skipped check proves
/// less than a performed one, and silence would count it as passed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationChecks {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub performed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
}

impl ValidationChecks {
    /// `true` when nothing was recorded, so producers can omit the field.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.performed.is_empty() && self.skipped.is_empty()
    }
}

/// Advisory signal accompanying a decision, mirroring `apf_policy_eval::Verdict`.
///
/// Orthogonal to [`Decision`]: `Warn` is an allow with elevated signal, not a
/// different authorization outcome. Without this field a warn is
/// indistinguishable from a plain allow in the record.
///
/// Ordered by severity, matching `apf_policy_eval::Verdict` — upstream
/// aggregates concurrent effects with `.max()`, so a consumer computing the
/// strongest verdict across a correlation must not have to hand-roll a rank
/// that can drift. Deliberately not `Default`: `Option<Verdict>` already
/// carries "unset", and an audit field should not silently default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Warn,
    Escalate,
}

impl Verdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Escalate => "escalate",
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireReview,
    RequireStepUp,
    Quarantine,
    StopSession,
}

impl Decision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireReview => "require_review",
            Self::RequireStepUp => "require_step_up",
            Self::Quarantine => "quarantine",
            Self::StopSession => "stop_session",
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultClass {
    Success,
    Failure,
    Denied,
    Partial,
    Timeout,
    Scrubbed,
}

impl ResultClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Partial => "partial",
            Self::Timeout => "timeout",
            Self::Scrubbed => "scrubbed",
        }
    }
}

impl std::fmt::Display for ResultClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub instance_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub workload_identity: Option<String>,
}

impl Component {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            instance_id: instance_id.into(),
            workload_identity: None,
        }
    }
}

/// Envelope-only context for events emitted before any policy is loaded.
///
/// [`CommonFields`] requires `bundle_digest` and `trust_root_id`, which do not
/// exist during process preflight — the bundle has not been fetched and no
/// trust root has been used to verify anything yet. `policy_service_startup`
/// events are emitted from that window, so they carry only the envelope the
/// schema requires of every event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupContext {
    pub correlation_id: String,
    pub enforcement_point_id: String,
    pub runtime_substrate: String,
    pub component: Component,
}

impl StartupContext {
    /// # Errors
    ///
    /// Returns [`AuditContextError`] when an identifier is empty, over-long, or
    /// otherwise outside the schema's `id`/`name` profiles.
    pub fn new(
        correlation_id: impl Into<String>,
        enforcement_point_id: impl Into<String>,
        runtime_substrate: impl Into<String>,
        component: Component,
    ) -> AuditContextResult<Self> {
        let correlation_id = correlation_id.into();
        let enforcement_point_id = enforcement_point_id.into();
        let runtime_substrate = runtime_substrate.into();
        require_id("correlation_id", &correlation_id)?;
        require_id("enforcement_point_id", &enforcement_point_id)?;
        require_name("runtime_substrate", &runtime_substrate)?;
        validate_component(&component)?;

        Ok(Self {
            correlation_id,
            enforcement_point_id,
            runtime_substrate,
            component,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonFields {
    pub correlation_id: String,
    pub user_id: Option<String>,
    pub agent_id: Option<String>,
    pub workspace_id: Option<String>,
    pub session_id: Option<String>,
    pub enforcement_point_id: String,
    pub runtime_substrate: String,
    pub component: Component,
    pub bundle_digest: String,
    /// Monotonic policy revision of the bundle in force. `None` when the
    /// bundle could not be parsed (e.g. signature or parse failure), since an
    /// unparsed bundle has no readable revision. Identity is `bundle_digest`.
    pub policy_revision: Option<u64>,
    pub trust_root_id: String,
    pub causation_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub device_id: Option<String>,
    pub deployment_profile: Option<String>,
    pub bundle_id: Option<String>,
    pub signer_id: Option<String>,
}

impl CommonFields {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        correlation_id: impl Into<String>,
        user_id: impl Into<String>,
        agent_id: impl Into<String>,
        workspace_id: impl Into<String>,
        session_id: impl Into<String>,
        enforcement_point_id: impl Into<String>,
        runtime_substrate: impl Into<String>,
        component: Component,
        bundle_digest: impl Into<String>,
        trust_root_id: impl Into<String>,
    ) -> Self {
        let mut common = Self::new_without_subject(
            correlation_id,
            enforcement_point_id,
            runtime_substrate,
            component,
            bundle_digest,
            trust_root_id,
        );
        common.user_id = Some(user_id.into());
        common.agent_id = Some(agent_id.into());
        common.workspace_id = Some(workspace_id.into());
        common.session_id = Some(session_id.into());
        common
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_without_subject(
        correlation_id: impl Into<String>,
        enforcement_point_id: impl Into<String>,
        runtime_substrate: impl Into<String>,
        component: Component,
        bundle_digest: impl Into<String>,
        trust_root_id: impl Into<String>,
    ) -> Self {
        Self {
            correlation_id: correlation_id.into(),
            user_id: None,
            agent_id: None,
            workspace_id: None,
            session_id: None,
            enforcement_point_id: enforcement_point_id.into(),
            runtime_substrate: runtime_substrate.into(),
            component,
            bundle_digest: bundle_digest.into(),
            policy_revision: None,
            trust_root_id: trust_root_id.into(),
            causation_id: None,
            trace_id: None,
            span_id: None,
            device_id: None,
            deployment_profile: None,
            bundle_id: None,
            signer_id: None,
        }
    }
}

pub type AuditContext = CommonFields;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectIdentity {
    user_id: String,
    agent_id: String,
    workspace_id: String,
    session_id: String,
    device_id: Option<String>,
    deployment_profile: Option<String>,
}

impl SubjectIdentity {
    pub fn new(
        user_id: impl Into<String>,
        agent_id: impl Into<String>,
        workspace_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> AuditContextResult<Self> {
        let user_id = user_id.into();
        let agent_id = agent_id.into();
        let workspace_id = workspace_id.into();
        let session_id = session_id.into();
        require_id("user_id", &user_id)?;
        require_id("agent_id", &agent_id)?;
        require_id("workspace_id", &workspace_id)?;
        require_id("session_id", &session_id)?;

        Ok(Self {
            user_id,
            agent_id,
            workspace_id,
            session_id,
            device_id: None,
            deployment_profile: None,
        })
    }

    pub fn with_device_id(mut self, device_id: impl Into<String>) -> AuditContextResult<Self> {
        let device_id = device_id.into();
        require_id("device_id", &device_id)?;
        self.device_id = Some(device_id);
        Ok(self)
    }

    pub fn with_deployment_profile(
        mut self,
        deployment_profile: impl Into<String>,
    ) -> AuditContextResult<Self> {
        let deployment_profile = deployment_profile.into();
        require_name("deployment_profile", &deployment_profile)?;
        self.deployment_profile = Some(deployment_profile);
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentity {
    bundle_digest: String,
    policy_revision: Option<u64>,
    trust_root_id: String,
    bundle_id: Option<String>,
    signer_id: Option<String>,
}

impl PolicyIdentity {
    pub fn new(
        bundle_digest: impl Into<String>,
        trust_root_id: impl Into<String>,
    ) -> AuditContextResult<Self> {
        let bundle_digest = bundle_digest.into();
        let trust_root_id = trust_root_id.into();
        require_digest("bundle_digest", &bundle_digest)?;
        require_id("trust_root_id", &trust_root_id)?;

        Ok(Self {
            bundle_digest,
            policy_revision: None,
            trust_root_id,
            bundle_id: None,
            signer_id: None,
        })
    }

    /// Attach the bundle's monotonic policy revision.
    ///
    /// Omit this when the bundle could not be parsed — a rejected bundle has
    /// no readable revision, and `VerifyOutcome::monotonic_counter` is `0` in
    /// that case, which is a real revision value rather than a sentinel.
    #[must_use]
    pub fn with_policy_revision(mut self, policy_revision: u64) -> Self {
        self.policy_revision = Some(policy_revision);
        self
    }

    pub fn with_bundle_id(mut self, bundle_id: impl Into<String>) -> AuditContextResult<Self> {
        let bundle_id = bundle_id.into();
        require_id("bundle_id", &bundle_id)?;
        self.bundle_id = Some(bundle_id);
        Ok(self)
    }

    pub fn with_signer_id(mut self, signer_id: impl Into<String>) -> AuditContextResult<Self> {
        let signer_id = signer_id.into();
        require_id("signer_id", &signer_id)?;
        self.signer_id = Some(signer_id);
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditContextTemplate {
    correlation_id: String,
    subject: SubjectIdentity,
    runtime_substrate: String,
    policy: PolicyIdentity,
    trace_id: Option<String>,
    span_id: Option<String>,
}

impl AuditContextTemplate {
    pub fn new(
        correlation_id: impl Into<String>,
        subject: SubjectIdentity,
        runtime_substrate: impl Into<String>,
        policy: PolicyIdentity,
    ) -> AuditContextResult<Self> {
        let correlation_id = correlation_id.into();
        let runtime_substrate = runtime_substrate.into();
        require_id("correlation_id", &correlation_id)?;
        require_name("runtime_substrate", &runtime_substrate)?;

        Ok(Self {
            correlation_id,
            subject,
            runtime_substrate,
            policy,
            trace_id: None,
            span_id: None,
        })
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    pub fn with_trace(
        mut self,
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
    ) -> AuditContextResult<Self> {
        let trace_id = trace_id.into();
        let span_id = span_id.into();
        require_id("trace_id", &trace_id)?;
        require_id("span_id", &span_id)?;
        self.trace_id = Some(trace_id);
        self.span_id = Some(span_id);
        Ok(self)
    }

    pub fn for_component(
        &self,
        enforcement_point_id: impl Into<String>,
        component: Component,
    ) -> AuditContextResult<AuditContext> {
        let enforcement_point_id = enforcement_point_id.into();
        require_id("enforcement_point_id", &enforcement_point_id)?;
        validate_component(&component)?;

        let mut ctx = CommonFields::new(
            &self.correlation_id,
            &self.subject.user_id,
            &self.subject.agent_id,
            &self.subject.workspace_id,
            &self.subject.session_id,
            enforcement_point_id,
            &self.runtime_substrate,
            component,
            &self.policy.bundle_digest,
            &self.policy.trust_root_id,
        );
        ctx.policy_revision = self.policy.policy_revision;
        ctx.device_id.clone_from(&self.subject.device_id);
        ctx.deployment_profile
            .clone_from(&self.subject.deployment_profile);
        ctx.bundle_id.clone_from(&self.policy.bundle_id);
        ctx.signer_id.clone_from(&self.policy.signer_id);
        ctx.trace_id.clone_from(&self.trace_id);
        ctx.span_id.clone_from(&self.span_id);
        Ok(ctx)
    }

    pub fn for_component_with_causation(
        &self,
        enforcement_point_id: impl Into<String>,
        component: Component,
        causation_id: impl Into<String>,
    ) -> AuditContextResult<AuditContext> {
        let causation_id = causation_id.into();
        require_id("causation_id", &causation_id)?;
        let mut ctx = self.for_component(enforcement_point_id, component)?;
        ctx.causation_id = Some(causation_id);
        Ok(ctx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationContext {
    correlation: String,
    causation: Option<String>,
    trace: Option<String>,
    span: Option<String>,
}

impl CorrelationContext {
    #[must_use]
    pub fn root() -> Self {
        Self {
            correlation: generate_correlation_id(),
            causation: None,
            trace: None,
            span: None,
        }
    }

    pub fn new(correlation_id: impl Into<String>) -> AuditContextResult<Self> {
        let correlation_id = correlation_id.into();
        require_id("correlation_id", &correlation_id)?;
        Ok(Self {
            correlation: correlation_id,
            causation: None,
            trace: None,
            span: None,
        })
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation
    }

    #[must_use]
    pub fn causation_id(&self) -> Option<&str> {
        self.causation.as_deref()
    }

    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace.as_deref()
    }

    #[must_use]
    pub fn span_id(&self) -> Option<&str> {
        self.span.as_deref()
    }

    pub fn with_causation(mut self, causation_id: impl Into<String>) -> AuditContextResult<Self> {
        let causation_id = causation_id.into();
        require_id("causation_id", &causation_id)?;
        self.causation = Some(causation_id);
        Ok(self)
    }

    pub fn with_trace(
        mut self,
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
    ) -> AuditContextResult<Self> {
        let trace_id = trace_id.into();
        let span_id = span_id.into();
        require_id("trace_id", &trace_id)?;
        require_id("span_id", &span_id)?;
        self.trace = Some(trace_id);
        self.span = Some(span_id);
        Ok(self)
    }

    pub fn apply_to(&self, event: &mut AuditEvent) {
        event.correlation_id.clone_from(&self.correlation);
        event.causation_id.clone_from(&self.causation);
        event.trace_id.clone_from(&self.trace);
        event.span_id.clone_from(&self.span);
    }
}

fn validate_component(component: &Component) -> AuditContextResult<()> {
    require_name("component.name", &component.name)?;
    require_version("component.version", &component.version)?;
    require_id("component.instance_id", &component.instance_id)?;
    if let Some(workload_identity) = &component.workload_identity {
        require_id("component.workload_identity", workload_identity)?;
    }
    Ok(())
}

fn require_id(field: &'static str, value: &str) -> AuditContextResult<()> {
    require_patterned_value(
        field,
        value,
        ID_MAX_BYTES,
        "must match APF id syntax",
        |character| character.is_ascii_alphanumeric(),
        |character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | ':' | '@' | '/' | '+' | '-' | '=')
        },
    )
}

fn require_name(field: &'static str, value: &str) -> AuditContextResult<()> {
    require_patterned_value(
        field,
        value,
        NAME_MAX_BYTES,
        "must match APF name syntax",
        |character| character.is_ascii_alphanumeric(),
        |character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-'),
    )
}

fn require_digest(field: &'static str, value: &str) -> AuditContextResult<()> {
    require_patterned_value(
        field,
        value,
        DIGEST_MAX_BYTES,
        "must match APF digest syntax",
        |character| character.is_ascii_alphanumeric(),
        |character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | ':' | '@' | '/' | '+' | '-' | '=')
        },
    )
}

fn require_version(field: &'static str, value: &str) -> AuditContextResult<()> {
    if value.is_empty() {
        return Err(invalid_field(field, value, "must not be empty"));
    }
    if value.len() > VERSION_MAX_BYTES {
        return Err(invalid_field(field, value, "exceeds maximum length"));
    }
    Ok(())
}

fn require_patterned_value<F, G>(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    reason: &'static str,
    valid_first: F,
    valid_rest: G,
) -> AuditContextResult<()>
where
    F: Fn(char) -> bool,
    G: Fn(char) -> bool,
{
    if value.is_empty() {
        return Err(invalid_field(field, value, "must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(invalid_field(field, value, "exceeds maximum length"));
    }

    let mut characters = value.chars();
    let first = characters
        .next()
        .expect("non-empty string should have first character");
    if !valid_first(first) || !characters.all(valid_rest) {
        return Err(invalid_field(field, value, reason));
    }

    Ok(())
}

fn invalid_field(field: &'static str, _value: &str, reason: &'static str) -> AuditContextError {
    AuditContextError::InvalidField { field, reason }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
    #[serde(
        default,
        rename = "class",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub resource_class: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub instance: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub data_class: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub tenant: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub attributes: Option<BTreeMap<String, String>>,
}

impl Resource {
    #[must_use]
    pub fn new(resource_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            id: id.into(),
            resource_class: None,
            instance: None,
            data_class: None,
            tenant: None,
            attributes: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligations {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub credential_scope: Option<CredentialScope>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub redaction_profile: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub max_result_size: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub allowed_destination: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub rate_limit: Option<RateLimit>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub audit_level: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub review_required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialScope {
    pub provider: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub mode: Option<String>,
    pub audience: String,
    pub scopes: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub ttl_seconds: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub expires_at: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub decision_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub limit: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub window_seconds: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRef {
    pub review_id: String,
    pub status: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub reviewer_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub decision_at: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditErrorInfo {
    pub code: String,
    pub message: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub retryable: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub sink_type: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub attempt: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub buffered: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub replay: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub schema_version: String,
    pub event_id: String,
    pub timestamp: String,
    pub event_type: EventType,
    pub correlation_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub causation_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub trace_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub span_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub user_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub agent_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub device_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub workspace_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub session_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub deployment_profile: Option<String>,
    pub enforcement_point_id: String,
    pub runtime_substrate: String,
    pub component: Component,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub bundle_digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub bundle_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub policy_revision: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub signer_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub trust_root_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub resource: Option<Resource>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub verb: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub argument_summary: Option<RedactedObject>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub decision: Option<Decision>,
    /// Result of an operation event; never combined with `decision`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub outcome: Option<Outcome>,
    /// provenance_signing only: the document was served despite the failure.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub served_unsigned: Option<bool>,
    /// admission_validation only: which checks ran and which could not.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub checks: Option<ValidationChecks>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub decision_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub reason_code: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub security_state: Option<SecurityState>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub findings: Option<Vec<Finding>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub verdict: Option<Verdict>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub effects: Option<Effects>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub rejection_reasons: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub reason: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub obligations: Option<Obligations>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub credential_scope: Option<CredentialScope>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub credential_request_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub result_class: Option<ResultClass>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub caller_kind: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub caller_sandbox_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub claimed_sandbox_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub result_summary: Option<RedactedObject>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub review_ref: Option<ReviewRef>,
    #[serde(
        default,
        rename = "error",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub error_info: Option<AuditErrorInfo>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub delivery: Option<Delivery>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    pub extensions: Option<BTreeMap<String, RedactedObject>>,
}

impl AuditEvent {
    #[must_use]
    pub fn new(event_type: EventType, common: CommonFields) -> Self {
        Self::with_ids(event_type, common, generate_event_id(), utc_timestamp_now())
    }

    /// Record why a bundle or startup preflight was rejected, dropping the
    /// field when no reason survives normalization.
    ///
    /// [`normalize_rejection_reasons`] yields an empty vector when every reason
    /// is prose rather than a code, and the schema requires at least one entry —
    /// so assigning it directly would destroy the record of a real rejection.
    /// The prose belongs in `error.message` via [`join_rejection_detail`].
    pub fn set_rejection_reasons(&mut self, reasons: Vec<String>) {
        self.rejection_reasons = (!reasons.is_empty()).then_some(reasons);
    }

    /// Build an `policy_service_startup` event from a [`StartupContext`], with every
    /// policy-identity field absent.
    ///
    /// The event type is fixed rather than a parameter: this constructor exists
    /// only for events emitted during preflight, before a bundle has been
    /// fetched or a trust root used. Accepting an arbitrary [`EventType`] would
    /// let a caller mint, say, a `credential_issuance` record with no policy
    /// identity — and the schema would accept it, because credential events are
    /// not covered by the bundle-context requirement.
    #[must_use]
    pub fn from_startup(ctx: &StartupContext) -> Self {
        Self::from_startup_with_ids(ctx, generate_event_id(), utc_timestamp_now())
    }

    #[must_use]
    pub fn from_startup_with_ids(
        ctx: &StartupContext,
        event_id: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        let common = CommonFields::new_without_subject(
            ctx.correlation_id.clone(),
            ctx.enforcement_point_id.clone(),
            ctx.runtime_substrate.clone(),
            ctx.component.clone(),
            // Placeholders: every policy-identity field is cleared below.
            // `CommonFields` requires these as `String`; a startup event has
            // no policy to identify.
            String::new(),
            String::new(),
        );
        let mut event =
            Self::with_ids(EventType::PolicyServiceStartup, common, event_id, timestamp);
        event.bundle_digest = None;
        event.bundle_id = None;
        event.policy_revision = None;
        event.signer_id = None;
        event.trust_root_id = None;
        event
    }

    #[must_use]
    pub fn with_ids(
        event_type: EventType,
        common: CommonFields,
        event_id: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            event_id: event_id.into(),
            timestamp: timestamp.into(),
            event_type,
            correlation_id: common.correlation_id,
            causation_id: common.causation_id,
            trace_id: common.trace_id,
            span_id: common.span_id,
            user_id: common.user_id,
            agent_id: common.agent_id,
            device_id: common.device_id,
            workspace_id: common.workspace_id,
            session_id: common.session_id,
            deployment_profile: common.deployment_profile,
            enforcement_point_id: common.enforcement_point_id,
            runtime_substrate: common.runtime_substrate,
            component: common.component,
            bundle_digest: Some(common.bundle_digest),
            bundle_id: common.bundle_id,
            policy_revision: common.policy_revision,
            signer_id: common.signer_id,
            trust_root_id: Some(common.trust_root_id),
            resource: None,
            verb: None,
            argument_summary: None,
            decision: None,
            outcome: None,
            served_unsigned: None,
            checks: None,
            decision_id: None,
            reason_code: None,
            security_state: None,
            findings: None,
            verdict: None,
            effects: None,
            rejection_reasons: None,
            reason: None,
            obligations: None,
            credential_scope: None,
            credential_request_id: None,
            result_class: None,
            caller_kind: None,
            caller_sandbox_id: None,
            claimed_sandbox_id: None,
            result_summary: None,
            review_ref: None,
            error_info: None,
            delivery: None,
            extensions: None,
        }
    }
}

#[must_use]
pub fn generate_event_id() -> String {
    generate_prefixed_id("evt")
}

#[must_use]
pub fn generate_correlation_id() -> String {
    generate_prefixed_id("corr")
}

#[must_use]
pub fn generate_request_id() -> String {
    generate_prefixed_id("req")
}

#[must_use]
pub fn generate_decision_id() -> String {
    generate_prefixed_id("dec")
}

#[must_use]
pub fn generate_credential_request_id() -> String {
    generate_prefixed_id("credreq")
}

fn generate_prefixed_id(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4().simple())
}

#[must_use]
pub fn utc_timestamp_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC RFC3339 timestamp formatting should not fail")
}
