// SPDX-License-Identifier: Apache-2.0
//! Shared APF audit event model, validator, and v0 JSONL emitter.

mod coercion;
mod component;
mod emitter;
mod events;
mod host;
mod model;
mod redaction;
mod sanitization;
pub mod span;
mod subscriber;
mod validation;

/// Canonical JSON Schema document for `apf.audit.event.v1`.
pub const AUDIT_EVENT_SCHEMA_JSON: &str =
    include_str!("../../../contracts/audit/apf.audit.event.v1.schema.json");

pub use coercion::{UNSPECIFIED, coerce_digest, coerce_id, coerce_lower_dotted, coerce_name};
pub use component::{AuditIdentity, ComponentAudit};
pub use emitter::{AuditEmitter, AuditError, AuditSink, EmitOutcome, JsonlSink};
pub use events::{
    AdmissionValidationEvent, AuthenticationEvent, AuthorizationEvent, ConfigGovernanceEvent,
    CredentialIssuanceEvent, PolicyActivationEvent, PolicyDistributionEvent, PolicyInjectionEvent,
    PolicyRefreshEvent, PolicyServiceStartupEvent, PolicyVerificationEvent, ProvenanceSigningEvent,
    ReviewDecisionEvent, ReviewRequestEvent, TypedAuditEvent,
};
pub use host::host_qualified_instance_id;
pub use model::{
    AuditContext, AuditContextError, AuditContextResult, AuditContextTemplate, AuditErrorInfo,
    AuditEvent, CallerKind, CommonFields, Component, CorrelationContext, CredentialScope, Decision,
    Delivery, ERROR_MESSAGE_MAX_BYTES, Effects, EventType, Finding, HeaderAction,
    HeaderMutationRecord, MAX_RECORDED_PATCHES, MAX_REJECTION_REASONS, Obligations, Outcome,
    PatchOp, PatchRecord, PolicyIdentity, REASON_CODE_MAX_BYTES, RateLimit, RedactedObject,
    Resource, ResultClass, ReviewRef, SCHEMA_VERSION, SecurityState, Severity, StartupContext,
    SubjectIdentity, ValidationChecks, Verdict, generate_correlation_id,
    generate_credential_request_id, generate_decision_id, generate_event_id, generate_request_id,
    join_rejection_detail, normalize_rejection_reasons,
};
pub use redaction::{RedactionError, RedactionProfile, redact};
pub use sanitization::{SanitizationError, SanitizationGuard};
pub use subscriber::{ApfObservation, ApfObservationKind, ApfObservationSink, ApfTracingLayer};
pub use validation::{ValidationError, ValidationResult};
