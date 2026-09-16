// SPDX-License-Identifier: Apache-2.0
//! Audit vocabulary for the extension trust boundary.
//!
//! Both OpenShell-facing listeners verify the same credential, so the events
//! live here rather than in each adapter. They are emitted under the calling
//! surface's own identity — the refusal belongs to the seam that made it, not
//! to a trust boundary that has no listener of its own.

use apf_audit::{
    AuditErrorInfo, AuthenticationEvent, CallerKind, ComponentAudit, TypedAuditEvent,
    join_rejection_detail,
};

use crate::{AuthorizationFailure, ExtensionCallerKind};

const CREDENTIAL_INVALID: &str = "extension_auth.credential_invalid";
const CALLER_UNAUTHENTICATED: &str = "extension_auth.caller_unauthenticated";
const CALLER_NOT_ALLOWED: &str = "extension_auth.caller_not_allowed";

/// Record a bearer credential this listener refused.
///
/// Best-effort: the refusal already happened and the caller is being turned
/// away either way. Failing the request because a log line did not write would
/// let a full disk deny valid callers.
///
/// # Errors
///
/// Returns the emission error for the caller to log.
pub fn emit_credential_invalid(audit: &ComponentAudit) -> Result<(), String> {
    // Nothing from the credential reaches the record. A rejected token is
    // attacker-supplied and unverified, so its claims name nothing that was
    // proven — and the raw token is a credential in its own right.
    emit(
        audit,
        AuthenticationEvent::unauthenticated(
            CREDENTIAL_INVALID,
            error(CREDENTIAL_INVALID, "bearer credential rejected"),
        ),
    )
}

/// Record a caller refused after the credential stage.
///
/// # Errors
///
/// Returns the emission error for the caller to log.
pub fn emit_authorization_failure(
    audit: &ComponentAudit,
    failure: AuthorizationFailure,
    caller_kind: Option<ExtensionCallerKind>,
) -> Result<(), String> {
    let event = match failure {
        // No caller was established, so there is no kind to name. Reaching
        // here means a runtime wrapped the service without the verifier.
        AuthorizationFailure::MissingCaller => AuthenticationEvent::unauthenticated(
            CALLER_UNAUTHENTICATED,
            error(
                CALLER_UNAUTHENTICATED,
                "no authenticated caller on the request",
            ),
        ),
        // Without a caller kind there is nothing proven to name, so this
        // degrades to the unauthenticated event rather than inventing one.
        AuthorizationFailure::CallerNotAllowed => match caller_kind {
            Some(kind) => AuthenticationEvent::authenticated(
                caller_kind_name(kind).as_str(),
                CALLER_NOT_ALLOWED,
                error(
                    CALLER_NOT_ALLOWED,
                    "caller kind is not permitted for this RPC",
                ),
            ),
            None => AuthenticationEvent::unauthenticated(
                CALLER_UNAUTHENTICATED,
                error(
                    CALLER_UNAUTHENTICATED,
                    "no authenticated caller on the request",
                ),
            ),
        },
    };
    emit(audit, event)
}

/// Map onto the audit crate's own vocabulary rather than restating the
/// strings: `authentication` records this field from two producers, and a second
/// spelling would let them disagree in one file. Exhaustive, so a new
/// extension caller kind fails to compile here.
fn caller_kind_name(kind: ExtensionCallerKind) -> CallerKind {
    match kind {
        ExtensionCallerKind::Gateway => CallerKind::Gateway,
        ExtensionCallerKind::Supervisor => CallerKind::Supervisor,
    }
}

fn error(code: &str, detail: &str) -> AuditErrorInfo {
    AuditErrorInfo {
        code: code.to_owned(),
        message: join_rejection_detail(&[detail.to_owned()]),
        retryable: Some(false),
    }
}

fn emit(audit: &ComponentAudit, event: AuthenticationEvent) -> Result<(), String> {
    // The digest is discarded: `authentication` clears every policy-identity field,
    // because a refusal at the trust boundary consulted no policy and must not
    // name the bundle that happens to be loaded.
    let Some(common) = audit.common("", None) else {
        return Ok(());
    };
    let event = event.into_audit_event(&common).map_err(|e| e.to_string())?;
    audit.emit_best_effort(&event)
}
