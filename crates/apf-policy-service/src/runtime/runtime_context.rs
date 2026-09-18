// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Runtime-context payload parser.
//!
//! `VerifyBundleRequest.runtime_context` arrives as opaque bytes on the wire.
//! This module decodes the JSON envelope carrying the caller's attested identity
//! fields. The current form is unsigned — trust is established by `SO_PEERCRED`
//! on the Unix domain socket.

use serde::{Deserialize, Serialize};

/// Caller identity fields decoded from the opaque `runtime_context` bytes on a request.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct RuntimeContext {
    #[serde(default)]
    pub entra_subject: Option<String>,
    #[serde(default)]
    pub entra_email: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub gateway_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
}

impl RuntimeContext {
    /// Parse `runtime_context` bytes. Empty bytes -> all-None (caller decides
    /// whether to treat that as fatal). Non-empty must be JSON.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RuntimeContextError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let mut ctx: Self = serde_json::from_slice(bytes).map_err(RuntimeContextError::Json)?;
        ctx.sanitize_correlation_id();
        Ok(ctx)
    }

    /// Replace a caller-supplied `correlation_id` that audit could not carry.
    ///
    /// No emit path threads this context yet — every call site passes
    /// `default()`. Sanitizing here rather than at the emitter is what keeps it
    /// that way: an id failing the schema's `id` pattern fails validation, and
    /// emission is fail-closed, so once a caller's value does reach an event it
    /// would be a remote halt. An unusable id cannot be joined on anyway.
    fn sanitize_correlation_id(&mut self) {
        let Some(id) = &self.correlation_id else {
            return;
        };
        if is_valid_audit_id(id) {
            return;
        }
        let replacement = apf_audit::generate_correlation_id();
        // Length only: the value is untrusted and unbounded.
        tracing::warn!(
            supplied_len = id.len(),
            %replacement,
            "caller correlation_id is not a valid audit id; substituted"
        );
        self.correlation_id = Some(replacement);
    }

    /// True iff every field is None — no caller context was attested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entra_subject.is_none()
            && self.entra_email.is_none()
            && self.workspace_id.is_none()
            && self.gateway_id.is_none()
            && self.correlation_id.is_none()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeContextError {
    #[error("runtime_context JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Mirrors the audit schema's `id` profile.
fn is_valid_audit_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '@' | '/' | '+' | '-' | '=')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_is_empty_context() {
        let ctx = RuntimeContext::from_bytes(&[]).unwrap();
        assert!(ctx.is_empty());
    }

    #[test]
    fn parses_caller_context() {
        let json = br#"{
            "entra_subject":"3f9b8c2d-7e44-4f5a-9b12-8d3e6a1c5f80",
            "entra_email":"alice@example.com",
            "workspace_id":"ws-0abc",
            "gateway_id":"openshell-gateway",
            "correlation_id":"6379ee09"
        }"#;
        let ctx = RuntimeContext::from_bytes(json).unwrap();
        assert_eq!(ctx.entra_email.as_deref(), Some("alice@example.com"));
        assert_eq!(ctx.workspace_id.as_deref(), Some("ws-0abc"));
        assert!(!ctx.is_empty());
    }
}
