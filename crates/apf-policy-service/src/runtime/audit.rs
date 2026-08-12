// SPDX-License-Identifier: Apache-2.0
//! Policy lifecycle audit emission.
//!
//! Audit wiring is deferred to the M5 audit milestone. All methods are no-ops
//! until the apf-audit crate is integrated and emission ownership between
//! policy-service (bundle lifecycle) and policy-gateway (evaluation events)
//! is established.

use crate::runtime::runtime_context::RuntimeContext;
use apf_bundle::{Bundle, VerifyOutcome};

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
    _reason_code: String,
    _message: String,
    retryable: bool,
    bundle_counter: Option<u64>,
    metadata_source: String,
}

impl PolicyRejectAudit {
    pub fn new(reason_code: &str, message: String) -> Self {
        Self {
            _reason_code: reason_code.to_string(),
            _message: message,
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

/// Audit emitter for policy lifecycle events (bundle load, hot-swap, rejection).
/// All methods are no-ops until the apf-audit crate is integrated.
#[derive(Clone, Default)]
pub struct PolicyServiceAudit;

impl PolicyServiceAudit {
    #[must_use]
    pub fn disabled() -> Self {
        Self
    }

    pub fn emit_verify_bundle(
        &self,
        _ctx: &RuntimeContext,
        _meta: &BundleAuditMetadata,
        _outcome: &VerifyOutcome,
    ) -> Result<(), String> {
        Ok(())
    }

    pub fn emit_policy_load(
        &self,
        _bundle: &Bundle,
        _meta: &BundleAuditMetadata,
    ) -> Result<(), String> {
        Ok(())
    }

    pub fn emit_policy_hot_swap(
        &self,
        _meta: &BundleAuditMetadata,
        _digest: &str,
        _counter: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    pub fn emit_policy_reject(
        &self,
        _ctx: &RuntimeContext,
        _meta: &BundleAuditMetadata,
        _digest: &str,
        _reject: PolicyRejectAudit,
    ) -> Result<(), String> {
        Ok(())
    }
}
