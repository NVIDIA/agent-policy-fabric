// SPDX-License-Identifier: Apache-2.0
// Audit sink for apf-policy-gateway. Milestone M5 — no-op stub.

/// No-op audit sink for the APF policy gateway.
pub struct PolicyGatewayAudit;

impl PolicyGatewayAudit {
    /// Returns a disabled audit sink that discards all events.
    pub fn disabled() -> Self {
        Self
    }

    /// Record a policy evaluation event. No-op until M5.
    pub fn emit_evaluate(&self, _verb: &str, _resource_class: &str, _allow: bool) {}

    /// Record a bundle load event. No-op until M5.
    pub fn emit_bundle_loaded(&self, _digest_hex: &str) {}
}
