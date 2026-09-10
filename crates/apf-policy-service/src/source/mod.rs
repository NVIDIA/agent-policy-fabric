// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Policy source — resolves (`surface_id`, name) to compiled projection bytes.
//!
//! [`PolicySource`] is the extension point for the fetch path. [`LocalBundleSource`]
//! reads from the bundle compiled at daemon startup and supports hot-swap via
//! `refresh()`. [`HttpBundleSource`] checks an in-memory cache first and on miss
//! fetches the bundle from an HTTP endpoint, runs it through the Compiler, and
//! populates the cache before returning.

pub mod http;
pub mod local;
pub mod resolver;

pub use http::{HttpBundleSource, UpdateStrategy};
pub use local::LocalBundleSource;
pub use resolver::{ClaimsResolver, PassthroughResolver, PolicyResolver, ResolvedPolicy};

/// Build the reject payload shared by every rejection audit event in this
/// module — load rejects, hot-swap rejects, and (once wired in) verify
/// rejects — so the reason-code/message/counter/digest shape stays uniform
/// instead of each call site formatting its own.
pub(crate) fn reject_audit(
    reason_code: &str,
    message: String,
    retryable: bool,
    counter: Option<u64>,
) -> crate::runtime::audit::PolicyRejectAudit {
    crate::runtime::audit::PolicyRejectAudit::new(reason_code, message)
        .with_retryable(retryable)
        .with_bundle_counter(counter)
}

/// The three dependencies every fail-closed bundle load needs together:
/// what to trust it against, where to durably record acceptance, and where
/// to log the outcome. Grouping them keeps `verify_and_advance`'s signature
/// from growing a new loose parameter every time one more piece of shared
/// context (e.g. a runtime/trace context for the real audit backend) is
/// needed.
pub struct BundleLoadContext<'a> {
    pub verifier: &'a dyn apf_types::BundleVerifier,
    pub counter_store: &'a mut apf_bundle::CounterStore,
    pub audit: &'a crate::runtime::audit::PolicyServiceAudit,
}

impl BundleLoadContext<'_> {
    /// Verify a bundle, hand the verified outcome to `on_verified` (the
    /// source-specific compile/cache step), and persist the monotonic
    /// counter only once `on_verified` succeeds — so a compile failure
    /// never consumes a counter slot, and a source can't accept a bundle
    /// into its cache without ever recording that acceptance durably.
    ///
    /// Every [`PolicySource`] backend with a fail-closed load path (a
    /// bundle that fails to load must not leave the service serving stale
    /// or unverified policy) should route through this instead of calling
    /// verification and `CounterStore::check_and_advance` separately —
    /// that split let the HTTP source's initial load verify a bundle and
    /// cache it without ever persisting the counter, so a restart forgot
    /// every bundle it had ever accepted.
    ///
    /// Also the single place that emits the load-lifecycle audit events
    /// (`emit_policy_load` on success, `emit_policy_reject` on
    /// verification or persist failure) for every fail-closed load path in
    /// this crate, including `main.rs`'s local-startup bootstrap — so a new
    /// load path can't silently skip audit, and there's exactly one event
    /// family for "did a bundle load" instead of one per call site.
    pub fn verify_and_advance<T>(
        &mut self,
        bundle_bytes: &[u8],
        bundle_path: &std::path::Path,
        on_verified: impl FnOnce(&apf_bundle::VerifyOutcome) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        use crate::runtime::audit::BundleAuditMetadata;
        use crate::runtime::runtime_context::RuntimeContext;

        let outcome = apf_bundle::verify_bundle(
            bundle_bytes,
            bundle_path,
            self.verifier,
            self.counter_store,
            std::time::SystemTime::now(),
            &std::collections::HashMap::new(),
        );
        let meta = BundleAuditMetadata::from_counter_and_digest(
            outcome.monotonic_counter,
            &outcome.digest_hex,
        );

        if !outcome.ok {
            let reject = reject_audit(
                "policy.bundle_rejected.verification_failed",
                format!(
                    "bundle verification failed: {:?}",
                    outcome.rejection_reasons
                ),
                false,
                outcome.parsed.then_some(outcome.monotonic_counter),
            );
            if let Err(e) = self.audit.emit_policy_reject(
                &RuntimeContext::default(),
                &meta,
                &outcome.digest_hex,
                reject,
            ) {
                tracing::warn!(error = %e, "audit emission failed for policy load reject");
            }
            anyhow::bail!(
                "bundle verification failed: {:?}",
                outcome.rejection_reasons
            );
        }

        let value = on_verified(&outcome)?;

        if let Err(e) = self
            .counter_store
            .check_and_advance(outcome.monotonic_counter)
        {
            let reject = reject_audit(
                "policy.bundle_rejected.counter_persist_failed",
                format!("counter advance: {e}"),
                true,
                Some(outcome.monotonic_counter),
            );
            if let Err(audit_err) = self.audit.emit_policy_reject(
                &RuntimeContext::default(),
                &meta,
                &outcome.digest_hex,
                reject,
            ) {
                tracing::warn!(error = %audit_err, "audit emission failed for policy load reject");
            }
            anyhow::bail!("counter advance: {e}");
        }

        let bundle = outcome
            .bundle
            .as_ref()
            .expect("outcome.ok guarantees bundle is present");
        if let Err(e) = self.audit.emit_policy_load(bundle, &meta) {
            tracing::warn!(error = %e, "audit emission failed for policy load");
        }

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::audit::PolicyServiceAudit;
    use apf_bundle::{CounterStore, Ed25519Signer};
    use apf_types::BundleSigner;

    fn good_bundle_yaml(counter: u64) -> String {
        format!(
            r#"id: test-bundle
policy_revision: {counter}
not_before: "2026-01-01T00:00:00Z"
expires_at: "2099-01-01T00:00:00Z"
manifest: []
runtime_compatibility: {{}}
"#
        )
    }

    #[test]
    fn verify_and_advance_rejects_tampered_signature() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let mut counter_store =
            CounterStore::load_or_init(&counter_path).expect("init counter store");

        let mut artifact = signer
            .sign(good_bundle_yaml(1).as_bytes())
            .expect("sign bundle");
        let last = artifact.len() - 1;
        artifact[last] ^= 0xFF;
        let bundle_path = tmp.path().join("bundle.yaml");

        let result = BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut counter_store,
            audit: &PolicyServiceAudit::disabled(),
        }
        .verify_and_advance(&artifact, &bundle_path, |outcome| {
            Ok(outcome.monotonic_counter)
        });
        assert!(result.is_err(), "tampered bundle should be rejected");
        assert_eq!(counter_store.high_water_mark(), 0);
    }

    #[test]
    fn verify_and_advance_persists_on_success() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let mut counter_store =
            CounterStore::load_or_init(&counter_path).expect("init counter store");

        let artifact = signer
            .sign(good_bundle_yaml(3).as_bytes())
            .expect("sign bundle");
        let bundle_path = tmp.path().join("bundle.yaml");

        let value = BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut counter_store,
            audit: &PolicyServiceAudit::disabled(),
        }
        .verify_and_advance(&artifact, &bundle_path, |outcome| {
            Ok(outcome.monotonic_counter * 2)
        })
        .expect("verify_and_advance should succeed");
        assert_eq!(value, 6);
        assert_eq!(counter_store.high_water_mark(), 3);

        let reloaded =
            CounterStore::load_or_init(&counter_path).expect("reload counter store from disk");
        assert_eq!(
            reloaded.high_water_mark(),
            3,
            "the counter must be persisted to disk, not just held in memory"
        );
    }

    #[test]
    fn verify_and_advance_does_not_consume_counter_when_compile_fails() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let mut counter_store =
            CounterStore::load_or_init(&counter_path).expect("init counter store");

        let artifact = signer
            .sign(good_bundle_yaml(3).as_bytes())
            .expect("sign bundle");
        let bundle_path = tmp.path().join("bundle.yaml");

        let audit = PolicyServiceAudit::disabled();
        let mut ctx = BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut counter_store,
            audit: &audit,
        };
        let result = ctx.verify_and_advance::<()>(&artifact, &bundle_path, |_outcome| {
            anyhow::bail!("simulated compile failure")
        });
        assert!(result.is_err(), "compile failure must propagate");
        assert_eq!(
            ctx.counter_store.high_water_mark(),
            0,
            "a bundle that failed to compile must not consume its counter slot"
        );

        // The same counter can still be retried once the underlying failure
        // (e.g. a bad compiler config) is fixed.
        let retry = ctx
            .verify_and_advance(&artifact, &bundle_path, |outcome| {
                Ok(outcome.monotonic_counter)
            })
            .expect("retry with the same counter should succeed");
        assert_eq!(retry, 3);
        assert_eq!(counter_store.high_water_mark(), 3);
    }

    #[test]
    fn verify_and_advance_rejects_replayed_counter_before_compiling() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let mut counter_store =
            CounterStore::load_or_init(&counter_path).expect("init counter store");
        counter_store.check_and_advance(5).expect("seed counter");

        let artifact = signer
            .sign(good_bundle_yaml(5).as_bytes())
            .expect("sign bundle");
        let bundle_path = tmp.path().join("bundle.yaml");

        let mut compile_was_called = false;
        let result = BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut counter_store,
            audit: &PolicyServiceAudit::disabled(),
        }
        .verify_and_advance(&artifact, &bundle_path, |outcome| {
            compile_was_called = true;
            Ok(outcome.monotonic_counter)
        });
        assert!(result.is_err(), "replayed counter should be rejected");
        assert!(
            !compile_was_called,
            "verification must reject the replay before the compile step ever runs"
        );
    }
}

/// A compiled projection ready to be vended to a caller.
#[derive(Clone)]
pub struct PolicyProjection {
    /// Substrate-native bytes (e.g. encoded openshell.sandbox.v1.SandboxPolicy).
    pub bytes: Vec<u8>,
    /// Hex SHA-256 of `bytes`.
    pub digest: String,
    /// Bundle monotonic counter at the time the projection was compiled.
    pub version: u64,
}

/// Result of a successful `PolicySource::refresh` call.
pub struct RefreshOutcome {
    /// Hex SHA-256 of the newly loaded bundle artifact.
    pub policy_digest: String,
    /// Monotonic counter of the newly loaded bundle.
    pub version: u64,
}

#[async_trait::async_trait]
pub trait PolicySource: Send + Sync {
    /// Return the projection for `(surface_id, name)` within the given variant.
    /// An empty variant string means use the default/only cache.
    fn get(&self, surface_id: &str, name: &str, variant: &str) -> Option<PolicyProjection>;

    /// All policy names available for `surface_id`.
    fn list(&self, surface_id: &str) -> Vec<String>;

    /// Whether this source has a verified bundle loaded and can serve
    /// requests. `LocalBundleSource` is always ready once constructed — the
    /// initial local bundle is loaded synchronously before it exists.
    /// `HttpBundleSource` overrides this: it is not ready until at least one
    /// variant has completed a successful fetch and verification.
    fn is_ready(&self) -> bool {
        true
    }

    /// Reload the policy bundle.
    ///
    /// - `LocalBundleSource`: `bundle_path` is required; points to the new
    ///   signed bundle file. The in-process core is swapped atomically after
    ///   successful compilation.
    /// - `HttpBundleSource`: `bundle_path` is ignored; polls the configured
    ///   remote URL for an updated bundle.
    ///
    /// Returns an error when this source does not support refresh.
    async fn refresh(
        &self,
        bundle_path: Option<&std::path::Path>,
    ) -> anyhow::Result<RefreshOutcome> {
        let _ = bundle_path;
        anyhow::bail!("this policy source does not support refresh")
    }
}
