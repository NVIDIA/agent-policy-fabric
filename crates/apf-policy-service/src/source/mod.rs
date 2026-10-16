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

/// Build the reject payload shared by the activation-refusal audit events in
/// this module — counter-persist failures and hot-swap rejects — so the
/// reason-code/message/counter/digest shape stays uniform. Verification
/// refusals carry their own structured codes via `emit_verify_bundle`.
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
    /// (`emit_verify_bundle` for the verification outcome, `emit_policy_load`
    /// on success, `emit_policy_reject` on persist failure) for every fail-closed load path in
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

        // Verification has its own event either way: success is not activation,
        // and a refusal carries the verifier's structured rejection reasons.
        if let Err(e) = self
            .audit
            .emit_verify_bundle(&RuntimeContext::default(), &meta, &outcome)
        {
            if outcome.ok {
                anyhow::bail!("audit emission failed for bundle verification: {e}");
            }
            tracing::warn!(error = %e, "audit emission failed for bundle verification");
        }
        if !outcome.ok {
            anyhow::bail!(
                "bundle verification failed: {:?}",
                outcome.rejection_reasons
            );
        }

        let value = on_verified(&outcome)?;

        if let Err(e) = self
            .counter_store
            .check_and_advance(outcome.monotonic_counter, &outcome.payload_digest_hex)
        {
            let reject = reject_audit(
                "policy.bundle_rejected.counter_persist_failed",
                format!("counter advance: {e}"),
                true,
                Some(outcome.monotonic_counter),
            );
            if let Err(audit_err) = self.audit.emit_policy_reject(
                &RuntimeContext::default(),
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

    /// The wiring, not the emitter: a load that fails verification must leave
    /// a `policy_verification` refused record in the file, or the taxonomy's
    /// headline query returns nothing for the event it exists to catch.
    #[test]
    fn a_failed_verification_is_recorded_as_one() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let mut counter_store =
            CounterStore::load_or_init(&tmp.path().join("counter")).expect("init counter store");
        let audit = PolicyServiceAudit::to_jsonl_in(tmp.path()).expect("build emitter");

        let mut artifact = signer
            .sign(good_bundle_yaml(1).as_bytes())
            .expect("sign bundle");
        let last = artifact.len() - 1;
        artifact[last] ^= 0xFF;

        let result = BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut counter_store,
            audit: &audit,
        }
        .verify_and_advance(&artifact, &tmp.path().join("bundle.yaml"), |outcome| {
            Ok(outcome.monotonic_counter)
        });
        assert!(result.is_err(), "tampered bundle should be rejected");

        let written = std::fs::read_to_string(tmp.path().join("apf-policy-service-audit.jsonl"))
            .expect("audit file");
        let parsed: apf_audit::AuditEvent =
            serde_json::from_str(written.trim()).expect("one record, deserializes");
        parsed.validate().expect("validates against the schema");
        assert_eq!(parsed.event_type, apf_audit::EventType::PolicyVerification);
        assert_eq!(parsed.outcome, Some(apf_audit::Outcome::Refused));
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
    fn verify_and_advance_rejects_older_counter_before_compiling() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let mut counter_store =
            CounterStore::load_or_init(&counter_path).expect("init counter store");
        counter_store
            .check_and_advance(6, &"6".repeat(64))
            .expect("seed counter");

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
        assert!(result.is_err(), "older counter should be rejected");
        assert!(
            !compile_was_called,
            "verification must reject the rollback before the compile step ever runs"
        );
    }

    #[test]
    fn verify_and_advance_reloads_identical_artifact_at_accepted_counter() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let artifact = signer
            .sign(good_bundle_yaml(2).as_bytes())
            .expect("sign bundle");
        let bundle_path = tmp.path().join("bundle.yaml");
        let audit = PolicyServiceAudit::disabled();

        {
            let mut counter_store =
                CounterStore::load_or_init(&counter_path).expect("init counter store");
            BundleLoadContext {
                verifier: &verifier,
                counter_store: &mut counter_store,
                audit: &audit,
            }
            .verify_and_advance(&artifact, &bundle_path, |_| Ok(()))
            .expect("first load should succeed");
        }
        let counter_bytes = std::fs::read(&counter_path).expect("read counter file");

        // A process restart reloads the store from disk and presents the
        // bundle it was already serving.
        let mut restarted =
            CounterStore::load_or_init(&counter_path).expect("reload counter store");
        let mut compile_was_called = false;
        BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut restarted,
            audit: &audit,
        }
        .verify_and_advance(&artifact, &bundle_path, |_| {
            compile_was_called = true;
            Ok(())
        })
        .expect("the identical artifact must reload after a restart");
        assert!(compile_was_called);
        assert_eq!(restarted.high_water_mark(), 2);
        assert_eq!(
            std::fs::read(&counter_path).expect("read counter file"),
            counter_bytes,
            "reloading the accepted artifact must leave the counter file untouched"
        );
    }

    #[test]
    fn verify_and_advance_rejects_different_artifact_at_accepted_counter() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let bundle_path = tmp.path().join("bundle.yaml");
        let audit = PolicyServiceAudit::disabled();

        let accepted = signer
            .sign(good_bundle_yaml(2).as_bytes())
            .expect("sign bundle");
        let mut counter_store =
            CounterStore::load_or_init(&counter_path).expect("init counter store");
        BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut counter_store,
            audit: &audit,
        }
        .verify_and_advance(&accepted, &bundle_path, |_| Ok(()))
        .expect("first load should succeed");

        // Same revision, same trusted signer, different content.
        let reissued = signer
            .sign(
                good_bundle_yaml(2)
                    .replace("id: test-bundle", "id: reissued-bundle")
                    .as_bytes(),
            )
            .expect("sign bundle");
        let mut compile_was_called = false;
        let result = BundleLoadContext {
            verifier: &verifier,
            counter_store: &mut counter_store,
            audit: &audit,
        }
        .verify_and_advance(&reissued, &bundle_path, |_| {
            compile_was_called = true;
            Ok(())
        });
        assert!(
            result.is_err(),
            "a different artifact at an accepted counter must be rejected"
        );
        assert!(!compile_was_called);
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

    /// The digest of the bundle currently serving `variant`, for a record that
    /// must name the policy in force even when no document is being fetched.
    ///
    /// For a record about a document, prefer [`Self::get_with_bundle`]: reading
    /// the two separately lets a hot-swap land in between, and lets a caller
    /// steer the variant so the two resolve to different caches.
    fn active_bundle_digest(&self, variant: &str) -> Option<String>;

    /// The projection and the digest of the bundle it came from, resolved
    /// together under one lock so a vend record cannot name a bundle other
    /// than the one the projection was served from.
    fn get_with_bundle(
        &self,
        surface_id: &str,
        name: &str,
        variant: &str,
    ) -> Option<(PolicyProjection, String)>;

    /// The `driver_config` allowlist for sandbox policy `name`, as
    /// `DriverConfigPolicy` protobuf bytes, if the signed bundle carries one.
    /// Minted into the provenance JWT so the interceptor can enforce it.
    /// Defaults to `None` for sources that do not yet surface it.
    fn driver_config(&self, name: &str, variant: &str) -> Option<Vec<u8>> {
        let _ = (name, variant);
        None
    }

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
