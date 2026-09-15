// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! HTTP bundle source — fetches a signed bundle tar.gz from an HTTP endpoint,
//! compiles it through the [`apf_compiler::Compiler`] pipeline, and serves
//! projections from an in-memory cache. A background task polls for updates on
//! a configurable interval.
//!
//! The trait is synchronous — all lookups are `BTreeMap` reads behind a
//! `RwLock`. Async I/O (HTTP fetch) is confined to the background polling task.
//!
//! ## Update strategies
//!
//! Polling: a background task re-checks the endpoint every N seconds.
//! HEAD-first optimization avoids downloading unchanged bundles.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tracing::{info, trace, warn};

use super::{PolicyProjection, PolicySource};
use crate::runtime::audit::PolicyServiceAudit;
use crate::runtime::runtime_context::RuntimeContext;
use apf_bundle::CounterStore;
use apf_types::BundleVerifier;

/// How the source detects bundle updates.
#[derive(Debug, Clone)]
pub enum UpdateStrategy {
    /// Poll the bundle endpoint on a fixed interval. Simple but has latency.
    Poll { interval: Duration },
    // Future: subscribe to a gRPC stream from a policy distribution service.
}

/// Maximum number of retry attempts for transient fetch failures.
const MAX_FETCH_RETRIES: u32 = 3;

/// In-memory snapshot of a compiled bundle's projections.
#[derive(Default)]
struct BundleCache {
    /// Pre-computed projections keyed by `(surface_id, name)`. Digest and
    /// version are computed once at cache-population time so `get()` is a
    /// cheap clone instead of a per-call SHA-256.
    projections: BTreeMap<(String, String), PolicyProjection>,
    /// Monotonic counter from the bundle manifest (`policy_revision`), for
    /// this variant only. See `HttpBundleSource::counter_store` for the
    /// separate, source-wide counter that gates whether a fetched bundle
    /// is accepted at all.
    current_counter: u64,
    /// SHA-256 hex digest of the fetched tar.gz — used for change detection
    /// without re-extracting the archive on every poll.
    bundle_digest: String,
    /// Bundle manifest identifier from the verified bundle.
    bundle_id: String,
}

impl BundleCache {
    /// Atomically swap the cache contents if `new_counter` strictly exceeds
    /// the current counter (monotonic-counter anti-rollback). Returns `true`
    /// when the swap is accepted.
    ///
    /// This check is redundant with `HttpBundleSource::counter_store`'s own
    /// monotonic check under normal, sequential polling — it only rejects
    /// here if something has already gone wrong upstream. Its real job is
    /// concurrency safety: two writers for the same variant (e.g. an
    /// on-demand `load_variant` call racing the background poll loop) can
    /// each independently pass the counter-store check, since that check
    /// only requires each write to exceed whatever was persisted *at the
    /// time it ran* — it does not order writers against each other. This
    /// check is what stops the slower writer from clobbering a newer
    /// result the faster one already applied to this cache.
    fn try_swap(
        &mut self,
        new_projections: BTreeMap<(String, String), PolicyProjection>,
        new_counter: u64,
        new_digest: String,
        new_bundle_id: String,
    ) -> bool {
        if new_counter <= self.current_counter {
            return false;
        }
        self.projections = new_projections;
        self.current_counter = new_counter;
        self.bundle_digest = new_digest;
        self.bundle_id = new_bundle_id;
        true
    }
}

/// Fetches signed bundle tar.gz files from an HTTP endpoint, compiles them, and
/// serves projections from per-variant in-memory caches.
///
/// The URL can be a literal (`https://.../bundle.tar.gz`) or a template with
/// a `{variant}` placeholder (`https://.../governed-{variant}/latest.tar.gz`),
/// filled in with [`ResolvedPolicy::variant`]. When a template is used,
/// each resolved variant gets its own [`BundleCache`], enabling a
/// [`PolicyResolver`] to route different callers to different bundle
/// editions.
pub struct HttpBundleSource {
    url_template: String,
    auth_token: String,
    compiler: apf_compiler::Compiler,
    /// Per-variant caches. A literal URL stores everything under the key `""`.
    caches: Arc<RwLock<BTreeMap<String, BundleCache>>>,
    http_client: reqwest::Client,
    /// Persistent counter store for cross-restart anti-rollback.
    ///
    /// One counter sequence for the whole source, shared by every resolved
    /// `{variant}` in `caches` above — not one counter per variant. A
    /// bundle fetched for one variant can be rejected here even if its
    /// counter is newer than that same variant's own last accepted bundle,
    /// as long as some other variant already advanced this shared counter
    /// further.
    counter_store: Mutex<CounterStore>,
    /// Audit emitter for policy lifecycle events on the load and hot-swap paths.
    audit: PolicyServiceAudit,
    /// Verifies every fetched bundle's signature against the trust store
    /// before it's compiled or served — see `extract_and_compile`.
    verifier: Arc<dyn BundleVerifier>,
}

impl HttpBundleSource {
    /// Build a new source. `url` may contain `{variant}` for template-based
    /// multi-bundle resolution. `verifier` and `counter_store` are both
    /// mandatory: an HTTP-fetched bundle is never trusted on transport
    /// (token/TLS) alone, and can't be checked for rollback without a
    /// counter store to check it against.
    pub fn new(
        url: &str,
        token: &str,
        compiler: apf_compiler::Compiler,
        verifier: Arc<dyn BundleVerifier>,
        counter_store: CounterStore,
    ) -> anyhow::Result<Self> {
        let http_client = reqwest::Client::builder()
            .build()
            .map_err(|e| anyhow::anyhow!("build HTTP client: {e}"))?;
        Ok(Self {
            url_template: url.to_string(),
            auth_token: token.to_string(),
            compiler,
            caches: Arc::new(RwLock::new(BTreeMap::new())),
            http_client,
            counter_store: Mutex::new(counter_store),
            audit: PolicyServiceAudit::disabled(),
            verifier,
        })
    }

    fn is_template(&self) -> bool {
        self.url_template.contains("{variant}")
    }

    fn resolve_url(&self, variant: &str) -> String {
        self.url_template.replace("{variant}", variant)
    }

    fn default_variant(&self) -> String {
        String::new()
    }

    /// Fetch the bundle, compile, and populate the cache. For literal URLs
    /// this is called once at startup. For template URLs, skip this — variants
    /// are loaded lazily on first access or by explicit `load_variant`.
    pub async fn load_initial(&self) -> anyhow::Result<()> {
        if self.is_template() {
            info!(
                url_template = %self.url_template,
                "http bundle source: template URL, variants loaded on demand"
            );
            return Ok(());
        }
        self.load_variant_inner(&self.default_variant(), &self.url_template)
            .await
    }

    /// Fetch and cache one resolved `{variant}` on demand — the
    /// counterpart to the background poll loop, for a caller that
    /// resolves a variant on a cache miss (e.g. a request surface routing
    /// by claims) rather than waiting for the next poll cycle to
    /// populate it.
    pub async fn load_variant(&self, variant: &str) -> anyhow::Result<()> {
        let url = self.resolve_url(variant);
        self.load_variant_inner(variant, &url).await
    }

    async fn load_variant_inner(&self, variant: &str, url: &str) -> anyhow::Result<()> {
        let tar_gz = self.fetch_bundle_from(url).await?;
        // Fails closed and persists the counter before returning — see
        // `extract_and_compile`. A verified-but-unpersisted bundle never
        // reaches the cache below.
        let (projections, counter, digest, bundle_id) = self.extract_and_compile(&tar_gz)?;

        let projection_count = projections.len();

        {
            let mut caches = self.caches.write().expect("cache lock poisoned");
            let cache = caches.entry(variant.to_string()).or_default();
            cache.projections = projections;
            cache.current_counter = counter;
            cache.bundle_digest = digest.clone();
            cache.bundle_id = bundle_id;
        }

        info!(
            url = %url,
            variant = %variant,
            counter,
            digest = %digest,
            projections = projection_count,
            "http bundle source: bundle loaded"
        );
        Ok(())
    }

    async fn check_remote_digest(&self, url: &str) -> anyhow::Result<Option<String>> {
        let mut req = self.http_client.head(url);
        if !self.auth_token.is_empty() {
            req = req.bearer_auth(&self.auth_token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("HEAD {url}: {e}"))?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("HEAD {url}: {e}"))?;

        if let Some(sha) = resp.headers().get("x-checksum-sha256") {
            return Ok(sha.to_str().ok().map(std::string::ToString::to_string));
        }
        if let Some(etag) = resp.headers().get("etag") {
            return Ok(etag.to_str().ok().map(std::string::ToString::to_string));
        }
        Ok(None)
    }

    async fn fetch_with_retry(&self, url: &str, max_retries: u32) -> anyhow::Result<Vec<u8>> {
        let mut attempt = 0;
        loop {
            match self.fetch_bundle_from(url).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) if attempt < max_retries => {
                    attempt += 1;
                    let backoff = Duration::from_secs(1 << attempt);
                    warn!(
                        attempt,
                        max_retries,
                        backoff_secs = backoff.as_secs(),
                        error = %e,
                        "http bundle fetch failed, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Poll all cached variants for updates. For each variant, a HEAD request
    /// short-circuits when the digest is unchanged. When a new bundle is
    /// accepted (higher monotonic counter), the cache is hot-swapped.
    pub async fn poll_for_update(&self) -> anyhow::Result<()> {
        let variants: Vec<String> = self
            .caches
            .read()
            .expect("cache lock poisoned")
            .keys()
            .cloned()
            .collect();

        if variants.is_empty() {
            return Ok(());
        }

        for variant in &variants {
            let url = if self.is_template() {
                self.resolve_url(variant)
            } else {
                self.url_template.clone()
            };
            if let Err(e) = self.poll_variant(variant, &url).await {
                warn!(variant = %variant, error = %e, "poll failed for variant");
            }
        }
        Ok(())
    }

    async fn poll_variant(&self, variant: &str, url: &str) -> anyhow::Result<()> {
        if let Some(remote_digest) = self.check_remote_digest(url).await? {
            let cached_digest = {
                let caches = self.caches.read().expect("cache lock poisoned");
                caches
                    .get(variant)
                    .map(|c| c.bundle_digest.clone())
                    .unwrap_or_default()
            };
            if remote_digest == cached_digest {
                trace!(url = %url, variant = %variant, "HEAD digest unchanged");
                return Ok(());
            }
            info!(
                url = %url,
                variant = %variant,
                cached = %cached_digest,
                remote = %remote_digest,
                "HEAD digest changed, fetching updated bundle"
            );
        }

        let tar_gz = self.fetch_with_retry(url, MAX_FETCH_RETRIES).await?;
        let new_digest = hex::encode(Sha256::digest(&tar_gz));

        {
            let caches = self.caches.read().expect("cache lock poisoned");
            if let Some(c) = caches.get(variant)
                && c.bundle_digest == new_digest
            {
                trace!(url = %url, "full-fetch digest unchanged after download");
                return Ok(());
            }
        }

        // `extract_and_compile` verifies, compiles, and persists the counter
        // before returning — a bundle that fails any of those steps (an
        // unpersisted counter included) propagates as `Err` here, which
        // `poll_for_update`'s caller logs and treats as "try again next
        // cycle" rather than a fatal poll-loop error. That's what keeps the
        // in-memory counter from ever running ahead of the durable one: this
        // point is only reached once persistence has already succeeded.
        let (projections, counter, digest, bundle_id) = self.extract_and_compile(&tar_gz)?;
        let projection_count = projections.len();

        let swapped = {
            let mut caches = self.caches.write().expect("cache lock poisoned");
            let cache = caches.entry(variant.to_string()).or_default();
            cache.try_swap(projections, counter, digest.clone(), bundle_id.clone())
        };

        if swapped {
            // Reached only after `extract_and_compile` already persisted the
            // counter (see above), so the swap is durable — not the
            // counter-not-persisted case the flag guards against.
            if let Err(e) =
                self.audit
                    .emit_policy_hot_swap(&digest, counter, Some(bundle_id.as_str()), false)
            {
                warn!(error = %e, "audit emission failed for policy hot-swap");
            }

            info!(
                variant = %variant,
                counter,
                digest = %digest,
                projections = projection_count,
                "http bundle source: cache updated"
            );
        } else {
            warn!(
                variant = %variant,
                counter,
                "http bundle source: bundle counter not newer; ignoring"
            );
            self.emit_hot_swap_reject(
                "policy.bundle_rejected.counter_not_newer",
                format!("bundle counter {counter} not newer than current"),
                false,
                counter,
                &digest,
            );
        }
        Ok(())
    }

    fn emit_hot_swap_reject(
        &self,
        reason_code: &str,
        message: String,
        retryable: bool,
        counter: u64,
        digest: &str,
    ) {
        let reject = super::reject_audit(reason_code, message, retryable, Some(counter))
            .with_metadata_source("http_bundle_source_poll");
        if let Err(e) = self
            .audit
            .emit_policy_reject(&RuntimeContext::default(), digest, reject)
        {
            warn!(error = %e, reason_code, "audit emission failed for hot-swap reject");
        }
    }

    /// Start the background update loop using the given [`UpdateStrategy`].
    pub fn start_updates(self: &Arc<Self>, strategy: UpdateStrategy) {
        match strategy {
            UpdateStrategy::Poll { interval } => {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(interval);
                    ticker.tick().await; // skip the immediate first tick
                    loop {
                        ticker.tick().await;
                        if let Err(e) = this.poll_for_update().await {
                            warn!(error = %e, "http bundle source poll failed");
                        }
                    }
                });
            }
        }
    }

    /// Convenience wrapper that starts polling on the given interval.
    pub fn start_polling(self: &Arc<Self>, interval: Duration) {
        self.start_updates(UpdateStrategy::Poll { interval });
    }

    /// Return the digest of the most recently updated variant, or the first
    /// variant if none has been updated since startup.
    pub fn current_bundle_digest(&self) -> String {
        let caches = self.caches.read().expect("cache lock poisoned");
        caches
            .values()
            .next()
            .map(|c| c.bundle_digest.clone())
            .unwrap_or_default()
    }

    /// Return the highest monotonic counter across all cached variants.
    pub fn current_counter(&self) -> u64 {
        let caches = self.caches.read().expect("cache lock poisoned");
        caches
            .values()
            .map(|c| c.current_counter)
            .max()
            .unwrap_or(0)
    }

    pub fn set_audit(&mut self, audit: PolicyServiceAudit) {
        self.audit = audit;
    }

    /// The bundle manifest identifier for the given variant's currently
    /// cached bundle. `""` selects the default/literal-URL variant. Returns
    /// `None` when that variant has no cache entry yet (nothing fetched).
    pub fn bundle_id(&self, variant: &str) -> Option<String> {
        let caches = self.caches.read().expect("cache lock poisoned");
        caches.get(variant).map(|c| c.bundle_id.clone())
    }

    async fn fetch_bundle_from(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        let mut req = self.http_client.get(url);
        if !self.auth_token.is_empty() {
            req = req.bearer_auth(&self.auth_token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("fetch {url}: {e}"))?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("fetch {url}: {e}"))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("read body from {url}: {e}"))?;
        Ok(bytes.to_vec())
    }

    /// Extract the tar.gz, locate the bundle manifest, and compile it.
    /// Returns `(projections, monotonic_counter, tar_gz_digest)`.
    /// Projections are returned with pre-computed SHA-256 digests so `get()`
    /// avoids per-call hashing.
    /// Unpack the tar.gz, then verify, compile, and persist the bundle
    /// through `BundleLoadContext` — the tar-unpack-and-find-manifest step
    /// has to run first since verification needs the extracted manifest
    /// bytes, not the raw tar.gz.
    #[allow(clippy::type_complexity)]
    fn extract_and_compile(
        &self,
        tar_gz: &[u8],
    ) -> anyhow::Result<(
        BTreeMap<(String, String), PolicyProjection>,
        u64,
        String,
        String,
    )> {
        let tar_digest = hex::encode(Sha256::digest(tar_gz));
        let tmp_dir = tempfile::tempdir().map_err(|e| anyhow::anyhow!("create temp dir: {e}"))?;

        let gz = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(gz);
        archive
            .unpack(tmp_dir.path())
            .map_err(|e| anyhow::anyhow!("unpack tar.gz: {e}"))?;

        let manifest_path =
            apf_bundle::find_bundle_manifest(tmp_dir.path(), self.verifier.as_ref())
                .map_err(|e| anyhow::anyhow!("find bundle manifest: {e}"))?;
        let bundle_bytes =
            std::fs::read(&manifest_path).map_err(|e| anyhow::anyhow!("read manifest: {e}"))?;

        let mut counter_store = self
            .counter_store
            .lock()
            .expect("counter store lock poisoned");

        let (projections, counter, bundle_id) = super::BundleLoadContext {
            verifier: self.verifier.as_ref(),
            counter_store: &mut counter_store,
            audit: &self.audit,
        }
        .verify_and_advance(&bundle_bytes, &manifest_path, |outcome| {
            let parsed_bundle = outcome
                .bundle
                .clone()
                .expect("outcome.ok guarantees bundle is present");
            let bundle_id = parsed_bundle.bundle_id.clone();

            // Compile from the already-verified payload's members, not the
            // raw on-disk file.
            let bundle_dir = manifest_path.parent().unwrap_or_else(|| tmp_dir.path());
            let members = parsed_bundle
                .load_members(bundle_dir)
                .map_err(|e| anyhow::anyhow!("load bundle members: {e}"))?;
            let compiled = self
                .compiler
                .lower_members(&members, None)
                .map_err(|e| anyhow::anyhow!("compile bundle: {e}"))?;

            let projections = apf_compiler::surfaces_to_projections(compiled.surfaces)
                .into_iter()
                .map(|(key, bytes)| {
                    let digest = hex::encode(Sha256::digest(&bytes));
                    (
                        key,
                        PolicyProjection {
                            bytes,
                            digest,
                            version: outcome.monotonic_counter,
                        },
                    )
                })
                .collect();

            Ok((projections, outcome.monotonic_counter, bundle_id))
        })?;

        Ok((projections, counter, tar_digest, bundle_id))
    }
}

#[async_trait::async_trait]
impl PolicySource for HttpBundleSource {
    fn get(&self, surface_id: &str, name: &str, variant: &str) -> Option<PolicyProjection> {
        let caches = self.caches.read().expect("cache lock poisoned");
        let key = (surface_id.to_string(), name.to_string());

        if !variant.is_empty() {
            return caches
                .get(variant)
                .and_then(|c| c.projections.get(&key).cloned());
        }

        for cache in caches.values() {
            if let Some(p) = cache.projections.get(&key) {
                return Some(p.clone());
            }
        }
        None
    }

    fn active_bundle_digest(&self, variant: &str) -> Option<String> {
        let caches = self.caches.read().expect("cache lock poisoned");
        // Exact for a named variant: falling back would name a bundle the
        // request was not served from. The empty variant means "unspecified"
        // and a template source has no default cache, so any loaded bundle is
        // context rather than causation — matching how `get` scans in that
        // case.
        let cache = if variant.is_empty() {
            caches.get(variant).or_else(|| caches.values().next())
        } else {
            caches.get(variant)
        };
        cache
            .map(|c| c.bundle_digest.clone())
            .filter(|d| !d.is_empty())
    }

    fn get_with_bundle(
        &self,
        surface_id: &str,
        name: &str,
        variant: &str,
    ) -> Option<(PolicyProjection, String)> {
        let caches = self.caches.read().expect("cache lock poisoned");
        let key = (surface_id.to_string(), name.to_string());
        // The projection and the digest must come from the SAME cache, or the
        // record names a bundle the document did not come from — which a
        // caller can steer, since the variant derives from a query parameter.
        let cache = if variant.is_empty() {
            caches.values().find(|c| c.projections.contains_key(&key))
        } else {
            caches.get(variant)
        }?;
        // No filter on an empty digest: this sits on the serving path, and
        // missing audit metadata must not turn a servable document into a 404.
        let projection = cache.projections.get(&key)?.clone();
        Some((projection, cache.bundle_digest.clone()))
    }

    fn list(&self, surface_id: &str) -> Vec<String> {
        let caches = self.caches.read().expect("cache lock poisoned");
        let mut names: Vec<String> = caches
            .values()
            .flat_map(|c| {
                c.projections
                    .keys()
                    .filter(|(kind, _)| kind == surface_id)
                    .map(|(_, name)| name.clone())
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }

    fn is_ready(&self) -> bool {
        let caches = self.caches.read().expect("cache lock poisoned");
        caches.values().any(|c| !c.bundle_digest.is_empty())
    }

    async fn refresh(
        &self,
        _bundle_path: Option<&std::path::Path>,
    ) -> anyhow::Result<super::RefreshOutcome> {
        // bundle_path is ignored; re-fetches from the configured remote URL.
        self.poll_for_update()
            .await
            .map_err(|e| anyhow::anyhow!("http bundle refresh failed: {e}"))?;
        Ok(super::RefreshOutcome {
            policy_digest: self.current_bundle_digest(),
            version: self.current_counter(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apf_bundle::YamlSigilVerifier;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn make_test_source(cache: BundleCache) -> HttpBundleSource {
        let mut caches = BTreeMap::new();
        caches.insert(String::new(), cache);
        // Empty trust store: these tests populate the cache directly and
        // never go through extract_and_compile, so no verification runs.
        let empty_trust_dir = tempfile::tempdir().expect("create empty trust dir");
        let verifier: Arc<dyn BundleVerifier> = Arc::new(YamlSigilVerifier::new(
            apf_bundle::TrustStore::load_from_dir(empty_trust_dir.path())
                .expect("load empty trust store"),
        ));
        let counter_dir = tempfile::tempdir().expect("create counter dir");
        let counter_store = CounterStore::load_or_init(&counter_dir.path().join("counter"))
            .expect("init counter store");
        HttpBundleSource {
            url_template: String::new(),
            auth_token: String::new(),
            compiler: apf_compiler::Compiler::new(vec![]),
            caches: Arc::new(RwLock::new(caches)),
            http_client: reqwest::Client::new(),
            counter_store: Mutex::new(counter_store),
            audit: PolicyServiceAudit::disabled(),
            verifier,
        }
    }

    #[test]
    fn http_source_returns_cached_projection() {
        let bytes = vec![10u8, 20, 30];
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        let mut projections = BTreeMap::new();
        projections.insert(
            ("openshell.sandbox.v1".to_string(), "default".to_string()),
            PolicyProjection {
                bytes: bytes.clone(),
                digest: digest.clone(),
                version: 5,
            },
        );
        let cache = BundleCache {
            projections,
            current_counter: 5,
            bundle_digest: "cafebabe".to_string(),
            bundle_id: "test-bundle".to_string(),
        };

        let source = make_test_source(cache);
        let p = source
            .get("openshell.sandbox.v1", "default", "")
            .expect("found");
        assert_eq!(p.bytes, bytes);
        assert_eq!(p.digest, digest);
        assert_eq!(p.version, 5);
    }

    #[test]
    fn bundle_cache_swap_higher_counter_succeeds() {
        let mut cache = BundleCache {
            current_counter: 3,
            ..Default::default()
        };

        let mut new_proj = BTreeMap::new();
        new_proj.insert(
            ("openshell.sandbox.v1".to_string(), "strict".to_string()),
            PolicyProjection {
                bytes: vec![7, 8, 9],
                digest: hex::encode(sha2::Sha256::digest([7, 8, 9])),
                version: 4,
            },
        );

        assert!(cache.try_swap(new_proj, 4, "new-digest".to_string(), "b1".to_string()));
        assert_eq!(cache.current_counter, 4);
        assert_eq!(cache.bundle_digest, "new-digest");
        assert_eq!(cache.bundle_id, "b1");
        assert!(
            cache
                .projections
                .contains_key(&("openshell.sandbox.v1".to_string(), "strict".to_string()))
        );
    }

    #[test]
    fn bundle_cache_swap_equal_counter_is_rejected() {
        let mut cache = BundleCache {
            current_counter: 5,
            bundle_digest: "old-digest".to_string(),
            bundle_id: "old-bundle".to_string(),
            ..Default::default()
        };

        assert!(!cache.try_swap(
            BTreeMap::new(),
            5,
            "new-digest".to_string(),
            "new-bundle".to_string()
        ));
        assert_eq!(cache.current_counter, 5);
        assert_eq!(cache.bundle_digest, "old-digest");
        assert_eq!(cache.bundle_id, "old-bundle");
    }

    #[test]
    fn bundle_cache_swap_lower_counter_is_rejected() {
        let mut cache = BundleCache {
            current_counter: 10,
            ..Default::default()
        };

        assert!(!cache.try_swap(BTreeMap::new(), 3, "x".to_string(), "y".to_string()));
        assert_eq!(cache.current_counter, 10);
    }

    #[test]
    fn http_source_list_filters_by_surface() {
        let mut projections = BTreeMap::new();
        projections.insert(
            ("openshell.sandbox.v1".to_string(), "default".to_string()),
            PolicyProjection {
                bytes: vec![1],
                digest: String::new(),
                version: 1,
            },
        );
        projections.insert(
            ("openshell.sandbox.v1".to_string(), "strict".to_string()),
            PolicyProjection {
                bytes: vec![2],
                digest: String::new(),
                version: 1,
            },
        );
        projections.insert(
            ("other.surface".to_string(), "x".to_string()),
            PolicyProjection {
                bytes: vec![3],
                digest: String::new(),
                version: 1,
            },
        );
        let cache = BundleCache {
            projections,
            current_counter: 1,
            bundle_digest: String::new(),
            bundle_id: String::new(),
        };
        let source = make_test_source(cache);

        let mut names = source.list("openshell.sandbox.v1");
        names.sort();
        assert_eq!(names, vec!["default", "strict"]);
        assert_eq!(source.list("other.surface"), vec!["x"]);
        assert!(source.list("missing").is_empty());
    }

    // ── HTTP source boots and verifies without any local bundle ──

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

    /// Minimal signer/verifier for these tests, shaped like a real
    /// yaml-sigil artifact: a payload document plus a separate signature
    /// document.
    struct TestSignedVerifier {
        key: [u8; 32],
    }

    impl TestSignedVerifier {
        fn new() -> Self {
            Self { key: [7u8; 32] }
        }

        fn mac(key: &[u8; 32], payload: &[u8]) -> String {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(payload);
            hex::encode(hasher.finalize())
        }

        fn sign(&self, payload: &str) -> Vec<u8> {
            let mac = Self::mac(&self.key, payload.as_bytes());
            format!("{payload}---\nsig: {mac}\n").into_bytes()
        }
    }

    impl BundleVerifier for TestSignedVerifier {
        fn verify(&self, artifact: &[u8]) -> Result<Vec<u8>, apf_types::VerifyError> {
            let text = std::str::from_utf8(artifact)
                .map_err(|e| apf_types::VerifyError::Verify(format!("not utf8: {e}")))?;
            let (payload, sig_doc) = text.split_once("---\n").ok_or_else(|| {
                apf_types::VerifyError::Verify("missing signature document".into())
            })?;
            let sig_hex = sig_doc
                .strip_prefix("sig: ")
                .and_then(|s| s.split_whitespace().next())
                .ok_or_else(|| apf_types::VerifyError::Verify("missing signature field".into()))?;
            if sig_hex != Self::mac(&self.key, payload.as_bytes()) {
                return Err(apf_types::VerifyError::Verify("signature mismatch".into()));
            }
            Ok(payload.as_bytes().to_vec())
        }
    }

    /// Packs `manifest_yaml` as `manifest.yaml` inside a single-file tar.gz,
    /// matching the archive shape `extract_and_compile` expects to unpack.
    fn pack_bundle_tar_gz(manifest_yaml: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest_yaml.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "manifest.yaml", manifest_yaml)
                .expect("append manifest to tar");
            builder.finish().expect("finish tar");
        }
        let mut gz_bytes = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::default());
            std::io::Write::write_all(&mut encoder, &tar_bytes).expect("gzip tar");
            encoder.finish().expect("finish gzip");
        }
        gz_bytes
    }

    /// Starts a local axum server serving `/bundle.tar.gz` from a shared,
    /// mutable body, returning its base URL alongside the handle used to
    /// change what it serves after the server starts — needed to simulate a
    /// poll fetching a newer bundle than the one served at startup.
    /// `serve_bundle` is a fixed-body wrapper around this for tests that
    /// never need to change the response.
    async fn serve_bundle_dynamic() -> (String, Arc<Mutex<Vec<u8>>>) {
        let body = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let shared = Arc::clone(&body);
        let app = axum::Router::new().route(
            "/bundle.tar.gz",
            axum::routing::get(move || {
                let shared = Arc::clone(&shared);
                async move { shared.lock().expect("body lock").clone() }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test bundle");
        });
        (format!("http://{addr}/bundle.tar.gz"), body)
    }

    /// Starts a local axum server that serves `body` at `/bundle.tar.gz` and
    /// returns its base URL. The server is bound to an OS-assigned loopback
    /// port and runs for the life of the test binary — acceptable for a
    /// short-lived unit test.
    async fn serve_bundle(body: Vec<u8>) -> String {
        let (url, shared) = serve_bundle_dynamic().await;
        *shared.lock().expect("body lock") = body;
        url
    }

    #[tokio::test]
    async fn http_source_loads_without_a_local_bundle_path() {
        let verifier = TestSignedVerifier::new();
        let artifact = verifier.sign(&good_bundle_yaml(1));
        assert!(
            apf_bundle::Bundle::from_payload_bytes(&artifact).is_err(),
            "a signed artifact should not parse as a bare Bundle"
        );
        let url = serve_bundle(pack_bundle_tar_gz(&artifact)).await;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let compiler = apf_compiler::Compiler::new(vec![]);
        let counter_store =
            CounterStore::load_or_init(&tmp.path().join("counter")).expect("init counter store");
        let src = HttpBundleSource::new(&url, "", compiler, Arc::new(verifier), counter_store)
            .expect("build http bundle source");

        assert!(!src.is_ready(), "source should not be ready before load");
        src.load_initial()
            .await
            .expect("load_initial should succeed from the remote bundle alone");
        assert!(src.is_ready());
        assert_eq!(src.bundle_id(""), Some("test-bundle".to_string()));
    }

    #[tokio::test]
    async fn http_source_persists_counter_on_initial_load() {
        let verifier = TestSignedVerifier::new();
        let artifact = verifier.sign(&good_bundle_yaml(2));
        let url = serve_bundle(pack_bundle_tar_gz(&artifact)).await;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");
        let compiler = apf_compiler::Compiler::new(vec![]);
        let counter_store = CounterStore::load_or_init(&counter_path).expect("init counter store");
        let src = HttpBundleSource::new(&url, "", compiler, Arc::new(verifier), counter_store)
            .expect("build http bundle source");

        src.load_initial()
            .await
            .expect("load_initial should succeed from the remote bundle alone");

        let reloaded =
            CounterStore::load_or_init(&counter_path).expect("reload counter store from disk");
        assert_eq!(
            reloaded.high_water_mark(),
            2,
            "initial load must persist the verified counter, not just cache it in memory"
        );
    }

    #[tokio::test]
    async fn http_source_poll_defers_swap_when_persist_fails() {
        let verifier = TestSignedVerifier::new();
        let (url, body) = serve_bundle_dynamic().await;
        *body.lock().expect("body lock") = pack_bundle_tar_gz(&verifier.sign(&good_bundle_yaml(1)));

        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");

        let compiler = apf_compiler::Compiler::new(vec![]);
        let counter_store = CounterStore::load_or_init(&counter_path).expect("init counter store");
        let src = HttpBundleSource::new(&url, "", compiler, Arc::new(verifier), counter_store)
            .expect("build http bundle source");
        src.load_initial()
            .await
            .expect("initial load should succeed");
        assert_eq!(src.current_counter(), 1);

        // Force the next persist attempt to fail with a real I/O error,
        // deterministically regardless of the test process's privileges —
        // unlike a permission-based block, which root bypasses. The atomic
        // writer creates a `.tmp` sibling before renaming it into place;
        // occupying that path with a directory makes the write fail with
        // "is a directory," a structural error no uid can override.
        std::fs::create_dir_all(counter_path.with_extension("tmp"))
            .expect("occupy the .tmp path with a directory");

        // `verifier` was moved into the source above; a fresh instance signs
        // with the same fixed test key.
        let verifier2 = TestSignedVerifier::new();
        *body.lock().expect("body lock") =
            pack_bundle_tar_gz(&verifier2.sign(&good_bundle_yaml(2)));

        // `poll_variant` itself now propagates the persist failure as `Err`
        // (via `extract_and_compile`) — it's `poll_for_update`, the loop the
        // background task actually calls, that catches and logs per-variant
        // errors so one variant's persist failure can't take down polling
        // for the others.
        let poll_result = src.poll_for_update().await;

        assert!(
            poll_result.is_ok(),
            "a persist failure for one variant must not fail the overall poll: {poll_result:?}"
        );
        assert_eq!(
            src.current_counter(),
            1,
            "the in-memory swap must be deferred, not applied, when persisting the new counter fails"
        );

        let reloaded =
            CounterStore::load_or_init(&counter_path).expect("reload counter store from disk");
        assert_eq!(
            reloaded.high_water_mark(),
            1,
            "the persisted counter must stay at the last successfully-written value"
        );
    }

    #[tokio::test]
    async fn http_source_rejects_unsigned_bundle() {
        let verifier = TestSignedVerifier::new();
        // Plain YAML bytes, never passed through `verifier.sign(...)` — no
        // signature document, so `verify()` rejects it.
        let unsigned = good_bundle_yaml(1).into_bytes();
        let url = serve_bundle(pack_bundle_tar_gz(&unsigned)).await;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let compiler = apf_compiler::Compiler::new(vec![]);
        let counter_store =
            CounterStore::load_or_init(&tmp.path().join("counter")).expect("init counter store");
        let src = HttpBundleSource::new(&url, "", compiler, Arc::new(verifier), counter_store)
            .expect("build http bundle source");

        let result = src.load_initial().await;
        assert!(result.is_err(), "unsigned bundle should be rejected");
        assert!(!src.is_ready());
    }

    #[tokio::test]
    async fn http_source_rejects_older_bundle_than_persisted_counter() {
        let verifier = TestSignedVerifier::new();
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");

        // Pre-seed the persistent counter store past the revision the
        // remote bundle will claim, simulating a newer bundle this host
        // already accepted in a prior run.
        {
            let mut seed_store =
                CounterStore::load_or_init(&counter_path).expect("init counter store");
            seed_store
                .check_and_advance(2, &hex::encode(Sha256::digest(b"newer bundle")))
                .expect("seed counter");
        }

        let artifact = verifier.sign(&good_bundle_yaml(1));
        let url = serve_bundle(pack_bundle_tar_gz(&artifact)).await;

        let compiler = apf_compiler::Compiler::new(vec![]);
        let counter_store =
            CounterStore::load_or_init(&counter_path).expect("reload counter store");
        let src = HttpBundleSource::new(&url, "", compiler, Arc::new(verifier), counter_store)
            .expect("build http bundle source");

        let result = src.load_initial().await;
        assert!(result.is_err(), "older bundle should be rejected");
        assert!(!src.is_ready());
    }

    /// A service restart re-fetches the bundle it was already serving and
    /// must come back ready without touching the persisted counter.
    #[tokio::test]
    async fn http_source_restart_reloads_identical_bundle() {
        let artifact = TestSignedVerifier::new().sign(&good_bundle_yaml(2));
        let url = serve_bundle(pack_bundle_tar_gz(&artifact)).await;
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");

        for run in ["initial", "restart"] {
            let counter_store =
                CounterStore::load_or_init(&counter_path).expect("load counter store");
            let src = HttpBundleSource::new(
                &url,
                "",
                apf_compiler::Compiler::new(vec![]),
                Arc::new(TestSignedVerifier::new()),
                counter_store,
            )
            .expect("build http bundle source");
            src.load_initial()
                .await
                .unwrap_or_else(|e| panic!("{run} load should succeed: {e}"));
            assert!(src.is_ready(), "{run}: source should be ready");
            assert_eq!(src.current_counter(), 2, "{run}: cached counter");
            assert_eq!(
                std::fs::read(&counter_path).expect("read counter file"),
                b"2\n",
                "{run}: persisted counter"
            );
        }
    }

    #[tokio::test]
    async fn http_source_rejects_different_bundle_at_accepted_counter() {
        let signer = TestSignedVerifier::new();
        let (url, body) = serve_bundle_dynamic().await;
        *body.lock().expect("body lock") = pack_bundle_tar_gz(&signer.sign(&good_bundle_yaml(2)));
        let tmp = tempfile::tempdir().expect("create temp dir");
        let counter_path = tmp.path().join("counter");

        let first = HttpBundleSource::new(
            &url,
            "",
            apf_compiler::Compiler::new(vec![]),
            Arc::new(TestSignedVerifier::new()),
            CounterStore::load_or_init(&counter_path).expect("init counter store"),
        )
        .expect("build http bundle source");
        first
            .load_initial()
            .await
            .expect("initial load should succeed");

        // Same revision, same trusted signer, different content.
        *body.lock().expect("body lock") = pack_bundle_tar_gz(
            &signer.sign(&good_bundle_yaml(2).replace("id: test-bundle", "id: reissued-bundle")),
        );
        let restarted = HttpBundleSource::new(
            &url,
            "",
            apf_compiler::Compiler::new(vec![]),
            Arc::new(TestSignedVerifier::new()),
            CounterStore::load_or_init(&counter_path).expect("reload counter store"),
        )
        .expect("build http bundle source");
        let result = restarted.load_initial().await;
        assert!(
            result.is_err(),
            "a different bundle at an accepted revision must be rejected"
        );
        assert!(!restarted.is_ready());
        assert_eq!(
            std::fs::read(&counter_path).expect("read counter file"),
            b"2\n"
        );
    }
}
