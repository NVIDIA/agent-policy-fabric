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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tracing::{info, trace, warn};

use super::{PolicyProjection, PolicySource};
use crate::runtime::audit::{BundleAuditMetadata, PolicyRejectAudit, PolicyServiceAudit};
use crate::runtime::runtime_context::RuntimeContext;
use apf_bundle::{CounterStore, YamlSigilVerifier};
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
    /// Monotonic counter from the bundle manifest (`policy_revision`).
    current_counter: u64,
    /// SHA-256 hex digest of the fetched tar.gz — used for change detection
    /// without re-extracting the archive on every poll.
    bundle_digest: String,
}

impl BundleCache {
    /// Atomically swap the cache contents if `new_counter` strictly exceeds
    /// the current counter (monotonic-counter anti-rollback). Returns `true`
    /// when the swap is accepted.
    fn try_swap(
        &mut self,
        new_projections: BTreeMap<(String, String), PolicyProjection>,
        new_counter: u64,
        new_digest: String,
    ) -> bool {
        if new_counter <= self.current_counter {
            return false;
        }
        self.projections = new_projections;
        self.current_counter = new_counter;
        self.bundle_digest = new_digest;
        true
    }
}

/// Fetches signed bundle tar.gz files from an HTTP endpoint, compiles them, and
/// serves projections from per-variant in-memory caches.
///
/// The URL can be a literal (`https://.../bundle.tar.gz`) or a template with
/// a `{variant}` placeholder (`https://.../governed-{variant}/latest.tar.gz`).
/// When a template is used, each resolved variant gets its own
/// [`BundleCache`], enabling the [`ClaimsResolver`] to route different users
/// to different policy bundles.
pub struct HttpBundleSource {
    url_template: String,
    auth_token: String,
    compiler: apf_compiler::Compiler,
    /// Per-variant caches. A literal URL stores everything under the key `""`.
    caches: Arc<RwLock<BTreeMap<String, BundleCache>>>,
    http_client: reqwest::Client,
    /// Persistent counter store for cross-restart anti-rollback.
    counter_store: Mutex<Option<CounterStore>>,
    /// Audit emitter for policy lifecycle events on the hot-swap path.
    audit: PolicyServiceAudit,
    /// Verifies every fetched bundle's signature against the trust store
    /// before it's compiled or served — see `super::verify_bundle_bytes`.
    verifier: YamlSigilVerifier,
}

impl HttpBundleSource {
    /// Build a new source. `url` may contain `{variant}` for template-based
    /// multi-bundle resolution. `verifier` is mandatory: an HTTP-fetched
    /// bundle is never trusted on transport (token/TLS) alone.
    pub fn new(
        url: &str,
        token: &str,
        compiler: apf_compiler::Compiler,
        verifier: YamlSigilVerifier,
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
            counter_store: Mutex::new(None),
            audit: PolicyServiceAudit,
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

    /// Fetch and cache a specific variant. Used at startup for the default
    /// variant and lazily for template-resolved variants.
    pub async fn load_variant(&self, variant: &str) -> anyhow::Result<()> {
        let url = self.resolve_url(variant);
        self.load_variant_inner(variant, &url).await
    }

    async fn load_variant_inner(&self, variant: &str, url: &str) -> anyhow::Result<()> {
        let tar_gz = self.fetch_bundle_from(url).await?;
        let (projections, counter, digest) = self.extract_and_compile(&tar_gz)?;

        let projection_count = projections.len();

        let mut caches = self.caches.write().expect("cache lock poisoned");
        let cache = caches.entry(variant.to_string()).or_default();
        cache.projections = projections;
        cache.current_counter = counter;
        cache.bundle_digest = digest.clone();

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

        let (projections, counter, digest) = self.extract_and_compile(&tar_gz)?;
        let projection_count = projections.len();

        let swapped = {
            let mut caches = self.caches.write().expect("cache lock poisoned");
            let cache = caches.entry(variant.to_string()).or_default();
            cache.try_swap(projections, counter, digest.clone())
        };

        if swapped {
            if let Some(ref mut store) = *self
                .counter_store
                .lock()
                .expect("counter store lock poisoned")
                && let Err(e) = store.check_and_advance(counter)
            {
                warn!(
                    counter,
                    error = %e,
                    "persistent counter advance failed; in-memory swap accepted"
                );
                self.emit_hot_swap_reject(
                    "policy.hot_swap_rejected.counter_persist_failed",
                    format!("persistent counter advance failed: {e}"),
                    true,
                    counter,
                    &digest,
                );
            }

            let metadata = BundleAuditMetadata::from_counter_and_digest(counter, &digest);
            if let Err(e) = self.audit.emit_policy_hot_swap(&metadata, &digest, counter) {
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
                "policy.hot_swap_rejected.counter_not_newer",
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
        let meta = BundleAuditMetadata::from_counter_and_digest(counter, digest);
        let reject = PolicyRejectAudit::new(reason_code, message)
            .with_retryable(retryable)
            .with_bundle_counter(Some(counter))
            .with_metadata_source("http_bundle_source_poll");
        if let Err(e) =
            self.audit
                .emit_policy_reject(&RuntimeContext::default(), &meta, digest, reject)
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

    pub fn set_counter_store(&self, store: CounterStore) {
        *self
            .counter_store
            .lock()
            .expect("counter store lock poisoned") = Some(store);
    }

    pub fn set_audit(&mut self, audit: PolicyServiceAudit) {
        self.audit = audit;
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
    #[allow(clippy::type_complexity)]
    fn extract_and_compile(
        &self,
        tar_gz: &[u8],
    ) -> anyhow::Result<(BTreeMap<(String, String), PolicyProjection>, u64, String)> {
        let tar_digest = hex::encode(Sha256::digest(tar_gz));
        let tmp_dir = tempfile::tempdir().map_err(|e| anyhow::anyhow!("create temp dir: {e}"))?;

        let gz = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(gz);
        archive
            .unpack(tmp_dir.path())
            .map_err(|e| anyhow::anyhow!("unpack tar.gz: {e}"))?;

        let manifest_path = find_bundle_manifest(tmp_dir.path())?;

        // Verify signature + counter before compiling, so an unsigned or
        // rolled-back artifact never reaches the compiler or the cache.
        let bundle_bytes = std::fs::read(&manifest_path)
            .map_err(|e| anyhow::anyhow!("read manifest: {e}"))?;
        let counter = {
            let counter_store_guard = self
                .counter_store
                .lock()
                .expect("counter store lock poisoned");
            let counter_store = counter_store_guard.as_ref().ok_or_else(|| {
                anyhow::anyhow!("counter store not configured; cannot verify bundle")
            })?;
            let outcome = super::verify_bundle_bytes(
                &bundle_bytes,
                &manifest_path,
                &self.verifier as &dyn BundleVerifier,
                counter_store,
            )?;
            outcome.monotonic_counter
        };

        let compiled = self
            .compiler
            .compile_file(&manifest_path)
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
                        version: counter,
                    },
                )
            })
            .collect();

        Ok((projections, counter, tar_digest))
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

/// Walk the extracted archive looking for the bundle manifest — the first
/// yaml-sigil signed artifact whose payload deserialises as a [`Bundle`].
///
/// Candidates are sorted so `manifest.yaml` and files whose name contains
/// `bundle` are tried first, avoiding unnecessary parse attempts in archives
/// with many YAML files.
fn find_bundle_manifest(extract_dir: &Path) -> anyhow::Result<PathBuf> {
    let mut candidates = Vec::new();
    collect_yaml_files(extract_dir, &mut candidates)?;

    candidates.sort_by_key(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "manifest.yaml" {
            0
        } else if name.contains("bundle") {
            1
        } else {
            2
        }
    });

    for path in &candidates {
        if let Ok(bytes) = std::fs::read(path)
            && apf_bundle::Bundle::from_payload_bytes(&bytes).is_ok()
        {
            return Ok(path.clone());
        }
    }
    anyhow::bail!(
        "no bundle manifest (.yaml) found in extracted archive at {}",
        extract_dir.display()
    )
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files(&path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn make_test_source(cache: BundleCache) -> HttpBundleSource {
        let mut caches = BTreeMap::new();
        caches.insert(String::new(), cache);
        // Empty trust store: these tests populate the cache directly and
        // never go through extract_and_compile, so no verification runs.
        let empty_trust_dir = tempfile::tempdir().expect("create empty trust dir");
        let verifier =
            YamlSigilVerifier::new(apf_bundle::TrustStore::load_from_dir(empty_trust_dir.path())
                .expect("load empty trust store"));
        HttpBundleSource {
            url_template: String::new(),
            auth_token: String::new(),
            compiler: apf_compiler::Compiler::new(vec![]),
            caches: Arc::new(RwLock::new(caches)),
            http_client: reqwest::Client::new(),
            counter_store: Mutex::new(None),
            audit: PolicyServiceAudit::default(),
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
        let mut cache = BundleCache::default();
        cache.current_counter = 3;

        let mut new_proj = BTreeMap::new();
        new_proj.insert(
            ("openshell.sandbox.v1".to_string(), "strict".to_string()),
            PolicyProjection {
                bytes: vec![7, 8, 9],
                digest: hex::encode(sha2::Sha256::digest(&[7, 8, 9])),
                version: 4,
            },
        );

        assert!(cache.try_swap(new_proj, 4, "new-digest".to_string()));
        assert_eq!(cache.current_counter, 4);
        assert_eq!(cache.bundle_digest, "new-digest");
        assert!(
            cache
                .projections
                .contains_key(&("openshell.sandbox.v1".to_string(), "strict".to_string()))
        );
    }

    #[test]
    fn bundle_cache_swap_equal_counter_is_rejected() {
        let mut cache = BundleCache::default();
        cache.current_counter = 5;
        cache.bundle_digest = "old-digest".to_string();

        assert!(!cache.try_swap(BTreeMap::new(), 5, "new-digest".to_string()));
        assert_eq!(cache.current_counter, 5);
        assert_eq!(cache.bundle_digest, "old-digest");
    }

    #[test]
    fn bundle_cache_swap_lower_counter_is_rejected() {
        let mut cache = BundleCache::default();
        cache.current_counter = 10;

        assert!(!cache.try_swap(BTreeMap::new(), 3, "x".to_string()));
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
        };
        let source = make_test_source(cache);

        let mut names = source.list("openshell.sandbox.v1");
        names.sort();
        assert_eq!(names, vec!["default", "strict"]);
        assert_eq!(source.list("other.surface"), vec!["x"]);
        assert!(source.list("missing").is_empty());
    }
}
