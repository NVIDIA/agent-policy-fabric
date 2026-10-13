// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Policy source backed by a local bundle file with hot-swap support.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use apf_bundle::CounterStore;
use apf_compiler::Compiler;
use apf_types::BundleVerifier;

use async_trait::async_trait;

use super::{PolicyProjection, PolicySource, RefreshOutcome};
use crate::runtime::audit::{BundleAuditMetadata, PolicyServiceAudit};
use crate::runtime::core::{DocumentSigner, LoadedBundle, PolicyServiceCore};

/// [`PolicySource`] backed by the current live bundle.
///
/// Holds an `ArcSwap` so hot-swaps via `refresh()` are immediately visible
/// to all document lookups without restarting the service.
///
/// Optionally configured with reload context (verifier, counter store,
/// compiler, signer) to support `refresh(bundle_path)`.
pub struct LocalBundleSource {
    core: Arc<arc_swap::ArcSwap<PolicyServiceCore>>,
    // Reload context — present when local hot-swap is supported.
    verifier: Option<Arc<dyn BundleVerifier>>,
    counter_store: Option<Mutex<CounterStore>>,
    compiler: Option<Compiler>,
    document_signer: Option<Arc<DocumentSigner>>,
    allowed_surfaces: Option<BTreeSet<String>>,
    audit: PolicyServiceAudit,
}

impl LocalBundleSource {
    /// Read-only source backed by the given core. Does not support `refresh()`.
    #[must_use]
    pub fn new(core: Arc<arc_swap::ArcSwap<PolicyServiceCore>>) -> Self {
        Self {
            core,
            verifier: None,
            counter_store: None,
            compiler: None,
            document_signer: None,
            allowed_surfaces: None,
            audit: PolicyServiceAudit::disabled(),
        }
    }

    /// Source with full reload context. Supports `refresh(bundle_path)`.
    #[must_use]
    pub fn with_reload(
        core: Arc<arc_swap::ArcSwap<PolicyServiceCore>>,
        verifier: Arc<dyn BundleVerifier>,
        counter_store: CounterStore,
        compiler: Compiler,
        document_signer: Option<Arc<DocumentSigner>>,
        allowed_surfaces: Option<BTreeSet<String>>,
        audit: PolicyServiceAudit,
    ) -> Self {
        Self {
            core,
            verifier: Some(verifier),
            counter_store: Some(Mutex::new(counter_store)),
            compiler: Some(compiler),
            document_signer,
            allowed_surfaces,
            audit,
        }
    }

    fn load_bundle(&self, bundle_path: &Path) -> anyhow::Result<PolicyServiceCore> {
        use apf_compiler::surfaces_to_projections;

        let verifier = self
            .verifier
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("reload context not configured"))?;
        let counter_store_mutex = self
            .counter_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("reload context not configured"))?;
        let compiler = self
            .compiler
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("reload context not configured"))?;

        let bundle_bytes = std::fs::read(bundle_path)
            .map_err(|e| anyhow::anyhow!("read bundle {}: {e}", bundle_path.display()))?;

        let mut counter_store = counter_store_mutex.lock().expect("counter store lock");

        // `verify_and_advance` only persists the counter once compilation
        // below succeeds, so a compilation failure doesn't permanently
        // consume the counter slot.
        super::BundleLoadContext {
            verifier: verifier.as_ref(),
            counter_store: &mut counter_store,
            audit: &self.audit,
        }
        .verify_and_advance(&bundle_bytes, bundle_path, |outcome| {
            let parsed_bundle = outcome.bundle.clone().expect("verified bundle present");
            let bundle_dir = bundle_path.parent().unwrap_or_else(|| Path::new("."));
            let members = parsed_bundle
                .load_members(bundle_dir)
                .map_err(|e| anyhow::anyhow!("load bundle members: {e}"))?;

            let compiled = compiler
                .lower_members(&members, self.allowed_surfaces.as_ref())
                .map_err(|e| anyhow::anyhow!("compile bundle: {e}"))?;

            let projections = surfaces_to_projections(compiled.surfaces);
            let driver_configs = compiled.sandbox_driver_configs;

            Ok(PolicyServiceCore {
                bundle: LoadedBundle {
                    digest_hex: outcome.digest_hex.clone(),
                    monotonic_counter: outcome.monotonic_counter,
                    audit_metadata: BundleAuditMetadata::from_counter_and_digest(
                        outcome.monotonic_counter,
                        "",
                    ),
                    bundle: parsed_bundle,
                },
                projections,
                driver_configs,
                document_signer: self.document_signer.clone(),
                audit: self.audit.clone(),
            })
        })
    }
}

#[async_trait]
impl PolicySource for LocalBundleSource {
    fn get(&self, surface_id: &str, name: &str, _variant: &str) -> Option<PolicyProjection> {
        let core = self.core.load();
        let bytes = core
            .projections
            .get(&(surface_id.to_string(), name.to_string()))?
            .clone();
        let digest = hex::encode(Sha256::digest(&bytes));
        let version = core.bundle.monotonic_counter;
        Some(PolicyProjection {
            bytes,
            digest,
            version,
        })
    }

    fn active_bundle_digest(&self, _variant: &str) -> Option<String> {
        Some(self.core.load().bundle.digest_hex.clone())
    }

    fn get_with_bundle(
        &self,
        surface_id: &str,
        name: &str,
        _variant: &str,
    ) -> Option<(PolicyProjection, String)> {
        // One load: a refresh between two would let the record name a bundle
        // other than the one this projection came from.
        let core = self.core.load();
        let bytes = core
            .projections
            .get(&(surface_id.to_string(), name.to_string()))?
            .clone();
        let digest = hex::encode(Sha256::digest(&bytes));
        Some((
            PolicyProjection {
                bytes,
                digest,
                version: core.bundle.monotonic_counter,
            },
            core.bundle.digest_hex.clone(),
        ))
    }

    fn driver_config(&self, name: &str, _variant: &str) -> Option<Vec<u8>> {
        self.core.load().driver_configs.get(name).cloned()
    }

    fn list(&self, surface_id: &str) -> Vec<String> {
        let core = self.core.load();
        core.projections
            .keys()
            .filter(|(kind, _)| kind == surface_id)
            .map(|(_, name)| name.clone())
            .collect()
    }

    async fn refresh(&self, bundle_path: Option<&Path>) -> anyhow::Result<RefreshOutcome> {
        let path = bundle_path
            .ok_or_else(|| anyhow::anyhow!("bundle_path is required for local bundle refresh"))?;
        let new_core = self.load_bundle(path)?;
        let outcome = RefreshOutcome {
            policy_digest: new_core.bundle.digest_hex.clone(),
            version: new_core.bundle.monotonic_counter,
        };
        self.core.store(Arc::new(new_core));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;

    fn make_source(projections: BTreeMap<(String, String), Vec<u8>>) -> LocalBundleSource {
        LocalBundleSource::new(Arc::new(arc_swap::ArcSwap::new(Arc::new(
            PolicyServiceCore {
                bundle: LoadedBundle {
                    digest_hex: "abc".to_string(),
                    monotonic_counter: 7,
                    audit_metadata: BundleAuditMetadata::from_counter_and_digest(0, ""),
                    bundle: Default::default(),
                },
                projections,
                driver_configs: BTreeMap::new(),
                document_signer: None,
                audit: PolicyServiceAudit::disabled(),
            },
        ))))
    }

    #[test]
    fn get_returns_projection_with_correct_digest_and_version() {
        let mut proj = BTreeMap::new();
        let bytes = vec![1u8, 2, 3];
        proj.insert(
            ("openshell.sandbox.v1".into(), "default".into()),
            bytes.clone(),
        );
        let source = make_source(proj);
        let p = source
            .get("openshell.sandbox.v1", "default", "")
            .expect("projection");
        assert_eq!(p.bytes, bytes);
        assert_eq!(p.version, 7);
        assert!(!p.digest.is_empty());
    }

    #[test]
    fn get_returns_none_for_unknown_name() {
        let source = make_source(BTreeMap::new());
        assert!(source.get("openshell.sandbox.v1", "default", "").is_none());
    }

    #[test]
    fn list_returns_names_for_surface() {
        let mut proj = BTreeMap::new();
        proj.insert(("openshell.sandbox.v1".into(), "default".into()), vec![1]);
        proj.insert(
            ("openshell.provider-profile.v1".into(), "slack".into()),
            vec![2],
        );
        let source = make_source(proj);
        let mut names = source.list("openshell.sandbox.v1");
        names.sort();
        assert_eq!(names, vec!["default"]);
    }
}
