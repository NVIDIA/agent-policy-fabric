// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Policy source that reads directly from the projections compiled at daemon startup.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::PolicyProjection;
use super::PolicySource;
use crate::runtime::core::PolicyServiceCore;

/// [`PolicySource`] backed by the bundle loaded at daemon startup.
pub struct LocalBundleSource {
    core: Arc<PolicyServiceCore>,
}

impl LocalBundleSource {
    #[must_use]
    pub fn new(core: Arc<PolicyServiceCore>) -> Self {
        Self { core }
    }
}

impl PolicySource for LocalBundleSource {
    fn get(&self, surface_id: &str, name: &str, _variant: &str) -> Option<PolicyProjection> {
        let bytes = self
            .core
            .projections
            .get(&(surface_id.to_string(), name.to_string()))?
            .clone();
        let digest = hex::encode(Sha256::digest(&bytes));
        let version = self.core.bundle.monotonic_counter;
        Some(PolicyProjection {
            bytes,
            digest,
            version,
        })
    }

    fn list(&self, surface_id: &str) -> Vec<String> {
        self.core
            .projections
            .keys()
            .filter(|(kind, _)| kind == surface_id)
            .map(|(_, name)| name.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use crate::runtime::audit::{BundleAuditMetadata, PolicyServiceAudit};
    use crate::runtime::core::{LoadedBundle, PolicyServiceCore};

    fn make_core(projections: BTreeMap<(String, String), Vec<u8>>) -> Arc<PolicyServiceCore> {
        Arc::new(PolicyServiceCore {
            bundle: LoadedBundle {
                digest_hex: "abc".to_string(),
                monotonic_counter: 7,
                audit_metadata: BundleAuditMetadata::from_counter_and_digest(0, ""),
            },
            projections,
            verifier_identity: None,
            audit: PolicyServiceAudit::disabled(),
        })
    }

    #[test]
    fn get_returns_projection_with_correct_digest_and_version() {
        let bytes = vec![1u8, 2, 3];
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        let mut proj = BTreeMap::new();
        proj.insert(
            ("openshell.sandbox.v1".to_string(), "default".to_string()),
            bytes.clone(),
        );
        let source = LocalBundleSource::new(make_core(proj));

        let p = source
            .get("openshell.sandbox.v1", "default", "")
            .expect("found");
        assert_eq!(p.bytes, bytes);
        assert_eq!(p.digest, digest);
        assert_eq!(p.version, 7);
    }

    #[test]
    fn get_returns_none_for_unknown_name() {
        let source = LocalBundleSource::new(make_core(BTreeMap::new()));
        assert!(source.get("openshell.sandbox.v1", "missing", "").is_none());
    }

    #[test]
    fn list_returns_names_for_surface() {
        let mut proj = BTreeMap::new();
        proj.insert(
            ("openshell.sandbox.v1".to_string(), "default".to_string()),
            vec![],
        );
        proj.insert(
            ("openshell.sandbox.v1".to_string(), "strict".to_string()),
            vec![],
        );
        proj.insert(("other.surface".to_string(), "x".to_string()), vec![]);
        let source = LocalBundleSource::new(make_core(proj));

        let mut names = source.list("openshell.sandbox.v1");
        names.sort();
        assert_eq!(names, vec!["default", "strict"]);
    }
}
