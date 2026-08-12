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
