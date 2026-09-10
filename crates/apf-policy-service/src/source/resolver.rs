// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Policy name resolution — maps a requested policy name + runtime context
//! to the concrete bundle variant name to look up in the policy source.
//!
//! Two implementations:
//! - [`PassthroughResolver`]: returns the policy name unchanged.
//! - [`ClaimsResolver`]: maps `user_subject` from the `OpenShell` platform
//!   context to a role suffix via a static role map, producing variant names
//!   like `"my-governed-profile-admin"`.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use apf_proto::runtime_v1alpha1::{RuntimeContext, runtime_context};

/// Result of resolving a policy name against runtime context.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// Key selecting which of a `PolicySource`'s parallel caches serves
    /// this caller for the same policy name. Its meaning is entirely up
    /// to the [`PolicyResolver`] implementation — [`ClaimsResolver`] uses
    /// a role suffix (e.g. `"rw"`, `"admin"`); [`PassthroughResolver`]
    /// leaves it empty. Also the `{variant}` a template `HttpBundleSource`
    /// URL resolves to. Empty string selects the source's single default
    /// cache.
    pub variant: String,
    /// Document name to look up within the variant's projections.
    pub name: String,
}

pub trait PolicyResolver: Send + Sync {
    fn resolve(&self, policy_name: &str, ctx: &RuntimeContext) -> ResolvedPolicy;
}

/// Returns `policy_name` unchanged. Context is accepted but unused,
/// keeping the interface stable for claims-based resolvers.
pub struct PassthroughResolver;

impl PolicyResolver for PassthroughResolver {
    fn resolve(&self, policy_name: &str, _ctx: &RuntimeContext) -> ResolvedPolicy {
        ResolvedPolicy {
            variant: String::new(),
            name: policy_name.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ClaimsResolver — resolve via user_subject → role suffix mapping.
// ---------------------------------------------------------------------------

/// JSON-serialisable configuration for [`ClaimsResolver`].
///
/// Loaded from disk at startup via [`ClaimsResolver::from_config_file`].
/// The only required field is `role_map`, which maps user subjects to the
/// variant suffix appended to the policy name at resolution time.
#[derive(Debug, Deserialize)]
pub struct ClaimsResolverConfig {
    /// Maps `user_subject` (e.g. `"alice@example.com"`) to a variant suffix
    /// (e.g. `"admin"`). At resolution time the suffix is appended to the
    /// policy name: `"{policy_name}-{suffix}"`.
    pub role_map: HashMap<String, String>,
}

/// Resolves policy variants from a static JSON config file mapping `user_subject`
/// to role suffixes. Unknown subjects fall through to the unmodified policy name.
pub struct ClaimsResolver {
    role_map: HashMap<String, String>,
}

impl ClaimsResolver {
    #[must_use]
    pub fn new(role_map: HashMap<String, String>) -> Self {
        Self { role_map }
    }

    /// Load a [`ClaimsResolverConfig`] from a JSON file and build the resolver.
    pub fn from_config_file(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read claims config {}: {e}", path.display()))?;
        let config: ClaimsResolverConfig = serde_json::from_str(&data)
            .map_err(|e| anyhow::anyhow!("parse claims config {}: {e}", path.display()))?;
        Ok(Self::new(config.role_map))
    }
}

impl PolicyResolver for ClaimsResolver {
    fn resolve(&self, policy_name: &str, ctx: &RuntimeContext) -> ResolvedPolicy {
        let user_subject = ctx.platform.as_ref().map(|p| match p {
            runtime_context::Platform::Openshell(o) => o.user_subject.as_str(),
        });

        let variant = user_subject
            .and_then(|s| self.role_map.get(s))
            .cloned()
            .unwrap_or_default();

        ResolvedPolicy {
            variant,
            name: policy_name.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apf_proto::runtime_v1alpha1::OpenShellContext;

    fn make_openshell_ctx(user_subject: &str, sandbox_id: &str) -> RuntimeContext {
        RuntimeContext {
            platform: Some(runtime_context::Platform::Openshell(OpenShellContext {
                sandbox_id: sandbox_id.to_string(),
                user_subject: user_subject.to_string(),
                agent_type: String::new(),
            })),
            audit_context: Default::default(),
        }
    }

    #[test]
    fn passthrough_returns_name_unchanged() {
        let r = PassthroughResolver;
        let ctx = RuntimeContext::default();
        let resolved = r.resolve("my-governed-profile", &ctx);
        assert_eq!(resolved.name, "my-governed-profile");
        assert!(resolved.variant.is_empty());
    }

    #[test]
    fn claims_resolver_maps_known_user_to_variant() {
        let mut map = HashMap::new();
        map.insert("alice@example.com".to_string(), "admin".to_string());
        map.insert("bob@example.com".to_string(), "restricted".to_string());
        let r = ClaimsResolver::new(map);

        let ctx = make_openshell_ctx("alice@example.com", "sb-1");
        let resolved = r.resolve("my-governed-profile", &ctx);
        assert_eq!(resolved.variant, "admin");
        assert_eq!(resolved.name, "my-governed-profile");
    }

    #[test]
    fn claims_resolver_falls_back_for_unknown_user() {
        let mut map = HashMap::new();
        map.insert("alice@example.com".to_string(), "admin".to_string());
        let r = ClaimsResolver::new(map);

        let ctx = make_openshell_ctx("unknown@example.com", "sb-1");
        let resolved = r.resolve("my-governed-profile", &ctx);
        assert!(resolved.variant.is_empty());
        assert_eq!(resolved.name, "my-governed-profile");
    }

    #[test]
    fn claims_resolver_loads_from_config_file() {
        let config_json =
            r#"{"role_map": {"alice@example.com": "admin", "bob@example.com": "restricted"}}"#;
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), config_json).expect("write config");

        let r = ClaimsResolver::from_config_file(tmp.path()).expect("load config");
        let ctx = make_openshell_ctx("bob@example.com", "sb-2");
        let resolved = r.resolve("my-governed-profile", &ctx);
        assert_eq!(resolved.variant, "restricted");
        assert_eq!(resolved.name, "my-governed-profile");
    }
}
