// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! TOML-based daemon configuration.
//!
//! All fields are optional so operators can provide a partial config file
//! and rely on CLI args or compiled defaults for the rest. The merge
//! precedence is: CLI > env var > TOML > compiled default.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level daemon configuration. All fields are optional; unset fields fall
/// back to CLI arguments or compiled defaults.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ServiceConfig {
    pub socket: Option<PathBuf>,
    pub bundle_path: Option<PathBuf>,
    pub trust_root_dir: Option<PathBuf>,
    pub counter_store: Option<PathBuf>,
    pub audit_log_path: Option<PathBuf>,
    pub allowed_uid: Option<u32>,
    pub http_addr: Option<SocketAddr>,
    pub surfaces: Option<Vec<String>>,
    pub document_ttl_secs: Option<u64>,

    #[serde(default)]
    pub verifier: VerifierConfig,
    #[serde(default)]
    pub policy_source: PolicySourceConfig,
    #[serde(default)]
    pub resolver: ResolverConfig,
    #[serde(default)]
    pub provenance: ProvenanceConfig,
}

/// Configuration for the document signer that mints provenance JWTs.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct VerifierConfig {
    pub signing_key: Option<PathBuf>,
    pub key_id: Option<String>,
}

/// Configuration for the policy bundle source backend.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PolicySourceConfig {
    pub backend: Option<String>,
    pub bundle_source_url: Option<String>,
    pub bundle_source_token: Option<String>,
    pub bundle_source_token_file: Option<PathBuf>,
    pub bundle_source_poll_interval_secs: Option<u64>,
}

/// Configuration for the policy name resolver.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ResolverConfig {
    pub backend: Option<String>,
    pub claims_config: Option<PathBuf>,
}

/// Configuration for the provenance token signer.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ProvenanceConfig {
    pub signer: Option<String>,
    pub oidc_discovery: Option<String>,
}

/// Apply TOML config values as defaults for any CLI `Args` fields that
/// weren't explicitly set. The caller passes the parsed `Args` struct;
/// fields at their compiled default are overridden by the TOML value.
/// Fields the user explicitly passed on the CLI are left untouched.
impl ServiceConfig {
    pub fn apply_to_args(
        &self,
        socket: &mut PathBuf,
        bundle_path: &mut Option<PathBuf>,
        trust_root_dir: &mut PathBuf,
        counter_store: &mut PathBuf,
        audit_log_path: &mut Option<PathBuf>,
        allowed_uid: &mut Option<u32>,
        verifier_signing_key: &mut Option<PathBuf>,
        verifier_key_id: &mut String,
        policy_source: &mut String,
        bundle_source_url: &mut Option<String>,
        bundle_source_token: &mut Option<String>,
        bundle_source_token_file: &mut Option<PathBuf>,
        bundle_source_poll_interval_secs: &mut u64,
        resolver: &mut String,
        claims_config: &mut Option<PathBuf>,
        http_addr: &mut Option<SocketAddr>,
        provenance_signer: &mut String,
        provenance_oidc_discovery: &mut Option<String>,
        surfaces: &mut Vec<String>,
    ) {
        if let Some(v) = &self.socket
            && *socket == PathBuf::from("/run/apf/apf-policy-service.sock")
        {
            *socket = v.clone();
        }
        if bundle_path.is_none() {
            *bundle_path = self.bundle_path.clone();
        }
        if let Some(v) = &self.trust_root_dir
            && *trust_root_dir == PathBuf::from("./trust-roots")
        {
            *trust_root_dir = v.clone();
        }
        if let Some(v) = &self.counter_store
            && *counter_store == PathBuf::from("/tmp/apf-counter")
        {
            *counter_store = v.clone();
        }
        if audit_log_path.is_none() {
            *audit_log_path = self.audit_log_path.clone();
        }
        if allowed_uid.is_none() {
            *allowed_uid = self.allowed_uid;
        }
        if verifier_signing_key.is_none() {
            *verifier_signing_key = self.verifier.signing_key.clone();
        }
        if let Some(v) = &self.verifier.key_id
            && verifier_key_id == "apf-dev"
        {
            *verifier_key_id = v.clone();
        }
        if let Some(v) = &self.policy_source.backend
            && policy_source == "local"
        {
            *policy_source = v.clone();
        }
        if bundle_source_url.is_none() {
            *bundle_source_url = self.policy_source.bundle_source_url.clone();
        }
        if bundle_source_token.is_none() {
            *bundle_source_token = self.policy_source.bundle_source_token.clone();
        }
        if bundle_source_token_file.is_none() {
            *bundle_source_token_file = self.policy_source.bundle_source_token_file.clone();
        }
        if let Some(v) = self.policy_source.bundle_source_poll_interval_secs
            && *bundle_source_poll_interval_secs == 30
        {
            *bundle_source_poll_interval_secs = v;
        }
        if let Some(v) = &self.resolver.backend
            && resolver == "passthrough"
        {
            *resolver = v.clone();
        }
        if claims_config.is_none() {
            *claims_config = self.resolver.claims_config.clone();
        }
        if http_addr.is_none() {
            *http_addr = self.http_addr;
        }
        if let Some(v) = &self.provenance.signer
            && provenance_signer == "apf-policy-adapter"
        {
            *provenance_signer = v.clone();
        }
        if provenance_oidc_discovery.is_none() {
            *provenance_oidc_discovery = self.provenance.oidc_discovery.clone();
        }
        if let Some(v) = &self.surfaces
            && surfaces.is_empty()
        {
            *surfaces = v.clone();
        }
    }
}

/// Build a `ServiceConfig` snapshot from resolved runtime values for --config-dump.
pub fn snapshot(
    socket: &Path,
    bundle_path: &Path,
    trust_root_dir: &Path,
    counter_store: &Path,
    audit_log_path: Option<&Path>,
    allowed_uid: Option<u32>,
    verifier_signing_key: Option<&Path>,
    verifier_key_id: &str,
    policy_source: &str,
    bundle_source_url: Option<&str>,
    bundle_source_token_file: Option<&Path>,
    bundle_source_poll_interval_secs: u64,
    resolver: &str,
    claims_config: Option<&Path>,
    http_addr: Option<SocketAddr>,
    provenance_signer: &str,
    provenance_oidc_discovery: &str,
    surfaces: &[String],
    document_ttl_secs: Option<u64>,
) -> ServiceConfig {
    ServiceConfig {
        socket: Some(socket.to_path_buf()),
        bundle_path: Some(bundle_path.to_path_buf()),
        trust_root_dir: Some(trust_root_dir.to_path_buf()),
        counter_store: Some(counter_store.to_path_buf()),
        audit_log_path: audit_log_path.map(Path::to_path_buf),
        allowed_uid,
        http_addr,
        surfaces: if surfaces.is_empty() {
            None
        } else {
            Some(surfaces.to_vec())
        },
        document_ttl_secs,
        verifier: VerifierConfig {
            signing_key: verifier_signing_key.map(Path::to_path_buf),
            key_id: Some(verifier_key_id.to_string()),
        },
        policy_source: PolicySourceConfig {
            backend: Some(policy_source.to_string()),
            bundle_source_url: bundle_source_url.map(str::to_string),
            bundle_source_token: None,
            bundle_source_token_file: bundle_source_token_file.map(Path::to_path_buf),
            bundle_source_poll_interval_secs: Some(bundle_source_poll_interval_secs),
        },
        resolver: ResolverConfig {
            backend: Some(resolver.to_string()),
            claims_config: claims_config.map(Path::to_path_buf),
        },
        provenance: ProvenanceConfig {
            signer: Some(provenance_signer.to_string()),
            oidc_discovery: Some(provenance_oidc_discovery.to_string()),
        },
    }
}

/// Load a [`ServiceConfig`] from a TOML file at `path`.
pub fn load(path: &Path) -> anyhow::Result<ServiceConfig> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read config {}: {e}", path.display()))?;
    let config: ServiceConfig = toml::from_str(&data)
        .map_err(|e| anyhow::anyhow!("parse config {}: {e}", path.display()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let toml = r#"
socket = "/var/run/apf/apf-policy-service.sock"
bundle_path = "/etc/apf/bundle.yaml"
trust_root_dir = "/etc/apf/trust-roots"
counter_store = "/var/lib/apf/counter"
audit_log_path = "/var/log/apf/audit.jsonl"
allowed_uid = 1000
http_addr = "127.0.0.1:9090"
surfaces = ["openshell.sandbox.v1", "openshell.provider-profile.v1"]

[verifier]
signing_key = "/etc/apf/keys/verifier.key"
key_id = "apf-prod"

[policy_source]
backend = "http"
bundle_source_url = "https://example.com/bundle.tar.gz"
bundle_source_token_file = "/vault/secrets/token"
bundle_source_poll_interval_secs = 60

[resolver]
backend = "claims"
claims_config = "/etc/apf/claims.json"

[provenance]
signer = "apf-policy-adapter"
oidc_discovery = "https://policy.example.com/.well-known/openid-configuration"
"#;
        let config: ServiceConfig = toml::from_str(toml).expect("parse");
        assert_eq!(
            config.socket.unwrap(),
            PathBuf::from("/var/run/apf/apf-policy-service.sock")
        );
        assert_eq!(config.allowed_uid.unwrap(), 1000);
        assert_eq!(config.verifier.key_id.unwrap(), "apf-prod");
        assert_eq!(config.policy_source.backend.unwrap(), "http");
        assert_eq!(
            config.policy_source.bundle_source_poll_interval_secs.unwrap(),
            60
        );
        assert_eq!(config.resolver.backend.unwrap(), "claims");
        assert_eq!(config.provenance.signer.unwrap(), "apf-policy-adapter");
        assert_eq!(config.surfaces.unwrap().len(), 2);
    }

    #[test]
    fn parses_partial_config() {
        let toml = r#"
bundle_path = "/etc/apf/bundle.yaml"

[policy_source]
backend = "http"
"#;
        let config: ServiceConfig = toml::from_str(toml).expect("parse");
        assert_eq!(
            config.bundle_path.unwrap(),
            PathBuf::from("/etc/apf/bundle.yaml")
        );
        assert!(config.socket.is_none());
        assert!(config.verifier.key_id.is_none());
        assert_eq!(config.policy_source.backend.unwrap(), "http");
        assert!(config.policy_source.bundle_source_url.is_none());
        assert!(config.resolver.backend.is_none());
    }

    #[test]
    fn empty_config_parses() {
        let config: ServiceConfig = toml::from_str("").expect("parse");
        assert!(config.socket.is_none());
        assert!(config.bundle_path.is_none());
        assert!(config.policy_source.backend.is_none());
    }

    #[test]
    fn load_from_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(
            tmp.path(),
            r#"
bundle_path = "/etc/apf/bundle.yaml"
http_addr = "0.0.0.0:8080"
"#,
        )
        .expect("write");
        let config = load(tmp.path()).expect("load");
        assert_eq!(
            config.bundle_path.unwrap(),
            PathBuf::from("/etc/apf/bundle.yaml")
        );
        assert_eq!(
            config.http_addr.unwrap(),
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
        );
    }
}
