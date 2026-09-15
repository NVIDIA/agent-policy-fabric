// SPDX-License-Identifier: Apache-2.0
//! Bundle parser — `PolicyBundle` envelope per the canonical proto
//! (`nvidia/agent_policy_fabric/policy/v1alpha1/policy_bundle.proto`).
//!
//! The bundle is a signed artifact. Callers must call `BundleVerifier::verify`
//! on the raw artifact bytes first to obtain the payload, then pass the payload
//! to `Bundle::from_payload_bytes`. This crate does not couple to any specific
//! signing format.
//!
//! Manifest-of-files: the envelope is a pure manifest. Policy content lives in
//! external member files referenced by `path` + `sha256`. After the signature
//! and per-member hashes verify, [`Bundle::load_members`] reads each member and
//! routes it by its self-describing `kind`; for example, `SandboxPolicy`
//! documents are collected by `name`. See
//! `docs/bundle-manifest-of-files-and-generic-surfaces-plan.md`.
//!
//! Members may themselves be yaml-sigil signed artifacts. Each member is
//! decomposed transparently: a signed member contributes its payload stream, an
//! unsigned member its bytes verbatim. The manifest `sha256` is over the raw
//! on-disk bytes (carrier included), so the bundle signature already chains
//! member integrity; per-member cryptographic verification against a trust
//! store is a separate, optional layer.
//!
//! Canonical proto field names (`id`, `policy_revision`, `description`) are the
//! YAML keys; the Rust field names that several modules thread through keep
//! their existing spelling via `serde(rename)`. The verifying-key identifier is
//! not a payload field — it travels in the signature carrier's `keyid` (see
//! [`Bundle::carrier_keyid`]). `runtime_compatibility` is an optional APF
//! extension with no proto counterpart.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signing::yaml_sigil::decompose_member;

/// Top-level bundle as it appears in the yaml-sigil artifact payload.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Bundle {
    // Buf-style envelope — optional; matches prototype-policy-examples.
    #[serde(rename = "apiVersion", default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,

    // PolicyBundle envelope (canonical proto field names).
    #[serde(rename = "id")]
    pub bundle_id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "policy_revision")]
    pub monotonic_counter: u64,
    pub not_before: String, // RFC 3339; verifier parses with chrono
    pub expires_at: String, // RFC 3339; verifier parses with chrono

    #[serde(default)]
    pub manifest: Vec<ManifestEntry>,

    // `runtime_compatibility` is an optional version gate (no-op when absent).
    // The verifying-key identifier is not a bundle field — it travels in the
    // yaml-sigil signature carrier's `keyid` (see `carrier_keyid`).
    #[serde(default)]
    pub runtime_compatibility: BTreeMap<String, RuntimeCompatEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeCompatEntry {
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
}

/// Member content loaded after signature + hash verification.
#[derive(Debug, Default)]
pub struct BundleMembers {
    /// `kind: SandboxPolicy` documents keyed by `name`. Raw YAML; the caller
    /// lowers each to `SandboxPolicy` proto bytes for the `openshell.sandbox.v1`
    /// surface.
    pub sandbox_policies: BTreeMap<String, Vec<u8>>,
    /// `ProviderProfile` documents keyed by `id` (`OpenShell` native) or
    /// `metadata.name` (APF envelope). Stored as raw YAML bytes; the compiler
    /// passes them through to the `openshell.provider.v1` surface unchanged.
    pub provider_profiles: BTreeMap<String, Vec<u8>>,
    /// `kind: HostTool` documents keyed by `metadata.name`, stored as raw YAML.
    pub host_tools: BTreeMap<String, Vec<u8>>,
    /// `kind: Provider` documents keyed by `metadata.name`. Raw YAML; the
    /// compiler parses each into the canonical Provider IR and validates it.
    pub providers: BTreeMap<String, Vec<u8>>,
    /// `kind: PolicyRule` documents as `(metadata.name, raw YAML)` pairs in
    /// manifest order — rules are evaluated in bundle order, so ordering is
    /// part of the policy semantics.
    pub policy_rules: Vec<(String, Vec<u8>)>,
    /// `kind: PolicyAnnotator` documents as `(metadata.name, raw YAML)` pairs
    /// in manifest order. Annotators are independent of each other, but bundle
    /// order determines which annotator a duplicate-key error attributes.
    pub policy_annotators: Vec<(String, Vec<u8>)>,
    /// `kind: PolicyEffect` documents as `(metadata.name, raw YAML)` pairs in
    /// manifest order.
    pub policy_effects: Vec<(String, Vec<u8>)>,
    /// `kind: PolicyFinding` documents as `(metadata.name, raw YAML)` pairs
    /// in manifest order.
    pub policy_findings: Vec<(String, Vec<u8>)>,
}

impl Bundle {
    /// Parse a bundle from verified payload bytes.
    ///
    /// Callers must call `BundleVerifier::verify` on the raw artifact first
    /// to obtain the payload, then pass those bytes here. This function does
    /// no signature checking — that is the verifier's responsibility.
    pub fn from_payload_bytes(payload: &[u8]) -> Result<Self, BundleParseError> {
        serde_yaml::from_slice(payload).map_err(BundleParseError::Yaml)
    }

    /// Read and classify every manifest member, resolving paths relative to
    /// `bundle_dir`. Callers must already have verified `self`'s own
    /// signature (`Bundle::from_payload_bytes` only accepts a verified
    /// payload); each member's hash against `entry.sha256` is checked here.
    pub fn load_members(&self, bundle_dir: &Path) -> Result<BundleMembers, MemberLoadError> {
        let mut members = BundleMembers::default();
        for entry in &self.manifest {
            let abs = bundle_dir.join(&entry.path);
            let raw = std::fs::read(&abs).map_err(|source| MemberLoadError::Read {
                path: entry.path.clone(),
                source,
            })?;
            let computed = hex::encode(Sha256::digest(&raw));
            if !computed.eq_ignore_ascii_case(&entry.sha256) {
                return Err(MemberLoadError::HashMismatch {
                    path: entry.path.clone(),
                    declared: entry.sha256.clone(),
                    computed,
                });
            }
            // A member may itself be a yaml-sigil signed artifact; take its
            // payload when signed, the bytes verbatim when not.
            let content = member_content(&entry.path, &raw)?;
            // Classify by the member's self-describing `kind`.
            let doc: serde_yaml::Value =
                serde_yaml::from_slice(&content).map_err(|source| MemberLoadError::Parse {
                    path: entry.path.clone(),
                    source,
                })?;
            match doc.get("kind").and_then(serde_yaml::Value::as_str) {
                Some("SandboxPolicy") => {
                    let name = doc
                        .get("metadata")
                        .and_then(|m| m.get("name"))
                        .and_then(serde_yaml::Value::as_str)
                        .filter(|n| !n.is_empty())
                        .ok_or_else(|| MemberLoadError::MissingName {
                            path: entry.path.clone(),
                            doc_kind: "SandboxPolicy".into(),
                        })?;
                    if members
                        .sandbox_policies
                        .insert(name.to_string(), content)
                        .is_some()
                    {
                        return Err(MemberLoadError::DuplicateName {
                            kind: "SandboxPolicy".to_string(),
                            name: name.to_string(),
                        });
                    }
                }
                Some("HostTool") => {
                    let name = metadata_name(&doc, &entry.path, "HostTool")?;
                    insert_unique(&mut members.host_tools, "HostTool", name, content)?;
                }
                Some("Provider") => {
                    let name = metadata_name(&doc, &entry.path, "Provider")?;
                    insert_unique(&mut members.providers, "Provider", name, content)?;
                }
                Some("PolicyRule") => {
                    let name = metadata_name(&doc, &entry.path, "PolicyRule")?;
                    push_unique(&mut members.policy_rules, "PolicyRule", name, content)?;
                }
                Some("PolicyAnnotator") => {
                    let name = metadata_name(&doc, &entry.path, "PolicyAnnotator")?;
                    push_unique(
                        &mut members.policy_annotators,
                        "PolicyAnnotator",
                        name,
                        content,
                    )?;
                }
                Some("PolicyEffect") => {
                    let name = metadata_name(&doc, &entry.path, "PolicyEffect")?;
                    push_unique(&mut members.policy_effects, "PolicyEffect", name, content)?;
                }
                Some("PolicyFinding") => {
                    let name = metadata_name(&doc, &entry.path, "PolicyFinding")?;
                    push_unique(&mut members.policy_findings, "PolicyFinding", name, content)?;
                }
                Some("ProviderProfile") => {
                    let name = metadata_name(&doc, &entry.path, "ProviderProfile")?;
                    insert_unique(
                        &mut members.provider_profiles,
                        "ProviderProfile",
                        name,
                        content,
                    )?;
                }
                // OpenShell native ProviderProfile: no `kind`, keyed by top-level `id`.
                None if doc.get("id").and_then(serde_yaml::Value::as_str).is_some()
                    && doc.get("endpoints").is_some() =>
                {
                    let id = doc
                        .get("id")
                        .and_then(serde_yaml::Value::as_str)
                        .expect("guarded above");
                    insert_unique(
                        &mut members.provider_profiles,
                        "ProviderProfile",
                        id,
                        content,
                    )?;
                }
                _ => {}
            }
        }
        Ok(members)
    }
}

/// Append a named member to an order-preserving list, rejecting duplicate
/// names.
fn push_unique(
    list: &mut Vec<(String, Vec<u8>)>,
    kind: &str,
    name: &str,
    content: Vec<u8>,
) -> Result<(), MemberLoadError> {
    if list.iter().any(|(n, _)| n == name) {
        return Err(MemberLoadError::DuplicateName {
            kind: kind.to_string(),
            name: name.to_string(),
        });
    }
    list.push((name.to_string(), content));
    Ok(())
}

/// Insert a named member into `map`, rejecting duplicate names.
fn insert_unique(
    map: &mut BTreeMap<String, Vec<u8>>,
    kind: &str,
    name: &str,
    content: Vec<u8>,
) -> Result<(), MemberLoadError> {
    if map.insert(name.to_string(), content).is_some() {
        return Err(MemberLoadError::DuplicateName {
            kind: kind.to_string(),
            name: name.to_string(),
        });
    }
    Ok(())
}

/// Extract `metadata.name` from a member document, returning `MissingName` on
/// absence.
fn metadata_name<'a>(
    doc: &'a serde_yaml::Value,
    path: &str,
    doc_kind: &str,
) -> Result<&'a str, MemberLoadError> {
    doc.get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(serde_yaml::Value::as_str)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| MemberLoadError::MissingName {
            path: path.to_string(),
            doc_kind: doc_kind.to_string(),
        })
}

/// Resolve a manifest member's content, transparently handling members that
/// are themselves yaml-sigil signed artifacts: a signed member yields its
/// payload stream, an unsigned member its bytes verbatim. A member that carries
/// a malformed signing attempt is rejected.
fn member_content(path: &str, raw: &[u8]) -> Result<Vec<u8>, MemberLoadError> {
    decompose_member(raw).map_err(|_| MemberLoadError::Decompose {
        path: path.to_string(),
    })
}

/// Convenience: parse a bundle from verified payload bytes.
pub fn parse_bundle(payload: &[u8]) -> Result<Bundle, BundleParseError> {
    Bundle::from_payload_bytes(payload)
}

#[derive(Debug, thiserror::Error)]
pub enum BundleParseError {
    #[error("yaml parse failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("artifact decomposition failed: not a signed yaml-sigil artifact")]
    Decomposition,
}

#[derive(Debug, thiserror::Error)]
pub enum MemberLoadError {
    #[error("read manifest member {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("parse manifest member {path}: {source}")]
    Parse {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("manifest member {path} carries a malformed signing attempt")]
    Decompose { path: String },
    #[error("manifest member {path}: sha256 mismatch (declared {declared}, computed {computed})")]
    HashMismatch {
        path: String,
        declared: String,
        computed: String,
    },
    #[error("manifest member {path}: {doc_kind} document has no name")]
    MissingName { path: String, doc_kind: String },
    #[error("duplicate {kind} document named {name}")]
    DuplicateName { kind: String, name: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // `load_members` hashes each member's raw on-disk bytes against the
    // manifest's declared `sha256`, so manifests are built from the real
    // member content rather than a hardcoded digest.
    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn bundle_yaml(id: &str, manifest_entries: &[(&str, &[u8])]) -> String {
        let mut manifest = String::new();
        for (path, content) in manifest_entries {
            manifest.push_str(&format!(
                "  - path: {path}\n    sha256: {}\n",
                sha256_hex(content)
            ));
        }
        format!(
            "apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1\n\
             kind: PolicyBundle\n\
             id: {id}\n\
             policy_revision: 1\n\
             not_before: \"2026-01-01T00:00:00Z\"\n\
             expires_at: \"2099-01-01T00:00:00Z\"\n\
             manifest:\n{manifest}runtime_compatibility: {{}}\n"
        )
    }

    fn sign_yaml_sigil(payload: &str, key: &ed25519_dalek::SigningKey, keyid: &str) -> Vec<u8> {
        yaml_sigil_signing::sign_yaml(&yaml_sigil_signing::SignYamlParams {
            payload: payload.as_bytes(),
            algorithm: yaml_sigil_traits::AlgorithmId::Ed25519,
            key: yaml_sigil_traits::signing::SigningKey::Ed25519(key),
            keyid: Some(keyid),
            append_missing_final_newline: true,
        })
        .expect("sign member with yaml-sigil")
    }

    static SANDBOX_MEMBER: &str = "kind: SandboxPolicy\nmetadata:\n  name: default\nspec:\n  filesystem:\n    include_workdir: true\n";

    #[test]
    fn parses_canonical_field_names() {
        let mut artifact = bundle_yaml(
            "test-bundle",
            &[("sandbox/default-policy.yaml", SANDBOX_MEMBER.as_bytes())],
        );
        artifact.push_str("description: parser test bundle\n");
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        assert_eq!(parsed.bundle_id, "test-bundle");
        assert_eq!(parsed.monotonic_counter, 1);
        assert_eq!(parsed.description.as_deref(), Some("parser test bundle"));
        assert_eq!(parsed.manifest.len(), 1);
        assert_eq!(parsed.manifest[0].path, "sandbox/default-policy.yaml");
    }

    #[test]
    fn load_members_routes_sandbox_policy_by_kind() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("sandbox")).unwrap();
        std::fs::write(
            tmp.path().join("sandbox/default-policy.yaml"),
            SANDBOX_MEMBER,
        )
        .unwrap();

        let artifact = bundle_yaml(
            "test-bundle",
            &[("sandbox/default-policy.yaml", SANDBOX_MEMBER.as_bytes())],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let members = parsed.load_members(tmp.path()).expect("load members");

        // SandboxPolicy member → collected by name, verbatim.
        let body = members
            .sandbox_policies
            .get("default")
            .expect("sandbox policy present");
        assert_eq!(body, SANDBOX_MEMBER.as_bytes());
    }

    static POLICY_RULE_MEMBER: &str = r#"apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyRule
metadata:
  name: outlook-grants
spec:
  description: Outlook grant enforcement
  language: cedar
  definition: |
    permit(principal, action, resource);
  data: {}
"#;

    #[test]
    fn load_members_routes_policy_rule_kind() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("policy-rules")).unwrap();
        std::fs::write(
            tmp.path().join("policy-rules/outlook.yaml"),
            POLICY_RULE_MEMBER,
        )
        .unwrap();

        let artifact = bundle_yaml(
            "policy-rule-bundle",
            &[("policy-rules/outlook.yaml", POLICY_RULE_MEMBER.as_bytes())],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let members = parsed.load_members(tmp.path()).expect("load members");

        assert_eq!(members.policy_rules.len(), 1);
        let (name, body) = &members.policy_rules[0];
        assert_eq!(name, "outlook-grants");
        assert_eq!(body, POLICY_RULE_MEMBER.as_bytes());
    }

    static POLICY_ANNOTATOR_MEMBER: &str = r"apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyAnnotator
metadata:
  name: secret-detector
spec:
  description: Detects credentials
  annotations:
    - name: secret_detected
      output: bool
      rules:
        - field: body_text
          op: regex_match
          pattern: 'AKIA[0-9A-Z]{16}'
";

    #[test]
    fn load_members_routes_policy_annotator_kind() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("policy-annotators")).unwrap();
        std::fs::write(
            tmp.path().join("policy-annotators/secrets.yaml"),
            POLICY_ANNOTATOR_MEMBER,
        )
        .unwrap();

        let artifact = bundle_yaml(
            "policy-annotator-bundle",
            &[(
                "policy-annotators/secrets.yaml",
                POLICY_ANNOTATOR_MEMBER.as_bytes(),
            )],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let members = parsed.load_members(tmp.path()).expect("load members");

        assert_eq!(members.policy_annotators.len(), 1);
        let (name, body) = &members.policy_annotators[0];
        assert_eq!(name, "secret-detector");
        assert_eq!(body, POLICY_ANNOTATOR_MEMBER.as_bytes());
    }

    static POLICY_EFFECT_MEMBER: &str = r"apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyEffect
metadata:
  name: redact-body
spec:
  body:
    replace: '[REDACTED]'
";

    static POLICY_FINDING_MEMBER: &str = r"apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: PolicyFinding
metadata:
  name: secret-detected
spec:
  type: secret_detected
  severity: critical
";

    #[test]
    fn load_members_routes_policy_effect_and_finding_kinds() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("policy-effects")).unwrap();
        std::fs::create_dir_all(tmp.path().join("policy-findings")).unwrap();
        std::fs::write(
            tmp.path().join("policy-effects/redact.yaml"),
            POLICY_EFFECT_MEMBER,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("policy-findings/secret.yaml"),
            POLICY_FINDING_MEMBER,
        )
        .unwrap();

        let artifact = bundle_yaml(
            "policy-effect-bundle",
            &[
                (
                    "policy-effects/redact.yaml",
                    POLICY_EFFECT_MEMBER.as_bytes(),
                ),
                (
                    "policy-findings/secret.yaml",
                    POLICY_FINDING_MEMBER.as_bytes(),
                ),
            ],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let members = parsed.load_members(tmp.path()).expect("load members");

        assert_eq!(members.policy_effects.len(), 1);
        let (name, body) = &members.policy_effects[0];
        assert_eq!(name, "redact-body");
        assert_eq!(body, POLICY_EFFECT_MEMBER.as_bytes());

        assert_eq!(members.policy_findings.len(), 1);
        let (name, body) = &members.policy_findings[0];
        assert_eq!(name, "secret-detected");
        assert_eq!(body, POLICY_FINDING_MEMBER.as_bytes());
    }

    #[test]
    fn load_members_rejects_duplicate_policy_effect_name() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("policy-effects")).unwrap();
        std::fs::create_dir_all(tmp.path().join("policy-findings")).unwrap();
        // Both manifest members carry metadata.name: redact-body.
        std::fs::write(
            tmp.path().join("policy-effects/redact.yaml"),
            POLICY_EFFECT_MEMBER,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("policy-findings/secret.yaml"),
            POLICY_EFFECT_MEMBER,
        )
        .unwrap();

        let artifact = bundle_yaml(
            "policy-effect-bundle",
            &[
                (
                    "policy-effects/redact.yaml",
                    POLICY_EFFECT_MEMBER.as_bytes(),
                ),
                (
                    "policy-findings/secret.yaml",
                    POLICY_EFFECT_MEMBER.as_bytes(),
                ),
            ],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let result = parsed.load_members(tmp.path());
        assert!(matches!(
            result,
            Err(MemberLoadError::DuplicateName { kind, name })
                if kind == "PolicyEffect" && name == "redact-body"
        ));
    }

    static GITLAB_PROVIDER_MEMBER: &str = r#"apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: Provider
metadata: { name: gitlab }
spec:
  type: source-control
  endpoints: [{ host: gitlab.example, port: 443 }]
"#;

    static NVIDIA_PROVIDER_MEMBER: &str = r#"apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: Provider
metadata: { name: nvidia }
spec:
  type: inference
  endpoints: [{ host: integrate.api.nvidia.com, port: 443 }]
"#;

    #[test]
    fn load_members_routes_provider_kind() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("providers")).unwrap();
        std::fs::write(
            tmp.path().join("providers/gitlab.yaml"),
            GITLAB_PROVIDER_MEMBER,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("providers/nvidia.yaml"),
            NVIDIA_PROVIDER_MEMBER,
        )
        .unwrap();

        let artifact = bundle_yaml(
            "provider-bundle",
            &[
                ("providers/gitlab.yaml", GITLAB_PROVIDER_MEMBER.as_bytes()),
                ("providers/nvidia.yaml", NVIDIA_PROVIDER_MEMBER.as_bytes()),
            ],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let members = parsed.load_members(tmp.path()).expect("load members");

        assert_eq!(members.providers.len(), 2);
        assert_eq!(
            members.providers.get("gitlab").unwrap(),
            GITLAB_PROVIDER_MEMBER.as_bytes()
        );
        assert!(members.providers.contains_key("nvidia"));
    }

    #[test]
    fn load_members_rejects_duplicate_provider_name() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("providers")).unwrap();
        // Both members declare metadata.name: gitlab.
        std::fs::write(
            tmp.path().join("providers/gitlab.yaml"),
            GITLAB_PROVIDER_MEMBER,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("providers/nvidia.yaml"),
            GITLAB_PROVIDER_MEMBER,
        )
        .unwrap();

        let artifact = bundle_yaml(
            "provider-bundle",
            &[
                ("providers/gitlab.yaml", GITLAB_PROVIDER_MEMBER.as_bytes()),
                ("providers/nvidia.yaml", GITLAB_PROVIDER_MEMBER.as_bytes()),
            ],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let result = parsed.load_members(tmp.path());
        assert!(matches!(
            result,
            Err(MemberLoadError::DuplicateName { kind, name }) if kind == "Provider" && name == "gitlab"
        ));
    }

    #[test]
    fn load_members_handles_signed_member() {
        // A member that is itself a real yaml-sigil signed artifact
        // contributes its payload, not the signature carrier.
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("sandbox")).unwrap();

        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let signed_member = sign_yaml_sigil(SANDBOX_MEMBER, &key, "test-key");
        assert_ne!(
            signed_member,
            SANDBOX_MEMBER.as_bytes(),
            "a signed member's on-disk bytes must differ from its payload"
        );
        std::fs::write(
            tmp.path().join("sandbox/default-policy.yaml"),
            &signed_member,
        )
        .unwrap();

        // The manifest's declared sha256 is over the on-disk bytes,
        // signature carrier included.
        let artifact = bundle_yaml(
            "test-bundle",
            &[("sandbox/default-policy.yaml", &signed_member)],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let members = parsed.load_members(tmp.path()).expect("load members");

        // The signed member's payload — not the carrier — is what gets vended.
        let body = members
            .sandbox_policies
            .get("default")
            .expect("sandbox policy present");
        assert_eq!(body, SANDBOX_MEMBER.as_bytes());
    }

    #[test]
    fn load_members_rejects_a_member_hash_mismatch() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("sandbox")).unwrap();
        // The on-disk bytes don't match SANDBOX_MEMBER, so the manifest's
        // declared hash (computed from SANDBOX_MEMBER) won't match either.
        std::fs::write(
            tmp.path().join("sandbox/default-policy.yaml"),
            "kind: SandboxPolicy\nmetadata:\n  name: tampered\n",
        )
        .unwrap();

        let artifact = bundle_yaml(
            "test-bundle",
            &[("sandbox/default-policy.yaml", SANDBOX_MEMBER.as_bytes())],
        );
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let result = parsed.load_members(tmp.path());
        assert!(matches!(
            result,
            Err(MemberLoadError::HashMismatch { path, .. }) if path == "sandbox/default-policy.yaml"
        ));
    }

    #[test]
    fn load_members_rejects_a_malformed_signing_attempt() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("sandbox")).unwrap();
        // A signature marker (`---\n`) with no signature document after it.
        let malformed: &[u8] = b"kind: SandboxPolicy\n---\n";
        std::fs::write(tmp.path().join("sandbox/default-policy.yaml"), malformed).unwrap();

        let artifact = bundle_yaml("test-bundle", &[("sandbox/default-policy.yaml", malformed)]);
        let parsed = parse_bundle(artifact.as_bytes()).expect("parse");
        let result = parsed.load_members(tmp.path());
        assert!(matches!(
            result,
            Err(MemberLoadError::Decompose { path }) if path == "sandbox/default-policy.yaml"
        ));
    }
}
