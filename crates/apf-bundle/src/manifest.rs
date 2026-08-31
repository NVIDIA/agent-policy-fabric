// SPDX-License-Identifier: Apache-2.0
//! Locate a bundle manifest among files extracted from an archive.

use std::path::{Path, PathBuf};

use apf_types::BundleVerifier;

use crate::bundle::Bundle;

#[derive(Debug, thiserror::Error)]
pub enum FindManifestError {
    #[error("read extracted archive directory: {0}")]
    Io(#[from] std::io::Error),
    #[error("no bundle manifest (.yaml) found in extracted archive at {0}")]
    NotFound(PathBuf),
}

/// Walk `extract_dir` looking for the bundle manifest — the first `.yaml`
/// file whose bytes verify against `verifier` and whose verified payload
/// deserialises as a [`Bundle`]. Candidates are matched on the verified
/// payload, never the raw file. This checks only the signature; callers
/// still run their own full verification (member hashes, expiry, counter)
/// once, after selection.
///
/// Candidates are sorted so `manifest.yaml` and files whose name contains
/// `bundle` are tried first.
pub fn find_bundle_manifest(
    extract_dir: &Path,
    verifier: &dyn BundleVerifier,
) -> Result<PathBuf, FindManifestError> {
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
            && let Ok(payload) = verifier.verify(&bytes)
            && Bundle::from_payload_bytes(&payload).is_ok()
        {
            return Ok(path.clone());
        }
    }
    Err(FindManifestError::NotFound(extract_dir.to_path_buf()))
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
    use crate::signing::YamlSigilVerifier;
    use crate::trust_store::TrustStore;
    use base64::Engine as _;

    fn yaml_sigil_sign(payload: &str, key: &ed25519_dalek::SigningKey, keyid: &str) -> Vec<u8> {
        yaml_sigil_signing::sign_yaml(&yaml_sigil_signing::SignYamlParams {
            payload: payload.as_bytes(),
            algorithm: yaml_sigil_traits::AlgorithmId::Ed25519,
            key: yaml_sigil_traits::signing::SigningKey::Ed25519(key),
            keyid: Some(keyid),
            append_missing_final_newline: true,
            yaml_backend: yaml_sigil_core::preferred_yaml_backend(),
        })
        .expect("sign bundle with yaml-sigil")
    }

    fn yaml_sigil_trust_store(key: &ed25519_dalek::SigningKey, keyid: &str) -> YamlSigilVerifier {
        let dir = tempfile::tempdir().expect("create trust dir");
        let pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        std::fs::write(
            dir.path().join(format!("{keyid}.pub")),
            format!("ed25519:{pub_b64}\n"),
        )
        .expect("write trust root");
        // TrustStore reads and copies keys at load time, so the tempdir can
        // be dropped once this returns.
        YamlSigilVerifier::new(TrustStore::load_from_dir(dir.path()).expect("load trust store"))
    }

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
    fn a_real_signed_artifact_does_not_parse_as_a_bare_bundle() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let artifact = yaml_sigil_sign(&good_bundle_yaml(1), &key, "test-key");
        assert!(Bundle::from_payload_bytes(&artifact).is_err());
    }

    #[test]
    fn finds_a_real_signed_manifest_among_candidates() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let artifact = yaml_sigil_sign(&good_bundle_yaml(1), &key, "test-key");

        let dir = tempfile::tempdir().expect("create extract dir");
        std::fs::write(dir.path().join("manifest.yaml"), &artifact).expect("write manifest");

        let verifier = yaml_sigil_trust_store(&key, "test-key");
        let found = find_bundle_manifest(dir.path(), &verifier).expect("manifest found");
        assert_eq!(found, dir.path().join("manifest.yaml"));
    }

    #[test]
    fn rejects_an_unsigned_candidate() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dir = tempfile::tempdir().expect("create extract dir");
        std::fs::write(dir.path().join("manifest.yaml"), good_bundle_yaml(1)).expect("write");

        let verifier = yaml_sigil_trust_store(&key, "test-key");
        assert!(find_bundle_manifest(dir.path(), &verifier).is_err());
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut artifact = yaml_sigil_sign(&good_bundle_yaml(1), &key, "test-key");
        let last = artifact.len() - 1;
        artifact[last] ^= 0xFF;

        let dir = tempfile::tempdir().expect("create extract dir");
        std::fs::write(dir.path().join("manifest.yaml"), &artifact).expect("write manifest");

        let verifier = yaml_sigil_trust_store(&key, "test-key");
        assert!(find_bundle_manifest(dir.path(), &verifier).is_err());
    }
}
