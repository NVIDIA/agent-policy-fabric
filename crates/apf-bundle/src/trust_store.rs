// SPDX-License-Identifier: Apache-2.0
//! Trust-root store — verifying keys indexed by key id (the signature
//! carrier's `keyid`).
//!
//! Supports two key formats:
//!   - Ed25519: `*.pub` files containing `ed25519:<base64-of-32-byte-key>`
//!   - ECDSA P-256: `*.pem` or `*.p256` files containing a SPKI PEM public key
//!
//! Filename stem (minus extension) is the key id. When both an Ed25519 and a
//! P-256 key share the same id, both are stored and offered to the verifier;
//! the signature's algorithm field selects which one is used.
//!
//! A deployment can replace this with a centrally delivered trust
//! root bundle that is itself signed and rotated.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::VerifyingKey;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p256::pkcs8::DecodePublicKey;

const KEY_PREFIX: &str = "ed25519:";

#[derive(Clone)]
pub struct TrustEntry {
    pub ed25519: Option<VerifyingKey>,
    pub p256: Option<P256VerifyingKey>,
}

/// Production extension points:
/// - JWKS URI: fetch signing public keys from a JSON Web Key Set endpoint
///   (e.g. a signing service's `.well-known/jwks.json`). Enables key rotation
///   without redeploying the verifying component. When implemented, add `--trust-root-jwks-uri`
///   and resolve keys by `kid` (key ID) matching the signature carrier's `keyid`.
/// - Centrally delivered trust root bundle, signed and rotated.
#[derive(Clone)]
pub struct TrustStore {
    keys: HashMap<String, TrustEntry>,
}

impl TrustStore {
    /// Load `*.pub` (Ed25519) and `*.pem`/`*.p256` (ECDSA P-256) files under `dir`.
    /// Keys with the same stem share a `TrustEntry`.
    pub fn load_from_dir(dir: &Path) -> Result<Self, TrustStoreError> {
        let mut keys: HashMap<String, TrustEntry> = HashMap::new();
        let entries = fs::read_dir(dir).map_err(|e| TrustStoreError::ReadDir {
            dir: dir.to_path_buf(),
            source: e,
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| TrustStoreError::ReadDir {
                dir: dir.to_path_buf(),
                source: e,
            })?;
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str());
            if ext != Some("pub") && ext != Some("pem") && ext != Some("p256") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| TrustStoreError::InvalidFilename { path: path.clone() })?
                .to_string();
            let raw = fs::read_to_string(&path).map_err(|e| TrustStoreError::ReadKey {
                path: path.clone(),
                source: e,
            })?;

            let entry = keys.entry(id).or_insert_with(|| TrustEntry {
                ed25519: None,
                p256: None,
            });

            if ext == Some("pub") {
                let key = parse_ed25519_key(&raw).map_err(|e| TrustStoreError::ParseKey {
                    path: path.clone(),
                    reason: e,
                })?;
                entry.ed25519 = Some(key);
            } else if ext == Some("pem") || ext == Some("p256") {
                let key = parse_p256_pem(&raw).map_err(|e| TrustStoreError::ParseKey {
                    path: path.clone(),
                    reason: e,
                })?;
                entry.p256 = Some(key);
            }
        }
        Ok(Self { keys })
    }

    /// Look up the Ed25519 key for a trust root id.
    #[must_use]
    pub fn get(&self, trust_root_id: &str) -> Option<&VerifyingKey> {
        self.keys
            .get(trust_root_id)
            .and_then(|e| e.ed25519.as_ref())
    }

    /// Look up the P-256 key for a trust root id.
    #[must_use]
    pub fn get_p256(&self, trust_root_id: &str) -> Option<&P256VerifyingKey> {
        self.keys.get(trust_root_id).and_then(|e| e.p256.as_ref())
    }

    /// Resolve both Ed25519 and P-256 keys for a given trust root ID.
    /// Today this reads from the file-loaded store. The JWKS extension
    /// would add a network lookup fallback when the file store misses.
    #[must_use]
    pub fn resolve_keys(
        &self,
        trust_root_id: &str,
    ) -> (Option<&VerifyingKey>, Option<&P256VerifyingKey>) {
        (self.get(trust_root_id), self.get_p256(trust_root_id))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn known_ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }
}

/// Parse a PEM-encoded ECDSA P-256 (NIST P-256 / secp256r1) SPKI public key.
fn parse_p256_pem(contents: &str) -> Result<P256VerifyingKey, String> {
    P256VerifyingKey::from_public_key_pem(contents.trim())
        .map_err(|e| format!("invalid P-256 PEM public key: {e}"))
}

fn parse_ed25519_key(contents: &str) -> Result<VerifyingKey, String> {
    let line = contents
        .lines()
        .find(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .ok_or_else(|| "empty trust-root file".to_string())?
        .trim();
    let b64 = line
        .strip_prefix(KEY_PREFIX)
        .ok_or_else(|| format!("expected key to start with `{KEY_PREFIX}`; got `{line}`"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("expected 32-byte key, got {} bytes", raw.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid Ed25519 public key: {e}"))
}

#[derive(Debug, thiserror::Error)]
pub enum TrustStoreError {
    #[error("could not read trust-root dir {dir}: {source}")]
    ReadDir {
        dir: PathBuf,
        source: std::io::Error,
    },
    #[error("trust-root file {path} has an invalid name")]
    InvalidFilename { path: PathBuf },
    #[error("could not read trust-root file {path}: {source}")]
    ReadKey {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not parse trust-root {path}: {reason}")]
    ParseKey { path: PathBuf, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn loads_valid_ed25519_keys() {
        let tmp = TempDir::new().unwrap();
        let key_bytes = [7u8; 32];
        let key_pub = VerifyingKey::from_bytes(&{
            use ed25519_dalek::SigningKey;
            let sk = SigningKey::from_bytes(&key_bytes);
            sk.verifying_key().to_bytes()
        })
        .unwrap();
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_pub.to_bytes());
        let path = tmp.path().join("dev-root.pub");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(format!("ed25519:{key_b64}\n").as_bytes())
            .unwrap();
        let store = TrustStore::load_from_dir(tmp.path()).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get("dev-root").is_some());
        assert!(store.get_p256("dev-root").is_none());
    }

    #[test]
    fn loads_valid_p256_pem_keys() {
        let tmp = TempDir::new().unwrap();
        let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3ZbGAZ9yE8OuYpOgTyWEViH1qdGU\nY0Gx15WwqJ/7DT8MJHS72qFF5Ti/c1orUnxmxO6Cpg55Go0r7WnOS2CwiA==\n-----END PUBLIC KEY-----\n";
        std::fs::write(tmp.path().join("dev.pem"), pem).unwrap();
        let store = TrustStore::load_from_dir(tmp.path()).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get_p256("dev").is_some());
        assert!(store.get("dev").is_none());
    }

    #[test]
    fn rejects_wrong_prefix() {
        let err = parse_ed25519_key("rsa:abc\n").unwrap_err();
        assert!(err.contains("expected key to start with"));
    }

    #[test]
    fn rejects_wrong_length() {
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let err = parse_ed25519_key(&format!("ed25519:{short}")).unwrap_err();
        assert!(err.contains("32-byte key"));
    }
}
