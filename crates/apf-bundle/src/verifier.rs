// SPDX-License-Identifier: Apache-2.0
//! Bundle verifier — composes the bundle checks.
//!
//! Each check appends to `rejection_reasons` rather than short-circuiting,
//! so the response can report multiple problems at once.
//!
//! Signature verification is delegated to a `BundleVerifier` impl supplied
//! by the caller — this crate does not couple to any signing format.

use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use semver::Version;
use sha2::{Digest, Sha256};

use apf_types::BundleVerifier;

use crate::bundle::{Bundle, ManifestEntry};
use crate::counter_store::{CounterCheckError, CounterStore};

#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub ok: bool,
    /// SHA-256 of the artifact as presented: payload plus signature envelope.
    /// Changes whenever the artifact is re-signed, even over identical
    /// content, because ECDSA signatures are randomized.
    pub digest_hex: String,
    /// SHA-256 of the verified payload document alone — the content at this
    /// revision, including the manifest and its member hashes. Stable across
    /// re-signing; empty when signature verification failed. This is what
    /// the counter store binds an accepted counter to.
    pub payload_digest_hex: String,
    /// Whether the bundle parsed far enough to read its fields.
    pub parsed: bool,
    pub monotonic_counter: u64,
    pub rejection_reasons: Vec<String>,
    /// Parsed bundle, present whenever signature verification and YAML parsing
    /// both succeeded (even if a later policy check — expiry, counter — failed).
    /// `None` only when the artifact could not be verified or parsed at all.
    pub bundle: Option<Bundle>,
}

/// Verify a bundle artifact end-to-end.
///
/// `runtime_versions` maps runtime adapter name to the version the caller
/// presents (e.g. `{"openshell" => "0.2.0"}`). The bundle's
/// `runtime_compatibility` map is checked against these versions.
/// The constant `OPENSHELL_RUNTIME_VERSION` is defined in `runtimes/openshell`
/// and passed in by the gateway — not hardcoded here.
#[must_use]
pub fn verify_bundle(
    bundle_bytes: &[u8],
    bundle_path: &Path,
    verifier: &dyn BundleVerifier,
    counter_store: &CounterStore,
    now: SystemTime,
    runtime_versions: &HashMap<&str, &str>,
) -> VerifyOutcome {
    let digest_hex = sha256_hex(bundle_bytes);

    // Step 1: signature verification — returns payload on success.
    let payload = match verifier.verify(bundle_bytes) {
        Ok(p) => p,
        Err(e) => {
            return VerifyOutcome {
                ok: false,
                digest_hex,
                payload_digest_hex: String::new(),
                parsed: false,
                monotonic_counter: 0,
                rejection_reasons: vec![format!("signature_invalid: {e}")],
                bundle: None,
            };
        }
    };
    let payload_digest_hex = sha256_hex(&payload);

    // Step 2: parse the verified payload.
    let bundle = match Bundle::from_payload_bytes(&payload) {
        Ok(b) => b,
        Err(e) => {
            return VerifyOutcome {
                ok: false,
                digest_hex,
                payload_digest_hex,
                parsed: false,
                monotonic_counter: 0,
                rejection_reasons: vec![format!("bundle_parse_failed: {e}")],
                bundle: None,
            };
        }
    };

    let mut reasons: Vec<String> = Vec::new();

    check_manifest_hashes(&bundle, bundle_path, &mut reasons);
    check_expiry(&bundle, now, &mut reasons);
    check_runtime_compat(&bundle, runtime_versions, &mut reasons);

    match counter_store.check(bundle.monotonic_counter, &payload_digest_hex) {
        Ok(()) => {}
        Err(CounterCheckError::Regression {
            candidate,
            high_water_mark,
        }) => reasons.push(format!(
            "counter_regression: bundle counter {candidate} <= high-water-mark {high_water_mark}"
        )),
        Err(CounterCheckError::ContentMismatch { counter, .. }) => reasons.push(format!(
            "counter_content_mismatch: bundle counter {counter} already accepted with a different artifact"
        )),
        Err(e @ CounterCheckError::Persist { .. }) => {
            reasons.push(format!("counter_check_failed: {e}"));
        }
    }

    VerifyOutcome {
        ok: reasons.is_empty(),
        digest_hex,
        payload_digest_hex,
        parsed: true,
        monotonic_counter: bundle.monotonic_counter,
        rejection_reasons: reasons,
        bundle: Some(bundle),
    }
}

fn check_manifest_hashes(bundle: &Bundle, bundle_path: &Path, reasons: &mut Vec<String>) {
    let base = bundle_path.parent().unwrap_or_else(|| Path::new("."));
    for ManifestEntry { path, sha256, .. } in &bundle.manifest {
        let abs = base.join(path);
        let actual = match std::fs::read(&abs) {
            Ok(b) => sha256_hex(&b),
            Err(e) => {
                reasons.push(format!(
                    "manifest_member_unreadable: {} ({e})",
                    abs.display()
                ));
                continue;
            }
        };
        let want = sha256.trim().to_ascii_lowercase();
        if want.is_empty() || want == "replace_with_digest" {
            reasons.push(format!("manifest_hash_unset: {path} (declared `{sha256}`)"));
            continue;
        }
        if actual != want {
            reasons.push(format!(
                "manifest_hash_mismatch: {path}: declared {want}, actual {actual}"
            ));
        }
    }
}

fn check_expiry(bundle: &Bundle, now: SystemTime, reasons: &mut Vec<String>) {
    let now_chrono: DateTime<Utc> = now.into();
    let not_before = match DateTime::parse_from_rfc3339(&bundle.not_before) {
        Ok(t) => t.with_timezone(&Utc),
        Err(e) => {
            reasons.push(format!("not_before_invalid: {e}"));
            return;
        }
    };
    let expires_at = match DateTime::parse_from_rfc3339(&bundle.expires_at) {
        Ok(t) => t.with_timezone(&Utc),
        Err(e) => {
            reasons.push(format!("expires_at_invalid: {e}"));
            return;
        }
    };
    if now_chrono < not_before {
        reasons.push(format!(
            "bundle_not_yet_valid: now {now_chrono} < not_before {not_before}"
        ));
    }
    if now_chrono > expires_at {
        reasons.push(format!(
            "bundle_expired: now {now_chrono} > expires_at {expires_at}"
        ));
    }
}

/// Check runtime_compatibility entries against the caller-supplied runtime versions.
/// Unknown adapter keys in the bundle are accepted as informational.
fn check_runtime_compat(
    bundle: &Bundle,
    runtime_versions: &HashMap<&str, &str>,
    reasons: &mut Vec<String>,
) {
    for (adapter, entry) in &bundle.runtime_compatibility {
        let Some(min_str) = entry.min_version.as_deref() else {
            continue;
        };
        let want = match Version::parse(min_str.trim_start_matches('v')) {
            Ok(v) => v,
            Err(e) => {
                reasons.push(format!(
                    "runtime_compat_invalid: {adapter}.min_version `{min_str}` is not semver ({e})"
                ));
                continue;
            }
        };
        let Some(&have_str) = runtime_versions.get(adapter.as_str()) else {
            // Caller didn't present a version for this adapter — skip.
            continue;
        };
        let have = match Version::parse(have_str.trim_start_matches('v')) {
            Ok(v) => v,
            Err(e) => {
                reasons.push(format!(
                    "runtime_compat_invalid: caller version for `{adapter}` `{have_str}` is not semver ({e})"
                ));
                continue;
            }
        };
        if have < want {
            reasons.push(format!(
                "runtime_compat_mismatch: bundle requires {adapter} >= {want}, caller is {have}"
            ));
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::ed25519::Ed25519Signer;
    use apf_types::BundleSigner;
    use tempfile::TempDir;

    fn signer() -> Ed25519Signer {
        Ed25519Signer::generate()
    }

    fn empty_counter(dir: &Path) -> CounterStore {
        CounterStore::load_or_init(&dir.join("counter")).unwrap()
    }

    fn no_versions() -> HashMap<&'static str, &'static str> {
        HashMap::new()
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
    fn happy_path_passes_all_checks() {
        let s = signer();
        let v = s.verifier();
        let tmp = TempDir::new().unwrap();
        let counter = empty_counter(tmp.path());
        let artifact = s.sign(good_bundle_yaml(1).as_bytes()).unwrap();
        let bundle_path = tmp.path().join("bundle.yaml");
        std::fs::write(&bundle_path, &artifact).unwrap();
        let out = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &no_versions(),
        );
        assert!(out.ok, "rejected: {:?}", out.rejection_reasons);
        assert_eq!(out.monotonic_counter, 1);
    }

    #[test]
    fn rejects_tampered_artifact() {
        let s = signer();
        let v = s.verifier();
        let tmp = TempDir::new().unwrap();
        let counter = empty_counter(tmp.path());
        let mut artifact = s.sign(good_bundle_yaml(1).as_bytes()).unwrap();
        *artifact.last_mut().unwrap() ^= 0xff;
        let bundle_path = tmp.path().join("bundle.yaml");
        std::fs::write(&bundle_path, &artifact).unwrap();
        let out = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &no_versions(),
        );
        assert!(!out.ok);
        assert!(
            out.rejection_reasons
                .iter()
                .any(|r| r.starts_with("signature_invalid"))
        );
    }

    #[test]
    fn rejects_expired_bundle() {
        let s = signer();
        let v = s.verifier();
        let tmp = TempDir::new().unwrap();
        let counter = empty_counter(tmp.path());
        let yaml = good_bundle_yaml(1).replace("2099-01-01", "2020-01-01");
        let artifact = s.sign(yaml.as_bytes()).unwrap();
        let bundle_path = tmp.path().join("bundle.yaml");
        std::fs::write(&bundle_path, &artifact).unwrap();
        let out = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &no_versions(),
        );
        assert!(!out.ok);
        assert!(
            out.rejection_reasons
                .iter()
                .any(|r| r.starts_with("bundle_expired"))
        );
    }

    #[test]
    fn accepts_same_counter_when_artifact_is_identical() {
        let s = signer();
        let v = s.verifier();
        let tmp = TempDir::new().unwrap();
        let mut counter = empty_counter(tmp.path());
        let artifact = s.sign(good_bundle_yaml(2).as_bytes()).unwrap();
        let bundle_path = tmp.path().join("bundle.yaml");
        std::fs::write(&bundle_path, &artifact).unwrap();
        let first = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &no_versions(),
        );
        assert!(first.ok, "rejected: {:?}", first.rejection_reasons);
        assert_eq!(
            first.payload_digest_hex,
            sha256_hex(good_bundle_yaml(2).as_bytes()),
            "payload digest covers the signed document alone"
        );
        assert_ne!(
            first.payload_digest_hex, first.digest_hex,
            "payload digest must not include the signature envelope"
        );
        counter
            .check_and_advance(2, &first.payload_digest_hex)
            .unwrap();

        let again = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &no_versions(),
        );
        assert!(again.ok, "rejected: {:?}", again.rejection_reasons);
    }

    #[test]
    fn rejects_same_counter_with_different_artifact() {
        let s = signer();
        let v = s.verifier();
        let tmp = TempDir::new().unwrap();
        let mut counter = empty_counter(tmp.path());
        counter
            .check_and_advance(2, &sha256_hex(good_bundle_yaml(2).as_bytes()))
            .unwrap();

        let yaml = good_bundle_yaml(2).replace("id: test-bundle", "id: other-bundle");
        let artifact = s.sign(yaml.as_bytes()).unwrap();
        let bundle_path = tmp.path().join("bundle.yaml");
        std::fs::write(&bundle_path, &artifact).unwrap();
        let out = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &no_versions(),
        );
        assert!(!out.ok);
        assert!(
            out.rejection_reasons
                .iter()
                .any(|r| r.starts_with("counter_content_mismatch"))
        );
    }

    #[test]
    fn rejects_counter_regression() {
        let s = signer();
        let v = s.verifier();
        let tmp = TempDir::new().unwrap();
        let mut counter = empty_counter(tmp.path());
        counter
            .check_and_advance(10, &sha256_hex(b"newer"))
            .unwrap();
        let artifact = s.sign(good_bundle_yaml(5).as_bytes()).unwrap();
        let bundle_path = tmp.path().join("bundle.yaml");
        std::fs::write(&bundle_path, &artifact).unwrap();
        let out = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &no_versions(),
        );
        assert!(!out.ok);
        assert!(
            out.rejection_reasons
                .iter()
                .any(|r| r.starts_with("counter_regression"))
        );
    }

    #[test]
    fn rejects_runtime_compat_mismatch() {
        let s = signer();
        let v = s.verifier();
        let tmp = TempDir::new().unwrap();
        let counter = empty_counter(tmp.path());
        let yaml = good_bundle_yaml(1).replace(
            "runtime_compatibility: {}",
            "runtime_compatibility:\n  openshell:\n    min_version: \"99.0.0\"\n",
        );
        let artifact = s.sign(yaml.as_bytes()).unwrap();
        let bundle_path = tmp.path().join("bundle.yaml");
        std::fs::write(&bundle_path, &artifact).unwrap();
        let mut versions = HashMap::new();
        versions.insert("openshell", "0.1.0");
        let out = verify_bundle(
            &artifact,
            &bundle_path,
            &v,
            &counter,
            SystemTime::now(),
            &versions,
        );
        assert!(!out.ok);
        assert!(
            out.rejection_reasons
                .iter()
                .any(|r| r.starts_with("runtime_compat_mismatch"))
        );
    }
}
