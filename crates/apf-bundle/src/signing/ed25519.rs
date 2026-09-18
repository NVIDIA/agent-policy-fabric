// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Default Ed25519 `BundleSigner` / `BundleVerifier` implementation.
//!
//! Artifact format: `<32-byte Ed25519 signature> || <payload bytes>`.
//! The signature covers the payload bytes. Verification returns the
//! payload on success.

use apf_types::{BundleSigner, BundleVerifier, SignError, VerifyError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// Generate a random keypair for tests and dev fixtures.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            key: self.key.verifying_key(),
        }
    }
}

impl BundleSigner for Ed25519Signer {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignError> {
        let sig: Signature = self.key.sign(payload);
        let mut artifact = Vec::with_capacity(64 + payload.len());
        artifact.extend_from_slice(&sig.to_bytes());
        artifact.extend_from_slice(payload);
        Ok(artifact)
    }
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }
}

impl BundleVerifier for Ed25519Verifier {
    fn verify(&self, artifact: &[u8]) -> Result<Vec<u8>, VerifyError> {
        if artifact.len() < 64 {
            return Err(VerifyError::Verify("artifact too short".into()));
        }
        let (sig_bytes, payload) = artifact.split_at(64);
        let sig = Signature::from_bytes(sig_bytes.try_into().expect("64 bytes"));
        self.key
            .verify(payload, &sig)
            .map_err(|e| VerifyError::Verify(e.to_string()))?;
        Ok(payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apf_types::{BundleSigner, BundleVerifier};

    #[test]
    fn round_trip() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let payload = b"hello apf-bundle";
        let artifact = signer.sign(payload).unwrap();
        let recovered = verifier.verify(&artifact).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn rejects_tampered_payload() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        let mut artifact = signer.sign(b"original").unwrap();
        *artifact.last_mut().unwrap() ^= 0xff;
        assert!(verifier.verify(&artifact).is_err());
    }

    #[test]
    fn rejects_too_short() {
        let signer = Ed25519Signer::generate();
        let verifier = signer.verifier();
        assert!(verifier.verify(&[0u8; 10]).is_err());
    }
}
