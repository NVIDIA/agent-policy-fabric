// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("{0}")]
    Sign(String),
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("{0}")]
    Verify(String),
}

/// Sign arbitrary bytes; return the signed artifact bytes.
pub trait BundleSigner: Send + Sync {
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// Verify a signed artifact; return the payload bytes on success.
/// The implementation is responsible for decomposing the artifact format.
pub trait BundleVerifier: Send + Sync {
    fn verify(&self, artifact: &[u8]) -> Result<Vec<u8>, VerifyError>;
}
