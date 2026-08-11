// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use super::audit::{BundleAuditMetadata, PolicyServiceAudit};

/// Summary of the bundle verified at startup.
pub struct LoadedBundle {
    pub digest_hex: String,
    pub monotonic_counter: u64,
    pub audit_metadata: BundleAuditMetadata,
}

/// Identity material used to sign vended documents (e.g. `GetDocument` responses).
/// The public key is published via the JWKS endpoint so callers can verify signatures.
pub struct DocumentSigner {
    pub key_id: String,
    pub signing_key: SigningKey,
}

/// Shared state both gRPC surfaces read from.
pub struct PolicyServiceCore {
    pub bundle: LoadedBundle,
    /// Vended projection bytes keyed by `(kind, name)`.
    pub projections: BTreeMap<(String, String), Vec<u8>>,
    /// Present when the daemon signs vended documents.
    pub verifier_identity: Option<Arc<DocumentSigner>>,
    pub audit: PolicyServiceAudit,
}
