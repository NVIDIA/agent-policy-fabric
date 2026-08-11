// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! `nvidia.agent_policy_fabric.policy.v1alpha1.PolicyService` gRPC surface.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use apf_proto::policy_service_v1alpha1 as wire;
use apf_proto::runtime_v1alpha1::runtime_context;
use apf_proto::openshell_sandbox::SandboxPolicy;
use apf_proto::spec_digest::sandbox_policy_spec_digest;
use prost::Message;
use serde::Serialize;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use wire::policy_service_server::PolicyService;

use crate::runtime::core::DocumentSigner;
use crate::source::PolicySource;
use crate::source::resolver::PolicyResolver;

/// Claims payload for the provenance JWT minted per `GetDocument` response.
#[derive(Debug, Serialize)]
struct ProvenanceClaims {
    /// Unique token ID — becomes the interceptor's `correlation-id` annotation.
    jti: String,
    /// Verifier key id — same as the JWT header `kid`.
    sub: String,
    /// Issued-at Unix seconds.
    iat: u64,
    /// Expiry Unix seconds. Omitted when no TTL is declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    /// Hex-encoded SHA-256 of the projection body.
    #[serde(rename = "apf/document-digest")]
    apf_document_digest: String,
    /// Monotonic bundle version counter.
    #[serde(rename = "apf/version")]
    apf_version: u64,
    /// Hex-encoded SHA-256 of the canonical JSON representation of `{ "policy": <SandboxPolicy> }`.
    /// Empty string for non-sandbox document kinds (e.g. provider profiles).
    #[serde(rename = "apf/spec-digest")]
    apf_spec_digest: String,
    /// Bundle manifest `id` field — stable name of the signed bundle that produced this document.
    #[serde(rename = "apf/bundle-id")]
    apf_bundle_id: String,
}

/// Encode a 32-byte Ed25519 seed as a PKCS#8 v1 DER blob (RFC 8410).
///
/// The structure is fixed for Ed25519:
/// SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { seed } } }
/// Total: 48 bytes. `ring` (used internally by `jsonwebtoken`) requires this form.
fn ed25519_seed_to_pkcs8_der(seed: &[u8; 32]) -> [u8; 48] {
    let mut der = [0u8; 48];
    der[..16].copy_from_slice(&[
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // SEQUENCE { OID 1.3.101.112 }
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes
    ]);
    der[16..].copy_from_slice(seed);
    der
}

/// Mint a compact JWT provenance token for the given projection.
///
/// Returns `None` and logs a warning if encoding fails — callers fall back to
/// an empty `provenance_token` (same behaviour as no signer configured).
fn mint_provenance_jwt(
    vi: &DocumentSigner,
    digest: &str,
    version: u64,
    valid_until_ms: u64,
    spec_digest: &str,
    bundle_id: &str,
) -> Option<String> {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let exp = if valid_until_ms > 0 {
        Some(valid_until_ms / 1000)
    } else {
        None
    };

    let claims = ProvenanceClaims {
        jti: Uuid::new_v4().to_string(),
        sub: vi.key_id.clone(),
        iat,
        exp,
        apf_document_digest: digest.to_string(),
        apf_version: version,
        apf_spec_digest: spec_digest.to_string(),
        apf_bundle_id: bundle_id.to_string(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(vi.key_id.clone());

    let seed = vi.signing_key.to_bytes();
    let der = ed25519_seed_to_pkcs8_der(&seed);
    let encoding_key = EncodingKey::from_ed_der(&der);

    match jsonwebtoken::encode(&header, &claims, &encoding_key) {
        Ok(token) => Some(token),
        Err(e) => {
            warn!(key_id = %vi.key_id, error = %e, "provenance JWT encoding failed");
            None
        }
    }
}

/// gRPC handler for the `nvidia.agent_policy_fabric.policy.v1alpha1.PolicyService` service.
pub struct PolicyServiceImpl {
    resolver: Arc<dyn PolicyResolver>,
    source: Arc<dyn PolicySource>,
    /// Empty = no restriction; non-empty = only these kinds are served.
    allowed_kinds: Arc<HashSet<String>>,
    /// Present when the daemon has a signing key; signs every `GetDocument` response body.
    signer: Option<Arc<DocumentSigner>>,
    /// How long (seconds) a substrate may cache a `GetDocument` response. Zero = no expiry.
    document_ttl_secs: u64,
    /// Bundle manifest `id` — included as `apf/bundle-id` in every provenance JWT.
    bundle_id: String,
}

impl PolicyServiceImpl {
    pub fn new(
        resolver: Arc<dyn PolicyResolver>,
        source: Arc<dyn PolicySource>,
        allowed_kinds: Arc<HashSet<String>>,
        signer: Option<Arc<DocumentSigner>>,
        document_ttl_secs: u64,
        bundle_id: String,
    ) -> Self {
        Self {
            resolver,
            source,
            allowed_kinds,
            signer,
            document_ttl_secs,
            bundle_id,
        }
    }

    fn check_kind(&self, kind: &str) -> Result<(), Status> {
        if kind.is_empty() {
            return Err(Status::invalid_argument("kind must be non-empty"));
        }
        if !self.allowed_kinds.is_empty() && !self.allowed_kinds.contains(kind) {
            return Err(Status::invalid_argument(format!(
                "kind '{kind}' is not served by this instance"
            )));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    async fn health(
        &self,
        _request: Request<wire::HealthRequest>,
    ) -> Result<Response<wire::HealthResponse>, Status> {
        Ok(Response::new(wire::HealthResponse {
            state: wire::HealthState::Ok as i32,
            detail: String::new(),
        }))
    }

    async fn get_document(
        &self,
        req: Request<wire::GetDocumentRequest>,
    ) -> Result<Response<wire::GetDocumentResponse>, Status> {
        let inner = req.into_inner();
        self.check_kind(&inner.kind)?;

        let ctx = inner.runtime_context.unwrap_or_default();
        let resolved = self.resolver.resolve(&inner.name, &ctx);

        let sandbox_id = ctx
            .platform
            .as_ref()
            .map(|p| match p {
                runtime_context::Platform::Openshell(o) => o.sandbox_id.as_str(),
            })
            .unwrap_or("-");

        match self
            .source
            .get(&inner.kind, &resolved.name, &resolved.variant)
        {
            Some(proj) => {
                let valid_until_ms = if self.document_ttl_secs > 0 {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis() as u64 + self.document_ttl_secs * 1000)
                } else {
                    0
                };
                info!(
                    kind = %inner.kind,
                    name = %inner.name,
                    resolved_name = %resolved.name,
                    resolved_variant = %resolved.variant,
                    sandbox_id = %sandbox_id,
                    digest = %proj.digest,
                    version = proj.version,
                    valid_until_ms,
                    "policy_service.get_document: served"
                );

                // Compute spec-digest for sandbox policy documents; empty string for others.
                let spec_digest = SandboxPolicy::decode(proj.bytes.as_ref())
                    .map(|p| sandbox_policy_spec_digest(&p))
                    .unwrap_or_default();

                let provenance_token = if let Some(id) = self.signer.as_ref() {
                    mint_provenance_jwt(
                        id,
                        &proj.digest,
                        proj.version,
                        valid_until_ms,
                        &spec_digest,
                        &self.bundle_id,
                    )
                    .unwrap_or_default()
                } else {
                    String::new()
                };

                Ok(Response::new(wire::GetDocumentResponse {
                    body: proj.bytes,
                    digest: proj.digest,
                    version: proj.version,
                    valid_until_ms,
                    provenance_token,
                }))
            }
            None => Err(Status::not_found(format!(
                "document '{}/{}' not found",
                inner.kind, inner.name
            ))),
        }
    }

    async fn list_documents(
        &self,
        req: Request<wire::ListDocumentsRequest>,
    ) -> Result<Response<wire::ListDocumentsResponse>, Status> {
        let inner = req.into_inner();
        self.check_kind(&inner.kind)?;
        let names = self.source.list(&inner.kind);
        Ok(Response::new(wire::ListDocumentsResponse { names }))
    }
}
