// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! `nvidia.agent_policy_fabric.policy.v1alpha1.PolicyService` gRPC surface.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use apf_proto::openshell_sandbox::SandboxPolicy;
use apf_proto::policy_service_v1alpha1 as wire;
use apf_proto::runtime_v1alpha1::runtime_context;
use apf_proto::spec_digest::sandbox_policy_spec_digest;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
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
    /// Hex-encoded `DriverConfigPolicy` protobuf — the driver-config allowlist
    /// for this sandbox policy. Absent when the policy carries no rule. The
    /// native projection cannot carry it, so it rides the signed token.
    #[serde(rename = "apf/driver-config", skip_serializing_if = "Option::is_none")]
    apf_driver_config: Option<String>,
}

/// Encode a 32-byte Ed25519 seed as a PKCS#8 v1 DER blob (RFC 8410).
///
/// The structure is fixed for Ed25519:
/// SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { seed } } }
/// Total: 48 bytes. `jsonwebtoken`'s Ed25519 signer requires this PKCS#8 form.
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
    driver_config_hex: Option<String>,
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
        apf_driver_config: driver_config_hex,
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
    /// Records a provenance mint failure, which vends an unsigned document.
    audit: crate::runtime::audit::PolicyServiceAudit,
}

impl PolicyServiceImpl {
    pub fn new(
        resolver: Arc<dyn PolicyResolver>,
        source: Arc<dyn PolicySource>,
        allowed_kinds: Arc<HashSet<String>>,
        signer: Option<Arc<DocumentSigner>>,
        document_ttl_secs: u64,
        bundle_id: String,
        audit: crate::runtime::audit::PolicyServiceAudit,
    ) -> Self {
        Self {
            resolver,
            source,
            allowed_kinds,
            signer,
            document_ttl_secs,
            bundle_id,
            audit,
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_kind(&self, kind: &str, verb: &str) -> Result<(), Status> {
        let message = if kind.is_empty() {
            "kind must be non-empty".to_owned()
        } else if !self.allowed_kinds.is_empty() && !self.allowed_kinds.contains(kind) {
            format!("kind '{kind}' is not served by this instance")
        } else {
            return Ok(());
        };
        // The request never resolved a variant, so any loaded bundle is context
        // rather than causation.
        // Emitted whether or not a bundle is loaded: an unserved-kind probe
        // during the startup window is exactly the one worth having.
        if let Err(e) = self.audit.emit_document_denied(
            &self.source.active_bundle_digest("").unwrap_or_default(),
            "policy.document_request_invalid",
            kind,
            "-",
            verb,
            message.clone(),
        ) {
            warn!(error = %e, "audit emission failed for invalid document request");
        }
        Err(Status::invalid_argument(message))
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
        self.check_kind(&inner.kind, "policy.get_document")?;

        let ctx = inner.runtime_context.unwrap_or_default();
        let resolved = self.resolver.resolve(&inner.name, &ctx);

        let sandbox_id = ctx
            .platform
            .as_ref()
            .map(|p| match p {
                runtime_context::Platform::Openshell(o) => o.sandbox_id.as_str(),
            })
            .unwrap_or("-");

        // Projection and digest from one read: separately, an unmapped
        // user_subject resolves to the empty variant, where the projection scan
        // and the digest lookup select different caches — a caller-steerable
        // mismatch, no race required.
        match self
            .source
            .get_with_bundle(&inner.kind, &resolved.name, &resolved.variant)
        {
            Some((proj, bundle_digest)) => {
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
                    // A signer is configured, so an empty token means the mint
                    // failed and the document is vended unsigned — the consumer
                    // cannot verify it came from here.
                    //
                    // The driver-config allowlist (if any) is hex-encoded
                    // DriverConfigPolicy protobuf; it rides the signed token so
                    // the interceptor can enforce it, since the native
                    // projection cannot carry it.
                    let driver_config_hex = self
                        .source
                        .driver_config(&resolved.name, &resolved.variant)
                        .map(hex::encode);
                    mint_provenance_jwt(
                        id,
                        &proj.digest,
                        proj.version,
                        valid_until_ms,
                        &spec_digest,
                        &self.bundle_id,
                        driver_config_hex,
                    )
                    .unwrap_or_else(|| {
                        if let Err(e) = self.audit.emit_provenance_mint_failed(
                            &bundle_digest,
                            &inner.kind,
                            &resolved.name,
                        ) {
                            warn!(error = %e, "audit emission failed for provenance mint failure");
                        }
                        String::new()
                    })
                } else {
                    String::new()
                };

                // This is the surface gateways actually poll, so it carries
                // the distribution evidence — which bundle reached which
                // consumer.
                if let Err(e) = self.audit.emit_document_vended(
                    &bundle_digest,
                    &inner.kind,
                    &resolved.name,
                    proj.version,
                ) {
                    warn!(error = %e, "audit emission failed for document vended");
                }

                Ok(Response::new(wire::GetDocumentResponse {
                    body: proj.bytes,
                    digest: proj.digest,
                    version: proj.version,
                    valid_until_ms,
                    provenance_token,
                }))
            }
            None => {
                // No projection, so no bundle to read it from; the active
                // digest is the best available context for the denial.
                // A variant that never fetched has no digest; the refusal is
                // still recorded, without policy identity.
                if let Err(e) = self.audit.emit_document_denied(
                    &self
                        .source
                        .active_bundle_digest(&resolved.variant)
                        .unwrap_or_default(),
                    "policy.document_not_found",
                    &inner.kind,
                    &resolved.name,
                    "policy.get_document",
                    format!("document '{}/{}' not found", inner.kind, inner.name),
                ) {
                    warn!(error = %e, "audit emission failed for document not found");
                }
                Err(Status::not_found(format!(
                    "document '{}/{}' not found",
                    inner.kind, inner.name
                )))
            }
        }
    }

    async fn list_documents(
        &self,
        req: Request<wire::ListDocumentsRequest>,
    ) -> Result<Response<wire::ListDocumentsResponse>, Status> {
        let inner = req.into_inner();
        self.check_kind(&inner.kind, "policy.list_documents")?;
        let names = self.source.list(&inner.kind);
        Ok(Response::new(wire::ListDocumentsResponse { names }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::audit::PolicyServiceAudit;
    use crate::source::resolver::PassthroughResolver;
    use apf_audit::AuditEvent;

    /// Serves nothing, so every request reaches the refusal path.
    struct EmptySource;

    #[async_trait::async_trait]
    impl PolicySource for EmptySource {
        fn get(&self, _: &str, _: &str, _: &str) -> Option<crate::source::PolicyProjection> {
            None
        }
        fn list(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
        fn active_bundle_digest(&self, _: &str) -> Option<String> {
            None
        }
        fn get_with_bundle(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Option<(crate::source::PolicyProjection, String)> {
            None
        }
    }

    fn verbs_written(dir: &std::path::Path) -> Vec<String> {
        let written = std::fs::read_to_string(dir.join("apf-policy-service-audit.jsonl"))
            .expect("audit log was written");
        written
            .lines()
            .map(|line| {
                let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
                parsed.validate().expect("validates against the schema");
                parsed.verb.expect("a refusal names the verb")
            })
            .collect()
    }

    /// The socket is the surface gateways actually poll, so a verb recorded
    /// here being wrong is the forensics that matters. Asserted at the call
    /// site: the emitter cannot tell which RPC invoked it, so a swapped pair of
    /// literals is invisible to any test that supplies the verb itself.
    #[tokio::test]
    async fn each_rpc_records_its_own_verb() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let svc = PolicyServiceImpl::new(
            Arc::new(PassthroughResolver),
            Arc::new(EmptySource),
            Arc::new(HashSet::from(["openshell.sandbox.v1".to_owned()])),
            None,
            60,
            "test-bundle".to_owned(),
            PolicyServiceAudit::to_jsonl_in(dir.path()).expect("build emitter"),
        );

        svc.list_documents(Request::new(wire::ListDocumentsRequest {
            kind: "aws.iam.v1".to_owned(),
        }))
        .await
        .expect_err("an unserved kind is refused");
        assert_eq!(verbs_written(dir.path()), ["policy.list_documents"]);

        svc.get_document(Request::new(wire::GetDocumentRequest {
            kind: "aws.iam.v1".to_owned(),
            name: "admin".to_owned(),
            runtime_context: None,
        }))
        .await
        .expect_err("an unserved kind is refused");
        assert_eq!(
            verbs_written(dir.path()),
            ["policy.list_documents", "policy.get_document"]
        );
    }
}
