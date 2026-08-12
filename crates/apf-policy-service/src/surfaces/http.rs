// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! JSON HTTP surface for the APF policy service daemon. Enabled via `--http-addr`.
//!
//! Routes:
//!   GET  /health
//!   GET  /healthz            — liveness probe (always 200)
//!   GET  /readyz             — readiness probe (200 when bundle loaded, 503 otherwise)
//!   GET  /v1/documents/{kind}[?`sandbox_id=…&user_subject=…&agent_type`=…]
//!   GET  /v1/documents/{kind}/{name}[?`sandbox_id=…&user_subject=…&agent_type`=…]
//!   POST /v1/refresh         — triggers an immediate bundle re-fetch
//!   GET  /.well-known/jwks.json  — Ed25519 JWK for the document signer

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use apf_proto::runtime_v1alpha1::{OpenShellContext, RuntimeContext, runtime_context};

use crate::runtime::core::PolicyServiceCore;
use crate::source::{PolicyResolver, PolicySource};

/// Shared state for the HTTP surface handlers.
#[derive(Clone)]
pub struct HttpState {
    pub core: Arc<PolicyServiceCore>,
    pub source: Arc<dyn PolicySource>,
    pub resolver: Arc<dyn PolicyResolver>,
    /// Empty = no restriction; non-empty = only these kinds are served.
    pub allowed_kinds: Arc<HashSet<String>>,
    /// When set, the `/v1/refresh` endpoint triggers an immediate re-fetch.
    pub http_source: Option<Arc<crate::source::HttpBundleSource>>,
}

impl HttpState {
    fn check_kind(&self, kind: &str) -> Result<(), (StatusCode, String)> {
        if kind.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "kind must be non-empty".into()));
        }
        if !self.allowed_kinds.is_empty() && !self.allowed_kinds.contains(kind) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("kind '{kind}' is not served by this instance"),
            ));
        }
        Ok(())
    }
}

/// Build the Axum router for the HTTP surface, wired to the given `state`.
pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/documents/{kind}", get(list_documents))
        .route("/v1/documents/{kind}/{name}", get(get_document))
        .route("/v1/refresh", post(refresh_policy))
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(state)
}

// --- /health ---

#[derive(Serialize)]
struct HealthBody {
    state: &'static str,
}

async fn health() -> Json<HealthBody> {
    Json(HealthBody { state: "ok" })
}

// --- /healthz (liveness) ---

#[derive(Serialize)]
struct HealthzBody {
    status: &'static str,
    version: &'static str,
}

async fn healthz() -> Json<HealthzBody> {
    Json(HealthzBody {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

// --- /readyz (readiness) ---

#[derive(Serialize)]
struct ReadyzBody {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

async fn readyz(State(s): State<HttpState>) -> (StatusCode, Json<ReadyzBody>) {
    if s.core.bundle.digest_hex.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyzBody {
                status: "not_ready",
                reason: Some("no bundle loaded"),
            }),
        );
    }
    (
        StatusCode::OK,
        Json(ReadyzBody {
            status: "ok",
            reason: None,
        }),
    )
}

// --- GET /v1/documents/{kind} and GET /v1/documents/{kind}/{name} ---

#[derive(Deserialize)]
struct GetDocumentQuery {
    sandbox_id: Option<String>,
    user_subject: Option<String>,
    agent_type: Option<String>,
}

#[derive(Serialize)]
struct ListDocumentsBody {
    names: Vec<String>,
}

async fn list_documents(
    State(s): State<HttpState>,
    Path(kind): Path<String>,
    Query(q): Query<GetDocumentQuery>,
) -> Result<Json<ListDocumentsBody>, (StatusCode, String)> {
    s.check_kind(&kind)?;
    tracing::debug!(
        kind = %kind,
        user_subject = q.user_subject.as_deref().unwrap_or("-"),
        sandbox_id = q.sandbox_id.as_deref().unwrap_or("-"),
        agent_type = q.agent_type.as_deref().unwrap_or("-"),
        "http.list_documents"
    );
    let names = s.source.list(&kind);
    Ok(Json(ListDocumentsBody { names }))
}

// --- GET /v1/documents/{kind}/{name} ---

#[derive(Serialize)]
struct GetDocumentBody {
    /// Base64-encoded substrate-native artifact bytes.
    body: String,
    digest: String,
    version: u64,
}

async fn get_document(
    State(s): State<HttpState>,
    Path((kind, name)): Path<(String, String)>,
    Query(q): Query<GetDocumentQuery>,
) -> Result<Json<GetDocumentBody>, (StatusCode, String)> {
    s.check_kind(&kind)?;

    let ctx = RuntimeContext {
        platform: Some(runtime_context::Platform::Openshell(OpenShellContext {
            sandbox_id: q.sandbox_id.unwrap_or_default(),
            user_subject: q.user_subject.unwrap_or_default(),
            agent_type: q.agent_type.unwrap_or_default(),
        })),
        audit_context: HashMap::new(),
    };
    let resolved = s.resolver.resolve(&name, &ctx);

    match s.source.get(&kind, &resolved.name, &resolved.variant) {
        Some(proj) => Ok(Json(GetDocumentBody {
            body: base64::engine::general_purpose::STANDARD.encode(&proj.bytes),
            digest: proj.digest,
            version: proj.version,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("document '{kind}/{name}' not found"),
        )),
    }
}

// --- POST /v1/refresh ---

#[derive(Serialize)]
struct RefreshResponse {
    status: &'static str,
    policy_digest: String,
    version: u64,
}

async fn refresh_policy(
    State(s): State<HttpState>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    tracing::info!("HTTP /v1/refresh triggered by operator");
    if let Some(ref src) = s.http_source {
        src.poll_for_update().await.map_err(|e| {
            tracing::warn!(error = %e, "HTTP /v1/refresh failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("refresh failed: {e}"),
            )
        })?;
        let digest = src.current_bundle_digest();
        let version = src.current_counter();
        return Ok(Json(RefreshResponse {
            status: "refreshed",
            policy_digest: digest,
            version,
        }));
    }
    Ok(Json(RefreshResponse {
        status: "no_http_source",
        policy_digest: s.core.bundle.digest_hex.clone(),
        version: s.core.bundle.monotonic_counter,
    }))
}

// --- GET /.well-known/jwks.json ---

#[derive(Serialize)]
struct JwksResponse {
    keys: Vec<JwkEntry>,
}

#[derive(Serialize)]
struct JwkEntry {
    kty: String,
    crv: String,
    kid: String,
    x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
}

async fn jwks(State(s): State<HttpState>) -> Json<JwksResponse> {
    let mut keys = Vec::new();
    if let Some(ref vi) = s.core.document_signer {
        let pk = vi.signing_key.verifying_key();
        keys.push(JwkEntry {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            kid: vi.key_id.clone(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes()),
            y: None,
        });
    }
    Json(JwksResponse { keys })
}
