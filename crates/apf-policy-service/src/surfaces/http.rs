// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! JSON HTTP surface for the APF policy service daemon. Enabled via
//! `--http-addr`; see `router()` for the route table and auth split.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use apf_proto::runtime_v1alpha1::{OpenShellContext, RuntimeContext, runtime_context};

use crate::runtime::core::DocumentSigner;
use crate::source::{PolicyResolver, PolicySource};

/// Shared state for the HTTP surface handlers.
#[derive(Clone)]
pub struct HttpState {
    pub source: Arc<dyn PolicySource>,
    pub resolver: Arc<dyn PolicyResolver>,
    /// Empty = no restriction; non-empty = only these kinds are served.
    pub allowed_kinds: Arc<HashSet<String>>,
    /// Gates the non-ops routes. `None` means they aren't mounted at all —
    /// see `router()`.
    pub bearer_token: Option<Arc<str>>,
    /// Present when the daemon signs vended documents. Independent of which
    /// `source` is active — the signing key is a CLI-level identity, not
    /// bundle content — so this is populated the same way for local and
    /// HTTP policy sources.
    pub document_signer: Option<Arc<DocumentSigner>>,
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
///
/// Ops/liveness routes stay unauthenticated regardless of `bearer_token` so
/// probes and JWKS fetch never depend on auth config. Everything else sits
/// behind `require_bearer_token` via `route_layer`. `main.rs` requires a
/// token whenever the HTTP surface is enabled at all, so `bearer_token` is
/// always `Some` in the running service; the `None` branch here is for
/// direct callers of `router()` (tests, other embedders) and stays
/// fail-closed on purpose — no token mounts no protected routes, rather
/// than serving them unauthenticated.
pub fn router(state: HttpState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(state.clone());

    if state.bearer_token.is_none() {
        return public;
    }

    let protected = Router::new()
        .route("/v1/documents/{kind}", get(list_documents))
        .route("/v1/documents/{kind}/{name}", get(get_document))
        .route("/v1/refresh", post(refresh_policy))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer_token,
        ))
        .with_state(state);

    public.merge(protected)
}

async fn require_bearer_token(State(s): State<HttpState>, req: Request, next: Next) -> Response {
    let Some(expected) = s.bearer_token.as_deref() else {
        // Unreachable: this layer is only attached when bearer_token is Some.
        return (StatusCode::UNAUTHORIZED, "bearer auth not configured").into_response();
    };
    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(req).await
        }
        _ => (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response(),
    }
}

/// Compares in time proportional to `a.len()`, independent of where (or
/// whether) the two inputs differ, so response latency can't be used to
/// recover the token a byte at a time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
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
    if !s.source.is_ready() {
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

#[derive(Deserialize, Default)]
struct RefreshRequest {
    bundle_path: Option<String>,
}

async fn refresh_policy(
    State(s): State<HttpState>,
    body: Option<Json<RefreshRequest>>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let bundle_path = req.bundle_path.as_deref().map(std::path::Path::new);
    tracing::info!("HTTP /v1/refresh triggered by operator");

    match s.source.refresh(bundle_path).await {
        Ok(outcome) => {
            tracing::info!(digest = %outcome.policy_digest, "bundle refreshed via /v1/refresh");
            Ok(Json(RefreshResponse {
                status: "refreshed",
                policy_digest: outcome.policy_digest,
                version: outcome.version,
            }))
        }
        Err(e) => {
            tracing::warn!(error = %e, "bundle refresh failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("refresh failed: {e}"),
            ))
        }
    }
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
    if let Some(ref vi) = s.document_signer {
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
