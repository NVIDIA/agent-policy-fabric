// SPDX-License-Identifier: Apache-2.0
// GatewayInterceptor service implementation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::reconciler;
use apf_openshell_auth::{
    Authenticated, AuthenticationMode, AuthorizationFailure, ExtensionAuthVerifier,
    ExtensionCallerKind,
};
use apf_policy_client::PolicyClientHandle;
use ed25519_dalek::VerifyingKey;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::bindings;
use crate::context;
use crate::patches::{self, PatchError};
use crate::proto::{
    DescribeRequest, GatewayInterceptor, GatewayInterceptorServer, InterceptorEvaluation,
    InterceptorManifest, InterceptorResult, ProviderProfileSnapshot,
    ProviderProfileSnapshotRequest, interceptor_evaluation,
};
use apf_proto::json as util;
use apf_proto::spec_digest::canonical_json_digest;

// Bounds CreateSandbox specs, config patches, and aggregated provider-profile
// snapshots. Unlike the middleware's HTTP body limit, there is no single
// OpenShell-advertised ceiling for these payload shapes; this is sized with
// headroom over a typical HTTP body limit for the multi-profile snapshot case.
const GRPC_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Operator-supplied configuration for the interceptor process.
#[derive(Clone)]
pub struct InterceptorConfig {
    /// Surface ID passed to `GetDocument` (e.g. `"openshell.sandbox.v1"`).
    pub document_kind: String,
    /// Document name passed to `GetDocument`.
    pub document_name: String,
    /// Key ID of the policy-service signing identity, recorded in log annotations.
    pub signing_key_id: String,
    /// Ed25519 public key used to verify provenance JWTs at inject and validate time.
    /// Shared with the JWKS watcher, which replaces the inner value on key rotation.
    pub verifying_key: Arc<RwLock<VerifyingKey>>,
}

/// The tonic service that implements `GatewayInterceptor`.
#[derive(Clone)]
pub struct GatewayInterceptorService {
    policy_service: PolicyClientHandle,
    config: InterceptorConfig,
    authentication: AuthenticationMode,
}

/// Size-limited gateway interceptor server protected by extension JWT authentication.
pub type AuthenticatedGatewayInterceptorServer =
    Authenticated<GatewayInterceptorServer<GatewayInterceptorService>>;

impl GatewayInterceptorService {
    /// Builds a size-limited server that authenticates every OpenShell call before dispatch.
    #[must_use]
    pub fn authenticated_server(
        policy_service: PolicyClientHandle,
        config: InterceptorConfig,
        verifier: ExtensionAuthVerifier,
    ) -> AuthenticatedGatewayInterceptorServer {
        let service = Self {
            policy_service,
            config,
            authentication: AuthenticationMode::Required {
                expected_audience: verifier.audience().to_string(),
            },
        };
        Authenticated::new(service.into_size_limited_server(), verifier)
    }

    /// Builds a size-limited server with authentication deliberately disabled.
    ///
    /// This mode is only for a matching OpenShell registration whose
    /// `allow_insecure_transport` setting explicitly opts out of extension authentication.
    #[must_use]
    pub fn insecure_server(
        policy_service: PolicyClientHandle,
        config: InterceptorConfig,
    ) -> GatewayInterceptorServer<Self> {
        Self {
            policy_service,
            config,
            authentication: AuthenticationMode::Insecure,
        }
        .into_size_limited_server()
    }

    fn into_size_limited_server(self) -> GatewayInterceptorServer<Self> {
        GatewayInterceptorServer::new(self)
            .max_decoding_message_size(GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(GRPC_MESSAGE_BYTES)
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<(), AuthorizationFailure> {
        // Every GatewayInterceptor RPC is called exclusively by the OpenShell
        // gateway at admission time — there is no supervisor caller on this surface.
        self.authentication
            .authorize(request, &[ExtensionCallerKind::Gateway])
            .map(|_| ())
    }

    fn expected_audience(&self) -> &str {
        self.authentication.expected_audience()
    }
}

/// Decoded claims from a provenance JWT, used for annotation population and TOCTOU detection.
#[derive(Debug, Default)]
struct ProvJwtClaims {
    pub jti: String,
    #[allow(dead_code)]
    pub sub: String,
    pub apf_document_digest: String,
    pub apf_spec_digest: String,
    #[allow(dead_code)]
    pub apf_bundle_id: String,
}

/// Verify the provenance JWT stored in operation annotations using the cached Ed25519 key.
///
/// Checks in order:
/// 1. Annotations `provenance-token`, `correlation-id`, and `document-digest` are present.
/// 2. JWT signature is valid against the supplied verifying key.
/// 3. JWT `exp` is not in the past (skipped when `exp == 0`).
/// 4. JWT `jti` equals the `correlation-id` annotation (anti-substitution).
/// 5. JWT `apf/document-digest` equals the `document-digest` annotation (anti-swap).
///
/// Returns the verified claims when all checks pass, so callers can use `apf/spec-digest`.
fn verify_provenance_jwt_from_eval(
    verifying_key: &VerifyingKey,
    eval: &InterceptorEvaluation,
) -> Option<ProvJwtClaims> {
    let op_json =
        context::operation_struct(eval).map_or(serde_json::Value::Null, util::struct_to_json);
    let annotations = &op_json["annotations"];

    let jwt = annotations["apf.nvidia.com/provenance-token"].as_str()?;
    let correlation_id = annotations["apf.nvidia.com/correlation-id"].as_str()?;
    let policy_digest = annotations["apf.nvidia.com/document-digest"].as_str()?;

    let claims = verify_jwt_internal(verifying_key, jwt).ok()?;

    if claims.jti != correlation_id {
        return None;
    }

    if claims.apf_document_digest != policy_digest {
        return None;
    }

    Some(claims)
}

/// Internal JWT verification: validates Ed25519 signature and optional expiry.
fn verify_jwt_internal(key: &VerifyingKey, jwt: &str) -> Result<ProvJwtClaims, ()> {
    use base64::Engine as _;
    use ed25519_dalek::Verifier;
    use std::time::{SystemTime, UNIX_EPOCH};

    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(());
    }

    // Verify signature over "header.payload"
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| ())?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| ())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let message = format!("{}.{}", parts[0], parts[1]);
    key.verify(message.as_bytes(), &sig).map_err(|_| ())?;

    // Decode payload
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| ())?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|_| ())?;

    // Check expiry
    let exp = payload["exp"].as_u64().unwrap_or(0);
    if exp > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX, |d| d.as_secs());
        if now > exp {
            return Err(());
        }
    }

    Ok(ProvJwtClaims {
        jti: payload["jti"].as_str().unwrap_or("").to_string(),
        sub: payload["sub"].as_str().unwrap_or("").to_string(),
        apf_document_digest: payload["apf/document-digest"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        apf_spec_digest: payload["apf/spec-digest"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        apf_bundle_id: payload["apf/bundle-id"].as_str().unwrap_or("").to_string(),
    })
}

/// Report whether the evaluated operation already carries an `annotations` object.
fn operation_has_annotations(eval: &InterceptorEvaluation) -> bool {
    context::operation_struct(eval)
        .map(util::struct_to_json)
        .as_ref()
        .and_then(|op| op.get("annotations"))
        .is_some_and(serde_json::Value::is_object)
}

/// Canonical spec-digest over a bare sandbox `policy` JSON value.
fn compute_spec_digest_from_policy(policy: &serde_json::Value) -> String {
    let digest_input = serde_json::json!({ "policy": policy });
    canonical_json_digest(&digest_input)
}

/// Canonical spec-digest from a `CreateSandbox` operation (policy at `/spec/policy`).
fn compute_spec_digest_from_op(op_json: &serde_json::Value) -> String {
    compute_spec_digest_from_policy(&op_json["spec"]["policy"])
}

/// Build an `allow` result with no patches or annotations.
#[must_use]
fn allow() -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        ..Default::default()
    }
}

/// Build a deny result with correlation context in `log_annotations` so the
/// gateway framework's structured log carries enough to correlate the denial.
#[must_use]
fn deny_with_context(
    reason: &str,
    correlation_id: &str,
    policy_digest: &str,
    binding_id: &str,
) -> InterceptorResult {
    let mut log_annotations = HashMap::new();
    if !correlation_id.is_empty() {
        log_annotations.insert(
            "apf.nvidia.com/correlation-id".to_string(),
            correlation_id.to_string(),
        );
    }
    if !policy_digest.is_empty() {
        log_annotations.insert(
            "apf.nvidia.com/document-digest".to_string(),
            policy_digest.to_string(),
        );
    }
    if !binding_id.is_empty() {
        log_annotations.insert(
            "apf.nvidia.com/binding-id".to_string(),
            binding_id.to_string(),
        );
    }
    InterceptorResult {
        allowed: false,
        reason: reason.to_string(),
        log_annotations,
        ..Default::default()
    }
}

impl GatewayInterceptorService {
    /// Handle `MODIFY_OPERATION` for `CreateSandbox`.
    ///
    /// Fetches the policy-service-vended policy projection, verifies it is signed, and
    /// returns RFC 6902 patches that rewrite the sandbox spec and inject
    /// provenance annotations into `operation.annotations` for `VALIDATE`.
    /// `apf.nvidia.com/provenance-token` carries the policy-service-minted JWT verbatim;
    /// `correlation-id` is sourced from the JWT `jti` claim.
    #[allow(clippy::too_many_lines)]
    async fn handle_sandbox_inject(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let ctx = context::extract(&eval).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let runtime_ctx = context::to_runtime_context(&ctx);

        let doc = self
            .policy_service
            .clone()
            .get_document(
                self.config.document_kind.clone(),
                self.config.document_name.clone(),
                Some(runtime_ctx),
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "policy service get_document failed");
                Status::unavailable(format!("policy service unavailable: {e}"))
            })?;

        let policy_digest = doc.digest.clone();
        let policy_version = doc.version;
        let policy_valid_until_ms = doc.valid_until_ms;
        let provenance_token = doc.provenance_token.clone();

        if provenance_token.is_empty() {
            warn!(
                correlation_id = %ctx.correlation_id,
                "CreateSandbox MODIFY_OPERATION denied: policy service vended no provenance token"
            );
            return Ok(Response::new(deny_with_context(
                "policy service vended no provenance token",
                &ctx.correlation_id,
                &policy_digest,
                &eval.binding_id,
            )));
        }

        if verify_jwt_internal(
            &self.config.verifying_key.read().unwrap().clone(),
            &provenance_token,
        )
        .is_err()
        {
            warn!(
                correlation_id = %ctx.correlation_id,
                "CreateSandbox MODIFY_OPERATION denied: provenance JWT invalid at inject time"
            );
            return Ok(Response::new(deny_with_context(
                "provenance JWT invalid",
                &ctx.correlation_id,
                &policy_digest,
                &eval.binding_id,
            )));
        }

        let mut patch_list = match patches::sandbox_policy_patches(&doc) {
            Err(PatchError::UnsignedProjection) => {
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "CreateSandbox MODIFY_OPERATION denied: policy projection has no provenance token"
                );
                return Ok(Response::new(deny_with_context(
                    "policy projection has no provenance token",
                    &ctx.correlation_id,
                    &policy_digest,
                    &eval.binding_id,
                )));
            }
            Err(PatchError::BodyDigestMismatch) => {
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "CreateSandbox MODIFY_OPERATION denied: policy body digest mismatch"
                );
                return Ok(Response::new(deny_with_context(
                    "policy body digest mismatch",
                    &ctx.correlation_id,
                    &policy_digest,
                    &eval.binding_id,
                )));
            }
            Err(e) => {
                return Err(Status::internal(format!("patch generation failed: {e}")));
            }
            Ok(result) => result,
        };

        // Source correlation_id, signer_identity, and bundle_id from JWT claims when available.
        let (correlation_id, signer_identity, bundle_id) =
            if let Some(claims) = patches::extract_provenance_claims(&provenance_token) {
                (claims.jti, claims.sub, claims.apf_bundle_id)
            } else {
                (
                    ctx.correlation_id.clone(),
                    self.config.signing_key_id.clone(),
                    String::new(),
                )
            };

        // proto3 JSON omits an empty annotations map, so a fresh
        // CreateSandboxRequest has no /annotations parent. Initialize it before
        // the per-key adds or the gateway rejects the first annotation patch.
        if !operation_has_annotations(&eval) {
            patch_list.push(patches::annotations_init_patch());
        }
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/document-digest",
            &policy_digest,
        ));
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/policy-version",
            &policy_version.to_string(),
        ));
        if !bundle_id.is_empty() {
            patch_list.push(patches::annotation_patch(
                "apf.nvidia.com/bundle-id",
                &bundle_id,
            ));
        }
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/signer-identity",
            &signer_identity,
        ));
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/correlation-id",
            &correlation_id,
        ));
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/provenance-token",
            &provenance_token,
        ));
        if policy_valid_until_ms > 0 {
            patch_list.push(patches::annotation_patch(
                "apf.nvidia.com/policy-valid-until",
                &policy_valid_until_ms.to_string(),
            ));
        }

        let mut log_annotations = HashMap::new();
        log_annotations.insert(
            "apf.nvidia.com/document-digest".to_string(),
            policy_digest.clone(),
        );
        log_annotations.insert(
            "apf.nvidia.com/signer-identity".to_string(),
            signer_identity.clone(),
        );
        log_annotations.insert(
            "apf.nvidia.com/correlation-id".to_string(),
            correlation_id.clone(),
        );
        log_annotations.insert(
            "apf.nvidia.com/sandbox-id".to_string(),
            ctx.sandbox_id.clone(),
        );
        if policy_valid_until_ms > 0 {
            log_annotations.insert(
                "apf.nvidia.com/policy-valid-until".to_string(),
                policy_valid_until_ms.to_string(),
            );
        }

        info!(
            correlation_id = %correlation_id,
            sandbox_id = %ctx.sandbox_id,
            policy_digest = %policy_digest,
            policy_valid_until_ms,
            "CreateSandbox policy injected"
        );

        Ok(Response::new(InterceptorResult {
            allowed: true,
            patches: patch_list,
            log_annotations,
            ..Default::default()
        }))
    }

    /// Handle `VALIDATE` for `CreateSandbox`.
    ///
    /// Verifies the provenance JWT and re-derives the canonical spec digest to detect
    /// post-injection mutation (TOCTOU window).
    #[allow(clippy::unused_async, clippy::too_many_lines)]
    async fn handle_sandbox_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        const REASON: &str = "sandbox policy integrity check failed";

        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let annotations = &op_json["annotations"];
        let correlation_id = annotations["apf.nvidia.com/correlation-id"]
            .as_str()
            .unwrap_or("");
        let policy_digest = annotations["apf.nvidia.com/document-digest"]
            .as_str()
            .unwrap_or("");
        let sandbox_id = op_json["name"].as_str().unwrap_or("");

        let jwt_claims = verify_provenance_jwt_from_eval(
            &self.config.verifying_key.read().unwrap().clone(),
            &eval,
        );

        if jwt_claims.is_none() {
            let token_present = annotations["apf.nvidia.com/provenance-token"]
                .as_str()
                .is_some();
            let deny_message = if token_present {
                "provenance token verification failed"
            } else {
                "provenance token missing"
            };
            warn!(
                correlation_id,
                sandbox_id, token_present, "CreateSandbox VALIDATE denied: {deny_message}"
            );
            return Ok(Response::new(deny_with_context(
                REASON,
                correlation_id,
                policy_digest,
                &eval.binding_id,
            )));
        }

        // jwt_claims is Some — unwrap is safe.
        let claims = jwt_claims.unwrap();

        // Spec-digest check: compare the JWT apf/spec-digest claim against the
        // canonical digest recomputed from the live spec.policy at validate time.
        // This detects TOCTOU mutations between inject and validate phases.
        if !claims.apf_spec_digest.is_empty() {
            let computed_digest = compute_spec_digest_from_op(&op_json);
            if computed_digest != claims.apf_spec_digest {
                warn!(
                    correlation_id,
                    sandbox_id,
                    "CreateSandbox VALIDATE denied: spec-digest mismatch (potential TOCTOU)"
                );
                return Ok(Response::new(deny_with_context(
                    REASON,
                    correlation_id,
                    policy_digest,
                    &eval.binding_id,
                )));
            }
        }

        info!(correlation_id, sandbox_id, "CreateSandbox VALIDATE allowed");
        Ok(Response::new(allow()))
    }

    /// Handle `MODIFY_OPERATION` for `UpdateConfig`.
    ///
    /// Fetches the policy-service-vended policy and overwrites the `policy` field in
    /// `UpdateConfigRequest` so callers cannot slip in an arbitrary policy.
    /// The provenance JWT from the response is injected as
    /// `apf.nvidia.com/provenance-token` for VALIDATE.
    #[allow(clippy::too_many_lines)]
    async fn handle_config_refresh(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let has_policy = !op_json["policy"].is_null();
        let has_merge_ops = op_json["mergeOperations"]
            .as_array()
            .is_some_and(|a| !a.is_empty());
        let setting_key = op_json["settingKey"]
            .as_str()
            .or_else(|| op_json["setting_key"].as_str());
        let sets_auto_approval = setting_key == Some("proposal_approval_mode")
            && op_json["settingValue"]["stringValue"]
                .as_str()
                .or_else(|| op_json["setting_value"]["string_value"].as_str())
                == Some("auto");
        // Settings-only updates (setting_key present, no policy/mergeOps) pass
        // through without modification. Injecting policy patches into a settings
        // request would conflict with the mutually-exclusive proto fields.
        if setting_key.is_some() && !has_policy && !has_merge_ops {
            if sets_auto_approval {
                let ctx = context::extract_provider(&eval);
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "UpdateConfig MODIFY_OPERATION denied: auto-approval attempt via settings"
                );
                return Ok(Response::new(deny_with_context(
                    "automatic policy proposal approval is blocked; policy is managed by APF",
                    &ctx.correlation_id,
                    "",
                    &eval.binding_id,
                )));
            }
            return Ok(Response::new(allow()));
        }
        if has_policy || has_merge_ops || sets_auto_approval {
            let ctx = context::extract_provider(&eval);
            let reason = if sets_auto_approval {
                "automatic policy proposal approval is blocked; policy is managed by APF"
            } else {
                "direct policy mutation not permitted; policy is managed by APF"
            };
            warn!(
                correlation_id = %ctx.correlation_id,
                has_policy,
                has_merge_ops,
                sets_auto_approval,
                "UpdateConfig MODIFY_OPERATION denied: {reason}"
            );
            return Ok(Response::new(deny_with_context(
                reason,
                &ctx.correlation_id,
                "",
                &eval.binding_id,
            )));
        }

        let ctx = context::extract_provider(&eval);
        let runtime_ctx = context::to_provider_runtime_context(&ctx);

        let doc = self
            .policy_service
            .clone()
            .get_document(
                self.config.document_kind.clone(),
                self.config.document_name.clone(),
                Some(runtime_ctx),
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "policy service get_document failed for config refresh");
                Status::unavailable(format!("policy service unavailable: {e}"))
            })?;

        let policy_digest = doc.digest.clone();
        let policy_version = doc.version;
        let policy_valid_until_ms = doc.valid_until_ms;
        let provenance_token = doc.provenance_token.clone();

        let spec_patches = match patches::sandbox_policy_patches(&doc) {
            Err(PatchError::UnsignedProjection) => {
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "UpdateConfig MODIFY_OPERATION denied: policy projection has no provenance token"
                );
                return Ok(Response::new(deny_with_context(
                    "policy projection has no provenance token",
                    &ctx.correlation_id,
                    &policy_digest,
                    &eval.binding_id,
                )));
            }
            Err(PatchError::BodyDigestMismatch) => {
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "UpdateConfig MODIFY_OPERATION denied: policy body digest mismatch"
                );
                return Ok(Response::new(deny_with_context(
                    "policy body digest mismatch",
                    &ctx.correlation_id,
                    &policy_digest,
                    &eval.binding_id,
                )));
            }
            Err(e) => {
                return Err(Status::internal(format!("patch generation failed: {e}")));
            }
            Ok(result) => result,
        };

        if provenance_token.is_empty() {
            warn!(
                correlation_id = %ctx.correlation_id,
                "UpdateConfig MODIFY_OPERATION denied: policy service vended no provenance token"
            );
            return Ok(Response::new(deny_with_context(
                "policy service vended no provenance token",
                &ctx.correlation_id,
                &policy_digest,
                &eval.binding_id,
            )));
        }

        let (correlation_id, signer_identity, bundle_id) =
            if let Some(claims) = patches::extract_provenance_claims(&provenance_token) {
                (claims.jti, claims.sub, claims.apf_bundle_id)
            } else {
                (
                    ctx.correlation_id.clone(),
                    self.config.signing_key_id.clone(),
                    String::new(),
                )
            };

        let mut patch_list: Vec<_> = spec_patches
            .into_iter()
            .filter(|p| p.path == "/spec/policy")
            .map(|mut p| {
                p.path = "/policy".to_string();
                p
            })
            .collect();

        // UpdateConfigRequest carries annotations at the top level, but the
        // refresher sends a bare request with no annotations map. Initialize it
        // before the per-key adds or the gateway rejects the first patch.
        if !operation_has_annotations(&eval) {
            patch_list.push(patches::annotations_init_patch());
        }
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/document-digest",
            &policy_digest,
        ));
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/policy-version",
            &policy_version.to_string(),
        ));
        if !bundle_id.is_empty() {
            patch_list.push(patches::annotation_patch(
                "apf.nvidia.com/bundle-id",
                &bundle_id,
            ));
        }
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/signer-identity",
            &signer_identity,
        ));
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/correlation-id",
            &correlation_id,
        ));
        patch_list.push(patches::annotation_patch(
            "apf.nvidia.com/provenance-token",
            &provenance_token,
        ));
        if policy_valid_until_ms > 0 {
            patch_list.push(patches::annotation_patch(
                "apf.nvidia.com/policy-valid-until",
                &policy_valid_until_ms.to_string(),
            ));
        }

        let mut log_annotations = HashMap::new();
        log_annotations.insert(
            "apf.nvidia.com/document-digest".to_string(),
            policy_digest.clone(),
        );
        log_annotations.insert(
            "apf.nvidia.com/signer-identity".to_string(),
            signer_identity.clone(),
        );
        log_annotations.insert(
            "apf.nvidia.com/correlation-id".to_string(),
            correlation_id.clone(),
        );
        if policy_valid_until_ms > 0 {
            log_annotations.insert(
                "apf.nvidia.com/policy-valid-until".to_string(),
                policy_valid_until_ms.to_string(),
            );
        }

        info!(
            correlation_id = %correlation_id,
            policy_digest = %policy_digest,
            policy_valid_until_ms,
            "UpdateConfig policy injected"
        );

        Ok(Response::new(InterceptorResult {
            allowed: true,
            patches: patch_list,
            log_annotations,
            ..Default::default()
        }))
    }

    /// Handle `VALIDATE` for `UpdateConfig`.
    ///
    /// Verifies the provenance JWT injected during `MODIFY_OPERATION`.
    #[allow(clippy::unused_async)]
    async fn handle_config_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let annotations = &op_json["annotations"];
        let correlation_id = annotations["apf.nvidia.com/correlation-id"]
            .as_str()
            .unwrap_or("");
        let policy_digest = annotations["apf.nvidia.com/document-digest"]
            .as_str()
            .unwrap_or("");

        let jwt_claims = verify_provenance_jwt_from_eval(
            &self.config.verifying_key.read().unwrap().clone(),
            &eval,
        );

        if jwt_claims.is_none() {
            let token_present = annotations["apf.nvidia.com/provenance-token"]
                .as_str()
                .is_some();
            let deny_message = if token_present {
                "provenance token verification failed"
            } else {
                "provenance token missing"
            };
            warn!(
                correlation_id,
                token_present, "UpdateConfig VALIDATE denied: {deny_message}"
            );
            return Ok(Response::new(deny_with_context(
                "config policy integrity check failed",
                correlation_id,
                policy_digest,
                &eval.binding_id,
            )));
        }

        // jwt_claims is Some — unwrap is safe.
        let claims = jwt_claims.unwrap();

        // Spec-digest check: compare the JWT apf/spec-digest claim against the
        // canonical digest recomputed from the injected /policy (UpdateConfig carries
        // the policy top-level, not under /spec). Detects a mutation of the policy
        // between MODIFY_OPERATION and VALIDATE.
        if !claims.apf_spec_digest.is_empty() {
            let computed_digest = compute_spec_digest_from_policy(&op_json["policy"]);
            if computed_digest != claims.apf_spec_digest {
                warn!(
                    correlation_id,
                    "UpdateConfig VALIDATE denied: spec-digest mismatch (potential TOCTOU)"
                );
                return Ok(Response::new(deny_with_context(
                    "config policy integrity check failed",
                    correlation_id,
                    policy_digest,
                    &eval.binding_id,
                )));
            }
        }

        info!(correlation_id, "UpdateConfig VALIDATE allowed");
        Ok(Response::new(allow()))
    }

    /// Handle `VALIDATE` for `ImportProviderProfiles`.
    #[allow(clippy::too_many_lines)]
    async fn handle_provider_profile_import_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let bundle_ids = match self
            .policy_service
            .clone()
            .list_documents("openshell.provider-profile.v1")
            .await
        {
            Ok(r) => r
                .names
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            Err(e) => {
                warn!(error = %e, "ImportProviderProfiles VALIDATE: policy service list_documents failed");
                return Ok(Response::new(deny_with_context(
                    "provider profile governance check failed: policy service unavailable",
                    "",
                    "",
                    &eval.binding_id,
                )));
            }
        };

        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let profiles = op_json["profiles"].as_array().cloned().unwrap_or_default();

        for item in &profiles {
            let profile = &item["profile"];
            let id = profile["id"].as_str().unwrap_or("");
            if !bundle_ids.contains(id) {
                let correlation_id = uuid::Uuid::new_v4().to_string();
                warn!(
                    profile_id = %id,
                    correlation_id = %correlation_id,
                    "ImportProviderProfiles VALIDATE denied: profile not in bundle"
                );
                return Ok(Response::new(deny_with_context(
                    &format!("provider profile '{id}' is not managed by the APF bundle"),
                    &correlation_id,
                    "",
                    &eval.binding_id,
                )));
            }

            // Verify the policy-service-minted provenance JWT stored in the profile annotation.
            // This detects profiles that were tampered with after being snapshotted.
            {
                let annotations = &profile["annotations"];
                let profile_hash = annotations["openshell.nvidia.com/profile-hash"]
                    .as_str()
                    .unwrap_or("");
                let profile_sig = annotations["openshell.nvidia.com/profile-signature"]
                    .as_str()
                    .unwrap_or("");

                let sig_ok = if profile_sig.is_empty() {
                    false
                } else {
                    verify_jwt_internal(
                        &self.config.verifying_key.read().unwrap().clone(),
                        profile_sig,
                    )
                    .is_ok_and(|c| c.apf_document_digest == profile_hash)
                };

                if !sig_ok {
                    let correlation_id = uuid::Uuid::new_v4().to_string();
                    let deny_message = if profile_sig.is_empty() {
                        "provider profile missing policy-service provenance signature"
                    } else {
                        "provider profile provenance signature invalid or hash mismatch"
                    };
                    warn!(
                        profile_id = %id,
                        correlation_id = %correlation_id,
                        "ImportProviderProfiles VALIDATE denied: {deny_message}"
                    );
                    return Ok(Response::new(deny_with_context(
                        deny_message,
                        &correlation_id,
                        "",
                        &eval.binding_id,
                    )));
                }
            }
        }

        info!("ImportProviderProfiles VALIDATE allowed");
        Ok(Response::new(allow()))
    }

    /// Handle `VALIDATE` for `UpdateProviderProfiles`.
    async fn handle_provider_profile_update_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let bundle_ids = match self
            .policy_service
            .clone()
            .list_documents("openshell.provider-profile.v1")
            .await
        {
            Ok(r) => r
                .names
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            Err(e) => {
                warn!(error = %e, "UpdateProviderProfiles VALIDATE: policy service list_documents failed");
                return Ok(Response::new(deny_with_context(
                    "provider profile governance check failed: policy service unavailable",
                    "",
                    "",
                    &eval.binding_id,
                )));
            }
        };

        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let target_id = op_json["id"].as_str().unwrap_or("");
        if !bundle_ids.contains(target_id) {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            warn!(
                profile_id = %target_id,
                "UpdateProviderProfiles VALIDATE denied: profile not in bundle"
            );
            return Ok(Response::new(deny_with_context(
                &format!("provider profile '{target_id}' is not managed by the APF bundle"),
                &correlation_id,
                "",
                &eval.binding_id,
            )));
        }

        info!("UpdateProviderProfiles VALIDATE allowed");
        Ok(Response::new(allow()))
    }

    /// Handle `VALIDATE` for `DeleteProviderProfile`.
    #[allow(clippy::unused_async)]
    async fn handle_provider_profile_delete_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        Ok(self.deny_provider_governance(&eval, "delete-provider-profile", "delete"))
    }

    /// Handle `VALIDATE` for `CreateProvider` and `UpdateProvider`.
    #[allow(clippy::too_many_lines)]
    async fn handle_provider_instance_type_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let bundle_types = match self
            .policy_service
            .clone()
            .list_documents("openshell.provider-profile.v1")
            .await
        {
            Ok(r) => r
                .names
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            Err(e) => {
                warn!(error = %e, "Provider VALIDATE: policy service list_documents failed");
                return Ok(Response::new(deny_with_context(
                    "provider type governance check failed: policy service unavailable",
                    "",
                    "",
                    &eval.binding_id,
                )));
            }
        };

        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let provider_type = op_json
            .pointer("/provider/type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !bundle_types.contains(provider_type) {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            warn!(
                provider_type,
                correlation_id = %correlation_id,
                "Provider VALIDATE denied: type not in bundle"
            );
            return Ok(Response::new(deny_with_context(
                &format!("provider type '{provider_type}' is not a bundle-managed profile"),
                &correlation_id,
                "",
                &eval.binding_id,
            )));
        }

        // Credential-schema validation is intentionally not done here: the
        // gateway redacts secret-annotated fields (provider.credentials) before
        // an interceptor sees the operation, so the map is always empty at this
        // point. Credential presence/shape is validated by the gateway against
        // the profile. The interceptor's role is governance — the provider type
        // must reference a bundle-managed profile, checked above.
        Ok(Response::new(allow()))
    }

    /// Handle `VALIDATE` for `SubmitPolicyAnalysis`.
    ///
    /// Denies agent-authored policy proposals. Mechanistic proposals (from the
    /// in-sandbox denial aggregator) are allowed through so the gateway can
    /// collect denial telemetry, but are blocked at `ApproveDraftChunk` time.
    #[allow(clippy::unused_async)]
    async fn handle_policy_analysis_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let mode = op_json["analysisMode"]
            .as_str()
            .or_else(|| op_json["analysis_mode"].as_str())
            .unwrap_or("");

        if mode == "agent_authored" {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            let reason =
                "agent-authored policy proposals are not permitted; policy is managed by APF";
            warn!(
                correlation_id = %correlation_id,
                "SubmitPolicyAnalysis VALIDATE denied: agent_authored proposal blocked"
            );
            return Ok(Response::new(deny_with_context(
                reason,
                &correlation_id,
                "",
                &eval.binding_id,
            )));
        }

        info!("SubmitPolicyAnalysis VALIDATE allowed");
        Ok(Response::new(allow()))
    }

    /// Handle `VALIDATE` for `ApproveDraftChunk` and `ApproveAllDraftChunks`.
    ///
    /// Draft chunk approval merges policy directly into the sandbox store,
    /// bypassing the `MODIFY_OPERATION` phase. Deny unconditionally when APF
    /// manages policy so that the proposal pathway cannot be used to override
    /// the bundle-vended policy.
    #[allow(clippy::unused_async)]
    async fn handle_draft_chunk_approve_deny(
        &self,
        eval: InterceptorEvaluation,
        method: &str,
    ) -> Result<Response<InterceptorResult>, Status> {
        let correlation_id = uuid::Uuid::new_v4().to_string();
        let reason = "policy proposal approval is not permitted; policy is managed by APF";
        warn!(
            correlation_id = %correlation_id,
            method,
            "draft chunk approval denied: proposal pathway blocked"
        );
        let resource_id = match method {
            "ApproveAllDraftChunks" => "approve-all-draft-chunks",
            _ => "approve-draft-chunk",
        };
        warn!(resource_id, correlation_id = %correlation_id, reason, "draft chunk approval denied");
        Ok(Response::new(deny_with_context(
            reason,
            &correlation_id,
            "",
            &eval.binding_id,
        )))
    }

    fn deny_provider_governance(
        &self,
        eval: &InterceptorEvaluation,
        resource_id: &'static str,
        operation: &str,
    ) -> Response<InterceptorResult> {
        let correlation_id = uuid::Uuid::new_v4().to_string();
        let reason = format!("provider profiles are bundle-managed; {operation} is not permitted");

        warn!(
            correlation_id = %correlation_id,
            binding_id = %eval.binding_id,
            operation,
            resource_id,
            "provider profile governance denied"
        );

        let mut log_annotations = HashMap::new();
        log_annotations.insert("apf.nvidia.com/correlation-id".to_string(), correlation_id);
        if !eval.binding_id.is_empty() {
            log_annotations.insert(
                "apf.nvidia.com/binding-id".to_string(),
                eval.binding_id.clone(),
            );
        }

        Response::new(InterceptorResult {
            allowed: false,
            reason,
            log_annotations,
            ..Default::default()
        })
    }
}

#[allow(clippy::too_many_lines)]
#[tonic::async_trait]
impl GatewayInterceptor for GatewayInterceptorService {
    async fn describe(
        &self,
        request: Request<DescribeRequest>,
    ) -> Result<Response<InterceptorManifest>, Status> {
        self.authorize(&request)
            .map_err(AuthorizationFailure::into_status)?;
        let mut manifest = bindings::manifest();
        manifest.expected_audience = self.expected_audience().to_string();
        Ok(Response::new(manifest))
    }

    async fn snapshot_provider_profiles(
        &self,
        request: Request<ProviderProfileSnapshotRequest>,
    ) -> Result<Response<ProviderProfileSnapshot>, Status> {
        self.authorize(&request)
            .map_err(AuthorizationFailure::into_status)?;
        use sha2::{Digest, Sha256};

        let mut policy_service = self.policy_service.clone();
        let names = policy_service
            .list_documents("openshell.provider-profile.v1")
            .await
            .map_err(|e| Status::internal(format!("list_documents: {e}")))?
            .names;

        // Fetch each profile body, digest, and provenance token.
        // (id, body, digest, provenance_token)
        let mut profile_entries: Vec<(String, Vec<u8>, String, String)> =
            Vec::with_capacity(names.len());
        for name in &names {
            let resp = policy_service
                .get_document("openshell.provider-profile.v1", name, None)
                .await
                .map_err(|e| Status::internal(format!("get_document '{name}': {e}")))?;
            profile_entries.push((name.clone(), resp.body, resp.digest, resp.provenance_token));
        }
        profile_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut profiles = Vec::with_capacity(profile_entries.len());
        let mut hasher = Sha256::new();
        hasher.update(b"apf-provider-profile-snapshot-v1");
        for (id, body, digest, provenance_token) in &profile_entries {
            match reconciler::profile_from_yaml(body) {
                Ok(mut p) => {
                    // Annotate each profile with its content hash and policy-service provenance
                    // JWT so the VALIDATE handler can detect tampering at import time.
                    p.annotations.insert(
                        "openshell.nvidia.com/profile-hash".to_string(),
                        digest.clone(),
                    );
                    if !provenance_token.is_empty() {
                        p.annotations.insert(
                            "openshell.nvidia.com/profile-signature".to_string(),
                            provenance_token.clone(),
                        );
                    }
                    profiles.push(p);
                }
                Err(e) => warn!(profile_id = %id, error = %e, "skipping unparseable profile"),
            }
            // Include both the ID and the content bytes so the revision changes
            // when any profile's body changes, not just when the set of IDs changes.
            hasher.update(id.as_bytes());
            hasher.update(b"\0");
            hasher.update(body);
            hasher.update(b"\0");
        }
        let revision = format!("sha256:{:x}", hasher.finalize());

        Ok(Response::new(ProviderProfileSnapshot {
            revision,
            profiles,
        }))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> Result<Response<InterceptorResult>, Status> {
        self.authorize(&request)
            .map_err(AuthorizationFailure::into_status)?;
        use interceptor_evaluation::Phase;
        let r = request.into_inner();
        match (r.method.as_str(), &r.phase) {
            ("CreateSandbox", Some(Phase::ModifyOperation(_))) => {
                self.handle_sandbox_inject(r).await
            }
            ("CreateSandbox", Some(Phase::Validate(_))) => self.handle_sandbox_verify(r).await,
            ("UpdateConfig", Some(Phase::ModifyOperation(_))) => {
                self.handle_config_refresh(r).await
            }
            ("UpdateConfig", Some(Phase::Validate(_))) => self.handle_config_verify(r).await,
            ("CreateProvider" | "UpdateProvider", Some(Phase::Validate(_))) => {
                self.handle_provider_instance_type_verify(r).await
            }
            ("ImportProviderProfiles", Some(Phase::Validate(_))) => {
                self.handle_provider_profile_import_verify(r).await
            }
            ("UpdateProviderProfiles", Some(Phase::Validate(_))) => {
                self.handle_provider_profile_update_verify(r).await
            }
            ("DeleteProviderProfile", Some(Phase::Validate(_))) => {
                self.handle_provider_profile_delete_verify(r).await
            }
            ("SubmitPolicyAnalysis", Some(Phase::Validate(_))) => {
                self.handle_policy_analysis_verify(r).await
            }
            ("ApproveDraftChunk" | "ApproveAllDraftChunks", Some(Phase::Validate(_))) => {
                let method = r.method.clone();
                self.handle_draft_chunk_approve_deny(r, &method).await
            }
            ("CreateSandbox" | "UpdateConfig", Some(Phase::PostCommit(post_commit))) => {
                let response = post_commit
                    .committed_response
                    .as_ref()
                    .map_or(serde_json::Value::Null, util::struct_to_json);
                let digest = response
                    .pointer("/annotations/apf.nvidia.com~1document-digest")
                    .or_else(|| {
                        response.pointer(
                            "/sandbox/metadata/annotations/apf.nvidia.com~1document-digest",
                        )
                    })
                    .or_else(|| response.pointer("/policyHash"))
                    .or_else(|| response.pointer("/policy_hash"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let cid = response
                    .pointer("/annotations/apf.nvidia.com~1correlation-id")
                    .or_else(|| {
                        response
                            .pointer("/sandbox/metadata/annotations/apf.nvidia.com~1correlation-id")
                    })
                    .and_then(serde_json::Value::as_str)
                    .map_or_else(|| uuid::Uuid::new_v4().to_string(), String::from);
                let sandbox_id = response
                    .pointer("/sandbox/metadata/id")
                    .or_else(|| response.pointer("/sandbox/metadata/name"))
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| r.principal.get("sandbox_id").map(String::as_str));
                let reason_code = match r.method.as_str() {
                    "CreateSandbox" => "interceptor.policy_committed",
                    "UpdateConfig" if digest.is_empty() => "interceptor.config_committed",
                    _ => "interceptor.policy_committed",
                };
                info!(
                    correlation_id = %cid,
                    sandbox_id = ?sandbox_id,
                    policy_digest = %digest,
                    reason_code,
                    "post-commit"
                );
                Ok(Response::new(allow()))
            }
            // The gateway can invoke unbound method/phase combinations. They
            // intentionally pass through without per-call logging to avoid a
            // high-volume stream of events for operations this interceptor
            // does not govern.
            _ => Ok(Response::new(allow())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use prost_types::{Struct as ProstStruct, Value as ProstValue, value::Kind};
    use rand::rngs::OsRng;
    use serde::Serialize;
    use std::collections::BTreeMap;
    use tonic::transport::Endpoint;

    /// PKCS#8 v1 DER encoding for an Ed25519 seed (RFC 8410, 48 bytes).
    fn ed25519_seed_to_pkcs8_der(seed: &[u8; 32]) -> [u8; 48] {
        let mut der = [0u8; 48];
        der[..16].copy_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        der[16..].copy_from_slice(seed);
        der
    }

    #[derive(Serialize)]
    struct TestClaims {
        jti: String,
        sub: String,
        iat: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        exp: Option<u64>,
        #[serde(rename = "apf/document-digest")]
        apf_document_digest: String,
        #[serde(rename = "apf/version")]
        apf_version: u64,
        #[serde(rename = "apf/spec-digest")]
        apf_spec_digest: String,
    }

    fn mint_test_jwt(
        signing_key: &SigningKey,
        key_id: &str,
        jti: &str,
        policy_digest: &str,
        exp: Option<u64>,
    ) -> String {
        mint_test_jwt_with_spec_digest(signing_key, key_id, jti, policy_digest, exp, "")
    }

    fn mint_test_jwt_with_spec_digest(
        signing_key: &SigningKey,
        key_id: &str,
        jti: &str,
        policy_digest: &str,
        exp: Option<u64>,
        spec_digest: &str,
    ) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        let seed = signing_key.to_bytes();
        let der = ed25519_seed_to_pkcs8_der(&seed);
        let encoding_key = EncodingKey::from_ed_der(&der);
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key_id.to_string());
        let claims = TestClaims {
            jti: jti.to_string(),
            sub: key_id.to_string(),
            iat: 1_000_000,
            exp,
            apf_document_digest: policy_digest.to_string(),
            apf_version: 1,
            apf_spec_digest: spec_digest.to_string(),
        };
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("encode")
    }

    fn eval_with_annotations(annotations: Vec<(&str, &str)>) -> InterceptorEvaluation {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        let ann_fields: BTreeMap<String, ProstValue> = annotations
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    ProstValue {
                        kind: Some(Kind::StringValue(v.to_string())),
                    },
                )
            })
            .collect();
        let operation_fields = [(
            "annotations".to_string(),
            ProstValue {
                kind: Some(Kind::StructValue(ProstStruct { fields: ann_fields })),
            },
        )]
        .into_iter()
        .collect();
        InterceptorEvaluation {
            method: "CreateSandbox".to_string(),
            phase: Some(Phase::Validate(ValidateEvaluation {
                proposed_operation: Some(ProstStruct {
                    fields: operation_fields,
                }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn service() -> GatewayInterceptorService {
        let channel = Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        GatewayInterceptorService {
            policy_service: PolicyClientHandle::from_channel(channel),
            config: InterceptorConfig {
                document_kind: "openshell.sandbox.v1".to_string(),
                document_name: "default".to_string(),
                signing_key_id: "test-key".to_string(),
                verifying_key: Arc::new(std::sync::RwLock::new(
                    SigningKey::generate(&mut OsRng).verifying_key(),
                )),
            },
            authentication: AuthenticationMode::Insecure,
        }
    }

    fn post_commit_evaluation() -> InterceptorEvaluation {
        let annotations = [
            (
                "apf.nvidia.com/correlation-id".to_string(),
                ProstValue {
                    kind: Some(Kind::StringValue("corr_post_commit".to_string())),
                },
            ),
            (
                "apf.nvidia.com/document-digest".to_string(),
                ProstValue {
                    kind: Some(Kind::StringValue("sha256:abc123".to_string())),
                },
            ),
        ]
        .into_iter()
        .collect();
        let metadata = [
            (
                "annotations".to_string(),
                ProstValue {
                    kind: Some(Kind::StructValue(ProstStruct {
                        fields: annotations,
                    })),
                },
            ),
            (
                "id".to_string(),
                ProstValue {
                    kind: Some(Kind::StringValue("sandbox-response-id".to_string())),
                },
            ),
        ]
        .into_iter()
        .collect();
        let sandbox = [(
            "metadata".to_string(),
            ProstValue {
                kind: Some(Kind::StructValue(ProstStruct { fields: metadata })),
            },
        )]
        .into_iter()
        .collect();
        let committed_response = [(
            "sandbox".to_string(),
            ProstValue {
                kind: Some(Kind::StructValue(ProstStruct { fields: sandbox })),
            },
        )]
        .into_iter()
        .collect();

        InterceptorEvaluation {
            binding_id: "create-sandbox-post-commit".to_string(),
            method: "CreateSandbox".to_string(),
            phase: Some(crate::proto::interceptor_evaluation::Phase::PostCommit(
                crate::proto::PostCommitEvaluation {
                    committed_response: Some(ProstStruct {
                        fields: committed_response,
                    }),
                },
            )),
            principal: [("subject".to_string(), "alice@example.com".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    fn update_config_post_commit_evaluation() -> InterceptorEvaluation {
        let annotations = [
            (
                "apf.nvidia.com/correlation-id".to_string(),
                ProstValue {
                    kind: Some(Kind::StringValue("corr_update_commit".to_string())),
                },
            ),
            (
                "apf.nvidia.com/document-digest".to_string(),
                ProstValue {
                    kind: Some(Kind::StringValue("sha256:update123".to_string())),
                },
            ),
        ]
        .into_iter()
        .collect();
        let committed_response = [
            (
                "annotations".to_string(),
                ProstValue {
                    kind: Some(Kind::StructValue(ProstStruct {
                        fields: annotations,
                    })),
                },
            ),
            (
                "policyHash".to_string(),
                ProstValue {
                    kind: Some(Kind::StringValue("sha256:local-policy".to_string())),
                },
            ),
        ]
        .into_iter()
        .collect();

        InterceptorEvaluation {
            binding_id: "config-policy-post-commit".to_string(),
            method: "UpdateConfig".to_string(),
            phase: Some(crate::proto::interceptor_evaluation::Phase::PostCommit(
                crate::proto::PostCommitEvaluation {
                    committed_response: Some(ProstStruct {
                        fields: committed_response,
                    }),
                },
            )),
            principal: [
                ("subject".to_string(), "operator-subject".to_string()),
                ("sandbox_id".to_string(), "sandbox-update-id".to_string()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }
    }

    fn global_setting_post_commit_evaluation() -> InterceptorEvaluation {
        let committed_response = [(
            "settingsRevision".to_string(),
            ProstValue {
                kind: Some(Kind::NumberValue(7.0)),
            },
        )]
        .into_iter()
        .collect();

        InterceptorEvaluation {
            binding_id: "config-policy-post-commit".to_string(),
            method: "UpdateConfig".to_string(),
            phase: Some(crate::proto::interceptor_evaluation::Phase::PostCommit(
                crate::proto::PostCommitEvaluation {
                    committed_response: Some(ProstStruct {
                        fields: committed_response,
                    }),
                },
            )),
            principal: [("subject".to_string(), "operator-subject".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn post_commit_passes_through() {
        let service = service();
        let result = service
            .evaluate(Request::new(post_commit_evaluation()))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn update_config_post_commit_passes_through() {
        let service = service();
        let result = service
            .evaluate(Request::new(update_config_post_commit_evaluation()))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn global_setting_post_commit_passes_through() {
        let service = service();
        let result = service
            .evaluate(Request::new(global_setting_post_commit_evaluation()))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn unmatched_evaluation_passes_through() {
        let service = service();
        let evaluation = InterceptorEvaluation {
            method: "Health".to_string(),
            phase: Some(crate::proto::interceptor_evaluation::Phase::Validate(
                crate::proto::ValidateEvaluation::default(),
            )),
            ..Default::default()
        };

        let result = service
            .evaluate(Request::new(evaluation))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
    }

    #[test]
    fn jwt_verify_none_when_no_operation() {
        let (_, vk) = test_keypair();
        let eval = InterceptorEvaluation::default();
        assert!(verify_provenance_jwt_from_eval(&vk, &eval).is_none());
    }

    #[test]
    fn jwt_verify_none_when_annotations_absent() {
        let (_, vk) = test_keypair();
        let eval = eval_with_annotations(vec![]);
        assert!(verify_provenance_jwt_from_eval(&vk, &eval).is_none());
    }

    #[test]
    fn jwt_verify_some_when_valid() {
        let (sk, vk) = test_keypair();
        let correlation_id = "corr-abc";
        let policy_digest = "sha256-xyz";
        let jwt = mint_test_jwt(&sk, "test-kid", correlation_id, policy_digest, None);

        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/correlation-id", correlation_id),
            ("apf.nvidia.com/provenance-token", &jwt),
            ("apf.nvidia.com/document-digest", policy_digest),
        ]);
        assert!(verify_provenance_jwt_from_eval(&vk, &eval).is_some());
    }

    #[test]
    fn jwt_verify_none_when_wrong_key() {
        let (sk, _) = test_keypair();
        let (_, other_vk) = test_keypair();
        let correlation_id = "corr-abc";
        let policy_digest = "sha256-xyz";
        let jwt = mint_test_jwt(&sk, "test-kid", correlation_id, policy_digest, None);

        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/correlation-id", correlation_id),
            ("apf.nvidia.com/provenance-token", &jwt),
            ("apf.nvidia.com/document-digest", policy_digest),
        ]);
        assert!(verify_provenance_jwt_from_eval(&other_vk, &eval).is_none());
    }

    #[test]
    fn jwt_verify_none_when_jti_tampered() {
        let (sk, vk) = test_keypair();
        let policy_digest = "sha256-xyz";
        let jwt = mint_test_jwt(&sk, "test-kid", "real-jti", policy_digest, None);

        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/correlation-id", "tampered-jti"),
            ("apf.nvidia.com/provenance-token", &jwt),
            ("apf.nvidia.com/document-digest", policy_digest),
        ]);
        assert!(verify_provenance_jwt_from_eval(&vk, &eval).is_none());
    }

    #[test]
    fn jwt_verify_none_when_digest_tampered() {
        let (sk, vk) = test_keypair();
        let correlation_id = "corr-abc";
        let jwt = mint_test_jwt(&sk, "test-kid", correlation_id, "real-digest", None);

        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/correlation-id", correlation_id),
            ("apf.nvidia.com/provenance-token", &jwt),
            ("apf.nvidia.com/document-digest", "tampered-digest"),
        ]);
        assert!(verify_provenance_jwt_from_eval(&vk, &eval).is_none());
    }

    #[test]
    fn jwt_verify_none_when_expired() {
        let (sk, vk) = test_keypair();
        let correlation_id = "corr-abc";
        let policy_digest = "sha256-xyz";
        // exp=1 is in 1970, guaranteed expired.
        let jwt = mint_test_jwt(&sk, "test-kid", correlation_id, policy_digest, Some(1));

        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/correlation-id", correlation_id),
            ("apf.nvidia.com/provenance-token", &jwt),
            ("apf.nvidia.com/document-digest", policy_digest),
        ]);
        assert!(verify_provenance_jwt_from_eval(&vk, &eval).is_none());
    }

    #[test]
    fn jwt_verify_some_when_no_exp() {
        let (sk, vk) = test_keypair();
        let correlation_id = "corr-abc";
        let policy_digest = "sha256-xyz";
        let jwt = mint_test_jwt(&sk, "test-kid", correlation_id, policy_digest, None);

        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/correlation-id", correlation_id),
            ("apf.nvidia.com/provenance-token", &jwt),
            ("apf.nvidia.com/document-digest", policy_digest),
        ]);
        assert!(verify_provenance_jwt_from_eval(&vk, &eval).is_some());
    }

    #[test]
    fn jwt_claims_carry_spec_digest() {
        let (sk, vk) = test_keypair();
        let correlation_id = "corr-spec";
        let policy_digest = "sha256-pol";
        let spec_digest = "cafebabe00";
        let jwt = mint_test_jwt_with_spec_digest(
            &sk,
            "test-kid",
            correlation_id,
            policy_digest,
            None,
            spec_digest,
        );

        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/correlation-id", correlation_id),
            ("apf.nvidia.com/provenance-token", &jwt),
            ("apf.nvidia.com/document-digest", policy_digest),
        ]);
        let claims = verify_provenance_jwt_from_eval(&vk, &eval).expect("should verify");
        assert_eq!(claims.apf_spec_digest, spec_digest);
    }

    fn eval_with_method_and_fields(
        method: &str,
        fields: Vec<(&str, &str)>,
    ) -> InterceptorEvaluation {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        let struct_fields: BTreeMap<String, ProstValue> = fields
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    ProstValue {
                        kind: Some(Kind::StringValue(v.to_string())),
                    },
                )
            })
            .collect();
        InterceptorEvaluation {
            method: method.to_string(),
            phase: Some(Phase::Validate(ValidateEvaluation {
                proposed_operation: Some(ProstStruct {
                    fields: struct_fields,
                }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn operation_has_annotations_true_when_map_present() {
        let eval = eval_with_annotations(vec![("apf.nvidia.com/x", "1")]);
        assert!(operation_has_annotations(&eval));
    }

    #[test]
    fn operation_has_annotations_false_when_absent() {
        let eval = eval_with_method_and_fields("CreateSandbox", vec![("name", "s1")]);
        assert!(!operation_has_annotations(&eval));
    }

    #[tokio::test]
    async fn policy_analysis_agent_authored_is_denied() {
        let svc = service();
        let eval = eval_with_method_and_fields(
            "SubmitPolicyAnalysis",
            vec![("analysisMode", "agent_authored")],
        );
        let result = svc
            .handle_policy_analysis_verify(eval)
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn policy_analysis_mechanistic_is_allowed() {
        let svc = service();
        let eval = eval_with_method_and_fields(
            "SubmitPolicyAnalysis",
            vec![("analysisMode", "mechanistic")],
        );
        let result = svc
            .handle_policy_analysis_verify(eval)
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn approve_draft_chunk_is_denied() {
        let svc = service();
        let eval = eval_with_method_and_fields("ApproveDraftChunk", vec![]);
        let result = svc
            .handle_draft_chunk_approve_deny(eval, "ApproveDraftChunk")
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn approve_all_draft_chunks_is_denied() {
        let svc = service();
        let eval = eval_with_method_and_fields("ApproveAllDraftChunks", vec![]);
        let result = svc
            .handle_draft_chunk_approve_deny(eval, "ApproveAllDraftChunks")
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    #[test]
    fn deny_with_context_populates_log_annotations() {
        let result = deny_with_context("reason", "corr-123", "sha256:abc", "binding-1");
        assert!(!result.allowed);
        assert_eq!(result.reason, "reason");
        assert_eq!(
            result
                .log_annotations
                .get("apf.nvidia.com/correlation-id")
                .map(String::as_str),
            Some("corr-123")
        );
        assert_eq!(
            result
                .log_annotations
                .get("apf.nvidia.com/document-digest")
                .map(String::as_str),
            Some("sha256:abc")
        );
        assert_eq!(
            result
                .log_annotations
                .get("apf.nvidia.com/binding-id")
                .map(String::as_str),
            Some("binding-1")
        );
    }

    #[test]
    fn deny_with_context_skips_empty_fields() {
        let result = deny_with_context("reason", "", "", "");
        assert!(!result.allowed);
        assert!(result.log_annotations.is_empty());
    }

    #[test]
    fn spec_digest_stable_with_all_fields() {
        let obj = serde_json::json!({
            "spec": {
                "policy": {
                    "filesystem": { "include_workdir": true, "read_only": ["/etc"], "read_write": [] },
                    "landlock": { "compatibility": "best_effort" },
                    "process": { "run_as_user": "nobody", "run_as_group": "nogroup" },
                    "network_policies": {}
                }
            }
        });
        let d1 = compute_spec_digest_from_op(&obj);
        let d2 = compute_spec_digest_from_op(&obj);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn spec_digest_empty_spec_is_valid_hash() {
        let obj = serde_json::json!({ "spec": {} });
        let digest = compute_spec_digest_from_op(&obj);
        assert_eq!(digest.len(), 64);
    }
}
