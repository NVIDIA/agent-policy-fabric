// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// GatewayInterceptor service implementation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::reconciler;
use apf_openshell_auth::protocol::{ExtensionFamily, validate_gateway_metadata};
use apf_openshell_auth::{
    Authenticated, AuthenticatedCaller, AuthenticationMode, AuthorizationFailure,
    ExtensionAuthVerifier, ExtensionCallerKind,
};
use apf_policy_client::PolicyClientHandle;
use ed25519_dalek::VerifyingKey;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::audit::{AdmissionPhase, AdmissionRecord, InterceptorAudit, Outcome};

/// The policy a decision was made under. The two are read together so a
/// hot-swap cannot pair one policy's digest with another's revision.
#[derive(Clone, Copy)]
struct PolicyIdentity<'a> {
    digest: &'a str,
    revision: Option<u64>,
}
use crate::bindings;
use crate::context;
use crate::driver_config;
use crate::patches::{self, PatchError};
use crate::proto::{
    DescribeRequest, GatewayInterceptor, GatewayInterceptorServer, InterceptorEvaluation,
    InterceptorManifest, InterceptorResult, ProviderProfileSnapshot,
    ProviderProfileSnapshotRequest, interceptor_evaluation,
};
use apf_proto::json as util;
use apf_proto::spec_digest::{canonical_json_digest, provider_profile_to_json};

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
    /// Where admission decisions are recorded.
    pub audit: InterceptorAudit,
    /// The OpenShell gateway's configured compute driver (e.g. `"podman"`,
    /// `"kubernetes"`). A caller-supplied driver-config mount is admitted only
    /// when its single driver key equals this value. Empty ⇒ no driver config
    /// can be admitted (every present driver config is denied).
    pub gateway_compute_driver: String,
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
        // Attached here rather than by the caller: the verifier refuses
        // credentials before any RPC runs, so a listener whose verifier has no
        // sink records nothing and fails silently. Both halves are in scope,
        // so there is no reason to let them be wired separately.
        let verifier = verifier.with_audit(config.audit.component());
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

    /// Resolve the provider profiles the current bundle manages, keyed by ID.
    ///
    /// Governance checks below compare an incoming profile's `id` and content
    /// against this map. Identities must come from resolved profiles, not raw
    /// document names — a bundle that publishes profiles only as the atomic
    /// `ProviderProfileSet` aggregate (no per-profile documents) would
    /// otherwise expose just the literal name `"default"`.
    async fn bundle_provider_profiles(
        &self,
    ) -> Result<
        std::collections::HashMap<String, crate::proto::openshell::v1::ProviderProfile>,
        String,
    > {
        let mut policy_service = self.policy_service.clone();
        let documents = reconciler::fetch_provider_profile_documents(&mut policy_service).await?;
        let profiles = reconciler::resolve_provider_profiles(&documents)?;
        Ok(profiles.into_iter().map(|p| (p.id.clone(), p)).collect())
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<(), AuthorizationFailure> {
        // Every GatewayInterceptor RPC is called exclusively by the OpenShell
        // gateway at admission time — there is no supervisor caller on this surface.
        let outcome = self
            .authentication
            .authorize(request, &[ExtensionCallerKind::Gateway])
            .map(|_| ());
        if let Err(failure) = outcome {
            // The caller kind only exists on the not-allowed branch; on the
            // unauthenticated one nothing was established to name.
            let caller_kind = request
                .extensions()
                .get::<AuthenticatedCaller>()
                .map(AuthenticatedCaller::kind);
            if let Err(e) = apf_openshell_auth::audit::emit_authorization_failure(
                &self.config.audit.component(),
                failure,
                caller_kind,
            ) {
                warn!(error = %e, "audit emission failed for extension authorization");
            }
        }
        outcome
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
    /// 0 when the token carries no readable version — absent, non-numeric, or
    /// an explicit zero. The anti-rollback floor, not a revision.
    pub apf_version: u64,
    pub apf_spec_digest: String,
    #[allow(dead_code)]
    pub apf_bundle_id: String,
    /// Hex-encoded `DriverConfigPolicy` protobuf — the signed driver-config
    /// allowlist for this sandbox policy. `None` when the policy carries none.
    pub apf_driver_config: Option<String>,
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
        apf_version: payload["apf/version"].as_u64().unwrap_or(0),
        apf_document_digest: payload["apf/document-digest"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        apf_spec_digest: payload["apf/spec-digest"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        apf_bundle_id: payload["apf/bundle-id"].as_str().unwrap_or("").to_string(),
        apf_driver_config: payload["apf/driver-config"].as_str().map(str::to_string),
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

/// Report whether an `UpdateConfig` operation carries merge operations.
///
/// Both spellings: proto3 JSON emits `mergeOperations`, but a producer using
/// `preserve_proto_field_names` emits `merge_operations`, and the sibling
/// `settingKey` checks already accept both. Recognising only one let a caller
/// present merge operations that neither the settings-only classifier nor the
/// direct-mutation denial saw.
fn merge_operations_present(op_json: &serde_json::Value) -> bool {
    ["mergeOperations", "merge_operations"].iter().any(|k| {
        op_json[*k]
            .as_array()
            .is_some_and(|entries| !entries.is_empty())
    })
}

/// Report whether an `UpdateConfig` operation is settings-only (a `settingKey`
/// with no `policy` or `mergeOperations`). Settings-only updates skip policy
/// patch injection at `MODIFY_OPERATION` and must be recognized the same way
/// at `VALIDATE`, or they get denied for a provenance token that was never
/// injected in the first place.
fn is_settings_only_update_config(op_json: &serde_json::Value) -> bool {
    let has_policy = !op_json["policy"].is_null();
    let has_merge_ops = merge_operations_present(op_json);
    let setting_key = op_json["settingKey"]
        .as_str()
        .or_else(|| op_json["setting_key"].as_str());
    setting_key.is_some() && !has_policy && !has_merge_ops
}

/// Report whether an `UpdateConfig` operation touches `proposal_approval_mode`.
fn sets_auto_approval(op_json: &serde_json::Value) -> bool {
    let setting_key = op_json["settingKey"]
        .as_str()
        .or_else(|| op_json["setting_key"].as_str());
    // Keyed on the setting, not its value. `settingValue` is a four-variant
    // oneof, so matching `stringValue == "auto"` inspects one arm and a
    // `bytesValue` or `boolValue` walks past. APF owns approval mode, so any
    // caller attempt to set it is refused regardless of the value.
    setting_key == Some("proposal_approval_mode")
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

/// Compare an incoming provider-profile operation value against the bundle's
/// own profile for the same ID, using the identical canonical proto3-JSON
/// representation the gateway itself reconstructs — not a caller-supplied
/// annotation, which this RPC has no ModifyOperation phase to let APF stamp.
///
/// `resourceVersion` and `annotations` are storage/runtime metadata, not bundle
/// content — the bundle's copy never carries them (they default to the
/// omitted-from-JSON zero/empty value), so they are stripped from the incoming
/// side before comparing.
fn provider_profile_matches_bundle(
    bundle_profile: &crate::proto::openshell::v1::ProviderProfile,
    incoming: &serde_json::Value,
) -> bool {
    let mut incoming = incoming.clone();
    if let Some(object) = incoming.as_object_mut() {
        object.remove("resourceVersion");
        object.remove("annotations");
    }
    canonical_json_digest(&provider_profile_to_json(bundle_profile))
        == canonical_json_digest(&incoming)
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

/// Stands in for the policy identity when no digest has been proven — either no
/// token was verified, or one verified and its claims would not parse. Naming
/// the response's digest instead would assert an identity nothing proved.
const UNVERIFIED_POLICY: &str = "unverified";

impl GatewayInterceptorService {
    /// Record an admission outcome for the CreateSandbox path.
    ///
    /// Records the admission decisions this handler reaches. Not recorded: a
    /// malformed request, an unreachable policy service, and a projection that
    /// passes its digest check but will not decode or re-serialise — the last
    /// is a policy integrity failure rather than infrastructure, and is a
    /// catalogue gap rather than a deliberate omission. Caller authentication
    /// is refused earlier still.
    ///
    /// `correlation_id` and the policy identity are passed rather than read
    /// from `ctx` or the response: once a token verifies, the sandbox
    /// annotation and VALIDATE both key on its `jti`, and the digest and
    /// version it signs are the only ones anything has proven.
    fn record_admission(
        &self,
        ctx: &context::SandboxReviewContext,
        correlation_id: &str,
        policy: PolicyIdentity<'_>,
        reason_code: &str,
        outcome: Outcome<'_>,
        applied: apf_audit::Effects,
    ) {
        let PolicyIdentity {
            digest: policy_digest,
            revision: policy_revision,
        } = policy;
        if let Err(e) = self.config.audit.emit_admission(&AdmissionRecord {
            outcome,
            phase: AdmissionPhase::Injection,
            verb: "interceptor.create_sandbox",
            reason_code,
            resource_kind: &self.config.document_kind,
            resource_id: &ctx.sandbox_id,
            sandbox_id: &ctx.sandbox_id,
            user_subject: &ctx.user_subject,
            agent_type: &ctx.agent_type,
            correlation_id,
            policy_digest,
            policy_revision,
            applied,
        }) {
            warn!(error = %e, "audit emission failed for sandbox admission");
        }
    }

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
            self.record_admission(
                &ctx,
                &ctx.correlation_id,
                // Nothing is proven yet, so the record names no policy rather
                // than one the response merely asserted.
                PolicyIdentity {
                    digest: UNVERIFIED_POLICY,
                    revision: None,
                },
                "interceptor.inject_denied.no_provenance_token",
                Outcome::Refused {
                    detail: "policy service vended no provenance token",
                },
                apf_audit::Effects::default(),
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
            self.record_admission(
                &ctx,
                &ctx.correlation_id,
                // Nothing is proven yet, so the record names no policy rather
                // than one the response merely asserted.
                PolicyIdentity {
                    digest: UNVERIFIED_POLICY,
                    revision: None,
                },
                "interceptor.inject_denied.invalid_jwt",
                Outcome::Refused {
                    detail: "provenance JWT invalid",
                },
                apf_audit::Effects::default(),
            );
            return Ok(Response::new(deny_with_context(
                "provenance JWT invalid",
                &ctx.correlation_id,
                &policy_digest,
                &eval.binding_id,
            )));
        }

        // From the signed token, not the response: a response can name a
        // different digest and version than the token it carries.
        //
        // The signature verified above, so unreadable claims mean the policy
        // service minted a token whose contract is broken. Admitting on that
        // would inject a policy nothing can name, and would record it as
        // unverified — indistinguishable from a refusal that never had a token.
        let Some(verified) = patches::extract_provenance_claims(&provenance_token).filter(|c| {
            // `jti` becomes the sandbox annotation and the audit correlation
            // id; empty, the record joins to nothing and VALIDATE compares
            // empty to empty. `sub` is the signer identity the annotation
            // carries.
            !c.jti.is_empty() && !c.sub.is_empty() && !c.apf_document_digest.is_empty()
        }) else {
            // Names the missing claim: an empty `sub` means the policy service
            // was started with an empty --document-key-id, which otherwise
            // reads as every token being malformed.
            let detail = match patches::extract_provenance_claims(&provenance_token) {
                None => "provenance JWT claims unreadable",
                Some(c) if c.jti.is_empty() => "provenance JWT carries no jti",
                Some(c) if c.sub.is_empty() => "provenance JWT carries no signer identity",
                Some(_) => "provenance JWT carries no document digest",
            };
            warn!(
                correlation_id = %ctx.correlation_id,
                %detail,
                "CreateSandbox MODIFY_OPERATION denied: provenance JWT claims unusable"
            );
            self.record_admission(
                &ctx,
                &ctx.correlation_id,
                PolicyIdentity {
                    digest: UNVERIFIED_POLICY,
                    revision: None,
                },
                "interceptor.inject_denied.invalid_jwt",
                Outcome::Refused { detail },
                apf_audit::Effects::default(),
            );
            return Ok(Response::new(deny_with_context(
                detail,
                &ctx.correlation_id,
                &policy_digest,
                &eval.binding_id,
            )));
        };
        // The response is unsigned. Letting it disagree with the token would put
        // one policy in the record and another in the sandbox annotation.
        // VALIDATE re-checks the digest but never the version, so a
        // version-only disagreement would otherwise reach a running sandbox.
        if policy_digest != verified.apf_document_digest || policy_version != verified.apf_version {
            warn!(
                correlation_id = %ctx.correlation_id,
                "CreateSandbox MODIFY_OPERATION denied: response policy identity disagrees with the signed token"
            );
            // `ctx`, matching what `deny_with_context` writes below and the
            // sibling refusals. On this path the two digests disagree by
            // construction, so the correlation id is the only field that can
            // join the record to the denial it accompanies.
            self.record_admission(
                &ctx,
                &ctx.correlation_id,
                PolicyIdentity {
                    digest: &verified.apf_document_digest,
                    revision: Some(verified.apf_version).filter(|v| *v != 0),
                },
                "interceptor.inject_denied.policy_identity_mismatch",
                Outcome::Refused {
                    detail: "response policy identity disagrees with the signed token",
                },
                apf_audit::Effects::default(),
            );
            return Ok(Response::new(deny_with_context(
                "response policy identity disagrees with the signed token",
                &ctx.correlation_id,
                &policy_digest,
                &eval.binding_id,
            )));
        }

        let verified_digest = verified.apf_document_digest.clone();
        // 0 is the anti-rollback floor, not a revision: recorded as absent
        // rather than as a fact the token never carried.
        let verified_version = Some(verified.apf_version).filter(|v| *v != 0);

        let mut patch_list = match patches::sandbox_policy_patches(&doc) {
            // Unreachable while the empty-token check above precedes this;
            // kept so a future `PatchError` change cannot turn a refusal into
            // an internal error.
            Err(PatchError::UnsignedProjection) => {
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "CreateSandbox MODIFY_OPERATION denied: policy projection has no provenance token"
                );
                self.record_admission(
                    &ctx,
                    &ctx.correlation_id,
                    PolicyIdentity {
                        digest: &verified_digest,
                        revision: verified_version,
                    },
                    "interceptor.inject_denied.unsigned_projection",
                    Outcome::Refused {
                        detail: "policy projection has no provenance token",
                    },
                    apf_audit::Effects::default(),
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
                self.record_admission(
                    &ctx,
                    &ctx.correlation_id,
                    PolicyIdentity {
                        digest: &verified_digest,
                        revision: verified_version,
                    },
                    "interceptor.inject_denied.body_digest_mismatch",
                    Outcome::Refused {
                        detail: "policy body digest mismatch",
                    },
                    apf_audit::Effects::default(),
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

        // From the verified claims; the handler refused above if they were absent.
        // The same claims the audit record used, so the annotation and the
        // record cannot name different policies.
        let (correlation_id, signer_identity, bundle_id) =
            (verified.jti, verified.sub, verified.apf_bundle_id);

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

        // The JWT-derived id, not `ctx`: it is what lands in the sandbox
        // annotation and what VALIDATE reads back, so a record keyed on
        // anything else cannot be joined to the sandbox it admitted.
        // What the injection changed. `policy_injected` alone says a policy
        // went in; this says which spec paths it rewrote — including the
        // `/annotations/...` provenance stamps. Paths and ops only: the patch
        // values carry the policy itself.
        let applied = apf_audit::Effects {
            patch_count: Some(patch_list.len() as u64),
            patches: patch_list
                .iter()
                .filter_map(|p| {
                    // An op the record cannot name is omitted rather than
                    // guessed at; `patch_count` stays exact either way.
                    let op = match p.op.as_str() {
                        "add" => apf_audit::PatchOp::Add,
                        "replace" => apf_audit::PatchOp::Replace,
                        "remove" => apf_audit::PatchOp::Remove,
                        _ => return None,
                    };
                    Some(apf_audit::PatchRecord::new(
                        p.path.chars().take(256).collect::<String>(),
                        op,
                    ))
                })
                .collect(),
            ..apf_audit::Effects::default()
        };

        self.record_admission(
            &ctx,
            &correlation_id,
            PolicyIdentity {
                digest: &verified_digest,
                revision: verified_version,
            },
            "interceptor.policy_injected",
            Outcome::Allowed,
            applied,
        );

        Ok(Response::new(InterceptorResult {
            allowed: true,
            patches: patch_list,
            log_annotations,
            ..Default::default()
        }))
    }

    /// Record a VALIDATE outcome for the CreateSandbox path.
    ///
    /// The revision comes from the verified token when there is one; the
    /// annotation carrying it is caller-presented at this phase.
    #[allow(clippy::too_many_arguments)]
    fn record_validation(
        &self,
        eval: &InterceptorEvaluation,
        sandbox_id: &str,
        agent_type: &str,
        correlation_id: &str,
        policy: PolicyIdentity<'_>,
        reason_code: &str,
        outcome: Outcome<'_>,
    ) {
        let PolicyIdentity {
            digest: policy_digest,
            revision: policy_revision,
        } = policy;
        if let Err(e) = self.config.audit.emit_admission(&AdmissionRecord {
            outcome,
            phase: AdmissionPhase::Validation,
            verb: "interceptor.validate_sandbox",
            reason_code,
            resource_kind: &self.config.document_kind,
            resource_id: sandbox_id,
            sandbox_id,
            user_subject: eval.principal.get("subject").map_or("", String::as_str),
            agent_type,
            correlation_id,
            policy_digest,
            policy_revision,
            applied: apf_audit::Effects::default(),
        }) {
            warn!(error = %e, "audit emission failed for sandbox validation");
        }
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
        let agent_type = op_json["labels"]["agent-type"].as_str().unwrap_or("");

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
            self.record_validation(
                &eval,
                sandbox_id,
                agent_type,
                correlation_id,
                PolicyIdentity {
                    digest: UNVERIFIED_POLICY,
                    revision: None,
                },
                if token_present {
                    "interceptor.validate_denied.provenance_invalid"
                } else {
                    "interceptor.validate_denied.provenance_missing"
                },
                Outcome::Refused {
                    detail: deny_message,
                },
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
                self.record_validation(
                    &eval,
                    sandbox_id,
                    agent_type,
                    correlation_id,
                    PolicyIdentity {
                        digest: &claims.apf_document_digest,
                        revision: Some(claims.apf_version).filter(|v| *v != 0),
                    },
                    "interceptor.validate_denied.spec_digest_mismatch",
                    Outcome::Refused {
                        detail: "sandbox spec changed between inject and validate",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    REASON,
                    correlation_id,
                    policy_digest,
                    &eval.binding_id,
                )));
            }
        }

        // Driver-config admission (harness mounts). Evaluated here on the final,
        // post-injection request, so a mount slipped in after inject is still
        // caught. Deny-by-default: until the signed SandboxPolicy carries a
        // driverConfig allowlist, any present driver config is refused.
        let driver_cfg = context::driver_config(&op_json)
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        // The allowlist rides the signature-verified provenance JWT (the native
        // projection cannot carry it); absent/unparsable ⇒ deny-by-default.
        let driver_rule = driver_config::decode_rule(claims.apf_driver_config.as_deref());
        let driver_decision = driver_config::evaluate(
            driver_rule.as_ref(),
            &driver_cfg,
            context::is_template_based(&op_json),
            &context::principal_roles(&eval),
            &self.config.gateway_compute_driver,
        );
        if !driver_decision.allowed {
            warn!(
                correlation_id,
                sandbox_id,
                reason = driver_decision.reason_code,
                "CreateSandbox VALIDATE denied: {}",
                driver_decision.detail
            );
            self.record_validation(
                &eval,
                sandbox_id,
                agent_type,
                correlation_id,
                PolicyIdentity {
                    digest: &claims.apf_document_digest,
                    revision: Some(claims.apf_version).filter(|v| *v != 0),
                },
                driver_decision.reason_code,
                Outcome::Refused {
                    detail: &driver_decision.detail,
                },
            );
            return Ok(Response::new(deny_with_context(
                &driver_decision.detail,
                correlation_id,
                policy_digest,
                &eval.binding_id,
            )));
        }

        info!(correlation_id, sandbox_id, "CreateSandbox VALIDATE allowed");
        // Distinct codes: the spec-digest comparison above is skipped when the
        // token carries no spec digest, and a record claiming the TOCTOU check
        // passed when it never ran would assert more than the phase proved.
        self.record_validation(
            &eval,
            sandbox_id,
            agent_type,
            correlation_id,
            PolicyIdentity {
                digest: &claims.apf_document_digest,
                revision: Some(claims.apf_version).filter(|v| *v != 0),
            },
            if claims.apf_spec_digest.is_empty() {
                "interceptor.validate_allowed.no_spec_digest"
            } else {
                "interceptor.validate_allowed"
            },
            Outcome::Allowed,
        );
        Ok(Response::new(allow()))
    }

    /// Record a governance outcome for the UpdateConfig path.
    ///
    /// The resource is the policy document, not a sandbox — these operations
    /// govern configuration, so there is no session to attribute them to.
    #[allow(clippy::too_many_arguments)]
    fn record_governance(
        &self,
        ctx: &context::ProviderReviewContext,
        correlation_id: &str,
        policy: PolicyIdentity<'_>,
        reason_code: &str,
        outcome: Outcome<'_>,
    ) {
        self.record_governance_event(
            "interceptor.update_config",
            &self.config.document_kind,
            &self.config.document_name,
            &ctx.user_subject,
            correlation_id,
            policy,
            reason_code,
            outcome,
        );
    }

    /// The general form: provider and proposal governance name their own verb
    /// and resource, while config governance above keeps its policy document.
    #[allow(clippy::too_many_arguments)]
    fn record_governance_event(
        &self,
        verb: &str,
        resource_kind: &str,
        resource_id: &str,
        user_subject: &str,
        correlation_id: &str,
        policy: PolicyIdentity<'_>,
        reason_code: &str,
        outcome: Outcome<'_>,
    ) {
        let PolicyIdentity {
            digest: policy_digest,
            revision: policy_revision,
        } = policy;
        if let Err(e) = self.config.audit.emit_admission(&AdmissionRecord {
            outcome,
            phase: AdmissionPhase::Governance,
            verb,
            reason_code,
            resource_kind,
            resource_id,
            sandbox_id: "",
            user_subject,
            agent_type: "",
            correlation_id,
            policy_digest,
            policy_revision,
            applied: apf_audit::Effects::default(),
        }) {
            warn!(error = %e, "audit emission failed for governance decision");
        }
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
        let has_merge_ops = merge_operations_present(&op_json);
        let sets_auto_approval = sets_auto_approval(&op_json);
        // Settings-only updates (setting_key present, no policy/mergeOps) pass
        // through without modification. Injecting policy patches into a settings
        // request would conflict with the mutually-exclusive proto fields.
        if is_settings_only_update_config(&op_json) {
            if sets_auto_approval {
                let ctx = context::extract_provider(&eval);
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "UpdateConfig MODIFY_OPERATION denied: approval-mode change via settings"
                );
                self.record_governance(
                    &ctx,
                    &ctx.correlation_id,
                    PolicyIdentity {
                        digest: UNVERIFIED_POLICY,
                        revision: None,
                    },
                    "interceptor.govern_denied.approval_mode_change",
                    Outcome::Refused {
                        detail: "approval mode is managed by APF",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    "approval mode is managed by APF",
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
                "approval mode is managed by APF"
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
            // The detail names every attempt, not just the one the reason code
            // is chosen for: a request carrying both a policy body and an
            // auto-approval setting would otherwise record only the latter, and
            // the caller picks which by adding a field.
            let attempted = format!(
                "{reason} (policy: {has_policy}, merge_operations: {has_merge_ops}, auto_approval: {sets_auto_approval})"
            );
            self.record_governance(
                &ctx,
                &ctx.correlation_id,
                PolicyIdentity {
                    digest: UNVERIFIED_POLICY,
                    revision: None,
                },
                if sets_auto_approval {
                    "interceptor.govern_denied.approval_mode_change"
                } else {
                    "interceptor.govern_denied.direct_policy_mutation"
                },
                Outcome::Refused { detail: &attempted },
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
                self.record_governance(
                    &ctx,
                    &ctx.correlation_id,
                    PolicyIdentity {
                        digest: UNVERIFIED_POLICY,
                        revision: None,
                    },
                    "interceptor.govern_denied.body_digest_mismatch",
                    Outcome::Refused {
                        detail: "policy body does not hash to the digest in its own token",
                    },
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

        // Unreachable: `sandbox_policy_patches` above returns
        // `UnsignedProjection` on an empty token, so that branch fires first.
        // Kept so a reordering there cannot silently drop the check.
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

        // The body is checked against the token's claim, never against the
        // response's digest, so the two can disagree — and then the record and
        // the annotation name a policy that was not the one injected. Refusing
        // mirrors the sandbox path; VALIDATE denies this case later anyway, so
        // this only moves an existing refusal early enough to be recorded.
        if let Some(claims) = patches::extract_provenance_claims(&provenance_token)
            && (policy_digest != claims.apf_document_digest || policy_version != claims.apf_version)
        {
            warn!(
                correlation_id = %ctx.correlation_id,
                "UpdateConfig MODIFY_OPERATION denied: response policy identity disagrees with the token"
            );
            self.record_governance(
                &ctx,
                &ctx.correlation_id,
                PolicyIdentity {
                    digest: &claims.apf_document_digest,
                    revision: Some(claims.apf_version).filter(|v| *v != 0),
                },
                "interceptor.govern_denied.policy_identity_mismatch",
                Outcome::Refused {
                    detail: "response policy identity disagrees with the token",
                },
            );
            return Ok(Response::new(deny_with_context(
                "response policy identity disagrees with the token",
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

        // The higher-blast-radius injection of the two: this rewrites the
        // governing policy for the whole deployment, not one sandbox.
        //
        // The digest is the response's. Unlike the sandbox path, this handler
        // never verifies the provenance token, so the record states what was
        // injected without claiming anything proved it; the `.unverified`
        // reason-code suffix is the marker for that.
        self.record_governance(
            &ctx,
            // The same value that lands in the config annotations and that
            // VALIDATE reads back — the jti when claims parse, ctx otherwise.
            &correlation_id,
            PolicyIdentity {
                digest: &policy_digest,
                revision: Some(policy_version).filter(|v| *v != 0),
            },
            // A distinct code, not the sandbox path's: this handler never
            // verifies the token, so the digest names what was injected without
            // anything having proved it. Reusing `policy_injected` would make
            // the two indistinguishable to a consumer.
            "interceptor.policy_injected.unverified",
            Outcome::Allowed,
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

        // Settings-only updates never get a provenance-token annotation at
        // MODIFY_OPERATION (see handle_config_refresh), so they must be
        // recognized and passed through here too, rather than denied for a
        // token that was never injected in the first place.
        // Read before the settings-only branch: these refusals are about an
        // injection, and the annotation carries the id that identifies it.
        let injected_correlation_id = op_json["annotations"]["apf.nvidia.com/correlation-id"]
            .as_str()
            .unwrap_or("");
        let provider_ctx = context::extract_provider(&eval);
        // One id for the record and the denial both. Resolving it in two places
        // let them diverge: the record joined to the injection, the denial to a
        // fresh UUID.
        let refusal_correlation_id = if injected_correlation_id.is_empty() {
            provider_ctx.correlation_id.as_str()
        } else {
            injected_correlation_id
        };

        // A request that was injected at MODIFY carries a provenance token. If
        // it now looks settings-only, `/policy` was removed after injection —
        // the classification is recomputed from caller-controlled state at each
        // phase, so deletion reclassifies the request and skips every check
        // below. The actor is whatever holds the operation between phases — a
        // peer interceptor or the gateway — not an ordinary API caller.
        let injected = !op_json["annotations"]["apf.nvidia.com/provenance-token"].is_null();
        if is_settings_only_update_config(&op_json) {
            if injected {
                let ctx = context::extract_provider(&eval);
                warn!(
                    correlation_id = %ctx.correlation_id,
                    "UpdateConfig VALIDATE denied: injected policy removed after injection"
                );
                self.record_governance(
                    &ctx,
                    refusal_correlation_id,
                    PolicyIdentity {
                        digest: UNVERIFIED_POLICY,
                        revision: None,
                    },
                    "interceptor.validate_denied.post_injection_mutation",
                    // Hedged: the annotation is caller-presented and unverified
                    // here, so a fabricated one reaches this branch. What is
                    // certain is the shape, not that an injection occurred.
                    Outcome::Refused {
                        detail: "settings-only request carrying a provenance annotation",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    "config policy integrity check failed",
                    refusal_correlation_id,
                    "",
                    &eval.binding_id,
                )));
            }
            if sets_auto_approval(&op_json) {
                let ctx = context::extract_provider(&eval);
                // The record, the denial and the log all carry the same id, or
                // the refusal cannot be joined to the response that carried it.
                warn!(
                    correlation_id = %refusal_correlation_id,
                    "UpdateConfig VALIDATE denied: approval-mode change via settings"
                );
                self.record_governance(
                    &ctx,
                    refusal_correlation_id,
                    PolicyIdentity {
                        digest: UNVERIFIED_POLICY,
                        revision: None,
                    },
                    "interceptor.validate_denied.approval_mode_change",
                    Outcome::Refused {
                        detail: "approval mode is managed by APF",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    "approval mode is managed by APF",
                    refusal_correlation_id,
                    "",
                    &eval.binding_id,
                )));
            }
            info!("UpdateConfig VALIDATE allowed: settings-only update");
            return Ok(Response::new(allow()));
        }

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
            let recorded_correlation_id = if correlation_id.is_empty() {
                provider_ctx.correlation_id.as_str()
            } else {
                correlation_id
            };
            self.record_governance(
                &provider_ctx,
                recorded_correlation_id,
                PolicyIdentity {
                    digest: UNVERIFIED_POLICY,
                    revision: None,
                },
                if token_present {
                    "interceptor.validate_denied.provenance_invalid"
                } else {
                    "interceptor.validate_denied.provenance_missing"
                },
                Outcome::Refused {
                    detail: deny_message,
                },
            );
            return Ok(Response::new(deny_with_context(
                "config policy integrity check failed",
                recorded_correlation_id,
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
                self.record_governance(
                    &context::extract_provider(&eval),
                    correlation_id,
                    PolicyIdentity {
                        digest: &claims.apf_document_digest,
                        revision: Some(claims.apf_version).filter(|v| *v != 0),
                    },
                    "interceptor.validate_denied.spec_digest_mismatch",
                    Outcome::Refused {
                        detail: "config policy changed between injection and validation",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    "config policy integrity check failed",
                    correlation_id,
                    policy_digest,
                    &eval.binding_id,
                )));
            }
        }

        // The spec digest covers `/policy` only, so a field added beside it
        // between MODIFY and VALIDATE passes both the JWT and the digest check.
        // This is the last phase that can refuse, and the sibling checks that
        // run at MODIFY must run again here.
        let sets_auto_approval = sets_auto_approval(&op_json);
        let has_merge_ops = merge_operations_present(&op_json);
        if sets_auto_approval || has_merge_ops {
            let ctx = context::extract_provider(&eval);
            warn!(
                correlation_id,
                sets_auto_approval,
                "UpdateConfig VALIDATE denied: forbidden field added after injection"
            );
            let attempted = format!(
                "forbidden field added after injection (auto_approval: {sets_auto_approval}, merge_operations: {has_merge_ops})"
            );
            self.record_governance(
                &ctx,
                correlation_id,
                PolicyIdentity {
                    digest: &claims.apf_document_digest,
                    revision: Some(claims.apf_version).filter(|v| *v != 0),
                },
                // One code for "the operation changed after injection", shared
                // with the deletion refusal above; the detail names which
                // field. The approval-mode refusal keeps its own code.
                "interceptor.validate_denied.post_injection_mutation",
                Outcome::Refused { detail: &attempted },
            );
            return Ok(Response::new(deny_with_context(
                "config policy integrity check failed",
                correlation_id,
                policy_digest,
                &eval.binding_id,
            )));
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
        let ctx = context::extract_provider(&eval);
        let unverified = PolicyIdentity {
            digest: UNVERIFIED_POLICY,
            revision: None,
        };
        let bundle_profiles = match self.bundle_provider_profiles().await {
            Ok(profiles) => profiles,
            Err(e) => {
                warn!(error = %e, correlation_id = %ctx.correlation_id, "ImportProviderProfiles VALIDATE: provider-profile set unavailable");
                self.record_governance_event(
                    "interceptor.import_provider_profiles",
                    "openshell.provider_profile",
                    "unresolved",
                    &ctx.user_subject,
                    &ctx.correlation_id,
                    unverified,
                    "interceptor.govern_denied.policy_service_unavailable",
                    Outcome::Refused {
                        detail: "provider profile governance check failed: policy service unavailable",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    "provider profile governance check failed: policy service unavailable",
                    &ctx.correlation_id,
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
            let Some(bundle_profile) = bundle_profiles.get(id) else {
                let correlation_id = uuid::Uuid::new_v4().to_string();
                warn!(
                    profile_id = %id,
                    correlation_id = %correlation_id,
                    "ImportProviderProfiles VALIDATE denied: profile not in bundle"
                );
                let reason = format!("provider profile '{id}' is not managed by the APF bundle");
                self.record_governance_event(
                    "interceptor.import_provider_profiles",
                    "openshell.provider_profile",
                    id,
                    &ctx.user_subject,
                    &correlation_id,
                    unverified,
                    "interceptor.govern_denied.unmanaged_provider_profile",
                    Outcome::Refused { detail: &reason },
                );
                return Ok(Response::new(deny_with_context(
                    &reason,
                    &correlation_id,
                    "",
                    &eval.binding_id,
                )));
            };

            // Compare the incoming profile against the bundle's own copy for this ID,
            // rather than trusting a caller-supplied provenance annotation — this RPC
            // has no ModifyOperation phase for APF to stamp, and the binding applies to
            // any caller, not just the reconciler. A bundle-managed ID with tampered
            // content (weakened enforcement, added endpoints, ...) must still be denied.
            if !provider_profile_matches_bundle(bundle_profile, profile) {
                let correlation_id = uuid::Uuid::new_v4().to_string();
                let reason =
                    format!("provider profile '{id}' content does not match the APF bundle");
                warn!(
                    profile_id = %id,
                    correlation_id = %correlation_id,
                    "ImportProviderProfiles VALIDATE denied: {reason}"
                );
                self.record_governance_event(
                    "interceptor.import_provider_profiles",
                    "openshell.provider_profile",
                    id,
                    &ctx.user_subject,
                    &correlation_id,
                    unverified,
                    "interceptor.govern_denied.profile_content_mismatch",
                    Outcome::Refused { detail: &reason },
                );
                return Ok(Response::new(deny_with_context(
                    &reason,
                    &correlation_id,
                    "",
                    &eval.binding_id,
                )));
            }
        }

        info!("ImportProviderProfiles VALIDATE allowed");
        self.record_governance_event(
            "interceptor.import_provider_profiles",
            "openshell.provider_profile",
            &format!("batch:{}", profiles.len()),
            &ctx.user_subject,
            &ctx.correlation_id,
            unverified,
            "interceptor.provider_profiles_allowed",
            Outcome::Allowed,
        );
        Ok(Response::new(allow()))
    }

    /// Handle `VALIDATE` for `UpdateProviderProfiles`.
    async fn handle_provider_profile_update_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let ctx = context::extract_provider(&eval);
        let unverified = PolicyIdentity {
            digest: UNVERIFIED_POLICY,
            revision: None,
        };
        let bundle_profiles = match self.bundle_provider_profiles().await {
            Ok(profiles) => profiles,
            Err(e) => {
                warn!(error = %e, correlation_id = %ctx.correlation_id, "UpdateProviderProfiles VALIDATE: provider-profile set unavailable");
                self.record_governance_event(
                    "interceptor.update_provider_profiles",
                    "openshell.provider_profile",
                    "unresolved",
                    &ctx.user_subject,
                    &ctx.correlation_id,
                    unverified,
                    "interceptor.govern_denied.policy_service_unavailable",
                    Outcome::Refused {
                        detail: "provider profile governance check failed: policy service unavailable",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    "provider profile governance check failed: policy service unavailable",
                    &ctx.correlation_id,
                    "",
                    &eval.binding_id,
                )));
            }
        };

        let op_json =
            context::operation_struct(&eval).map_or(serde_json::Value::Null, util::struct_to_json);
        let target_id = op_json["id"].as_str().unwrap_or("");
        let Some(bundle_profile) = bundle_profiles.get(target_id) else {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            warn!(
                profile_id = %target_id,
                "UpdateProviderProfiles VALIDATE denied: profile not in bundle"
            );
            let reason = format!("provider profile '{target_id}' is not managed by the APF bundle");
            self.record_governance_event(
                "interceptor.update_provider_profiles",
                "openshell.provider_profile",
                target_id,
                &ctx.user_subject,
                &correlation_id,
                unverified,
                "interceptor.govern_denied.unmanaged_provider_profile",
                Outcome::Refused { detail: &reason },
            );
            return Ok(Response::new(deny_with_context(
                &reason,
                &correlation_id,
                "",
                &eval.binding_id,
            )));
        };

        // As with ImportProviderProfiles: compare the update payload's content
        // against the bundle's own copy for this ID. Bundle-ID membership alone
        // does not prove the payload's content — endpoints, credentials, enforcement
        // mode — actually matches what the bundle says for that ID.
        let incoming_profile = &op_json["profile"]["profile"];
        if !provider_profile_matches_bundle(bundle_profile, incoming_profile) {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            let reason =
                format!("provider profile '{target_id}' content does not match the APF bundle");
            warn!(
                profile_id = %target_id,
                correlation_id = %correlation_id,
                "UpdateProviderProfiles VALIDATE denied: {reason}"
            );
            self.record_governance_event(
                "interceptor.update_provider_profiles",
                "openshell.provider_profile",
                target_id,
                &ctx.user_subject,
                &correlation_id,
                unverified,
                "interceptor.govern_denied.profile_content_mismatch",
                Outcome::Refused { detail: &reason },
            );
            return Ok(Response::new(deny_with_context(
                &reason,
                &correlation_id,
                "",
                &eval.binding_id,
            )));
        }

        info!("UpdateProviderProfiles VALIDATE allowed");
        self.record_governance_event(
            "interceptor.update_provider_profiles",
            "openshell.provider_profile",
            target_id,
            &ctx.user_subject,
            &ctx.correlation_id,
            unverified,
            "interceptor.provider_profiles_allowed",
            Outcome::Allowed,
        );
        Ok(Response::new(allow()))
    }

    /// Handle `VALIDATE` for `DeleteProviderProfile`.
    #[allow(clippy::unused_async)]
    async fn handle_provider_profile_delete_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        Ok(self.deny_provider_governance(
            &eval,
            "delete-provider-profile",
            "delete",
            "interceptor.delete_provider_profile",
            "interceptor.govern_denied.profile_delete",
        ))
    }

    /// Handle `VALIDATE` for `CreateProvider` and `UpdateProvider`.
    #[allow(clippy::too_many_lines)]
    async fn handle_provider_instance_type_verify(
        &self,
        eval: InterceptorEvaluation,
    ) -> Result<Response<InterceptorResult>, Status> {
        let ctx = context::extract_provider(&eval);
        let verb = if eval.method == "UpdateProvider" {
            "interceptor.update_provider"
        } else {
            "interceptor.create_provider"
        };
        let bundle_types = match self.bundle_provider_profiles().await {
            Ok(profiles) => profiles
                .into_keys()
                .collect::<std::collections::HashSet<_>>(),
            Err(e) => {
                warn!(error = %e, correlation_id = %ctx.correlation_id, "Provider VALIDATE: provider-profile set unavailable");
                self.record_governance_event(
                    verb,
                    "openshell.provider",
                    "unresolved",
                    &ctx.user_subject,
                    &ctx.correlation_id,
                    PolicyIdentity {
                        digest: UNVERIFIED_POLICY,
                        revision: None,
                    },
                    "interceptor.govern_denied.policy_service_unavailable",
                    Outcome::Refused {
                        detail: "provider type governance check failed: policy service unavailable",
                    },
                );
                return Ok(Response::new(deny_with_context(
                    "provider type governance check failed: policy service unavailable",
                    &ctx.correlation_id,
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
            let reason = format!("provider type '{provider_type}' is not a bundle-managed profile");
            self.record_governance_event(
                verb,
                "openshell.provider",
                provider_type,
                &ctx.user_subject,
                &correlation_id,
                PolicyIdentity {
                    digest: UNVERIFIED_POLICY,
                    revision: None,
                },
                "interceptor.govern_denied.unmanaged_provider_type",
                Outcome::Refused { detail: &reason },
            );
            return Ok(Response::new(deny_with_context(
                &reason,
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
        self.record_governance_event(
            verb,
            "openshell.provider",
            provider_type,
            &ctx.user_subject,
            &ctx.correlation_id,
            PolicyIdentity {
                digest: UNVERIFIED_POLICY,
                revision: None,
            },
            "interceptor.provider_type_allowed",
            Outcome::Allowed,
        );
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

        let ctx = context::extract_provider(&eval);
        let unverified = PolicyIdentity {
            digest: UNVERIFIED_POLICY,
            revision: None,
        };
        if mode == "agent_authored" {
            let correlation_id = uuid::Uuid::new_v4().to_string();
            let reason =
                "agent-authored policy proposals are not permitted; policy is managed by APF";
            warn!(
                correlation_id = %correlation_id,
                "SubmitPolicyAnalysis VALIDATE denied: agent_authored proposal blocked"
            );
            self.record_governance_event(
                "interceptor.submit_policy_analysis",
                "apf.policy_proposal",
                mode,
                &ctx.user_subject,
                &correlation_id,
                unverified,
                "interceptor.govern_denied.agent_authored_proposal",
                Outcome::Refused { detail: reason },
            );
            return Ok(Response::new(deny_with_context(
                reason,
                &correlation_id,
                "",
                &eval.binding_id,
            )));
        }

        info!("SubmitPolicyAnalysis VALIDATE allowed");
        // Mechanistic proposals pass so denial telemetry can be collected;
        // they are still blocked at approval. The allow is a governance
        // decision too, and must be as visible as the refusal.
        self.record_governance_event(
            "interceptor.submit_policy_analysis",
            "apf.policy_proposal",
            if mode.is_empty() { "unspecified" } else { mode },
            &ctx.user_subject,
            &ctx.correlation_id,
            unverified,
            "interceptor.policy_analysis_allowed",
            Outcome::Allowed,
        );
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
        let (resource_id, verb) = match method {
            "ApproveAllDraftChunks" => (
                "approve-all-draft-chunks",
                "interceptor.approve_all_draft_chunks",
            ),
            _ => ("approve-draft-chunk", "interceptor.approve_draft_chunk"),
        };
        warn!(resource_id, correlation_id = %correlation_id, reason, "draft chunk approval denied");
        let ctx = context::extract_provider(&eval);
        self.record_governance_event(
            verb,
            "apf.policy_proposal",
            resource_id,
            &ctx.user_subject,
            &correlation_id,
            PolicyIdentity {
                digest: UNVERIFIED_POLICY,
                revision: None,
            },
            "interceptor.govern_denied.draft_approval",
            Outcome::Refused { detail: reason },
        );
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
        verb: &'static str,
        reason_code: &'static str,
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

        let ctx = context::extract_provider(eval);
        self.record_governance_event(
            verb,
            "openshell.provider_profile",
            resource_id,
            &ctx.user_subject,
            &correlation_id,
            PolicyIdentity {
                digest: UNVERIFIED_POLICY,
                revision: None,
            },
            reason_code,
            Outcome::Refused { detail: &reason },
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
        validate_gateway_metadata(
            ExtensionFamily::GatewayInterceptor,
            &manifest.name,
            manifest
                .extension
                .as_ref()
                .expect("interceptor manifest protocol metadata is static"),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
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

        // Pin one verifier for the whole snapshot. A concurrent key rotation or
        // bundle change must fail the request rather than mix policy identities.
        let verifying_key =
            *self.config.verifying_key.read().map_err(|_| {
                Status::failed_precondition("provider profile verifier unavailable")
            })?;
        let mut profile_entries = Vec::with_capacity(names.len());
        let mut policy_identity = None;
        for name in &names {
            let resp = policy_service
                .get_document("openshell.provider-profile.v1", name, None)
                .await
                .map_err(|e| Status::internal(format!("get_document '{name}': {e}")))?;
            let claims = verify_jwt_internal(&verifying_key, &resp.provenance_token)
                .map_err(|()| Status::failed_precondition("provider profile provenance invalid"))?;
            if claims.sub != self.config.signing_key_id
                || claims.apf_bundle_id.is_empty()
                || claims.apf_version == 0
                || claims.apf_version != resp.version
                || claims.apf_document_digest != resp.digest
                || hex::encode(Sha256::digest(&resp.body)) != resp.digest
            {
                return Err(Status::failed_precondition(
                    "provider profile provenance mismatch",
                ));
            }
            let identity = (claims.apf_bundle_id, claims.apf_version);
            if policy_identity
                .as_ref()
                .is_some_and(|previous| previous != &identity)
            {
                return Err(Status::failed_precondition(
                    "provider profile policy changed during snapshot",
                ));
            }
            policy_identity = Some(identity);
            profile_entries.push((name.clone(), resp.body));
        }
        profile_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut hasher = Sha256::new();
        hasher.update(b"apf-provider-profile-snapshot-v2");
        hasher.update(verifying_key.as_bytes());
        // These are verified stable identities, not JWT nonce/issuance fields.
        for field in [
            self.config.signing_key_id.as_bytes(),
            policy_identity
                .as_ref()
                .map_or(&b""[..], |p| p.0.as_bytes()),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.update(policy_identity.as_ref().map_or(0, |p| p.1).to_be_bytes());
        for (id, body) in &profile_entries {
            // Include both the ID and the content bytes so the revision changes
            // when any profile's body changes, not just when the set of IDs changes.
            hasher.update((id.len() as u64).to_be_bytes());
            hasher.update(id.as_bytes());
            hasher.update((body.len() as u64).to_be_bytes());
            hasher.update(body);
        }
        let revision = format!("sha256:{:x}", hasher.finalize());

        // OpenShell trusts configured interceptor sources. Provenance is
        // verified above; do not inject per-read import annotations into this
        // catalog's runtime configuration identity. The independent
        // profile-import/admission checks remain intact.
        let documents: Vec<reconciler::ProviderProfileDocument> = profile_entries
            .into_iter()
            .map(|(name, body)| reconciler::ProviderProfileDocument {
                name,
                body,
                digest: String::new(),
            })
            .collect();
        let profiles = reconciler::resolve_provider_profiles(&documents).map_err(|_| {
            Status::failed_precondition("provider profile snapshot contains an invalid profile")
        })?;

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
    use serde::Serialize;
    use std::collections::BTreeMap;
    use tonic::transport::Endpoint;

    /// PKCS#8 v1 DER encoding for an Ed25519 seed (RFC 8410, 48 bytes).
    pub(super) fn ed25519_seed_to_pkcs8_der(seed: &[u8; 32]) -> [u8; 48] {
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
        #[serde(rename = "apf/bundle-id")]
        apf_bundle_id: String,
        #[serde(rename = "apf/driver-config", skip_serializing_if = "Option::is_none")]
        apf_driver_config: Option<String>,
    }

    pub(super) fn mint_test_jwt(
        signing_key: &SigningKey,
        key_id: &str,
        jti: &str,
        policy_digest: &str,
        exp: Option<u64>,
    ) -> String {
        mint_test_jwt_with_spec_digest(signing_key, key_id, jti, policy_digest, exp, "")
    }

    pub(super) fn mint_test_jwt_with_spec_digest(
        signing_key: &SigningKey,
        key_id: &str,
        jti: &str,
        policy_digest: &str,
        exp: Option<u64>,
        spec_digest: &str,
    ) -> String {
        mint_test_jwt_full(signing_key, key_id, jti, policy_digest, exp, spec_digest, 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn mint_test_jwt_full(
        signing_key: &SigningKey,
        key_id: &str,
        jti: &str,
        policy_digest: &str,
        exp: Option<u64>,
        spec_digest: &str,
        version: u64,
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
            apf_version: version,
            apf_spec_digest: spec_digest.to_string(),
            apf_bundle_id: "test-bundle".to_string(),
            apf_driver_config: None,
        };
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("encode")
    }

    /// Mint a signed token carrying an `apf/driver-config` claim (hex-encoded
    /// `DriverConfigPolicy` protobuf), as the policy-service does when the
    /// signed SandboxPolicy carries a driver-config allowlist.
    pub(super) fn mint_test_jwt_with_driver_config(
        signing_key: &SigningKey,
        key_id: &str,
        jti: &str,
        policy_digest: &str,
        driver_config_hex: &str,
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
            exp: None,
            apf_document_digest: policy_digest.to_string(),
            apf_version: 1,
            apf_spec_digest: String::new(),
            apf_bundle_id: "test-bundle".to_string(),
            apf_driver_config: Some(driver_config_hex.to_string()),
        };
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("encode")
    }

    pub(super) fn eval_with_annotations(annotations: Vec<(&str, &str)>) -> InterceptorEvaluation {
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
        let signing_key =
            SigningKey::generate(&mut ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng));
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
                gateway_compute_driver: String::new(),
                signing_key_id: "test-key".to_string(),
                verifying_key: Arc::new(std::sync::RwLock::new(
                    SigningKey::generate(&mut ed25519_dalek::rand_core::UnwrapErr(
                        getrandom::SysRng,
                    ))
                    .verifying_key(),
                )),
                audit: InterceptorAudit::disabled(),
            },
            authentication: AuthenticationMode::Insecure,
        }
    }

    fn json_to_prost(v: &serde_json::Value) -> ProstValue {
        let kind = match v {
            serde_json::Value::Null => Kind::NullValue(0),
            serde_json::Value::Bool(b) => Kind::BoolValue(*b),
            serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
            serde_json::Value::String(s) => Kind::StringValue(s.clone()),
            serde_json::Value::Array(a) => Kind::ListValue(prost_types::ListValue {
                values: a.iter().map(json_to_prost).collect(),
            }),
            serde_json::Value::Object(o) => Kind::StructValue(ProstStruct {
                fields: o
                    .iter()
                    .map(|(k, val)| (k.clone(), json_to_prost(val)))
                    .collect(),
            }),
        };
        ProstValue { kind: Some(kind) }
    }

    fn json_to_struct(v: serde_json::Value) -> ProstStruct {
        match json_to_prost(&v).kind {
            Some(Kind::StructValue(s)) => s,
            _ => panic!("expected a JSON object"),
        }
    }

    fn service_with_key(
        verifying_key: VerifyingKey,
        compute_driver: &str,
    ) -> GatewayInterceptorService {
        let channel = Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        GatewayInterceptorService {
            policy_service: PolicyClientHandle::from_channel(channel),
            config: InterceptorConfig {
                document_kind: "openshell.sandbox.v1".to_string(),
                document_name: "default".to_string(),
                gateway_compute_driver: compute_driver.to_string(),
                signing_key_id: "test-kid".to_string(),
                verifying_key: Arc::new(std::sync::RwLock::new(verifying_key)),
                audit: InterceptorAudit::disabled(),
            },
            authentication: AuthenticationMode::Insecure,
        }
    }

    fn validate_eval_with_principal(
        op: ProstStruct,
        principal: Vec<(&str, &str)>,
    ) -> InterceptorEvaluation {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        InterceptorEvaluation {
            method: "CreateSandbox".to_string(),
            phase: Some(Phase::Validate(ValidateEvaluation {
                proposed_operation: Some(op),
                ..Default::default()
            })),
            principal: principal
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    /// Hex-encoded `DriverConfigPolicy` for the SAW harness rule, as the
    /// policy-service mints into the provenance JWT.
    fn harness_rule_hex() -> String {
        use prost::Message;
        let rule = apf_proto::ir::DriverConfigPolicy {
            deny_templates: true,
            allowed: vec![apf_proto::ir::DriverConfigAllow {
                require_role: "openshell-admin".to_string(),
                drivers: vec!["podman".to_string(), "docker".to_string()],
                max_mounts: 1,
                mounts: vec![apf_proto::ir::DriverConfigMount {
                    r#type: "volume".to_string(),
                    source_prefix: "saw-harness-".to_string(),
                    target: "/sandbox/harness".to_string(),
                    read_only: true,
                }],
            }],
        };
        hex::encode(rule.encode_to_vec())
    }

    fn harness_op(token: &str, source: &str, target: &str, read_only: bool) -> ProstStruct {
        json_to_struct(serde_json::json!({
            "name": "sb-harness",
            "annotations": {
                "apf.nvidia.com/correlation-id": "corr-dc",
                "apf.nvidia.com/document-digest": "sha256-dc",
                "apf.nvidia.com/provenance-token": token,
            },
            "spec": { "template": { "driver_config": {
                "podman": { "mounts": [
                    { "type": "volume", "source": source, "target": target, "read_only": read_only }
                ] }
            } } }
        }))
    }

    // End-to-end admit path: a signed token carrying the driver-config rule is
    // verified, decoded, and enforced in CreateSandbox VALIDATE.
    #[tokio::test]
    async fn driver_config_admits_exact_harness_mount_for_admin() {
        let (sk, vk) = test_keypair();
        let jwt = mint_test_jwt_with_driver_config(
            &sk,
            "test-kid",
            "corr-dc",
            "sha256-dc",
            &harness_rule_hex(),
        );
        let service = service_with_key(vk, "podman");
        let op = harness_op(&jwt, "saw-harness-abc", "/sandbox/harness", true);
        let eval = validate_eval_with_principal(
            op,
            vec![("subject", "installer@saw"), ("roles", "openshell-admin")],
        );
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(
            result.allowed,
            "admin + exact harness mount should be ADMITTED: {}",
            result.reason
        );
    }

    #[tokio::test]
    async fn driver_config_denies_harness_mount_for_non_admin() {
        let (sk, vk) = test_keypair();
        let jwt = mint_test_jwt_with_driver_config(
            &sk,
            "test-kid",
            "corr-dc",
            "sha256-dc",
            &harness_rule_hex(),
        );
        let service = service_with_key(vk, "podman");
        let op = harness_op(&jwt, "saw-harness-abc", "/sandbox/harness", true);
        let eval = validate_eval_with_principal(
            op,
            vec![("subject", "user@corp"), ("roles", "developer")],
        );
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed, "non-admin caller must be denied");
    }

    #[tokio::test]
    async fn driver_config_denies_wrong_target_even_for_admin() {
        let (sk, vk) = test_keypair();
        let jwt = mint_test_jwt_with_driver_config(
            &sk,
            "test-kid",
            "corr-dc",
            "sha256-dc",
            &harness_rule_hex(),
        );
        let service = service_with_key(vk, "podman");
        let op = harness_op(&jwt, "saw-harness-abc", "/etc", true);
        let eval = validate_eval_with_principal(
            op,
            vec![("subject", "installer@saw"), ("roles", "openshell-admin")],
        );
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed, "wrong target must be denied");
    }

    #[tokio::test]
    async fn driver_config_denies_present_mount_when_token_has_no_rule() {
        // deny-by-default: a request carrying driver_config but a token with no
        // apf/driver-config claim is refused.
        let (sk, vk) = test_keypair();
        let jwt = mint_test_jwt(&sk, "test-kid", "corr-dc", "sha256-dc", None);
        let service = service_with_key(vk, "podman");
        let op = harness_op(&jwt, "saw-harness-abc", "/sandbox/harness", true);
        let eval = validate_eval_with_principal(
            op,
            vec![("subject", "installer@saw"), ("roles", "openshell-admin")],
        );
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(
            !result.allowed,
            "deny-by-default: present mount, no signed rule"
        );
    }

    fn describe_request() -> DescribeRequest {
        DescribeRequest {
            gateway: Some(apf_openshell_auth::protocol::extension_metadata(
                ExtensionFamily::GatewayInterceptor,
                "openshell/gateway",
                "0.0.117",
            )),
        }
    }

    #[tokio::test]
    async fn describe_negotiates_gateway_interceptor_protocol() {
        let manifest = service()
            .describe(Request::new(describe_request()))
            .await
            .expect("matching gateway protocol should negotiate")
            .into_inner();
        let metadata = manifest.extension.expect("protocol metadata");
        assert_eq!(
            metadata.required_capabilities,
            vec!["openshell.gateway-interceptor.contract"]
        );
    }

    #[tokio::test]
    async fn describe_rejects_missing_gateway_protocol_metadata() {
        let error = service()
            .describe(Request::new(DescribeRequest { gateway: None }))
            .await
            .expect_err("missing gateway metadata must fail closed");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            error
                .message()
                .contains("did not provide protocol metadata")
        );
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

    /// Build an `UpdateConfig` evaluation for a settings-only update (`setting_key`
    /// present, no `policy`/`mergeOperations`) at the given phase.
    pub(super) fn settings_only_update_config_evaluation(
        phase: crate::proto::interceptor_evaluation::Phase,
    ) -> InterceptorEvaluation {
        InterceptorEvaluation {
            binding_id: "config-policy-settings-only".to_string(),
            method: "UpdateConfig".to_string(),
            phase: Some(phase),
            principal: [("subject".to_string(), "operator-subject".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    pub(super) fn settings_only_operation_fields(
        setting_key: &str,
        string_value: &str,
    ) -> ProstStruct {
        let setting_value_fields = [(
            "stringValue".to_string(),
            ProstValue {
                kind: Some(Kind::StringValue(string_value.to_string())),
            },
        )]
        .into_iter()
        .collect();
        let fields = [
            (
                "settingKey".to_string(),
                ProstValue {
                    kind: Some(Kind::StringValue(setting_key.to_string())),
                },
            ),
            (
                "settingValue".to_string(),
                ProstValue {
                    kind: Some(Kind::StructValue(ProstStruct {
                        fields: setting_value_fields,
                    })),
                },
            ),
        ]
        .into_iter()
        .collect();
        ProstStruct { fields }
    }

    #[tokio::test]
    async fn update_config_modify_operation_allows_settings_only() {
        use crate::proto::{ModifyOperationEvaluation, interceptor_evaluation::Phase};
        let service = service();
        let eval = settings_only_update_config_evaluation(Phase::ModifyOperation(
            ModifyOperationEvaluation {
                proposed_operation: Some(settings_only_operation_fields(
                    "providers_v2_enabled",
                    "true",
                )),
            },
        ));
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
        assert!(result.patches.is_empty());
    }

    #[tokio::test]
    async fn update_config_modify_operation_denies_auto_approval_setting() {
        use crate::proto::{ModifyOperationEvaluation, interceptor_evaluation::Phase};
        let service = service();
        let eval = settings_only_update_config_evaluation(Phase::ModifyOperation(
            ModifyOperationEvaluation {
                proposed_operation: Some(settings_only_operation_fields(
                    "proposal_approval_mode",
                    "auto",
                )),
            },
        ));
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn update_config_validate_allows_settings_only() {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        let service = service();
        let eval = settings_only_update_config_evaluation(Phase::Validate(ValidateEvaluation {
            proposed_operation: Some(settings_only_operation_fields(
                "agent_policy_proposals_enabled",
                "false",
            )),
            ..Default::default()
        }));
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn update_config_validate_denies_auto_approval_setting() {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        let service = service();
        let eval = settings_only_update_config_evaluation(Phase::Validate(ValidateEvaluation {
            proposed_operation: Some(settings_only_operation_fields(
                "proposal_approval_mode",
                "auto",
            )),
            ..Default::default()
        }));
        let result = service
            .evaluate(Request::new(eval))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
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

    /// One audited service for the governance handlers that consult no
    /// policy document — proposal and profile-delete refusals, and their
    /// allows, must leave `config_governance` records.
    fn audited_service(dir: &std::path::Path) -> GatewayInterceptorService {
        let channel = Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        GatewayInterceptorService {
            policy_service: PolicyClientHandle::from_channel(channel),
            config: InterceptorConfig {
                document_kind: "openshell.sandbox.v1".to_string(),
                document_name: "default".to_string(),
                gateway_compute_driver: String::new(),
                signing_key_id: "test-key".to_string(),
                verifying_key: Arc::new(std::sync::RwLock::new(
                    SigningKey::generate(&mut ed25519_dalek::rand_core::UnwrapErr(
                        getrandom::SysRng,
                    ))
                    .verifying_key(),
                )),
                audit: InterceptorAudit::to_jsonl_in(dir).expect("build emitter"),
            },
            authentication: AuthenticationMode::Insecure,
        }
    }

    fn governance_records(dir: &std::path::Path) -> Vec<apf_audit::AuditEvent> {
        let written =
            std::fs::read_to_string(dir.join("apf-policy-gateway-interceptor-audit.jsonl"))
                .expect("audit log was written");
        written
            .lines()
            .map(|line| {
                let parsed: apf_audit::AuditEvent =
                    serde_json::from_str(line).expect("deserializes");
                parsed.validate().expect("validates against the schema");
                parsed
            })
            .collect()
    }

    #[tokio::test]
    async fn proposal_governance_decisions_leave_records() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = audited_service(dir.path());

        let deny = eval_with_method_and_fields(
            "SubmitPolicyAnalysis",
            vec![("analysisMode", "agent_authored")],
        );
        assert!(
            !svc.handle_policy_analysis_verify(deny)
                .await
                .unwrap()
                .into_inner()
                .allowed
        );
        let allow = eval_with_method_and_fields(
            "SubmitPolicyAnalysis",
            vec![("analysisMode", "mechanistic")],
        );
        assert!(
            svc.handle_policy_analysis_verify(allow)
                .await
                .unwrap()
                .into_inner()
                .allowed
        );
        let chunk = eval_with_method_and_fields("ApproveDraftChunk", vec![]);
        assert!(
            !svc.handle_draft_chunk_approve_deny(chunk, "ApproveDraftChunk")
                .await
                .unwrap()
                .into_inner()
                .allowed
        );

        let records = governance_records(dir.path());
        assert_eq!(records.len(), 3, "every decision leaves a record");
        for r in &records {
            assert_eq!(r.event_type, apf_audit::EventType::ConfigGovernance);
        }
        assert_eq!(
            records[0].reason_code.as_deref(),
            Some("interceptor.govern_denied.agent_authored_proposal")
        );
        assert_eq!(
            records[0].verb.as_deref(),
            Some("interceptor.submit_policy_analysis")
        );
        assert_eq!(records[0].outcome, Some(apf_audit::Outcome::Refused));
        assert_eq!(
            records[1].reason_code.as_deref(),
            Some("interceptor.policy_analysis_allowed")
        );
        assert_eq!(records[1].outcome, Some(apf_audit::Outcome::Success));
        assert_eq!(
            records[2].reason_code.as_deref(),
            Some("interceptor.govern_denied.draft_approval")
        );
        assert_eq!(
            records[2].verb.as_deref(),
            Some("interceptor.approve_draft_chunk")
        );
    }

    #[tokio::test]
    async fn profile_delete_refusal_leaves_a_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = audited_service(dir.path());
        let eval = eval_with_method_and_fields("DeleteProviderProfile", vec![]);
        let result = svc
            .handle_provider_profile_delete_verify(eval)
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);

        let records = governance_records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.event_type, apf_audit::EventType::ConfigGovernance);
        assert_eq!(
            r.verb.as_deref(),
            Some("interceptor.delete_provider_profile")
        );
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.profile_delete")
        );
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
    }

    #[tokio::test]
    async fn provider_create_fails_closed_and_leaves_a_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        // The lazy channel has no listener: the catalog fetch fails, and the
        // governance check must refuse rather than pass ungoverned.
        let svc = audited_service(dir.path());
        let eval = eval_with_method_and_fields("CreateProvider", vec![]);
        let result = svc
            .handle_provider_instance_type_verify(eval)
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);

        let records = governance_records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.event_type, apf_audit::EventType::ConfigGovernance);
        assert_eq!(r.verb.as_deref(), Some("interceptor.create_provider"));
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.policy_service_unavailable")
        );
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
        assert_eq!(
            result
                .log_annotations
                .get("apf.nvidia.com/correlation-id")
                .map(String::as_str),
            Some(r.correlation_id.as_str()),
            "the deny response and the record must join on one correlation id"
        );
    }

    /// A credential-shaped caller value degrades the record, but the record
    /// must keep the correlation id the response carried — the join matters
    /// most on exactly the inputs that trip the sanitizer.
    #[tokio::test]
    async fn a_degraded_governance_record_keeps_a_safe_correlation_id() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = audited_service(dir.path());
        let hostile = eval_with_method_and_fields(
            "SubmitPolicyAnalysis",
            vec![("analysisMode", "AKIAAAAAAAAAAAAAAAAA")],
        );
        let result = svc
            .handle_policy_analysis_verify(hostile)
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed, "non-agent_authored modes pass governance");

        let records = governance_records(dir.path());
        assert_eq!(records.len(), 1, "the decision must still leave a record");
        let r = &records[0];
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied admission detail omitted"),
            "the record must mark itself as degraded"
        );
        assert!(
            uuid::Uuid::parse_str(&r.correlation_id).is_ok(),
            "a producer-minted uuid survives degradation: {}",
            r.correlation_id
        );
    }

    /// Emitter-level pin for the fallback correlation rule: a safe id is
    /// kept verbatim, so the record still joins the response that carried it.
    #[test]
    fn degraded_record_preserves_a_sanitizer_safe_correlation_id() {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter");
        audit
            .emit_admission(&AdmissionRecord {
                outcome: Outcome::Refused {
                    detail: "credential AKIAAAAAAAAAAAAAAAAA is not a bundle-managed profile",
                },
                phase: AdmissionPhase::Governance,
                verb: "interceptor.create_provider",
                reason_code: "interceptor.govern_denied.unmanaged_provider_type",
                resource_kind: "openshell.provider",
                resource_id: "AKIAAAAAAAAAAAAAAAAA",
                sandbox_id: "",
                user_subject: "",
                agent_type: "",
                correlation_id: "11111111-2222-4333-8444-555555555555",
                policy_digest: UNVERIFIED_POLICY,
                policy_revision: None,
                applied: apf_audit::Effects::default(),
            })
            .expect("emit");
        let records = governance_records(dir.path());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(
            r.reason.as_deref(),
            Some("caller-supplied admission detail omitted"),
            "the hostile detail must degrade the record"
        );
        assert_eq!(
            r.correlation_id, "11111111-2222-4333-8444-555555555555",
            "the safe correlation id must survive degradation"
        );
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

/// Admission tests that reach past the policy-service fetch.
///
/// The other test module points the client at a dead address, so every test
/// there returns at `get_document` and nothing after it has ever run. These
/// serve a real stub over a Unix socket instead, with a real audit sink, so the
/// handler's recording can be observed.
#[cfg(test)]
mod admission_audit_tests {
    use super::tests::{
        eval_with_annotations, mint_test_jwt, mint_test_jwt_full, mint_test_jwt_with_spec_digest,
        settings_only_operation_fields, settings_only_update_config_evaluation,
    };
    use super::*;
    use crate::audit::InterceptorAudit;
    use apf_audit::AuditEvent;
    use apf_proto::openshell_sandbox::SandboxPolicy;
    use apf_proto::policy_service_v1alpha1::{
        GetDocumentRequest, GetDocumentResponse, HealthRequest, HealthResponse,
        ListDocumentsRequest, ListDocumentsResponse,
        policy_service_server::{PolicyService, PolicyServiceServer},
    };
    use ed25519_dalek::SigningKey;
    use prost::Message as _;
    use prost_types::{Struct as ProstStruct, Value as ProstValue};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;

    const KEY_ID: &str = "test-key";

    struct StubPolicyService {
        doc: GetDocumentResponse,
        names: Option<Vec<String>>,
        documents: BTreeMap<String, GetDocumentResponse>,
    }

    #[tonic::async_trait]
    impl PolicyService for StubPolicyService {
        async fn get_document(
            &self,
            request: Request<GetDocumentRequest>,
        ) -> Result<Response<GetDocumentResponse>, Status> {
            Ok(Response::new(
                self.documents
                    .get(&request.into_inner().name)
                    .unwrap_or(&self.doc)
                    .clone(),
            ))
        }
        async fn health(
            &self,
            _: Request<HealthRequest>,
        ) -> Result<Response<HealthResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn list_documents(
            &self,
            _: Request<ListDocumentsRequest>,
        ) -> Result<Response<ListDocumentsResponse>, Status> {
            match &self.names {
                Some(names) => Ok(Response::new(ListDocumentsResponse {
                    names: names.clone(),
                })),
                None => Err(Status::unimplemented("stub")),
            }
        }
    }

    /// Short path under `/tmp`: macOS caps socket paths near 104 bytes, and the
    /// per-user temp dir is long enough to matter.
    fn socket_path() -> std::path::PathBuf {
        std::path::PathBuf::from(format!(
            "/tmp/apf-ix-{}.sock",
            uuid::Uuid::new_v4().simple()
        ))
    }

    /// Bind before serving so the client cannot connect to a socket that does
    /// not exist yet — a spawn-then-connect race is the usual source of
    /// flakiness here.
    /// Removes the socket even if the harness is never constructed — a connect
    /// failure between bind and construction would otherwise strand it.
    struct SocketGuard(std::path::PathBuf);

    impl Drop for SocketGuard {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).ok();
        }
    }

    async fn serve_stub(doc: GetDocumentResponse) -> (PolicyClientHandle, SocketGuard) {
        serve_stub_with_names(doc, None).await
    }

    async fn serve_stub_with_names(
        doc: GetDocumentResponse,
        names: Option<Vec<String>>,
    ) -> (PolicyClientHandle, SocketGuard) {
        serve_stub_documents(doc, names, BTreeMap::new()).await
    }

    async fn serve_stub_documents(
        doc: GetDocumentResponse,
        names: Option<Vec<String>>,
        documents: BTreeMap<String, GetDocumentResponse>,
    ) -> (PolicyClientHandle, SocketGuard) {
        let path = socket_path();
        let listener = UnixListener::bind(&path).expect("bind stub socket");
        let guard = SocketGuard(path.clone());
        tokio::spawn(async move {
            Server::builder()
                .add_service(PolicyServiceServer::new(StubPolicyService {
                    doc,
                    names,
                    documents,
                }))
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await
        });
        let client = PolicyClientHandle::connect(&path)
            .await
            .expect("connect to stub");
        (client, guard)
    }

    fn signed_document(
        signing_key: &SigningKey,
        jti: &str,
        key_id: &str,
        claim_digest: Option<&str>,
        response_version: u64,
    ) -> GetDocumentResponse {
        let mut body = Vec::new();
        SandboxPolicy::default().encode(&mut body).expect("encode");
        let digest = hex::encode(Sha256::digest(&body));
        let token = mint_test_jwt(
            signing_key,
            key_id,
            jti,
            claim_digest.unwrap_or(&digest),
            None,
        );
        GetDocumentResponse {
            body,
            digest,
            version: response_version,
            valid_until_ms: 0,
            provenance_token: token,
        }
    }

    fn create_sandbox_modify(sandbox_id: &str, subject: &str) -> InterceptorEvaluation {
        use crate::proto::{ModifyOperationEvaluation, interceptor_evaluation::Phase};
        let mut labels = BTreeMap::new();
        labels.insert(
            "agent-type".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue(
                    "claude-code".to_string(),
                )),
            },
        );
        let mut op = BTreeMap::new();
        op.insert(
            "name".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue(
                    sandbox_id.to_string(),
                )),
            },
        );
        op.insert(
            "labels".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StructValue(ProstStruct {
                    fields: labels,
                })),
            },
        );
        let mut principal = std::collections::HashMap::new();
        principal.insert("subject".to_string(), subject.to_string());
        InterceptorEvaluation {
            method: "CreateSandbox".to_string(),
            principal,
            phase: Some(Phase::ModifyOperation(ModifyOperationEvaluation {
                proposed_operation: Some(ProstStruct { fields: op }),
            })),
            ..Default::default()
        }
    }

    struct Harness {
        service: GatewayInterceptorService,
        dir: tempfile::TempDir,
        _socket: SocketGuard,
    }

    impl Harness {
        fn records(&self) -> Vec<AuditEvent> {
            let written = std::fs::read_to_string(
                self.dir
                    .path()
                    .join("apf-policy-gateway-interceptor-audit.jsonl"),
            )
            .expect("audit log was written");
            written
                .lines()
                .map(|line| {
                    let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
                    parsed.validate().expect("validates against the schema");
                    parsed
                })
                .collect()
        }
    }

    async fn harness(signing_key: &SigningKey, doc: GetDocumentResponse) -> Harness {
        let (client, _socket) = serve_stub(doc).await;
        let dir = tempfile::tempdir().expect("temp dir");
        let service = GatewayInterceptorService {
            policy_service: client,
            config: InterceptorConfig {
                document_kind: "openshell.sandbox.v1".to_string(),
                document_name: "default".to_string(),
                gateway_compute_driver: String::new(),
                signing_key_id: KEY_ID.to_string(),
                verifying_key: Arc::new(std::sync::RwLock::new(signing_key.verifying_key())),
                audit: InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter"),
            },
            authentication: AuthenticationMode::Insecure,
        };
        Harness {
            service,
            dir,
            _socket,
        }
    }

    #[tokio::test]
    async fn snapshot_profiles_emit_enum_endpoints_and_fail_closed_on_invalid_modes() {
        for mode in ["enforce", "typo"] {
            let doc = signed_profile(
                format!(
                    "id: p\nendpoints: [{{host: api.example, port: 443, enforcement: {mode}}}]\n"
                )
                .into_bytes(),
                "snapshot",
            );
            let mut h = harness(&key(), doc.clone()).await;
            let (client, _socket) = serve_stub_with_names(doc, Some(vec!["p".into()])).await;
            h.service.policy_service = client;
            let result = h
                .service
                .snapshot_provider_profiles(Request::new(ProviderProfileSnapshotRequest {}))
                .await;
            if mode == "enforce" {
                let snapshot = result.unwrap().into_inner();
                assert_eq!(snapshot.profiles.len(), 1);
                assert_eq!(snapshot.profiles[0].endpoints[0].enforcement, 1);
            } else {
                assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
            }
        }
    }

    async fn snapshot_documents(
        bodies: &[(&str, Vec<u8>)],
    ) -> Result<ProviderProfileSnapshot, Status> {
        let documents = bodies
            .iter()
            .map(|(name, body)| (name.to_string(), signed_profile(body.clone(), name)))
            .collect();
        snapshot_responses(documents).await
    }

    fn signed_profile(body: Vec<u8>, nonce: &str) -> GetDocumentResponse {
        let digest = hex::encode(Sha256::digest(&body));
        GetDocumentResponse {
            provenance_token: mint_test_jwt(&key(), KEY_ID, nonce, &digest, None),
            body,
            digest,
            version: 1,
            valid_until_ms: 0,
        }
    }

    async fn snapshot_responses(
        documents: BTreeMap<String, GetDocumentResponse>,
    ) -> Result<ProviderProfileSnapshot, Status> {
        let mut h = harness(&key(), GetDocumentResponse::default()).await;
        let (client, _socket) = serve_stub_documents(
            GetDocumentResponse::default(),
            Some(documents.keys().cloned().collect()),
            documents,
        )
        .await;
        h.service.policy_service = client;
        h.service
            .snapshot_provider_profiles(Request::new(ProviderProfileSnapshotRequest {}))
            .await
            .map(Response::into_inner)
    }

    #[tokio::test]
    async fn snapshot_accepts_empty_and_populated_compiler_aggregate_without_duplicates() {
        let profile =
            b"id: p\nendpoints: [{host: api.example, port: 443, enforcement: enforce}]\n".to_vec();
        let mut revisions = Vec::new();
        for profiles in [vec![], vec![profile.clone()]] {
            let aggregate = apf_proto::ProviderProfileSet { profiles }.encode_to_vec();
            let snapshot = snapshot_documents(&[("default", aggregate), ("p", profile.clone())])
                .await
                .unwrap();
            assert_eq!(snapshot.profiles.len(), 1);
            assert_eq!(snapshot.profiles[0].id, "p");
            assert_eq!(snapshot.profiles[0].endpoints[0].enforcement, 1);
            assert!(snapshot.profiles[0].annotations.is_empty());
            revisions.push(snapshot.revision);
        }
        assert_ne!(
            revisions[0], revisions[1],
            "aggregate remains part of revision identity"
        );
    }

    #[tokio::test]
    async fn snapshot_imports_aggregate_profiles_when_no_individual_documents_exist() {
        // Bundles signed before the compiler composed one document per
        // profile publish only the `default` ProviderProfileSet aggregate.
        let profile =
            b"id: p\nendpoints: [{host: api.example, port: 443, enforcement: enforce}]\n".to_vec();
        let aggregate = apf_proto::ProviderProfileSet {
            profiles: vec![profile],
        }
        .encode_to_vec();
        let snapshot = snapshot_documents(&[("default", aggregate)]).await.unwrap();
        assert_eq!(snapshot.profiles.len(), 1);
        assert_eq!(snapshot.profiles[0].id, "p");
        assert_eq!(snapshot.profiles[0].endpoints[0].enforcement, 1);
    }

    #[tokio::test]
    async fn snapshot_revision_ignores_fresh_tokens_but_tracks_verified_policy() {
        let body = b"id: p\nendpoints: [{host: api.example, port: 443}]\n".to_vec();
        let first = snapshot_responses(BTreeMap::from([(
            "p".into(),
            signed_profile(body.clone(), "first"),
        )]))
        .await
        .unwrap();
        let second = snapshot_responses(BTreeMap::from([(
            "p".into(),
            signed_profile(body.clone(), "second"),
        )]))
        .await
        .unwrap();
        assert_eq!(first.revision, second.revision);
        assert_eq!(first.profiles, second.profiles);
        assert!(first.profiles[0].annotations.is_empty());
        let changed = snapshot_documents(&[(
            "p",
            b"id: p\nendpoints: [{host: other.example, port: 443}]\n".to_vec(),
        )])
        .await
        .unwrap();
        assert_ne!(first.revision, changed.revision);
        let mut document = signed_profile(body, "third");
        document.version = 2;
        document.provenance_token =
            mint_test_jwt_full(&key(), KEY_ID, "third", &document.digest, None, "", 2);
        let newer = snapshot_responses(BTreeMap::from([("p".into(), document)]))
            .await
            .unwrap();
        assert_ne!(first.revision, newer.revision);
    }

    #[tokio::test]
    async fn snapshot_rejects_invalid_provenance_atomically_including_aggregate() {
        for name in ["p", "default"] {
            let body = if name == "default" {
                Vec::new()
            } else {
                b"id: p\n".to_vec()
            };
            for failure in [
                "missing",
                "wrong-key",
                "expired",
                "body",
                "digest",
                "version",
                "signer",
                "mixed-version",
            ] {
                let mut bad = signed_profile(body.clone(), "bad");
                match failure {
                    "missing" => bad.provenance_token.clear(),
                    "wrong-key" => {
                        bad.provenance_token = mint_test_jwt(
                            &SigningKey::from_bytes(&[8; 32]),
                            KEY_ID,
                            "bad",
                            &bad.digest,
                            None,
                        )
                    }
                    "expired" => {
                        bad.provenance_token =
                            mint_test_jwt(&key(), KEY_ID, "bad", &bad.digest, Some(1))
                    }
                    "body" => bad.body.push(b' '),
                    "digest" => bad.digest = "0".repeat(64),
                    "version" => bad.version += 1,
                    "signer" => {
                        bad.provenance_token =
                            mint_test_jwt(&key(), "other", "bad", &bad.digest, None)
                    }
                    "mixed-version" => {
                        bad.version = 2;
                        bad.provenance_token =
                            mint_test_jwt_full(&key(), KEY_ID, "bad", &bad.digest, None, "", 2);
                    }
                    _ => unreachable!(),
                }
                let result = snapshot_responses(BTreeMap::from([
                    (
                        "a-valid".into(),
                        signed_profile(b"id: a-valid\n".to_vec(), "valid"),
                    ),
                    (name.into(), bad),
                ]))
                .await;
                assert_eq!(
                    result.unwrap_err().code(),
                    tonic::Code::FailedPrecondition,
                    "{name}: {failure}"
                );
            }
        }
    }

    #[tokio::test]
    async fn snapshot_keeps_yaml_profile_named_default() {
        let snapshot = snapshot_documents(&[("default", b"id: default\n".to_vec())])
            .await
            .unwrap();
        assert_eq!(snapshot.profiles.len(), 1);
        assert_eq!(snapshot.profiles[0].id, "default");
    }

    #[tokio::test]
    async fn snapshot_rejects_malformed_aggregate_and_actual_profiles_atomically() {
        let valid = b"id: a-valid\n".to_vec();
        let invalid = b"id: z-invalid\nendpoints: [{enforcement: typo}]\n".to_vec();
        for broken in [
            vec![0xff],
            invalid.clone(),
            apf_proto::ProviderProfileSet {
                profiles: vec![invalid.clone()],
            }
            .encode_to_vec(),
        ] {
            let error = snapshot_documents(&[("a-valid", valid.clone()), ("default", broken)])
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        }
        for broken in [Vec::new(), invalid] {
            let error = snapshot_documents(&[
                ("a-valid", valid.clone()),
                ("default", Vec::new()),
                ("z-invalid", broken),
            ])
            .await
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        }
    }

    fn json_operation_struct(value: serde_json::Value) -> ProstStruct {
        match apf_proto::json::json_to_proto_value(&value)
            .expect("test fixture is valid JSON")
            .kind
        {
            Some(prost_types::value::Kind::StructValue(s)) => s,
            other => panic!("expected a JSON object, got {other:?}"),
        }
    }

    fn import_provider_profiles_validate(profile: serde_json::Value) -> InterceptorEvaluation {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        InterceptorEvaluation {
            method: "ImportProviderProfiles".to_string(),
            phase: Some(Phase::Validate(ValidateEvaluation {
                proposed_operation: Some(json_operation_struct(serde_json::json!({
                    "profiles": [{ "profile": profile }]
                }))),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn update_provider_profiles_validate(
        id: &str,
        profile: serde_json::Value,
    ) -> InterceptorEvaluation {
        use crate::proto::{ValidateEvaluation, interceptor_evaluation::Phase};
        InterceptorEvaluation {
            method: "UpdateProviderProfiles".to_string(),
            phase: Some(Phase::Validate(ValidateEvaluation {
                proposed_operation: Some(json_operation_struct(serde_json::json!({
                    "id": id,
                    "profile": { "profile": profile }
                }))),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// The bundle's own profile for `yaml`, and the same content in the
    /// canonical proto3-JSON shape the gateway hands the interceptor at
    /// VALIDATE — the unmodified fixture every content-comparison test starts
    /// from.
    fn bundle_profile_and_json(yaml: &[u8]) -> serde_json::Value {
        let profile = reconciler::profile_from_yaml(yaml).expect("valid profile YAML");
        apf_proto::spec_digest::provider_profile_to_json(&profile)
    }

    async fn provider_profile_harness(yaml: Vec<u8>) -> Harness {
        let mut h = harness(&key(), GetDocumentResponse::default()).await;
        let (client, _socket) = serve_stub_with_names(
            GetDocumentResponse {
                body: yaml,
                ..Default::default()
            },
            Some(vec!["p".into()]),
        )
        .await;
        h.service.policy_service = client;
        h._socket = _socket;
        h
    }

    const PROFILE_YAML: &[u8] =
        b"id: p\nendpoints: [{host: api.example, port: 443, enforcement: enforce}]\n";

    #[tokio::test]
    async fn import_provider_profiles_allowed_when_content_matches_bundle() {
        let profile_json = bundle_profile_and_json(PROFILE_YAML);
        let h = provider_profile_harness(PROFILE_YAML.to_vec()).await;
        let result = h
            .service
            .evaluate(Request::new(import_provider_profiles_validate(
                profile_json,
            )))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed, "{result:?}");
    }

    #[tokio::test]
    async fn import_provider_profiles_denied_when_id_not_in_bundle() {
        let mut profile_json = bundle_profile_and_json(PROFILE_YAML);
        profile_json["id"] = serde_json::json!("not-managed");
        let h = provider_profile_harness(PROFILE_YAML.to_vec()).await;
        let result = h
            .service
            .evaluate(Request::new(import_provider_profiles_validate(
                profile_json,
            )))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn import_provider_profiles_denied_when_content_differs_from_bundle() {
        let mut profile_json = bundle_profile_and_json(PROFILE_YAML);
        // Same ID, tampered content: a port the bundle never authored.
        profile_json["endpoints"][0]["port"] = serde_json::json!(9999);
        let h = provider_profile_harness(PROFILE_YAML.to_vec()).await;
        let result = h
            .service
            .evaluate(Request::new(import_provider_profiles_validate(
                profile_json,
            )))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn update_provider_profiles_allowed_when_content_matches_bundle_ignoring_resource_version()
     {
        let mut profile_json = bundle_profile_and_json(PROFILE_YAML);
        // A real UpdateProviderProfiles call carries the gateway's existing
        // resource_version, which the bundle's own copy never has — must be
        // ignored, not treated as a content mismatch.
        profile_json["resourceVersion"] = serde_json::json!("7");
        let h = provider_profile_harness(PROFILE_YAML.to_vec()).await;
        let result = h
            .service
            .evaluate(Request::new(update_provider_profiles_validate(
                "p",
                profile_json,
            )))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed, "{result:?}");
    }

    #[tokio::test]
    async fn update_provider_profiles_denied_when_id_not_in_bundle() {
        let profile_json = bundle_profile_and_json(PROFILE_YAML);
        let h = provider_profile_harness(PROFILE_YAML.to_vec()).await;
        let result = h
            .service
            .evaluate(Request::new(update_provider_profiles_validate(
                "not-managed",
                profile_json,
            )))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn update_provider_profiles_denied_when_content_differs_from_bundle() {
        let mut profile_json = bundle_profile_and_json(PROFILE_YAML);
        profile_json["endpoints"][0]["enforcement"] = serde_json::json!("AUDIT");
        let h = provider_profile_harness(PROFILE_YAML.to_vec()).await;
        let result = h
            .service
            .evaluate(Request::new(update_provider_profiles_validate(
                "p",
                profile_json,
            )))
            .await
            .unwrap()
            .into_inner();
        assert!(!result.allowed);
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// These paths never fetch a document, so they need no stub — only a real
    /// audit sink, which the other test module does not wire.
    fn offline_harness(signing_key: &SigningKey) -> (GatewayInterceptorService, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let service = GatewayInterceptorService {
            policy_service: PolicyClientHandle::disconnected(),
            config: InterceptorConfig {
                document_kind: "openshell.sandbox.v1".to_string(),
                document_name: "default".to_string(),
                gateway_compute_driver: String::new(),
                signing_key_id: KEY_ID.to_string(),
                verifying_key: Arc::new(std::sync::RwLock::new(signing_key.verifying_key())),
                audit: InterceptorAudit::to_jsonl_in(dir.path()).expect("build emitter"),
            },
            authentication: AuthenticationMode::Insecure,
        };
        (service, dir)
    }

    fn offline_records(dir: &tempfile::TempDir) -> Vec<AuditEvent> {
        let written = std::fs::read_to_string(
            dir.path()
                .join("apf-policy-gateway-interceptor-audit.jsonl"),
        )
        .expect("audit log was written");
        written
            .lines()
            .map(|line| {
                let parsed: AuditEvent = serde_json::from_str(line).expect("deserializes");
                parsed.validate().expect("validates against the schema");
                parsed
            })
            .collect()
    }

    /// A sandbox whose spec changed between inject and validate is the TOCTOU
    /// case the phase exists to catch; an unrecorded one is invisible.
    #[tokio::test]
    async fn a_spec_digest_mismatch_at_validate_is_recorded() {
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let token = mint_test_jwt_with_spec_digest(&k, KEY_ID, "jti-v1", "digest-1", None, "aa");
        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/provenance-token", token.as_str()),
            ("apf.nvidia.com/correlation-id", "jti-v1"),
            ("apf.nvidia.com/document-digest", "digest-1"),
        ]);

        let result = svc.evaluate(Request::new(eval)).await.expect("answers");
        assert!(!result.into_inner().allowed);

        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.validate_denied.spec_digest_mismatch")
        );
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
        assert_eq!(r.verb.as_deref(), Some("interceptor.validate_sandbox"));
        assert!(
            r.error_info
                .as_ref()
                .is_some_and(|e| e.message.contains("changed between inject and validate")),
            "the refusal detail must reach the record: {:?}",
            r.error_info
        );
        // Verification requires the claim and the annotation to agree, so this
        // pins the value, not which of the two it came from.
        assert_eq!(r.bundle_digest.as_deref(), Some("digest-1"));
    }

    /// Absent and unverifiable are different failures and must not share a code.
    #[tokio::test]
    async fn validate_without_a_token_is_recorded_as_missing_not_invalid() {
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let eval = eval_with_annotations(vec![("apf.nvidia.com/correlation-id", "jti-v2")]);

        let result = svc.evaluate(Request::new(eval)).await.expect("answers");
        assert!(!result.into_inner().allowed);

        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.validate_denied.provenance_missing")
        );
        assert_eq!(r.bundle_digest.as_deref(), Some("unverified"));
    }

    /// Folding a present-but-bad token into "missing" erases the signal that
    /// someone presented a forged or expired one.
    #[tokio::test]
    async fn validate_with_an_unverifiable_token_is_recorded_as_invalid() {
        let k = key();
        let foreign = SigningKey::from_bytes(&[9u8; 32]);
        let (svc, dir) = offline_harness(&k);
        let token = mint_test_jwt(&foreign, KEY_ID, "jti-v3", "digest-1", None);
        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/provenance-token", token.as_str()),
            ("apf.nvidia.com/correlation-id", "jti-v3"),
            ("apf.nvidia.com/document-digest", "digest-1"),
        ]);

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );
        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.validate_denied.provenance_invalid")
        );
        assert_eq!(r.bundle_digest.as_deref(), Some("unverified"));
    }

    /// The allow must name the verified policy and revision, and must say when
    /// the TOCTOU check did not run.
    #[tokio::test]
    async fn validate_allowed_names_the_verified_policy() {
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let token = mint_test_jwt_full(&k, KEY_ID, "jti-v4", "digest-2", None, "", 42);
        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/provenance-token", token.as_str()),
            ("apf.nvidia.com/correlation-id", "jti-v4"),
            ("apf.nvidia.com/document-digest", "digest-2"),
        ]);

        assert!(
            svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );
        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.validate_allowed.no_spec_digest"),
            "the token carried no spec digest, so the check never ran"
        );
        assert_eq!(r.bundle_digest.as_deref(), Some("digest-2"));
        assert_eq!(
            r.policy_revision,
            Some(42),
            "the signed revision, not the caller's annotation"
        );
    }

    /// A caller supplying a policy body directly is a distinct attempt from an
    /// auto-approval setting, and both must be traceable.
    #[tokio::test]
    async fn a_direct_policy_mutation_is_recorded_with_what_was_attempted() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let mut op = BTreeMap::new();
        op.insert(
            "policy".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue("mine".to_string())),
            },
        );
        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::ModifyOperation(
                crate::proto::ModifyOperationEvaluation {
                    proposed_operation: Some(ProstStruct { fields: op }),
                },
            )),
            ..Default::default()
        };

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );
        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.direct_policy_mutation")
        );
        let message = r
            .error_info
            .as_ref()
            .map(|e| e.message.as_str())
            .unwrap_or_default();
        assert!(
            message.contains("policy: true"),
            "the record must name what was attempted: {message}"
        );
    }

    /// The base code, taken when the token carries a spec digest and it
    /// matches — the shorter half of a prefix pair, and the only one a
    /// prefix-matching consumer could silently conflate.
    #[tokio::test]
    async fn validate_allowed_with_a_matching_spec_digest_uses_the_base_code() {
        let k = key();
        let (svc, dir) = offline_harness(&k);
        // The spec digest over an operation carrying only annotations.
        let eval_for_digest = eval_with_annotations(vec![]);
        let op_json = context::operation_struct(&eval_for_digest)
            .map_or(serde_json::Value::Null, util::struct_to_json);
        let spec_digest = compute_spec_digest_from_op(&op_json);

        let token =
            mint_test_jwt_with_spec_digest(&k, KEY_ID, "jti-v5", "digest-3", None, &spec_digest);
        let eval = eval_with_annotations(vec![
            ("apf.nvidia.com/provenance-token", token.as_str()),
            ("apf.nvidia.com/correlation-id", "jti-v5"),
            ("apf.nvidia.com/document-digest", "digest-3"),
        ]);

        assert!(
            svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );
        assert_eq!(
            offline_records(&dir)[0].reason_code.as_deref(),
            Some("interceptor.validate_allowed"),
            "a matching spec digest must not report as skipped"
        );
    }

    /// The config path had no equivalent of the sandbox path's identity check,
    /// so the record could name a policy that was never injected.
    #[tokio::test]
    async fn a_config_response_disagreeing_with_its_token_is_refused() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        // Body matches the token's claim, so the body-digest check passes; only
        // the response's own digest field disagrees.
        let mut doc = signed_document(&k, "jti-c2", KEY_ID, None, 1);
        let claim_digest = doc.digest.clone();
        doc.digest = "c".repeat(64);
        let h = harness(&k, doc).await;

        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::ModifyOperation(
                crate::proto::ModifyOperationEvaluation {
                    proposed_operation: Some(ProstStruct {
                        fields: BTreeMap::new(),
                    }),
                },
            )),
            ..Default::default()
        };
        assert!(
            !h.service
                .evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );

        let r = &h.records()[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.policy_identity_mismatch")
        );
        assert_eq!(
            r.bundle_digest.as_deref(),
            Some(claim_digest.as_str()),
            "the token's claim, not the response's digest"
        );
    }

    /// Inject clean, then add a forbidden field before VALIDATE: the JWT and
    /// the spec digest both still pass, because the digest covers `/policy`
    /// only. VALIDATE is the last phase that can refuse.
    #[tokio::test]
    async fn a_field_added_after_injection_is_refused_at_validate() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);

        // A policy the digest is computed over, plus a forbidden sibling.
        let policy = ProstValue {
            kind: Some(prost_types::value::Kind::StringValue("p".to_string())),
        };
        let spec_digest =
            compute_spec_digest_from_policy(&serde_json::Value::String("p".to_string()));
        let token =
            mint_test_jwt_with_spec_digest(&k, KEY_ID, "jti-v6", "digest-4", None, &spec_digest);

        let mut ann = BTreeMap::new();
        for (key, value) in [
            ("apf.nvidia.com/provenance-token", token.as_str()),
            ("apf.nvidia.com/correlation-id", "jti-v6"),
            ("apf.nvidia.com/document-digest", "digest-4"),
        ] {
            ann.insert(
                key.to_string(),
                ProstValue {
                    kind: Some(prost_types::value::Kind::StringValue(value.to_string())),
                },
            );
        }
        let mut fields = BTreeMap::new();
        fields.insert("policy".to_string(), policy);
        fields.insert(
            "annotations".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StructValue(ProstStruct {
                    fields: ann,
                })),
            },
        );
        fields.insert(
            "merge_operations".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: vec![ProstValue {
                            kind: Some(prost_types::value::Kind::StringValue("op".to_string())),
                        }],
                    },
                )),
            },
        );

        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::Validate(crate::proto::ValidateEvaluation {
                proposed_operation: Some(ProstStruct { fields }),
                current_state: None,
            })),
            ..Default::default()
        };

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed,
            "a field added after injection must not pass the last enforcement phase"
        );
        assert_eq!(
            offline_records(&dir)[0].reason_code.as_deref(),
            Some("interceptor.validate_denied.post_injection_mutation")
        );
        assert_eq!(
            offline_records(&dir)[0].outcome,
            Some(apf_audit::Outcome::Refused),
            "the response denies, so the record must too"
        );
    }

    /// A body that does not hash to the digest in its own signed token is a
    /// tamper signal on the trust path, fleet-wide — P0, and previously
    /// enforced without a record.
    #[tokio::test]
    async fn a_config_body_not_matching_its_token_is_recorded() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        // Claim names a digest the body does not hash to.
        let doc = signed_document(&k, "jti-c3", KEY_ID, Some(&"d".repeat(64)), 1);
        let h = harness(&k, doc).await;

        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::ModifyOperation(
                crate::proto::ModifyOperationEvaluation {
                    proposed_operation: Some(ProstStruct {
                        fields: BTreeMap::new(),
                    }),
                },
            )),
            ..Default::default()
        };
        assert!(
            !h.service
                .evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );

        let r = &h.records()[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.body_digest_mismatch")
        );
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
    }

    /// The config VALIDATE provenance failure was the one refusal in this
    /// handler with no record while its four siblings gained one.
    #[tokio::test]
    async fn config_validate_without_provenance_is_recorded() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let mut fields = BTreeMap::new();
        // Not settings-only, so it reaches the provenance check.
        fields.insert(
            "policy".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue("p".to_string())),
            },
        );
        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::Validate(crate::proto::ValidateEvaluation {
                proposed_operation: Some(ProstStruct { fields }),
                current_state: None,
            })),
            ..Default::default()
        };

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );
        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.validate_denied.provenance_missing")
        );
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
        assert_eq!(r.bundle_digest.as_deref(), Some("unverified"));
    }

    /// The refusal and the denial it accompanies must carry the same id, or
    /// the record joins to the injection while the gateway's log joins to
    /// nothing.
    #[tokio::test]
    async fn a_settings_only_refusal_keys_on_the_injected_correlation_id() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let mut ann = BTreeMap::new();
        for (key, value) in [
            ("apf.nvidia.com/provenance-token", "t"),
            ("apf.nvidia.com/correlation-id", "jti-inj"),
        ] {
            ann.insert(
                key.to_string(),
                ProstValue {
                    kind: Some(prost_types::value::Kind::StringValue(value.to_string())),
                },
            );
        }
        let mut fields = BTreeMap::new();
        fields.insert(
            "annotations".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StructValue(ProstStruct {
                    fields: ann,
                })),
            },
        );
        fields.insert(
            "settingKey".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue(
                    "log_level".to_string(),
                )),
            },
        );
        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::Validate(crate::proto::ValidateEvaluation {
                proposed_operation: Some(ProstStruct { fields }),
                current_state: None,
            })),
            ..Default::default()
        };

        let result = svc
            .evaluate(Request::new(eval))
            .await
            .expect("answers")
            .into_inner();
        assert!(!result.allowed);
        assert_eq!(
            offline_records(&dir)[0].correlation_id,
            "jti-inj",
            "the record must key on the injection it describes"
        );
        assert_eq!(
            result
                .log_annotations
                .get("apf.nvidia.com/correlation-id")
                .map(String::as_str),
            Some("jti-inj"),
            "the denial must carry the same id as the record"
        );
    }

    /// Deletion, not addition: removing `/policy` after injection reclassifies
    /// the request as settings-only, which previously skipped the JWT check,
    /// the digest check and every sibling check.
    #[tokio::test]
    async fn removing_the_injected_policy_before_validate_is_refused() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);

        let mut ann = BTreeMap::new();
        ann.insert(
            "apf.nvidia.com/provenance-token".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue("t".to_string())),
            },
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "annotations".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StructValue(ProstStruct {
                    fields: ann,
                })),
            },
        );
        // No `policy`: it was injected at MODIFY and removed since.
        fields.insert(
            "settingKey".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue(
                    "log_level".to_string(),
                )),
            },
        );

        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::Validate(crate::proto::ValidateEvaluation {
                proposed_operation: Some(ProstStruct { fields }),
                current_state: None,
            })),
            ..Default::default()
        };

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed,
            "an injected policy removed before validation must not pass"
        );
        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.validate_denied.post_injection_mutation")
        );
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
    }

    /// The auto-approval check reads two nested keys; accepting only matched
    /// spelling pairs let a cross-spelled producer through as settings-only.
    #[tokio::test]
    async fn a_cross_spelled_auto_approval_setting_is_still_denied() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let mut fields = BTreeMap::new();
        fields.insert(
            "settingKey".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue(
                    "proposal_approval_mode".to_string(),
                )),
            },
        );
        let mut inner = BTreeMap::new();
        inner.insert(
            "string_value".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue("auto".to_string())),
            },
        );
        fields.insert(
            "settingValue".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StructValue(ProstStruct {
                    fields: inner,
                })),
            },
        );
        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::ModifyOperation(
                crate::proto::ModifyOperationEvaluation {
                    proposed_operation: Some(ProstStruct { fields }),
                },
            )),
            ..Default::default()
        };

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed,
            "a mixed-convention setting must not pass as settings-only"
        );
        assert_eq!(
            offline_records(&dir)[0].reason_code.as_deref(),
            Some("interceptor.govern_denied.approval_mode_change")
        );
    }

    /// The protobuf field name must be recognised too. Recognising only the
    /// camelCase spelling let a caller present merge operations that neither
    /// the settings-only classifier nor the direct-mutation denial saw.
    #[tokio::test]
    async fn snake_case_merge_operations_are_still_denied_and_recorded() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let mut op = settings_only_operation_fields("some_setting", "value");
        op.fields.insert(
            "merge_operations".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: vec![ProstValue {
                            kind: Some(prost_types::value::Kind::StringValue("op".to_string())),
                        }],
                    },
                )),
            },
        );
        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::ModifyOperation(
                crate::proto::ModifyOperationEvaluation {
                    proposed_operation: Some(op),
                },
            )),
            ..Default::default()
        };

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed,
            "merge operations must be denied whichever spelling they arrive in"
        );
        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.direct_policy_mutation")
        );
        let message = r
            .error_info
            .as_ref()
            .map(|e| e.message.as_str())
            .unwrap_or_default();
        assert!(
            message.contains("merge_operations: true"),
            "the record must name the attempt: {message}"
        );
    }

    /// The case the detail exists for: with both a policy body and an
    /// auto-approval setting, the code names one and the detail must name both,
    /// or a caller picks which attempt is visible by adding a field.
    #[tokio::test]
    async fn both_attempts_are_named_when_a_request_carries_both() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let mut op = settings_only_operation_fields("proposal_approval_mode", "auto");
        op.fields.insert(
            "policy".to_string(),
            ProstValue {
                kind: Some(prost_types::value::Kind::StringValue("mine".to_string())),
            },
        );
        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::ModifyOperation(
                crate::proto::ModifyOperationEvaluation {
                    proposed_operation: Some(op),
                },
            )),
            ..Default::default()
        };

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );
        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.approval_mode_change")
        );
        let message = r
            .error_info
            .as_ref()
            .map(|e| e.message.as_str())
            .unwrap_or_default();
        assert!(
            message.contains("policy: true") && message.contains("auto_approval: true"),
            "the record must name both attempts, not just the one it is coded for: {message}"
        );
    }

    /// The deployment-wide injection. Distinct from the sandbox path's code
    /// because this handler never verifies the token — a consumer filtering on
    /// `policy_injected` must not pick this up as verified.
    #[tokio::test]
    async fn a_config_policy_injection_is_recorded_as_unverified() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let doc = signed_document(&k, "jti-c1", KEY_ID, None, 1);
        let expected_digest = doc.digest.clone();
        let h = harness(&k, doc).await;

        let eval = InterceptorEvaluation {
            method: "UpdateConfig".to_string(),
            phase: Some(Phase::ModifyOperation(
                crate::proto::ModifyOperationEvaluation {
                    proposed_operation: Some(ProstStruct {
                        fields: BTreeMap::new(),
                    }),
                },
            )),
            ..Default::default()
        };
        let result = h
            .service
            .evaluate(Request::new(eval))
            .await
            .expect("answers")
            .into_inner();
        assert!(result.allowed, "a clean config refresh is permitted");

        let r = &h.records()[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.policy_injected.unverified"),
            "must not read as the verified sandbox injection"
        );
        assert_eq!(r.bundle_digest.as_deref(), Some(expected_digest.as_str()));
        assert_eq!(
            r.correlation_id, "jti-c1",
            "must join to the id injected into the config annotations"
        );
        assert_eq!(r.session_id, None, "a config change belongs to no sandbox");
    }

    /// The auto-approval attempt at VALIDATE is a separate site from the one at
    /// MODIFY and was previously unexercised.
    #[tokio::test]
    async fn an_approval_mode_change_at_validate_is_recorded() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let eval = settings_only_update_config_evaluation(Phase::Validate(
            crate::proto::ValidateEvaluation {
                proposed_operation: Some(settings_only_operation_fields(
                    "proposal_approval_mode",
                    "auto",
                )),
                current_state: None,
            },
        ));

        assert!(
            !svc.evaluate(Request::new(eval))
                .await
                .expect("answers")
                .into_inner()
                .allowed
        );
        assert_eq!(
            offline_records(&dir)[0].reason_code.as_deref(),
            Some("interceptor.validate_denied.approval_mode_change")
        );
    }

    /// APF owns approval mode, so any caller change to it is a governance
    /// bypass attempt and the record is its only trace.
    #[tokio::test]
    async fn an_approval_mode_change_is_recorded() {
        use crate::proto::interceptor_evaluation::Phase;
        let k = key();
        let (svc, dir) = offline_harness(&k);
        let eval = settings_only_update_config_evaluation(Phase::ModifyOperation(
            crate::proto::ModifyOperationEvaluation {
                proposed_operation: Some(settings_only_operation_fields(
                    "proposal_approval_mode",
                    "auto",
                )),
            },
        ));

        let result = svc.evaluate(Request::new(eval)).await.expect("answers");
        assert!(!result.into_inner().allowed);

        let r = &offline_records(&dir)[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.govern_denied.approval_mode_change")
        );
        assert_eq!(r.verb.as_deref(), Some("interceptor.update_config"));
        assert_eq!(
            r.session_id, None,
            "a config operation belongs to no sandbox"
        );
    }

    async fn evaluate(h: &Harness) -> InterceptorResult {
        h.service
            .evaluate(Request::new(create_sandbox_modify("sbx-9", "alice@corp")))
            .await
            .expect("evaluate answers")
            .into_inner()
    }

    /// The record must name the policy the token proves and the caller who
    /// asked, and must be joinable to the sandbox by correlation id.
    #[tokio::test]
    async fn an_injected_policy_is_recorded_against_the_verified_token() {
        let k = key();
        let doc = signed_document(&k, "jti-1", KEY_ID, None, 1);
        let expected_digest = doc.digest.clone();
        let h = harness(&k, doc).await;

        let result = evaluate(&h).await;
        assert!(result.allowed, "a valid document must be admitted");

        let records = h.records();
        assert_eq!(records.len(), 1, "exactly one record per admission");
        let r = &records[0];
        assert_eq!(r.event_type, apf_audit::EventType::PolicyInjection);
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Success));
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.policy_injected")
        );
        assert_eq!(r.bundle_digest.as_deref(), Some(expected_digest.as_str()));
        assert_eq!(
            r.policy_revision,
            Some(1),
            "from the token, not the response"
        );
        assert_eq!(r.correlation_id, "jti-1", "joins to the sandbox annotation");
        assert_eq!(r.session_id.as_deref(), Some("sbx-9"));
        assert_eq!(r.user_id.as_deref(), Some("alice@corp"));

        // The record has to say what the injection changed, not only that one
        // happened — otherwise reconstructing it means going back to the bundle.
        let effects = r.effects.as_ref().expect("the injection is recorded");
        let count = effects.patch_count.expect("patch count recorded");
        assert!(count > 0, "an injection that patched nothing is not one");
        assert_eq!(effects.patches.len() as u64, count, "every patch listed");
        assert!(
            effects.patches.iter().all(|p| p.path.starts_with('/')),
            "JSON pointers, not values: {:?}",
            effects.patches
        );
        assert!(
            effects
                .patches
                .iter()
                .any(|p| p.path.contains("document-digest")),
            "the provenance annotation stamps are named: {:?}",
            effects.patches
        );
        // Fidelity, not just presence: each audited (path, op) pair must match
        // what the response actually carried, or the record claims different
        // spec edits than the ones made.
        assert_eq!(effects.patches.len(), result.patches.len());
        for (recorded, actual) in effects.patches.iter().zip(&result.patches) {
            assert_eq!(recorded.path, actual.path);
            assert_eq!(recorded.op.as_str(), actual.op, "op for {}", actual.path);
        }
        // The token is a patch VALUE. Recording paths must never carry it.
        let line = serde_json::to_string(r).expect("record serializes");
        assert!(
            !line.contains("token\":\"ey"),
            "no patch value may reach the record: {line}"
        );

        // The other half of the join: a record naming an id the sandbox does
        // not carry is unusable, and VALIDATE reads this same annotation.
        let annotation = result
            .patches
            .iter()
            .find(|p| p.path.ends_with("correlation-id"))
            .expect("correlation-id annotation is injected");
        let injected = annotation
            .value
            .as_ref()
            .and_then(|v| match v.kind.as_ref() {
                Some(prost_types::value::Kind::StringValue(s)) => Some(s.as_str()),
                _ => None,
            })
            .expect("annotation carries a string");
        assert_eq!(
            injected, "jti-1",
            "the sandbox must carry the id the record names"
        );
    }

    /// The digest must come from the signed token, never the response — the
    /// response is unsigned and can name a different policy.
    #[tokio::test]
    async fn a_response_disagreeing_with_the_token_is_refused() {
        let k = key();
        let doc = signed_document(&k, "jti-2", KEY_ID, Some(&"b".repeat(64)), 1);
        let h = harness(&k, doc).await;

        let result = evaluate(&h).await;
        assert!(!result.allowed);

        let records = h.records();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].reason_code.as_deref(),
            Some("interceptor.inject_denied.policy_identity_mismatch")
        );
        assert_eq!(records[0].outcome, Some(apf_audit::Outcome::Refused));
        assert_eq!(
            records[0].bundle_digest.as_deref(),
            Some("b".repeat(64).as_str()),
            "the record names the signed token's policy, not the response's"
        );
    }

    /// VALIDATE re-checks the digest but never the version, so a version-only
    /// disagreement would otherwise reach a running sandbox.
    #[tokio::test]
    async fn a_version_only_disagreement_is_refused() {
        let k = key();
        let doc = signed_document(&k, "jti-6", KEY_ID, None, 9);
        let h = harness(&k, doc).await;

        assert!(!evaluate(&h).await.allowed);
        let r = &h.records()[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.inject_denied.policy_identity_mismatch")
        );
        assert_eq!(
            r.policy_revision,
            Some(1),
            "the record names the token's revision, not the response's 9"
        );
    }

    /// The identity check intercepts a disagreeing digest, so this is reached
    /// only when the response and token agree and the body does not hash to
    /// what they both claim.
    #[tokio::test]
    async fn a_body_that_does_not_match_its_digest_is_refused() {
        let k = key();
        let mut doc = signed_document(&k, "jti-7", KEY_ID, None, 1);
        // Digest and claim still agree; the body no longer hashes to either.
        doc.body.push(0);
        let h = harness(&k, doc).await;

        assert!(!evaluate(&h).await.allowed);
        let r = &h.records()[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.inject_denied.body_digest_mismatch")
        );
        assert_eq!(r.outcome, Some(apf_audit::Outcome::Refused));
    }

    /// The third conjunct of the claims filter. Without it a token with an
    /// empty digest claim is still denied, but under the wrong reason code —
    /// so only the code distinguishes the two.
    #[tokio::test]
    async fn a_token_without_a_document_digest_is_refused_as_a_bad_token() {
        let k = key();
        let mut doc = signed_document(&k, "jti-8", KEY_ID, None, 1);
        doc.provenance_token = mint_test_jwt(&k, KEY_ID, "jti-8", "", None);
        let h = harness(&k, doc).await;

        assert!(!evaluate(&h).await.allowed);
        assert_eq!(
            h.records()[0].reason_code.as_deref(),
            Some("interceptor.inject_denied.invalid_jwt"),
            "an unusable claim is a bad token, not a policy mismatch"
        );
    }

    /// Revision 0 is the anti-rollback floor, not a revision the token carried,
    /// so it must be recorded as absent rather than as fact.
    #[tokio::test]
    async fn revision_zero_is_recorded_as_absent() {
        let k = key();
        let mut doc = signed_document(&k, "jti-9", KEY_ID, None, 0);
        doc.provenance_token = mint_test_jwt_full(&k, KEY_ID, "jti-9", &doc.digest, None, "", 0);
        let h = harness(&k, doc).await;

        assert!(evaluate(&h).await.allowed);
        assert_eq!(h.records()[0].policy_revision, None);
    }

    /// A token carrying no `jti` would admit a sandbox whose record joins to
    /// nothing, because VALIDATE compares the empty annotation to the empty
    /// claim and passes.
    #[tokio::test]
    async fn a_token_without_a_jti_is_refused() {
        let k = key();
        let doc = signed_document(&k, "", KEY_ID, None, 1);
        let h = harness(&k, doc).await;

        assert!(!evaluate(&h).await.allowed);
        let records = h.records();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].reason_code.as_deref(),
            Some("interceptor.inject_denied.invalid_jwt")
        );
    }

    /// Asserted separately from the `jti` case: with only one of the two,
    /// dropping either conjunct from the claims filter still passes.
    #[tokio::test]
    async fn a_token_without_a_signer_identity_is_refused() {
        let k = key();
        let doc = signed_document(&k, "jti-3", "", None, 1);
        let h = harness(&k, doc).await;

        assert!(!evaluate(&h).await.allowed);
        assert_eq!(
            h.records()[0].reason_code.as_deref(),
            Some("interceptor.inject_denied.invalid_jwt")
        );
    }

    /// Nothing is proven before the token verifies, so the record names no
    /// policy rather than one the response merely asserted.
    #[tokio::test]
    async fn a_document_with_no_token_is_refused_without_naming_a_policy() {
        let k = key();
        let mut doc = signed_document(&k, "jti-4", KEY_ID, None, 1);
        doc.provenance_token = String::new();
        let h = harness(&k, doc).await;

        assert!(!evaluate(&h).await.allowed);
        let r = &h.records()[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.inject_denied.no_provenance_token")
        );
        assert_eq!(r.bundle_digest.as_deref(), Some("unverified"));
        assert_eq!(r.policy_revision, None);
    }

    /// A token signed by a key the gateway does not trust.
    #[tokio::test]
    async fn a_foreign_signed_token_is_refused() {
        let trusted = key();
        let foreign = SigningKey::from_bytes(&[9u8; 32]);
        let doc = signed_document(&foreign, "jti-5", KEY_ID, None, 1);
        let h = harness(&trusted, doc).await;

        assert!(!evaluate(&h).await.allowed);
        let r = &h.records()[0];
        assert_eq!(
            r.reason_code.as_deref(),
            Some("interceptor.inject_denied.invalid_jwt")
        );
        assert_eq!(r.bundle_digest.as_deref(), Some("unverified"));
    }
}
