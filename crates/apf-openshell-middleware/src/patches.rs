// SPDX-License-Identifier: Apache-2.0
// Convert a GetDocumentResponse body into RFC 6902 JSON patches for sandbox and provider objects.

use prost::Message;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};

use apf_proto::gateway_interceptor_v1::JsonPatch;
use apf_proto::json::json_to_proto_value;
use apf_proto::openshell_sandbox::SandboxPolicy;
use apf_proto::policy_service_v1alpha1::GetDocumentResponse;

/// Decoded claims from the policy-service-minted provenance JWT.
///
/// Extracted without signature verification at inject time to populate annotations.
/// Full signature verification runs at VALIDATE time using the cached JWKS-derived key.
#[derive(Debug, Clone)]
pub struct ProvenanceClaims {
    /// Unique token ID — stored as `apf.nvidia.com/correlation-id`.
    pub jti: String,
    /// Verifier key id — stored as `apf.nvidia.com/signer-identity`.
    pub sub: String,
    /// Expiry Unix seconds (0 = no expiry declared).
    pub exp: u64,
    /// Policy digest hex.
    pub apf_document_digest: String,
    /// Bundle version counter.
    pub apf_version: u64,
    /// Hex-encoded SHA-256 of the canonical JSON `{ "policy": <SandboxPolicy> }`.
    /// Empty for non-sandbox document kinds.
    pub apf_spec_digest: String,
    /// Bundle manifest `id` — stored as `apf.nvidia.com/bundle-id`.
    pub apf_bundle_id: String,
}

/// Raw claims shape used only for JSON deserialization.
#[derive(Debug, Deserialize)]
struct RawClaims {
    #[serde(default)]
    jti: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    exp: u64,
    #[serde(rename = "apf/document-digest", default)]
    apf_document_digest: String,
    #[serde(rename = "apf/version", default)]
    apf_version: u64,
    #[serde(rename = "apf/spec-digest", default)]
    apf_spec_digest: String,
    #[serde(rename = "apf/bundle-id", default)]
    apf_bundle_id: String,
}

/// Decode the payload segment of a compact JWT without verifying the signature.
///
/// Used at inject time to read `jti`, `sub`, `exp`, `apf/document-digest`, `apf/version`
/// for annotation population. Signature verification is deferred to VALIDATE
/// using the cached JWKS-derived verifying key.
///
/// Returns `None` when the JWT is not a valid three-part compact serialization or
/// when the payload is not valid base64url-encoded JSON.
#[must_use]
pub fn extract_provenance_claims(jwt: &str) -> Option<ProvenanceClaims> {
    let mut parts = jwt.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;

    use base64::Engine as _;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let raw: RawClaims = serde_json::from_slice(&payload_bytes).ok()?;

    Some(ProvenanceClaims {
        jti: raw.jti,
        sub: raw.sub,
        exp: raw.exp,
        apf_document_digest: raw.apf_document_digest,
        apf_version: raw.apf_version,
        apf_spec_digest: raw.apf_spec_digest,
        apf_bundle_id: raw.apf_bundle_id,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    #[error("policy projection has no provenance token")]
    UnsignedProjection,
    #[error("body digest does not match JWT apf/document-digest claim")]
    BodyDigestMismatch,
    #[error("failed to decode SandboxPolicy: {0}")]
    Decode(String),
    #[error("failed to serialize policy to JSON: {0}")]
    Serialize(String),
    #[error("provider profile YAML decode failed: {0}")]
    YamlDecode(String),
}

/// Build RFC 6902 add-patches from the policy-service-vended `GetDocumentResponse`.
///
/// Fails closed (`PatchError::UnsignedProjection`) when the response carries no
/// `provenance_token`.
///
/// Also checks `SHA-256(body) == JWT apf/document-digest` to catch corruption or swap
/// between the daemon and interceptor (`PatchError::BodyDigestMismatch`).
pub fn sandbox_policy_patches(doc: &GetDocumentResponse) -> Result<Vec<JsonPatch>, PatchError> {
    if doc.provenance_token.is_empty() {
        return Err(PatchError::UnsignedProjection);
    }

    // Verify body integrity: the hex-encoded SHA-256 of body must match the
    // JWT apf/document-digest claim decoded without signature verification.
    if let Some(claims) = extract_provenance_claims(&doc.provenance_token) {
        let actual_digest = hex::encode(Sha256::digest(&doc.body));
        if !claims.apf_document_digest.is_empty() && actual_digest != claims.apf_document_digest {
            return Err(PatchError::BodyDigestMismatch);
        }
    }

    let policy =
        SandboxPolicy::decode(doc.body.as_ref()).map_err(|e| PatchError::Decode(e.to_string()))?;

    // Serialize via the shared descriptor-driven proto3-JSON path so the injected
    // policy is byte-identical to what the daemon digested and what the gateway
    // re-encodes for VALIDATE. Hand-building here would drop or add fields (e.g.
    // `ports`) that the digest covers, breaking the spec-digest integrity check.
    let policy_value = apf_proto::spec_digest::sandbox_policy_to_json(&policy);

    Ok(vec![JsonPatch {
        op: "add".to_string(),
        path: "/spec/policy".to_string(),
        from: String::new(),
        value: Some(json_to_proto_value(&policy_value).map_err(PatchError::Serialize)?),
    }])
}

/// Build RFC 6902 replace-patches from policy-service-vended provider profile `GetDocumentResponse` docs.
///
/// Each entry in `docs` is `(original_profile_index, profile_id, doc)` where
/// `original_profile_index` is the position of this profile in the object's `profiles` array.
/// Using the caller-supplied index instead of the iteration index avoids path drift when
/// profiles without an `id` are skipped during collection.
pub fn provider_profile_patches(
    docs: &[(usize, String, GetDocumentResponse)],
) -> Result<Vec<JsonPatch>, PatchError> {
    let mut patches = Vec::new();
    for (original_index, _profile_id, doc) in docs {
        if doc.provenance_token.is_empty() {
            return Err(PatchError::UnsignedProjection);
        }
        let profile_value: JsonValue =
            serde_yaml::from_slice(&doc.body).map_err(|e| PatchError::YamlDecode(e.to_string()))?;
        let proto_value = json_to_proto_value(&profile_value).map_err(PatchError::Serialize)?;
        patches.push(JsonPatch {
            op: "replace".to_string(),
            path: format!("/profiles/{original_index}/profile"),
            from: String::new(),
            value: Some(proto_value),
        });
    }
    Ok(patches)
}

/// Build a JSON Patch that initializes an empty `annotations` object.
///
/// RFC 6902 `add` to `/annotations/key` fails when the parent object does not
/// exist. proto3 JSON omits empty maps, so a request built without annotations
/// carries no `annotations` field. Prepend this before any [`annotation_patch`]
/// entries when the target operation has no `annotations` map.
#[must_use]
pub fn annotations_init_patch() -> JsonPatch {
    JsonPatch {
        op: "add".to_string(),
        path: "/annotations".to_string(),
        value: Some(
            json_to_proto_value(&JsonValue::Object(serde_json::Map::new()))
                .expect("empty object is always a valid proto value"),
        ),
        from: String::new(),
    }
}

/// Build a JSON Patch that writes `value` into `operation.annotations[key]`.
///
/// JSON Pointer requires `~` → `~0` and `/` → `~1` escaping inside path segments.
#[must_use]
pub fn annotation_patch(key: &str, value: &str) -> JsonPatch {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    JsonPatch {
        op: "add".to_string(),
        path: format!("/annotations/{escaped}"),
        value: Some(
            json_to_proto_value(&JsonValue::String(value.to_string()))
                .expect("string is always a valid proto value"),
        ),
        from: String::new(),
    }
}
