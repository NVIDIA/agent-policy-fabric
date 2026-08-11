// SPDX-License-Identifier: Apache-2.0
// Convert a GetDocumentResponse body into RFC 6902 JSON patches for sandbox and provider objects.

use prost::Message;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};

use crate::proto::JsonPatch;
use apf_proto::json::json_to_proto_value;
use apf_proto::policy_service_v1alpha1::GetDocumentResponse;
use apf_proto::openshell_sandbox::SandboxPolicy;

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

    #[allow(clippy::items_after_statements)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use apf_proto::openshell_sandbox::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicyRule, ProcessPolicy, SandboxPolicy,
    };
    use prost::Message;
    use prost_types::value::Kind;

    /// Fake JWT with no apf/document-digest claim so body-integrity check is skipped in tests.
    fn fake_token() -> String {
        use base64::Engine as _;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","kid":"test","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"jti":"test-jti","sub":"test","iat":1,"apf/document-digest":"","apf/version":1}"#,
        );
        format!("{header}.{payload}.fakesig")
    }

    /// Fake JWT with the given body digest in the apf/document-digest claim.
    fn fake_token_with_digest(body: &[u8]) -> String {
        use base64::Engine as _;
        let digest = hex::encode(Sha256::digest(body));
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","kid":"test","typ":"JWT"}"#);
        let payload_json = format!(
            r#"{{"jti":"test-jti","sub":"test","iat":1,"apf/document-digest":"{digest}","apf/version":1}}"#
        );
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        format!("{header}.{payload}.fakesig")
    }

    fn signed_doc(policy: SandboxPolicy) -> GetDocumentResponse {
        let mut body = Vec::new();
        policy.encode(&mut body).expect("encode");
        GetDocumentResponse {
            body,
            digest: "sha256-aabbcc".to_string(),
            version: 1,
            valid_until_ms: 0,
            provenance_token: fake_token(),
        }
    }

    fn no_token_doc() -> GetDocumentResponse {
        GetDocumentResponse {
            body: vec![],
            digest: "sha256-aabbcc".to_string(),
            version: 1,
            valid_until_ms: 0,
            provenance_token: String::new(),
        }
    }

    #[test]
    fn no_provenance_token_returns_unsigned_error() {
        let err = sandbox_policy_patches(&no_token_doc()).unwrap_err();
        assert!(matches!(err, PatchError::UnsignedProjection));
    }

    #[test]
    fn body_digest_mismatch_returns_error() {
        let body = b"some-body-bytes".to_vec();
        let wrong_digest_token = {
            use base64::Engine as _;
            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(r#"{"jti":"x","sub":"k","iat":1,"apf/document-digest":"deadbeef00","apf/version":1}"#);
            format!("{header}.{payload}.sig")
        };
        let doc = GetDocumentResponse {
            body: body.clone(),
            digest: "sha256-aabbcc".to_string(),
            version: 1,
            valid_until_ms: 0,
            provenance_token: wrong_digest_token,
        };
        let err = sandbox_policy_patches(&doc).unwrap_err();
        assert!(matches!(err, PatchError::BodyDigestMismatch));
    }

    #[test]
    fn body_digest_match_passes() {
        let policy = SandboxPolicy {
            version: 1,
            filesystem: None,
            landlock: None,
            process: None,
            network_policies: std::collections::HashMap::new(),
            network_middlewares: std::collections::HashMap::new(),
        };
        let mut body = Vec::new();
        policy.encode(&mut body).expect("encode");
        let token = fake_token_with_digest(&body);
        let doc = GetDocumentResponse {
            body,
            digest: "sha256-aabbcc".to_string(),
            version: 1,
            valid_until_ms: 0,
            provenance_token: token,
        };
        let patches = sandbox_policy_patches(&doc).unwrap();
        assert_eq!(patches.len(), 1);
    }

    #[test]
    fn valid_signed_body_returns_patch() {
        let policy = SandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/etc".to_string()],
                read_write: vec![],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProcessPolicy {
                run_as_user: "nobody".to_string(),
                run_as_group: "nogroup".to_string(),
            }),
            network_policies: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "default".to_string(),
                    NetworkPolicyRule {
                        name: "default".to_string(),
                        endpoints: vec![],
                        binaries: vec![],
                    },
                );
                m
            },
            network_middlewares: std::collections::HashMap::new(),
        };
        let doc = signed_doc(policy);
        let patches = sandbox_policy_patches(&doc).unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].op, "add");
        assert_eq!(patches[0].path, "/spec/policy");
    }

    #[test]
    fn patches_omit_absent_optional_fields() {
        let policy = SandboxPolicy {
            version: 1,
            filesystem: None,
            landlock: None,
            process: None,
            network_policies: std::collections::HashMap::new(),
            network_middlewares: std::collections::HashMap::new(),
        };
        let doc = signed_doc(policy);
        let patches = sandbox_policy_patches(&doc).unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].path, "/spec/policy");
    }

    fn signed_provider_doc(yaml_body: Vec<u8>) -> GetDocumentResponse {
        GetDocumentResponse {
            body: yaml_body,
            digest: "sha256-ppdigest".to_string(),
            version: 1,
            valid_until_ms: 0,
            provenance_token: fake_token(),
        }
    }

    fn unsigned_provider_doc() -> GetDocumentResponse {
        GetDocumentResponse {
            body: b"id: github\n".to_vec(),
            digest: "sha256-ppdigest".to_string(),
            version: 1,
            valid_until_ms: 0,
            provenance_token: String::new(),
        }
    }

    #[test]
    fn annotations_init_patch_adds_empty_object() {
        let patch = annotations_init_patch();
        assert_eq!(patch.op, "add");
        assert_eq!(patch.path, "/annotations");
        let value = patch.value.expect("value present");
        assert!(matches!(value.kind, Some(Kind::StructValue(s)) if s.fields.is_empty()));
    }

    #[test]
    fn annotation_patch_escapes_slash_in_key() {
        let patch = annotation_patch("apf.nvidia.com/document-digest", "sha256:abc");
        assert_eq!(patch.op, "add");
        assert_eq!(patch.path, "/annotations/apf.nvidia.com~1document-digest");
    }

    #[test]
    fn provider_empty_docs_returns_empty_patches() {
        let docs: Vec<(usize, String, GetDocumentResponse)> = vec![];
        let patches = provider_profile_patches(&docs).unwrap();
        assert!(patches.is_empty());
    }

    #[test]
    fn provider_unsigned_doc_returns_error() {
        let docs = vec![(0usize, "github".to_string(), unsigned_provider_doc())];
        let err = provider_profile_patches(&docs).unwrap_err();
        assert!(matches!(err, PatchError::UnsignedProjection));
    }

    #[test]
    fn provider_single_signed_doc_returns_one_replace_patch() {
        let yaml_body = b"id: github\ndisplay_name: GitHub\ncategory: source_control\n".to_vec();
        let docs = vec![(0usize, "github".to_string(), signed_provider_doc(yaml_body))];
        let patches = provider_profile_patches(&docs).unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].op, "replace");
        assert_eq!(patches[0].path, "/profiles/0/profile");
        assert!(patches[0].value.is_some());
    }

    #[test]
    fn provider_two_signed_docs_return_two_replace_patches() {
        let yaml_gh = b"id: github\ndisplay_name: GitHub\n".to_vec();
        let yaml_gl = b"id: gitlab\ndisplay_name: GitLab\n".to_vec();
        let docs = vec![
            (0usize, "github".to_string(), signed_provider_doc(yaml_gh)),
            (1usize, "gitlab".to_string(), signed_provider_doc(yaml_gl)),
        ];
        let patches = provider_profile_patches(&docs).unwrap();
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0].op, "replace");
        assert_eq!(patches[0].path, "/profiles/0/profile");
        assert_eq!(patches[1].op, "replace");
        assert_eq!(patches[1].path, "/profiles/1/profile");
    }

    #[test]
    fn provider_original_index_used_for_patch_path() {
        let yaml_body = b"id: gitlab\ndisplay_name: GitLab\n".to_vec();
        let docs = vec![(2usize, "gitlab".to_string(), signed_provider_doc(yaml_body))];
        let patches = provider_profile_patches(&docs).unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].path, "/profiles/2/profile");
    }

    #[test]
    fn extract_provenance_claims_roundtrip() {
        use base64::Engine as _;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","kid":"test-key","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"jti":"abc-123","sub":"test-key","iat":1000,"exp":2000,"apf/document-digest":"deadbeef","apf/version":7,"apf/spec-digest":"cafebabe"}"#,
        );
        let jwt = format!("{header}.{payload}.fakesig");

        let claims = extract_provenance_claims(&jwt).expect("should parse");
        assert_eq!(claims.jti, "abc-123");
        assert_eq!(claims.sub, "test-key");
        assert_eq!(claims.exp, 2000);
        assert_eq!(claims.apf_document_digest, "deadbeef");
        assert_eq!(claims.apf_version, 7);
        assert_eq!(claims.apf_spec_digest, "cafebabe");
    }

    #[test]
    fn extract_provenance_claims_returns_none_for_garbage() {
        assert!(extract_provenance_claims("not.a.jwt.at.all").is_none());
        assert!(extract_provenance_claims("").is_none());
        assert!(extract_provenance_claims("header.!!!.sig").is_none());
    }

    #[test]
    fn extract_provenance_claims_no_exp_defaults_to_zero() {
        use base64::Engine as _;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"jti":"x","sub":"k","iat":1,"apf/document-digest":"dd","apf/version":1}"#);
        let jwt = format!("{header}.{payload}.sig");
        let claims = extract_provenance_claims(&jwt).expect("should parse");
        assert_eq!(claims.exp, 0);
    }
}
