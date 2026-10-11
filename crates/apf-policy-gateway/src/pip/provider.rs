// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract types shared by every provider transport: the lookup, the
//! validated answer, the error taxonomy, and output validation.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use apf_policy_eval::ProviderStatus;
use apf_proto::json::struct_to_json;
use apf_proto::pip_v1alpha1::{AttributeStatus, EvaluationSubject, GetAttributesResponse};
use prost::Message as _;
use serde_json::{Map, Value};
use tonic::{Request, Status, transport::server::UdsConnectInfo};

/// Size cap on a request or response message.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Length cap on an evidence reference.
pub const MAX_EVIDENCE_REF_CHARS: usize = 128;
/// Nesting cap on claim values.
pub const MAX_CLAIM_DEPTH: usize = 16;
/// Length cap on a claim key.
pub const MAX_KEY_BYTES: usize = 128;
/// Largest integer that survives the Struct wire format without loss.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// One attribute lookup against one provider.
#[derive(Debug, Clone, PartialEq)]
pub struct Lookup {
    /// The evaluation subject projected to the provider's declared paths.
    pub subject: EvaluationSubject,
    /// Domain the provider is registered for.
    pub domain: String,
    /// Caller-supplied correlation id, forwarded for audit joins.
    pub correlation_id: String,
}

/// Validated attributes a provider returned for one domain.
#[derive(Debug, Clone, PartialEq)]
pub struct Attributes {
    /// Claim record without `_meta`.
    pub claims: Map<String, Value>,
    /// Remaining freshness the provider advertised.
    pub ttl_seconds: u32,
    /// Age of the underlying facts when the provider answered.
    pub age_seconds: u32,
    /// Audit pointer to the evidence behind the attributes.
    pub evidence_ref: Option<String>,
}

/// Outcome of a successful lookup.
#[derive(Debug, Clone, PartialEq)]
pub enum LookupResult {
    Found(Attributes),
    /// The provider holds nothing for the subject.
    NoData,
}

/// Why a lookup produced no answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("provider did not answer within its budget")]
    Timeout,
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("provider in-flight limit reached")]
    Capacity,
    #[error("evaluation input could not be sent: {0}")]
    InvalidInput(String),
    #[error("provider output rejected: {0}")]
    InvalidOutput(String),
    #[error("provider refused the gateway: {0}")]
    Unauthorized(String),
    #[error("provider misconfigured: {0}")]
    Misconfigured(String),
}

impl ProviderError {
    /// The status recorded in provenance and deny reasons.
    #[must_use]
    pub const fn status(&self) -> ProviderStatus {
        match self {
            Self::Timeout => ProviderStatus::Timeout,
            Self::Unavailable(_) => ProviderStatus::Unavailable,
            Self::Capacity => ProviderStatus::Capacity,
            Self::InvalidInput(_) => ProviderStatus::InvalidInput,
            Self::InvalidOutput(_) => ProviderStatus::InvalidOutput,
            Self::Unauthorized(_) => ProviderStatus::Unauthorized,
            Self::Misconfigured(_) => ProviderStatus::Misconfigured,
        }
    }

    /// Map a gRPC status from a provider onto the error taxonomy.
    #[must_use]
    pub fn from_status(status: &Status) -> Self {
        use tonic::Code;
        match status.code() {
            Code::DeadlineExceeded => Self::Timeout,
            Code::ResourceExhausted => Self::Capacity,
            Code::InvalidArgument => Self::InvalidInput(status.message().to_owned()),
            Code::Unauthenticated | Code::PermissionDenied => {
                Self::Unauthorized(status.message().to_owned())
            }
            Code::Unimplemented | Code::FailedPrecondition => {
                Self::Misconfigured(status.message().to_owned())
            }
            code => Self::Unavailable(format!("{code:?}")),
        }
    }
}

/// Future returned by [`ProviderTransport::lookup`].
pub type LookupFuture<'a> =
    Pin<Box<dyn Future<Output = Result<LookupResult, ProviderError>> + Send + 'a>>;

/// A way to reach one provider.
pub trait ProviderTransport: Send + Sync {
    /// Look the subject up within `budget`.
    fn lookup<'a>(&'a self, lookup: Lookup, budget: Duration) -> LookupFuture<'a>;
}

/// Structural checks on a claim value: bounded depth, no nulls, integers
/// only, bounded keys that cannot collide with the engine's escape syntax.
///
/// # Errors
///
/// Returns the first violation.
pub fn check_value(value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_CLAIM_DEPTH {
        return Err("claim nesting limit exceeded".to_owned());
    }
    match value {
        Value::Null => Err("null claims are not supported".to_owned()),
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .ok_or_else(|| "claims require integer numbers".to_owned())?;
            if integer.unsigned_abs() > MAX_SAFE_INTEGER {
                return Err("integer exceeds the wire format's precision".to_owned());
            }
            Ok(())
        }
        Value::Object(fields) => {
            for (key, child) in fields {
                if key.is_empty() || key.len() > MAX_KEY_BYTES {
                    return Err("claim key must be 1-128 bytes".to_owned());
                }
                if key.starts_with("__") {
                    return Err(format!("claim key '{key}' uses a reserved prefix"));
                }
                check_value(child, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(items) => items
            .iter()
            .try_for_each(|child| check_value(child, depth + 1)),
        Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

/// Validate an evidence reference: bounded, printable, optional.
///
/// # Errors
///
/// Returns the violation.
pub fn validate_evidence_ref(raw: &str) -> Result<Option<String>, String> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.chars().count() > MAX_EVIDENCE_REF_CHARS {
        return Err("evidence reference exceeds 128 characters".to_owned());
    }
    if raw.chars().any(char::is_control) {
        return Err("evidence reference contains control characters".to_owned());
    }
    Ok(Some(raw.to_owned()))
}

/// Validate a provider response for `domain` and extract the attributes.
///
/// # Errors
///
/// Returns `InvalidOutput` for any contract violation.
pub fn validate_response(
    response: &GetAttributesResponse,
    domain: &str,
) -> Result<LookupResult, ProviderError> {
    if response.encoded_len() > MAX_MESSAGE_BYTES {
        return Err(ProviderError::InvalidOutput(
            "response exceeds the message size cap".to_owned(),
        ));
    }
    let evidence_ref =
        validate_evidence_ref(&response.evidence_ref).map_err(ProviderError::InvalidOutput)?;
    let roots = response
        .context_attributes
        .as_ref()
        .map(struct_to_json)
        .unwrap_or_else(|| Value::Object(Map::new()));
    let Value::Object(roots) = roots else {
        return Err(ProviderError::InvalidOutput(
            "context attributes must be an object".to_owned(),
        ));
    };
    match AttributeStatus::try_from(response.status) {
        Ok(AttributeStatus::NoData) => {
            if !roots.is_empty() || response.ttl_seconds != 0 {
                return Err(ProviderError::InvalidOutput(
                    "a no-data response carries no attributes and no cache lifetime".to_owned(),
                ));
            }
            Ok(LookupResult::NoData)
        }
        Ok(AttributeStatus::Found) => {
            if let Some(other) = roots.keys().find(|root| root.as_str() != domain) {
                return Err(ProviderError::InvalidOutput(format!(
                    "domain '{other}' was not requested"
                )));
            }
            let Some(record) = roots.get(domain) else {
                return Ok(LookupResult::NoData);
            };
            let Value::Object(claims) = record else {
                return Err(ProviderError::InvalidOutput(
                    "domain attributes must be a record".to_owned(),
                ));
            };
            if claims.contains_key("_meta") {
                return Err(ProviderError::InvalidOutput(
                    "provenance is written by the gateway, not the provider".to_owned(),
                ));
            }
            check_value(record, 0).map_err(ProviderError::InvalidOutput)?;
            Ok(LookupResult::Found(Attributes {
                claims: claims.clone(),
                ttl_seconds: response.ttl_seconds,
                age_seconds: response.age_seconds,
                evidence_ref,
            }))
        }
        Ok(AttributeStatus::Unspecified) | Err(_) => Err(ProviderError::InvalidOutput(
            "response status must be found or no_data".to_owned(),
        )),
    }
}

/// Server-side peer check for providers that speak the contract over a Unix
/// socket: the connecting process must run as `expected_uid`, and bearer
/// credentials are never accepted on this surface.
///
/// # Errors
///
/// Returns `UNAUTHENTICATED` or `PERMISSION_DENIED` for the caller.
#[allow(clippy::result_large_err)]
pub fn authorize_peer<T>(request: &Request<T>, expected_uid: u32) -> Result<(), Status> {
    let uid = request
        .extensions()
        .get::<UdsConnectInfo>()
        .and_then(|info| info.peer_cred.as_ref())
        .map(tokio::net::unix::UCred::uid);
    if uid != Some(expected_uid) {
        return Err(Status::unauthenticated(
            "Unix peer with the registered UID required",
        ));
    }
    if request.metadata().contains_key("authorization") {
        return Err(Status::permission_denied(
            "bearer credentials are not accepted on the provider socket",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use apf_proto::json::json_to_proto_value;
    use serde_json::json;

    use super::*;

    fn found(value: Value) -> GetAttributesResponse {
        let Some(apf_proto::prost_types::value::Kind::StructValue(context)) =
            json_to_proto_value(&value).expect("struct").kind
        else {
            panic!("fixture must be an object");
        };
        GetAttributesResponse {
            context_attributes: Some(context),
            ttl_seconds: 30,
            evidence_ref: "CHG0012".to_owned(),
            status: AttributeStatus::Found as i32,
            age_seconds: 4,
        }
    }

    #[test]
    fn found_response_yields_claims_and_metadata() {
        let result = validate_response(
            &found(json!({"change": {"approval": "approved", "risk": 2}})),
            "change",
        )
        .expect("valid");
        let LookupResult::Found(attributes) = result else {
            panic!("expected attributes");
        };
        assert_eq!(attributes.claims["approval"], json!("approved"));
        assert_eq!(attributes.ttl_seconds, 30);
        assert_eq!(attributes.age_seconds, 4);
        assert_eq!(attributes.evidence_ref.as_deref(), Some("CHG0012"));
    }

    #[test]
    fn found_without_the_domain_root_is_no_data() {
        assert_eq!(
            validate_response(&found(json!({})), "change").expect("valid"),
            LookupResult::NoData
        );
    }

    #[test]
    fn contract_violations_are_invalid_output() {
        for bad in [
            json!({"identity": {}}),
            json!({"change": {}, "identity": {}}),
            json!({"change": {"_meta": {}}}),
            json!({"change": {"x": null}}),
            json!({"change": {"x": 1.5}}),
            json!({"change": {"x": {"__entity": {}}}}),
            json!({"change": false}),
            json!({"change": {"x": 9_007_199_254_740_992_u64}}),
        ] {
            let error = validate_response(&found(bad.clone()), "change")
                .expect_err(&format!("{bad} must be rejected"));
            assert!(
                matches!(error, ProviderError::InvalidOutput(_)),
                "{bad}: {error}"
            );
        }
        let mut deep = json!(true);
        for _ in 0..18 {
            deep = json!({"nested": deep});
        }
        assert!(check_value(&deep, 0).is_err());

        let mut unspecified = found(json!({"change": {"a": 1}}));
        unspecified.status = AttributeStatus::Unspecified as i32;
        assert!(validate_response(&unspecified, "change").is_err());

        let mut long_evidence = found(json!({"change": {"a": 1}}));
        long_evidence.evidence_ref = "x".repeat(129);
        assert!(validate_response(&long_evidence, "change").is_err());
    }

    #[test]
    fn no_data_must_be_empty_and_uncacheable() {
        let no_data = GetAttributesResponse {
            status: AttributeStatus::NoData as i32,
            ..GetAttributesResponse::default()
        };
        assert_eq!(
            validate_response(&no_data, "change").expect("valid"),
            LookupResult::NoData
        );
        let mut with_ttl = no_data.clone();
        with_ttl.ttl_seconds = 5;
        assert!(validate_response(&with_ttl, "change").is_err());
        let mut with_roots = found(json!({"change": {"a": 1}}));
        with_roots.status = AttributeStatus::NoData as i32;
        assert!(validate_response(&with_roots, "change").is_err());
    }

    #[test]
    fn grpc_codes_map_onto_the_taxonomy() {
        use tonic::Code;
        let cases = [
            (Code::DeadlineExceeded, ProviderStatus::Timeout),
            (Code::Unavailable, ProviderStatus::Unavailable),
            (Code::ResourceExhausted, ProviderStatus::Capacity),
            (Code::InvalidArgument, ProviderStatus::InvalidInput),
            (Code::Unauthenticated, ProviderStatus::Unauthorized),
            (Code::PermissionDenied, ProviderStatus::Unauthorized),
            (Code::Unimplemented, ProviderStatus::Misconfigured),
            (Code::FailedPrecondition, ProviderStatus::Misconfigured),
            (Code::Internal, ProviderStatus::Unavailable),
        ];
        for (code, status) in cases {
            assert_eq!(
                ProviderError::from_status(&Status::new(code, "x")).status(),
                status,
                "{code:?}"
            );
        }
    }

    #[test]
    fn peer_authorization_requires_a_unix_peer() {
        assert!(authorize_peer(&Request::new(()), 1000).is_err());
    }

    #[test]
    fn evidence_reference_rules() {
        assert_eq!(validate_evidence_ref("").expect("empty is none"), None);
        assert_eq!(
            validate_evidence_ref("CHG0012").expect("valid"),
            Some("CHG0012".to_owned())
        );
        assert!(validate_evidence_ref("a\nb").is_err());
        assert!(validate_evidence_ref(&"x".repeat(129)).is_err());
    }
}
