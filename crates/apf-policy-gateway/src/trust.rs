// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Provenance-token trust: JWT verification plus JWKS key fetch and rotation.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tracing::{info, warn};

/// Claims shape used for decoding policy-service provenance JWTs.
#[derive(Debug, Deserialize)]
pub struct ProvJwtClaims {
    #[serde(default)]
    pub jti: String,
    #[serde(default)]
    pub exp: u64,
    #[serde(rename = "apf/document-digest", default)]
    pub apf_document_digest: String,
    #[serde(rename = "apf/spec-digest", default)]
    pub apf_spec_digest: String,
    #[serde(rename = "apf/bundle-id", default)]
    pub apf_bundle_id: String,
}

/// Failure modes returned by [`verify_jwt`].
#[derive(Debug, PartialEq)]
pub enum JwtError {
    /// The Ed25519 signature did not verify — indicates tampering.
    BadSignature,
    /// The signature is valid but the token's `exp` claim has passed.
    Expired,
}

/// Verify a compact JWT string using the supplied Ed25519 verifying key.
///
/// Returns the decoded claims on success, or:
/// - [`JwtError::BadSignature`] if the Ed25519 signature is invalid.
/// - [`JwtError::Expired`] if the signature is valid but `exp > 0` and `now > exp`.
pub fn verify_jwt(verifying_key: &VerifyingKey, jwt: &str) -> Result<ProvJwtClaims, JwtError> {
    let decoding_key = DecodingKey::from_ed_der(verifying_key.as_bytes());
    let mut validation = Validation::new(Algorithm::EdDSA);
    // Disable library exp check; we do it manually so exp==0 means no expiry.
    validation.validate_exp = false;
    validation.required_spec_claims = std::collections::HashSet::new();

    let token_data = jsonwebtoken::decode::<ProvJwtClaims>(jwt, &decoding_key, &validation)
        .map_err(|_| JwtError::BadSignature)?;
    let claims = token_data.claims;

    if claims.exp > 0 {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX, |d| d.as_secs());
        if now_secs > claims.exp {
            return Err(JwtError::Expired);
        }
    }

    Ok(claims)
}

/// Fetch the JWKS from `url` and return the first Ed25519 (`OKP`/`Ed25519`) verifying key found.
pub async fn fetch_ed25519_key_from_jwks(url: &str) -> anyhow::Result<VerifyingKey> {
    let body = reqwest::get(url)
        .await
        .map_err(|e| anyhow::anyhow!("JWKS fetch failed: {e}"))?
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("JWKS response unreadable: {e}"))?;

    let jwks: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("JWKS JSON parse failed: {e}"))?;

    let keys = jwks["keys"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("JWKS missing 'keys' array"))?;

    for key in keys {
        let kty = key["kty"].as_str().unwrap_or("");
        let crv = key["crv"].as_str().unwrap_or("");
        if kty != "OKP" || crv != "Ed25519" {
            continue;
        }
        let x_b64 = key["x"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Ed25519 JWK missing 'x' field"))?;
        let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|e| anyhow::anyhow!("Ed25519 JWK 'x' base64url decode failed: {e}"))?;
        let key_bytes: [u8; 32] = x_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 JWK 'x' must be exactly 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Ed25519 JWK 'x' is not a valid public key: {e}"))?;
        return Ok(vk);
    }

    Err(anyhow::anyhow!(
        "no Ed25519 key (kty=OKP, crv=Ed25519) found in JWKS at {url}"
    ))
}

/// Configuration for the JWKS key rotation watcher.
pub struct JwksWatcherConfig {
    pub jwks_url: String,
    pub interval: Duration,
}

/// Spawn a background task that re-fetches the JWKS at `config.interval` and
/// writes a new key into `key` when the public-key bytes differ from the
/// currently cached value. On fetch failure the current key is retained and
/// a warning is logged; the next interval will retry.
pub fn spawn_jwks_watcher(config: JwksWatcherConfig, key: Arc<RwLock<VerifyingKey>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(config.interval).await;

            let new_key = match fetch_ed25519_key_from_jwks(&config.jwks_url).await {
                Ok(k) => k,
                Err(e) => {
                    warn!(
                        url = %config.jwks_url,
                        error = %e,
                        "JWKS re-fetch failed; keeping current verifying key"
                    );
                    continue;
                }
            };

            // Compare under the read lock, then upgrade only when a rotation is
            // detected so the common (no-change) path avoids write contention.
            let rotated = {
                let current = key.read().unwrap();
                new_key.as_bytes() != current.as_bytes()
            };

            if rotated {
                info!(url = %config.jwks_url, "JWKS key rotated; updating verifying key");
                *key.write().unwrap() = new_key;
            }
        }
    });
}
