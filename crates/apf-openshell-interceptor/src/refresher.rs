// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Sandbox policy refresher: propagates bundle policy changes to running sandboxes.
//
// Subscribes to bundle-changed events and sends a bare `UpdateConfig` to the
// gateway for each running sandbox. The interceptor's own `UpdateConfig`
// MODIFY_OPERATION handler injects the freshly vended policy and provenance
// annotations into that request, so the refresh carries no policy payload
// itself. Each sandbox then picks up the new revision through its normal
// config polling.
//
// A TTL timer fires proactively when `valid_until_ms` is close to expiring so
// sandboxes are refreshed before the policy projection becomes invalid.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use tokio::sync::broadcast::error::RecvError;
use tonic::Code;
use tracing::{info, warn};

use crate::proto::openshell::datamodel::v1::{ObjectMeta, WorkspaceSelector, workspace_selector};
use crate::proto::openshell::v1::{
    ListSandboxesRequest, Sandbox, SandboxPhase, UpdateConfigRequest,
};
use crate::reconciler::connect_gateway;
use apf_types::events::{BundleEvent, BundleEventReceiver};

const LIST_SANDBOXES_PAGE_SIZE: i32 = 100;

/// How far in the future to set the TTL sleep when no deadline is active.
const FAR_FUTURE: Duration = Duration::from_secs(365 * 24 * 3600);

/// Proactive refresh fires this many milliseconds before `valid_until_ms` to
/// give sandboxes time to pull the new projection before the old one expires.
const MARGIN_MS: u64 = 30_000;

/// Configuration for the sandbox policy refresher.
pub struct RefresherConfig {
    pub gateway_endpoint: String,
    /// Client TLS config for the gateway connection. `None` for plaintext.
    pub gateway_tls: Option<tonic::transport::ClientTlsConfig>,
    /// Ed25519 public key used to re-verify stored provenance tokens on read-back.
    /// Shared with the JWKS watcher; the inner value is replaced on key rotation.
    pub verifying_key: Arc<RwLock<VerifyingKey>>,
}

/// Spawn a background task that refreshes running sandbox policies on
/// bundle-changed events and, when `valid_until_ms` is set, proactively
/// before the deadline.
#[allow(clippy::too_many_lines)]
pub fn spawn_policy_refresher(config: RefresherConfig, mut rx: BundleEventReceiver) {
    tokio::spawn(async move {
        // Start with the TTL sleep far in the future; it will be reset on the
        // first bundle-changed event that carries a non-zero valid_until_ms.
        let ttl_sleep = tokio::time::sleep(FAR_FUTURE);
        tokio::pin!(ttl_sleep);

        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(BundleEvent::BundleChanged { digest, valid_until_ms }) => {
                            match refresh_running_sandboxes(
                                &config.gateway_endpoint,
                                config.gateway_tls.clone(),
                                Arc::clone(&config.verifying_key),
                            )
                            .await
                            {
                                Ok(refreshed) => {
                                    info!(refreshed, %digest, "sandbox policy refresh complete");
                                }
                                Err(e) => {
                                    warn!(error = %e, "sandbox policy refresh failed");
                                }
                            }

                            // Arm the TTL timer when the projection carries an expiry.
                            if valid_until_ms > 0 {
                                let now_ms = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                                let delay_ms = valid_until_ms
                                    .saturating_sub(now_ms)
                                    .saturating_sub(MARGIN_MS);
                                let deadline = tokio::time::Instant::now()
                                    + Duration::from_millis(delay_ms);
                                ttl_sleep.as_mut().reset(deadline);
                            }
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            warn!(
                                skipped,
                                "policy refresher lagged; missed bundle-changed events"
                            );
                        }
                        Err(RecvError::Closed) => break,
                    }
                }

                () = &mut ttl_sleep => {
                    info!("policy-valid-until approaching; triggering proactive sandbox refresh");
                    match refresh_running_sandboxes(
                        &config.gateway_endpoint,
                        config.gateway_tls.clone(),
                        Arc::clone(&config.verifying_key),
                    )
                    .await
                    {
                        Ok(refreshed) => {
                            info!(refreshed, "proactive sandbox policy refresh complete");
                        }
                        Err(e) => {
                            warn!(error = %e, "proactive sandbox policy refresh failed");
                        }
                    }
                    // Reset to far future until the next bundle-changed event
                    // provides a new deadline.
                    ttl_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + FAR_FUTURE);
                }
            }
        }
    });
}

/// Send a policy-less `UpdateConfig` to every running sandbox and audit
/// provenance token validity for all sandboxes. Returns the number of
/// sandboxes refreshed.
///
/// For every sandbox that carries an `apf.nvidia.com/provenance-token`
/// annotation the token's Ed25519 signature is re-verified. A failure means
/// the stored provenance record does not match what the policy service minted —
/// indicating a post-admission tamper. The event is logged at WARN; the refresh
/// proceeds regardless so eligible sandboxes pick up a fresh, correctly-annotated revision.
async fn refresh_running_sandboxes(
    gateway_endpoint: &str,
    tls: Option<tonic::transport::ClientTlsConfig>,
    verifying_key: Arc<RwLock<VerifyingKey>>,
) -> Result<u32, String> {
    let mut client = connect_gateway(gateway_endpoint, tls).await?;
    let mut page_token = String::new();
    let mut seen_tokens = std::collections::HashSet::new();
    let mut refreshed = 0_u32;
    loop {
        let response = client
            .list_sandboxes(ListSandboxesRequest {
                page_size: LIST_SANDBOXES_PAGE_SIZE,
                page_token: page_token.clone(),
                workspace_scope: Some(default_workspace()),
                label_selector: String::new(),
            })
            .await
            .map_err(|s| format!("list_sandboxes: {s}"))?
            .into_inner();
        for sandbox in response.sandboxes {
            let Some(metadata) = sandbox.metadata.as_ref() else {
                continue;
            };
            if metadata.name.is_empty() {
                continue;
            }

            // Re-verify the stored provenance token for every sandbox that
            // carries one. A signature failure indicates post-admission tamper.
            // An expiry alone is not tamper — eligible sandboxes are renewed
            // below via UpdateConfig; ineligible ones are logged at warn.
            if let Some(token) = metadata.annotations.get("apf.nvidia.com/provenance-token") {
                let key = *verifying_key.read().unwrap();
                if is_bad_signature(&key, token) {
                    let cid = metadata
                        .annotations
                        .get("apf.nvidia.com/correlation-id")
                        .map_or("", String::as_str)
                        .to_string();
                    warn!(
                        sandbox = %metadata.name,
                        correlation_id = %cid,
                        "TAMPER DETECTED: stored provenance token failed verification"
                    );
                } else if is_expired(&key, token) && !accepts_policy_refresh(&sandbox) {
                    warn!(
                        sandbox = %metadata.name,
                        "provenance token expired; sandbox not eligible for policy refresh"
                    );
                }
            }

            if !accepts_policy_refresh(&sandbox) {
                continue;
            }
            let result = client.update_config(refresh_request(metadata)?).await;
            match result {
                Ok(resp) => {
                    refreshed += 1;
                    info!(
                        sandbox = %metadata.name,
                        version = resp.into_inner().version,
                        "sandbox policy refreshed"
                    );
                }
                Err(status) if status.code() == Code::InvalidArgument => {
                    warn!(
                        sandbox = %metadata.name,
                        reason = %status.message(),
                        "policy refresh rejected for running sandbox; change applies to new sandboxes only"
                    );
                }
                Err(status) => {
                    warn!(
                        sandbox = %metadata.name,
                        error = %status,
                        "sandbox policy refresh failed"
                    );
                }
            }
        }
        page_token = response.next_page_token;
        if page_token.is_empty() {
            break;
        }
        if !seen_tokens.insert(page_token.clone()) {
            return Err("sandbox list returned a repeated page token".into());
        }
    }
    Ok(refreshed)
}

fn refresh_request(metadata: &ObjectMeta) -> Result<UpdateConfigRequest, String> {
    if metadata.workspace != "default" || metadata.name.is_empty() {
        return Err("sandbox is outside the requested workspace or has no name".into());
    }
    Ok(UpdateConfigRequest {
        sandbox: metadata.name.clone(),
        expected_resource_version: metadata.resource_version,
        workspace_scope: Some(default_workspace()),
        ..Default::default()
    })
}

// Preserve the refresher's existing default-workspace scope. Never broaden
// refresh to every workspace just because the new API permits that selector.
fn default_workspace() -> WorkspaceSelector {
    WorkspaceSelector {
        selection: Some(workspace_selector::Selection::Workspace("default".into())),
    }
}

/// Returns true when the JWT has a bad signature (does not verify with the supplied key).
/// Callers needing full trust verification should use a dedicated trust module.
fn is_bad_signature(key: &VerifyingKey, jwt: &str) -> bool {
    use ed25519_dalek::Verifier;
    // Minimal structural check: split header.payload.sig, verify Ed25519 over "header.payload"
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return true;
    }
    use base64::Engine as _;
    let sig_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]) {
        Ok(b) if b.len() == 64 => b,
        _ => return true,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return true,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let message = format!("{}.{}", parts[0], parts[1]);
    key.verify(message.as_bytes(), &sig).is_err()
}

/// Returns true when the JWT payload `exp` claim is in the past (token expired).
fn is_expired(_key: &VerifyingKey, jwt: &str) -> bool {
    use base64::Engine as _;
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() != 3 {
        return false;
    }
    let Ok(payload_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
    else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
        return false;
    };
    let exp = payload["exp"].as_u64().unwrap_or(0);
    if exp == 0 {
        return false;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_secs());
    now > exp
}

/// Only ready or provisioning sandboxes poll their config, so only those can
/// pick up a refreshed policy.
fn accepts_policy_refresh(sandbox: &Sandbox) -> bool {
    let phase = sandbox
        .status
        .as_ref()
        .and_then(|status| SandboxPhase::try_from(status.phase).ok());
    matches!(
        phase,
        Some(SandboxPhase::Ready | SandboxPhase::Provisioning)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::openshell::datamodel::v1::ObjectMeta;
    use crate::proto::openshell::v1::SandboxStatus;

    fn sandbox_in_phase(phase: SandboxPhase) -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                name: "demo".to_string(),
                ..Default::default()
            }),
            spec: None,
            status: Some(SandboxStatus {
                phase: phase as i32,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn refresh_is_scoped_and_preserves_optimistic_concurrency() {
        let mut metadata = ObjectMeta {
            name: "same-name".into(),
            workspace: "default".into(),
            resource_version: 42,
            ..Default::default()
        };
        let request = refresh_request(&metadata).unwrap();
        assert_eq!(request.sandbox, "same-name");
        assert_eq!(request.expected_resource_version, 42);
        assert_eq!(
            request.workspace_scope.unwrap().selection,
            Some(workspace_selector::Selection::Workspace("default".into()))
        );
        assert!(!request.global);
        assert!(request.policy.is_none());
        for workspace in ["other-user", ""] {
            metadata.workspace = workspace.into();
            assert!(refresh_request(&metadata).is_err());
        }
    }

    #[test]
    fn refresh_targets_ready_and_provisioning_sandboxes() {
        assert!(accepts_policy_refresh(&sandbox_in_phase(
            SandboxPhase::Ready
        )));
        assert!(accepts_policy_refresh(&sandbox_in_phase(
            SandboxPhase::Provisioning
        )));
        assert!(!accepts_policy_refresh(&sandbox_in_phase(
            SandboxPhase::Error
        )));
        assert!(!accepts_policy_refresh(&sandbox_in_phase(
            SandboxPhase::Deleting
        )));
        assert!(!accepts_policy_refresh(&sandbox_in_phase(
            SandboxPhase::Unknown
        )));
        assert!(!accepts_policy_refresh(&Sandbox::default()));
    }
}
