// SPDX-License-Identifier: Apache-2.0
// Provider profile reconciler: pushes bundle-managed profiles to the gateway at startup
// and re-reconciles when the digest watcher signals a bundle change.

use std::time::Duration;

use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::{info, warn};

use crate::proto::openshell::v1::{
    ImportProviderProfilesRequest, ProviderProfile, ProviderProfileCredential,
    ProviderProfileDiscovery, ProviderProfileImportItem, UpdateProviderProfilesRequest,
    open_shell_client::OpenShellClient,
};
use crate::proto::openshell::sandbox::v1::NetworkEndpoint;
use apf_policy_client::PolicyClientHandle;

const RECONCILE_ATTEMPTS: u32 = 5;
const RECONCILE_RETRY_DELAY: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// YAML serde structs matching the OpenShell provider profile YAML format
// (same format produced by the policy-service compiler and stored as GetDocument body).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct ProfileYaml {
    pub id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub credentials: Vec<CredentialYaml>,
    #[serde(default)]
    pub endpoints: Vec<EndpointYaml>,
    #[serde(default)]
    pub binaries: Vec<String>,
    #[serde(default)]
    pub inference_capable: bool,
    #[serde(default)]
    pub discovery: Option<DiscoveryYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CredentialYaml {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub env_vars: Vec<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub auth_style: String,
    #[serde(default)]
    pub header_name: String,
    #[serde(default)]
    pub query_param: String,
    #[serde(default)]
    pub path_template: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct EndpointYaml {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u32,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    enforcement: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    path: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct DiscoveryYaml {
    #[serde(default)]
    credentials: Vec<String>,
}

fn category_from_str(s: &str) -> i32 {
    match s {
        "other" => 1,
        "inference" => 2,
        "agent" => 3,
        "source_control" => 4,
        "messaging" => 5,
        "data" => 6,
        "knowledge" => 7,
        _ => 0,
    }
}

pub fn profile_from_yaml(bytes: &[u8]) -> Result<ProviderProfile, String> {
    let yaml: ProfileYaml =
        serde_yaml::from_slice(bytes).map_err(|e| format!("YAML parse failed: {e}"))?;

    Ok(ProviderProfile {
        id: yaml.id,
        display_name: yaml.display_name,
        description: yaml.description,
        category: category_from_str(&yaml.category),
        credentials: yaml
            .credentials
            .into_iter()
            .map(|c| ProviderProfileCredential {
                name: c.name,
                description: c.description,
                env_vars: c.env_vars,
                required: c.required,
                auth_style: c.auth_style,
                header_name: c.header_name,
                query_param: c.query_param,
                path_template: c.path_template,
                ..Default::default()
            })
            .collect(),
        endpoints: yaml
            .endpoints
            .into_iter()
            .map(|e| NetworkEndpoint {
                host: e.host,
                port: e.port,
                protocol: e.protocol,
                access: e.access,
                enforcement: e.enforcement,
                tls: e.tls,
                path: e.path,
                ..Default::default()
            })
            .collect(),
        binaries: yaml
            .binaries
            .into_iter()
            .map(
                |path| crate::proto::openshell::sandbox::v1::NetworkBinary {
                    path,
                    ..Default::default()
                },
            )
            .collect(),
        inference_capable: yaml.inference_capable,
        discovery: yaml.discovery.map(|d| ProviderProfileDiscovery {
            credentials: d.credentials,
        }),
        resource_version: 0,
        annotations: std::collections::HashMap::default(),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Gateway client helpers
// ---------------------------------------------------------------------------

pub(crate) async fn connect_gateway(
    endpoint: &str,
    tls: Option<ClientTlsConfig>,
) -> Result<OpenShellClient<Channel>, String> {
    let ep = Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| format!("invalid gateway endpoint: {e}"))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15));
    let channel = if let Some(tls_cfg) = tls {
        ep.tls_config(tls_cfg)
            .map_err(|e| format!("gateway TLS config: {e}"))?
            .connect()
            .await
    } else {
        ep.connect().await
    }
    .map_err(|e| format!("connect gateway: {e}"))?;
    Ok(OpenShellClient::new(channel))
}

async fn reconcile_one(
    client: &mut OpenShellClient<Channel>,
    profile: ProviderProfile,
) -> Result<(), String> {
    use tonic::Code;
    let id = profile.id.clone();

    match client
        .get_provider_profile(
            crate::proto::openshell::v1::GetProviderProfileRequest { id: id.clone(), ..Default::default() },
        )
        .await
    {
        Ok(resp) => {
            let existing = resp.into_inner().profile.ok_or_else(|| {
                format!("get_provider_profile '{id}': missing profile in response")
            })?;
            if existing.resource_version == 0 {
                info!(profile_id = %id, "provider profile is built-in; skipping reconcile");
                return Ok(());
            }
            let mut updated = profile;
            updated.resource_version = existing.resource_version;
            let resp = client
                .update_provider_profiles(UpdateProviderProfilesRequest {
                    id: id.clone(),
                    profile: Some(ProviderProfileImportItem {
                        profile: Some(updated),
                        source: "apf-bundle".to_string(),
                        ..Default::default()
                    }),
                    expected_resource_version: existing.resource_version,
                    ..Default::default()
                })
                .await
                .map_err(|s| format!("update_provider_profiles '{id}': {s}"))?
                .into_inner();
            if resp.updated {
                info!(profile_id = %id, "provider profile updated");
            } else {
                info!(profile_id = %id, "provider profile unchanged");
            }
            Ok(())
        }
        Err(status) if status.code() == Code::NotFound => {
            let resp = client
                .import_provider_profiles(ImportProviderProfilesRequest {
                    profiles: vec![ProviderProfileImportItem {
                        profile: Some(profile),
                        source: "apf-bundle".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .await
                .map_err(|s| format!("import_provider_profiles '{id}': {s}"))?
                .into_inner();
            if resp.imported {
                info!(profile_id = %id, "provider profile imported");
            } else {
                let diag: Vec<_> = resp
                    .diagnostics
                    .iter()
                    .map(|d| d.message.as_str())
                    .collect();
                return Err(format!(
                    "import_provider_profiles '{id}' rejected: {}",
                    diag.join("; ")
                ));
            }
            Ok(())
        }
        Err(status) => Err(format!("get_provider_profile '{id}': {status}")),
    }
}

async fn reconcile_all(
    gateway_endpoint: &str,
    tls: Option<ClientTlsConfig>,
    mut policy_service: PolicyClientHandle,
) -> Result<String, String> {
    let ids = policy_service
        .list_documents("openshell.provider-profile.v1")
        .await
        .map_err(|e| format!("list_documents failed: {e}"))?
        .names;

    if ids.is_empty() {
        info!("bundle has no provider profiles; nothing to reconcile");
        return Ok(String::new());
    }

    let mut client = connect_gateway(gateway_endpoint, tls).await?;
    let mut last_digest = String::new();

    for id in &ids {
        let doc = policy_service
            .get_document("openshell.provider-profile.v1", id, None)
            .await
            .map_err(|e| format!("get_document '{id}': {e}"))?;
        last_digest = doc.digest;
        let profile =
            profile_from_yaml(&doc.body).map_err(|e| format!("profile '{id}' YAML: {e}"))?;
        reconcile_one(&mut client, profile).await?;
    }

    info!(
        count = ids.len(),
        "provider profile reconciliation complete"
    );
    Ok(last_digest)
}

/// Spawn a background task that reconciles bundle-managed provider profiles with
/// the gateway. Performs an initial reconcile with retries at startup, then
/// re-reconciles whenever a bundle-changed event arrives on `rx`. A failed
/// event-driven reconcile is logged and retried on the next event.
pub fn spawn_profile_reconciler(
    gateway_endpoint: String,
    tls: Option<ClientTlsConfig>,
    policy_service: PolicyClientHandle,
    mut rx: tokio::sync::broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        // Initial reconcile: up to RECONCILE_ATTEMPTS with a fixed retry delay.
        let mut last_error = String::new();
        for attempt in 1..=RECONCILE_ATTEMPTS {
            match reconcile_all(&gateway_endpoint, tls.clone(), policy_service.clone()).await {
                Ok(digest) => {
                    info!(digest, "provider profile reconciliation succeeded");
                    last_error.clear();
                    break;
                }
                Err(err) => {
                    last_error = err.clone();
                    warn!(
                        attempt,
                        max_attempts = RECONCILE_ATTEMPTS,
                        error = %last_error,
                        "provider profile reconcile attempt failed"
                    );
                    if attempt < RECONCILE_ATTEMPTS {
                        tokio::time::sleep(RECONCILE_RETRY_DELAY).await;
                    }
                }
            }
        }
        if !last_error.is_empty() {
            warn!(
                max_attempts = RECONCILE_ATTEMPTS,
                error = %last_error,
                "provider profile reconcile failed after all attempts; will retry on next bundle change"
            );
        }

        // Event loop: re-reconcile when the digest watcher signals a change.
        loop {
            match rx.recv().await {
                Ok(_event) => {
                    match reconcile_all(&gateway_endpoint, tls.clone(), policy_service.clone())
                        .await
                    {
                        Ok(digest) => {
                            info!(digest, "provider profile reconciliation after bundle change succeeded");
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "provider profile reconcile after bundle change failed; will retry on next event"
                            );
                        }
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    // Slow reconcile caused the broadcast buffer to overflow.
                    // The next event will trigger another reconcile.
                    warn!(
                        skipped,
                        "profile reconciler lagged; missed bundle-changed events"
                    );
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}
