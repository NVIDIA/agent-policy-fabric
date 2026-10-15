// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Provider profile reconciler: pushes bundle-managed profiles to the gateway at startup
// and re-reconciles when the digest watcher signals a bundle change.

use std::time::Duration;

use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::{info, warn};

use crate::proto::openshell::sandbox::v1::{
    GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, McpOptions, NetworkAccessPreset,
    NetworkEndpoint, NetworkEnforcementMode, NetworkTlsMode,
};
use crate::proto::openshell::v1::{
    ImportProviderProfilesRequest, ProviderCredentialRefresh, ProviderCredentialRefreshMaterial,
    ProviderCredentialRefreshOutput, ProviderCredentialRefreshStrategy,
    ProviderCredentialTokenGrant, ProviderCredentialTokenGrantAudienceOverride, ProviderProfile,
    ProviderProfileCredential, ProviderProfileDiscovery, ProviderProfileImportItem,
    UpdateProviderProfilesRequest, open_shell_client::OpenShellClient,
};
use apf_policy_client::PolicyClientHandle;
use apf_proto::ProviderProfileSet;
use apf_types::events::{BundleEvent, BundleEventReceiver};
use prost::Message as _;

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
    #[serde(default)]
    pub refresh: Option<RefreshYaml>,
    #[serde(default)]
    pub token_grant: Option<TokenGrantYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RefreshYaml {
    #[serde(default)]
    strategy: String,
    #[serde(default)]
    token_url: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    refresh_before_seconds: i64,
    #[serde(default)]
    max_lifetime_seconds: i64,
    #[serde(default)]
    material: Vec<RefreshMaterialYaml>,
    #[serde(default)]
    additional_outputs: Vec<RefreshOutputYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RefreshMaterialYaml {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    secret: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct RefreshOutputYaml {
    #[serde(default)]
    output: String,
    #[serde(default)]
    credential: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct TokenGrantYaml {
    #[serde(default)]
    token_endpoint: String,
    #[serde(default)]
    audience: String,
    #[serde(default)]
    jwt_svid_audience: String,
    #[serde(default)]
    client_assertion_type: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    cache_ttl_seconds: i64,
    #[serde(default)]
    audience_overrides: Vec<TokenGrantAudienceOverrideYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct TokenGrantAudienceOverrideYaml {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u32,
    #[serde(default)]
    path: String,
    #[serde(default)]
    audience: String,
    #[serde(default)]
    scopes: Vec<String>,
}

fn refresh_strategy_from_str(s: &str) -> i32 {
    match s {
        "static" => ProviderCredentialRefreshStrategy::Static,
        "external" => ProviderCredentialRefreshStrategy::External,
        "oauth2_refresh_token" => ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
        "oauth2_client_credentials" => ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        "google_service_account_jwt" => ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
        "aws_sts_assume_role" => ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
        _ => ProviderCredentialRefreshStrategy::Unspecified,
    }
    .into()
}

fn refresh_from_yaml(r: RefreshYaml) -> Result<ProviderCredentialRefresh, String> {
    Ok(ProviderCredentialRefresh {
        strategy: refresh_strategy_from_str(&r.strategy),
        token_url: r.token_url,
        scopes: r.scopes,
        refresh_before: duration_seconds(r.refresh_before_seconds)?,
        max_lifetime: duration_seconds(r.max_lifetime_seconds)?,
        material: r
            .material
            .into_iter()
            .map(|m| ProviderCredentialRefreshMaterial {
                name: m.name,
                description: m.description,
                required: m.required,
                secret: m.secret,
            })
            .collect(),
        additional_outputs: r
            .additional_outputs
            .into_iter()
            .map(|o| ProviderCredentialRefreshOutput {
                output: o.output,
                credential: o.credential,
            })
            .collect(),
    })
}

fn token_grant_from_yaml(t: TokenGrantYaml) -> Result<ProviderCredentialTokenGrant, String> {
    Ok(ProviderCredentialTokenGrant {
        token_endpoint: t.token_endpoint,
        audience: t.audience,
        jwt_svid_audience: t.jwt_svid_audience,
        client_assertion_type: t.client_assertion_type,
        scopes: t.scopes,
        cache_ttl: duration_seconds(t.cache_ttl_seconds)?,
        audience_overrides: t
            .audience_overrides
            .into_iter()
            .map(|o| ProviderCredentialTokenGrantAudienceOverride {
                host: o.host,
                port: o.port,
                path: o.path,
                audience: o.audience,
                scopes: o.scopes,
            })
            .collect(),
        ..Default::default()
    })
}

// Zero in APF authoring means no override; preserve that as an absent duration.
fn duration_seconds(seconds: i64) -> Result<Option<prost_types::Duration>, String> {
    if !(0..=315_576_000_000).contains(&seconds) {
        return Err("credential duration seconds out of range".into());
    }
    Ok((seconds != 0).then_some(prost_types::Duration { seconds, nanos: 0 }))
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
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    rules: Vec<L7RuleYaml>,
    #[serde(default)]
    deny_rules: Vec<L7DenyRuleYaml>,
    #[serde(default)]
    allow_encoded_slash: bool,
    #[serde(default)]
    websocket_credential_rewrite: bool,
    #[serde(default)]
    request_body_credential_rewrite: bool,
    #[serde(default)]
    persisted_queries: String,
    #[serde(default)]
    graphql_persisted_queries: std::collections::HashMap<String, GraphqlOperationYaml>,
    #[serde(default)]
    graphql_max_body_bytes: u32,
    #[serde(default)]
    json_rpc_max_body_bytes: u32,
    #[serde(default)]
    mcp: Option<McpOptionsYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct L7RuleYaml {
    #[serde(default)]
    allow: Option<L7AllowYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct L7AllowYaml {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    query: std::collections::HashMap<String, L7QueryMatcherYaml>,
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    params: std::collections::HashMap<String, L7QueryMatcherYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct L7DenyRuleYaml {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    query: std::collections::HashMap<String, L7QueryMatcherYaml>,
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    params: std::collections::HashMap<String, L7QueryMatcherYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct L7QueryMatcherYaml {
    #[serde(default)]
    glob: String,
    #[serde(default)]
    any: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct GraphqlOperationYaml {
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct McpOptionsYaml {
    #[serde(default)]
    strict_tool_names: Option<bool>,
    #[serde(default)]
    allow_all_known_mcp_methods: Option<bool>,
}

fn l7query_from_yaml(m: L7QueryMatcherYaml) -> L7QueryMatcher {
    L7QueryMatcher {
        glob: m.glob,
        any: m.any,
    }
}

fn l7rule_from_yaml(r: L7RuleYaml) -> L7Rule {
    L7Rule {
        allow: r.allow.map(|a| L7Allow {
            method: a.method,
            path: a.path,
            command: a.command,
            query: a
                .query
                .into_iter()
                .map(|(k, v)| (k, l7query_from_yaml(v)))
                .collect(),
            operation_type: a.operation_type,
            operation_name: a.operation_name,
            fields: a.fields,
            params: a
                .params
                .into_iter()
                .map(|(k, v)| (k, l7query_from_yaml(v)))
                .collect(),
        }),
    }
}

fn l7deny_rule_from_yaml(d: L7DenyRuleYaml) -> L7DenyRule {
    L7DenyRule {
        method: d.method,
        path: d.path,
        command: d.command,
        query: d
            .query
            .into_iter()
            .map(|(k, v)| (k, l7query_from_yaml(v)))
            .collect(),
        operation_type: d.operation_type,
        operation_name: d.operation_name,
        fields: d.fields,
        params: d
            .params
            .into_iter()
            .map(|(k, v)| (k, l7query_from_yaml(v)))
            .collect(),
    }
}

fn graphql_operation_from_yaml(op: GraphqlOperationYaml) -> GraphqlOperation {
    GraphqlOperation {
        operation_type: op.operation_type,
        operation_name: op.operation_name,
        fields: op.fields,
    }
}

fn mcp_options_from_yaml(m: McpOptionsYaml) -> McpOptions {
    McpOptions {
        strict_tool_names: m.strict_tool_names,
        allow_all_known_mcp_methods: m.allow_all_known_mcp_methods,
        versions: Vec::new(),
    }
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
            .map(|c| {
                Ok(ProviderProfileCredential {
                    name: c.name,
                    description: c.description,
                    env_vars: c.env_vars,
                    required: c.required,
                    auth_style: c.auth_style,
                    header_name: c.header_name,
                    query_param: c.query_param,
                    path_template: c.path_template,
                    refresh: c.refresh.map(refresh_from_yaml).transpose()?,
                    token_grant: c.token_grant.map(token_grant_from_yaml).transpose()?,
                    token_grant_owners: Vec::new(),
                })
            })
            .collect::<Result<_, String>>()?,
        endpoints: yaml
            .endpoints
            .into_iter()
            .map(|e| {
                Ok(NetworkEndpoint {
                    host: e.host,
                    port: e.port,
                    protocol: e.protocol,
                    access: endpoint_access(&e.access)? as i32,
                    enforcement: endpoint_enforcement(&e.enforcement)? as i32,
                    tls: endpoint_tls(&e.tls)? as i32,
                    path: e.path,
                    ports: e.ports,
                    allowed_ips: e.allowed_ips,
                    rules: e.rules.into_iter().map(l7rule_from_yaml).collect(),
                    deny_rules: e
                        .deny_rules
                        .into_iter()
                        .map(l7deny_rule_from_yaml)
                        .collect(),
                    allow_encoded_slash: e.allow_encoded_slash,
                    websocket_credential_rewrite: e.websocket_credential_rewrite,
                    request_body_credential_rewrite: e.request_body_credential_rewrite,
                    persisted_queries: e.persisted_queries,
                    graphql_persisted_queries: e
                        .graphql_persisted_queries
                        .into_iter()
                        .map(|(k, v)| (k, graphql_operation_from_yaml(v)))
                        .collect(),
                    graphql_max_body_bytes: e.graphql_max_body_bytes,
                    json_rpc_max_body_bytes: e.json_rpc_max_body_bytes,
                    mcp: e.mcp.map(mcp_options_from_yaml),
                    ..Default::default()
                })
            })
            .collect::<Result<_, String>>()?,
        binaries: yaml
            .binaries
            .into_iter()
            .map(|path| crate::proto::openshell::sandbox::v1::NetworkBinary { path })
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

/// One `openshell.provider-profile.v1` document as returned by the policy service.
pub struct ProviderProfileDocument {
    pub name: String,
    pub body: Vec<u8>,
    pub digest: String,
}

/// List and fetch every `openshell.provider-profile.v1` document the policy
/// service currently publishes.
pub async fn fetch_provider_profile_documents(
    policy_service: &mut PolicyClientHandle,
) -> Result<Vec<ProviderProfileDocument>, String> {
    const KIND: &str = "openshell.provider-profile.v1";
    let names = policy_service
        .list_documents(KIND)
        .await
        .map_err(|e| format!("list_documents provider-profile: {e}"))?
        .names;
    let mut documents = Vec::with_capacity(names.len());
    for name in names {
        let doc = policy_service
            .get_document(KIND, &name, None)
            .await
            .map_err(|e| format!("get_document '{name}': {e}"))?;
        documents.push(ProviderProfileDocument {
            name,
            body: doc.body,
            digest: doc.digest,
        });
    }
    Ok(documents)
}

/// Resolve the provider profiles a bundle publishes from its raw
/// `openshell.provider-profile.v1` documents.
///
/// The compiler emits one document per profile plus an aggregate
/// `ProviderProfileSet` at `default` covering the legacy passthrough
/// profiles, so both layouts coexist for those bundles. Bundles signed
/// before the compiler composed individual documents for every profile
/// publish only that `default` aggregate. Resolve both: when any document
/// besides `default` exists, `default`'s aggregate (if present) is
/// redundant with those individual documents and is validated but not
/// imported, to avoid duplicates; otherwise `default`'s aggregate is the
/// sole source of profiles. A document that fails to parse under either
/// interpretation fails the whole resolution.
pub fn resolve_provider_profiles(
    documents: &[ProviderProfileDocument],
) -> Result<Vec<ProviderProfile>, String> {
    let has_individual_documents = documents.iter().any(|doc| doc.name != "default");
    let mut profiles = Vec::with_capacity(documents.len());
    for doc in documents {
        match profile_from_yaml(&doc.body) {
            Ok(profile) => profiles.push(profile),
            Err(_) if doc.name == "default" => {
                let aggregate = ProviderProfileSet::decode(doc.body.as_slice())
                    .map_err(|e| format!("decode ProviderProfileSet: {e}"))?;
                let members = aggregate
                    .profiles
                    .iter()
                    .enumerate()
                    .map(|(i, bytes)| {
                        profile_from_yaml(bytes).map_err(|e| format!("profile[{i}] YAML: {e}"))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                if !has_individual_documents {
                    profiles.extend(members);
                }
            }
            Err(e) => return Err(format!("profile '{}' YAML: {e}", doc.name)),
        }
    }
    Ok(profiles)
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
        .get_provider_profile(crate::proto::openshell::v1::GetProviderProfileRequest {
            id: id.clone(),
            ..Default::default()
        })
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
                .update_provider_profiles(
                    #[allow(clippy::needless_update)]
                    UpdateProviderProfilesRequest {
                        id: id.clone(),
                        profile: Some(ProviderProfileImportItem {
                            profile: Some(updated),
                            source: "apf-bundle".to_string(),
                            ..Default::default()
                        }),
                        expected_resource_version: existing.resource_version,
                        ..Default::default()
                    },
                )
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
                .import_provider_profiles(
                    #[allow(clippy::needless_update)]
                    ImportProviderProfilesRequest {
                        profiles: vec![ProviderProfileImportItem {
                            profile: Some(profile),
                            source: "apf-bundle".to_string(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                )
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
    let documents = fetch_provider_profile_documents(&mut policy_service).await?;
    let revision = documents
        .iter()
        .find(|doc| doc.name == "default")
        .map_or_else(String::new, |doc| doc.digest.clone());
    let profiles = resolve_provider_profiles(&documents)?;

    if profiles.is_empty() {
        info!("bundle has no provider profiles; nothing to reconcile");
        return Ok(revision);
    }

    let mut client = connect_gateway(gateway_endpoint, tls).await?;

    let count = profiles.len();
    for profile in profiles {
        reconcile_one(&mut client, profile).await?;
    }

    info!(count, "provider profile reconciliation complete");
    Ok(revision)
}

/// Spawn a background task that reconciles bundle-managed provider profiles with
/// the gateway. Performs an initial reconcile with retries at startup, then
/// re-reconciles whenever a bundle-changed event arrives on `rx`. A failed
/// event-driven reconcile is logged and retried on the next event.
pub fn spawn_profile_reconciler(
    gateway_endpoint: String,
    tls: Option<ClientTlsConfig>,
    policy_service: PolicyClientHandle,
    mut rx: BundleEventReceiver,
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

        // Event loop: re-reconcile when the digest watcher signals a bundle change.
        loop {
            match rx.recv().await {
                Ok(BundleEvent::BundleChanged { digest, .. }) => {
                    match reconcile_all(&gateway_endpoint, tls.clone(), policy_service.clone())
                        .await
                    {
                        Ok(_) => {
                            info!(
                                %digest,
                                "provider profile reconciliation after bundle change succeeded"
                            );
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

// Keep the APF authoring vocabulary stable while emitting the pinned OpenShell
// enum wire format. Unknown values must fail, never become audit/no inspection.
fn endpoint_tls(value: &str) -> Result<NetworkTlsMode, String> {
    match value {
        "" => Ok(NetworkTlsMode::Unspecified),
        "skip" => Ok(NetworkTlsMode::Skip),
        "terminate" => Ok(NetworkTlsMode::Terminate),
        "passthrough" => Ok(NetworkTlsMode::Passthrough),
        _ => Err("invalid endpoint tls mode".into()),
    }
}

fn endpoint_enforcement(value: &str) -> Result<NetworkEnforcementMode, String> {
    match value {
        "" => Ok(NetworkEnforcementMode::Unspecified),
        "enforce" => Ok(NetworkEnforcementMode::Enforce),
        "audit" => Ok(NetworkEnforcementMode::Audit),
        _ => Err("invalid endpoint enforcement mode".into()),
    }
}

fn endpoint_access(value: &str) -> Result<NetworkAccessPreset, String> {
    match value {
        "" => Ok(NetworkAccessPreset::Unspecified),
        "read-only" => Ok(NetworkAccessPreset::ReadOnly),
        "read-write" => Ok(NetworkAccessPreset::ReadWrite),
        "full" => Ok(NetworkAccessPreset::Full),
        _ => Err("invalid endpoint access preset".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_imports_individual_documents_and_validates_default_without_duplicating() {
        let p = b"id: p\nendpoints: [{host: api.example, port: 443}]\n".to_vec();
        let aggregate = ProviderProfileSet {
            profiles: vec![p.clone()],
        }
        .encode_to_vec();
        let documents = [
            ProviderProfileDocument {
                name: "p".into(),
                body: p,
                digest: String::new(),
            },
            ProviderProfileDocument {
                name: "default".into(),
                body: aggregate,
                digest: String::new(),
            },
        ];
        let profiles = resolve_provider_profiles(&documents).unwrap();
        assert_eq!(
            profiles.len(),
            1,
            "aggregate duplicate must not be imported"
        );
        assert_eq!(profiles[0].id, "p");
    }

    #[test]
    fn resolve_imports_aggregate_when_it_is_the_only_document() {
        let p = b"id: p\nendpoints: [{host: api.example, port: 443}]\n".to_vec();
        let aggregate = ProviderProfileSet { profiles: vec![p] }.encode_to_vec();
        let documents = [ProviderProfileDocument {
            name: "default".into(),
            body: aggregate,
            digest: String::new(),
        }];
        let profiles = resolve_provider_profiles(&documents).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, "p");
    }

    #[test]
    fn resolve_keeps_a_real_profile_named_default() {
        let documents = [ProviderProfileDocument {
            name: "default".into(),
            body: b"id: default\n".to_vec(),
            digest: String::new(),
        }];
        let profiles = resolve_provider_profiles(&documents).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, "default");
    }

    #[test]
    fn resolve_fails_closed_on_a_malformed_aggregate_member() {
        let aggregate = ProviderProfileSet {
            profiles: vec![b"id: [unterminated\n".to_vec()],
        }
        .encode_to_vec();
        let documents = [ProviderProfileDocument {
            name: "default".into(),
            body: aggregate,
            digest: String::new(),
        }];
        assert!(resolve_provider_profiles(&documents).is_err());
    }

    #[test]
    fn profile_modes_use_enum_wire_types() {
        let profile = profile_from_yaml(
            b"id: p\nendpoints: [{tls: terminate, enforcement: enforce, access: read-write}]\n",
        )
        .unwrap();
        let endpoint = &profile.endpoints[0];
        assert_eq!(endpoint.encode_to_vec(), vec![0x20, 2, 0x28, 1, 0x30, 2]);
        assert!(!endpoint.allow_uninspected_credentials);
        assert!(!endpoint.provider_credentialed);
        let defaults = profile_from_yaml(b"id: p\nendpoints: [{}]\n").unwrap();
        let endpoint = &defaults.endpoints[0];
        assert_eq!(
            (endpoint.tls, endpoint.enforcement, endpoint.access),
            (0, 0, 0)
        );
        for (field, value, expected) in [
            ("tls", "skip", 1),
            ("tls", "passthrough", 3),
            ("enforcement", "audit", 2),
            ("access", "read-only", 1),
            ("access", "full", 3),
        ] {
            let yaml = format!("id: p\nendpoints: [{{{field}: {value}}}]\n");
            let profile = profile_from_yaml(yaml.as_bytes()).unwrap();
            let endpoint = &profile.endpoints[0];
            let actual = match field {
                "tls" => endpoint.tls,
                "access" => endpoint.access,
                _ => endpoint.enforcement,
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn unknown_endpoint_modes_reject_the_entire_profile() {
        for field in ["tls", "enforcement", "access"] {
            for value in ["unknown", "ENFORCE", "1"] {
                let yaml = format!(
                    "id: p\nendpoints: [{{enforcement: enforce}}, {{{field}: '{value}'}}]\n"
                );
                let error = profile_from_yaml(yaml.as_bytes()).unwrap_err();
                assert!(error.contains(field), "{error}");
            }
        }
    }

    #[test]
    fn mcp_endpoint_survives_reconciliation() {
        let yaml = br#"
id: egress-gateway
category: other
endpoints:
  - host: host.openshell.internal
    port: 10443
    path: /mcp/local
    protocol: mcp
    enforcement: enforce
    mcp:
      allow_all_known_mcp_methods: true
"#;
        let profile = profile_from_yaml(yaml).expect("parses");
        let ep = &profile.endpoints[0];
        assert_eq!(ep.protocol, "mcp");
        let mcp = ep.mcp.as_ref().expect("mcp survives reconciliation");
        assert_eq!(mcp.allow_all_known_mcp_methods, Some(true));
    }

    #[test]
    fn rules_and_deny_rules_survive_reconciliation() {
        let yaml = br#"
id: p
category: other
endpoints:
  - host: api.example
    port: 443
    protocol: mcp
    rules:
      - allow:
          method: tools/call
          params:
            name:
              any: [read_file]
    deny_rules:
      - method: tools/call
        params:
          name:
            any: [delete_file]
    json_rpc_max_body_bytes: 131072
"#;
        let profile = profile_from_yaml(yaml).expect("parses");
        let ep = &profile.endpoints[0];
        assert_eq!(ep.json_rpc_max_body_bytes, 131_072);
        let allow = ep.rules[0].allow.as_ref().expect("allow present");
        assert_eq!(allow.method, "tools/call");
        assert_eq!(allow.params["name"].any, vec!["read_file".to_string()]);
        assert_eq!(ep.deny_rules[0].method, "tools/call");
        assert_eq!(
            ep.deny_rules[0].params["name"].any,
            vec!["delete_file".to_string()]
        );
    }

    #[test]
    fn credential_duration_conversion_preserves_absence_and_rejects_invalid_values() {
        assert_eq!(duration_seconds(0).unwrap(), None);
        assert_eq!(
            duration_seconds(60).unwrap(),
            Some(prost_types::Duration {
                seconds: 60,
                nanos: 0
            })
        );
        for seconds in [-1, 315_576_000_001, i64::MAX] {
            for config in [
                format!("refresh: {{refresh_before_seconds: {seconds}}}"),
                format!("refresh: {{max_lifetime_seconds: {seconds}}}"),
                format!("token_grant: {{cache_ttl_seconds: {seconds}}}"),
            ] {
                let yaml = format!("id: p\ncredentials: [{{name: key, {config}}}]\n");
                assert!(profile_from_yaml(yaml.as_bytes()).is_err());
            }
        }
        let profile = profile_from_yaml(
            b"id: p\ncredentials: [{name: key, token_grant: {cache_ttl_seconds: 60}}]\n",
        )
        .unwrap();
        let grant = profile.credentials[0].token_grant.as_ref().unwrap();
        assert_eq!(
            grant.cache_ttl,
            Some(prost_types::Duration {
                seconds: 60,
                nanos: 0
            })
        );
        assert_eq!(grant.grant_type, 0);
        assert!(grant.subject_token.is_none());
    }

    #[test]
    fn external_refresh_survives_reconciliation() {
        let yaml = br#"
id: calendar-read
category: messaging
credentials:
  - name: calendar_read_token
    description: Microsoft Graph read access token for the calendar tool
    env_vars: [CALENDAR_CLI_ACCESS_TOKEN]
    required: true
    auth_style: bearer
    header_name: authorization
    refresh:
      strategy: external
      token_url: https://login.microsoftonline.com/common/oauth2/v2.0/token
      scopes:
        - https://graph.microsoft.com/Calendars.Read
      refresh_before_seconds: 600
      max_lifetime_seconds: 3600
"#;
        let profile = profile_from_yaml(yaml).expect("parses");
        let cred = &profile.credentials[0];
        assert_eq!(
            cred.description,
            "Microsoft Graph read access token for the calendar tool"
        );
        let refresh = cred.refresh.as_ref().expect("refresh survives");
        assert_eq!(
            refresh.strategy,
            i32::from(ProviderCredentialRefreshStrategy::External)
        );
        assert_eq!(
            refresh.token_url,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        );
        assert_eq!(
            refresh.refresh_before,
            Some(prost_types::Duration {
                seconds: 600,
                nanos: 0
            })
        );
        assert_eq!(
            refresh.max_lifetime,
            Some(prost_types::Duration {
                seconds: 3600,
                nanos: 0
            })
        );
    }
}
