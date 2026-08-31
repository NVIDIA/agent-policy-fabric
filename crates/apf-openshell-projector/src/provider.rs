// SPDX-License-Identifier: Apache-2.0
//! Composes a canonical `Provider` into an `OpenShell` `ProviderProfile`, emitted
//! as a YAML document. `OpenShell` parses the YAML into its `ProviderProfile`
//! proto on import, so the serialized shape here must match the field set of
//! `OpenShell`'s `providers/*.yaml` (`snake_case` keys, empty fields omitted).

use std::collections::HashMap;

use apf_proto::ir;
use serde::Serialize;

/// Compose a `ProviderProfile` YAML document from a canonical `Provider`.
pub fn compose(provider: &ir::Provider) -> Result<Vec<u8>, String> {
    let profile = ProviderProfileDoc::from_ir(provider);
    serde_yaml::to_string(&profile)
        .map(String::into_bytes)
        .map_err(|e| format!("serialize ProviderProfile: {e}"))
}

// ---------------------------------------------------------------------------
// Serde shape — matches OpenShell's providers/*.yaml
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ProviderProfileDoc {
    id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    category: String,
    // The examples emit `inference_capable` only when true.
    #[serde(skip_serializing_if = "is_false")]
    inference_capable: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    credentials: Vec<CredentialDoc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovery: Option<DiscoveryDoc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<EndpointDoc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    binaries: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CredentialDoc {
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    env_vars: Vec<String>,
    required: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    auth_style: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    header_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    query_param: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    path_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh: Option<RefreshDoc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_grant: Option<TokenGrantDoc>,
}

#[derive(Debug, Serialize)]
struct DiscoveryDoc {
    credentials: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RefreshDoc {
    strategy: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    token_url: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero_i64")]
    refresh_before_seconds: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    max_lifetime_seconds: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    material: Vec<RefreshMaterialDoc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    additional_outputs: Vec<RefreshOutputDoc>,
}

#[derive(Debug, Serialize)]
struct RefreshMaterialDoc {
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    required: bool,
    secret: bool,
}

#[derive(Debug, Serialize)]
struct RefreshOutputDoc {
    output: String,
    credential: String,
}

#[derive(Debug, Serialize)]
struct TokenGrantDoc {
    token_endpoint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    audience: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    jwt_svid_audience: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_assertion_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero_i64")]
    cache_ttl_seconds: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    audience_overrides: Vec<TokenGrantAudienceOverrideDoc>,
}

#[derive(Debug, Serialize)]
struct TokenGrantAudienceOverrideDoc {
    #[serde(skip_serializing_if = "String::is_empty")]
    host: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    port: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    path: String,
    audience: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EndpointDoc {
    host: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    port: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tls: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    access: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    enforcement: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<L7RuleDoc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny_rules: Vec<L7DenyRuleDoc>,
    #[serde(skip_serializing_if = "is_false")]
    allow_encoded_slash: bool,
    #[serde(skip_serializing_if = "is_false")]
    websocket_credential_rewrite: bool,
    #[serde(skip_serializing_if = "is_false")]
    request_body_credential_rewrite: bool,
    #[serde(skip_serializing_if = "is_false")]
    allow_uninspected_credentials: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    persisted_queries: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    graphql_persisted_queries: HashMap<String, GraphqlOperationDoc>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    graphql_max_body_bytes: u32,
    #[serde(skip_serializing_if = "is_zero_u32")]
    json_rpc_max_body_bytes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<McpOptionsDoc>,
}

#[derive(Debug, Serialize)]
struct L7RuleDoc {
    #[serde(skip_serializing_if = "Option::is_none")]
    allow: Option<L7AllowDoc>,
}

#[derive(Debug, Serialize)]
struct L7AllowDoc {
    #[serde(skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    command: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    query: HashMap<String, L7QueryMatcherDoc>,
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    params: HashMap<String, L7QueryMatcherDoc>,
}

#[derive(Debug, Serialize)]
struct L7DenyRuleDoc {
    #[serde(skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    command: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    query: HashMap<String, L7QueryMatcherDoc>,
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    params: HashMap<String, L7QueryMatcherDoc>,
}

#[derive(Debug, Serialize)]
struct L7QueryMatcherDoc {
    #[serde(skip_serializing_if = "String::is_empty")]
    glob: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    any: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GraphqlOperationDoc {
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    operation_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
}

#[derive(Debug, Serialize)]
struct McpOptionsDoc {
    #[serde(skip_serializing_if = "Option::is_none")]
    strict_tool_names: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_all_known_mcp_methods: Option<bool>,
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

impl ProviderProfileDoc {
    fn from_ir(provider: &ir::Provider) -> Self {
        let meta = provider.metadata.clone().unwrap_or_default();
        let spec = provider.spec.clone().unwrap_or_default();

        let category = category_for(&spec.r#type);
        // inference_capable is derived from the category rather than authored.
        // OpenShell's copilot profile is category `agent` without this flag, so
        // a canonical copilot projects `inference_capable: true` where the hand
        // -authored profile omits it — an accepted, documented divergence.
        let inference_capable = matches!(spec.r#type.as_str(), "inference" | "agent");

        let credentials: Vec<CredentialDoc> = spec
            .credentials
            .iter()
            .map(|c| credential_doc(c, &meta.name))
            .collect();

        // discovery lists every credential not explicitly opted out
        // (`discoverable: false`); an unset value defaults to discoverable.
        let discovery_names: Vec<String> = credentials
            .iter()
            .zip(spec.credentials.iter())
            .filter(|(_, c)| c.discoverable != Some(false))
            .map(|(doc, _)| doc.name.clone())
            .collect();
        let discovery = if discovery_names.is_empty() {
            None
        } else {
            Some(DiscoveryDoc {
                credentials: discovery_names,
            })
        };

        Self {
            id: meta.name,
            display_name: meta.title,
            description: meta.description,
            category,
            inference_capable,
            credentials,
            discovery,
            endpoints: spec.endpoints.iter().map(endpoint_doc).collect(),
            binaries: spec.binaries.iter().map(|b| b.path.clone()).collect(),
        }
    }
}

fn category_for(provider_type: &str) -> String {
    match provider_type {
        "inference" => "inference",
        "agent" => "agent",
        "source-control" => "source_control",
        "messaging" => "messaging",
        "data" => "data",
        "knowledge" => "knowledge",
        _ => "other",
    }
    .to_string()
}

fn credential_doc(cred: &ir::Credential, provider_id: &str) -> CredentialDoc {
    // A nameless credential defaults to the provider id, which is stable and
    // unique for the common single-credential provider.
    let name = if cred.name.is_empty() {
        provider_id.to_string()
    } else {
        cred.name.clone()
    };
    // An empty style means bearer; OpenShell treats bearer as the default but
    // the examples author it explicitly.
    let auth_style = if cred.style.is_empty() {
        "bearer".to_string()
    } else {
        cred.style.clone()
    };

    CredentialDoc {
        name,
        description: cred.description.clone(),
        env_vars: cred.env_vars.clone(),
        required: cred.required,
        auth_style,
        header_name: cred.header.clone(),
        query_param: cred.query_param.clone(),
        path_template: cred.path_template.clone(),
        refresh: cred.source.as_ref().and_then(refresh_doc),
        token_grant: cred.source.as_ref().and_then(token_grant_doc),
    }
}

fn refresh_doc(source: &ir::CredentialSource) -> Option<RefreshDoc> {
    use ir::credential_source::Kind;
    match source.kind.as_ref() {
        // Static credentials have no refresh block.
        Some(Kind::HostEnv(_)) | None => None,
        // token_grant is minted at use time, not on a refresh schedule; it has
        // its own top-level field on the credential.
        Some(Kind::TokenGrant(_)) => None,
        Some(Kind::External(e)) => Some(RefreshDoc {
            strategy: "external".to_string(),
            token_url: e.token_url.clone(),
            scopes: e.scopes.clone(),
            refresh_before_seconds: e.refresh_before_seconds,
            max_lifetime_seconds: e.max_lifetime_seconds,
            material: Vec::new(),
            additional_outputs: Vec::new(),
        }),
        Some(Kind::GoogleServiceAccountJwt(g)) => Some(RefreshDoc {
            strategy: "google_service_account_jwt".to_string(),
            token_url: String::new(),
            scopes: Vec::new(),
            refresh_before_seconds: g.refresh_before_seconds,
            max_lifetime_seconds: g.max_lifetime_seconds,
            material: g.material.iter().map(material_doc).collect(),
            additional_outputs: g.additional_outputs.iter().map(output_doc).collect(),
        }),
        Some(Kind::AwsStsAssumeRole(a)) => Some(RefreshDoc {
            strategy: "aws_sts_assume_role".to_string(),
            token_url: String::new(),
            scopes: Vec::new(),
            refresh_before_seconds: a.refresh_before_seconds,
            max_lifetime_seconds: a.max_lifetime_seconds,
            material: a.material.iter().map(material_doc).collect(),
            additional_outputs: a.additional_outputs.iter().map(output_doc).collect(),
        }),
        Some(Kind::Oauth2(o)) => {
            let strategy = match o.grant.as_str() {
                "client-credentials" => "oauth2_client_credentials",
                "refresh-token" => "oauth2_refresh_token",
                _ => "unspecified",
            }
            .to_string();

            // The canonical `parameters` map binds an input name to a host env
            // var. OpenShell's refresh material has no field for the source
            // env var, so the binding is not carried here — the env var
            // travels with the credential's `env_vars`. Each parameter key
            // becomes one material entry, marked secret when its name
            // suggests a secret value.
            let mut material: Vec<RefreshMaterialDoc> = o
                .parameters
                .keys()
                .map(|key| RefreshMaterialDoc {
                    name: key.clone(),
                    description: String::new(),
                    required: true,
                    secret: looks_secret(key),
                })
                .collect();
            material.sort_by(|a, b| a.name.cmp(&b.name));

            Some(RefreshDoc {
                strategy,
                token_url: o.token_url.clone(),
                scopes: o.scopes.clone(),
                refresh_before_seconds: o.refresh_before_seconds,
                max_lifetime_seconds: o.max_lifetime_seconds,
                material,
                additional_outputs: o.additional_outputs.iter().map(output_doc).collect(),
            })
        }
    }
}

fn token_grant_doc(source: &ir::CredentialSource) -> Option<TokenGrantDoc> {
    use ir::credential_source::Kind;
    let Some(Kind::TokenGrant(t)) = source.kind.as_ref() else {
        return None;
    };
    Some(TokenGrantDoc {
        token_endpoint: t.token_endpoint.clone(),
        audience: t.audience.clone(),
        jwt_svid_audience: t.jwt_svid_audience.clone(),
        client_assertion_type: t.client_assertion_type.clone(),
        scopes: t.scopes.clone(),
        cache_ttl_seconds: t.cache_ttl_seconds,
        audience_overrides: t
            .audience_overrides
            .iter()
            .map(audience_override_doc)
            .collect(),
    })
}

fn audience_override_doc(o: &ir::TokenGrantAudienceOverride) -> TokenGrantAudienceOverrideDoc {
    TokenGrantAudienceOverrideDoc {
        host: o.host.clone(),
        port: o.port,
        path: o.path.clone(),
        audience: o.audience.clone(),
        scopes: o.scopes.clone(),
    }
}

fn material_doc(m: &ir::RefreshMaterial) -> RefreshMaterialDoc {
    RefreshMaterialDoc {
        name: m.name.clone(),
        description: m.description.clone(),
        required: m.required,
        secret: m.secret,
    }
}

fn output_doc(o: &ir::RefreshOutput) -> RefreshOutputDoc {
    RefreshOutputDoc {
        output: o.output.clone(),
        credential: o.credential.clone(),
    }
}

fn looks_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("secret") || k.contains("token") || k.contains("key")
}

fn endpoint_doc(e: &ir::NetworkEndpoint) -> EndpointDoc {
    EndpointDoc {
        host: e.host.clone(),
        port: e.port,
        path: e.path.clone(),
        protocol: e.protocol.clone(),
        tls: e.tls.clone(),
        access: e.access.clone(),
        enforcement: e.enforcement.clone(),
        // The parse layer promotes a single `port` into `ports`; suppress that
        // echo so the projected endpoint matches the hand-authored shape.
        ports: if e.ports == vec![e.port] {
            Vec::new()
        } else {
            e.ports.clone()
        },
        allowed_ips: e.allowed_ips.clone(),
        rules: e.rules.iter().map(l7rule_doc).collect(),
        deny_rules: e.deny_rules.iter().map(l7deny_rule_doc).collect(),
        allow_encoded_slash: e.allow_encoded_slash,
        websocket_credential_rewrite: e.websocket_credential_rewrite,
        request_body_credential_rewrite: e.request_body_credential_rewrite,
        allow_uninspected_credentials: e.allow_uninspected_credentials,
        persisted_queries: e.persisted_queries.clone(),
        graphql_persisted_queries: e
            .graphql_persisted_queries
            .iter()
            .map(|(k, op)| (k.clone(), graphql_operation_doc(op)))
            .collect(),
        graphql_max_body_bytes: e.graphql_max_body_bytes,
        json_rpc_max_body_bytes: e.json_rpc_max_body_bytes,
        mcp: e.mcp.as_ref().map(mcp_options_doc),
    }
}

fn l7rule_doc(r: &ir::L7Rule) -> L7RuleDoc {
    L7RuleDoc {
        allow: r.allow.as_ref().map(l7allow_doc),
    }
}

fn l7allow_doc(a: &ir::L7Allow) -> L7AllowDoc {
    L7AllowDoc {
        method: a.method.clone(),
        path: a.path.clone(),
        command: a.command.clone(),
        query: a
            .query
            .iter()
            .map(|(k, m)| (k.clone(), l7query_doc(m)))
            .collect(),
        operation_type: a.operation_type.clone(),
        operation_name: a.operation_name.clone(),
        fields: a.fields.clone(),
        params: a
            .params
            .iter()
            .map(|(k, m)| (k.clone(), l7query_doc(m)))
            .collect(),
    }
}

fn l7deny_rule_doc(d: &ir::L7DenyRule) -> L7DenyRuleDoc {
    L7DenyRuleDoc {
        method: d.method.clone(),
        path: d.path.clone(),
        command: d.command.clone(),
        query: d
            .query
            .iter()
            .map(|(k, m)| (k.clone(), l7query_doc(m)))
            .collect(),
        operation_type: d.operation_type.clone(),
        operation_name: d.operation_name.clone(),
        fields: d.fields.clone(),
        params: d
            .params
            .iter()
            .map(|(k, m)| (k.clone(), l7query_doc(m)))
            .collect(),
    }
}

fn l7query_doc(m: &ir::L7QueryMatcher) -> L7QueryMatcherDoc {
    L7QueryMatcherDoc {
        glob: m.glob.clone(),
        any: m.any.clone(),
    }
}

fn graphql_operation_doc(op: &ir::GraphqlOperation) -> GraphqlOperationDoc {
    GraphqlOperationDoc {
        operation_type: op.operation_type.clone(),
        operation_name: op.operation_name.clone(),
        fields: op.fields.clone(),
    }
}

fn mcp_options_doc(m: &ir::McpOptions) -> McpOptionsDoc {
    McpOptionsDoc {
        strict_tool_names: m.strict_tool_names,
        allow_all_known_mcp_methods: m.allow_all_known_mcp_methods,
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !*v
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use apf_compiler::provider;

    /// Project a canonical Provider YAML and parse the result back into a value
    /// for order-independent comparison.
    fn project(canonical: &str) -> serde_yaml::Value {
        let ir = provider::parse(canonical.as_bytes()).expect("parse canonical provider");
        let bytes = compose(&ir).expect("compose provider profile");
        serde_yaml::from_slice(&bytes).expect("parse projected yaml")
    }

    fn expected(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).expect("parse expected yaml")
    }

    fn v(s: &str) -> serde_yaml::Value {
        serde_yaml::Value::from(s)
    }
    fn vi(n: i64) -> serde_yaml::Value {
        serde_yaml::Value::from(n)
    }
    fn vb(b: bool) -> serde_yaml::Value {
        serde_yaml::Value::from(b)
    }

    // github — source-control, single bearer (header) credential, mixed
    // rest/graphql endpoints.
    const GITHUB_CANONICAL: &str = r#"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: Provider
metadata:
  name: github
  title: GitHub
  description: GitHub API and Git operations
spec:
  type: source-control
  credentials:
    - name: api_token
      envVars: [GITHUB_TOKEN, GH_TOKEN]
      required: true
      style: bearer
      header: authorization
  endpoints:
    - { host: api.github.com, port: 443, protocol: rest, access: read-only, enforcement: enforce }
    - { host: api.github.com, port: 443, path: /graphql, protocol: graphql, access: read-only, enforcement: enforce }
    - { host: github.com, port: 443, protocol: rest, access: read-only, enforcement: enforce }
  binaries: [/usr/bin/gh, /usr/local/bin/gh, /usr/bin/git, /usr/local/bin/git]
"#;
    const GITHUB_EXPECTED: &str = r#"
id: github
display_name: GitHub
description: GitHub API and Git operations
category: source_control
credentials:
  - name: api_token
    env_vars: [GITHUB_TOKEN, GH_TOKEN]
    required: true
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_token]
endpoints:
  - { host: api.github.com, port: 443, protocol: rest, access: read-only, enforcement: enforce }
  - { host: api.github.com, port: 443, path: /graphql, protocol: graphql, access: read-only, enforcement: enforce }
  - { host: github.com, port: 443, protocol: rest, access: read-only, enforcement: enforce }
binaries: [/usr/bin/gh, /usr/local/bin/gh, /usr/bin/git, /usr/local/bin/git]
"#;

    // nvidia — inference, single bearer (header) credential.
    const NVIDIA_CANONICAL: &str = r#"
kind: Provider
metadata:
  name: nvidia
  title: NVIDIA
  description: NVIDIA inference endpoints
spec:
  type: inference
  credentials:
    - name: api_key
      envVars: [NVIDIA_API_KEY]
      required: true
      style: bearer
      header: authorization
  endpoints:
    - { host: integrate.api.nvidia.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  binaries: [/usr/bin/curl, /usr/local/bin/curl]
"#;
    const NVIDIA_EXPECTED: &str = r#"
id: nvidia
display_name: NVIDIA
description: NVIDIA inference endpoints
category: inference
inference_capable: true
credentials:
  - name: api_key
    env_vars: [NVIDIA_API_KEY]
    required: true
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - { host: integrate.api.nvidia.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
binaries: [/usr/bin/curl, /usr/local/bin/curl]
"#;

    // claude-code — agent, header-style credential.
    const CLAUDE_CANONICAL: &str = r#"
kind: Provider
metadata:
  name: claude-code
  title: Claude Code
  description: Claude Code CLI
spec:
  type: agent
  credentials:
    - name: api_key
      envVars: [ANTHROPIC_API_KEY, CLAUDE_API_KEY]
      required: true
      style: header
      header: x-api-key
  endpoints:
    - { host: api.anthropic.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: statsig.anthropic.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: sentry.io, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  binaries: [/usr/bin/claude, /usr/local/bin/claude]
"#;
    const CLAUDE_EXPECTED: &str = r#"
id: claude-code
display_name: Claude Code
description: Claude Code CLI
category: agent
inference_capable: true
credentials:
  - name: api_key
    env_vars: [ANTHROPIC_API_KEY, CLAUDE_API_KEY]
    required: true
    auth_style: header
    header_name: x-api-key
discovery:
  credentials: [api_key]
endpoints:
  - { host: api.anthropic.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: statsig.anthropic.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: sentry.io, port: 443, protocol: rest, access: read-write, enforcement: enforce }
binaries: [/usr/bin/claude, /usr/local/bin/claude]
"#;

    // codex — agent, four static credentials, glob binary path.
    const CODEX_CANONICAL: &str = r#"
kind: Provider
metadata:
  name: codex
  title: Codex
  description: OpenAI Codex CLI
spec:
  type: agent
  credentials:
    - name: access_token
      envVars: [CODEX_AUTH_ACCESS_TOKEN]
      required: true
      style: bearer
    - name: refresh_token
      envVars: [CODEX_AUTH_REFRESH_TOKEN]
      required: true
      style: bearer
    - name: account_id
      envVars: [CODEX_AUTH_ACCOUNT_ID]
      required: true
      style: bearer
    - name: id_token
      envVars: [CODEX_AUTH_ID_TOKEN]
      style: bearer
  endpoints:
    - { host: api.openai.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: auth.openai.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: chatgpt.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: ab.chatgpt.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  binaries: [/usr/bin/codex, /usr/local/bin/codex, "/usr/lib/node_modules/@openai/**"]
"#;
    // The hand-authored codex profile omits auth_style on its credentials; the
    // canonical authoring sets bearer explicitly. The comparison normalizes that
    // away below by injecting auth_style into the expected value.
    const CODEX_EXPECTED: &str = r#"
id: codex
display_name: Codex
description: OpenAI Codex CLI
category: agent
inference_capable: true
credentials:
  - { name: access_token, env_vars: [CODEX_AUTH_ACCESS_TOKEN], required: true, auth_style: bearer }
  - { name: refresh_token, env_vars: [CODEX_AUTH_REFRESH_TOKEN], required: true, auth_style: bearer }
  - { name: account_id, env_vars: [CODEX_AUTH_ACCOUNT_ID], required: true, auth_style: bearer }
  - { name: id_token, env_vars: [CODEX_AUTH_ID_TOKEN], required: false, auth_style: bearer }
discovery:
  credentials: [access_token, refresh_token, account_id, id_token]
endpoints:
  - { host: api.openai.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: auth.openai.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: chatgpt.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: ab.chatgpt.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
binaries: [/usr/bin/codex, /usr/local/bin/codex, "/usr/lib/node_modules/@openai/**"]
"#;

    // copilot — agent without inference_capable in the hand-authored profile;
    // the canonical derivation emits inference_capable: true (documented diff).
    const COPILOT_CANONICAL: &str = r#"
kind: Provider
metadata:
  name: copilot
  title: GitHub Copilot
  description: GitHub Copilot CLI and Copilot service APIs
spec:
  type: agent
  credentials:
    - name: api_token
      envVars: [COPILOT_GITHUB_TOKEN, GH_TOKEN, GITHUB_TOKEN]
      required: true
      style: bearer
      header: authorization
  endpoints:
    - { host: api.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: api.individual.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: api.business.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: api.enterprise.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: copilot-proxy.githubusercontent.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
    - { host: telemetry.enterprise.githubcopilot.com, port: 443 }
    - { host: default.exp-tas.com, port: 443 }
  binaries:
    - /usr/bin/copilot
    - "/usr/lib/node_modules/@github/copilot/node_modules/@github/**/copilot"
"#;
    const COPILOT_EXPECTED: &str = r#"
id: copilot
display_name: GitHub Copilot
description: GitHub Copilot CLI and Copilot service APIs
category: agent
credentials:
  - name: api_token
    env_vars: [COPILOT_GITHUB_TOKEN, GH_TOKEN, GITHUB_TOKEN]
    required: true
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_token]
endpoints:
  - { host: api.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: api.individual.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: api.business.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: api.enterprise.githubcopilot.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: copilot-proxy.githubusercontent.com, port: 443, protocol: rest, access: read-write, enforcement: enforce }
  - { host: telemetry.enterprise.githubcopilot.com, port: 443 }
  - { host: default.exp-tas.com, port: 443 }
binaries:
  - /usr/bin/copilot
  - "/usr/lib/node_modules/@github/copilot/node_modules/@github/**/copilot"
"#;

    #[test]
    fn parity_github() {
        assert_eq!(project(GITHUB_CANONICAL), expected(GITHUB_EXPECTED));
    }

    #[test]
    fn parity_nvidia() {
        assert_eq!(project(NVIDIA_CANONICAL), expected(NVIDIA_EXPECTED));
    }

    #[test]
    fn parity_claude_code() {
        assert_eq!(project(CLAUDE_CANONICAL), expected(CLAUDE_EXPECTED));
    }

    #[test]
    fn parity_codex() {
        assert_eq!(project(CODEX_CANONICAL), expected(CODEX_EXPECTED));
    }

    #[test]
    fn parity_copilot_with_documented_inference_diff() {
        let projected = project(COPILOT_CANONICAL);
        let mut want = expected(COPILOT_EXPECTED);
        // The hand-authored copilot profile omits inference_capable even though
        // category is agent; the derivation emits it. Encode the known diff.
        assert!(want.get("inference_capable").is_none());
        want.as_mapping_mut().unwrap().insert(
            serde_yaml::Value::from("inference_capable"),
            serde_yaml::Value::from(true),
        );
        assert_eq!(projected, want);
    }

    #[test]
    fn oauth2_client_credentials_maps_to_refresh_material() {
        let canonical = r#"
kind: Provider
metadata: { name: acme }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [SERVICE_TOKEN]
      style: bearer
      required: true
      source:
        kind: oauth2
        grant: client-credentials
        tokenUrl: https://idp.example/oauth2/token
        scopes: [api.read]
        refreshBeforeSeconds: 60
        maxLifetimeSeconds: 3600
        parameters:
          client_id: ACME_CLIENT_ID
          client_secret: ACME_CLIENT_SECRET
"#;
        let value = project(canonical);
        let cred = &value["credentials"][0];
        let refresh = &cred["refresh"];
        assert_eq!(refresh["strategy"], v("oauth2_client_credentials"));
        assert_eq!(refresh["token_url"], v("https://idp.example/oauth2/token"));
        assert_eq!(refresh["refresh_before_seconds"], vi(60));
        assert_eq!(refresh["max_lifetime_seconds"], vi(3600));
        let material = refresh["material"].as_sequence().expect("material seq");
        assert_eq!(material.len(), 2);
        // Sorted by name: client_id (not secret), client_secret (secret).
        assert_eq!(material[0]["name"], v("client_id"));
        assert_eq!(material[0]["secret"], vb(false));
        assert_eq!(material[0]["required"], vb(true));
        assert_eq!(material[1]["name"], v("client_secret"));
        assert_eq!(material[1]["secret"], vb(true));
    }

    #[test]
    fn oauth2_refresh_token_grant_maps_strategy() {
        let canonical = r#"
kind: Provider
metadata: { name: acme }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [TOKEN]
      style: bearer
      source:
        kind: oauth2
        grant: refresh-token
        tokenUrl: https://idp.example/token
"#;
        let value = project(canonical);
        assert_eq!(
            value["credentials"][0]["refresh"]["strategy"],
            v("oauth2_refresh_token")
        );
    }

    #[test]
    fn host_env_source_has_no_refresh() {
        let canonical = r#"
kind: Provider
metadata: { name: acme }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [INJECTED]
      style: bearer
      source: { kind: host-env, name: HOST_VAR }
"#;
        let value = project(canonical);
        assert!(value["credentials"][0].get("refresh").is_none());
    }

    #[test]
    fn nameless_credential_defaults_to_provider_id() {
        let canonical = r#"
kind: Provider
metadata: { name: solo }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - envVars: [SOLO_TOKEN]
      style: bearer
"#;
        let value = project(canonical);
        assert_eq!(value["credentials"][0]["name"], v("solo"));
        assert_eq!(value["discovery"]["credentials"][0], v("solo"));
    }

    #[test]
    fn discoverable_false_excluded_from_discovery() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: shown
      envVars: [A]
      style: bearer
    - name: hidden
      envVars: [B]
      style: bearer
      discoverable: false
"#;
        let value = project(canonical);
        let disc = value["discovery"]["credentials"].as_sequence().unwrap();
        assert_eq!(disc.len(), 1);
        assert_eq!(disc[0], v("shown"));
    }

    #[test]
    fn credential_description_projects() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [TOKEN]
      style: bearer
      description: The API token used for all requests.
"#;
        let value = project(canonical);
        assert_eq!(
            value["credentials"][0]["description"],
            v("The API token used for all requests.")
        );
    }

    #[test]
    fn external_source_maps_refresh_with_timing() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [TOKEN]
      style: bearer
      source:
        kind: external
        tokenUrl: https://idp.example/token
        scopes: [read]
        refreshBeforeSeconds: 600
        maxLifetimeSeconds: 3600
"#;
        let value = project(canonical);
        let refresh = &value["credentials"][0]["refresh"];
        assert_eq!(refresh["strategy"], v("external"));
        assert_eq!(refresh["token_url"], v("https://idp.example/token"));
        assert_eq!(refresh["scopes"][0], v("read"));
        assert_eq!(refresh["refresh_before_seconds"], vi(600));
        assert_eq!(refresh["max_lifetime_seconds"], vi(3600));
    }

    #[test]
    fn aws_sts_assume_role_maps_material_and_outputs() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: access_key
      envVars: [AWS_ACCESS_KEY_ID]
      style: bearer
      source:
        kind: aws-sts-assume-role
        refreshBeforeSeconds: 300
        maxLifetimeSeconds: 900
        material:
          - name: role_arn
            description: IAM role to assume
            required: true
            secret: false
        additionalOutputs:
          - output: secret_access_key
            credential: secret_key
          - output: session_token
            credential: session_token
"#;
        let value = project(canonical);
        let refresh = &value["credentials"][0]["refresh"];
        assert_eq!(refresh["strategy"], v("aws_sts_assume_role"));
        assert_eq!(refresh["refresh_before_seconds"], vi(300));
        assert_eq!(refresh["max_lifetime_seconds"], vi(900));
        assert_eq!(refresh["material"][0]["name"], v("role_arn"));
        assert_eq!(
            refresh["material"][0]["description"],
            v("IAM role to assume")
        );
        assert_eq!(refresh["material"][0]["required"], vb(true));
        let outputs = refresh["additional_outputs"].as_sequence().unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0]["output"], v("secret_access_key"));
        assert_eq!(outputs[0]["credential"], v("secret_key"));
        assert_eq!(outputs[1]["output"], v("session_token"));
        assert_eq!(outputs[1]["credential"], v("session_token"));
    }

    #[test]
    fn google_service_account_jwt_maps_material() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [TOKEN]
      style: bearer
      source:
        kind: google-service-account-jwt
        refreshBeforeSeconds: 120
        material:
          - name: private_key
            required: true
            secret: true
"#;
        let value = project(canonical);
        let refresh = &value["credentials"][0]["refresh"];
        assert_eq!(refresh["strategy"], v("google_service_account_jwt"));
        assert_eq!(refresh["refresh_before_seconds"], vi(120));
        assert_eq!(refresh["material"][0]["name"], v("private_key"));
        assert_eq!(refresh["material"][0]["secret"], vb(true));
    }

    #[test]
    fn oauth2_additional_outputs_project() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [TOKEN]
      style: bearer
      source:
        kind: oauth2
        grant: client-credentials
        tokenUrl: https://idp.example/token
        additionalOutputs:
          - output: session_token
            credential: session_token
"#;
        let value = project(canonical);
        let outputs = value["credentials"][0]["refresh"]["additional_outputs"]
            .as_sequence()
            .unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["output"], v("session_token"));
        assert_eq!(outputs[0]["credential"], v("session_token"));
    }

    #[test]
    fn token_grant_maps_to_top_level_field_not_refresh() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - name: token
      envVars: [TOKEN]
      style: bearer
      source:
        kind: token-grant
        tokenEndpoint: https://idp.example/token
        audience: https://api.example
        scopes: [read]
        cacheTtlSeconds: 60
        audienceOverrides:
          - host: other.example
            audience: https://other.example
"#;
        let value = project(canonical);
        let cred = &value["credentials"][0];
        assert!(cred.get("refresh").is_none());
        let grant = &cred["token_grant"];
        assert_eq!(grant["token_endpoint"], v("https://idp.example/token"));
        assert_eq!(grant["audience"], v("https://api.example"));
        assert_eq!(grant["scopes"][0], v("read"));
        assert_eq!(grant["cache_ttl_seconds"], vi(60));
        assert_eq!(grant["audience_overrides"][0]["host"], v("other.example"));
        assert_eq!(
            grant["audience_overrides"][0]["audience"],
            v("https://other.example")
        );
    }

    #[test]
    fn endpoint_l7_rules_deny_rules_and_mcp_project() {
        let canonical = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints:
    - host: api.example
      port: 443
      protocol: mcp
      allow_uninspected_credentials: true
      rules:
        - allow: { method: tools/call, params: { name: { any: [read_file] } } }
      deny_rules:
        - method: tools/call
          params: { name: { any: [delete_file] } }
      mcp:
        strict_tool_names: true
"#;
        let value = project(canonical);
        let ep = &value["endpoints"][0];
        assert_eq!(ep["allow_uninspected_credentials"], vb(true));
        assert_eq!(ep["rules"][0]["allow"]["method"], v("tools/call"));
        assert_eq!(
            ep["rules"][0]["allow"]["params"]["name"]["any"][0],
            v("read_file")
        );
        assert_eq!(ep["deny_rules"][0]["method"], v("tools/call"));
        assert_eq!(
            ep["deny_rules"][0]["params"]["name"]["any"][0],
            v("delete_file")
        );
        assert_eq!(ep["mcp"]["strict_tool_names"], vb(true));
    }
}
