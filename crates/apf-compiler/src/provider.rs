// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Frontend: parse a canonical APF `Provider` YAML document into the
//! `nvidia.agent_policy_fabric.policy.v1alpha1.Provider` IR, plus structural
//! validation over the parsed result.
//!
//! The serde types below are private parse-tree nodes mirroring the proto
//! schema. They reuse the shared `NetworkEndpoint`/`NetworkBinary` parse types
//! from [`frontend`] so a provider endpoint and a sandbox network endpoint share
//! one type. `parse` is the single public entry point. The credential `source`
//! is a `oneOf` over `host-env` and `oauth2`; deferred kinds become new branches
//! later.

use std::collections::HashMap;

use apf_proto::ir;
use serde::Deserialize;

use super::frontend::{self, FrontendError, NetworkEndpointDef};

/// Parse `bytes` as a canonical APF `Provider` YAML document and return the
/// canonical IR.
pub fn parse(bytes: &[u8]) -> Result<ir::Provider, FrontendError> {
    let yaml = std::str::from_utf8(bytes)?;
    let doc: Document = serde_yaml::from_str(yaml)?;
    Ok(to_ir(doc))
}

/// A structural defect in a parsed `Provider` that parsing alone cannot catch.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("endpoint {index}: host is empty")]
    EmptyHost { index: usize },
    #[error("endpoint {index} ({host}): no valid port")]
    NoPort { index: usize, host: String },
    #[error("credential {index}: style '{style}' requires a {field}")]
    StyleMissingField {
        index: usize,
        style: String,
        field: &'static str,
    },
}

/// Structural validation of a parsed provider: well-formed endpoints and
/// credential styles consistent with their accompanying field. The serde layer
/// already rejects unknown `source.kind`; this is the semantic backstop.
pub fn validate(provider: &ir::Provider) -> Result<(), ValidationError> {
    let Some(spec) = provider.spec.as_ref() else {
        return Ok(());
    };
    for (index, ep) in spec.endpoints.iter().enumerate() {
        if ep.host.is_empty() {
            return Err(ValidationError::EmptyHost { index });
        }
        let has_port = ep.port != 0 || ep.ports.iter().any(|p| *p != 0);
        if !has_port {
            return Err(ValidationError::NoPort {
                index,
                host: ep.host.clone(),
            });
        }
    }
    for (index, cred) in spec.credentials.iter().enumerate() {
        let (style, field, value) = match cred.style.as_str() {
            "bearer" => ("bearer", "header", &cred.header),
            "header" => ("header", "header", &cred.header),
            "query" => ("query", "queryParam", &cred.query_param),
            "path" => ("path", "pathTemplate", &cred.path_template),
            _ => continue,
        };
        if value.is_empty() {
            return Err(ValidationError::StyleMissingField {
                index,
                style: style.to_string(),
                field,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parse tree — private YAML serde types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(rename = "apiVersion", default)]
    #[allow(dead_code)]
    api_version: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    #[serde(default)]
    metadata: Option<MetadataDef>,
    spec: SpecDef,
}

// No deny_unknown_fields on metadata — forward-compat (labels, annotations, …).
#[derive(Debug, Default, Deserialize)]
struct MetadataDef {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    version: u32,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecDef {
    #[serde(rename = "type", default)]
    provider_type: String,
    #[serde(default)]
    endpoints: Vec<NetworkEndpointDef>,
    #[serde(default)]
    binaries: Vec<BinaryDef>,
    #[serde(default)]
    credentials: Vec<CredentialDef>,
}

// A provider binary, authored either as a plain path string
// (`[/usr/bin/gh]`) or as an explicit object.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BinaryDef {
    Path(String),
    Object(BinaryObjectDef),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryObjectDef {
    path: String,
}

impl BinaryDef {
    fn into_ir(self) -> ir::NetworkBinary {
        match self {
            BinaryDef::Path(path) => ir::NetworkBinary { path },
            BinaryDef::Object(o) => ir::NetworkBinary { path: o.path },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialDef {
    #[serde(rename = "envVars", default)]
    env_vars: Vec<String>,
    #[serde(default)]
    style: String,
    #[serde(default)]
    header: String,
    #[serde(rename = "queryParam", default)]
    query_param: String,
    #[serde(rename = "pathTemplate", default)]
    path_template: String,
    #[serde(default)]
    source: Option<SourceDef>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    discoverable: Option<bool>,
    #[serde(default)]
    required: bool,
}

// Tagged on `kind` — the discriminator over the supported credential sources.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum SourceDef {
    HostEnv(HostEnvDef),
    Oauth2(OAuth2Def),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEnvDef {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuth2Def {
    #[serde(default)]
    grant: String,
    #[serde(rename = "tokenUrl", default)]
    token_url: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(rename = "refreshBeforeSeconds", default)]
    refresh_before_seconds: i64,
    #[serde(rename = "maxLifetimeSeconds", default)]
    max_lifetime_seconds: i64,
    #[serde(default)]
    parameters: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Parse tree → canonical IR
// ---------------------------------------------------------------------------

fn to_ir(doc: Document) -> ir::Provider {
    let metadata = doc.metadata.map(|m| ir::ObjectMeta {
        name: m.name,
        namespace: m.namespace,
        version: m.version,
        title: m.title,
        description: m.description,
    });
    ir::Provider {
        metadata,
        spec: Some(ir::ProviderSpec {
            r#type: doc.spec.provider_type,
            endpoints: doc
                .spec
                .endpoints
                .into_iter()
                .map(frontend::to_endpoint)
                .collect(),
            binaries: doc
                .spec
                .binaries
                .into_iter()
                .map(BinaryDef::into_ir)
                .collect(),
            credentials: doc
                .spec
                .credentials
                .into_iter()
                .map(to_credential)
                .collect(),
        }),
    }
}

fn to_credential(c: CredentialDef) -> ir::Credential {
    ir::Credential {
        env_vars: c.env_vars,
        style: c.style,
        header: c.header,
        query_param: c.query_param,
        path_template: c.path_template,
        source: c.source.map(to_source),
        name: c.name,
        discoverable: c.discoverable,
        required: c.required,
    }
}

fn to_source(s: SourceDef) -> ir::CredentialSource {
    use ir::credential_source::Kind;
    let kind = match s {
        SourceDef::HostEnv(h) => Kind::HostEnv(ir::HostEnvSource { name: h.name }),
        SourceDef::Oauth2(o) => Kind::Oauth2(ir::OAuth2Source {
            grant: o.grant,
            token_url: o.token_url,
            scopes: o.scopes,
            refresh_before_seconds: o.refresh_before_seconds,
            max_lifetime_seconds: o.max_lifetime_seconds,
            parameters: o.parameters,
        }),
    };
    ir::CredentialSource { kind: Some(kind) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::credential_source::Kind;

    // Provider type: source-control (github, env-var credential).
    const GITHUB: &str = r#"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: Provider
metadata: { name: github }
spec:
  type: source-control
  binaries: [/usr/bin/gh]
  endpoints: [{ host: api.github.com, port: 443, protocol: rest, access: read-write }]
  credentials:
    - envVars: [GITHUB_TOKEN]
      style: bearer
      header: Authorization
"#;

    // Provider type: inference (generic, env-var API key).
    const INFERENCE_API: &str = r#"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: Provider
metadata: { name: inference-api }
spec:
  type: inference
  endpoints:
    - { host: inference-api.example.com, port: 443, protocol: rest, access: read-write }
  credentials:
    - envVars: [INFERENCE_API_KEY]
      style: bearer
"#;

    // Provider type: data (pypi, no credentials).
    const PYPI: &str = r#"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: Provider
metadata: { name: pypi }
spec:
  type: data
  endpoints:
    - { host: pypi.org, port: 443 }
    - { host: files.pythonhosted.org, port: 443 }
  binaries: [/usr/bin/python3.13]
"#;

    // oauth2 client-credentials credential.
    const OAUTH2: &str = r#"
apiVersion: nvidia.agent-policy-fabric.policy/v1alpha1
kind: Provider
metadata: { name: service }
spec:
  type: other
  endpoints:
    - { host: api.example, port: 443 }
  credentials:
    - envVars: [SERVICE_TOKEN]
      style: bearer
      source:
        kind: oauth2
        grant: client-credentials
        tokenUrl: https://idp.example/oauth2/token
        scopes: [api.read]
        parameters:
          client_id: ACME_CLIENT_ID
          client_secret: ACME_CLIENT_SECRET
"#;

    fn spec(doc: &ir::Provider) -> &ir::ProviderSpec {
        doc.spec.as_ref().expect("spec present")
    }

    #[test]
    fn parses_source_control_env_var() {
        let p = parse(GITHUB.as_bytes()).expect("github parses");
        assert_eq!(p.metadata.as_ref().unwrap().name, "github");
        let s = spec(&p);
        assert_eq!(s.r#type, "source-control");
        assert_eq!(
            s.binaries,
            vec![ir::NetworkBinary {
                path: "/usr/bin/gh".into()
            }]
        );
        assert_eq!(s.endpoints.len(), 1);
        let ep = &s.endpoints[0];
        assert_eq!(ep.host, "api.github.com");
        assert_eq!(ep.port, 443);
        // Single port promoted into the ports array (shared NetworkEndpoint normalization).
        assert_eq!(ep.ports, vec![443]);
        assert_eq!(ep.protocol, "rest");
        assert_eq!(ep.access, "read-write");
        assert_eq!(s.credentials.len(), 1);
        let cred = &s.credentials[0];
        assert_eq!(cred.env_vars, vec!["GITHUB_TOKEN"]);
        assert_eq!(cred.style, "bearer");
        // No source authored → host-env default applied later at compile (Step 6).
        assert!(cred.source.is_none());
        // discoverable unauthored → None; default-true applied at compile (Step 6).
        assert!(cred.discoverable.is_none());
        assert!(cred.name.is_empty());
    }

    #[test]
    fn parses_inference_env_var() {
        let p = parse(INFERENCE_API.as_bytes()).expect("inference-api parses");
        let s = spec(&p);
        assert_eq!(s.r#type, "inference");
        assert_eq!(s.endpoints[0].host, "inference-api.example.com");
        assert!(s.binaries.is_empty());
        assert_eq!(s.credentials[0].env_vars, vec!["INFERENCE_API_KEY"]);
        assert_eq!(s.credentials[0].style, "bearer");
    }

    #[test]
    fn parses_data_no_credentials() {
        let p = parse(PYPI.as_bytes()).expect("pypi parses");
        let s = spec(&p);
        assert_eq!(s.r#type, "data");
        let hosts: Vec<&str> = s.endpoints.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["pypi.org", "files.pythonhosted.org"]);
        assert_eq!(
            s.binaries,
            vec![ir::NetworkBinary {
                path: "/usr/bin/python3.13".into()
            }]
        );
        assert!(s.credentials.is_empty());
    }

    #[test]
    fn parses_oauth2_client_credentials() {
        let p = parse(OAUTH2.as_bytes()).expect("oauth2 parses");
        let cred = &spec(&p).credentials[0];
        assert_eq!(cred.env_vars, vec!["SERVICE_TOKEN"]);
        let src = cred.source.as_ref().expect("source present");
        match src.kind.as_ref().expect("kind present") {
            Kind::Oauth2(o) => {
                assert_eq!(o.grant, "client-credentials");
                assert_eq!(o.token_url, "https://idp.example/oauth2/token");
                assert_eq!(o.scopes, vec!["api.read"]);
                assert_eq!(
                    o.parameters.get("client_id").map(String::as_str),
                    Some("ACME_CLIENT_ID")
                );
                assert_eq!(
                    o.parameters.get("client_secret").map(String::as_str),
                    Some("ACME_CLIENT_SECRET")
                );
            }
            other => panic!("expected oauth2 source, got {other:?}"),
        }
    }

    #[test]
    fn parses_host_env_explicit_with_name() {
        let yaml = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - envVars: [INJECTED]
      source: { kind: host-env, name: HOST_VAR }
      discoverable: false
      name: primary
"#;
        let p = parse(yaml.as_bytes()).expect("parses");
        let cred = &spec(&p).credentials[0];
        assert_eq!(cred.name, "primary");
        assert_eq!(cred.discoverable, Some(false));
        match cred.source.as_ref().unwrap().kind.as_ref().unwrap() {
            Kind::HostEnv(h) => assert_eq!(h.name, "HOST_VAR"),
            other => panic!("expected host-env, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_source_kind() {
        let yaml = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  credentials:
    - envVars: [X]
      source: { kind: vault-secret }
"#;
        let err = parse(yaml.as_bytes()).expect_err("deferred source kind must reject");
        assert!(
            format!("{err}").contains("kind") || format!("{err}").contains("variant"),
            "error should mention the unknown kind: {err}"
        );
    }

    #[test]
    fn validate_accepts_well_formed_provider() {
        let p = parse(GITHUB.as_bytes()).expect("parses");
        validate(&p).expect("well-formed provider validates");
    }

    #[test]
    fn validate_rejects_empty_host() {
        let yaml = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: "", port: 443 }]
"#;
        let p = parse(yaml.as_bytes()).expect("parses");
        assert!(matches!(
            validate(&p),
            Err(ValidationError::EmptyHost { .. })
        ));
    }

    #[test]
    fn validate_rejects_missing_port() {
        let yaml = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example }]
"#;
        let p = parse(yaml.as_bytes()).expect("parses");
        assert!(matches!(validate(&p), Err(ValidationError::NoPort { .. })));
    }

    #[test]
    fn validate_rejects_header_style_without_header() {
        let yaml = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - envVars: [X]
      style: header
"#;
        let p = parse(yaml.as_bytes()).expect("parses");
        match validate(&p) {
            Err(ValidationError::StyleMissingField { style, field, .. }) => {
                assert_eq!(style, "header");
                assert_eq!(field, "header");
            }
            other => panic!("expected StyleMissingField, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_bearer_style_without_header() {
        let yaml = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - envVars: [TOKEN]
      style: bearer
"#;
        let p = parse(yaml.as_bytes()).expect("parses");
        match validate(&p) {
            Err(ValidationError::StyleMissingField { style, field, .. }) => {
                assert_eq!(style, "bearer");
                assert_eq!(field, "header");
            }
            other => panic!("expected StyleMissingField, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_header_style_with_header() {
        let yaml = r#"
kind: Provider
metadata: { name: p }
spec:
  type: other
  endpoints: [{ host: api.example, port: 443 }]
  credentials:
    - envVars: [X]
      style: header
      header: X-Api-Key
"#;
        let p = parse(yaml.as_bytes()).expect("parses");
        validate(&p).expect("header style with header validates");
    }

    #[test]
    fn rejects_unknown_spec_field() {
        let yaml = "spec:\n  type: other\n  bogus: true\n";
        let err = parse(yaml.as_bytes()).expect_err("unknown field must reject");
        assert!(format!("{err}").contains("bogus"));
    }
}
