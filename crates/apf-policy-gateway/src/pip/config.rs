// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Deployment-owned provider registration: the `--pip-config` file model,
//! its validation, and the lowering of an `http` registration into the form
//! the REST transport consumes.
//!
//! A registration names the provider, the context namespace policy reads it
//! under, the transport type, the requests it applies to, the endpoint, the
//! failure mode and the per-lookup timeout. An `http` registration also
//! describes the request (query parameters and the keys that fill them) and
//! the response (where the record is, how it is checked, which fields become
//! claims). A field ref in the response block names one top-level field by
//! its API name or gives a JSON pointer; lowering turns both into pointers.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use super::subject::SubjectPath;

/// Most providers one gateway consults.
pub const MAX_PROVIDERS: usize = 16;
/// Size cap on the registration file.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// Length cap on a correlation id forwarded to providers.
pub const MAX_CORRELATION_ID_BYTES: usize = 256;
/// Most keys one `http` request may take.
pub const MAX_KEYS: usize = 8;
/// Most entries in `applies_to`.
pub const MAX_APPLIES_TO: usize = 64;
/// In-flight lookups per provider; one more fails with `Capacity`.
pub const MAX_IN_FLIGHT: usize = 32;

/// The registration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    pub providers: Vec<ProviderRegistration>,
}

/// One registered provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRegistration {
    /// Label in audit records and deny reasons.
    pub name: String,
    /// Context namespace; policy reads `context.<context>.*`. The wire
    /// contract and audit records carry it as the domain.
    pub context: String,
    /// Transport type: `grpc` speaks the contract, `http` calls a JSON API.
    #[serde(rename = "type")]
    pub kind: ProviderKind,
    /// Tool names or action ids the provider runs for; every request when
    /// absent.
    pub applies_to: Option<Vec<String>>,
    pub endpoint: Endpoint,
    /// Request shape; `http` only. Absent means a fixed lookup with no keys.
    pub request: Option<Request>,
    /// Response handling; `http` only.
    pub response: Option<Response>,
    pub on_failure: FailureMode,
    /// Per-lookup timeout; the stage cap when absent.
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Grpc,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    FailClosed,
    Degrade,
}

/// When a provider is consulted: a request whose tool name or action id is
/// listed. An empty list selects every request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trigger {
    pub applies_to: Vec<String>,
}

impl Trigger {
    #[must_use]
    pub fn new(applies_to: Vec<String>) -> Self {
        Self { applies_to }
    }

    /// Whether the trigger selects a request with this action id and tool.
    #[must_use]
    pub fn matches(&self, action_id: &str, tool: Option<&str>) -> bool {
        self.applies_to.is_empty()
            || self
                .applies_to
                .iter()
                .any(|entry| entry == action_id || tool == Some(entry.as_str()))
    }
}

/// Where and how the provider is reached.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// `https://host[:port]`, `http://` for a loopback host, or
    /// `unix:///path` for `grpc`. An `http` URL may hold `{key}` tokens in
    /// its path segments.
    pub url: String,
    /// Pinned CA and client identity for a `grpc` `https://` endpoint.
    pub tls: Option<TlsConfig>,
    /// UID the provider runs as, for a `grpc` `unix://` endpoint.
    pub peer_uid: Option<u32>,
    /// Credentials for an `http` endpoint.
    pub auth: Option<HttpAuth>,
}

/// Mutual TLS material: the CA that signs the provider's certificate and the
/// gateway's own client identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub ca_file: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
}

/// Credentials for an `http` endpoint; exactly one must be set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpAuth {
    pub bearer_token_file: Option<PathBuf>,
    /// File holding the user on the first line and the password on the second.
    pub basic_auth_file: Option<PathBuf>,
}

/// The request an `http` provider receives.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Query parameters; a value is a literal or exactly one `{key}` token.
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    /// Keys that fill the tokens, by name.
    #[serde(default)]
    pub keys: BTreeMap<String, KeySpec>,
}

/// One lookup key: the subject field it comes from and the shape it must
/// have.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    pub from: SubjectPath,
    /// Anchored regular expression the value must match.
    pub pattern: String,
}

/// How an `http` provider's response becomes claims.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Field ref of the record in the body; the body itself when absent. A
    /// list there must hold exactly one record.
    pub record_path: Option<String>,
    /// Record fields that must equal a key, as field ref to `{key}` token.
    #[serde(default)]
    pub must_match: BTreeMap<String, String>,
    /// Fields kept as claims; presence-only when absent.
    pub keep: Option<Keep>,
}

/// Which record fields become claims.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Keep {
    /// API field names kept under their own names.
    Names(Vec<String>),
    /// Claim name to the field ref it reads.
    Renamed(BTreeMap<String, String>),
}

/// Gateway-wide constraints the registrations must respect.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Hard cap on the whole enrichment stage; no provider timeout may
    /// exceed it, and it is the timeout of a provider that names none.
    pub stage_budget: Duration,
    /// The gateway's own evaluation socket, which no provider may alias.
    pub gateway_socket: Option<PathBuf>,
}

/// Parsed form of a `grpc` registration's endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointKind {
    Unix(PathBuf),
    Https(url::Url),
    HttpLoopback(url::Url),
}

/// An `http` registration lowered to what the REST transport consumes:
/// parameters instead of keys, JSON pointers instead of field refs, and the
/// resolved timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSource {
    /// Endpoint URL; path segments may hold `{param}` tokens.
    pub url: String,
    /// Query pairs; a value is a literal or one `{param}` token.
    pub query: BTreeMap<String, String>,
    pub params: Vec<HttpParam>,
    pub auth: Option<HttpAuth>,
    /// Client timeout, equal to the lookup budget.
    pub timeout: Duration,
    /// JSON pointer to the record; the body itself when absent.
    pub select: Option<String>,
    /// Record fields that must carry a parameter's value.
    pub matches: Vec<MatchSpec>,
    /// Claim name to the JSON pointer it reads; empty means presence-only.
    pub claims: BTreeMap<String, String>,
}

/// A request parameter resolved from the subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpParam {
    pub name: String,
    pub from: SubjectPath,
    /// Anchored regular expression the resolved value must match.
    pub pattern: String,
}

/// One record field the answer must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchSpec {
    /// JSON pointer into the record.
    pub pointer: String,
    /// Parameter whose value the record must hold there.
    pub param: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid provider registration YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid provider registration: {0}")]
    Invalid(String),
    #[error("provider '{provider}': {reason}")]
    Provider { provider: String, reason: String },
}

impl ConfigError {
    fn provider(name: &str, reason: impl Into<String>) -> Self {
        Self::Provider {
            provider: name.to_owned(),
            reason: reason.into(),
        }
    }
}

impl RegistryConfig {
    /// Parse the registration file. Validation is separate so callers can
    /// report every structural problem with its provider name.
    ///
    /// # Errors
    ///
    /// Returns the YAML error.
    pub fn from_yaml(bytes: &[u8]) -> Result<Self, ConfigError> {
        Ok(serde_yaml::from_slice(bytes)?)
    }

    /// Check every registration against the contract rules and `limits`.
    ///
    /// # Errors
    ///
    /// Returns the first violation.
    pub fn validate(&self, limits: &Limits) -> Result<(), ConfigError> {
        if self.providers.is_empty() || self.providers.len() > MAX_PROVIDERS {
            return Err(ConfigError::Invalid(format!(
                "providers must list between 1 and {MAX_PROVIDERS} entries"
            )));
        }
        let mut names = HashSet::new();
        let mut contexts = HashSet::new();
        for registration in &self.providers {
            registration.validate(limits)?;
            if !names.insert(registration.name.as_str()) {
                return Err(ConfigError::provider(
                    &registration.name,
                    "provider names must be unique",
                ));
            }
            if !contexts.insert(registration.context.as_str()) {
                return Err(ConfigError::provider(
                    &registration.name,
                    format!(
                        "context '{}' already has a registered provider",
                        registration.context
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl ProviderRegistration {
    /// Per-lookup budget: `timeout_ms`, or the stage cap when absent.
    #[must_use]
    pub fn budget(&self, limits: &Limits) -> Duration {
        self.timeout_ms
            .map_or(limits.stage_budget, Duration::from_millis)
    }

    /// Trigger built from `applies_to`; one that matches everything when
    /// absent.
    #[must_use]
    pub fn trigger(&self) -> Trigger {
        Trigger::new(self.applies_to.clone().unwrap_or_default())
    }

    /// Subject fields the provider receives: the distinct sources of its keys
    /// for `http`, identity and action for `grpc`.
    #[must_use]
    pub fn subject_paths(&self) -> Vec<SubjectPath> {
        match self.kind {
            ProviderKind::Grpc => super::subject::default_subject(),
            ProviderKind::Http => {
                let mut paths: Vec<SubjectPath> = Vec::new();
                for key in self
                    .request
                    .iter()
                    .flat_map(|request| request.keys.values())
                {
                    if !paths.contains(&key.from) {
                        paths.push(key.from.clone());
                    }
                }
                paths
            }
        }
    }

    /// Parse and classify a `grpc` endpoint.
    ///
    /// # Errors
    ///
    /// Returns the reason the endpoint is unusable.
    pub fn endpoint_kind(&self) -> Result<EndpointKind, ConfigError> {
        let fail =
            |reason: String| ConfigError::provider(&self.name, format!("endpoint.url: {reason}"));
        let endpoint = self.endpoint.url.as_str();
        if let Some(path) = endpoint.strip_prefix("unix://") {
            return unix_socket_path(path).map(EndpointKind::Unix).map_err(fail);
        }
        let url = parse_endpoint_url(endpoint).map_err(fail)?;
        match url.scheme() {
            "https" => Ok(EndpointKind::Https(url)),
            "http" if is_loopback_host(&url) => Ok(EndpointKind::HttpLoopback(url)),
            "http" => Err(fail(
                "plain http endpoints are allowed for loopback hosts only".to_owned(),
            )),
            other => Err(fail(format!("unsupported scheme '{other}'"))),
        }
    }

    /// Lower an `http` registration for the REST transport, checking the
    /// endpoint, request and response rules on the way.
    ///
    /// # Errors
    ///
    /// Returns the first violation, naming the key path.
    pub fn http_source(&self, limits: &Limits) -> Result<HttpSource, ConfigError> {
        let fail = |reason: String| ConfigError::provider(&self.name, reason);
        if self.kind != ProviderKind::Http {
            return Err(fail(
                "only type: http registrations describe a REST source".to_owned(),
            ));
        }
        let url = parse_endpoint_url(&self.endpoint.url)
            .map_err(|reason| fail(format!("endpoint.url: {reason}")))?;
        match url.scheme() {
            "https" => {}
            "http" if is_loopback_host(&url) => {}
            "http" => {
                return Err(fail(
                    "endpoint.url: plain http is allowed for loopback hosts only".to_owned(),
                ));
            }
            other => return Err(fail(format!("endpoint.url: unsupported scheme '{other}'"))),
        }

        let fixed = Request::default();
        let request = self.request.as_ref().unwrap_or(&fixed);
        validate_keys(&request.keys).map_err(fail)?;
        let defined = |token: &str| request.keys.contains_key(token);
        let undefined = |place: &str, token: &str| {
            fail(format!(
                "{place} references key '{token}', which request.keys does not define"
            ))
        };

        let mut used: HashSet<&str> = HashSet::new();
        for token in url_tokens(&self.endpoint.url)
            .map_err(|reason| fail(format!("endpoint.url: {reason}")))?
        {
            if !defined(token) {
                return Err(undefined("endpoint.url", token));
            }
            used.insert(token);
        }
        for (parameter, value) in &request.query {
            if parameter.contains(['{', '}']) {
                return Err(fail(format!(
                    "request.query parameter names are literal; '{parameter}' cannot hold a {{key}} token"
                )));
            }
            if let Some(token) = single_token(value)
                .map_err(|reason| fail(format!("request.query.{parameter} {reason}")))?
            {
                if !defined(token) {
                    return Err(undefined(&format!("request.query.{parameter}"), token));
                }
                used.insert(token);
            }
        }
        if let Some(unused) = request
            .keys
            .keys()
            .find(|name| !used.contains(name.as_str()))
        {
            return Err(fail(format!(
                "request.keys.{unused} is never used in endpoint.url or request.query"
            )));
        }

        let presence_only = Response::default();
        let response = self.response.as_ref().unwrap_or(&presence_only);
        let select = response
            .record_path
            .as_deref()
            .map(|field| {
                field_ref_pointer(field)
                    .map_err(|reason| fail(format!("response.record_path {reason}")))
            })
            .transpose()?;
        let mut matches = Vec::with_capacity(response.must_match.len());
        for (field, value) in &response.must_match {
            let pointer = field_ref_pointer(field)
                .map_err(|reason| fail(format!("response.must_match.{field} {reason}")))?;
            let token = single_token(value).ok().flatten().ok_or_else(|| {
                fail(format!(
                    "response.must_match.{field} must be exactly one {{key}} token"
                ))
            })?;
            if !defined(token) {
                return Err(undefined(&format!("response.must_match.{field}"), token));
            }
            matches.push(MatchSpec {
                pointer,
                param: token.to_owned(),
            });
        }
        let claims = lower_keep(response.keep.as_ref()).map_err(fail)?;

        if let Some(auth) = &self.endpoint.auth {
            let configured = usize::from(auth.bearer_token_file.is_some())
                + usize::from(auth.basic_auth_file.is_some());
            if configured != 1 {
                return Err(fail(
                    "endpoint.auth must set exactly one of bearer_token_file or basic_auth_file"
                        .to_owned(),
                ));
            }
        }

        Ok(HttpSource {
            url: self.endpoint.url.clone(),
            query: request.query.clone(),
            params: request
                .keys
                .iter()
                .map(|(name, key)| HttpParam {
                    name: name.clone(),
                    from: key.from.clone(),
                    pattern: key.pattern.clone(),
                })
                .collect(),
            auth: self.endpoint.auth.clone(),
            timeout: self.budget(limits),
            select,
            matches,
            claims,
        })
    }

    fn validate(&self, limits: &Limits) -> Result<(), ConfigError> {
        let fail = |reason: String| ConfigError::provider(&self.name, reason);
        if !is_valid_name(&self.name) {
            return Err(ConfigError::Invalid(format!(
                "provider name '{}' must be 1-64 ASCII letters, digits, dots, underscores or hyphens",
                self.name
            )));
        }
        if apf_audit::has_forbidden_key_name(&self.name) {
            return Err(fail(
                "provider name contains a word the audit sanitizer rejects".to_owned(),
            ));
        }
        if !apf_audit::SanitizationGuard::accepts_string(&self.name) {
            return Err(fail(
                "provider name reads as a credential-like value to the audit sanitizer".to_owned(),
            ));
        }
        validate_context(&self.context).map_err(fail)?;
        if let Some(applies_to) = &self.applies_to {
            validate_applies_to(applies_to).map_err(fail)?;
        }
        let cap = u64::try_from(limits.stage_budget.as_millis()).unwrap_or(u64::MAX);
        if let Some(timeout_ms) = self.timeout_ms
            && (timeout_ms == 0 || timeout_ms > cap)
        {
            return Err(fail(format!(
                "timeout_ms must be between 1 and the stage budget of {cap} ms"
            )));
        }

        match self.kind {
            ProviderKind::Grpc => {
                if self.endpoint.auth.is_some() {
                    return Err(fail(
                        "endpoint.auth is only valid for type: http".to_owned(),
                    ));
                }
                if self.request.is_some() {
                    return Err(fail("request is only valid for type: http".to_owned()));
                }
                if self.response.is_some() {
                    return Err(fail("response is only valid for type: http".to_owned()));
                }
                if self.endpoint.url.contains(['{', '}']) {
                    return Err(fail(
                        "endpoint.url cannot hold {key} tokens for type: grpc".to_owned(),
                    ));
                }
                match self.endpoint_kind()? {
                    EndpointKind::Unix(path) => {
                        if self.endpoint.tls.is_some() {
                            return Err(fail(
                                "endpoint.tls is only valid for https:// endpoints".to_owned(),
                            ));
                        }
                        if let Some(gateway_socket) = &limits.gateway_socket {
                            ensure_distinct_sockets(&path, gateway_socket)
                                .map_err(|reason| fail(format!("endpoint.url: {reason}")))?;
                        }
                    }
                    EndpointKind::Https(_) => {
                        if self.endpoint.tls.is_none() {
                            return Err(fail(
                                "endpoint.tls with ca_file, client_cert_file and client_key_file is required for https:// endpoints"
                                    .to_owned(),
                            ));
                        }
                        if self.endpoint.peer_uid.is_some() {
                            return Err(fail(
                                "endpoint.peer_uid is only valid for unix:// endpoints".to_owned(),
                            ));
                        }
                    }
                    EndpointKind::HttpLoopback(_) => {
                        if self.endpoint.tls.is_some() {
                            return Err(fail(
                                "endpoint.tls is only valid for https:// endpoints".to_owned(),
                            ));
                        }
                        if self.endpoint.peer_uid.is_some() {
                            return Err(fail(
                                "endpoint.peer_uid is only valid for unix:// endpoints".to_owned(),
                            ));
                        }
                    }
                }
                Ok(())
            }
            ProviderKind::Http => {
                if self.endpoint.tls.is_some() {
                    return Err(fail(
                        "endpoint.tls: client certificates for http endpoints are not supported in this release"
                            .to_owned(),
                    ));
                }
                if self.endpoint.peer_uid.is_some() {
                    return Err(fail(
                        "endpoint.peer_uid is only valid for a unix:// endpoint of type: grpc"
                            .to_owned(),
                    ));
                }
                self.http_source(limits).map(drop)
            }
        }
    }
}

fn validate_keys(keys: &BTreeMap<String, KeySpec>) -> Result<(), String> {
    if keys.len() > MAX_KEYS {
        return Err(format!(
            "request.keys lists {} keys; at most {MAX_KEYS} are allowed",
            keys.len()
        ));
    }
    for (name, key) in keys {
        if !is_lower_identifier(name, 64) {
            return Err(format!(
                "request.keys.{name}: key names must be 1-64 lower-case letters, digits or underscores and start with a letter"
            ));
        }
        if !(key.pattern.starts_with('^') && key.pattern.ends_with('$')) {
            return Err(format!(
                "request.keys.{name}.pattern must be anchored with ^ and $"
            ));
        }
        compile_param_pattern(&key.pattern)
            .map_err(|error| format!("request.keys.{name}.pattern is invalid: {error}"))?;
    }
    Ok(())
}

/// Claim name to JSON pointer for a `keep` block; empty when absent.
fn lower_keep(keep: Option<&Keep>) -> Result<BTreeMap<String, String>, String> {
    const EMPTY: &str =
        "response.keep must name at least one field; omit it for a presence-only lookup";
    let mut claims = BTreeMap::new();
    match keep {
        None => {}
        Some(Keep::Names(names)) => {
            if names.is_empty() {
                return Err(EMPTY.to_owned());
            }
            for name in names {
                if !is_lower_identifier(name, 64) {
                    return Err(format!(
                        "response.keep entry '{name}' is not a valid claim name (1-64 lower-case letters, digits or underscores, starting with a letter); use the map form to rename the field, e.g. keep: {{ <claim>: {name} }}"
                    ));
                }
                if claims.insert(name.clone(), format!("/{name}")).is_some() {
                    return Err(format!("response.keep lists '{name}' twice"));
                }
            }
        }
        Some(Keep::Renamed(renamed)) => {
            if renamed.is_empty() {
                return Err(EMPTY.to_owned());
            }
            for (claim, field) in renamed {
                if !is_lower_identifier(claim, 64) {
                    return Err(format!(
                        "response.keep.{claim}: claim names must be 1-64 lower-case letters, digits or underscores and start with a letter"
                    ));
                }
                let pointer = field_ref_pointer(field)
                    .map_err(|reason| format!("response.keep.{claim} {reason}"))?;
                claims.insert(claim.clone(), pointer);
            }
        }
    }
    Ok(claims)
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

/// `[a-z][a-z0-9_]*` within `max_len` bytes: the shape of contexts, key
/// names and claim names. `_meta` cannot pass, so no claim can shadow the
/// provenance record.
fn is_lower_identifier(name: &str, max_len: usize) -> bool {
    !name.is_empty()
        && name.len() <= max_len
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_context(context: &str) -> Result<(), String> {
    if !is_lower_identifier(context, 32) {
        return Err(format!(
            "context '{context}' must be 1-32 lower-case letters, digits or underscores and start with a letter"
        ));
    }
    if apf_policy_eval::RESERVED_CONTEXT_ROOTS.contains(&context) {
        return Err(format!("context '{context}' is a reserved context root"));
    }
    if apf_audit::has_forbidden_key_name(context) {
        return Err(format!(
            "context '{context}' contains a word the audit sanitizer rejects"
        ));
    }
    if !apf_audit::SanitizationGuard::accepts_string(context) {
        return Err(format!(
            "context '{context}' reads as a credential-like value to the audit sanitizer"
        ));
    }
    Ok(())
}

fn validate_applies_to(entries: &[String]) -> Result<(), String> {
    if entries.is_empty() || entries.len() > MAX_APPLIES_TO {
        return Err(format!(
            "applies_to must list between 1 and {MAX_APPLIES_TO} entries; omit it to run for every request"
        ));
    }
    for entry in entries {
        let ok = !entry.is_empty()
            && entry.len() <= 256
            && entry
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/@".contains(&byte));
        if !ok {
            return Err(format!(
                "applies_to entry '{entry}' must be 1-256 ASCII letters, digits or -_.:/@"
            ));
        }
    }
    Ok(())
}

fn unix_socket_path(path: &str) -> Result<PathBuf, String> {
    let ok = path.starts_with('/')
        && !path.ends_with('/')
        && !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '?' | '#' | '%'))
        && !path.split('/').any(|segment| matches!(segment, "." | ".."));
    if !ok {
        return Err(
            "unix endpoints must be absolute paths without traversal, query, fragment or percent escapes"
                .to_owned(),
        );
    }
    Ok(PathBuf::from(path))
}

fn parse_endpoint_url(text: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(text).map_err(|error| format!("invalid URL: {error}"))?;
    if url.host_str().is_none() {
        return Err("URL must name a host".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not carry credentials".to_owned());
    }
    if url.fragment().is_some() {
        return Err("URL must not carry a fragment".to_owned());
    }
    Ok(url)
}

/// Whether a URL names `localhost` or a loopback address, where plain `http`
/// is allowed. Every transport applies this one rule.
pub(crate) fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Compile a key pattern so that the whole value must match it. The
/// configured expression is grouped before it is anchored, so a top-level
/// alternation cannot match a prefix or a suffix on its own.
///
/// # Errors
///
/// Returns the regex error.
pub(crate) fn compile_param_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::Regex::new(&format!("^(?:{pattern})$"))
}

/// Convert a field ref to a JSON pointer: a bare name is one top-level
/// field, escaped per RFC 6901; a value starting with `/` is a pointer
/// already.
fn field_ref_pointer(field: &str) -> Result<String, String> {
    if field.is_empty() {
        return Err("must not be empty".to_owned());
    }
    if field.starts_with('/') {
        return Ok(field.to_owned());
    }
    if field.contains('/') {
        return Err("must be a bare field name or a JSON pointer starting with /".to_owned());
    }
    Ok(format!("/{}", field.replace('~', "~0")))
}

/// The key a template value names: `None` for a literal without braces, the
/// key for exactly one `{key}` token, an error for anything else.
fn single_token(value: &str) -> Result<Option<&str>, String> {
    if !value.contains(['{', '}']) {
        return Ok(None);
    }
    value
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|name| !name.is_empty() && !name.contains(['{', '}']))
        .map(Some)
        .ok_or_else(|| "must be a literal or exactly one {key} token".to_owned())
}

/// The `{key}` tokens of a URL template, which may appear in its path only.
fn url_tokens(raw: &str) -> Result<Vec<&str>, String> {
    let (without_query, static_query) = match raw.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (raw, None),
    };
    let authority_start = without_query
        .find("://")
        .map(|index| index + 3)
        .ok_or_else(|| "must be an absolute URL".to_owned())?;
    let path_start = without_query[authority_start..]
        .find('/')
        .map_or(without_query.len(), |index| authority_start + index);
    if without_query[..path_start].contains(['{', '}']) {
        return Err("the scheme, host and port cannot hold {key} tokens".to_owned());
    }
    if static_query.is_some_and(|query| query.contains(['{', '}'])) {
        return Err(
            "{key} tokens are not supported in the URL query string; use request.query".to_owned(),
        );
    }
    tokens(&without_query[path_start..])
}

/// The `{key}` tokens of a template, in order.
fn tokens(template: &str) -> Result<Vec<&str>, String> {
    let mut found = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        if rest[..start].contains('}') {
            return Err("stray '}'".to_owned());
        }
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            return Err("unterminated '{' token".to_owned());
        };
        let name = &after[..end];
        if name.is_empty() || name.contains('{') {
            return Err("malformed {key} token".to_owned());
        }
        found.push(name);
        rest = &after[end + 1..];
    }
    if rest.contains('}') {
        return Err("stray '}'".to_owned());
    }
    Ok(found)
}

/// A provider socket must not be the gateway's own evaluation listener,
/// neither by path nor by inode, since the gateway removes and rebinds that
/// path at startup.
fn ensure_distinct_sockets(provider: &Path, gateway: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if resolve_existing_prefix(provider)? == resolve_existing_prefix(gateway)? {
        return Err("provider socket cannot be the gateway's evaluation socket".to_owned());
    }
    if let (Ok(provider), Ok(gateway)) = (std::fs::metadata(provider), std::fs::metadata(gateway))
        && (provider.dev(), provider.ino()) == (gateway.dev(), gateway.ino())
    {
        return Err("provider socket aliases the gateway's evaluation socket".to_owned());
    }
    Ok(())
}

/// Canonicalize the longest existing prefix of `path` and re-append the rest,
/// so paths can be compared before either socket exists.
fn resolve_existing_prefix(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(path)
    };
    if absolute
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err("socket path cannot contain parent traversal".to_owned());
    }
    let mut parent = absolute.as_path();
    let mut suffix = Vec::new();
    loop {
        match parent.canonicalize() {
            Ok(mut canonical) => {
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                suffix.push(
                    parent
                        .file_name()
                        .ok_or_else(|| "invalid socket path".to_owned())?
                        .to_owned(),
                );
                parent = parent
                    .parent()
                    .ok_or_else(|| "invalid socket path".to_owned())?;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRPC_HTTPS_PROVIDER: &str = r#"
providers:
  - name: agent-registry
    context: agent
    type: grpc
    applies_to: [github_merge_pull_request]
    endpoint:
      url: https://registry.agents.example.com:8443
      tls:
        ca_file: /etc/apf/providers/registry-ca.pem
        client_cert_file: /etc/apf/providers/gateway.pem
        client_key_file: /etc/apf/providers/gateway.key
    on_failure: fail_closed
    timeout_ms: 150
"#;

    const HTTP_PROVIDER: &str = r#"
providers:
  - name: change-management
    context: change
    type: http
    applies_to: [github_merge_pull_request]
    endpoint:
      url: http://127.0.0.1:19500/api/now/table/change_request
      auth: { bearer_token_file: /etc/apf/providers/itsm.token }
    request:
      query: { cmdb_ci.name: "{repository}", state: scheduled }
      keys:
        repository: { from: args.repository, pattern: "^[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._-]{0,63}$" }
    response:
      record_path: result
      must_match: { cmdb_ci.name: "{repository}" }
      keep: [number, state, approval, risk]
    on_failure: degrade
    timeout_ms: 200
"#;

    const UNIX_PROVIDER: &str = r#"
providers:
  - name: identity
    context: identity
    type: grpc
    endpoint:
      url: unix:///run/apf/providers/identity.sock
      peer_uid: 1201
    on_failure: fail_closed
    timeout_ms: 20
"#;

    const TLS_BLOCK: &str = "      tls:\n        ca_file: /etc/apf/providers/registry-ca.pem\n        client_cert_file: /etc/apf/providers/gateway.pem\n        client_key_file: /etc/apf/providers/gateway.key\n";
    const KEEP_LIST: &str = "keep: [number, state, approval, risk]";
    const STRICT_PATTERN: &str =
        "pattern: \"^[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._-]{0,63}$\"";

    /// A request block with one key filling one query value.
    const REQUEST_BLOCK: &str = "    request:\n      query: { cmdb_ci.name: \"{repository}\", state: scheduled }\n      keys:\n        repository: { from: args.repository, pattern: '^[a-z/]+$' }\n";
    /// A response block checking and keeping fields of the selected record.
    const RESPONSE_BLOCK: &str = "    response:\n      record_path: result\n      must_match: { cmdb_ci.name: \"{repository}\" }\n      keep: [number, state]\n";

    /// An `http` registration on `url` with `blocks` between the endpoint
    /// and the failure mode.
    fn http(url: &str, blocks: &str) -> String {
        format!(
            "providers:\n  - name: a\n    context: change\n    type: http\n    endpoint:\n      url: {url}\n{blocks}    on_failure: degrade\n"
        )
    }

    fn limits() -> Limits {
        Limits {
            stage_budget: Duration::from_millis(250),
            gateway_socket: Some(PathBuf::from("/run/apf/policy-gateway.sock")),
        }
    }

    fn parse(yaml: &str) -> RegistryConfig {
        RegistryConfig::from_yaml(yaml.as_bytes()).expect("valid YAML")
    }

    fn validate(yaml: &str) -> Result<(), ConfigError> {
        parse(yaml).validate(&limits())
    }

    /// Parse and validate, flattening the error to its message.
    fn check(yaml: &str) -> Result<(), String> {
        RegistryConfig::from_yaml(yaml.as_bytes())
            .and_then(|config| config.validate(&limits()))
            .map_err(|error| error.to_string())
    }

    fn lower(yaml: &str) -> HttpSource {
        parse(yaml).providers[0]
            .http_source(&limits())
            .expect("registration lowers")
    }

    #[test]
    fn the_example_shapes_validate() {
        for yaml in [GRPC_HTTPS_PROVIDER, HTTP_PROVIDER, UNIX_PROVIDER] {
            validate(yaml).expect("example validates");
        }
        let grpc = &parse(GRPC_HTTPS_PROVIDER).providers[0];
        assert!(matches!(
            grpc.endpoint_kind().expect("https"),
            EndpointKind::Https(_)
        ));
        assert_eq!(grpc.budget(&limits()), Duration::from_millis(150));
        assert_eq!(
            grpc.subject_paths(),
            super::super::subject::default_subject()
        );
        assert!(
            grpc.trigger()
                .matches("github::merge", Some("github_merge_pull_request"))
        );
        assert!(grpc.trigger().matches("github_merge_pull_request", None));
        assert!(!grpc.trigger().matches("other", Some("other")));

        let http = &parse(HTTP_PROVIDER).providers[0];
        assert_eq!(
            http.subject_paths(),
            vec![SubjectPath::Arg("repository".to_owned())]
        );
        let source = http.http_source(&limits()).expect("lowers");
        assert_eq!(
            source.url,
            "http://127.0.0.1:19500/api/now/table/change_request"
        );
        assert_eq!(source.query["cmdb_ci.name"], "{repository}");
        assert_eq!(source.query["state"], "scheduled");
        assert_eq!(source.params.len(), 1);
        assert_eq!(source.params[0].name, "repository");
        assert_eq!(
            source.params[0].from,
            SubjectPath::Arg("repository".to_owned())
        );
        assert_eq!(source.timeout, Duration::from_millis(200));
        assert_eq!(source.select.as_deref(), Some("/result"));
        assert_eq!(
            source.matches,
            vec![MatchSpec {
                pointer: "/cmdb_ci.name".to_owned(),
                param: "repository".to_owned()
            }]
        );
        assert_eq!(
            source.claims.keys().cloned().collect::<Vec<_>>(),
            ["approval", "number", "risk", "state"]
        );
        assert_eq!(source.claims["number"], "/number");
        assert_eq!(
            source
                .auth
                .as_ref()
                .and_then(|auth| auth.bearer_token_file.as_deref()),
            Some(Path::new("/etc/apf/providers/itsm.token"))
        );

        let unix = &parse(UNIX_PROVIDER).providers[0];
        assert_eq!(
            unix.endpoint_kind().expect("unix"),
            EndpointKind::Unix(PathBuf::from("/run/apf/providers/identity.sock"))
        );
        assert_eq!(unix.budget(&limits()), Duration::from_millis(20));
        assert!(unix.trigger().matches("anything", None));
    }

    #[test]
    fn applies_to_matches_the_tool_name_or_the_action_id() {
        let trigger = Trigger::new(vec![
            "github_merge_pull_request".to_owned(),
            "gitlab::merge_request_merge".to_owned(),
        ]);
        assert!(trigger.matches("gitlab::merge_request_merge", Some("gitlab")));
        assert!(trigger.matches(
            "github::merge_pull_request",
            Some("github_merge_pull_request")
        ));
        assert!(trigger.matches("github_merge_pull_request", None));
        assert!(!trigger.matches("gitlab::merge_request_read", Some("gitlab")));
        assert!(!trigger.matches("x", None));
        assert!(Trigger::default().matches("x", None));
        assert_eq!(
            parse(UNIX_PROVIDER).providers[0].trigger(),
            Trigger::default()
        );
    }

    #[test]
    fn timeout_defaults_to_the_stage_cap() {
        let http = HTTP_PROVIDER.replace("    timeout_ms: 200\n", "");
        validate(&http).expect("an absent timeout validates");
        let registration = &parse(&http).providers[0];
        assert_eq!(registration.budget(&limits()), Duration::from_millis(250));
        assert_eq!(
            registration.http_source(&limits()).expect("lowers").timeout,
            Duration::from_millis(250)
        );
        let grpc = UNIX_PROVIDER.replace("    timeout_ms: 20\n", "");
        assert_eq!(
            parse(&grpc).providers[0].budget(&limits()),
            Duration::from_millis(250)
        );
        for bad in ["timeout_ms: 0", "timeout_ms: 251"] {
            let error = check(&UNIX_PROVIDER.replace("timeout_ms: 20", bad)).expect_err(bad);
            assert!(
                error.contains(
                    "provider 'identity': timeout_ms must be between 1 and the stage budget of 250 ms"
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn unknown_and_deferred_keys_are_rejected() {
        let cases = [
            (
                "legacy pips root",
                HTTP_PROVIDER.replace("providers:", "pips:"),
            ),
            (
                "domain",
                HTTP_PROVIDER.replace("context: change", "domain: change"),
            ),
            (
                "budget_ms",
                HTTP_PROVIDER.replace("timeout_ms: 200", "budget_ms: 200"),
            ),
            (
                "trigger",
                HTTP_PROVIDER.replace(
                    "applies_to: [github_merge_pull_request]",
                    "trigger: { tools: [github_merge_pull_request] }",
                ),
            ),
            (
                "subject",
                HTTP_PROVIDER.replace(
                    "    on_failure: degrade\n",
                    "    on_failure: degrade\n    subject: [action, args.repository]\n",
                ),
            ),
            (
                "cache",
                UNIX_PROVIDER.replace(
                    "    on_failure:",
                    "    cache: { ttl_seconds: 60 }\n    on_failure:",
                ),
            ),
            (
                "max_in_flight",
                UNIX_PROVIDER.replace("    on_failure:", "    max_in_flight: 4\n    on_failure:"),
            ),
            (
                "max_response_bytes",
                HTTP_PROVIDER.replace(
                    "    response:\n",
                    "    response:\n      max_response_bytes: 4096\n",
                ),
            ),
            (
                "method",
                HTTP_PROVIDER.replace("    request:\n", "    request:\n      method: POST\n"),
            ),
            (
                "body",
                HTTP_PROVIDER.replace(
                    "    request:\n",
                    "    request:\n      body: { ci: \"{repository}\" }\n",
                ),
            ),
            (
                "headers",
                HTTP_PROVIDER.replace(
                    "    request:\n",
                    "    request:\n      headers: { Accept: application/json }\n",
                ),
            ),
            (
                "claim coercion",
                HTTP_PROVIDER.replace(KEEP_LIST, "keep: { risk: { from: risk, as: int } }"),
            ),
            (
                "auth.mtls",
                HTTP_PROVIDER.replace(
                    "auth: { bearer_token_file: /etc/apf/providers/itsm.token }",
                    "auth: { mtls: { ca_file: /a, client_cert_file: /b, client_key_file: /c } }",
                ),
            ),
            (
                "source",
                UNIX_PROVIDER.replace(
                    "    on_failure:",
                    "    source: { url: https://example.com }\n    on_failure:",
                ),
            ),
            (
                "select",
                HTTP_PROVIDER.replace("record_path: result", "select: /result"),
            ),
            ("match", HTTP_PROVIDER.replace("must_match:", "match:")),
            ("claims", HTTP_PROVIDER.replace("keep:", "claims:")),
            (
                "params",
                HTTP_PROVIDER.replace("      keys:\n", "      params:\n"),
            ),
            (
                "key spec typo",
                HTTP_PROVIDER.replace("pattern:", "patern:"),
            ),
            (
                "missing type",
                UNIX_PROVIDER.replace("    type: grpc\n", ""),
            ),
            (
                "unknown type",
                UNIX_PROVIDER.replace("type: grpc", "type: rest"),
            ),
        ];
        for (label, yaml) in &cases {
            assert!(
                RegistryConfig::from_yaml(yaml.as_bytes()).is_err(),
                "{label} must be rejected when the file is parsed"
            );
        }
    }

    #[test]
    fn tokens_and_keys_must_agree() {
        let error = check(&http("http://127.0.0.1:9/api/{repo}", REQUEST_BLOCK))
            .expect_err("a url token without a key");
        assert!(
            error.contains(
                "provider 'a': endpoint.url references key 'repo', which request.keys does not define"
            ),
            "{error}"
        );
        let error = check(&http(
            "http://127.0.0.1:9/api",
            &REQUEST_BLOCK.replace("\"{repository}\"", "\"{repo}\""),
        ))
        .expect_err("a query token without a key");
        assert!(
            error.contains(
                "request.query.cmdb_ci.name references key 'repo', which request.keys does not define"
            ),
            "{error}"
        );
        let error = check(&http(
            "http://127.0.0.1:9/api",
            &REQUEST_BLOCK.replace("cmdb_ci.name: \"{repository}\", ", ""),
        ))
        .expect_err("a key that fills nothing");
        assert!(
            error
                .contains("request.keys.repository is never used in endpoint.url or request.query"),
            "{error}"
        );
        let error = check(&http(
            "http://127.0.0.1:9/api",
            &format!(
                "{REQUEST_BLOCK}{}",
                RESPONSE_BLOCK.replace("\"{repository}\"", "\"{repo}\"")
            ),
        ))
        .expect_err("a must_match token without a key");
        assert!(
            error.contains(
                "response.must_match.cmdb_ci.name references key 'repo', which request.keys does not define"
            ),
            "{error}"
        );
        let error = check(&http("http://127.0.0.1:9/api/{repository}", ""))
            .expect_err("a token with no request block");
        assert!(
            error.contains("endpoint.url references key 'repository'"),
            "{error}"
        );

        // One key may fill the path and the query; a fixed lookup needs
        // neither keys nor tokens.
        validate(&http("http://127.0.0.1:9/api/{repository}", REQUEST_BLOCK))
            .expect("a key used twice");
        validate(&http(
            "http://127.0.0.1:9/api",
            &format!("{REQUEST_BLOCK}{RESPONSE_BLOCK}"),
        ))
        .expect("request and response blocks");
        validate(&http("http://127.0.0.1:9/api", "")).expect("a fixed lookup");
        validate(&http(
            "http://127.0.0.1:9/api",
            "    request:\n      query: { state: scheduled }\n",
        ))
        .expect("a fixed lookup with a literal query");
    }

    #[test]
    fn must_match_values_are_single_key_tokens() {
        for value in [
            "scheduled",
            "\"x{repository}\"",
            "\"{repository}{repository}\"",
            "\"{}\"",
            "''",
        ] {
            let yaml = http(
                "http://127.0.0.1:9/api",
                &format!(
                    "{REQUEST_BLOCK}{}",
                    RESPONSE_BLOCK.replace("\"{repository}\"", value)
                ),
            );
            let error = check(&yaml).expect_err(value);
            assert!(
                error.contains(
                    "provider 'a': response.must_match.cmdb_ci.name must be exactly one {key} token"
                ),
                "{value}: {error}"
            );
        }
    }

    #[test]
    fn query_values_are_literals_or_single_key_tokens() {
        for value in [
            "\"x{repository}\"",
            "\"{repository}/{repository}\"",
            "\"{\"",
        ] {
            let yaml = http(
                "http://127.0.0.1:9/api/{repository}",
                &REQUEST_BLOCK.replace("state: scheduled", &format!("state: {value}")),
            );
            let error = check(&yaml).expect_err(value);
            assert!(
                error.contains(
                    "provider 'a': request.query.state must be a literal or exactly one {key} token"
                ),
                "{value}: {error}"
            );
        }
        let error = check(&http(
            "http://127.0.0.1:9/api/{repository}",
            &REQUEST_BLOCK.replace("state: scheduled", "\"{repository}\": scheduled"),
        ))
        .expect_err("a templated parameter name");
        assert!(
            error.contains("request.query parameter names are literal"),
            "{error}"
        );
    }

    #[test]
    fn field_refs_lower_to_pointers() {
        let source = lower(HTTP_PROVIDER);
        assert_eq!(source.select.as_deref(), Some("/result"));
        assert_eq!(source.matches[0].pointer, "/cmdb_ci.name");
        assert_eq!(source.claims["number"], "/number");

        let renamed = HTTP_PROVIDER
            .replace(
                KEEP_LIST,
                "keep: { ci_name: cmdb_ci.name, tilde: \"a~b\", first_number: /result/0/number, number: number }",
            )
            .replace("record_path: result", "record_path: /result/0");
        let source = lower(&renamed);
        assert_eq!(source.select.as_deref(), Some("/result/0"));
        assert_eq!(source.claims["ci_name"], "/cmdb_ci.name");
        assert_eq!(source.claims["tilde"], "/a~0b");
        assert_eq!(source.claims["first_number"], "/result/0/number");
        assert_eq!(source.claims["number"], "/number");

        let error = check(&HTTP_PROVIDER.replace("record_path: result", "record_path: result/0"))
            .expect_err("a bare field ref cannot contain a slash");
        assert!(
            error.contains(
                "response.record_path must be a bare field name or a JSON pointer starting with /"
            ),
            "{error}"
        );
        let error = check(&HTTP_PROVIDER.replace("record_path: result", "record_path: ''"))
            .expect_err("an empty record_path");
        assert!(
            error.contains("response.record_path must not be empty"),
            "{error}"
        );
        let error = check(&HTTP_PROVIDER.replace(KEEP_LIST, "keep: { risk: '' }"))
            .expect_err("an empty keep field ref");
        assert!(
            error.contains("response.keep.risk must not be empty"),
            "{error}"
        );

        // No response block lowers to a presence-only lookup.
        let source = lower(&http("http://127.0.0.1:9/api", REQUEST_BLOCK));
        assert_eq!(source.select, None);
        assert!(source.matches.is_empty());
        assert!(source.claims.is_empty());
    }

    #[test]
    fn keep_list_entries_must_be_claim_names() {
        let keep = |keep: &str| HTTP_PROVIDER.replace(KEEP_LIST, keep);
        let error = check(&keep("keep: [cmdb_ci.name]")).expect_err("a dotted API name");
        assert!(
            error.contains(
                "provider 'change-management': response.keep entry 'cmdb_ci.name' is not a valid claim name"
            ),
            "{error}"
        );
        assert!(
            error.contains(
                "use the map form to rename the field, e.g. keep: { <claim>: cmdb_ci.name }"
            ),
            "{error}"
        );
        for bad in [
            "keep: [_meta]",
            "keep: [Number]",
            "keep: [/number]",
            "keep: [number, number]",
            "keep: []",
            "keep: {}",
            "keep: { _meta: number }",
            "keep: { Risk: risk }",
        ] {
            assert!(check(&keep(bad)).is_err(), "{bad} must be rejected");
        }
        let error = check(&keep("keep: [number, number]")).expect_err("duplicate");
        assert!(
            error.contains("response.keep lists 'number' twice"),
            "{error}"
        );
        let error = check(&keep("keep: []")).expect_err("empty");
        assert!(
            error.contains(
                "response.keep must name at least one field; omit it for a presence-only lookup"
            ),
            "{error}"
        );
    }

    #[test]
    fn http_registrations_reject_tls_and_peer_uid() {
        let tls = HTTP_PROVIDER.replace("      auth:", &format!("{TLS_BLOCK}      auth:"));
        let error = check(&tls).expect_err("tls on http");
        assert!(
            error.contains(
                "provider 'change-management': endpoint.tls: client certificates for http endpoints are not supported in this release"
            ),
            "{error}"
        );
        let peer = HTTP_PROVIDER.replace("      auth:", "      peer_uid: 7\n      auth:");
        let error = check(&peer).expect_err("peer_uid on http");
        assert!(
            error.contains(
                "provider 'change-management': endpoint.peer_uid is only valid for a unix:// endpoint of type: grpc"
            ),
            "{error}"
        );
    }

    #[test]
    fn grpc_registrations_reject_auth_request_and_response() {
        let auth = UNIX_PROVIDER.replace(
            "      peer_uid: 1201\n",
            "      peer_uid: 1201\n      auth: { bearer_token_file: /etc/apf/providers/t }\n",
        );
        let error = check(&auth).expect_err("auth on grpc");
        assert!(
            error.contains("provider 'identity': endpoint.auth is only valid for type: http"),
            "{error}"
        );
        let request = UNIX_PROVIDER.replace(
            "    on_failure:",
            "    request: { query: { state: scheduled } }\n    on_failure:",
        );
        let error = check(&request).expect_err("request on grpc");
        assert!(
            error.contains("provider 'identity': request is only valid for type: http"),
            "{error}"
        );
        let response = UNIX_PROVIDER.replace(
            "    on_failure:",
            "    response: { keep: [number] }\n    on_failure:",
        );
        let error = check(&response).expect_err("response on grpc");
        assert!(
            error.contains("provider 'identity': response is only valid for type: http"),
            "{error}"
        );
    }

    #[test]
    fn registration_negatives() {
        let many_keys = |count: usize| {
            let keys: String = (0..count)
                .map(|i| format!("        k{i}: {{ from: args.k{i}, pattern: '^[a-z]+$' }}\n"))
                .collect();
            let query: String = (0..count)
                .map(|i| format!("        q{i}: \"{{k{i}}}\"\n"))
                .collect();
            http(
                "http://127.0.0.1:9/api",
                &format!("    request:\n      query:\n{query}      keys:\n{keys}"),
            )
        };
        validate(&many_keys(MAX_KEYS)).expect("the key cap is inclusive");
        let socket = "unix:///run/apf/providers/identity.sock";
        let cases: Vec<(&str, String)> = vec![
            (
                "bad name",
                UNIX_PROVIDER.replace("name: identity", "name: 'bad name'"),
            ),
            (
                "reserved context",
                UNIX_PROVIDER.replace("context: identity", "context: args"),
            ),
            (
                "forbidden context word",
                UNIX_PROVIDER.replace("context: identity", "context: message_class"),
            ),
            (
                "context shape",
                UNIX_PROVIDER.replace("context: identity", "context: Identity"),
            ),
            (
                "gateway socket",
                UNIX_PROVIDER.replace(socket, "unix:///run/apf/policy-gateway.sock"),
            ),
            (
                "relative unix",
                UNIX_PROVIDER.replace(socket, "unix://run/apf/identity.sock"),
            ),
            (
                "traversal",
                UNIX_PROVIDER.replace(socket, "unix:///run/apf/../identity.sock"),
            ),
            (
                "tls on unix",
                UNIX_PROVIDER.replace("      peer_uid: 1201\n", TLS_BLOCK),
            ),
            (
                "grpc token in url",
                UNIX_PROVIDER.replace(socket, "unix:///run/apf/providers/{identity}.sock"),
            ),
            (
                "https without tls",
                GRPC_HTTPS_PROVIDER.replace(TLS_BLOCK, ""),
            ),
            (
                "peer_uid on https",
                GRPC_HTTPS_PROVIDER.replace("      tls:\n", "      peer_uid: 7\n      tls:\n"),
            ),
            (
                "grpc http off loopback",
                GRPC_HTTPS_PROVIDER.replace(TLS_BLOCK, "").replace(
                    "https://registry.agents.example.com:8443",
                    "http://registry.agents.example.com:8443",
                ),
            ),
            (
                "grpc tls on loopback http",
                GRPC_HTTPS_PROVIDER.replace(
                    "https://registry.agents.example.com:8443",
                    "http://127.0.0.1:8443",
                ),
            ),
            (
                "http off loopback",
                HTTP_PROVIDER.replace("http://127.0.0.1:19500", "http://10.0.0.5:19500"),
            ),
            (
                "token in host",
                HTTP_PROVIDER.replace("http://127.0.0.1:19500", "https://{repository}.example.com"),
            ),
            (
                "token in the url query string",
                HTTP_PROVIDER.replace("/change_request\n", "/change_request?x={repository}\n"),
            ),
            (
                "unterminated token",
                HTTP_PROVIDER.replace("/change_request\n", "/change_request/{repository\n"),
            ),
            (
                "stray brace",
                HTTP_PROVIDER.replace("/change_request\n", "/change_request}\n"),
            ),
            ("too many keys", many_keys(MAX_KEYS + 1)),
            (
                "key name shape",
                HTTP_PROVIDER
                    .replace("repository:", "Repository:")
                    .replace("{repository}", "{Repository}"),
            ),
            (
                "key from an unknown subject path",
                HTTP_PROVIDER.replace("from: args.repository", "from: body_text"),
            ),
            (
                "unanchored pattern",
                HTTP_PROVIDER.replace(STRICT_PATTERN, "pattern: \"[a-z]+\""),
            ),
            (
                "invalid pattern",
                HTTP_PROVIDER.replace(STRICT_PATTERN, "pattern: \"^[a-z$\""),
            ),
            (
                "two auth methods",
                HTTP_PROVIDER.replace(
                    "auth: { bearer_token_file: /etc/apf/providers/itsm.token }",
                    "auth: { bearer_token_file: /a, basic_auth_file: /b }",
                ),
            ),
            (
                "empty auth",
                HTTP_PROVIDER.replace(
                    "auth: { bearer_token_file: /etc/apf/providers/itsm.token }",
                    "auth: {}",
                ),
            ),
            (
                "credential-like name",
                UNIX_PROVIDER.replace("name: identity", "name: risk-assessment-service"),
            ),
            (
                "empty applies_to",
                UNIX_PROVIDER.replace("    on_failure:", "    applies_to: []\n    on_failure:"),
            ),
            (
                "applies_to entry shape",
                UNIX_PROVIDER.replace(
                    "    on_failure:",
                    "    applies_to: ['has space']\n    on_failure:",
                ),
            ),
            ("no providers", "providers: []\n".to_owned()),
        ];
        for (label, yaml) in &cases {
            assert!(check(yaml).is_err(), "{label} must be rejected");
        }
    }

    #[test]
    fn provider_count_is_capped() {
        let many = |count: usize| {
            let mut yaml = String::from("providers:\n");
            for i in 0..count {
                yaml.push_str(&format!(
                    "  - name: provider{i}\n    context: area{i}\n    type: grpc\n    endpoint:\n      url: unix:///run/apf/providers/provider{i}.sock\n    on_failure: degrade\n"
                ));
            }
            yaml
        };
        validate(&many(MAX_PROVIDERS)).expect("the provider cap is inclusive");
        let error = check(&many(MAX_PROVIDERS + 1)).expect_err("one over the cap");
        assert!(
            error.contains("providers must list between 1 and 16 entries"),
            "{error}"
        );
    }

    #[test]
    fn http_subject_projection_is_the_distinct_key_sources() {
        let yaml = http(
            "http://127.0.0.1:9/api/{repository}/{again}",
            "    request:\n      query: { who: \"{who}\" }\n      keys:\n        repository: { from: args.repository, pattern: '^[a-z]+$' }\n        again: { from: args.repository, pattern: '^[a-z]+$' }\n        who: { from: user_subject, pattern: '^.+$' }\n",
        );
        validate(&yaml).expect("validates");
        assert_eq!(
            parse(&yaml).providers[0].subject_paths(),
            vec![
                SubjectPath::Arg("repository".to_owned()),
                SubjectPath::UserSubject
            ]
        );
        assert!(
            parse(&http("http://127.0.0.1:9/api", "")).providers[0]
                .subject_paths()
                .is_empty(),
            "a fixed lookup sends nothing"
        );
    }

    #[test]
    fn credential_like_names_and_contexts_are_rejected() {
        let name = UNIX_PROVIDER.replace("name: identity", "name: risk-assessment-service");
        let error = check(&name).expect_err("rejected");
        assert!(
            error.contains("provider name reads as a credential-like value"),
            "{error}"
        );
        let context =
            UNIX_PROVIDER.replace("context: identity", "context: ghp_aaaaaaaaaaaaaaaaaaaa");
        let error = check(&context).expect_err("rejected");
        assert!(
            error.contains("reads as a credential-like value"),
            "{error}"
        );
    }

    #[test]
    fn param_patterns_match_the_whole_value() {
        let pattern = compile_param_pattern("^[a-z]+|[0-9]+$").expect("compiles");
        assert!(pattern.is_match("abc"));
        assert!(pattern.is_match("42"));
        assert!(!pattern.is_match("abc^OR42"));
        assert!(!pattern.is_match("abc42"));
        assert!(compile_param_pattern("^[a-z$").is_err());
    }

    #[test]
    fn duplicate_names_and_contexts_are_rejected() {
        let other = |name: &str, context: &str| {
            format!(
                "  - name: {name}\n    context: {context}\n    type: grpc\n    endpoint:\n      url: unix:///run/apf/providers/other.sock\n    on_failure: degrade\n"
            )
        };
        let error = check(&format!("{UNIX_PROVIDER}{}", other("other", "identity")))
            .expect_err("duplicate context");
        assert!(
            error
                .contains("provider 'other': context 'identity' already has a registered provider"),
            "{error}"
        );
        let error = check(&format!("{UNIX_PROVIDER}{}", other("identity", "other")))
            .expect_err("duplicate name");
        assert!(
            error.contains("provider 'identity': provider names must be unique"),
            "{error}"
        );
    }
}
