// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic REST provider: answers a lookup with one GET against a configured
//! JSON API and projects the response into the registered context's claims.
//!
//! Request parameters come from the projected subject, must match their
//! anchored patterns, and are percent-encoded for the position they fill: a
//! path segment or a query value. The client follows no redirects, uses no
//! proxy, and requires `https` away from loopback. Credential files are read
//! on every call, so a rotated token takes effect without a restart; they are
//! also read once at construction so a broken credential fails startup
//! instead of degrading every evaluation.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apf_proto::pip_v1alpha1::EvaluationSubject;
use nix::fcntl::OFlag;
use regex::Regex;
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use url::Url;

use super::config::{
    ConfigError, HttpAuth, HttpSource, MAX_IN_FLIGHT, MatchSpec, compile_param_pattern,
    is_loopback_host,
};
use super::provider::{
    Attributes, Lookup, LookupFuture, LookupResult, ProviderError, ProviderTransport, check_value,
    validate_evidence_ref,
};
use super::subject::{self, SubjectPath};

/// Size cap on a bearer token or basic credential file.
pub const MAX_CREDENTIAL_BYTES: usize = 8 * 1024;
/// Size cap on a response body.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Mode bits a secret file must not carry: any group or other access.
const OWNER_ONLY: u32 = 0o077;
/// Value substituted for every parameter when a template is checked at
/// construction.
const PLACEHOLDER: &str = "x";

/// Resolved parameter values by name.
type ParamValues = BTreeMap<String, String>;

/// HTTP client bound to one lowered `http` registration.
pub struct HttpTransport {
    name: String,
    client: Client,
    template: UrlTemplate,
    params: Vec<Param>,
    credentials: Option<CredentialFile>,
    timeout: Duration,
    select: Option<String>,
    matches: Vec<MatchSpec>,
    /// Claim name to the pointer it reads; empty means presence-only.
    claims: BTreeMap<String, String>,
    /// In-flight permits; a lookup that finds none fails with `Capacity`.
    permits: Semaphore,
}

/// A request parameter: the subject field it comes from and the shape it
/// must have.
struct Param {
    name: String,
    from: SubjectPath,
    pattern: Regex,
}

/// Where the per-call credential is read from.
#[derive(Clone)]
enum CredentialFile {
    Bearer(PathBuf),
    Basic(PathBuf),
}

impl CredentialFile {
    fn from_auth(auth: &HttpAuth) -> Result<Self, String> {
        match (&auth.bearer_token_file, &auth.basic_auth_file) {
            (Some(path), None) => Ok(Self::Bearer(path.clone())),
            (None, Some(path)) => Ok(Self::Basic(path.clone())),
            _ => Err(
                "endpoint.auth must set exactly one of bearer_token_file or basic_auth_file"
                    .to_owned(),
            ),
        }
    }
}

/// A credential read from its file.
enum Credential {
    Bearer(String),
    Basic { user: String, password: String },
}

/// The request URL split into its fixed origin and the parts that take
/// parameters.
struct UrlTemplate {
    /// Scheme, host and port exactly as configured.
    origin: String,
    /// Raw path, with `{name}` tokens.
    path: String,
    /// Query string written into the URL itself, if any.
    static_query: Option<String>,
    /// Configured query pairs; values may hold tokens.
    query: BTreeMap<String, String>,
    /// Parsed form of the template, for origin comparison.
    parsed: Url,
}

impl HttpTransport {
    /// Build the transport from a lowered registration: compile the key
    /// patterns, check the URL template, build the client and prove the
    /// credential file readable.
    ///
    /// # Errors
    ///
    /// Returns the first configuration error, attributed to `name`.
    pub fn new(name: &str, source: &HttpSource) -> Result<Self, ConfigError> {
        let fail = |reason: String| ConfigError::Provider {
            provider: name.to_owned(),
            reason,
        };
        let params = source
            .params
            .iter()
            .map(|param| {
                let pattern = compile_param_pattern(&param.pattern).map_err(|error| {
                    format!("request.keys.{}.pattern is invalid: {error}", param.name)
                })?;
                Ok(Param {
                    name: param.name.clone(),
                    from: param.from.clone(),
                    pattern,
                })
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(fail)?;

        let template = UrlTemplate::new(source).map_err(fail)?;
        let client =
            build_client(source.timeout, template.parsed.scheme() == "https").map_err(fail)?;
        let credentials = source
            .auth
            .as_ref()
            .map(CredentialFile::from_auth)
            .transpose()
            .map_err(fail)?;
        if let Some(file) = &credentials {
            read_credential(file).map_err(fail)?;
        }

        let transport = Self {
            name: name.to_owned(),
            client,
            template,
            params,
            credentials,
            timeout: source.timeout,
            select: source.select.clone(),
            matches: source.matches.clone(),
            claims: source.claims.clone(),
            permits: Semaphore::new(MAX_IN_FLIGHT),
        };

        // Rendering the request with placeholder values proves that every
        // token names a declared parameter and that the template survives
        // URL parsing unchanged.
        let placeholders: ParamValues = transport
            .params
            .iter()
            .map(|param| (param.name.clone(), PLACEHOLDER.to_owned()))
            .collect();
        transport.template.render(&placeholders).map_err(fail)?;
        Ok(transport)
    }

    /// Registered provider name, for logs.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    async fn perform(
        &self,
        lookup: &Lookup,
        deadline: Duration,
        status: &mut Option<u16>,
    ) -> Result<LookupResult, ProviderError> {
        let Some(values) = self.resolve_params(&lookup.subject) else {
            return Ok(LookupResult::NoData);
        };
        let url = self.template.render(&values).map_err(|reason| {
            ProviderError::Unavailable(format!("request URL could not be built: {reason}"))
        })?;

        let mut request = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .timeout(deadline);
        if let Some(file) = &self.credentials {
            request = match load_credential(file).await? {
                Credential::Bearer(token) => request.bearer_auth(token),
                Credential::Basic { user, password } => request.basic_auth(user, Some(password)),
            };
        }

        let response = request.send().await.map_err(request_error)?;
        let code = response.status();
        *status = Some(code.as_u16());
        match code {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ProviderError::Misconfigured(format!(
                    "upstream rejected the gateway's credentials with status {}",
                    code.as_u16()
                )));
            }
            StatusCode::NOT_FOUND => return Ok(LookupResult::NoData),
            code if !code.is_success() => {
                return Err(ProviderError::Unavailable(format!(
                    "upstream returned status {}",
                    code.as_u16()
                )));
            }
            _ => {}
        }

        let body = read_body(response).await?;
        let json: Value = serde_json::from_slice(&body)
            .map_err(|_| ProviderError::Unavailable("response body is not JSON".to_owned()))?;
        self.project(&json, &values)
    }

    /// Resolve every parameter from the subject. `None` means the lookup has
    /// no answer: a parameter is absent, empty or fails its pattern.
    fn resolve_params(&self, subject: &EvaluationSubject) -> Option<ParamValues> {
        let mut values = ParamValues::new();
        for param in &self.params {
            let Some(value) = subject::lookup_value(subject, &param.from) else {
                tracing::debug!(
                    provider = %self.name,
                    parameter = %param.name,
                    "parameter absent from the subject; no lookup"
                );
                return None;
            };
            if !param.pattern.is_match(&value) {
                tracing::warn!(
                    provider = %self.name,
                    parameter = %param.name,
                    "parameter value rejected by its pattern; no lookup"
                );
                return None;
            }
            values.insert(param.name.clone(), value);
        }
        Some(values)
    }

    /// Select the record, check that it is the one asked for, and copy the
    /// kept fields into claims.
    fn project(&self, body: &Value, values: &ParamValues) -> Result<LookupResult, ProviderError> {
        let selected = match &self.select {
            Some(pointer) => body.pointer(pointer),
            None => Some(body),
        };
        let Some(selected) = selected else {
            return Ok(LookupResult::NoData);
        };
        let record = match selected {
            Value::Object(_) => selected,
            Value::Array(items) => match items.as_slice() {
                [] => return Ok(LookupResult::NoData),
                [only @ Value::Object(_)] => only,
                [_] => {
                    return Err(ProviderError::InvalidOutput(
                        "the selected record is not an object".to_owned(),
                    ));
                }
                _ => return Ok(LookupResult::NoData),
            },
            _ => {
                return Err(ProviderError::InvalidOutput(
                    "the selected value is not a record".to_owned(),
                ));
            }
        };

        for spec in &self.matches {
            let Some(expected) = values.get(&spec.param) else {
                return Err(ProviderError::Misconfigured(format!(
                    "must_match references key '{}', which the request does not define",
                    spec.param
                )));
            };
            let actual = record.pointer(&spec.pointer).and_then(scalar_text);
            if actual.as_deref() != Some(expected.as_str()) {
                return Ok(LookupResult::NoData);
            }
        }

        let mut claims = Map::new();
        for (name, pointer) in &self.claims {
            let Some(value) = record.pointer(pointer) else {
                continue;
            };
            if value.is_null() {
                continue;
            }
            if has_float(value) {
                return Err(ProviderError::Unavailable(format!(
                    "claim '{name}' holds a non-integer number"
                )));
            }
            check_value(value, 1).map_err(|reason| {
                ProviderError::InvalidOutput(format!("claim '{name}': {reason}"))
            })?;
            claims.insert(name.clone(), value.clone());
        }
        let evidence_ref = evidence_ref(&claims);
        Ok(LookupResult::Found(Attributes {
            claims,
            ttl_seconds: 0,
            age_seconds: 0,
            evidence_ref,
        }))
    }

    fn log(&self, status: Option<u16>, result: &Result<LookupResult, ProviderError>) {
        let host = self.template.parsed.host_str().unwrap_or_default();
        match result {
            Ok(result) => {
                let outcome = match result {
                    LookupResult::Found(_) => "found",
                    LookupResult::NoData => "no_data",
                };
                tracing::debug!(
                    provider = %self.name,
                    host,
                    status,
                    outcome,
                    "rest provider lookup"
                );
            }
            Err(error) => tracing::warn!(
                provider = %self.name,
                host,
                status,
                outcome = ?error.status(),
                error = %error,
                "rest provider lookup failed"
            ),
        }
    }
}

impl ProviderTransport for HttpTransport {
    fn lookup<'a>(&'a self, lookup: Lookup, budget: Duration) -> LookupFuture<'a> {
        Box::pin(async move {
            let _permit = self
                .permits
                .try_acquire()
                .map_err(|_| ProviderError::Capacity)?;
            let deadline = budget.min(self.timeout);
            let mut status = None;
            let result =
                match tokio::time::timeout(deadline, self.perform(&lookup, deadline, &mut status))
                    .await
                {
                    Ok(result) => result,
                    Err(_elapsed) => Err(ProviderError::Timeout),
                };
            self.log(status, &result);
            result
        })
    }
}

impl UrlTemplate {
    /// Split the raw template so tokens are substituted in the path only,
    /// and verify that the origin carries none.
    fn new(source: &HttpSource) -> Result<Self, String> {
        let raw = source.url.as_str();
        let parsed = Url::parse(raw).map_err(|error| format!("invalid URL: {error}"))?;
        if parsed.host_str().is_none() {
            return Err("URL must name a host".to_owned());
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("URL must not carry credentials".to_owned());
        }
        if raw.contains('#') {
            return Err("URL must not carry a fragment".to_owned());
        }
        match parsed.scheme() {
            "https" => {}
            "http" if is_loopback_host(&parsed) => {}
            "http" => {
                return Err("plain http is allowed for loopback hosts only".to_owned());
            }
            other => return Err(format!("unsupported URL scheme '{other}'")),
        }

        let (without_query, static_query) = match raw.split_once('?') {
            Some((before, query)) => (before, Some(query.to_owned())),
            None => (raw, None),
        };
        let authority_start = without_query
            .find("://")
            .map(|index| index + 3)
            .ok_or_else(|| "URL must be absolute".to_owned())?;
        let path_start = without_query[authority_start..]
            .find('/')
            .map_or(without_query.len(), |index| authority_start + index);
        let origin = &without_query[..path_start];
        let path = &without_query[path_start..];
        if origin.contains(['{', '}']) {
            return Err("the URL scheme, host and port cannot be templated".to_owned());
        }
        if static_query
            .as_deref()
            .is_some_and(|query| query.contains(['{', '}']))
        {
            return Err(
                "tokens in the URL query string are not supported; put templated pairs in request.query"
                    .to_owned(),
            );
        }
        if source.query.keys().any(|key| key.contains(['{', '}'])) {
            return Err("query parameter names cannot be templated".to_owned());
        }
        Ok(Self {
            origin: origin.to_owned(),
            path: path.to_owned(),
            static_query,
            query: source.query.clone(),
            parsed,
        })
    }

    /// Render the request URL for `values`. Path values are percent-encoded
    /// as single segments, query values are form-encoded, and the result
    /// must parse back to exactly what was built, on the configured origin.
    fn render(&self, values: &ParamValues) -> Result<Url, String> {
        let mut path = String::new();
        substitute(&self.path, values, &mut path, push_path_segment)?;
        if path.is_empty() {
            path.push('/');
        }

        let mut query = self.static_query.clone().unwrap_or_default();
        if !self.query.is_empty() {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (key, template) in &self.query {
                let mut value = String::new();
                substitute(template, values, &mut value, push_plain)?;
                serializer.append_pair(key, &value);
            }
            if !query.is_empty() {
                query.push('&');
            }
            query.push_str(&serializer.finish());
        }

        let mut target = format!("{}{path}", self.origin);
        if !query.is_empty() {
            target.push('?');
            target.push_str(&query);
        }
        let url =
            Url::parse(&target).map_err(|error| format!("rendered URL is invalid: {error}"))?;
        if url.scheme() != self.parsed.scheme()
            || url.host() != self.parsed.host()
            || url.port_or_known_default() != self.parsed.port_or_known_default()
        {
            return Err("rendered URL left the configured origin".to_owned());
        }
        if url.path() != path {
            return Err(
                "rendered path changed under URL normalization; write the template path percent-encoded and without dot segments"
                    .to_owned(),
            );
        }
        let expected_query = (!query.is_empty()).then_some(query.as_str());
        if url.query() != expected_query {
            return Err(
                "rendered query changed under URL normalization; write the template query percent-encoded"
                    .to_owned(),
            );
        }
        Ok(url)
    }
}

/// Append `template` to `out`, replacing each `{name}` token with the value
/// of that parameter passed through `encode`. Tokens are read from the
/// template only, so a value is never expanded again.
fn substitute(
    template: &str,
    values: &ParamValues,
    out: &mut String,
    encode: fn(&str, &mut String),
) -> Result<(), String> {
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after
            .find('}')
            .ok_or_else(|| "template has an unterminated '{' token".to_owned())?;
        let name = &after[..end];
        let value = values
            .get(name)
            .ok_or_else(|| format!("token '{{{name}}}' names no declared parameter"))?;
        encode(value, out);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(())
}

fn push_plain(value: &str, out: &mut String) {
    out.push_str(value);
}

/// Percent-encode a value as one path segment: every byte other than the
/// unreserved characters is escaped, including `/`, `?`, `#`, `%` and `^`.
fn push_path_segment(value: &str, out: &mut String) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
}

/// Build the client: no redirects, no proxy, bounded by `timeout`, and
/// `https` only when the template is `https`.
fn build_client(timeout: Duration, https_only: bool) -> Result<Client, String> {
    Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(timeout)
        .https_only(https_only)
        .build()
        .map_err(|error| format!("HTTP client could not be built: {error}"))
}

/// Read a credential file on a blocking thread and map failures to a
/// misconfiguration, since the file was valid at startup.
async fn load_credential(file: &CredentialFile) -> Result<Credential, ProviderError> {
    let file = file.clone();
    tokio::task::spawn_blocking(move || read_credential(&file))
        .await
        .map_err(|_| ProviderError::Unavailable("credential read was interrupted".to_owned()))?
        .map_err(ProviderError::Misconfigured)
}

/// Read and parse a credential file: a regular, owner-only file holding the
/// token on its first line, or the basic user and password on two lines.
fn read_credential(file: &CredentialFile) -> Result<Credential, String> {
    match file {
        CredentialFile::Bearer(path) => {
            let bytes = read_secret_file(path, MAX_CREDENTIAL_BYTES, "bearer_token_file")?;
            parse_bearer(&bytes)
        }
        CredentialFile::Basic(path) => {
            let bytes = read_secret_file(path, MAX_CREDENTIAL_BYTES, "basic_auth_file")?;
            parse_basic(&bytes)
        }
    }
}

fn parse_bearer(bytes: &[u8]) -> Result<Credential, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "bearer_token_file must be UTF-8 text".to_owned())?;
    let token = text.lines().next().unwrap_or_default().trim();
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("bearer_token_file must hold one printable token on its first line".to_owned());
    }
    Ok(Credential::Bearer(token.to_owned()))
}

fn parse_basic(bytes: &[u8]) -> Result<Credential, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "basic_auth_file must be UTF-8 text".to_owned())?;
    let mut lines = text.lines();
    let user = lines.next().unwrap_or_default();
    let printable = |value: &str| !value.is_empty() && !value.chars().any(char::is_control);
    match lines.next() {
        Some(password) if printable(user) && !user.contains(':') && printable(password) => {
            Ok(Credential::Basic {
                user: user.to_owned(),
                password: password.to_owned(),
            })
        }
        _ => Err(
            "basic_auth_file must hold the user on the first line and the password on the second"
                .to_owned(),
        ),
    }
}

/// Read a secret file after proving it is a regular, owner-only file within
/// `max_bytes`, without following a symlink. The opened inode is checked
/// again so the file cannot be swapped between inspection and read.
fn read_secret_file(path: &Path, max_bytes: usize, what: &str) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let describe = |error: std::io::Error| format!("{what} {}: {error}", path.display());
    let inspected = std::fs::symlink_metadata(path).map_err(describe)?;
    check_secret_metadata(&inspected, max_bytes, what)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits())
        .open(path)
        .map_err(describe)?;
    let opened = file.metadata().map_err(describe)?;
    check_secret_metadata(&opened, max_bytes, what)?;
    if (inspected.dev(), inspected.ino()) != (opened.dev(), opened.ino()) {
        return Err(format!(
            "{what} {} changed while being opened",
            path.display()
        ));
    }
    let cap = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(describe)?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "{what} {} exceeds {max_bytes} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

fn check_secret_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: usize,
    what: &str,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_file() {
        return Err(format!(
            "{what} must be a regular file, not a symlink or special file"
        ));
    }
    if metadata.mode() & OWNER_ONLY != 0 {
        return Err(format!("{what} must be accessible only by its owner"));
    }
    if metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(format!("{what} exceeds {max_bytes} bytes"));
    }
    Ok(())
}

/// Map a client error onto the taxonomy without carrying the URL, which
/// would hold parameter values.
fn request_error(error: reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        return ProviderError::Timeout;
    }
    let reason = if error.is_connect() {
        "connection failed"
    } else if error.is_body() || error.is_decode() {
        "response body could not be read"
    } else if error.is_request() {
        "request could not be sent"
    } else {
        "request failed"
    };
    ProviderError::Unavailable(reason.to_owned())
}

/// Read the body up to the response cap; anything larger is a fault.
async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>, ProviderError> {
    let too_large = || {
        ProviderError::Unavailable(format!(
            "response exceeds the {MAX_RESPONSE_BYTES}-byte cap"
        ))
    };
    let cap = u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX);
    if response.content_length().is_some_and(|length| length > cap) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(request_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// String form of a scalar record value, for `must_match` comparisons.
fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn has_float(value: &Value) -> bool {
    match value {
        Value::Number(number) => !(number.is_i64() || number.is_u64()),
        Value::Array(items) => items.iter().any(has_float),
        Value::Object(fields) => fields.values().any(has_float),
        Value::Null | Value::Bool(_) | Value::String(_) => false,
    }
}

/// Evidence reference: the `number` or `id` claim when it is a bounded,
/// printable string or an integer.
fn evidence_ref(claims: &Map<String, Value>) -> Option<String> {
    let value = claims.get("number").or_else(|| claims.get("id"))?;
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    validate_evidence_ref(&text).ok().flatten()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use apf_policy_eval::EvalInput;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::{Path as AxumPath, Query, RawQuery, Request, State};
    use axum::http::{StatusCode, header};
    use axum::middleware::{self, Next};
    use axum::response::{IntoResponse, Redirect, Response};
    use axum::routing::get;
    use base64::Engine as _;
    use serde_json::json;
    use tokio::task::JoinSet;

    use super::*;
    use crate::pip::config::{Limits, ProviderRegistration};

    const STRICT_PATTERN: &str = "pattern: \"^[a-z0-9-]+/[a-z0-9-]+$\"";
    const PERMISSIVE_PATTERN: &str = "pattern: \"^.+$\"";
    const KEEP_LIST: &str = "keep: [number, state, approval, risk]";
    const BUDGET: Duration = Duration::from_secs(5);

    /// One request the fake upstream received.
    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        raw_query: Option<String>,
        headers: axum::http::HeaderMap,
    }

    impl Recorded {
        fn header(&self, name: header::HeaderName) -> Option<String> {
            self.headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        }
    }

    #[derive(Clone, Default)]
    struct Upstream {
        requests: Arc<Mutex<Vec<Recorded>>>,
    }

    impl Upstream {
        fn requests(&self) -> Vec<Recorded> {
            self.requests.lock().expect("lock").clone()
        }
    }

    async fn record(State(upstream): State<Upstream>, request: Request, next: Next) -> Response {
        upstream.requests.lock().expect("lock").push(Recorded {
            method: request.method().to_string(),
            path: request.uri().path().to_owned(),
            raw_query: request.uri().query().map(str::to_owned),
            headers: request.headers().clone(),
        });
        next.run(request).await
    }

    fn change(project: &str) -> Value {
        json!({
            "number": "CHG0012",
            "state": "scheduled",
            "approval": "approved",
            "risk": 2,
            "cmdb_ci.name": project,
        })
    }

    fn project_of(params: &HashMap<String, String>) -> String {
        params.get("cmdb_ci.name").cloned().unwrap_or_default()
    }

    async fn table(Query(params): Query<HashMap<String, String>>) -> Response {
        let project = project_of(&params);
        let result = match project.as_str() {
            "nv/none" => json!([]),
            "nv/two" => json!([change(&project), change(&project)]),
            "nv/other" => json!([change("nv/elsewhere")]),
            "nv/float" => {
                let mut record = change(&project);
                record["risk"] = json!(2.5);
                json!([record])
            }
            "nv/scalar" => json!([7]),
            _ => json!([change(&project)]),
        };
        axum::Json(json!({ "result": result })).into_response()
    }

    /// The record itself, not wrapped in a result list.
    async fn record_route(Query(params): Query<HashMap<String, String>>) -> Response {
        axum::Json(change(&project_of(&params))).into_response()
    }

    async fn projects(AxumPath(project): AxumPath<String>) -> Response {
        axum::Json(json!({ "result": [change(&project)] })).into_response()
    }

    async fn status_route(AxumPath(code): AxumPath<u16>) -> Response {
        StatusCode::from_u16(code).expect("status").into_response()
    }

    async fn not_json() -> Response {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            "not json",
        )
            .into_response()
    }

    async fn oversized() -> Response {
        axum::Json(json!({
            "result": [{ "cmdb_ci.name": "nv/apf", "pad": "x".repeat(MAX_RESPONSE_BYTES) }]
        }))
        .into_response()
    }

    async fn oversized_chunked() -> Response {
        let chunks: Vec<Result<Vec<u8>, Infallible>> = (0..=MAX_RESPONSE_BYTES / 1024)
            .map(|_| Ok(vec![b'x'; 1024]))
            .collect();
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Body::from_stream(tokio_stream::iter(chunks)),
        )
            .into_response()
    }

    async fn redirect_route() -> Response {
        Redirect::temporary("/api/now/table/change_request?cmdb_ci.name=nv%2Fapf").into_response()
    }

    async fn echo(
        Query(params): Query<HashMap<String, String>>,
        RawQuery(raw): RawQuery,
    ) -> Response {
        axum::Json(json!({
            "result": [{
                "query": raw.unwrap_or_default(),
                "cmdb_ci.name": project_of(&params),
            }]
        }))
        .into_response()
    }

    async fn slow(query: Query<HashMap<String, String>>) -> Response {
        tokio::time::sleep(Duration::from_millis(500)).await;
        table(query).await
    }

    async fn start_upstream() -> (u16, Upstream) {
        let upstream = Upstream::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let app = Router::new()
            .route("/api/now/table/change_request", get(table))
            .route("/record", get(record_route))
            .route("/projects/{project}/changes", get(projects))
            .route("/status/{code}", get(status_route))
            .route("/not-json", get(not_json))
            .route("/oversized", get(oversized))
            .route("/oversized-chunked", get(oversized_chunked))
            .route("/redirect", get(redirect_route))
            .route("/echo", get(echo))
            .route("/slow", get(slow))
            .layer(middleware::from_fn_with_state(upstream.clone(), record));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (port, upstream)
    }

    fn registration_yaml(port: u16, path: &str) -> String {
        format!(
            r#"name: change-table
context: change
type: http
endpoint:
  url: http://127.0.0.1:{port}{path}
request:
  query:
    cmdb_ci.name: "{{project}}"
    state: scheduled
  keys:
    project: {{ from: args.project, pattern: "^[a-z0-9-]+/[a-z0-9-]+$" }}
response:
  record_path: result
  must_match: {{ cmdb_ci.name: "{{project}}" }}
  keep: [number, state, approval, risk]
on_failure: degrade
timeout_ms: 2000
"#
        )
    }

    /// Add an `auth` block to the endpoint of `yaml`.
    fn with_auth(yaml: &str, auth: &str) -> String {
        yaml.replace("request:\n", &format!("  auth:\n    {auth}\nrequest:\n"))
    }

    fn limits() -> Limits {
        Limits {
            stage_budget: BUDGET,
            gateway_socket: None,
        }
    }

    fn registration(yaml: &str) -> ProviderRegistration {
        serde_yaml::from_str(yaml).expect("registration YAML")
    }

    fn transport(yaml: &str) -> HttpTransport {
        let registration = registration(yaml);
        let source = registration
            .http_source(&limits())
            .expect("registration lowers");
        HttpTransport::new(&registration.name, &source).expect("transport builds")
    }

    /// Lower and construct, flattening every error to its message.
    fn build(yaml: &str) -> Result<(), String> {
        let registration: ProviderRegistration =
            serde_yaml::from_str(yaml).map_err(|error| error.to_string())?;
        let source = registration
            .http_source(&limits())
            .map_err(|error| error.to_string())?;
        HttpTransport::new(&registration.name, &source)
            .map(drop)
            .map_err(|error| error.to_string())
    }

    fn lookup(project: Option<&str>) -> Lookup {
        let mut args = Map::new();
        if let Some(project) = project {
            args.insert("project".to_owned(), json!(project));
        }
        let input = EvalInput::for_tool_call(
            Some("gitlab_merge_request_merge".to_owned()),
            None,
            "user@corp.com".to_owned(),
            args,
        );
        Lookup {
            subject: subject::project(
                &input,
                &[SubjectPath::Action, SubjectPath::Arg("project".to_owned())],
            ),
            domain: "change".to_owned(),
            correlation_id: "corr-1".to_owned(),
        }
    }

    async fn run(
        transport: &HttpTransport,
        project: Option<&str>,
    ) -> Result<LookupResult, ProviderError> {
        transport.lookup(lookup(project), BUDGET).await
    }

    fn secret_file(dir: &Path, name: &str, contents: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn found_record_is_projected_with_evidence() {
        let (port, upstream) = start_upstream().await;
        let transport = transport(&registration_yaml(port, "/api/now/table/change_request"));
        assert_eq!(transport.name(), "change-table");
        let result = run(&transport, Some("nv/apf"))
            .await
            .expect("lookup succeeds");
        let LookupResult::Found(attributes) = result else {
            panic!("expected attributes");
        };
        assert_eq!(attributes.claims["number"], json!("CHG0012"));
        assert_eq!(attributes.claims["state"], json!("scheduled"));
        assert_eq!(attributes.claims["approval"], json!("approved"));
        assert_eq!(attributes.claims["risk"], json!(2));
        assert_eq!(attributes.claims.len(), 4, "cmdb_ci.name is not kept");
        assert_eq!(attributes.ttl_seconds, 0);
        assert_eq!(attributes.age_seconds, 0);
        assert_eq!(attributes.evidence_ref.as_deref(), Some("CHG0012"));

        let seen = upstream.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].path, "/api/now/table/change_request");
        assert_eq!(
            seen[0].raw_query.as_deref(),
            Some("cmdb_ci.name=nv%2Fapf&state=scheduled")
        );
        assert_eq!(
            seen[0].header(header::ACCEPT).as_deref(),
            Some("application/json")
        );
        assert_eq!(seen[0].header(header::AUTHORIZATION), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_path_absent_takes_the_body_as_the_record() {
        let (port, upstream) = start_upstream().await;
        let yaml = registration_yaml(port, "/record").replace("  record_path: result\n", "");
        let unwrapped = transport(&yaml);
        let result = run(&unwrapped, Some("nv/apf"))
            .await
            .expect("lookup succeeds");
        assert!(matches!(
            result,
            LookupResult::Found(attributes) if attributes.claims["number"] == json!("CHG0012")
        ));
        assert_eq!(upstream.requests().len(), 1);

        // The same body wrapped in a result list is no record without a path.
        let wrapped = transport(
            &registration_yaml(port, "/api/now/table/change_request")
                .replace("  record_path: result\n", ""),
        );
        let result = run(&wrapped, Some("nv/apf"))
            .await
            .expect("lookup succeeds");
        assert_eq!(result, LookupResult::NoData, "the kept fields are absent");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keep_absent_is_presence_only() {
        let (port, _upstream) = start_upstream().await;
        let yaml = registration_yaml(port, "/api/now/table/change_request")
            .replace(&format!("  {KEEP_LIST}\n"), "");
        let presence_only = transport(&yaml);
        let result = run(&presence_only, Some("nv/apf"))
            .await
            .expect("lookup succeeds");
        let LookupResult::Found(attributes) = result else {
            panic!("expected a found result");
        };
        assert!(attributes.claims.is_empty(), "no claims are kept");
        assert_eq!(attributes.evidence_ref, None);
        assert_eq!(
            run(&presence_only, Some("nv/other"))
                .await
                .expect("lookup succeeds"),
            LookupResult::NoData,
            "must_match still applies"
        );

        // Without must_match either, any record found is an answer.
        let unchecked =
            transport(&yaml.replace("  must_match: { cmdb_ci.name: \"{project}\" }\n", ""));
        assert!(matches!(
            run(&unchecked, Some("nv/other"))
                .await
                .expect("lookup succeeds"),
            LookupResult::Found(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unusable_parameters_yield_no_data_without_a_request() {
        let (port, upstream) = start_upstream().await;
        let transport = transport(&registration_yaml(port, "/api/now/table/change_request"));
        for project in [
            None,
            Some(""),
            Some("a/b^ORapproval=approved"),
            Some("NV/APF"),
        ] {
            assert_eq!(
                run(&transport, project).await.expect("lookup succeeds"),
                LookupResult::NoData,
                "{project:?}"
            );
        }
        assert!(
            upstream.requests().is_empty(),
            "no request leaves for a rejected parameter"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unmatched_records_and_404_yield_no_data() {
        let (port, _upstream) = start_upstream().await;
        let table = transport(&registration_yaml(port, "/api/now/table/change_request"));
        for project in ["nv/none", "nv/two", "nv/other"] {
            assert_eq!(
                run(&table, Some(project)).await.expect("lookup succeeds"),
                LookupResult::NoData,
                "{project}"
            );
        }
        let missing = transport(&registration_yaml(port, "/status/404"));
        assert_eq!(
            run(&missing, Some("nv/apf"))
                .await
                .expect("lookup succeeds"),
            LookupResult::NoData
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejected_credentials_are_misconfigured() {
        let (port, _upstream) = start_upstream().await;
        for code in [401, 403] {
            let transport = transport(&registration_yaml(port, &format!("/status/{code}")));
            assert!(
                matches!(
                    run(&transport, Some("nv/apf")).await,
                    Err(ProviderError::Misconfigured(_))
                ),
                "{code}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn upstream_faults_are_unavailable() {
        let (port, _upstream) = start_upstream().await;
        for path in [
            "/status/500",
            "/status/503",
            "/not-json",
            "/oversized",
            "/oversized-chunked",
        ] {
            let transport = transport(&registration_yaml(port, path));
            assert!(
                matches!(
                    run(&transport, Some("nv/apf")).await,
                    Err(ProviderError::Unavailable(_))
                ),
                "{path}"
            );
        }

        let table = transport(&registration_yaml(port, "/api/now/table/change_request"));
        assert!(
            matches!(
                run(&table, Some("nv/float")).await,
                Err(ProviderError::Unavailable(_))
            ),
            "a kept field holding a float"
        );
        assert!(
            matches!(
                run(&table, Some("nv/scalar")).await,
                Err(ProviderError::InvalidOutput(_))
            ),
            "a scalar where a record is expected"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn injection_is_rejected_by_the_pattern_and_encoded_on_the_wire() {
        let (port, upstream) = start_upstream().await;
        let hostile = "a/b^ORapproval=approved";
        let strict = transport(&registration_yaml(port, "/echo"));
        assert_eq!(
            run(&strict, Some(hostile)).await.expect("lookup succeeds"),
            LookupResult::NoData
        );
        assert!(upstream.requests().is_empty());

        let permissive = transport(
            &registration_yaml(port, "/echo")
                .replace(STRICT_PATTERN, PERMISSIVE_PATTERN)
                .replace(KEEP_LIST, "keep: [number, query]"),
        );
        let result = run(&permissive, Some(hostile))
            .await
            .expect("lookup succeeds");
        let LookupResult::Found(attributes) = result else {
            panic!("expected attributes");
        };
        let seen = upstream.requests();
        assert_eq!(seen.len(), 1);
        let raw_query = seen[0].raw_query.clone().expect("query string");
        assert_eq!(
            raw_query,
            "cmdb_ci.name=a%2Fb%5EORapproval%3Dapproved&state=scheduled"
        );
        assert_eq!(attributes.claims["query"], json!(raw_query));
        assert_eq!(attributes.evidence_ref, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn path_tokens_are_encoded_as_a_single_segment() {
        let (port, upstream) = start_upstream().await;
        let yaml = registration_yaml(port, "/projects/{project}/changes");
        let strict = transport(&yaml);
        assert!(matches!(
            run(&strict, Some("nv/apf")).await.expect("lookup succeeds"),
            LookupResult::Found(_)
        ));
        assert_eq!(upstream.requests()[0].path, "/projects/nv%2Fapf/changes");

        let permissive = transport(&yaml.replace(STRICT_PATTERN, PERMISSIVE_PATTERN));
        assert!(
            matches!(
                run(&permissive, Some("..")).await,
                Err(ProviderError::Unavailable(_))
            ),
            "dot segments cannot rewrite the path"
        );
        assert_eq!(
            upstream.requests().len(),
            1,
            "no request leaves for a rewritten path"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn redirects_are_not_followed() {
        let (port, upstream) = start_upstream().await;
        let transport = transport(&registration_yaml(port, "/redirect"));
        assert!(matches!(
            run(&transport, Some("nv/apf")).await,
            Err(ProviderError::Unavailable(_))
        ));
        let seen = upstream.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/redirect");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_shorter_than_the_upstream_delay_is_a_timeout() {
        let (port, _upstream) = start_upstream().await;
        let transport = transport(&registration_yaml(port, "/slow"));
        let started = std::time::Instant::now();
        assert_eq!(
            transport
                .lookup(lookup(Some("nv/apf")), Duration::from_millis(50))
                .await,
            Err(ProviderError::Timeout)
        );
        assert!(
            started.elapsed() < Duration::from_millis(450),
            "the budget bounds the call"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_client_timeout_is_the_lookup_budget() {
        let (port, _upstream) = start_upstream().await;
        let yaml = registration_yaml(port, "/slow").replace("timeout_ms: 2000", "timeout_ms: 50");
        let transport = transport(&yaml);
        assert_eq!(transport.timeout, Duration::from_millis(50));
        let started = std::time::Instant::now();
        assert_eq!(
            run(&transport, Some("nv/apf")).await,
            Err(ProviderError::Timeout),
            "a budget above the timeout does not extend the call"
        );
        assert!(started.elapsed() < Duration::from_millis(450));

        let defaulted =
            registration(&registration_yaml(port, "/slow").replace("timeout_ms: 2000\n", ""))
                .http_source(&limits())
                .expect("lowers");
        assert_eq!(
            defaulted.timeout, BUDGET,
            "absent timeout_ms is the stage cap"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bearer_and_basic_credentials_are_sent_and_rotate_without_restart() {
        let (port, upstream) = start_upstream().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let yaml = registration_yaml(port, "/api/now/table/change_request");

        let token = secret_file(dir.path(), "change.token", "tok-one\n", 0o600);
        let bearer = transport(&with_auth(
            &yaml,
            &format!("bearer_token_file: {}", token.display()),
        ));
        run(&bearer, Some("nv/apf")).await.expect("lookup succeeds");
        std::fs::write(&token, "tok-two\n").expect("rotate the token");
        run(&bearer, Some("nv/apf")).await.expect("lookup succeeds");

        let basic_file = secret_file(dir.path(), "change.basic", "svc-apf\nsecond-line\n", 0o600);
        let basic = transport(&with_auth(
            &yaml,
            &format!("basic_auth_file: {}", basic_file.display()),
        ));
        run(&basic, Some("nv/apf")).await.expect("lookup succeeds");

        let authorization: Vec<Option<String>> = upstream
            .requests()
            .iter()
            .map(|seen| seen.header(header::AUTHORIZATION))
            .collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode("svc-apf:second-line");
        assert_eq!(
            authorization,
            vec![
                Some("Bearer tok-one".to_owned()),
                Some("Bearer tok-two".to_owned()),
                Some(format!("Basic {encoded}")),
            ]
        );
    }

    #[test]
    fn credential_files_are_checked_at_construction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let yaml = registration_yaml(4, "/api/now/table/change_request");
        let bearer = |path: &Path| {
            build(&with_auth(
                &yaml,
                &format!("bearer_token_file: {}", path.display()),
            ))
        };
        let basic = |path: &Path| {
            build(&with_auth(
                &yaml,
                &format!("basic_auth_file: {}", path.display()),
            ))
        };

        let cases = [
            (
                "group readable",
                secret_file(dir.path(), "readable.token", "tok\n", 0o640),
            ),
            ("empty", secret_file(dir.path(), "empty.token", "\n", 0o600)),
            (
                "oversized",
                secret_file(
                    dir.path(),
                    "big.token",
                    &"x".repeat(MAX_CREDENTIAL_BYTES + 1),
                    0o600,
                ),
            ),
            ("missing", dir.path().join("missing.token")),
        ];
        for (label, path) in &cases {
            assert!(bearer(path).is_err(), "{label} must be rejected");
        }
        let target = secret_file(dir.path(), "real.token", "tok\n", 0o600);
        let link = dir.path().join("link.token");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(bearer(&link).is_err(), "a symlink must be rejected");
        assert!(bearer(&target).is_ok());

        let one_line = secret_file(dir.path(), "one.basic", "user-only\n", 0o600);
        assert!(basic(&one_line).is_err(), "a basic file needs two lines");
        let colon = secret_file(dir.path(), "colon.basic", "user:name\npw\n", 0o600);
        assert!(
            basic(&colon).is_err(),
            "a basic user cannot contain a colon"
        );
        let good = secret_file(dir.path(), "good.basic", "svc\npw\n", 0o600);
        assert!(basic(&good).is_ok());

        let error = build(&with_auth(
            &yaml,
            "bearer_token_file: /a\n    basic_auth_file: /b",
        ))
        .expect_err("two credential files");
        assert!(error.contains("exactly one of"), "{error}");
    }

    #[test]
    fn constructor_rejects_unsafe_templates() {
        let base = registration_yaml(8443, "/api/now/table/change_request");
        let origin = "http://127.0.0.1:8443";
        let cases = [
            (
                "http off loopback",
                base.replace(origin, "http://10.0.0.5:8443"),
            ),
            (
                "token in host",
                base.replace(origin, "http://{project}.example.com"),
            ),
            (
                "undeclared token",
                base.replace("state: scheduled", "state: \"{state}\""),
            ),
            (
                "token in the URL query string",
                base.replace(
                    "/api/now/table/change_request\n",
                    "/api/now/table/change_request?x={project}\n",
                ),
            ),
            (
                "dot segment in the template",
                base.replace(
                    "/api/now/table/change_request\n",
                    "/api/now/../table/change_request\n",
                ),
            ),
            (
                "unencoded space in the template",
                base.replace(
                    "/api/now/table/change_request\n",
                    "/api/now/table/change request\n",
                ),
            ),
        ];
        for (label, yaml) in &cases {
            assert!(build(yaml).is_err(), "{label} must be rejected");
        }
        for allowed in [
            "https://change.example.com",
            "http://localhost:8443",
            "http://[::1]:8443",
        ] {
            assert!(build(&base.replace(origin, allowed)).is_ok(), "{allowed}");
        }
    }

    #[test]
    fn templates_render_tokens_in_path_and_query_only() {
        let source = HttpSource {
            url: "https://api.example.com/v4/projects/{project}/issues?per_page=1".to_owned(),
            query: [("labels", "{label}"), ("state", "opened")]
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            params: Vec::new(),
            auth: None,
            timeout: BUDGET,
            select: None,
            matches: Vec::new(),
            claims: BTreeMap::new(),
        };
        let template = UrlTemplate::new(&source).expect("template");
        let values: ParamValues = [("project", "nv/apf"), ("label", "a b&c=d")]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        let url = template.render(&values).expect("renders");
        assert_eq!(
            url.as_str(),
            "https://api.example.com/v4/projects/nv%2Fapf/issues?per_page=1&labels=a+b%26c%3Dd&state=opened"
        );
        assert!(
            template.render(&ParamValues::new()).is_err(),
            "a token without a value"
        );
    }

    #[test]
    fn path_segments_escape_everything_but_unreserved_characters() {
        let mut out = String::new();
        push_path_segment("a/b?c#d%e^f g~h.i-j_k", &mut out);
        assert_eq!(out, "a%2Fb%3Fc%23d%25e%5Ef%20g~h.i-j_k");
        let mut utf8 = String::new();
        push_path_segment("é", &mut utf8);
        assert_eq!(utf8, "%C3%A9");
    }

    #[test]
    fn floats_are_found_at_any_depth() {
        assert!(has_float(&json!(2.5)));
        assert!(has_float(&json!({ "a": [1, { "b": 0.5 }] })));
        assert!(!has_float(&json!({ "a": [1, { "b": "0.5" }] })));
        assert!(!has_float(&json!(-7)));
    }

    #[test]
    fn evidence_reference_comes_from_number_or_id() {
        let mut claims = Map::new();
        assert_eq!(evidence_ref(&claims), None);
        claims.insert("id".to_owned(), json!(42));
        assert_eq!(evidence_ref(&claims).as_deref(), Some("42"));
        claims.insert("number".to_owned(), json!("CHG0012"));
        assert_eq!(evidence_ref(&claims).as_deref(), Some("CHG0012"));
        claims.insert("number".to_owned(), json!("x".repeat(129)));
        assert_eq!(evidence_ref(&claims), None);
        claims.insert("number".to_owned(), json!("a\nb"));
        assert_eq!(evidence_ref(&claims), None);
        claims.insert("number".to_owned(), json!({ "nested": true }));
        assert_eq!(evidence_ref(&claims), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_flight_limit_yields_capacity() {
        let (port, upstream) = start_upstream().await;
        let transport = Arc::new(transport(&registration_yaml(port, "/slow")));
        let mut tasks = JoinSet::new();
        for _ in 0..=MAX_IN_FLIGHT {
            let transport = Arc::clone(&transport);
            tasks.spawn(async move {
                transport
                    .lookup(lookup(Some("nv/apf")), Duration::from_secs(2))
                    .await
            });
        }
        let (mut found, mut capacity) = (0, 0);
        while let Some(result) = tasks.join_next().await {
            match result.expect("task") {
                Ok(LookupResult::Found(_)) => found += 1,
                Err(ProviderError::Capacity) => capacity += 1,
                other => panic!("unexpected outcome {other:?}"),
            }
        }
        assert_eq!((found, capacity), (MAX_IN_FLIGHT, 1));
        assert_eq!(
            upstream.requests().len(),
            MAX_IN_FLIGHT,
            "the rejected lookup sent nothing"
        );
        transport
            .lookup(lookup(Some("nv/apf")), BUDGET)
            .await
            .expect("permits released");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn alternation_cannot_escape_the_pattern_anchors() {
        let (port, upstream) = start_upstream().await;
        let transport = transport(
            &registration_yaml(port, "/api/now/table/change_request").replace(
                STRICT_PATTERN,
                "pattern: \"^[a-z0-9-]+/[a-z0-9-]+|legacy-[0-9]+$\"",
            ),
        );
        assert_eq!(
            run(&transport, Some("nv/apf^ORapproval=approved"))
                .await
                .expect("lookup succeeds"),
            LookupResult::NoData
        );
        assert!(
            upstream.requests().is_empty(),
            "no request leaves for a value matching one branch only"
        );
        for project in ["legacy-7", "nv/apf"] {
            assert!(
                matches!(
                    run(&transport, Some(project)).await,
                    Ok(LookupResult::Found(_))
                ),
                "{project}"
            );
        }
        assert_eq!(upstream.requests().len(), 2);
    }

    #[test]
    fn any_loopback_address_is_accepted_for_plain_http() {
        let base = registration_yaml(8443, "/api/now/table/change_request");
        let origin = "http://127.0.0.1:8443";
        build(&base.replace(origin, "http://127.0.0.2:8443")).expect("127.0.0.2 is loopback");
        let error = build(&base.replace(origin, "http://10.0.0.5:8443")).expect_err("off loopback");
        assert!(error.contains("loopback hosts only"), "{error}");
    }
}
